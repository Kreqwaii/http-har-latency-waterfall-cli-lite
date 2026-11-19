"""Core HAR parsing, latency waterfall percentiles, rule engine, and diffing."""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

SEVERITY_ORDER: Dict[str, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

STATIC_EXTENSIONS = (
    ".js",
    ".mjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)

COMPRESSIBLE_MIME_PREFIXES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "image/svg+xml",
)

STATIC_MIME_PREFIXES = (
    "text/css",
    "application/javascript",
    "application/x-javascript",
    "image/",
    "font/",
    "application/font-",
)

COMPRESSED_ENCODINGS = ("gzip", "br", "zstd", "deflate")


@dataclass
class HarEntry:
    method: str
    url: str
    host: str
    path: str
    endpoint: str
    status: int
    ttfb_ms: float
    total_ms: float
    body_bytes: int
    content_type: str
    content_encoding: str
    cache_control: str
    location: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    endpoint: str
    url: str
    detail: str


@dataclass
class LatencyStats:
    count: int
    p50_ttfb_ms: float
    p95_ttfb_ms: float
    p99_ttfb_ms: float
    p50_total_ms: float
    p95_total_ms: float
    p99_total_ms: float
    avg_total_ms: float
    error_count: int
    total_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "p50_ttfb_ms": round(self.p50_ttfb_ms, 2),
            "p95_ttfb_ms": round(self.p95_ttfb_ms, 2),
            "p99_ttfb_ms": round(self.p99_ttfb_ms, 2),
            "p50_total_ms": round(self.p50_total_ms, 2),
            "p95_total_ms": round(self.p95_total_ms, 2),
            "p99_total_ms": round(self.p99_total_ms, 2),
            "avg_total_ms": round(self.avg_total_ms, 2),
            "error_count": self.error_count,
            "total_bytes": self.total_bytes,
        }


@dataclass
class AnalysisResult:
    source: str
    summary: LatencyStats
    hosts: Dict[str, LatencyStats]
    endpoints: Dict[str, LatencyStats]
    findings: List[Finding] = field(default_factory=list)

    def max_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    def should_fail(self, fail_on: str) -> bool:
        threshold = SEVERITY_ORDER.get(fail_on, 0)
        if threshold == 0:
            return False
        return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "summary": self.summary.to_dict(),
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "endpoint": f.endpoint,
                    "url": f.url,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
        }


def percentile(values: List[float], pct: float) -> float:
    """Compute linear-interpolated percentile (0..100) on a list of floats."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_vals[int(k)])
    return float(sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f]))


def _extract_headers(headers: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not isinstance(headers, list):
        return result
    for item in headers:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip().lower()
            value = str(item.get("value", "")).strip()
            if name:
                result[name] = value
    return result


def _safe_ms(val: Any) -> float:
    try:
        num = float(val)
        return num if num >= 0 else 0.0
    except (TypeError, ValueError):
        return 0.0


def _safe_int(val: Any) -> int:
    try:
        num = int(val)
        return num if num >= 0 else 0
    except (TypeError, ValueError):
        return 0


def parse_har_file(path: Path) -> List[HarEntry]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "log" not in raw:
        raise ValueError(f"Invalid HAR file (missing 'log' object): {path}")
    entries_raw = raw["log"].get("entries", [])
    if not isinstance(entries_raw, list):
        raise ValueError(f"Invalid HAR file ('log.entries' must be a list): {path}")

    entries: List[HarEntry] = []
    for item in entries_raw:
        if not isinstance(item, dict):
            continue
        req = item.get("request", {}) or {}
        resp = item.get("response", {}) or {}
        timings = item.get("timings", {}) or {}

        method = str(req.get("method", "GET")).upper()
        url = str(req.get("url", ""))
        parsed = urlparse(url)
        host = parsed.netloc or "unknown"
        path_part = parsed.path or "/"
        endpoint = f"{method} {path_part}"

        status = _safe_int(resp.get("status", 0))
        ttfb_ms = _safe_ms(timings.get("wait", 0.0))
        total_ms = _safe_ms(item.get("time", 0.0))
        if total_ms == 0.0 and ttfb_ms > 0.0:
            total_ms = ttfb_ms + _safe_ms(timings.get("receive", 0.0))

        resp_headers = _extract_headers(resp.get("headers", []))
        content = resp.get("content", {}) or {}
        content_type = str(
            resp_headers.get("content-type") or content.get("mimeType") or ""
        ).lower()
        content_encoding = str(resp_headers.get("content-encoding", "")).lower()
        cache_control = str(resp_headers.get("cache-control", "")).lower()
        location = str(resp_headers.get("location", ""))

        body_bytes = _safe_int(resp.get("bodySize", -1))
        if body_bytes == 0:
            body_bytes = _safe_int(content.get("size", 0))

        entries.append(
            HarEntry(
                method=method,
                url=url,
                host=host,
                path=path_part,
                endpoint=endpoint,
                status=status,
                ttfb_ms=ttfb_ms,
                total_ms=total_ms,
                body_bytes=body_bytes,
                content_type=content_type,
                content_encoding=content_encoding,
                cache_control=cache_control,
                location=location,
            )
        )
    return entries


def compute_stats(entries: List[HarEntry]) -> LatencyStats:
    if not entries:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0)
    ttfbs = [e.ttfb_ms for e in entries]
    totals = [e.total_ms for e in entries]
    errors = sum(1 for e in entries if e.status >= 400)
    total_bytes = sum(e.body_bytes for e in entries)
    return LatencyStats(
        count=len(entries),
        p50_ttfb_ms=percentile(ttfbs, 50),
        p95_ttfb_ms=percentile(ttfbs, 95),
        p99_ttfb_ms=percentile(ttfbs, 99),
        p50_total_ms=percentile(totals, 50),
        p95_total_ms=percentile(totals, 95),
        p99_total_ms=percentile(totals, 99),
        avg_total_ms=sum(totals) / len(totals),
        error_count=errors,
        total_bytes=total_bytes,
    )


def _is_static_asset(entry: HarEntry) -> bool:
    lower_path = entry.path.lower()
    if any(lower_path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return True
    return any(entry.content_type.startswith(p) for p in STATIC_MIME_PREFIXES)


def _is_compressible(entry: HarEntry) -> bool:
    if not entry.content_type:
        return entry.path.lower().endswith((".js", ".css", ".html", ".json", ".svg", ".xml"))
    return any(entry.content_type.startswith(p) for p in COMPRESSIBLE_MIME_PREFIXES)


def analyze_entries(
    entries: List[HarEntry],
    source: str = "<memory>",
    slow_ms: float = 500.0,
    large_kb: float = 50.0,
) -> AnalysisResult:
    summary = compute_stats(entries)

    by_host: Dict[str, List[HarEntry]] = defaultdict(list)
    by_endpoint: Dict[str, List[HarEntry]] = defaultdict(list)
    for e in entries:
        by_host[e.host].append(e)
        by_endpoint[e.endpoint].append(e)

    host_stats = {h: compute_stats(lst) for h, lst in sorted(by_host.items())}
    endpoint_stats = {
        ep: compute_stats(lst)
        for ep, lst in sorted(by_endpoint.items(), key=lambda kv: -compute_stats(kv[1]).p95_total_ms)
    }

    findings: List[Finding] = []
    large_bytes = int(large_kb * 1024)

    # HAR001: 4xx/5xx errors
    for e in entries:
        if e.status >= 500:
            findings.append(
                Finding(
                    rule_id="HAR001",
                    severity="critical",
                    title=f"HTTP {e.status} Server Error",
                    endpoint=e.endpoint,
                    url=e.url,
                    detail=f"Server returned {e.status} in {e.total_ms:.1f}ms",
                )
            )
        elif e.status >= 400:
            findings.append(
                Finding(
                    rule_id="HAR001",
                    severity="high",
                    title=f"HTTP {e.status} Client Error",
                    endpoint=e.endpoint,
                    url=e.url,
                    detail=f"Request failed with status {e.status} in {e.total_ms:.1f}ms",
                )
            )

    # HAR002: Slow API / request calls (> slow_ms)
    for e in entries:
        if e.total_ms > slow_ms:
            sev = "high" if e.total_ms > slow_ms * 3 else "medium"
            findings.append(
                Finding(
                    rule_id="HAR002",
                    severity=sev,
                    title=f"Slow request (>{slow_ms:.0f}ms)",
                    endpoint=e.endpoint,
                    url=e.url,
                    detail=f"Total {e.total_ms:.1f}ms (TTFB {e.ttfb_ms:.1f}ms)",
                )
            )

    # HAR003: Large uncompressed payloads (> large_kb without gzip/br/zstd/deflate)
    for e in entries:
        if (
            e.body_bytes > large_bytes
            and _is_compressible(e)
            and not any(enc in e.content_encoding for enc in COMPRESSED_ENCODINGS)
        ):
            findings.append(
                Finding(
                    rule_id="HAR003",
                    severity="medium",
                    title=f"Large uncompressed payload (>{large_kb:.0f}KB)",
                    endpoint=e.endpoint,
                    url=e.url,
                    detail=f"{e.body_bytes / 1024:.1f}KB without gzip/br encoding ({e.content_type or 'unknown'})",
                )
            )

    # HAR004: Duplicate / N+1 identical requests
    req_counts = Counter((e.method, e.url) for e in entries)
    for (method, url), count in req_counts.items():
        if count >= 2:
            parsed = urlparse(url)
            ep = f"{method} {parsed.path or '/'}"
            sev = "high" if count >= 4 else "medium"
            findings.append(
                Finding(
                    rule_id="HAR004",
                    severity=sev,
                    title=f"Duplicate / N+1 request ({count}x)",
                    endpoint=ep,
                    url=url,
                    detail=f"Identical {method} {url} executed {count} times",
                )
            )

    # HAR005: Redirect chains (3xx responses)
    redirect_entries = [e for e in entries if 300 <= e.status < 400]
    for e in redirect_entries:
        findings.append(
            Finding(
                rule_id="HAR005",
                severity="low",
                title=f"HTTP {e.status} Redirect",
                endpoint=e.endpoint,
                url=e.url,
                detail=f"Redirects to {e.location or '<unknown>'} ({e.total_ms:.1f}ms)",
            )
        )

    # HAR006: Missing Cache-Control on static assets
    for e in entries:
        if 200 <= e.status < 300 and _is_static_asset(e) and not e.cache_control:
            findings.append(
                Finding(
                    rule_id="HAR006",
                    severity="low",
                    title="Missing Cache-Control on static asset",
                    endpoint=e.endpoint,
                    url=e.url,
                    detail=f"Static asset ({e.content_type or e.path}) has no Cache-Control header",
                )
            )

    return AnalysisResult(
        source=source,
        summary=summary,
        hosts=host_stats,
        endpoints=endpoint_stats,
        findings=findings,
    )


def analyze_har_file(
    path: Path,
    slow_ms: float = 500.0,
    large_kb: float = 50.0,
) -> AnalysisResult:
    entries = parse_har_file(path)
    return analyze_entries(entries, source=str(path), slow_ms=slow_ms, large_kb=large_kb)


def diff_analyses(baseline: AnalysisResult, target: AnalysisResult) -> Dict[str, Any]:
    b = baseline.summary
    t = target.summary

    def _delta(new_val: float, old_val: float) -> float:
        return round(new_val - old_val, 2)

    all_endpoints = sorted(set(baseline.endpoints.keys()) | set(target.endpoints.keys()))
    endpoint_diffs: List[Dict[str, Any]] = []
    for ep in all_endpoints:
        bs = baseline.endpoints.get(ep)
        ts = target.endpoints.get(ep)
        b_p95 = bs.p95_total_ms if bs else 0.0
        t_p95 = ts.p95_total_ms if ts else 0.0
        b_ttfb = bs.p95_ttfb_ms if bs else 0.0
        t_ttfb = ts.p95_ttfb_ms if ts else 0.0
        endpoint_diffs.append(
            {
                "endpoint": ep,
                "baseline_p95_ms": round(b_p95, 2),
                "target_p95_ms": round(t_p95, 2),
                "delta_p95_ms": _delta(t_p95, b_p95),
                "baseline_p95_ttfb_ms": round(b_ttfb, 2),
                "target_p95_ttfb_ms": round(t_ttfb, 2),
                "delta_p95_ttfb_ms": _delta(t_ttfb, b_ttfb),
            }
        )

    endpoint_diffs.sort(key=lambda d: -abs(d["delta_p95_ms"]))

    return {
        "baseline": baseline.source,
        "target": target.source,
        "summary_diff": {
            "requests_delta": t.count - b.count,
            "errors_delta": t.error_count - b.error_count,
            "p50_ttfb_delta_ms": _delta(t.p50_ttfb_ms, b.p50_ttfb_ms),
            "p95_ttfb_delta_ms": _delta(t.p95_ttfb_ms, b.p95_ttfb_ms),
            "p50_total_delta_ms": _delta(t.p50_total_ms, b.p50_total_ms),
            "p95_total_delta_ms": _delta(t.p95_total_ms, b.p95_total_ms),
            "p99_total_delta_ms": _delta(t.p99_total_ms, b.p99_total_ms),
            "bytes_delta": t.total_bytes - b.total_bytes,
            "findings_delta": len(target.findings) - len(baseline.findings),
        },
        "endpoint_diffs": endpoint_diffs,
        "target_findings": target.to_dict()["findings"],
    }


def format_analysis_markdown(result: AnalysisResult, top: int = 15) -> str:
    s = result.summary
    lines = [
        f"# HAR Latency Waterfall Report: `{result.source}`",
        "",
        "## Summary",
        f"- **Requests:** {s.count} | **Errors (4xx/5xx):** {s.error_count} | **Total Size:** {s.total_bytes / 1024:.1f} KB",
        f"- **TTFB (ms):** p50={s.p50_ttfb_ms:.1f} | p95={s.p95_ttfb_ms:.1f} | p99={s.p99_ttfb_ms:.1f}",
        f"- **Total (ms):** p50={s.p50_total_ms:.1f} | p95={s.p95_total_ms:.1f} | p99={s.p99_total_ms:.1f}",
        f"- **Findings:** {len(result.findings)} (max severity: `{result.max_severity()}`)",
        "",
        "## Top Endpoints by p95 Total Latency",
        "| Endpoint | Count | Errors | p50 TTFB | p95 TTFB | p50 Total | p95 Total | p99 Total |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for ep, st in list(result.endpoints.items())[:top]:
        lines.append(
            f"| `{ep}` | {st.count} | {st.error_count} | {st.p50_ttfb_ms:.1f}ms | {st.p95_ttfb_ms:.1f}ms | "
            f"{st.p50_total_ms:.1f}ms | {st.p95_total_ms:.1f}ms | {st.p99_total_ms:.1f}ms |"
        )

    if result.findings:
        lines.extend(["", "## Findings", "| Rule | Severity | Endpoint | Detail |", "|---|---|---|---|"])
        for f in result.findings:
            lines.append(f"| `{f.rule_id}` | `{f.severity}` | `{f.endpoint}` | {f.detail} |")
    else:
        lines.extend(["", "## Findings", "No performance or reliability issues detected."])

    return "\n".join(lines) + "\n"


def format_diff_markdown(diff_data: Dict[str, Any], top: int = 15) -> str:
    sd = diff_data["summary_diff"]
    lines = [
        f"# HAR Regression Diff: `{diff_data['baseline']}` -> `{diff_data['target']}`",
        "",
        "## Summary Delta",
        f"- **Requests Delta:** {sd['requests_delta']:+d} | **Errors Delta:** {sd['errors_delta']:+d}",
        f"- **p95 TTFB Delta:** {sd['p95_ttfb_delta_ms']:+.2f} ms",
        f"- **p95 Total Delta:** {sd['p95_total_delta_ms']:+.2f} ms | **p99 Total Delta:** {sd['p99_total_delta_ms']:+.2f} ms",
        f"- **Transfer Size Delta:** {sd['bytes_delta'] / 1024:+.1f} KB",
        f"- **Findings Delta:** {sd['findings_delta']:+d}",
        "",
        "## Endpoint Latency Changes (Top by |p95 Delta|)",
        "| Endpoint | Baseline p95 | Target p95 | Delta p95 | Delta TTFB p95 |",
        "|---|---:|---:|---:|---:|",
    ]
    for d in diff_data["endpoint_diffs"][:top]:
        lines.append(
            f"| `{d['endpoint']}` | {d['baseline_p95_ms']:.1f}ms | {d['target_p95_ms']:.1f}ms | "
            f"{d['delta_p95_ms']:+.1f}ms | {d['delta_p95_ttfb_ms']:+.1f}ms |"
        )
    return "\n".join(lines) + "\n"
