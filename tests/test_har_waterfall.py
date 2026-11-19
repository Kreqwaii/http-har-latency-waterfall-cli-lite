import json
import tempfile
import unittest
from pathlib import Path

from har_waterfall_lite.analyzer import (
    HarEntry,
    analyze_entries,
    analyze_har_file,
    compute_stats,
    diff_analyses,
    format_analysis_markdown,
    format_diff_markdown,
    parse_har_file,
    percentile,
)
from har_waterfall_lite.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"


def _make_entry(
    method: str = "GET",
    url: str = "https://api.example.com/v1/items",
    status: int = 200,
    ttfb_ms: float = 50.0,
    total_ms: float = 100.0,
    body_bytes: int = 1024,
    content_type: str = "application/json",
    content_encoding: str = "gzip",
    cache_control: str = "",
    location: str = "",
) -> HarEntry:
    return HarEntry(
        method=method,
        url=url,
        host="api.example.com",
        path="/v1/items",
        endpoint=f"{method} /v1/items",
        status=status,
        ttfb_ms=ttfb_ms,
        total_ms=total_ms,
        body_bytes=body_bytes,
        content_type=content_type,
        content_encoding=content_encoding,
        cache_control=cache_control,
        location=location,
    )


class TestPercentilesAndStats(unittest.TestCase):
    def test_percentile_empty(self):
        self.assertEqual(percentile([], 50), 0.0)

    def test_percentile_single(self):
        self.assertEqual(percentile([42.5], 95), 42.5)

    def test_percentile_interpolation(self):
        vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertEqual(percentile(vals, 50), 30.0)
        self.assertAlmostEqual(percentile(vals, 95), 48.0, places=2)
        self.assertAlmostEqual(percentile(vals, 99), 49.6, places=2)

    def test_compute_stats_empty(self):
        st = compute_stats([])
        self.assertEqual(st.count, 0)
        self.assertEqual(st.error_count, 0)

    def test_compute_stats_values(self):
        entries = [
            _make_entry(ttfb_ms=20.0, total_ms=100.0, body_bytes=500, status=200),
            _make_entry(ttfb_ms=40.0, total_ms=200.0, body_bytes=1500, status=500),
        ]
        st = compute_stats(entries)
        self.assertEqual(st.count, 2)
        self.assertEqual(st.error_count, 1)
        self.assertEqual(st.total_bytes, 2000)
        self.assertEqual(st.avg_total_ms, 150.0)
        self.assertEqual(st.p50_ttfb_ms, 30.0)


class TestHarParsing(unittest.TestCase):
    def test_parse_valid_baseline_sample(self):
        entries = parse_har_file(SAMPLES_DIR / "baseline.har")
        self.assertEqual(len(entries), 4)
        self.assertEqual(entries[0].host, "app.example.com")

    def test_parse_invalid_missing_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.har"
            p.write_text('{"not_log": {}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_har_file(p)

    def test_parse_invalid_entries_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad2.har"
            p.write_text('{"log": {"entries": "nope"}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_har_file(p)

    def test_negative_timings_clamped_to_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "neg.har"
            p.write_text(
                json.dumps(
                    {
                        "log": {
                            "entries": [
                                {
                                    "request": {"method": "GET", "url": "https://a.com/x"},
                                    "response": {"status": 200, "bodySize": -1, "content": {"size": 256}},
                                    "time": -1,
                                    "timings": {"wait": -1},
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            entries = parse_har_file(p)
            self.assertEqual(entries[0].ttfb_ms, 0.0)
            self.assertEqual(entries[0].total_ms, 0.0)
            self.assertEqual(entries[0].body_bytes, 256)


class TestRules(unittest.TestCase):
    def test_har001_4xx_high(self):
        res = analyze_entries([_make_entry(status=404)])
        rules = [f for f in res.findings if f.rule_id == "HAR001"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].severity, "high")

    def test_har001_5xx_critical(self):
        res = analyze_entries([_make_entry(status=503)])
        rules = [f for f in res.findings if f.rule_id == "HAR001"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].severity, "critical")

    def test_har002_slow_medium_and_high(self):
        res = analyze_entries([_make_entry(total_ms=650.0), _make_entry(url="https://api.example.com/v1/other", total_ms=1800.0)], slow_ms=500.0)
        rules = [f for f in res.findings if f.rule_id == "HAR002"]
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].severity, "medium")
        self.assertEqual(rules[1].severity, "high")

    def test_har003_large_uncompressed(self):
        res = analyze_entries([_make_entry(body_bytes=60 * 1024, content_encoding="")])
        rules = [f for f in res.findings if f.rule_id == "HAR003"]
        self.assertEqual(len(rules), 1)

    def test_har003_compressed_ignored(self):
        res = analyze_entries([_make_entry(body_bytes=60 * 1024, content_encoding="br")])
        rules = [f for f in res.findings if f.rule_id == "HAR003"]
        self.assertEqual(len(rules), 0)

    def test_har003_binary_image_ignored(self):
        res = analyze_entries([_make_entry(body_bytes=120 * 1024, content_type="image/png", content_encoding="", cache_control="max-age=3600")])
        rules = [f for f in res.findings if f.rule_id == "HAR003"]
        self.assertEqual(len(rules), 0)

    def test_har004_duplicate_2x_and_4x(self):
        e1 = _make_entry(url="https://api.example.com/v1/dup")
        res2 = analyze_entries([e1, e1])
        self.assertEqual([f for f in res2.findings if f.rule_id == "HAR004"][0].severity, "medium")

        res4 = analyze_entries([e1, e1, e1, e1])
        self.assertEqual([f for f in res4.findings if f.rule_id == "HAR004"][0].severity, "high")

    def test_har005_redirect(self):
        res = analyze_entries([_make_entry(status=301, location="https://api.example.com/new")])
        rules = [f for f in res.findings if f.rule_id == "HAR005"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].severity, "low")

    def test_har006_static_missing_cache_control(self):
        e = _make_entry(url="https://cdn.example.com/app.js", content_type="application/javascript", cache_control="")
        res = analyze_entries([e])
        rules = [f for f in res.findings if f.rule_id == "HAR006"]
        self.assertEqual(len(rules), 1)

    def test_har006_static_with_cache_control_ok(self):
        e = _make_entry(url="https://cdn.example.com/app.js", content_type="application/javascript", cache_control="public, max-age=31536000")
        res = analyze_entries([e])
        rules = [f for f in res.findings if f.rule_id == "HAR006"]
        self.assertEqual(len(rules), 0)


class TestSamplesAndDiff(unittest.TestCase):
    def test_baseline_sample_clean(self):
        res = analyze_har_file(SAMPLES_DIR / "baseline.har")
        self.assertEqual(len(res.findings), 0)
        self.assertEqual(res.max_severity(), "none")

    def test_regressed_sample_triggers_all_six_rules(self):
        res = analyze_har_file(SAMPLES_DIR / "regressed.har")
        rule_ids = {f.rule_id for f in res.findings}
        self.assertEqual(rule_ids, {"HAR001", "HAR002", "HAR003", "HAR004", "HAR005", "HAR006"})

    def test_diff_analyses_deltas(self):
        base = analyze_har_file(SAMPLES_DIR / "baseline.har")
        reg = analyze_har_file(SAMPLES_DIR / "regressed.har")
        d = diff_analyses(base, reg)
        self.assertEqual(d["summary_diff"]["requests_delta"], 2)
        self.assertEqual(d["summary_diff"]["errors_delta"], 1)
        self.assertGreater(d["summary_diff"]["p95_total_delta_ms"], 0)
        self.assertGreater(len(d["endpoint_diffs"]), 0)

    def test_markdown_and_json_formatters(self):
        res = analyze_har_file(SAMPLES_DIR / "regressed.har")
        md = format_analysis_markdown(res)
        self.assertIn("# HAR Latency Waterfall Report", md)
        self.assertIn("HAR001", md)
        d_json = json.dumps(res.to_dict())
        self.assertIn("summary", d_json)

        diff_md = format_diff_markdown(diff_analyses(analyze_har_file(SAMPLES_DIR / "baseline.har"), res))
        self.assertIn("# HAR Regression Diff", diff_md)


class TestCLI(unittest.TestCase):
    def test_cli_analyze_json_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            code = main(["analyze", str(SAMPLES_DIR / "baseline.har"), "--format", "json", "-o", str(out)])
            self.assertEqual(code, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["count"], 4)

    def test_cli_analyze_fail_on_exit_1(self):
        code = main(["analyze", str(SAMPLES_DIR / "regressed.har"), "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_cli_analyze_fail_on_none_exit_0(self):
        code = main(["analyze", str(SAMPLES_DIR / "regressed.har"), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_cli_diff_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "diff.md"
            code = main([
                "diff",
                str(SAMPLES_DIR / "baseline.har"),
                str(SAMPLES_DIR / "regressed.har"),
                "-o",
                str(out),
                "--fail-on",
                "critical",
            ])
            self.assertEqual(code, 1)
            self.assertIn("HAR Regression Diff", out.read_text(encoding="utf-8"))

    def test_cli_missing_file_returns_2(self):
        code = main(["analyze", str(SAMPLES_DIR / "does_not_exist.har")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
