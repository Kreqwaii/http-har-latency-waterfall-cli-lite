"""CLI interface for http-har-latency-waterfall-cli-lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .analyzer import (
    SEVERITY_ORDER,
    analyze_har_file,
    diff_analyses,
    format_analysis_markdown,
    format_diff_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="har-waterfall-lite",
        description="Fast offline HTTP Archive (.har) performance & regression analyzer.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze a single .har capture")
    p_analyze.add_argument("har_file", type=Path, help="Path to .har file")
    p_analyze.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    p_analyze.add_argument("-o", "--output", type=Path, default=None, help="Write report to file")
    p_analyze.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER.keys()),
        default="none",
        help="Exit with code 1 if any finding meets or exceeds this severity",
    )
    p_analyze.add_argument("--slow-ms", type=float, default=500.0, help="Slow request threshold in ms (default: 500)")
    p_analyze.add_argument("--large-kb", type=float, default=50.0, help="Large uncompressed payload threshold in KB (default: 50)")
    p_analyze.add_argument("--top", type=int, default=15, help="Max endpoints to show in Markdown table")

    # diff
    p_diff = subparsers.add_parser("diff", help="Compare baseline .har against target .har")
    p_diff.add_argument("baseline_har", type=Path, help="Path to baseline .har file")
    p_diff.add_argument("target_har", type=Path, help="Path to target/regressed .har file")
    p_diff.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    p_diff.add_argument("-o", "--output", type=Path, default=None, help="Write diff report to file")
    p_diff.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER.keys()),
        default="none",
        help="Exit with code 1 if target has any finding >= this severity",
    )
    p_diff.add_argument("--slow-ms", type=float, default=500.0, help="Slow request threshold in ms (default: 500)")
    p_diff.add_argument("--large-kb", type=float, default=50.0, help="Large uncompressed payload threshold in KB (default: 50)")
    p_diff.add_argument("--top", type=int, default=15, help="Max endpoints to show in Markdown table")

    return parser


def _write_output(text: str, output_path: Optional[Path]) -> None:
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "analyze":
            result = analyze_har_file(args.har_file, slow_ms=args.slow_ms, large_kb=args.large_kb)
            if args.format == "json":
                rendered = json.dumps(result.to_dict(), indent=2) + "\n"
            else:
                rendered = format_analysis_markdown(result, top=args.top)
            _write_output(rendered, args.output)
            return 1 if result.should_fail(args.fail_on) else 0

        if args.command == "diff":
            base_res = analyze_har_file(args.baseline_har, slow_ms=args.slow_ms, large_kb=args.large_kb)
            targ_res = analyze_har_file(args.target_har, slow_ms=args.slow_ms, large_kb=args.large_kb)
            diff_data = diff_analyses(base_res, targ_res)
            if args.format == "json":
                rendered = json.dumps(diff_data, indent=2) + "\n"
            else:
                rendered = format_diff_markdown(diff_data, top=args.top)
            _write_output(rendered, args.output)
            return 1 if targ_res.should_fail(args.fail_on) else 0

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
