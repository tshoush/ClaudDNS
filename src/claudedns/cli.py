"""Command-line interface: ``claudedns analyze <file>``."""

from __future__ import annotations

import argparse
import json
import sys

from .analyze import Summary, summarize
from .bind import read_bind
from .dnstap import read_dnstap
from .formats import detect_format
from .records import ParseStats


def _print_text(fmt: str, summary: Summary) -> None:
    print(f"format:          {fmt}")
    print(f"queries:         {summary.total_queries}")
    print(f"skipped frames:  {summary.skipped}")
    if summary.avg_qps is not None:
        print(f"avg qps:         {summary.avg_qps}")
        print(f"peak qps:        {summary.peak_qps}")
    else:
        print("rates:           unavailable (no timestamps in input)")

    for title, rows in (
        ("top domains", summary.top_domains),
        ("top clients", summary.top_clients),
        ("query types", summary.query_types),
    ):
        print(f"\n{title}:")
        for name, count in rows:
            print(f"  {count:>10}  {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="claudedns", description="DNS traffic analysis")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="summarize query traffic from a capture or log")
    analyze.add_argument("path", help="dnstap capture or BIND-style query log")
    analyze.add_argument(
        "--format",
        choices=["auto", "dnstap", "bind"],
        default="auto",
        help="input format (default: auto-detect)",
    )
    analyze.add_argument("--top", type=int, default=10, help="rows per top-N table")
    analyze.add_argument("--json", action="store_true", help="emit JSON instead of text")

    args = parser.parse_args(argv)

    try:
        fmt = detect_format(args.path) if args.format == "auto" else args.format
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    stats = ParseStats()
    reader = read_dnstap if fmt == "dnstap" else read_bind
    try:
        with open(args.path, "rb") as f:
            summary = summarize(reader(f, stats), top=args.top)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary.skipped = stats.skipped
    if args.json:
        print(json.dumps({"format": fmt, **summary.to_dict()}, indent=2))
    else:
        _print_text(fmt, summary)
    return 0
