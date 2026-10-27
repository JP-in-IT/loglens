"""Command-line entry point.

Usage:
    python -m loglens auth sample_logs/auth.log
    python -m loglens web sample_logs/access.log --format json
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from typing import List, Optional

from . import detectors, parsers, report


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loglens", description="Detect suspicious activity in SSH and web server logs.")
    sub = p.add_subparsers(dest="kind", required=True)

    auth = sub.add_parser("auth", help="Analyze an SSH auth log (auth.log / secure)")
    auth.add_argument("file", help="Path to the log file, or - for stdin")
    auth.add_argument("--year", type=int, help="Year for syslog timestamps (default: current year)")
    auth.add_argument("--threshold", type=_positive_int, default=5, help="Failed logins that count as brute force (default 5)")
    auth.add_argument("--window", type=_positive_int, default=5, help="Brute-force window in minutes (default 5)")

    web = sub.add_parser("web", help="Analyze a web access log (Apache/Nginx combined format)")
    web.add_argument("file", help="Path to the log file, or - for stdin")
    web.add_argument("--error-threshold", type=_positive_int, default=20, help="4xx responses that count as a burst (default 20)")

    for s in (auth, web):
        s.add_argument("--format", choices=["text", "json"], default="text")
        s.add_argument("--no-evidence", action="store_true", help="Hide raw log lines in text output")
        s.add_argument(
            "--min-severity",
            choices=["low", "medium", "high", "critical"],
            default="low",
            help="Only show findings at or above this severity",
        )
    return p


def _read_lines(path: str) -> List[str]:
    if path == "-":
        return sys.stdin.readlines()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        lines = _read_lines(args.file)
    except OSError as exc:
        print(f"loglens: cannot read {args.file}: {exc.strerror}", file=sys.stderr)
        return 2

    if args.kind == "auth":
        events = list(parsers.parse_auth_log(lines, year=args.year))
        findings = (
            detectors.detect_brute_force(events, threshold=args.threshold, window=timedelta(minutes=args.window))
            + detectors.detect_user_enumeration(events)
            + detectors.detect_success_after_failures(events)
        )
    else:
        events = list(parsers.parse_web_log(lines))
        findings = (
            detectors.detect_web_attacks(events)
            + detectors.detect_scanners(events)
            + detectors.detect_error_bursts(events, threshold=args.error_threshold)
        )

    cutoff = detectors.SEVERITY_ORDER[args.min_severity]
    findings = [f for f in detectors.sort_findings(findings) if detectors.SEVERITY_ORDER[f.severity] <= cutoff]

    if args.format == "json":
        print(report.to_json(findings))
    else:
        print(f"Parsed {len(events)} event(s) from {len(lines)} line(s).\n")
        print(report.to_text(findings, show_evidence=not args.no_evidence), end="")

    # Non-zero exit when something high or critical turns up, so the tool can gate a script or CI job.
    return 1 if any(detectors.SEVERITY_ORDER[f.severity] <= 1 for f in findings) else 0
