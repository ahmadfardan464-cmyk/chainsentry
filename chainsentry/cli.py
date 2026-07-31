"""chainsentry CLI: scan one or more Solidity files and emit findings."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from chainsentry import __version__
from chainsentry.scanner import scan_paths
from chainsentry.reporters import to_json, to_markdown, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chainsentry",
        description="Lightweight smart contract static analyzer (PoC).",
    )
    p.add_argument("paths", nargs="+", help="One or more .sol files or directories.")
    p.add_argument(
        "-f", "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "-o", "--output",
        type=Path,
        help="Write findings to this file instead of stdout.",
    )
    p.add_argument(
        "--min-severity",
        choices=("info", "low", "medium", "high", "critical"),
        default="info",
        help="Drop findings below this severity (default: info).",
    )
    p.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Exit non-zero if any finding at or above this severity is found.",
    )
    p.add_argument(
        "--list-detectors",
        action="store_true",
        help="List all registered detectors and exit.",
    )
    p.add_argument("--version", action="version", version=f"chainsentry {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_detectors:
        from chainsentry.detectors import ALL_DETECTORS
        for d in ALL_DETECTORS:
            print(f"{d.id:<22s} [{d.severity:8s}] {d.name}")
        return 0

    # Map severity -> int for filtering.
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = sev_rank[args.min_severity]
    fail_rank = sev_rank[args.fail_on] if args.fail_on != "none" else None

    # Expand paths.
    expanded: list[Path] = []
    for raw in args.paths:
        p = Path(raw)
        if p.is_dir():
            expanded.extend(sorted(p.rglob("*.sol")))
        elif p.is_file():
            expanded.append(p)
        else:
            print(f"chainsentry: not found: {raw}", file=sys.stderr)
            return 2

    if not expanded:
        print("chainsentry: no .sol files found", file=sys.stderr)
        return 2

    # Scan.
    reports = scan_paths(expanded)
    for r in reports:
        r.findings = [f for f in r.findings if sev_rank.get(f.severity, 0) >= min_rank]

    # Render.
    if args.format == "json":
        out = to_json_multi(reports)
    elif args.format == "markdown":
        out = to_markdown(reports)
    else:
        out = to_text(reports)

    if args.output:
        args.output.write_text(out, encoding="utf-8")
    else:
        print(out)

    # Exit code policy.
    if fail_rank is not None:
        for r in reports:
            for f in r.findings:
                if sev_rank.get(f.severity, 0) >= fail_rank:
                    return 1
    return 0


def to_json_multi(reports) -> str:
    """Render multiple reports as a single JSON array."""
    import json
    return json.dumps([r.to_dict() for r in reports], indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
