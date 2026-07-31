"""Output formatters: JSON, Markdown, plain text."""
from __future__ import annotations

import json
from typing import Iterable

from chainsentry.scanner import ScanReport, SEVERITY_ORDER


SEVERITY_ICONS = {
    "critical": "🛑",
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "ℹ️",
}


def to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown(reports: Iterable[ScanReport]) -> str:
    """Render one or more reports as a Markdown report."""
    out: list[str] = []
    for report in reports:
        out.append(_md_report(report))
        out.append("")
    return "\n".join(out)


def _md_report(r: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"# chainsentry report — `{r.file}`")
    lines.append("")
    lines.append(f"**Detectors run:** {r.detector_count}  ")
    lines.append(f"**Duration:** {r.duration_ms} ms  ")
    lines.append(f"**Findings:** {len(r.findings)}")
    lines.append("")

    counts = r.by_severity()
    if any(counts.values()):
        lines.append("## Severity breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev, 0):
                lines.append(f"| {SEVERITY_ICONS.get(sev, '')} {sev} | {counts[sev]} |")
        lines.append("")

    if not r.findings:
        lines.append("✅ No findings.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for i, f in enumerate(r.findings, 1):
        lines.append(f"### {i}. [{f.severity.upper()}] {f.detector} — line {f.line}")
        lines.append("")
        lines.append(f"**{f.message}**")
        lines.append("")
        if f.snippet:
            lines.append("```solidity")
            lines.append(f.snippet)
            lines.append("```")
            lines.append("")
        if f.fix:
            lines.append(f"**Fix:** {f.fix}")
            lines.append("")
        if f.references:
            lines.append("**References:**")
            for ref in f.references:
                lines.append(f"- {ref}")
            lines.append("")
    return "\n".join(lines)


def to_text(reports: Iterable[ScanReport]) -> str:
    """One-line summary per finding, then per-file summary."""
    out: list[str] = []
    for r in reports:
        out.append(f"{r.file}: {len(r.findings)} findings ({r.detector_count} detectors, {r.duration_ms} ms)")
        for f in r.findings:
            icon = SEVERITY_ICONS.get(f.severity, "•")
            out.append(f"  {icon} {f.severity:8s}  L{f.line:<4d}  [{f.detector}] {f.message}")
    return "\n".join(out)
