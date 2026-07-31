"""Output formatters: JSON, Markdown, plain text, SARIF."""
from __future__ import annotations

import json
import uuid
from typing import Iterable

from chainsentry.scanner import ScanReport, SEVERITY_ORDER


SEVERITY_ICONS = {
    "critical": "🛑",
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "ℹ️",
}

# SARIF severity mapping (chainsentry → SARIF level).
SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

TOOL_INFO = {
    "name": "chainsentry",
    "version": "0.1.0",
    "informationUri": "https://github.com/ahmardan464-cmyk/chainsentry",
    "semanticVersion": "0.1.0",
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


def to_sarif(reports: Iterable[ScanReport]) -> str:
    """Render one or more reports in SARIF 2.1.0 (Static Analysis Results Interchange Format).

    GitHub code scanning natively ingests SARIF, so this format lets
    chainsentry output be triaged in PR diffs / Security tab / branch
    protection checks.

    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    runs: list[dict] = []

    # Build a stable, deduped rules[] entry per detector ID across all reports
    # so the SARIF output stays compact.
    rules_seen: dict[str, dict] = {}

    for r in reports:
        results: list[dict] = []
        for f in r.findings:
            rule_id = f.detector
            if rule_id not in rules_seen:
                rules_seen[rule_id] = _sarif_rule(rule_id, f.severity)

            results.append({
                "ruleId": rule_id,
                "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r.file},
                            "region": {
                                "startLine": max(f.line, 1),
                                "startColumn": max(f.column, 1),
                                "snippet": {"text": f.snippet} if f.snippet else None,
                            },
                        }
                    }
                ],
            })

        runs.append({
            "tool": {"driver": {**TOOL_INFO, "rules": list(rules_seen.values())}},
            "originalUriBaseIds": {
                "PROJECTROOT": {"uri": "file:///"}
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": r.scanned_at if hasattr(r, "scanned_at") else None,
                }
            ],
        })

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    return json.dumps(sarif, indent=2)


def _sarif_rule(rule_id: str, severity: str) -> dict:
    """One rules[] entry per detector ID — surfaced to GitHub as one rule."""
    level = SEVERITY_TO_SARIF_LEVEL.get(severity, "note")
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": f"chainsentry: {rule_id}"},
        "defaultConfiguration": {"level": level},
        "helpUri": f"https://github.com/ahmardan464-cmyk/chainsentry/blob/main/docs/detectors.md#{rule_id}",
        "properties": {
            "tags": ["security", "solidity", "static-analysis"],
            "precision": "medium",
        },
    }
