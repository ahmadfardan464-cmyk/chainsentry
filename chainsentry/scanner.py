"""Core scanner: dispatches source files to all registered detectors.

Stdlib-only. No solc, slither, or mythril required — works directly on
Solidity source text. This is intentional for the PoC: zero install, runs
in <1 second, and ships with reproducible findings that the ESP grant
proposal can demo today.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable

from chainsentry.models import Finding, ScanReport, SEVERITY_ORDER
from chainsentry.detectors import ALL_DETECTORS


def scan_file(path: str | Path) -> ScanReport:
    """Scan a single .sol file. Returns a ScanReport."""
    path = Path(path)
    source = path.read_text(encoding="utf-8", errors="replace")
    return scan_source(source, str(path))


def scan_source(source: str, filename: str = "<source>") -> ScanReport:
    """Scan an in-memory source string. Returns a ScanReport."""
    start = time.perf_counter()

    source_lines = source.splitlines()
    findings: list[Finding] = []

    for detector in ALL_DETECTORS:
        try:
            results = detector.scan(source, source_lines)
        except Exception as exc:  # noqa: BLE001 — detector should not crash scan
            findings.append(Finding(
                detector=detector.id,
                severity="info",
                line=0,
                column=0,
                snippet="",
                message=f"Detector {detector.id} crashed: {exc!r}",
            ))
            continue
        findings.extend(results)

    # Sort: severity desc, then line asc.
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.line, f.column))

    duration_ms = int((time.perf_counter() - start) * 1000)
    return ScanReport(
        file=filename,
        findings=findings,
        detector_count=len(ALL_DETECTORS),
        duration_ms=duration_ms,
    )


def scan_paths(paths: Iterable[str | Path]) -> list[ScanReport]:
    """Scan multiple files. Returns one report per file."""
    reports: list[ScanReport] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for sol in sorted(p.rglob("*.sol")):
                reports.append(scan_file(sol))
        elif p.is_file():
            reports.append(scan_file(p))
        else:
            raise FileNotFoundError(p)
    return reports
