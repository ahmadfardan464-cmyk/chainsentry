"""Data models used across the scanner and reporters.

Kept dependency-free so detectors can import without circular issues.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    detector: str
    severity: str
    line: int
    column: int
    snippet: str
    message: str
    fix: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    file: str
    findings: list[Finding] = field(default_factory=list)
    detector_count: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "detector_count": self.detector_count,
            "duration_ms": self.duration_ms,
            "findings": [f.to_dict() for f in self.findings],
        }

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
