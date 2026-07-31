"""Base detector class. All detectors inherit from this."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from chainsentry.models import Finding


@dataclass
class Detector(ABC):
    id: str = ""
    name: str = ""
    severity: str = "medium"
    description: str = ""
    references: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.references is None:
            self.references = []

    @abstractmethod
    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        """Run the detector on `source` (full text) and `source_lines` (split).

        Return a list of `Finding` objects. Do not raise on parse errors;
        the scanner wraps your call in try/except and continues.
        """
        raise NotImplementedError

    def _make_finding(
        self,
        line: int,
        column: int,
        snippet: str,
        message: str,
        fix: str = "",
    ) -> Finding:
        return Finding(
            detector=self.id,
            severity=self.severity,
            line=line,
            column=column,
            snippet=snippet.strip(),
            message=message,
            fix=fix,
            references=list(self.references),
        )
