"""Floating pragma detector: ^ or >= in pragma solidity."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
FLOATING_RE = re.compile(r"[\^>]")


class FloatingPragmaDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="floating-pragma",
            name="Floating pragma",
            severity="low",
            description="Locking the pragma helps ensure the contract is not deployed with a different compiler than tested.",
            references=[
                "https://swcregistry.io/docs/SWC-103",
                "CWE-710",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(source_lines, 1):
            if "pragma solidity" in line:
                if FLOATING_RE.search(line):
                    findings.append(self._make_finding(
                        line=i,
                        column=1,
                        snippet=line.strip(),
                        message="Floating pragma — contract can be compiled with unintended Solidity version.",
                        fix=(
                            "Use a pinned pragma (e.g. `pragma solidity 0.8.24;`) for production. "
                            "Floating pragmas are fine for libraries and examples but not for "
                            "deployed code."
                        ),
                    ))
                break
        return findings
