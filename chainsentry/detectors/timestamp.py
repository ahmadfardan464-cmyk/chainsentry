"""Timestamp dependence detector: block.timestamp or now in risky arithmetic."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


# Match block.timestamp or now when used in a comparison or arithmetic.
TIMESTAMP_RE = re.compile(r"\b(?:block\.timestamp|now)\b")
RISKY_OPS_RE = re.compile(
    r"(?:==|!=|<=|>=|<|>|"
    r"\+|-|\*|/|\%|"
    r"require\s*\(|assert\s*\()",
)


class TimestampDependenceDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="timestamp-dependence",
            name="Block timestamp dependence",
            severity="medium",
            description="block.timestamp can be influenced by miners/validators within bounds.",
            references=[
                "https://swcregistry.io/docs/SWC-116",
                "https://docs.soliditylang.org/en/latest/security-considerations.html#block-timestamp",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(source_lines, 1):
            if TIMESTAMP_RE.search(line) and RISKY_OPS_RE.search(line):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                findings.append(self._make_finding(
                    line=i,
                    column=line.find("block.timestamp") + 1 if "block.timestamp" in line else line.find("now") + 1,
                    snippet=line.rstrip(),
                    message="`block.timestamp` (or `now`) used in arithmetic/comparison — manipulators can shift within ~15s.",
                    fix=(
                        "Don't use block.timestamp for randomness or strict equality comparisons. "
                        "Block numbers are monotonic and use `block.number` for ordering. "
                        "For time-dependent logic, accept a margin (e.g., 1-2 minutes) "
                        "or use a Chainlink oracle."
                    ),
                ))
        return findings
