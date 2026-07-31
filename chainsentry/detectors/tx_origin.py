"""tx.origin detector: auth check using tx.origin (always phishable)."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.scanner import Finding


# Look for `tx.origin == ...` or `require(tx.origin ...)`.
TX_ORIGIN_RE = re.compile(r"tx\.origin", re.MULTILINE)


class TxOriginDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="tx-origin",
            name="tx.origin for authentication",
            severity="high",
            description="tx.origin is phishable by intermediate contracts. Use msg.sender.",
            references=[
                "https://swcregistry.io/docs/SWC-115",
                "https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin",
                "CWE-284",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(source_lines, 1):
            if TX_ORIGIN_RE.search(line):
                # Skip if the line is purely a comment.
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                findings.append(self._make_finding(
                    line=i,
                    column=line.find("tx.origin") + 1,
                    snippet=line.rstrip(),
                    message="`tx.origin` used — phishable via malicious intermediate contract.",
                    fix=(
                        "Use `msg.sender` for authentication. If you need to know if the caller is "
                        "an EOA, use `msg.sender == tx.origin` AFTER checking msg.sender == owner, "
                        "but the safer pattern is to require msg.sender and never trust tx.origin."
                    ),
                ))
        return findings
