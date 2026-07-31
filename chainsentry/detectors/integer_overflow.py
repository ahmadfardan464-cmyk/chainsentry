"""Integer overflow / underflow detector (legacy Solidity <0.8)."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
SOLC_08 = re.compile(r"\b0\.8\.")
UNSAFE_MATH_RE = re.compile(r"\b(?:SafeMath|using\s+SafeMath|safeMath)\b", re.IGNORECASE)


class IntegerOverflowDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="integer-overflow",
            name="Integer overflow / underflow (pre-0.8 Solidity)",
            severity="medium",
            description="Arithmetic without SafeMath in Solidity <0.8 silently wraps.",
            references=[
                "https://swcregistry.io/docs/SWC-101",
                "https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html#silent-overflow-checks",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        # Skip if pragma is >= 0.8 OR SafeMath is used.
        pragma_m = PRAGMA_RE.search(source)
        if not pragma_m:
            return findings
        pragma = pragma_m.group(1)
        if SOLC_08.search(pragma):
            return findings
        if UNSAFE_MATH_RE.search(source):
            return findings
        # Note the version.
        for i, line in enumerate(source_lines, 1):
            if "pragma solidity" in line:
                findings.append(self._make_finding(
                    line=i,
                    column=1,
                    snippet=line.strip(),
                    message=f"Contract compiles with Solidity {pragma.strip()} (<0.8) — no built-in overflow check.",
                    fix=(
                        "Upgrade to Solidity >=0.8 (built-in checked arithmetic). "
                        "If you must stay on 0.4-0.7, import `using SafeMath for uint256;` "
                        "and use `.add/.sub/.mul/.div` everywhere you do arithmetic."
                    ),
                ))
                break
        return findings
