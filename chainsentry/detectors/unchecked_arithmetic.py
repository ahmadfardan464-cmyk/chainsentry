"""Unchecked-arithmetic detector — flag arithmetic inside `unchecked { ... }` blocks in Solidity 0.8+.

Solc 0.8+ has built-in overflow/underflow checks. Code wrapped in
`unchecked { ... }` opts out, restoring 0.7- semantics. This is fine
for gas optimization when overflow is impossible by construction, but
is a footgun in:

  * token math (balance updates that are not provably bounded)
  * loop counters that involve user-controlled input
  * cross-contract callbacks where the other side may re-enter

This detector flags `unchecked` blocks that contain arithmetic on
uint/int variables — auditors should verify the overflow impossibility.

References:
  - SWC-101: Integer Overflow and Underflow
  - https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic
"""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


# Find `unchecked { ... }` blocks (one or more statements inside).
UNCHECKED_BLOCK_RE = re.compile(
    r"unchecked\s*\{",
    re.MULTILINE,
)

# Arithmetic ops that overflow/underflow.
ARITH_OPS = re.compile(
    r"(\w+)\s*(\+=|-=|\*=|\+\+|--)"
    r"|"
    r"\b(\w+)\s*[+\-*/%]\s*(\w+)"
)


class UncheckedArithmeticDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="unchecked-arithmetic",
            name="Arithmetic inside `unchecked { ... }` block (0.8+)",
            severity="medium",
            description=(
                "Solidity 0.8+ arithmetic that re-enables pre-0.8 semantics "
                "via `unchecked { ... }`. Verify overflow impossibility before "
                "leaving in production code."
            ),
            references=[
                "https://swcregistry.io/docs/SWC-101",
                "https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic",
                "CWE-190",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        for match in UNCHECKED_BLOCK_RE.finditer(source):
            # Brace-walk the block body.
            start = match.end()
            depth = 1
            i = start
            while i < len(source) and depth > 0:
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                i += 1
            body = source[start : i - 1]

            if not ARITH_OPS.search(body):
                continue

            line_no = source[: match.start()].count("\n") + 1
            snippet_line = (
                source_lines[line_no - 1].strip()
                if line_no - 1 < len(source_lines)
                else ""
            )
            findings.append(self._make_finding(
                line=line_no,
                column=1,
                snippet=snippet_line or "unchecked { ... }",
                message=(
                    "`unchecked { ... }` block contains arithmetic on integers. "
                    "Solidity 0.8+ overflow checks are disabled inside this block. "
                    "Verify overflow impossibility by construction, or remove `unchecked`."
                ),
                fix=(
                    "Either remove `unchecked` to re-enable 0.8+ overflow checks, "
                    "or add a comment proving the arithmetic cannot overflow "
                    "(e.g. bounded loop counter with constant upper bound). "
                    "Common false-positive risk: token balance math that may "
                    "wrap around under adversarial control."
                ),
            ))

        return findings
