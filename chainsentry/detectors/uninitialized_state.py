"""Uninitialized state detector: state variables declared without initialization."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.scanner import Finding


# State vars are declared at contract scope (not inside function bodies).
# Match: type visibility? name ;   without an = sign.
STATE_VAR_RE = re.compile(
    r"^\s*(?:public\s+|private\s+|internal\s+)?"
    r"(?:mapping\s*\([^)]+\)\s+|address\s+|uint\d*\s+|int\d*\s+|bool\s+|string\s+|bytes\d*\s+)"
    r"(\w+)\s*;"
)


class UninitializedStateDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="uninitialized-state",
            name="Uninitialized state variable",
            severity="low",
            description="State var declared without initializer — defaults to zero/empty/false, may indicate missing logic.",
            references=[
                "https://swcregistry.io/docs/SWC-109",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        # This is a noisy heuristic — we only flag when a state var is referenced
        # in a require/if without ever being assigned in the contract.
        findings: list[Finding] = []
        contract_match = re.search(r"contract\s+(\w+)\s*(?:is\s+[^{]*)?\{", source)
        if not contract_match:
            return findings
        # Find contract body.
        start = contract_match.end()
        depth = 1
        i = start
        while i < len(source) and depth > 0:
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
            i += 1
        body = source[start : i - 1]

        # Collect state vars with no initialization.
        bare_vars: list[tuple[str, int]] = []
        for m in STATE_VAR_RE.finditer(body):
            name = m.group(1)
            line_no = source[: start + m.start()].count("\n") + 1
            bare_vars.append((name, line_no))

        # Only flag if the var is read in a require/assert (suggesting relied-upon).
        for name, line_no in bare_vars:
            if re.search(rf"require\s*\(\s*{name}\b", body) or re.search(rf"assert\s*\(\s*{name}\b", body):
                findings.append(self._make_finding(
                    line=line_no,
                    column=1,
                    snippet=f"{name} (declared without initializer)",
                    message=f"State var `{name}` is read in a require/assert but never initialized — defaults to zero/false.",
                    fix=(
                        "Either initialize in the declaration (`uint256 x = 0;`) or set in the "
                        "constructor. If the var is meant to be set later, do an explicit "
                        "`False`/empty check before the require to make the intent obvious."
                    ),
                ))
        return findings
