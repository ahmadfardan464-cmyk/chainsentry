"""Reentrancy detector: external call followed by state change."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.scanner import Finding


# Heuristic: inside a function, an external call (.call, .send, .transfer,
# address(addr).call(...)) appears BEFORE a state-changing assignment
# (x =, balances[...], state =, etc.) on subsequent lines.
EXTERNAL_CALL_RE = re.compile(
    r"(?:\.call\s*\{[^}]*\}\s*\(|\.call\s*\(|"
    r"\.send\s*\(|\.transfer\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(|"
    r"address\s*\([^)]+\)\.transfer\s*\(|address\s*\([^)]+\)\.send\s*\(|"
    r"payable\s*\([^)]+\)\.transfer\s*\()"
)
STATE_WRITE_RE = re.compile(
    r"^\s*(?:"
    r"[a-zA-Z_]\w*(?:\[[^\]]+\])?\s*(?:\+\+|--|-=|\+=|\*=|/=|%=|&=|\|\|=|\^=|<<=|>>=|>>>=)"  # compound incl ++/--
    r"|[a-zA-Z_]\w*(?:\[[^\]]+\])?\s*=(?!=|>)"  # simple =, not == or =>
    r"|(?:delete|selfdestruct|suicide)\b"
    r")"
)


class ReentrancyDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="reentrancy",
            name="Reentrancy (external call before state change)",
            severity="high",
            description="External call made before state update — vulnerable to reentrancy.",
            references=[
                "https://swcregistry.io/docs/SWC-107",
                "https://docs.soliditylang.org/en/latest/security-considerations.html#re-entrancy",
                "CWE-841",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        # Walk function-by-function. Look for the pattern within a single function.
        for match in re.finditer(
            r"function\s+(\w+)[^{]*\{",
            source,
        ):
            func_name = match.group(1)
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
            body_lines = body.splitlines()
            # Find earliest external call line and earliest state write line.
            call_line: int | None = None
            write_line: int | None = None
            for j, line in enumerate(body_lines, 1):
                if call_line is None and EXTERNAL_CALL_RE.search(line):
                    call_line = j
                if call_line is not None and write_line is None and STATE_WRITE_RE.match(line):
                    write_line = j
                    break
            if call_line is not None and write_line is not None and write_line > call_line:
                snippet = _grab_block(body_lines, call_line, write_line)
                findings.append(self._make_finding(
                    line=call_line,
                    column=1,
                    snippet=snippet,
                    message=f"Function `{func_name}` makes an external call before a state change — expose to reentrancy.",
                    fix=(
                        "Apply checks-effects-interactions: do all state writes BEFORE the external call. "
                        "Or use a ReentrancyGuard (OpenZeppelin). Consider pulling funds via a "
                        "withdraw() pattern so users call back, not the protocol."
                    ),
                ))
        return findings


def _grab_block(body_lines: list[str], a: int, b: int, ctx: int = 2) -> str:
    lo = max(1, a - ctx)
    hi = min(len(body_lines), b + ctx)
    return "\n".join(body_lines[lo - 1 : hi])
