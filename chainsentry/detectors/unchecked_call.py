"""Unchecked low-level call detector: .call() return value not checked."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


# Detect `(bool ok, ) = addr.call(...)` or similar without a require on ok.
LOW_CALL_RE = re.compile(
    r"(?:\(\s*(?:bool\s+)?(\w+)\s*[,)]\s*=\s*[^;]+?\.(?:call|delegatecall|staticcall)\s*\(|\.\s*call\s*\([^)]*\)\s*[;])",
    re.MULTILINE,
)
OK_USED_RE = re.compile(r"require\s*\(\s*(\w+)\s*\)|if\s*\(\s*!\s*(\w+)\s*\)|if\s*\(\s*(\w+)\s*\)")


class UncheckedCallDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="unchecked-call",
            name="Unchecked low-level call return value",
            severity="medium",
            description="Address.call/transfer/send return value not checked — failures will be silently ignored.",
            references=[
                "https://swcregistry.io/docs/SWC-104",
                "CWE-252",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        # Find each low-level call and check if the success variable is checked.
        for i, line in enumerate(source_lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            # Look for `(bool ok, ...)` or `bool ok;` pattern from a .call
            if re.search(r"\(\s*bool\s+\w+", stripped) and re.search(r"\.\s*(?:call|delegatecall|staticcall)\s*\(", stripped):
                # Try to find the ok variable name.
                m = re.search(r"\(\s*bool\s+(\w+)", stripped)
                if not m:
                    continue
                ok_var = m.group(1)
                # Look ahead in the next ~5 lines for a check on ok_var.
                window = "\n".join(source_lines[i - 1 : min(i + 5, len(source_lines))])
                if not re.search(rf"require\s*\(\s*{ok_var}\s*\)", window) \
                   and not re.search(rf"if\s*\(\s*!?\s*{ok_var}\s*\)", window):
                    findings.append(self._make_finding(
                        line=i,
                        column=1,
                        snippet=stripped,
                        message=f"Return value of `.call(...)` (variable `{ok_var}`) is not checked.",
                        fix=(
                            "Wrap the call in a `require(success)` or use OpenZeppelin's "
                            "Address.sendValue / ReentrancyGuard. Or replace `.call` with "
                            "`.transfer` (2300 gas) where appropriate, but note the gas stipend "
                            "issues with smart contract wallets."
                        ),
                    ))
        return findings
