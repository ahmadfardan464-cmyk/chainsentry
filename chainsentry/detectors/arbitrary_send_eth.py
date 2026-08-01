"""Arbitrary-send-ETH detector (SWC-114) — flag unprotected `transfer`/`call{value:}` to user-controlled addresses.

Pattern: a function that forwards ETH to an address derived from
caller-controlled input (a function parameter, storage written by an
external function, etc.) and lacks access control + a zero-address
check + a balance check.

This is the class of bug behind the Parity Wallet `initWallet` /
`executeDelegateCall` incidents and countless drainer exploits.

References:
  - SWC-114: https://swcregistry.io/docs/SWC-114
  - CWE-284
  - Parity Wallet hack post-mortems (2017)
"""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


# Catch `addr.transfer(...)`, `addr.send(...)`, `addr.call{value: ...}(...)`.
ETH_SEND_RE = re.compile(
    r"(?:(\w+)\s*\.\s*(?:transfer|send)\s*\(|"
    r"(\w+)\s*\.\s*call\s*\{[^}]*value\s*:)"
)

# Functions that take a single `address` parameter and forward ETH.
FUNC_TAKES_ADDRESS_RE = re.compile(
    r"function\s+(\w+)\s*\(\s*address\s+(\w+)",
    re.MULTILINE,
)

# Access-control modifiers.
PRIV_MODIFIER_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|requiresAuth|auth)\s*\("
)


class ArbitrarySendEthDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="arbitrary-send-eth",
            name="Unprotected ETH send to user-controlled address (SWC-114)",
            severity="high",
            description=(
                "Function forwards ETH to an address from external input "
                "without access control + zero-address + balance checks. "
                "Drainer / Parity-Wallet-class risk."
            ),
            references=[
                "https://swcregistry.io/docs/SWC-114",
                "https://cwe.mitre.org/data/definitions/284.html",
                "https://www.parity.io/blog/security-alert-2",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        # Build a map: function name → (start offset, modifier string).
        func_info: dict[str, tuple[int, str, str]] = {}
        for match in FUNC_TAKES_ADDRESS_RE.finditer(source):
            func_name = match.group(1)
            addr_param = match.group(2)
            # Find the function header end (the opening `{`).
            open_idx = source.find("{", match.end())
            if open_idx == -1:
                continue
            # Modifier string is the text between `)` and `{`.
            header_end = source.rfind(")", match.start(), open_idx)
            modifier = source[header_end + 1 : open_idx] if header_end != -1 else ""
            func_info[func_name] = (match.start(), modifier, addr_param)

        # Find each ETH-send expression and trace back to the enclosing function.
        for match in ETH_SEND_RE.finditer(source):
            send_offset = match.start()
            enclosing_func: str | None = None
            enclosing_start = -1
            for fname, (fstart, _, _) in func_info.items():
                if fstart < send_offset and (enclosing_start == -1 or fstart > enclosing_start):
                    enclosing_func = fname
                    enclosing_start = fstart
            if enclosing_func is None:
                continue

            fstart, modifier, addr_param = func_info[enclosing_func]

            # Skip if the function is access-controlled — admin-initiated send is OK.
            if PRIV_MODIFIER_RE.search(modifier):
                continue

            # Skip if the function does not actually forward to the addr parameter.
            # Look at the function body for the variable name.
            body_start = source.find("{", fstart)
            body_end = source.find("}", body_start) if body_start != -1 else -1
            if body_start == -1 or body_end == -1:
                continue
            body = source[body_start : body_end + 1]
            if addr_param not in body:
                continue

            line_no = source[: send_offset].count("\n") + 1
            snippet_line = (
                source_lines[line_no - 1].strip()
                if line_no - 1 < len(source_lines)
                else ""
            )
            findings.append(self._make_finding(
                line=line_no,
                column=1,
                snippet=snippet_line or f"{enclosing_func} forwards ETH to {addr_param}",
                message=(
                    f"Function `{enclosing_func}` forwards ETH to a "
                    f"caller-supplied address (`{addr_param}`) without access "
                    "control. Anyone can call this and drain contract balance."
                ),
                fix=(
                    "Add `onlyOwner` (or a role-based modifier). Add a "
                    "`require({addr_param} != address(0))` zero-address check. "
                    "Add a balance check `require(address(this).balance >= amount)`. "
                    "Consider pulling instead of pushing via a withdrawal pattern."
                ),
            ))

        return findings
