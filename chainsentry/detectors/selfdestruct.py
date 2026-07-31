"""Unprotected SELFDESTRUCT — flag callable selfdestruct without access control.

SWC-106: contracts that allow anyone to call `selfdestruct` are exposed to
permanent destruction by arbitrary external callers.

Limitations (PoC scope): string-substring match. May miss hardened
patterns (e.g. immediate `address(this).balance` redistribution); those
are caught by Slither.
"""
from __future__ import annotations

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


class SelfdestructDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="selfdestruct-unprotected",
            name="Unprotected SELFDESTRUCT",
            severity="high",
            description=(
                "selfdestruct reachable inside a function lacking "
                "onlyOwner/onlyRole — anyone can permanently destroy the contract."
            ),
            references=[
                "https://swcregistry.io/docs/SWC-106",
                "https://cwe.mitre.org/data/definitions/CWE-284.html",
                "https://eips.ethereum.org/EIPS/eip-6780",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        in_modifierless_function = False

        for i, line in enumerate(source_lines, start=1):
            stripped = line.strip()

            if stripped.startswith("function "):
                in_modifierless_function = not any(
                    mod in stripped
                    for mod in ("onlyOwner", "onlyAdmin", "onlyRole", "restricted", "self")
                )
                continue

            if in_modifierless_function and "selfdestruct" in stripped:
                findings.append(self._make_finding(
                    line=i,
                    column=line.find("selfdestruct") + 1,
                    snippet=stripped,
                    message=(
                        "`selfdestruct(...)` reachable without access control. "
                        "Any external caller can permanently destroy the contract "
                        "and drain its ETH balance."
                    ),
                    fix=(
                        "Restrict `selfdestruct` to a privileged function "
                        "(onlyOwner / onlyRole) and add a deprecation / migration "
                        "guard. Note EIP-6780 (post-Dencun selfdestruct semantics) "
                        "before relying on the keyword alone."
                    ),
                ))

        return findings
