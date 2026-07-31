"""Ether-frozen detector — flag contracts that accept ETH but provide no withdraw path.

SWC-132: a contract that accepts ETH via `receive()`, `fallback()`, or a
payable function without any matching withdrawal / transfer path traps funds.

Limitations: this is a structural heuristic. Vaults intentionally holding
ETH as reserves will trigger a false positive; reported as `low` severity
to allow triage discrimination.
"""
from __future__ import annotations

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


class EtherFrozenDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="ether-frozen",
            name="Ether-frozen contract (no withdraw path)",
            severity="low",
            description=(
                "Contract receives ETH but provides no withdraw / refund / "
                "payout function. Funds may become permanently inaccessible."
            ),
            references=[
                "https://swcregistry.io/docs/SWC-132",
                "https://cwe.mitre.org/data/definitions/CWE-674.html",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        full_source = source
        lower_source = source.lower()

        accepts_eth = (
            "receive()" in full_source
            or "fallback()" in full_source
            or "payable" in lower_source
        )
        has_withdraw = (
            ("transfer(" in lower_source or "send(" in lower_source or ".call{value:" in lower_source)
            and ("withdraw" in lower_source or "refund" in lower_source or "payout" in lower_source)
        )

        if accepts_eth and not has_withdraw:
            receive_line = 0
            for i, line in enumerate(source_lines, start=1):
                if "receive(" in line or "fallback(" in line or "payable" in line.lower():
                    receive_line = i
                    break

            findings.append(self._make_finding(
                line=receive_line or 1,
                column=1,
                snippet=(
                    "Contract accepts ETH (via receive/fallback/payable) but "
                    "shows no `withdraw` / `refund` / `payout` path."
                ),
                message=(
                    "Contract receives ETH but provides no withdrawal, refund, "
                    "or payout function. Any ETH sent to this contract is at "
                    "risk of being permanently locked."
                ),
                fix=(
                    "Add an explicit withdraw / refund / payout function gated "
                    "by appropriate access control. Alternatively, document "
                    "the intentional reserve + provide an admin override path."
                ),
            ))

        return findings
