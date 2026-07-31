"""Unsafe randomness detector: blockhash/coinbase/prevrandao used as source of randomness."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


UNSAFE_RAND_RE = re.compile(
    r"\b(?:blockhash|block\.difficulty|block\.prevrandao|block\.coinbase|"
    r"gaslimit|gasLimit|"
    r"keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*block\.|"
    r"keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*msg\.sender)"
)


class UnsafeRandomnessDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="unsafe-randomness",
            name="Unsafe source of randomness",
            severity="medium",
            description="blockhash/coinbase/etc. can be influenced by validators — never use for game/lottery outcomes.",
            references=[
                "https://swcregistry.io/docs/SWC-120",
                "CWE-330",
                "https://docs.chain.link/vrf",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(source_lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if UNSAFE_RAND_RE.search(line):
                findings.append(self._make_finding(
                    line=i,
                    column=1,
                    snippet=stripped,
                    message="Unsafe randomness source — validators/sequencers can manipulate block attributes.",
                    fix=(
                        "Use Chainlink VRF (verifiable random function) for any randomness that "
                        "carries economic value. For non-economic decisions, accept that the "
                        "value is biasable and design for it (commit-reveal phases, time-weighted "
                        "averaging, etc.)."
                    ),
                ))
        return findings
