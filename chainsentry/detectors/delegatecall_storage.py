"""Delegatecall storage layout detector: delegatecall to a contract whose
storage layout may not match the caller. Without explicit guards, the
storage being read/written is the caller's, but the code being executed
is the callee's — a classic upgradeability footgun and the source of
several real exploits (e.g., Parity multi-sig 2017)."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding  # noqa: F401  — used by base

DELEGATE_RE = re.compile(r"\.delegatecall\s*\(")


class DelegatecallStorageDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="delegatecall-storage",
            name="Unchecked delegatecall",
            severity="high",
            description="delegatecall runs the callee's code in the caller's storage — vulnerable to storage collision and unauthorized owner takeover.",
            references=[
                "https://swcregistry.io/docs/SWC-112",
                "https://docs.soliditylang.org/en/latest/security-considerations.html#delegatecall",
                "CWE-829",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        # Find delegatecall usage and check for storage layout comment or
        # / a require that the target address is from a known proxy slot.
        for i, line in enumerate(source_lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if DELEGATE_RE.search(line):
                # Look in the surrounding 4 lines for a guard comment.
                window = "\n".join(source_lines[max(0, i - 4) : i + 1])
                has_guard = bool(re.search(
                    r"//.*(?:storage\s+layout|safe|trusted|slot\s*0)",
                    window,
                    re.IGNORECASE,
                ))
                if has_guard:
                    continue
                findings.append(self._make_finding(
                    line=i,
                    column=line.find("delegatecall") + 1,
                    snippet=stripped,
                    message="Unchecked `.delegatecall(...)` — target's code runs in the caller's storage. Verify storage layout matches.",
                    fix=(
                        "Use the EIP-1967 proxy pattern (storage slot "
                        "0x360894... for implementation). For libraries, "
                        "use `using ... for ...` instead of raw delegatecall. "
                        "Add a comment naming the expected storage layout "
                        "and a require that the target is a known implementation."
                    ),
                ))
        return findings
