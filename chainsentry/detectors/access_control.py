"""Access control detector: privileged functions without access modifier."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*(?:public\s+|external\s+|internal\s+|private\s+)?"
    r"(?:public\s+|external\s+|internal\s+|private\s+)?"
    r"(?:virtual\s+|override\s+)*"
    r"([^{]*)\{",
    re.MULTILINE,
)
PRIV_MODIFIER_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyMinter|onlyBurner|requiresAuth|isAdmin|auth)\s*\(",
)


class AccessControlDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="missing-access-control",
            name="Missing access control on privileged function",
            severity="high",
            description="State-changing function with no visibility modifier or onlyOwner-style check.",
            references=[
                "https://swcregistry.io/docs/SWC-105",
                "https://swcregistry.io/docs/SWC-106",
                "CWE-862",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        # Skip if contract uses OZ Ownable / AccessControl (heuristic: import present).
        if not re.search(r"import\s+[^\n]*OpenZeppelin", source) and not re.search(r"\bOwnable\b", source):
            for match in FUNC_RE.finditer(source):
                func_name = match.group(1)
                between = match.group(2) or ""
                # Heuristic: state-changing and privileged if it has one of these names.
                looks_privileged = bool(re.search(
                    r"^(?:set|withdraw|transfer|burn|mint|pause|unpause|upgrade|kill|drain|setFee|setOwner|setAdmin|setRate|setOracle|setImplementation|approve|execute|emergency)",
                    func_name,
                ))
                if not looks_privileged:
                    continue
                if PRIV_MODIFIER_RE.search(between):
                    continue
                # Approximate line number.
                line_no = source[: match.start()].count("\n") + 1
                findings.append(self._make_finding(
                    line=line_no,
                    column=1,
                    snippet=f"function {func_name}(...) {between.strip()}",
                    message=f"Privileged function `{func_name}` lacks an access-control modifier (onlyOwner, etc.).",
                    fix=(
                        "Add `onlyOwner` or use OpenZeppelin's AccessControl with roles. "
                        "Restrict default visibility — prefer `external` over `public` for "
                        "transactional functions. Apply modifers consistently across all "
                        "state-mutating paths."
                    ),
                ))
        return findings
