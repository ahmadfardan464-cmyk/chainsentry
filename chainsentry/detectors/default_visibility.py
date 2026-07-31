"""Default visibility detector: state-modifying functions without explicit visibility."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


# Function declared without any of public/external/internal/private.
FUNC_NO_VIS_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*(?:returns\s*\([^)]+\)\s*)?(?:virtual\s+)?(?:override\s+)*\{",
    re.MULTILINE,
)


class DefaultVisibilityDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="default-visibility",
            name="Default function visibility",
            severity="low",
            description="Function declared without explicit visibility — defaults to public in pre-0.5 Solidity.",
            references=[
                "https://swcregistry.io/docs/SWC-100",
                "CWE-710",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        if not PRAGMA_RE.match(source):
            return findings
        m = PRAGMA_RE.search(source)
        pragma = m.group(1) if m else ""
        # Only flag if pragma looks like 0.4.x or very early 0.5.
        if not re.search(r"\b0\.[1-4]\.|0\.5\.[0-2]\b", pragma):
            return findings
        for match in FUNC_NO_VIS_RE.finditer(source):
            func_name = match.group(1)
            line_no = source[: match.start()].count("\n") + 1
            findings.append(self._make_finding(
                line=line_no,
                column=1,
                snippet=f"function {func_name}(...)",
                message=f"Function `{func_name}` has no explicit visibility modifier (defaults to `public` in 0.4.x).",
                fix=(
                    "Always specify `public`, `external`, `internal`, or `private` explicitly. "
                    "Default visibility changed to public in 0.5+ which has been a source of "
                    "real exploits (e.g., the Parity wallet incident)."
                ),
            ))
        return findings


PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
