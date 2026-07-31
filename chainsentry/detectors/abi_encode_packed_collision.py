"""ABI-encodePacked hash collision detector — flag multi-arg abi.encodePacked where ordering or dynamic types introduce ambiguity.

SWC-133: `abi.encodePacked(a, b)` with multiple dynamic-length arguments
(or mixed-length fixed arguments) is ambiguous under certain inputs.

Common exploitation path: signature replay when `abi.encodePacked(addr, uint)`
serves as a unique key — two distinct inputs can hash to the same value
because field boundaries are not framed.
"""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


_ENCODE_PACKED_RE = re.compile(r"abi\.encodePacked\s*\(([^)]*)\)")


class AbiEncodePackedCollisionDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="abi-encode-packed-collision",
            name="abi.encodePacked multi-arg collision risk",
            severity="medium",
            description=(
                "abi.encodePacked used with multiple arguments (any dynamic "
                "type present) introduces boundary ambiguity under packed encoding."
            ),
            references=[
                "https://swcregistry.io/docs/SWC-133",
                "https://cwe.mitre.org/data/definitions/CWE-1240.html",
                "https://docs.soliditylang.org/en/latest/abi-spec.html#non-standard-packed-mode",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(source_lines, start=1):
            match = _ENCODE_PACKED_RE.search(line)
            if not match:
                continue

            arg_str = match.group(1)
            arg_count = self._count_top_level_args(arg_str)
            has_dynamic = self._has_dynamic_type(arg_str)

            if arg_count < 2:
                continue

            findings.append(self._make_finding(
                line=i,
                column=match.start() + 1,
                snippet=line.strip(),
                message=(
                    f"abi.encodePacked used with {arg_count} arguments"
                    + (" and at least one dynamic-length type" if has_dynamic else "")
                    + ". Two distinct inputs can hash to the same packed "
                    "value when field boundaries are not framed."
                ),
                fix=(
                    "Use `abi.encode` instead (pads each field to 32 bytes, "
                    "eliminating boundary ambiguity). If packed encoding is "
                    "required, ensure arguments are fixed-length and "
                    "homogeneously typed (e.g. all `bytes32`)."
                ),
            ))

        return findings

    @staticmethod
    def _count_top_level_args(arg_str: str) -> int:
        depth = 0
        count = 0
        for ch in arg_str:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                count += 1
        return count + 1 if arg_str.strip() else 0

    @staticmethod
    def _has_dynamic_type(arg_str: str) -> bool:
        lowered = arg_str.lower()
        return any(marker in lowered for marker in ("string", "bytes ", "[]"))
