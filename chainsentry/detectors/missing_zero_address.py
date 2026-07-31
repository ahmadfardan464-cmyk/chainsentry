"""Missing zero-address check: setting an address parameter (owner, oracle,
treasury, ...) to address(0) without explicit guard. Common footgun in
initializer / setter functions."""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding  # noqa: F401


# Lines that assign an address-typed parameter to a state variable
# without a require(param != address(0)) in the same scope.
ADDR_PARAM_RE = re.compile(
    r"^\s*(?:public\s+|private\s+|internal\s+)?\s*"
    r"(?:address\s+(\w+)\s*(?:=\s*[^;]+)?;"
    r"|function\s+\w+\s*\([^)]*\b(address\s+\w+)[^)]*\)\s*[^;]*\{[^}]*)",
    re.MULTILINE,
)
RECV_FALLBACK_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\b(address\s+\w+)[^)]*\)\s+(?:public\s+)?(?:external\s+)?",
    re.MULTILINE,
)


class MissingZeroAddressDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="missing-zero-address",
            name="Missing zero-address check",
            severity="medium",
            description="Address parameter/state var assigned without a `require(_ != address(0))` guard.",
            references=[
                "https://swcregistry.io/docs/SWC-128",
                "https://docs.soliditylang.org/en/latest/security-considerations.html#checking-arguments",
                "CWE-20",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        # Heuristic: for each function that takes `address _x` and assigns it
        # to a state variable, check that there's a `require(_x != address(0))`
        # in the function body.
        for match in re.finditer(
            r"function\s+(\w+)\s*\(([^)]*)\)",
            source,
        ):
            func_name = match.group(1)
            params = match.group(2)
            # Find address-typed parameters.
            addr_params = re.findall(r"address(?:\s+(?:calldata\s+)?)(\w+)", params)
            if not addr_params:
                continue
            # Find the function body.
            start = match.end()
            depth = 0
            i = start
            while i < len(source):
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = source[start : i + 1]
            # Skip view/pure/read-only functions.
            if re.search(r"\b(?:view|pure)\b", body):
                continue
            # Skip if body contains a require that checks the param against address(0).
            for p in addr_params:
                guard = re.search(rf"require\s*\(\s*{p}\s*!=\s*address\s*\(\s*0\s*\)\s*", body) \
                    or re.search(rf"if\s*\(\s*{p}\s*==\s*address\s*\(\s*0\s*\)\s*\)", body)
                if not guard:
                    # Check if the param is assigned to a state var.
                    if re.search(rf"\b{re.escape(p)}\s*=", body):
                        line_no = source[: match.start()].count("\n") + 1
                        findings.append(self._make_finding(
                            line=line_no,
                            column=1,
                            snippet=f"function {func_name}(address {p})",
                            message=f"Function `{func_name}` accepts address parameter `{p}` and assigns it without a zero-address check.",
                            fix=(
                                "Add `require(_param != address(0), \"zero address\");` "
                                "before any state-write that uses the parameter. "
                                "Or use OpenZeppelin's Address library which has "
                                "an `Address.isContract` helper if you need to "
                                "assert the address is a contract too."
                            ),
                        ))
        return findings
