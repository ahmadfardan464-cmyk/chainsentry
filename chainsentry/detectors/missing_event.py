"""Missing-event detector — flag state-mutating privileged functions that don't emit an event.

Pattern: a state-changing function whose name matches a privileged verb
(`set*`, `transfer*`, `mint*`, `burn*`, `pause*`, etc.) but where the body
contains no `emit ` statement to a named event.

Why: off-chain monitors (subgraphs, indexers, governance dashboards)
rely on event emission for state observability. Functions that silently
mutate state make incident detection harder and create audit blind spots.

Severity: low — observability issue, not direct loss of funds.
"""
from __future__ import annotations

import re

from chainsentry.detectors.base import Detector
from chainsentry.models import Finding


# Match function declarations whose name suggests state mutation.
FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)[^{]*\{",
    re.MULTILINE,
)

# Privileged verbs that almost always warrant an event.
PRIV_VERB_RE = re.compile(
    r"^(?:set|transfer|mint|burn|pause|unpause|upgrade|kill|drain|"
    r"setFee|setRate|setOracle|setImplementation|approve|execute|emergency|"
    r"register|deregister|whitelist|blacklist|add|remove|subscribe|"
    r"setAdmin|setOwner|setSigner|setGuardian|setTreasury)",
    re.IGNORECASE,
)

# Match `event FooBar(...);` declarations so we know what events exist.
EVENT_DECL_RE = re.compile(r"event\s+(\w+)\s*\(")

# Match any `emit Something(...)` call.
EMIT_RE = re.compile(r"emit\s+(\w+)\s*\(")


class MissingEventDetector(Detector):
    def __init__(self) -> None:
        super().__init__(
            id="missing-event",
            name="State-mutating privileged function with no event emit",
            severity="low",
            description=(
                "Privileged state-changing function does not emit any event. "
                "Off-chain monitors cannot observe the change. Audit trail is weaker."
            ),
            references=[
                "https://swcregistry.io/docs/SWC-135",  # closest SWC — events metadata
                "https://docs.soliditylang.org/en/latest/contracts.html#events",
            ],
        )

    def scan(self, source: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        # No emits anywhere? Skip (contract maybe doesn't need events).
        declared_events = set(EVENT_DECL_RE.findall(source))
        emitted_events = set(EMIT_RE.findall(source))
        if not emitted_events and not declared_events:
            return findings

        for match in FUNC_RE.finditer(source):
            func_name = match.group(1)
            if not PRIV_VERB_RE.match(func_name):
                continue

            # Find the function body via brace-walk.
            start = match.end()
            depth = 1
            i = start
            while i < len(source) and depth > 0:
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                i += 1
            body = source[start : i - 1]

            if EMIT_RE.search(body):
                continue  # Function emits something — fine.

            line_no = source[: match.start()].count("\n") + 1
            findings.append(self._make_finding(
                line=line_no,
                column=1,
                snippet=f"function {func_name}(...) {{ ... }}",
                message=(
                    f"Privileged function `{func_name}` mutates state but "
                    "emits no event. Off-chain monitors and indexers cannot "
                    "observe the change."
                ),
                fix=(
                    "Add an `event FooChanged(address indexed by, ...)` "
                    "declaration and `emit FooChanged(msg.sender, ...)` at "
                    "the end of the function. Older event names can stay; "
                    "add a new one to preserve logs."
                ),
            ))

        return findings
