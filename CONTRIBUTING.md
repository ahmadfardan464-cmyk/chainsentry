# Contributing to chainsentry

Thanks for your interest in improving chainsentry. This guide covers the
detector-author workflow. New to the project? Start with the
[README](README.md) + [docs/detectors.md](docs/detectors.md) first.

## Quick start

```bash
git clone https://github.com/ahmardan464-cmyk/chainsentry.git
cd chainsentry

# Run the test suite
python3 -m pytest tests/ -v

# Run the scanner against the sample vulnerable contract
python3 -m chainsentry contracts/vulnerable.sol -f markdown

# List all detectors
python3 -m chainsentry --list-detectors
```

No `pip install` needed — chainsentry is Python stdlib only (Flask is the
only optional dep, for the web UI).

## Repo layout

```
chainsentry/
├── scanner.py          # orchestrator: dispatches source → detectors → findings
├── detectors/          # one file per detector, all registered in __init__.py
├── models.py           # Finding + ScanReport dataclasses
├── reporters.py        # text/json/markdown formatters
├── cli.py              # argparse CLI entrypoint
└── __main__.py         # allows `python3 -m chainsentry`

contracts/
├── vulnerable.sol      # fixture: known-bad patterns for detector tests
└── safe.sol            # fixture: clean contract (should produce 0 findings)

tests/
└── test_scanner.py     # full-test pass against the vulnerable + safe fixtures
```

## Adding a new detector

chainsentry ships 12 detectors in M1. M2 target is 25. Each detector is
a single file in `chainsentry/detectors/` and follows the same shape.

### 1. Pick an SWC entry to target

Look at the [SWC Registry](https://swcregistry.io/) for an SWC ID that
chainsentry doesn't yet detect. Common gaps from M1 → M2:

- **SWC-105** — Forbidden abi.encodePacked usage (signature malleability)
- **SWC-106** — Unprotected SELFDESTRUCT
- **SWC-115** — Authorization through tx.origin (already covered by `tx_origin`)
- **SWC-128** — DoS with block gas limit (over complex operations)
- **SWC-132** — Unexpected Ether balance (no withdraw function)
- **SWC-133** — Hash collision with multiple variables

Open an issue to claim it before starting.

### 2. Create the detector file

```python
"""Description (line 1).

Longer explanation (2-4 sentences) of the vulnerability and why chainsentry
flags it. Keep plain-English; junior auditors and CISOs are the audience.
"""
from __future__ import annotations

from chainsentry.models import Finding


# SWC registry ID we are flagging. Used for the `references` field.
SWC_ID = "SWC-XXX"
CWE_ID = "CWE-XXX"  # if applicable


def detect(source_lines: list[str], filename: str = "<source>") -> list[Finding]:
    """Return a list of findings.

    `source_lines` is the contract split into lines (preserves original
    newlines via splitlines()). Return empty list if the detector finds
    nothing.

    Heuristics to keep in mind:
      - Stay syntax-lite: this is NOT a Slither replacement. Match on
        substrings + token context, not full AST.
      - False positives are expensive to live down — better under-fire.
      - Severity is a statement about exploitability AND blast radius.
    """
    findings: list[Finding] = []
    for i, line in enumerate(source_lines, start=1):
        if "selfdestruct" in line and "_;" not in line:
            findings.append(Finding(
                detector="selfdestruct-unprotected",
                severity="high",
                line=i,
                column=line.find("selfdestruct") + 1,
                snippet=line.strip(),
                message="`selfdestruct(...)` reachable without access control — anyone can permanently destroy the contract.",
                fix="Restrict `selfdestruct` to a privileged function (onlyOwner) and add a re-init guard if the contract can be re-deployed.",
                references=[
                    f"https://swcregistry.io/docs/{SWC_ID}",
                    f"https://cwe.mitre.org/data/definitions/{CWE_ID}.html",
                ],
            ))
    return findings
```

### 3. Register the detector

In `chainsentry/detectors/__init__.py`:

```python
from chainsentry.detectors.selfdestruct import detect as selfdestruct_detect

ALL_DETECTORS = [
    reentrancy_detect,
    tx_origin_detect,
    # ...
    selfdestruct_detect,  # add here
]
```

### 4. Add a test fixture

Append a vulnerable pattern to `contracts/vulnerable.sol` and verify
chainsentry catches it:

```bash
python3 -m chainsentry contracts/vulnerable.sol -f text
```

Make sure existing positive findings are still detected (no regressions).

### 5. Run the full test suite

```bash
python3 -m pytest tests/ -v
```

All existing tests must pass. Add a new test for your detector if it has
non-trivial false-positive concerns.

### 6. Open a PR

- Title: `[detector] Add selfdestruct detector (SWC-106)`
- Body: link the issue you claimed, paste sample output
- Required checks: tests/ passes + chainsentry run against contracts/vulnerable.sol catches the new pattern

## Code style

- Python 3.8+ syntax (`from __future__ import annotations` at top)
- Type hints on all detector signatures
- No third-party imports in detector files (stdlib only)
- Line length ≤ 100 chars
- Detector function signature: `def detect(source_lines: list[str], filename: str = "<source>") -> list[Finding]`

## Severity rubric

| Severity | Use for |
|---|---|
| `critical` | Direct loss of funds under normal conditions |
| `high` | Loss of funds under realistic adversarial conditions |
| `medium` | Conditional loss of funds, or significant DoS / griefing |
| `low` | Code smell / best-practice violation; hard to exploit |
| `info` | Informational; not a vulnerability but worth noting |

If unsure, default to `medium` and let triage escalate.

## Communications

- Issues: GitHub issue tracker (preferred)
- Discord: [link to be added]
- Telegram: @AhmadFardan

Looking forward to your detector PR 🚀