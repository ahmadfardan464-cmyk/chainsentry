# chainsentry

Lightweight, **zero-install** smart contract static analyzer — find common
Solidity vulnerabilities before they ship.

> **Status:** PoC. 12 detectors across reentrancy, tx.origin, timestamp
> dependence, unchecked calls, access control, integer overflow, unsafe
> randomness, default visibility, floating pragma, uninitialized state,
> delegatecall storage, and missing zero-address check.
> Stdlib-only Python. Runs in <10 ms on contracts under 1k lines.

## Why

Existing toolchains (Slither, Mythril, Echidna) are powerful but require
a Solidity compiler, install hundreds of MB of dependencies, and produce
output that demands fluent Solidity to interpret. **chainsentry** trades
depth for friction-free accessibility: paste a contract, get a
prioritised report in markdown, understand each finding's WHY, and
ship the fix without leaving your editor.

It is meant to be paired with Slither, not replace it: chainsentry is the
fast pre-commit check, Slither is the deep CI gate.

## Quick start

### CLI

```bash
# Run on a single file
python3 -m chainsentry contracts/vulnerable.sol -f text

# Markdown report
python3 -m chainsentry contracts/ -f markdown -o report.md

# CI-friendly: fail on high/critical
python3 -m chainsentry contracts/ --fail-on high

# List detectors
python3 -m chainsentry --list-detectors
```

No `pip install` required for the CLI. Stdlib only. Python 3.8+.

### Web UI

```bash
python3 -m web.app
# Open http://127.0.0.1:5000
```

A small Flask app (Flask is the only non-stdlib dep, optional). Paste a
contract, get a markdown report in the browser. See `web/README.md`.

## Detectors

| ID | Severity | Name |
|---|---|---|
| `reentrancy` | high | Reentrancy (external call before state change) |
| `tx-origin` | high | tx.origin for authentication |
| `timestamp-dependence` | medium | Block timestamp dependence |
| `unchecked-call` | medium | Unchecked low-level call return value |
| `missing-access-control` | high | Missing access control on privileged function |
| `integer-overflow` | medium | Integer overflow (pre-0.8 Solidity) |
| `unsafe-randomness` | medium | Unsafe source of randomness |
| `default-visibility` | low | Default function visibility |
| `floating-pragma` | low | Floating pragma |
| `uninitialized-state` | low | Uninitialized state variable |
| `delegatecall-storage` | high | Unchecked delegatecall storage layout |
| `missing-zero-address` | medium | Missing zero-address check on assignment |

Each detector emits a `Finding` with: line, column, snippet, severity,
plain-English message, fix recommendation, and references to SWC registry
/ CWE / docs.

## Demo

```bash
$ python3 -m chainsentry contracts/vulnerable.sol -f text
contracts/vulnerable.sol: 11 findings (12 detectors, 3 ms)
  🔴 high   L3   [reentrancy] Function `withdraw` makes an external call before a state change — expose to reentrancy.
  🔴 high   L20  [missing-access-control] Privileged function `transferOwnership` lacks an access-control modifier (onlyOwner, etc.).
  🔴 high   L21  [tx-origin] `tx.origin` used — phishable via malicious intermediate contract.
  ...
```

See `docs/detectors.md` for the full reference.

## Roadmap

- **M1 (current):** Core PoC + 12 detectors + CLI + JSON/Markdown/text reporters + web UI ✅
- **M2:** 25 detectors, Solidity AST parser (slither-analyzer optional), GitHub Action with `--sarif` output
- **M3:** Public detector registry, browser extension (Etherscan inline scan), community submissions
- **M4:** HackerOne/Cantina/Code4rena export, conference talks, benchmark report

## Funding

Submitted to Ethereum Foundation ESP — see `docs/esp-application.md`.
$100K ask, milestone-based, public open-source license (MIT).

## License

MIT — see `LICENSE`.
