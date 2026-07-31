# chainsentry

Lightweight, **zero-install** smart contract static analyzer — find common
Solidity vulnerabilities before they ship.

> **Status:** PoC. 10 detectors across reentrancy, tx.origin, timestamp
> dependence, unchecked calls, access control, integer overflow, unsafe
> randomness, default visibility, floating pragma, and uninitialized state.
> Stdlib-only Python. Runs in <100 ms on contracts under 1k lines.

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

No `pip install` required. Stdlib only. Python 3.8+.

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

Each detector emits a `Finding` with: line, column, snippet, severity,
plain-English message, fix recommendation, and references to SWC registry
/ CWE / docs.

## Demo

```bash
$ python3 -m chainsentry contracts/vulnerable.sol -f text
contracts/vulnerable.sol: 10 findings (10 detectors, 1 ms)
  🛑 HIGH    L18   [reentrancy] Function `withdraw` makes an external call before a state change — expose to reentrancy.
  🔴 HIGH    L14   [tx-origin] `tx.origin` used — phishable via malicious intermediate contract.
  ...
```

See `docs/detectors.md` for the full reference.

## Roadmap (post-grant)

- **M1 (current):** Core PoC + 10 detectors + CLI + JSON/Markdown/text reporters
- **M2:** Web UI (paste contract → scan → report), GitHub Action, `--sarif` output
- **M3:** 25 detectors, Solidity AST parser (slither-analyzer optional), webhook integration
- **M4:** Public launch, browser extension (Etherscan inline scan), community rule registry

## Why this fits the Ethereum Foundation ESP

- **Public good, open-source:** every detector is Apache-2.0, every report is reproducible
- **Ecosystem benefit:** reduces the supply-chain risk of insecure Solidity landing in mainnet
- **Complementary, not duplicative:** Slither/Mythril remain authoritative for deep analysis
- **Low barrier:** teams without Solidity expertise can run scans and read the report
- **Measurable impact:** detector-precision tracked on a public benchmark corpus

## License

MIT — see `LICENSE`.
