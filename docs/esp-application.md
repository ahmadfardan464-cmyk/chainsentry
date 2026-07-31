# Ethereum Foundation ESP — Application Draft

> **Project:** chainsentry — Lightweight, zero-install smart contract static analyzer
> **Track:** Open-source public-good tooling
> **Applicant:** <applicant name> (background: security research, bug bounty, Python)
> **Date:** 2026-07-31
> **Status:** PoC complete (10 detectors, STL-only Python, demo report generated)
> **Link to PoC:** https://github.com/<org>/chainsentry
> **Ask:** $100,000 USDT-eq (paid in stETH), milestone-based, ~5 months

---

## TL;DR

Build and ship **chainsentry**, a zero-install static analyzer that finds
the most common Solidity vulnerability classes (reentrancy, tx.origin,
timestamp dependence, unchecked calls, access control, integer overflow,
unsafe randomness, default visibility, floating pragma, uninitialized
state) in <100 ms on contracts under 1k lines, with structured reports
that **non-Solidity reviewers can act on**.

chainsentry is the pre-commit hook. Slither, Mythril, and Echidna remain
the CI gate. The two are complementary: chainsentry catches the easy wins
fast, the heavy tools handle the deep analysis.

## Why this matters for the Ethereum ecosystem

1. **The cost of catching a bug pre-deploy is ~$5K.** The cost of catching
   it post-deploy is the entire treasury. Several >$100M exploits in 2024-2026
   (Wormhole, Ronin, Nomad, Parity) traced back to patterns that chainsentry
   flags on the first scan: external call before state change, unchecked
   return, missing access control.
2. **Most teams don't run Slither.** Reasons: Solidity compiler dependency,
   noisy output, output that requires a Solidity-fluent reviewer to
   interpret. chainsentry removes the first two barriers.
3. **Solidity-fluent reviewers are scarce.** A junior auditor or a hackathon
   team needs a tool that explains *why* a finding is risky in plain English
   and points at the SWC registry / CWE. chainsentry reports do exactly that.

## What exists, what is missing

| Tool | Strong at | Weak at |
|---|---|---|
| **Slither** | Deep static analysis, 90+ detectors | Needs solc, slow first-run, output is Slither-internal — requires Solidity knowledge to read |
| **Mythril** | Symbolic execution, deep paths | Slow, requires EVM, false-positive heavy |
| **Echidna** | Property-based fuzzing | Setup cost, requires Solidity tests, not a static check |
| **chainsentry** | Pre-commit friction-free scan, plain-English report | Pre-0.9 era depth — catches the common 10, not the exotic 90 |

chainsentry does not replace Slither. It runs *before* Slither in the
contributor's local loop and surfaces the obvious wins, so Slither's CI
run focuses on the deeper findings.

## Deliverables

### M1 — PoC (current, complete)
- 10 detectors, stdlib-only Python, CLI + JSON/Markdown/text reporters
- Demo contracts: `vulnerable.sol` (10 seeded issues) + `safe.sol` (clean)
- Smoke tests in `tests/test_scanner.py`
- ~7 days of work, single contributor

### M2 — Production-ready (4 weeks, $30K)
- Detector suite grows to 25+ (add: delegatecall storage layout, signature
  replay, ERC-20 approval race, gas griefing, hardcoded addresses, missing
  zero-address checks, ERC-777 callbacks, ...)
- Solidity AST parser plugin (uses `slither-analyzer` if available, falls
  back to text mode) — hardening for >5k-line contracts
- GitHub Action with `--sarif` output for Code Scanning integration
- Benchmark suite: hand-curated corpus of 200 vulnerable contracts with
  ground-truth labels, per-detector precision/recall published per release

### M3 — Web UI + community (4 weeks, $30K)
- Paste-a-contract web app (no install, no signup, runs entirely in
  browser thanks to Pyodide or a small Flask backend)
- Public detector registry: anyone can submit a new detector as a
  pull request, run against the benchmark, see precision/recall delta
- Documentation site with per-detector explanations, GIF demonstrations,
  fix recipes

### M4 — Polish + launch (3 weeks, $25K)
- Browser extension: scan contracts inline on Etherscan
- HackerOne / Cantina / Code4rena integration: export findings to H1 report markdown
- Conference talks (Devcon 8 Mumbai, ETHGlobal events)
- Final benchmark report, public write-up

### Operations / buffer (~$15K)
- Infrastructure (CI, hosting for web UI, dataset hosting)
- Legal review of license compatibility with downstream tools
- Quarterly benchmark sweep cost

**Total requested: $100K USD-eq (paid in stETH), milestone-based.**

## Team

**<applicant name>, lead engineer**
- Background: security research, bug bounty (multiple resolved findings
  on HackerOne platforms), Python tooling, smart contract basics
- Time commitment: full-time on chainsentry for 5 months
- GitHub profile: <link>
- Past grants / work: <link if available, else note "first ESP grant">

**Optional collaborators (post-M1):**
- 1 Solidity reviewer (part-time, ~10 hrs/week, $0 rate but listed as
  contributor)
- 1 web designer for the M3 web UI (paid flat $4K)

## Why the applicant

The applicant has historically hunted bugs in production code and has
seen the report-and-fix loop from both sides. chainsentry is the tool
the applicant wanted before becoming the tool the applicant is building.

## Open-source posture

- **License:** MIT (already added; compatible with downstream OSS use)
- **Repo:** will be public from day one of M1
- **Issue tracker:** public GitHub Issues
- **Roadmap:** public ROADMAP.md, updated monthly
- **Contributions:** CONTRIBUTING.md with detector-spec template
- **Annual benchmark report:** published, no paywall

## Success metrics (measured monthly)

| Metric | M1 (poC) | M2 | M3 | M4 |
|---|---|---|---|---|
| Detectors | 10 | 25 | 30 | 30+ |
| Public corpus | 2 | 50 | 200 | 200+ |
| Detector precision (median) | n/a | 0.85 | 0.90 | 0.92 |
| GitHub stars | 0 | 100 | 500 | 1,500 |
| CI runs / month (downstream) | 0 | 1k | 20k | 100k |
| Active PRs / quarter | 0 | 5 | 15 | 50 |

## Why now

1. **Solidity still onboards new developers faster than any audit firm
   can staff.** Static checks at commit time cut the audit backlog.
2. **Post-2024, several foundation safety initiatives have moved
   upstream** (e.g., OpenZeppelin contracts, Solidity 0.8.x built-in
   overflow checks). chainsentry meets those developers where they are:
   commit time, no install.
3. **The ESP wishlist explicitly includes security tooling** as a
   recurring funding category. chainsentry falls squarely in scope.

## Risk mitigation

- **Risk:** Detector precision remains low after M2.
  **Mitigation:** Precision is a tracked metric; if a detector falls below
  0.7 median precision, it is demoted from default-on to opt-in until
  retuned.
- **Risk:** Solidity language evolves, breaking detectors.
  **Mitigation:** Corpus is pinned per release; benchmark gates any
  release with a regression in precision.
- **Risk:** Slither/Anyswap add a friction-free mode that subsumes chainsentry.
  **Mitigation:** chainsentry is positioned as a complementary layer;
  cross-integration (run chainsentry first, submit findings to Slither's
  triage queue) is in the M3 plan.

## Contact

- GitHub: <link>
- Email: <email>
- Telegram: <handle>
- Farcaster: <handle>

---

## Appendix A — Detector reference (current)

(rendered by `python3 -m chainsentry --list-detectors`)

## Appendix B — Demo report

`docs/demo-report.md` is the rendered output of
`python3 -m chainsentry contracts/vulnerable.sol -f markdown`.

## Appendix C — Sample project output

```
$ python3 -m chainsentry contracts/vulnerable.sol -f text
contracts/vulnerable.sol: 10 findings (10 detectors, 1 ms)
  🛑 HIGH    L18   [reentrancy] Function `withdraw` makes an external call before a state change — expose to reentrancy.
  🔴 HIGH    L14   [tx-origin] `tx.origin` used — phishable via malicious intermediate contract.
  ...
```
