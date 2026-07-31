# Detector reference

Each detector maps to one or more SWC entries and a CWE. Patterns are
pure-text regex/AST-lite on Solidity source — no solc, no slither, no
mythril required.

---

## `reentrancy` — high

**Pattern:** within a function body, an external call
(`.call/.send/.transfer/.delegatecall` or `address(...).call(...)`)
appears *before* a state-changing assignment (`x = ...`, `delete`,
`selfdestruct`, `+=`, `-=`, etc.).

**Why it matters:** classic reentrancy — the attacker re-enters the
function before the state update lands, draining repeatedly.

**Fix:** checks-effects-interactions pattern. Write all state updates
*before* the external call. Consider OpenZeppelin's `ReentrancyGuard`
or a withdrawal pattern where users call back, not the protocol.

**References:** SWC-107, CWE-841, Solidity docs §re-entrancy.

## `tx-origin` — high

**Pattern:** any use of `tx.origin` outside of comments.

**Why it matters:** `tx.origin` is the *signer* of the original tx, not
the immediate caller. An intermediate contract can be tricked into
calling `transferOwnership(this)` and a malicious contract sitting
in between passes `tx.origin == owner` because the original signer
was the owner.

**Fix:** use `msg.sender` for auth. Never trust `tx.origin`.

**References:** SWC-115, CWE-284.

## `timestamp-dependence` — medium

**Pattern:** `block.timestamp` or `now` used in arithmetic or comparison.

**Why it matters:** validators can shift timestamps within ~15s. Strict
equality or short-window logic is manipulable.

**Fix:** prefer `block.number` for ordering. Accept a margin for
time-dependent logic. Use Chainlink oracles for time-sensitive
external state.

**References:** SWC-116.

## `unchecked-call` — medium

**Pattern:** `(bool ok, ...) = addr.call(...)` not followed by a
`require(ok)` or `if(!ok)` check.

**Why it matters:** failed calls silently swallow the failure. The
caller thinks the transfer succeeded when it didn't.

**Fix:** `require(ok, "...")` after every low-level call. Or use
OpenZeppelin's `Address.sendValue`.

**References:** SWC-104, CWE-252.

## `missing-access-control` — high

**Pattern:** state-modifying function name (set*/withdraw*/transfer*/burn*/
mint*/pause*/upgrade*/drain*/...) lacking an `onlyOwner` / `onlyRole` /
auth modifier.

**Why it matters:** anyone can call these functions. The most common
category of high-severity findings in the wild.

**Fix:** `onlyOwner` or OpenZeppelin `AccessControl` with roles.
Apply modifiers consistently across all state-mutating paths.

**References:** SWC-105, SWC-106, CWE-862.

## `integer-overflow` — medium

**Pattern:** `pragma solidity ^X.Y` where X.Y < 0.8, *and* no `SafeMath`
or `using SafeMath` is detected.

**Why it matters:** pre-0.8 Solidity silently wraps arithmetic. `type(uint256).max + 1` = 0.

**Fix:** upgrade to Solidity >=0.8 (built-in checked arithmetic). Or
`using SafeMath for uint256;` and `.add/.sub/.mul/.div`.

**References:** SWC-101.

## `unsafe-randomness` — medium

**Pattern:** `blockhash`, `block.difficulty`, `block.prevrandao`,
`block.coinbase`, or `keccak256(abi.encodePacked(block.X, msg.sender))`.

**Why it matters:** validators/sequencers can manipulate these within
bounds. Use only for non-economic decisions.

**Fix:** Chainlink VRF for any randomness with economic value.

**References:** SWC-120, CWE-330, Chainlink VRF docs.

## `default-visibility` — low

**Pattern:** `function f(...) ... {` with no explicit `public` /
`external` / `internal` / `private` on a Solidity version <0.5.

**Why it matters:** defaulted to public in pre-0.5. Real-exploit
history (e.g., Parity wallet).

**Fix:** always specify visibility explicitly.

**References:** SWC-100, CWE-710.

## `floating-pragma` — low

**Pattern:** `pragma solidity ^X.Y` or `>= X.Y`.

**Why it matters:** un-pinned pragma can be compiled with a different
version than the one tested.

**Fix:** pin: `pragma solidity 0.8.24;`. Floating pragmas are fine
for libraries and examples, not for deployed code.

**References:** SWC-103.

## `uninitialized-state` — low

**Pattern:** state variable declared without `=` and later read in a
`require`/`assert` without first being written in the constructor.

**Why it matters:** default-zero assumption can mask missing init logic.

**Fix:** initialize in the declaration or in the constructor.

**References:** SWC-109.

## `delegatecall-storage` — high

**Pattern:** `.delegatecall(...)` without a nearby guard comment
mentioning storage layout or a known proxy slot.

**Why it matters:** delegatecall runs the callee's code in the caller's
storage. The Parity multi-sig 2017 incident and several recent
upgradeability incidents traced back to this pattern.

**Fix:** use the EIP-1967 proxy pattern (storage slot 0x360894... for
implementation). For libraries, use `using ... for ...` instead of
raw delegatecall. Add a comment naming the expected storage layout.

**References:** SWC-112, CWE-829.

## `missing-zero-address` — medium

**Pattern:** function taking `address _x` and assigning it to a state
variable without a `require(_x != address(0))` guard.

**Why it matters:** setting an owner / oracle / treasury to
`0x0000...0000` often bricks the contract or makes it unrecoverable.

**Fix:** `require(_param != address(0), "zero address");` before any
state-write that uses the parameter. OpenZeppelin's `Address` library
has helpers (`Address.isContract`) if you also need to assert the
address is a contract.

**References:** SWC-128, CWE-20.
