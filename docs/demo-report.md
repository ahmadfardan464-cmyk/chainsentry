# chainsentry report — `contracts/vulnerable.sol`

**Detectors run:** 12  
**Duration:** 4 ms  
**Findings:** 11

## Severity breakdown

| Severity | Count |
|---|---|
| 🔴 high | 5 |
| 🟠 medium | 5 |
| 🟡 low | 1 |

## Findings

### 1. [HIGH] reentrancy — line 3

**Function `withdraw` makes an external call before a state change — expose to reentrancy.**

```solidity
require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
```

**Fix:** Apply checks-effects-interactions: do all state writes BEFORE the external call. Or use a ReentrancyGuard (OpenZeppelin). Consider pulling funds via a withdraw() pattern so users call back, not the protocol.

**References:**
- https://swcregistry.io/docs/SWC-107
- https://docs.soliditylang.org/en/latest/security-considerations.html#re-entrancy
- CWE-841

### 2. [HIGH] missing-access-control — line 20

**Privileged function `transferOwnership` lacks an access-control modifier (onlyOwner, etc.).**

```solidity
function transferOwnership(...)
```

**Fix:** Add `onlyOwner` or use OpenZeppelin's AccessControl with roles. Restrict default visibility — prefer `external` over `public` for transactional functions. Apply modifers consistently across all state-mutating paths.

**References:**
- https://swcregistry.io/docs/SWC-105
- https://swcregistry.io/docs/SWC-106
- CWE-862

### 3. [HIGH] tx-origin — line 21

**`tx.origin` used — phishable via malicious intermediate contract.**

```solidity
require(tx.origin == owner);
```

**Fix:** Use `msg.sender` for authentication. If you need to know if the caller is an EOA, use `msg.sender == tx.origin` AFTER checking msg.sender == owner, but the safer pattern is to require msg.sender and never trust tx.origin.

**References:**
- https://swcregistry.io/docs/SWC-115
- https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin
- CWE-284

### 4. [HIGH] missing-access-control — line 26

**Privileged function `withdraw` lacks an access-control modifier (onlyOwner, etc.).**

```solidity
function withdraw(...)
```

**Fix:** Add `onlyOwner` or use OpenZeppelin's AccessControl with roles. Restrict default visibility — prefer `external` over `public` for transactional functions. Apply modifers consistently across all state-mutating paths.

**References:**
- https://swcregistry.io/docs/SWC-105
- https://swcregistry.io/docs/SWC-106
- CWE-862

### 5. [HIGH] missing-access-control — line 58

**Privileged function `emergencyDrain` lacks an access-control modifier (onlyOwner, etc.).**

```solidity
function emergencyDrain(...)
```

**Fix:** Add `onlyOwner` or use OpenZeppelin's AccessControl with roles. Restrict default visibility — prefer `external` over `public` for transactional functions. Apply modifers consistently across all state-mutating paths.

**References:**
- https://swcregistry.io/docs/SWC-105
- https://swcregistry.io/docs/SWC-106
- CWE-862

### 6. [MEDIUM] integer-overflow — line 5

**Contract compiles with Solidity ^0.7.6 (<0.8) — no built-in overflow check.**

```solidity
pragma solidity ^0.7.6;
```

**Fix:** Upgrade to Solidity >=0.8 (built-in checked arithmetic). If you must stay on 0.4-0.7, import `using SafeMath for uint256;` and use `.add/.sub/.mul/.div` everywhere you do arithmetic.

**References:**
- https://swcregistry.io/docs/SWC-101
- https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html#silent-overflow-checks

### 7. [MEDIUM] unsafe-randomness — line 39

**Unsafe randomness source — validators/sequencers can manipulate block attributes.**

```solidity
return uint256(blockhash(block.number - 1)) % 100 == guess;
```

**Fix:** Use Chainlink VRF (verifiable random function) for any randomness that carries economic value. For non-economic decisions, accept that the value is biasable and design for it (commit-reveal phases, time-weighted averaging, etc.).

**References:**
- https://swcregistry.io/docs/SWC-120
- CWE-330
- https://docs.chain.link/vrf

### 8. [MEDIUM] unsafe-randomness — line 44

**Unsafe randomness source — validators/sequencers can manipulate block attributes.**

```solidity
return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 6;
```

**Fix:** Use Chainlink VRF (verifiable random function) for any randomness that carries economic value. For non-economic decisions, accept that the value is biasable and design for it (commit-reveal phases, time-weighted averaging, etc.).

**References:**
- https://swcregistry.io/docs/SWC-120
- CWE-330
- https://docs.chain.link/vrf

### 9. [MEDIUM] timestamp-dependence — line 44

**`block.timestamp` (or `now`) used in arithmetic/comparison — manipulators can shift within ~15s.**

```solidity
return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 6;
```

**Fix:** Don't use block.timestamp for randomness or strict equality comparisons. Block numbers are monotonic and use `block.number` for ordering. For time-dependent logic, accept a margin (e.g., 1-2 minutes) or use a Chainlink oracle.

**References:**
- https://swcregistry.io/docs/SWC-116
- https://docs.soliditylang.org/en/latest/security-considerations.html#block-timestamp

### 10. [MEDIUM] timestamp-dependence — line 49

**`block.timestamp` (or `now`) used in arithmetic/comparison — manipulators can shift within ~15s.**

```solidity
return block.timestamp > deadline;
```

**Fix:** Don't use block.timestamp for randomness or strict equality comparisons. Block numbers are monotonic and use `block.number` for ordering. For time-dependent logic, accept a margin (e.g., 1-2 minutes) or use a Chainlink oracle.

**References:**
- https://swcregistry.io/docs/SWC-116
- https://docs.soliditylang.org/en/latest/security-considerations.html#block-timestamp

### 11. [LOW] floating-pragma — line 5

**Floating pragma — contract can be compiled with unintended Solidity version.**

```solidity
pragma solidity ^0.7.6;
```

**Fix:** Use a pinned pragma (e.g. `pragma solidity 0.8.24;`) for production. Floating pragmas are fine for libraries and examples but not for deployed code.

**References:**
- https://swcregistry.io/docs/SWC-103
- CWE-710

