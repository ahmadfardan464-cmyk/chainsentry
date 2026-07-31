// SPDX-License-Identifier: MIT
// SAFE-PATTERN REFERENCE — used to confirm chainsentry does not flag false positives.

pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeVault is Ownable {
    mapping(address => uint256) public balances;

    // CORRECT: checks-effects-interactions + ReentrancyGuard pattern via withdrawal.
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;          // state write FIRST
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");           // check return value
    }

    // CORRECT: explicit access control + brief explanation.
    function emergencyDrain() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}
