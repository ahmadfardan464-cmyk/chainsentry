// SPDX-License-Identifier: MIT
// INTENTIONALLY VULNERABLE — used as chainsentry demo input.
// Every pattern below should be flagged by at least one detector.

pragma solidity ^0.7.6;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public withdrawalLimit;

    // UNINITIALIZED STATE
    address public oracle;

    constructor() {
        owner = msg.sender;
    }

    // TX.ORIGIN
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner);
        owner = newOwner;
    }

    // REENTRANCY + MISSING ACCESS CONTROL
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // UNCHECKED CALL
    function flush(address payable to) public {
        to.call{value: address(this).balance}("");
    }

    // TIMESTAMP DEPENDENCE
    function isLucky(uint256 guess) public view returns (bool) {
        return uint256(blockhash(block.number - 1)) % 100 == guess;
    }

    // UNSAFE RANDOMNESS
    function rollDice() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 6;
    }

    // TIMESTAMP IN ARITHMETIC
    function windowOpen() public view returns (bool) {
        return block.timestamp > deadline;
    }

    // INTEGER OVERFLOW (pre-0.8)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // DEFAULT VISIBILITY (no modifier on old pragma)
    function emergencyDrain() {
        payable(owner).transfer(address(this).balance);
    }
}
