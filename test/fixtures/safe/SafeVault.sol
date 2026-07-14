// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeVault {
    uint256 public lastProcessedBlock;

    function markProcessed() external {
        require(block.number > lastProcessedBlock, "already processed");
        lastProcessedBlock = block.number;
    }
}
