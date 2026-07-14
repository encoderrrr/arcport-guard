// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Suppressed {
    function externalOracleCompatibilityProbe() external view returns (uint256) {
        // arcport-ignore-next-line ARC002
        return uint256(block.prevrandao);
    }
}
