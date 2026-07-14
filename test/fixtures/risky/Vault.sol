// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

contract Vault {
    IERC20 public usdc;
    uint256 public lastTimestamp;

    function unsafeRandom() external view returns (uint256) {
        return uint256(block.prevrandao);
    }

    function compareBalances() external view returns (bool) {
        return usdc.balanceOf(address(this)) == address(this).balance;
    }

    function ordered() external view returns (bool) {
        require(block.timestamp > lastTimestamp, "same timestamp");
        return true;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
