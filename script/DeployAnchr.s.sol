// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/AnchrAnchorRegistry.sol";

contract DeployAnchr is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        AnchrAnchorRegistry registry = new AnchrAnchorRegistry();

        vm.stopBroadcast();

        console.log("AnchrAnchorRegistry deployed at:", address(registry));
        console.log("Update ANCHOR_ADDRESS in anchr-core.js to:");
        console.log(address(registry));
    }
}
