// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/AnchrVault.sol";

contract DeployVault is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        AnchrVault vault = new AnchrVault();

        vm.stopBroadcast();

        console.log("AnchrVault deployed at:", address(vault));
    }
}
