//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.20;

import {SXGVerifier} from "../src/Bob.sol";
import {Script} from "forge-std/Script.sol";
import "forge-std/console.sol";


contract Deploy is Script {
    function setUp() public pure {
        console.log("Deploying VerifySPV contract");
    }

    function run() public {
        bytes32 privateKey = vm.envBytes32("DEPLOYER_PRIVATE_KEY");
        require(privateKey != 0, "DEPLOYER_PRIVATE_KEY is not set or invalid");
        vm.startBroadcast(uint256(privateKey));

        SXGVerifier verify = new SXGVerifier(
            0x3B6041173B80E77f038f3F2C0f9744f04837185e,
            0x00c1c5f7a9d301b8250bd2f7593e0fcb9311a015748e7506ecc90ed30ca68ee0
        );
        console.logAddress(address(verify));
        vm.stopBroadcast();
    }
}
