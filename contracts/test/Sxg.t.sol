// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SXG} from "../src/Sxg.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    uint32 result;
    bytes32 vkey;
    bytes publicValues;
    bytes proof;
}

contract SXGTest is Test {
    address verifier;
    SXG public sxg;

    function loadSample() public view returns (SP1ProofFixtureJson memory) {
        return
            SP1ProofFixtureJson({
                result: 1,
                vkey: 0x00cacd7a6bd9bf05403e6025a3f07687589f397c117db0387631fc2acb105eff,
                publicValues: hex"0000000000000000000000000000000000000000000000000000000000000001",
                proof: hex"6a2906ac21d04f16a0b65a4614269ffaa702b89e5f4af256bf057d7210ea14d2e4eb003718416563bd7c3558910f61a515ec26b3aaba426931da7e0196e1c007827c4bda2947aa3e01c50b0d09205a076be5f96f3093d081e8ddfe0ed20d5bdbeeae3080240a293565baa15ef6787722810f6d70411f920f054e22a3a94a92e5f3cfc90d1bec7415f91ecf1ee6493c6e8d2736059afeda7c4e1b5a6f11c61cd5936db86e0d27d53150eb1a1137044994767c44dc5d61a65c76f95a9fd416e35de1b6982b2a407fc15fa38cf2df4f64fc6f3eb84a7f6e73a6cc01b3916db1734f3e8698b90b62224a46f50fae2d637b0dd7e7d70854bb87e99d6426cc58132c8b98563f42"
            });
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadSample();
        verifier = address(new SP1VerifierGateway(address(1)));

        sxg = new SXG(verifier, fixture.vkey);
    }

    function test_ValidSXGProof() public {
        SP1ProofFixtureJson memory fixture = loadSample();
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode(true)
        );
        uint32 result = sxg.verifySXGProof(fixture.publicValues, fixture.proof);
        assert(result == 1);
    }

    function testFail_InvalidSxgProof() public view {
        SP1ProofFixtureJson memory fixture = loadSample();

        bytes memory fakeProof = new bytes(fixture.proof.length);

        uint32 result = sxg.verifySXGProof(fixture.publicValues, fakeProof);
        assert(result == 0);
    }
}
