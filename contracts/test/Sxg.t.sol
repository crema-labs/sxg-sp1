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
                vkey: 0x00a0e618e71b21b9a573b86f463534b87b469655a024665b54ec256f6831446d,
                publicValues: hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000004200000000000000000000000000000000000000000000000000000000000000750000000000000000000000000000000000000000000000000000000000000069000000000000000000000000000000000000000000000000000000000000006c00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000069000000000000000000000000000000000000000000000000000000000000006e000000000000000000000000000000000000000000000000000000000000006700000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000066000000000000000000000000000000000000000000000000000000000000006f0000000000000000000000000000000000000000000000000000000000000075000000000000000000000000000000000000000000000000000000000000006e0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000006100000000000000000000000000000000000000000000000000000000000000740000000000000000000000000000000000000000000000000000000000000069000000000000000000000000000000000000000000000000000000000000006f000000000000000000000000000000000000000000000000000000000000006e0000000000000000000000000000000000000000000000000000000000000061000000000000000000000000000000000000000000000000000000000000006c0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006c0000000000000000000000000000000000000000000000000000000000000069000000000000000000000000000000000000000000000000000000000000006200000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000061000000000000000000000000000000000000000000000000000000000000007200000000000000000000000000000000000000000000000000000000000000690000000000000000000000000000000000000000000000000000000000000065000000000000000000000000000000000000000000000000000000000000007300000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000074000000000000000000000000000000000000000000000000000000000000006f000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000065000000000000000000000000000000000000000000000000000000000000006d000000000000000000000000000000000000000000000000000000000000006f000000000000000000000000000000000000000000000000000000000000007600000000000000000000000000000000000000000000000000000000000000650000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006c0000000000000000000000000000000000000000000000000000000000000069000000000000000000000000000000000000000000000000000000000000006d00000000000000000000000000000000000000000000000000000000000000690000000000000000000000000000000000000000000000000000000000000074000000000000000000000000000000000000000000000000000000000000006100000000000000000000000000000000000000000000000000000000000000740000000000000000000000000000000000000000000000000000000000000069000000000000000000000000000000000000000000000000000000000000006f000000000000000000000000000000000000000000000000000000000000006e000000000000000000000000000000000000000000000000000000000000007300000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000066000000000000000000000000000000000000000000000000000000000000006f000000000000000000000000000000000000000000000000000000000000007200000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000074000000000000000000000000000000000000000000000000000000000000006800000000000000000000000000000000000000000000000000000000000000650000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006600000000000000000000000000000000000000000000000000000000000000750000000000000000000000000000000000000000000000000000000000000074000000000000000000000000000000000000000000000000000000000000007500000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000065000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000072000000000000000000000000000000000000000000000000000000000000006f000000000000000000000000000000000000000000000000000000000000006a000000000000000000000000000000000000000000000000000000000000006500000000000000000000000000000000000000000000000000000000000000630000000000000000000000000000000000000000000000000000000000000074000000000000000000000000000000000000000000000000000000000000007300000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000061000000000000000000000000000000000000000000000000000000000000006e00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000020",
                proof: hex"6a2906ac21ce0f452cf45bc66dc4c788318602dded2efd89566ef4340aa31ed7c62ea63724a46efa300b4209e95b1e7343838cf75bc8be3ae97953c8083ebc95092a5b612cfeebdbf87105d3950cd585a9088717f48d79d852e4543d492d634054394c0b245c3020d5695f563e3da5adc1b05967633f8d6a3c730088a0d9f225fc5dc5921fe4d54eb4e142effd5c1ac44af8774e342ca2a410e77b7635dc092c6bc1ead30188c96c94d2976a95ab289b5ac827aad8f1380f664ed7c1243a51ffe015941121546239e317c37364bd5c50fa6169f6145ae3572737831ab1caa117a9d40c08105a1b0df1cf71d3a56eb6ca29b256480d390a89348c9daeb841d02dd7f228d9"
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

        (uint32 result, string memory data_to_verify) = sxg.verifySXGProof(
            fixture.publicValues,
            fixture.proof
        );

        console.log(data_to_verify);
        assert(result == 1);
    }

    function testFail_InvalidSxgProof() public view {
        SP1ProofFixtureJson memory fixture = loadSample();

        bytes memory fakeProof = new bytes(fixture.proof.length);

        (uint32 result, string memory sui) = sxg.verifySXGProof(
            fixture.publicValues,
            fixture.proof
        );
        console.log(sui);
        assert(result == 0);
    }
}
