// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

struct PublicValuesStruct {
    uint32 result;
}

/// @title Sxg.
/// @author Succinct Labs
/// @notice This contract implements a simple example of verifying the proof of a computing a
///         fibonacci number.
contract SXG {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the sxg program.
    bytes32 public sxgProgramVKey;

    constructor(address _verifier, bytes32 _sxgProgramVKey) {
        verifier = _verifier;
        sxgProgramVKey = _sxgProgramVKey;
    }

    /// @notice The entrypoint for verifying the proof of a sxg number.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifySXGProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) public view returns (uint32) {
        ISP1Verifier(verifier).verifyProof(
            sxgProgramVKey,
            _publicValues,
            _proofBytes
        );
        PublicValuesStruct memory publicValues = abi.decode(
            _publicValues,
            (PublicValuesStruct)
        );

        return publicValues.result;
    }
}
