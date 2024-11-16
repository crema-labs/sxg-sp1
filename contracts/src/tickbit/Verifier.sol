// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISP1Verifier {
    function verifyProof(
        bytes32 _vkey,
        bytes calldata _publicValues,
        bytes calldata _proof
    ) external view returns (bool);
}

struct BlockParams {
    uint256 block_number;
    bytes32 block_hash;
}
struct PublicValuesStruct {
    uint32 result;
    BlockParams blockParams;
    uint256 px;
    uint256 py;
}

/// @title SXGVerifier
/// @notice This contract implements a verifier for proof of a mined bitcoin block, it's block number and hash as serverd inside a bitcoin explorer's web content.
contract SXGVerifier {
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

    /// @notice The entrypoint for verifying the proof of a block params.
    /// @param _publicValues The encoded public values.
    /// @param _proofBytes The encoded proof.

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
