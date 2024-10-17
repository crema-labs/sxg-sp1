// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SP1 Verifier Interface
/// @author Succinct Labs
/// @notice This contract is the interface for the SP1 Verifier.
interface ISP1Verifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @dev It is expected that the first 4 bytes of proofBytes must match the first 4 bytes of
    /// target verifier's VERIFIER_HASH.
    /// @param programVKey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

interface ISP1VerifierWithHash is ISP1Verifier {
    /// @notice Returns the hash of the verifier.
    function VERIFIER_HASH() external pure returns (bytes32);
}

struct PublicValuesStruct {
    uint32 result;
    uint8[] data_to_verify;
}

/// @title Sxg.
/// @author Crema Labs
/// @notice This contract implements a simple example of verifying the proof sxg.
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
    ) public view returns (uint32, string memory) {
        ISP1Verifier(verifier).verifyProof(
            sxgProgramVKey,
            _publicValues,
            _proofBytes
        );
        PublicValuesStruct memory publicValues = abi.decode(
            _publicValues,
            (PublicValuesStruct)
        );

        string memory data_to_verify_str = convertToASCII(
            publicValues.data_to_verify
        );

        return (publicValues.result, data_to_verify_str);
    }

    function convertToASCII(
        uint8[] memory data
    ) internal pure returns (string memory) {
        bytes memory asciiBytes = new bytes(data.length);
        for (uint i = 0; i < data.length; i++) {
            require(
                data[i] >= 32 && data[i] <= 126,
                "Input contains non-printable ASCII characters"
            );
            asciiBytes[i] = bytes1(data[i]);
        }
        return string(asciiBytes);
    }
}
