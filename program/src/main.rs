//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, sha256_hash, verify_ecdsa_p256_signature, PublicValuesStruct};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.

    let n = sp1_zkvm::io::read::<u32>();

    let sha256_hash = sha256_hash(&[1, 11]);

    let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
    let public_key_hex = "0457be97dd389c893d7271a1fe7546aaf09074aba40779d19c21c00832bc3f821add286faf7beb2f0722050169d89ae7fe0b02e8b8bea4c5141b188ff678e6d8bf";
    let signature_hex = "6a7570a91dd49c4ff738efd81ceaadbf89daad02611d184e276906eeb36712254ff40cda556ed67ef04b3933e2e92830b6cfae684da605f07f779fad78945e22";

    let result = verify_ecdsa_p256_signature(message, signature_hex, public_key_hex);

    let (a, b) = fibonacci(n);

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
