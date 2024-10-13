//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::constants::{DATA_TO_VERIFY, FINAL_PAYLOAD, PAYLOAD};

use fibonacci_lib::sxg::{sxg_verify, SXGInput};
use fibonacci_lib::{fibonacci, sha256_hash, verify_ecdsa_p256_signature, PublicValuesStruct};
use hex;
pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.

    let n = sp1_zkvm::io::read::<u32>();

    let (a, b) = fibonacci(n);

    let final_payload = FINAL_PAYLOAD;
    let data_to_verify = DATA_TO_VERIFY;
    let payload = PAYLOAD;

    let data_to_verify_start_index = 0;
    let integrity_start_index = 694 / 2;

    let px = "45E3943B0705F9EF69B53A4EFB8C668E6A9F90124E9BCF917662CFADEA56C0C1";
    let py = "F3703834F92F6FE70A004BA4098D079BFB5F927E042991EFD5A1572E8F9D39D6";

    let r = "9970818CBCA38C196795EEAD295BDED48311702DF7DDB0C2BB448276894C393D";
    let s = "729B2F9229D545A553F0F7CBC1792E9A6185E539DBF667FE5BC38D673D90C014";

    let r = hex::decode(r).unwrap();
    let s = hex::decode(s).unwrap();

    let px = hex::decode(px).unwrap();
    let py = hex::decode(py).unwrap();

    let input = SXGInput {
        final_payload: final_payload.to_vec(),
        data_to_verify: data_to_verify.to_vec(),
        data_to_verify_start_index,
        integrity_start_index,
        payload: payload.to_vec(),
        r: r.try_into().unwrap(),
        s: s.try_into().unwrap(),
        px: px.try_into().unwrap(),
        py: py.try_into().unwrap(),
    };

    let result = sxg_verify(input).unwrap();

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
