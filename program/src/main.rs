#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;

use lib::sxg::SXGInput;
use lib::PublicValuesStruct;
pub fn main() {
    let sxg_input = sp1_zkvm::io::read::<SXGInput>();
    let result = sxg_input.verify().unwrap() as u32;

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        result,
        data_to_verify: sxg_input.data_to_verify,
    });

    sp1_zkvm::io::commit_slice(&bytes);
}
