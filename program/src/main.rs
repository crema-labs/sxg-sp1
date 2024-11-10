#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy::primitives::U256;
use alloy_sol_types::SolType;

use lib::sxg::SXGInput;
use lib::{BlockParams, PublicValuesStruct};
pub fn main() {
    let sxg_input = sp1_zkvm::io::read::<SXGInput>();
    let result = sxg_input.verify().unwrap() as u32;

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        result,
        blockParams: BlockParams {
            block_number: alloy_sol_types::private::Uint::from(sxg_input.block_params.block_number),
            block_hash: alloy_sol_types::private::FixedBytes::from_slice(
                &hex::decode(sxg_input.block_params.block_hash).unwrap(),
            ),
        },
        px: U256::from_be_slice(&sxg_input.px),
        py: U256::from_be_slice(&sxg_input.py),
    });

    sp1_zkvm::io::commit_slice(&bytes);
}
