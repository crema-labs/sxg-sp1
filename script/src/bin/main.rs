//! An end-to-end example of using the SP1 SDK to generate a proof of a program that verifies SXG input.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use lib::{sxg::SXGInput, PublicValuesStruct};
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const SXG_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::new();

    let mut stdin = SP1Stdin::new();

    // TestCase from crema.sh
    let sxg_input = SXGInput::default_testcase();

    stdin.write(&sxg_input);

    if args.execute {
        let (output, report) = client.execute(SXG_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct { result } = decoded;
        println!("SXG verification result: {}", result);

        assert_eq!(result, 1);
        println!("SXG verification is successful!");

        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        let (pk, vk) = client.setup(SXG_ELF);

        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        proof
            .save("proof-with-io.json")
            .expect("saving proof failed");

        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
