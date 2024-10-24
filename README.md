# Verifiable Web Proofs using SXG's

Signed HTTP Exchanges (SXG) is draft specification that allows web content to be signed and verified. This project is a proof of concept that demonstrates how SXG's can be used to verify the integrity and authenticity of web content using zero-knowledge proofs.

## Does all website have sxg enabled?

No, not all websites have SXG enabled. It would be great if all websites supported SXG. But it will on click on cloudflare to enable so, it would be great if all websites supported SXG to enable it.

## How can we enable it?

Literally only cloudflare can enable it with one click. So then cloudflare will sign the content and then we can verify it using the zero-knowledge proof.

## How can I check if a website supports SXG?

Currently, only a few websites support SXG.

Some of the websites that support SXG are:

1. [vivs.wiki](https://vivs.wiki/blog/SXG)
2. [crema.sh](https://crema.sh/)

You can use these extension to verify whether sxg is enabled or not.
<img width="1125" alt="Screenshot 2024-10-17 at 6 27 07 PM" src="https://github.com/user-attachments/assets/cc4a9ee2-bf61-4b9a-9108-8cec5b7811b9">

If you want to learn more about sxg you can visit [here](https://web.dev/signed-exchanges/)

Verify the integrity and authenticity of web content using Signed HTTP Exchanges (SXG) and zero-knowledge proofs.

This Project contains:

1. sp1 circuit for verify sxg
2. smart contract to verify the proof on chain

Deployed contract: [0xadf974bae8d9de2a007058dfbb557097627a1a18](https://sepolia.etherscan.io/address/0xadf974bae8d9de2a007058dfbb557097627a1a18#readContract)

This is a template for creating an end-to-end [SP1](https://github.com/succinctlabs/sp1) project that can generate a proof of any RISC-V program.

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/getting-started/install.html)

## Usage

1. Use Sxg Extension to generate inputs for sxg content you wanted to prove from https://github.com/crema-labs/sxg-extension
![image](https://github.com/user-attachments/assets/f0bd451d-e317-4274-8175-5992f5ecca56)

In case you wanted to generate proof and verify:

```bash
RUST_LOG=info cargo run --release --bin evm -- --system groth16 --input-file-id <sxg-input>
```

2. Smart Contract Verification

We've also developed a smart contract to verify the proofs generated by our SP1 circuit. This allows for on-chain verification of web content integrity and authenticity.

To interact with the contract or view its details, check out our deployed contract on Etherscan:
[0xadf974bae8d9de2a007058dfbb557097627a1a18](https://sepolia.etherscan.io/address/0xadf974bae8d9de2a007058dfbb557097627a1a18#readContract)
