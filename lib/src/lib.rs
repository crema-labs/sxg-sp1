use alloy_sol_types::sol;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

pub fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn verify_ecdsa_p256_signature(
    message: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let signature_bytes = hex::decode(signature_hex)?;
    let signature = Signature::from_slice(&signature_bytes)?;

    let public_key_bytes = hex::decode(public_key_hex)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)?;

    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_ecdsa_p256_signature() {
        let message =
            b"ECDSA proves knowledge of a secret number in the context of a single message";
        let public_key_hex = "0457be97dd389c893d7271a1fe7546aaf09074aba40779d19c21c00832bc3f821add286faf7beb2f0722050169d89ae7fe0b02e8b8bea4c5141b188ff678e6d8bf";
        let signature_hex = "6a7570a91dd49c4ff738efd81ceaadbf89daad02611d184e276906eeb36712254ff40cda556ed67ef04b3933e2e92830b6cfae684da605f07f779fad78945e22";

        let result = verify_ecdsa_p256_signature(message, signature_hex, public_key_hex);
        assert!(result.unwrap());
    }
}
