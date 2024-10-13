pub mod constants;
pub mod sxg;

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

pub fn verify_ecdsa_p256_r_s(
    message: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
    px: &[u8; 32],
    py: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(r);
    signature_bytes[32..].copy_from_slice(s);
    let signature = Signature::from_slice(&signature_bytes)?;

    let mut public_key_bytes = [4u8; 65];
    public_key_bytes[1..33].copy_from_slice(px);
    public_key_bytes[33..].copy_from_slice(py);

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)?;

    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use constants::FINAL_PAYLOAD;

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

    #[test]
    fn test_verify_ecdsa_p256_r_s() {
        let px1 = "45E3943B0705F9EF69B53A4EFB8C668E6A9F90124E9BCF917662CFADEA56C0C1";
        let py1 = "F3703834F92F6FE70A004BA4098D079BFB5F927E042991EFD5A1572E8F9D39D6";

        let r1 = "9970818CBCA38C196795EEAD295BDED48311702DF7DDB0C2BB448276894C393D";
        let s1 = "729B2F9229D545A553F0F7CBC1792E9A6185E539DBF667FE5BC38D673D90C014";

        let r: [u8; 32] = hex::decode(r1).unwrap().try_into().unwrap();
        let s: [u8; 32] = hex::decode(s1).unwrap().try_into().unwrap();
        let px: [u8; 32] = hex::decode(px1).unwrap().try_into().unwrap();
        let py: [u8; 32] = hex::decode(py1).unwrap().try_into().unwrap();

        let result0 = verify_ecdsa_p256_r_s(FINAL_PAYLOAD, &r, &s, &px, &py).unwrap();
        assert!(result0);

        let r_hex = "6a7570a91dd49c4ff738efd81ceaadbf89daad02611d184e276906eeb3671225";
        let s_hex = "4ff40cda556ed67ef04b3933e2e92830b6cfae684da605f07f779fad78945e22";
        let px_hex = "57be97dd389c893d7271a1fe7546aaf09074aba40779d19c21c00832bc3f821a";
        let py_hex = "dd286faf7beb2f0722050169d89ae7fe0b02e8b8bea4c5141b188ff678e6d8bf";
        let message1 =
            b"ECDSA proves knowledge of a secret number in the context of a single message";

        let r: [u8; 32] = hex::decode(r_hex).unwrap().try_into().unwrap();
        let s: [u8; 32] = hex::decode(s_hex).unwrap().try_into().unwrap();
        let px: [u8; 32] = hex::decode(px_hex).unwrap().try_into().unwrap();
        let py: [u8; 32] = hex::decode(py_hex).unwrap().try_into().unwrap();

        let result1 = verify_ecdsa_p256_r_s(message1, &r, &s, &px, &py).unwrap();
        assert!(result1);
    }
}
