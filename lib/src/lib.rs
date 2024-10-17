pub mod sxg;
pub mod test_case_1;
pub mod test_case_2;

use alloy_sol_types::sol;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 result;
        uint8[] data_to_verify;
    }
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
    use test_case_1::FINAL_PAYLOAD_1;
    use test_case_2::FINAL_PAYLOAD_2;

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

        let result0 = verify_ecdsa_p256_r_s(FINAL_PAYLOAD_1, &r, &s, &px, &py).unwrap();
        assert!(result0);

        let px2 = "E3718107FBB87954103F30F5D611F3A16D2997FFA6830EEEF666B243FD562594";
        let py2 = "C3FD5B2E946914400E26DC518AF9CEA72080148A22377F36902EEB0FBA2BD454";

        let r2 = "8F05B0DC32FE4F4EB60C630BFAA722DC9839202BC02E04B0AB3F97112E2E683C";
        let s2 = "FECEAC9E4DDDA1A332C60504ADDADD6BC7986370B2D26ED9172E6334EEE76608";

        let r_1: [u8; 32] = hex::decode(r2).unwrap().try_into().unwrap();
        let s_1: [u8; 32] = hex::decode(s2).unwrap().try_into().unwrap();
        let px_1: [u8; 32] = hex::decode(px2).unwrap().try_into().unwrap();
        let py_1: [u8; 32] = hex::decode(py2).unwrap().try_into().unwrap();

        let result1 = verify_ecdsa_p256_r_s(FINAL_PAYLOAD_2, &r_1, &s_1, &px_1, &py_1).unwrap();
        assert!(result1);

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
