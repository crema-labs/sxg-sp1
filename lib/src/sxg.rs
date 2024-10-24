use crate::{
    sha256_hash,
    test_case_1::{DATA_TO_VERIFY_1, FINAL_PAYLOAD_1, PAYLOAD_1},
    test_case_2::{DATA_TO_VERIFY_2, FINAL_PAYLOAD_2, PAYLOAD_2},
    verify_ecdsa_p256_r_s,
};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SXGInput {
    pub final_payload: Vec<u8>,
    pub data_to_verify: Vec<u8>,
    pub data_to_verify_start_index: usize,
    pub integrity_start_index: usize,
    pub payload: Vec<u8>,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub px: [u8; 32],
    pub py: [u8; 32],
}

fn calculate_integrity(input: &[u8], record_size: usize) -> [u8; 32] {
    if input.is_empty() {
        return sha256_hash(&[]);
    }

    let actual_record_size = record_size.min(input.len());
    let mut records: Vec<&[u8]> = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let chunk_size = (i + actual_record_size).min(input.len()) - i;
        records.push(&input[i..i + chunk_size]);
        i += actual_record_size;
    }

    let mut proofs: Vec<[u8; 32]> = Vec::new();
    for record in records.into_iter().rev() {
        let mut to_hash = Vec::from(record);
        if !proofs.is_empty() {
            to_hash.extend_from_slice(&proofs[0]);
            to_hash.push(1);
        } else {
            to_hash.push(0);
        }
        let hash_result = sha256_hash(&to_hash);
        proofs.insert(0, hash_result);
    }

    proofs[0]
}

impl SXGInput {
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.payload[self.data_to_verify_start_index
            ..self.data_to_verify_start_index + self.data_to_verify.len()]
            != self.data_to_verify
        {
            return Ok(false);
        }

        let prefix = (b"mi-sha256-03=").to_vec();
        let payload = calculate_integrity(&self.payload, 16384).to_vec();

        let mice_payload = base64::prelude::BASE64_STANDARD.encode(payload);
        let mice = mice_payload.as_bytes();
        let mice_bytes = [prefix, mice.to_vec()].concat();

        if self.final_payload
            [self.integrity_start_index..self.integrity_start_index + mice_bytes.len()]
            != mice_bytes[..]
        {
            return Ok(false);
        }

        Ok(
            verify_ecdsa_p256_r_s(&self.final_payload, &self.r, &self.s, &self.px, &self.py)
                .is_ok(),
        )
    }

    pub fn default_testcase_1() -> SXGInput {
        let final_payload = FINAL_PAYLOAD_1;
        let data_to_verify = DATA_TO_VERIFY_1;
        let payload = PAYLOAD_1;

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

        SXGInput {
            final_payload: final_payload.to_vec(),
            data_to_verify: data_to_verify.to_vec(),
            data_to_verify_start_index,
            integrity_start_index,
            payload: payload.to_vec(),
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
            px: px.try_into().unwrap(),
            py: py.try_into().unwrap(),
        }
    }

    pub fn default_testcase_2() -> SXGInput {
        let final_payload = FINAL_PAYLOAD_2;
        let data_to_verify = DATA_TO_VERIFY_2;
        let payload = PAYLOAD_2;

        let data_to_verify_start_index = 7504;
        let integrity_start_index = 349;

        let px = "E3718107FBB87954103F30F5D611F3A16D2997FFA6830EEEF666B243FD562594";
        let py = "C3FD5B2E946914400E26DC518AF9CEA72080148A22377F36902EEB0FBA2BD454";

        let r = "8F05B0DC32FE4F4EB60C630BFAA722DC9839202BC02E04B0AB3F97112E2E683C";
        let s = "FECEAC9E4DDDA1A332C60504ADDADD6BC7986370B2D26ED9172E6334EEE76608";

        let r = hex::decode(r).unwrap();
        let s = hex::decode(s).unwrap();

        let px = hex::decode(px).unwrap();
        let py = hex::decode(py).unwrap();

        SXGInput {
            final_payload: final_payload.to_vec(),
            data_to_verify: data_to_verify.to_vec(),
            data_to_verify_start_index,
            integrity_start_index,
            payload: payload.to_vec(),
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
            px: px.try_into().unwrap(),
            py: py.try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sxg::SXGInput;

    #[test]
    fn test_sxg() {
        let default_input = SXGInput::default_testcase_1();
        assert!(default_input.verify().unwrap());

        let default_input = SXGInput::default_testcase_2();
        assert!(default_input.verify().unwrap());
    }
}
