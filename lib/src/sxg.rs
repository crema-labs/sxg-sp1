use crate::{
    sha256_hash,
    test_case_1::{DATA_TO_VERIFY_1, FINAL_PAYLOAD_1, PAYLOAD_1},
    test_case_2::{DATA_TO_VERIFY_2, FINAL_PAYLOAD_2, PAYLOAD_2},
    verify_ecdsa_p256_r_s,
};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockParams {
    pub block_number: u64,
    pub block_hash: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SXGInput {
    pub final_payload: Vec<u8>,
    pub block_params: BlockParams,
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
        let verify_string = format!(
            "<script>\r
var coinShort = 'BTC', urlParam = 'coin='+coinShort.toLowerCase(),\r
    blockID = {}, blockHash = '{}',\r
    hasMeta = 0;\r
</script>",
            self.block_params.block_number, self.block_params.block_hash
        );

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

        // convert verify_string to bytes
        let verify_string_bytes = verify_string.as_bytes();

        // convert to string
        let payload = String::from_utf8(self.payload.clone());
        let string_bytes  = String::from_utf8(verify_string_bytes.to_vec());

        println!("payload: {:?}", payload.unwrap());
        println!("verify_string_bytes: {:?}", string_bytes.unwrap());



        // find if verify_string_bytes is in final_payload or not, if not found return false
        self.payload
            .windows(verify_string_bytes.len())
            .position(|window| window == verify_string_bytes)
            .ok_or("payload verification failed")?;

        Ok(
            verify_ecdsa_p256_r_s(&self.final_payload, &self.r, &self.s, &self.px, &self.py)
                .is_ok(),
        )
    }

    pub fn default_testcase_1() -> SXGInput {
        let final_payload = FINAL_PAYLOAD_1;
        let payload = PAYLOAD_1;

        let px = "96c5e1904a90ef4c3fa99fba0767f9af8786307b2ccb069ad7f32008b3583bc7";
        let py = "e9f9c412e20ea07a5733dc6199ad16d723ee5392e2cfc33bc0279ddcde8e4118";

        let r = "f8aece1b178e87347127cfc07ef58ebea26d23f2781f5ccbdc5965ba30877b4e";
        let s = "8b197e5ef505e006840f6e5aac3a689d192872127f64ea52050b6bc87f6bc25f";

        let r = hex::decode(r).unwrap();
        let s = hex::decode(s).unwrap();

        let px = hex::decode(px).unwrap();
        let py = hex::decode(py).unwrap();

        println!("r: {:?}", r);
        println!("s: {:?}", s);

        println!("px: {:?}", px);
        println!("py: {:?}", py);

        SXGInput {
            final_payload: final_payload.to_vec(),
            integrity_start_index: 332,
            block_params: BlockParams {
                block_number: 869404,
                block_hash: "000000000000000000025f8f185ff4bb3879cc3455c965687947a2963e55fe7e"
                    .to_string(),
            },
            payload: payload.to_vec(),
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
            px: px.try_into().unwrap(),
            py: py.try_into().unwrap(),
        }
    }

    //     pub fn default_testcase_2() -> SXGInput {
    //         let final_payload = FINAL_PAYLOAD_2;
    //         let data_to_verify = DATA_TO_VERIFY_2;
    //         let payload = PAYLOAD_2;

    //         let data_to_verify_start_index = 7504;
    //         let integrity_start_index = 349;

    //         let px = "E3718107FBB87954103F30F5D611F3A16D2997FFA6830EEEF666B243FD562594";
    //         let py = "C3FD5B2E946914400E26DC518AF9CEA72080148A22377F36902EEB0FBA2BD454";

    //         let r = "8F05B0DC32FE4F4EB60C630BFAA722DC9839202BC02E04B0AB3F97112E2E683C";
    //         let s = "FECEAC9E4DDDA1A332C60504ADDADD6BC7986370B2D26ED9172E6334EEE76608";

    //         let r = hex::decode(r).unwrap();
    //         let s = hex::decode(s).unwrap();

    //         let px = hex::decode(px).unwrap();
    //         let py = hex::decode(py).unwrap();

    //         SXGInput {
    //             final_payload: final_payload.to_vec(),
    //             data_to_verify: data_to_verify.to_vec(),
    //             data_to_verify_start_index,
    //             integrity_start_index,
    //             payload: payload.to_vec(),
    //             r: r.try_into().unwrap(),
    //             s: s.try_into().unwrap(),
    //             px: px.try_into().unwrap(),
    //             py: py.try_into().unwrap(),
    //         }
    //     }
}

#[cfg(test)]
mod tests {
    use crate::sxg::SXGInput;

    #[test]
    fn test_sxg() {
        let default_input = SXGInput::default_testcase_1();
        assert!(default_input.verify().unwrap());

        // let default_input = SXGInput::default_testcase_2();
        // assert!(default_input.verify().unwrap());
    }
}
