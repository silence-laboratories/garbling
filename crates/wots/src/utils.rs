use sha2::Digest;
use sl_compute_common::BinaryString;

use crate::constants::{
    PADDING_LENGTH, WOTS_LEN, WOTS_LEN1, WOTS_LEN2, WOTS_LOG_W, WOTS_W,
};

pub fn int_to_bits(val: u128, bitlen: usize) -> BinaryString {
    let mut out = BinaryString::new();

    if bitlen >= 128 {
        for _ in 0..(bitlen - 128) {
            out.push(false);
        }
        for i in (bitlen - 128)..bitlen {
            out.push((val >> (bitlen - 1 - i)) & 1 == 1);
        }
    } else {
        for i in 0..bitlen {
            out.push((val >> (bitlen - 1 - i)) & 1 == 1);
        }
    }

    out
}

pub fn u8_vec_to_binary_string(vec_u8: Vec<u8>) -> BinaryString {
    let mut output: BinaryString = BinaryString::with_capacity(vec_u8.len());
    for byte in vec_u8 {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            output.push(bit != 0);
        }
    }

    output
}

pub fn binary_string_to_u8_vec(input: BinaryString) -> Vec<u8> {
    let mut vec_u8 = Vec::new();
    let mut byte = 0u8;

    for i in 0..(input.length as usize) {
        if input.get(i) {
            byte |= 1 << (7 - (i % 8));
        }
        if i % 8 == 7 {
            vec_u8.push(byte);
            byte = 0;
        }
    }
    if input.length % 8 != 0 {
        vec_u8.push(byte);
    }

    vec_u8
}

pub fn prf(key: &BinaryString, data: &BinaryString) -> BinaryString {
    let mut temp = int_to_bits(3, PADDING_LENGTH * 8);

    temp.extend(key);
    temp.extend(data);

    // println!("{} {}", key.length, data.length);
    let conc = binary_string_to_u8_vec(temp);

    // println!("{}", hex::encode(&conc));

    let sha = sha2::Sha256::new_with_prefix(conc);

    let prf_byte = sha.finalize().to_vec();

    u8_vec_to_binary_string(prf_byte)
}

pub fn chain_lengths(msg: &[u8]) -> Vec<u32> {
    // assert!(WOTS_W.is_power_of_two());

    // let WOTS_LOG_W = WOTS_W.trailing_zeros();
    // let n = msg.len() as u32;

    // let WOTS_LEN1 = (8 * n + WOTS_LOG_W - 1) / WOTS_LOG_W;
    // let WOTS_LEN2 = ((WOTS_LEN1 * (WOTS_W - 1)).ilog(WOTS_W) + 1) as u32;
    // let len = WOTS_LEN1 + WOTS_LEN2;

    let mut lengths = vec![0u32; WOTS_LEN];

    // ---------- base_w(msg) ----------
    let mut in_idx = 0usize;
    let mut total = 0u32;
    let mut bits = 0u32;

    #[allow(clippy::needless_range_loop)]
    for i in 0..WOTS_LEN1 {
        if bits == 0 {
            total = msg[in_idx] as u32;
            in_idx += 1;
            bits = 8;
        }

        bits -= WOTS_LOG_W as u32;
        lengths[i] = (total >> bits) & (WOTS_W as u32 - 1);
    }

    // ---------- checksum ----------
    let mut csum = 0u32;
    #[allow(clippy::needless_range_loop)]
    for i in 0..WOTS_LEN1 {
        csum += WOTS_W as u32 - 1 - lengths[i];
    }

    // Align checksum to byte boundary
    let shift = (WOTS_LEN2 * WOTS_LOG_W) % 8;
    if shift != 0 {
        csum <<= 8 - shift;
    }

    // ---- Convert checksum to minimal byte array ----
    let csum_bits = WOTS_LEN2 * WOTS_LOG_W;
    let csum_bytes_len = csum_bits.div_ceil(8);

    let mut csum_bytes = vec![0u8; csum_bytes_len];
    for i in 0..csum_bytes_len {
        csum_bytes[csum_bytes_len - 1 - i] = (csum >> (8 * i)) as u8;
    }

    // ---------- base_w(csum_bytes) ----------
    let mut in_idx = 0usize;
    let mut total = 0u32;
    let mut bits = 0u32;

    #[allow(clippy::needless_range_loop)]
    for i in WOTS_LEN1..WOTS_LEN {
        if bits == 0 {
            total = csum_bytes[in_idx] as u32;
            in_idx += 1;
            bits = 8;
        }

        bits -= WOTS_LOG_W as u32;
        lengths[i] = (total >> bits) & (WOTS_W as u32 - 1);
    }

    lengths
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    use crate::{constants::N, utils::chain_lengths};

    #[test]
    fn test_chain_lengths() {
        let mut rng = StdRng::from_entropy();
        let mut msg = [0u8; N];
        rng.fill_bytes(&mut msg);

        println!("msg=  {msg:?}");

        let lengths = chain_lengths(&msg);

        println!("lengths = {lengths:?}");
    }
}
