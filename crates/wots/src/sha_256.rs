use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};
use sl_compute_common::BinaryString;

use crate::constants::{N, PADDING_LENGTH};

pub const SHA256_CIRCUIT: &str = include_str!("../../../circuits/sha256.txt");

pub fn build_sha256_circuit(input_len: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let chaining_state_hex: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
        0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut chaining_state: BinaryString = BinaryString::with_capacity(256);
    for id in 0..chaining_state_hex.len() {
        let value = chaining_state_hex[7 - id];
        let mut temp2 = Vec::new();
        for i in 0..32 {
            chaining_state.push((value >> i) & 1 == 1);
            temp2.push((value >> i) & 1 == 1);
        }
    }

    let mut chainingstate_ids = Vec::new();
    for i in 0..chaining_state.length as usize {
        let val = if chaining_state.get(i) { 1 } else { 0 };
        chainingstate_ids.push(builder.constant(val));
    }

    let input_ids = builder.new_inputs(input_len as u16);

    let mut padded_input = input_ids.clone();
    padded_input.push(builder.constant(1));

    let k = (448 - (padded_input.len() % 512) + 512) % 512;

    for _ in 0..k {
        padded_input.push(builder.constant(0));
    }

    let length_bits = input_len.to_be_bytes();

    for byte in length_bits.iter() {
        for i in (0..8).rev() {
            let value = ((byte >> i) & 1u8) as u16;
            padded_input.push(builder.constant(value));
        }
    }

    let count = padded_input.len() / 512;

    let sha256_circuit = BinaryCircuit::parse(SHA256_CIRCUIT).unwrap();

    for i in 0..count {
        let mut block_inp = padded_input[512 * i..512 * (i + 1)].to_vec();
        block_inp.reverse();

        let curr_chainingstate_ids = builder
            .add_circuit(&sha256_circuit, &[&block_inp, &chainingstate_ids]);

        chainingstate_ids = curr_chainingstate_ids;
    }

    for i in 0..chainingstate_ids.len() {
        builder.output(chainingstate_ids[chainingstate_ids.len() - i - 1]);
    }

    builder.finish()
}

pub fn build_f_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let key = builder.new_inputs(N as u16 * 8);
    let data = builder.new_inputs(N as u16 * 8);

    let padding_ids = vec![builder.constant(0); PADDING_LENGTH * 8];

    let hash_input = [padding_ids, key, data].concat();

    let sha_circuit = build_sha256_circuit(hash_input.len());

    let hash_output = builder.add_circuit(&sha_circuit, &[&hash_input]);

    for i in hash_output {
        builder.output(i);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use garbled_circuit::utilities::utils::bool_vec_to_hex;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use sha2::Digest;

    use crate::{eval::evaluate, sha_256::build_sha256_circuit};

    fn vec_bytes_to_vec_bool(bytes: &[u8]) -> Vec<bool> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);

        for byte in bytes {
            for i in (0..8).rev() {
                // MSB → LSB
                bits.push(((byte >> i) & 1) == 1);
            }
        }

        bits
    }

    #[test]
    fn test_sha_256() {
        let mut iplen = 8;

        for _ in 0..10 {
            let circuit = build_sha256_circuit(iplen * 8);

            let mut bl = vec![0u8; iplen];

            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut bl);

            let blbool = vec_bytes_to_vec_bool(&bl);

            let output = evaluate(&circuit, &[&blbool]);

            let sha = sha2::Sha256::new_with_prefix(bl);

            let out = sha.finalize().to_vec();

            let expected = hex::encode(out);

            let actual = bool_vec_to_hex(output);

            assert_eq!(expected, actual, "{iplen}");

            iplen *= 2;
        }
    }
}
