use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};

pub const BLAKE2B_CIRCUIT: &str =
    include_str!("../../../circuits/blake2b.txt");

pub const H_WORDS: [bool; 512] = [
    false, false, false, true, false, false, true, false, true, false, false,
    true, false, false, true, true, true, false, true, true, true, true,
    false, true, false, true, false, false, true, true, true, true, true,
    true, true, false, false, true, true, false, false, true, true, false,
    false, true, true, true, true, false, false, true, false, false, false,
    false, false, true, false, true, false, true, true, false, true, true,
    false, true, true, true, false, false, true, true, true, false, false,
    true, false, true, false, true, false, true, false, false, true, true,
    false, false, true, false, false, false, false, true, true, false, true,
    false, false, false, false, true, false, true, true, true, false, true,
    false, true, true, true, true, false, false, true, true, false, true,
    true, false, true, true, true, false, true, true, true, false, true,
    false, true, false, false, false, false, false, true, true, true, true,
    true, false, false, true, false, true, false, false, true, false, true,
    true, true, true, true, true, true, false, true, false, false, true,
    true, true, false, true, true, false, false, true, true, true, true,
    false, true, true, true, false, true, true, false, false, false, true,
    true, true, true, false, false, true, false, false, false, true, true,
    true, true, false, true, true, false, true, true, false, false, true,
    false, true, true, true, false, false, false, true, true, true, true,
    true, false, true, false, false, true, false, true, true, true, false,
    false, true, false, true, false, true, true, true, true, true, true,
    true, true, false, false, true, false, true, false, true, false, false,
    true, false, true, true, false, false, false, true, false, true, true,
    false, true, false, false, false, false, false, true, false, true, true,
    false, false, true, true, true, true, false, true, true, false, true,
    false, true, true, true, true, true, true, true, true, false, false,
    true, false, false, true, false, true, false, false, true, true, true,
    false, false, false, false, true, false, false, false, true, false, true,
    false, true, true, true, true, true, false, false, false, false, false,
    true, true, false, true, true, false, false, true, true, true, true,
    true, false, false, true, true, false, true, false, true, false, false,
    false, false, true, true, false, false, false, true, false, false, false,
    true, false, true, true, false, true, false, true, false, false, false,
    false, false, true, true, false, true, true, false, false, true, true,
    true, false, true, false, true, true, false, true, false, true, true,
    true, true, false, true, true, false, false, false, false, false, true,
    false, true, true, false, true, true, true, true, true, true, true,
    false, true, false, true, false, true, true, false, false, true, true,
    false, true, true, true, true, false, false, false, false, false, true,
    true, true, true, true, true, false, false, false, true, false, false,
    true, true, true, true, false, true, false, false, false, false, true,
    false, false, false, true, true, true, true, true, true, false, true,
    true, false, false, true, false, false, false, true, false, false, true,
    true, false, false, false, true, false, true, true, false, false, true,
    true, false, false, false, false, false, true, true, true, true, true,
    false, true, true, false, true, false,
];

pub const H_WORDS_ZCASH: [bool; 512] = [
    false, false, false, true, false, false, true, false, true, false, false,
    true, false, false, true, true, true, false, true, true, true, true,
    false, true, false, true, false, false, true, true, true, true, true,
    true, true, false, false, true, true, false, false, true, true, false,
    false, true, true, true, true, false, false, true, false, false, false,
    false, false, true, false, true, false, true, true, false, true, true,
    false, true, true, true, false, false, true, true, true, false, false,
    true, false, true, false, true, false, true, false, false, true, true,
    false, false, true, false, false, false, false, true, true, false, true,
    false, false, false, false, true, false, true, true, true, false, true,
    false, true, true, true, true, false, false, true, true, false, true,
    true, false, true, true, true, false, true, true, true, false, true,
    false, true, false, false, false, false, false, true, true, true, true,
    true, false, false, true, false, true, false, false, true, false, true,
    true, true, true, true, true, true, false, true, false, false, true,
    true, true, false, true, true, false, false, true, true, true, true,
    false, true, true, true, false, true, true, false, false, false, true,
    true, true, true, false, false, true, false, false, false, true, true,
    true, true, false, true, true, false, true, true, false, false, true,
    false, true, true, true, false, false, false, true, true, true, true,
    true, false, true, false, false, true, false, true, true, true, false,
    false, true, false, true, false, true, true, true, true, true, true,
    true, true, false, false, true, false, true, false, true, false, false,
    true, false, true, true, false, false, false, true, false, true, true,
    false, true, false, false, false, false, false, true, false, true, true,
    false, false, true, true, true, true, false, true, true, false, true,
    false, true, true, true, true, true, true, true, true, false, false,
    true, false, false, true, false, true, false, false, true, true, true,
    false, false, false, false, true, false, false, false, true, false, true,
    false, true, true, true, true, true, false, false, false, false, false,
    true, true, false, true, true, false, false, true, true, true, true,
    true, false, false, true, true, false, true, false, true, false, false,
    false, false, true, true, false, false, false, true, false, false, false,
    true, false, true, true, false, true, false, true, false, false, false,
    false, false, true, true, false, true, true, false, false, true, true,
    false, false, false, true, true, false, false, false, true, true, true,
    true, false, true, true, false, false, false, false, false, true, false,
    false, false, false, false, true, false, false, false, true, true, true,
    false, false, false, false, true, true, false, true, true, false, false,
    false, false, true, false, true, true, false, false, false, true, true,
    true, true, true, false, false, true, true, false, true, false, false,
    true, false, false, false, false, false, false, false, false, false,
    false, true, false, false, false, false, false, true, false, false,
    false, true, true, true, false, true, true, true, false, false, true,
    false, true, false, false, true, false, false, false, false, true, false,
    true, false, true, true, false, true, false, false, false, false, true,
    true, true, true, true, true, true, false, false,
];

pub fn create_blake2b_circuit(input_len: usize) -> BinaryCircuit {
    assert_eq!(input_len % 8, 0);
    let mut builder = CircuitBuilder::new();
    let inputs = builder.new_inputs(input_len as u16);

    let blocks = inputs.chunks(1024);

    let mut h_words = H_WORDS
        .iter()
        .map(|&v| builder.constant(v))
        .collect::<Vec<_>>();

    let num_of_blocks = blocks.len();

    let blake2b_circuit = BinaryCircuit::parse(BLAKE2B_CIRCUIT).unwrap();

    let mut bytes_processed = 0;
    for (i, blk) in blocks.enumerate() {
        let is_last_val = i == (num_of_blocks - 1);
        bytes_processed += blk.len() as u64 / 8;
        let mut in1 = Vec::with_capacity(1024);
        in1.extend_from_slice(&h_words);
        for j in 0..64 {
            let val = (bytes_processed >> j) & 1;
            in1.push(builder.constant(val != 0));
        }
        in1.extend_from_slice(&[builder.constant(is_last_val); 64]);
        in1.extend_from_slice(&vec![
            builder.constant(false);
            1024 - in1.len()
        ]);

        let mut in2 = blk.to_vec();
        in2.extend_from_slice(&vec![
            builder.constant(false);
            1024 - blk.len()
        ]);

        h_words = builder.add_circuit(&blake2b_circuit, &[&in1, &in2]);
    }
    for i in &h_words {
        builder.output(*i);
    }

    builder.finish()
}

pub fn create_blake2b_zcash_circuit(input_len: usize) -> BinaryCircuit {
    assert_eq!(input_len % 8, 0);
    let mut builder = CircuitBuilder::new();
    let inputs = builder.new_inputs(input_len as u16);

    let blocks = inputs.chunks(1024);

    let mut h_words = H_WORDS_ZCASH
        .iter()
        .map(|&v| builder.constant(v))
        .collect::<Vec<_>>();

    let num_of_blocks = blocks.len();

    let blake2b_circuit = BinaryCircuit::parse(BLAKE2B_CIRCUIT).unwrap();

    let mut bytes_processed = 0;
    for (i, blk) in blocks.enumerate() {
        let is_last_val = i == (num_of_blocks - 1);
        bytes_processed += blk.len() as u64 / 8;
        let mut in1 = Vec::with_capacity(1024);
        in1.extend_from_slice(&h_words);
        for j in 0..64 {
            let val = (bytes_processed >> j) & 1;
            in1.push(builder.constant(val != 0));
        }
        in1.extend_from_slice(&[builder.constant(is_last_val); 64]);
        in1.extend_from_slice(&vec![
            builder.constant(false);
            1024 - in1.len()
        ]);

        let mut in2 = blk.to_vec();
        in2.extend_from_slice(&vec![
            builder.constant(false);
            1024 - blk.len()
        ]);

        h_words = builder.add_circuit(&blake2b_circuit, &[&in1, &in2]);
    }
    for i in &h_words {
        builder.output(*i);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use crate::{
        blake2b::{create_blake2b_circuit, create_blake2b_zcash_circuit},
        eval::evaluate,
        utils::{bits_to_bytes_le, bytes_to_bits_be},
    };
    use blake2b_simd::{Params, blake2b};
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    #[test]
    fn test_blake2b_circuit() {
        let mut rng = StdRng::from_entropy();
        let mut bytes: [u8; 201] = [1u8; 201];
        rng.fill_bytes(&mut bytes);
        let circ = create_blake2b_circuit(bytes.len() * 8);
        let bits = bytes_to_bits_be(&bytes);
        let out = evaluate(&circ, &[&bits]);

        assert_eq!(
            bits_to_bytes_le(&out),
            blake2b(&bytes).as_bytes().to_vec()
        );
    }

    #[test]
    fn test_blake2b_zcash_circuit() {
        let mut rng = StdRng::from_entropy();
        let mut bytes: [u8; 201] = [1u8; 201];
        rng.fill_bytes(&mut bytes);
        let circ = create_blake2b_zcash_circuit(bytes.len() * 8);
        let bits = bytes_to_bits_be(&bytes);
        let out = evaluate(&circ, &[&bits]);

        let mut hasher = Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state();
        hasher.update(&bytes);
        assert_eq!(
            bits_to_bytes_le(&out),
            hasher.finalize().as_bytes().to_vec()
        );
    }
}
