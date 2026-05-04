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

pub fn create_blake2b_circuit(input_len: usize) -> BinaryCircuit {
    assert_eq!(input_len % 8, 0);
    let mut builder = CircuitBuilder::new();
    let inputs = builder.new_inputs(input_len as u16);

    let blocks = inputs.chunks(1024);

    let mut h_words = H_WORDS
        .iter()
        .map(|&v| {
            let val = if v { 1 } else { 0 };
            builder.constant(val)
        })
        .collect::<Vec<_>>();

    let num_of_blocks = blocks.len();

    let blake2b_circuit = BinaryCircuit::parse(BLAKE2B_CIRCUIT).unwrap();

    let mut bytes_processed = 0;
    for (i, blk) in blocks.enumerate() {
        let is_last_val = if i == (num_of_blocks - 1) { 1 } else { 0 };
        bytes_processed += blk.len() as u64 / 8;
        let mut in1 = Vec::with_capacity(1024);
        in1.extend_from_slice(&h_words);
        for j in 0..64 {
            let val = (bytes_processed >> j) & 1;
            in1.push(builder.constant(val as u16));
        }
        in1.extend_from_slice(&[builder.constant(is_last_val); 64]);
        in1.extend_from_slice(&vec![builder.constant(0); 1024 - in1.len()]);

        let mut in2 = blk.to_vec();
        in2.extend_from_slice(&vec![builder.constant(0); 1024 - blk.len()]);

        h_words = builder.add_circuit(&blake2b_circuit, &[&in1, &in2]);
    }
    for i in &h_words {
        builder.output(*i);
    }

    builder.finish()
}
