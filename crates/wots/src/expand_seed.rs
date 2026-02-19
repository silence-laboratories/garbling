use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};
use sl_compute_common::BinaryString;

use crate::{
    constants::{N, PADDING_LENGTH, WOTS_LEN},
    sha_256::build_sha256_circuit,
    utils::int_to_bits,
};

pub fn build_expand_seed_circuit(
    address: &BinaryString,
    pub_seed: &BinaryString,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    assert_eq!(address.length, 8 * 5 * 4);

    let input_seed_ids = builder.new_inputs(N as u16 * 8);

    let prf_circuit = build_prf_keygen_circuit(8 * 32 * 2);

    for i in 0..WOTS_LEN {
        let add_chain = int_to_bits(i as u128, 32);

        let add_hash = int_to_bits(0, 32);

        let mut data = pub_seed.clone();
        data.extend(address);
        data.extend(&add_chain);
        data.extend(&add_hash);
        data.extend(&add_hash);

        let data_ids = (0..data.length as usize)
            .map(|v| {
                let val = if data.get(v) { 1 } else { 0 };
                builder.constant(val)
            })
            .collect::<Vec<_>>();

        let ex_seed_ids =
            builder.add_circuit(&prf_circuit, &[&input_seed_ids, &data_ids]);

        for i in ex_seed_ids {
            builder.output(i);
        }
    }

    builder.finish()
}

pub fn build_prf_keygen_circuit(data_len: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let key = builder.new_inputs(N as u16 * 8);
    let data = builder.new_inputs(data_len as u16);

    let pads = int_to_bits(4, PADDING_LENGTH * 8);

    let padding_ids = (0..PADDING_LENGTH * 8)
        .map(|v| {
            let val = if pads.get(v) { 1 } else { 0 };
            builder.constant(val)
        })
        .collect::<Vec<_>>();

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

    use crate::{
        constants::WOTS_LEN, eval::evaluate,
        expand_seed::build_expand_seed_circuit,
        utils::u8_vec_to_binary_string,
    };

    #[test]
    fn test_expand_seed() {
        let pub_seed = u8_vec_to_binary_string(vec![0u8; 32]);
        let address = u8_vec_to_binary_string(vec![0u8; 20]);

        let input_seed = vec![false; 256];

        let circ = build_expand_seed_circuit(&address, &pub_seed);

        let out = evaluate(&circ, &[&input_seed]);

        for i in 0..WOTS_LEN {
            println!(
                "{}",
                bool_vec_to_hex(out[256 * i..256 * (i + 1)].to_vec())
            )
        }
    }
}
