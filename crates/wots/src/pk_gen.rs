use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};
use sl_compute_common::BinaryString;

use crate::{
    chain::build_chain_circuit,
    constants::{WOTS_LEN, WOTS_W},
    expand_seed::build_expand_seed_circuit,
    get_circuit::get_bristol_fashion,
    utils::int_to_bits,
};

pub fn build_pk_gen_circuit(
    address: &BinaryString,
    pub_seed: &BinaryString,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    assert_eq!(address.length, 8 * 5 * 4);

    let sk_seed_ids = builder.new_inputs(256);

    let expand_circ = build_expand_seed_circuit(address, pub_seed);

    let seeds_temp = builder.add_circuit(&expand_circ, &[&sk_seed_ids]);

    let sk_ids = (0..WOTS_LEN)
        .map(|i| seeds_temp[256 * i..256 * (i + 1)].to_vec())
        .collect::<Vec<_>>();

    #[allow(clippy::needless_range_loop)]
    for i in 0..WOTS_LEN {
        let add_chain = int_to_bits(i as u128, 32);

        let mut add = address.clone();
        add.extend(&add_chain);

        let chain_circuit =
            build_chain_circuit(0, WOTS_W - 1, pub_seed, &add);

        let pk_ids = builder.add_circuit(&chain_circuit, &[&sk_ids[i]]);

        for i in pk_ids {
            builder.output(i);
        }
    }

    builder.finish()
}

pub fn get_pk_gen_circuit_bfs(
    address: &BinaryString,
    pub_seed: &BinaryString,
) -> String {
    let circuit = build_pk_gen_circuit(address, pub_seed);

    get_bristol_fashion(&circuit)
}

#[cfg(test)]
mod tests {
    use garbled_circuit::utilities::utils::bool_vec_to_hex;

    use crate::{
        constants::{N, WOTS_LEN},
        eval::evaluate,
        pk_gen::build_pk_gen_circuit,
        utils::u8_vec_to_binary_string,
    };

    #[test]
    fn test_pk_gen() {
        let seed_byte = vec![1; 32];

        let pub_seed = u8_vec_to_binary_string(seed_byte);
        let address = u8_vec_to_binary_string(vec![0; 5 * 4]);

        let circ = build_pk_gen_circuit(&address, &pub_seed);

        let out = evaluate(&circ, &[&[false; 256]]);

        for i in 0..WOTS_LEN {
            println!(
                "{}",
                bool_vec_to_hex(out[8 * N * i..8 * N * (i + 1)].to_vec())
            )
        }
    }
}
