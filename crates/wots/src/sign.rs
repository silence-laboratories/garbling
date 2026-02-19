use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};
use sl_compute_common::BinaryString;

use crate::{
    chain::build_chain_circuit,
    constants::{N, WOTS_LEN},
    expand_seed::build_expand_seed_circuit,
    get_circuit::get_bristol_fashion,
    utils::{chain_lengths, int_to_bits},
};

pub fn build_sign_circuit(
    msg: &[u8; 32],
    pub_seed: &BinaryString,
    address: &BinaryString,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let sk_seed_ids = builder.new_inputs(N as u16 * 8);

    let expand_circuit = build_expand_seed_circuit(address, pub_seed);

    let seeds_temp = builder.add_circuit(&expand_circuit, &[&sk_seed_ids]);

    let sk_ids = (0..WOTS_LEN)
        .map(|i| seeds_temp[256 * i..256 * (i + 1)].to_vec())
        .collect::<Vec<_>>();

    let lengths = chain_lengths(msg);

    for i in 0..WOTS_LEN {
        let add_chain = int_to_bits(i as u128, 32);

        let mut add = address.clone();
        add.extend(&add_chain);

        let chain_circuit =
            build_chain_circuit(0, lengths[i] as usize, pub_seed, &add);

        let chain_output = builder.add_circuit(&chain_circuit, &[&sk_ids[i]]);

        for i in chain_output {
            builder.output(i);
        }
    }

    builder.finish()
}

pub fn get_sign_circuit_bfs(
    msg: &[u8; 32],
    address: &BinaryString,
    pub_seed: &BinaryString,
) -> String {
    let circuit = build_sign_circuit(msg, address, pub_seed);

    get_bristol_fashion(&circuit)
}

#[cfg(test)]
mod tests {
    use garbled_circuit::utilities::utils::bool_vec_to_hex;

    use crate::{
        constants::{N, WOTS_LEN},
        eval::evaluate,
        sign::build_sign_circuit,
        utils::u8_vec_to_binary_string,
    };

    #[test]
    fn test_sign() {
        let seed_byte = vec![1; 32];

        let pub_seed = u8_vec_to_binary_string(seed_byte);
        let address = u8_vec_to_binary_string(vec![0; 5 * 4]);

        let msg = [
            72, 236, 137, 90, 32, 66, 13, 191, 81, 59, 6, 233, 46, 155, 224,
            164, 153, 48, 233, 152, 231, 111, 120, 222, 117, 212, 246, 88,
            235, 159, 27, 4,
        ];

        let circ = build_sign_circuit(&msg, &pub_seed, &address);

        let sig = evaluate(&circ, &[&[false; 256]]);

        for i in 0..WOTS_LEN {
            println!(
                "{}",
                bool_vec_to_hex(sig[8 * N * i..8 * N * (i + 1)].to_vec())
            )
        }
    }
}
