use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};
use sl_compute_common::BinaryString;

use crate::{
    constants::N,
    sha_256::build_f_circuit,
    utils::{int_to_bits, prf},
};

pub fn binstr_to_boolvec(val: &BinaryString) -> Vec<bool> {
    (0..val.length as usize)
        .map(|v| val.get(v))
        .collect::<Vec<_>>()
}

pub fn build_chain_circuit(
    start: usize,
    steps: usize,
    seed: &BinaryString,
    address: &BinaryString,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let input_ids = builder.new_inputs(N as u16 * 8);

    let mut tmp_ids = input_ids.clone();

    assert_eq!(address.length, 8 * 6 * 4);

    for j in start..steps {
        let add_hash = int_to_bits(j as u128, 32);

        let mut add = address.clone();
        add.extend(&add_hash);

        let mut add_key = add.clone();
        let mut add_mask = add.clone();

        add_key.extend(&int_to_bits(0, 32));
        add_mask.extend(&int_to_bits(1, 32));

        let key = prf(seed, &add_key);
        let bitmask = prf(seed, &add_mask);

        let mut key_ids = Vec::new();
        for i in 0..key.length as usize {
            let val = if key.get(i) { 1 } else { 0 };
            key_ids.push(builder.constant(val));
        }

        let mut bitmask_ids = Vec::new();
        for i in 0..bitmask.length as usize {
            let val = if bitmask.get(i) { 1 } else { 0 };
            bitmask_ids.push(builder.constant(val));
        }

        let masked_ids = tmp_ids
            .iter()
            .zip(bitmask_ids.iter())
            .map(|(x, y)| builder.xor(*x, *y))
            .collect::<Vec<_>>();

        let f_circuit = build_f_circuit();

        tmp_ids = builder.add_circuit(&f_circuit, &[&key_ids, &masked_ids]);
    }

    for i in tmp_ids {
        builder.output(i);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use garbled_circuit::utilities::utils::bool_vec_to_hex;

    use crate::{
        chain::build_chain_circuit, eval::evaluate,
        utils::u8_vec_to_binary_string,
    };

    #[test]
    fn test_chain() {
        let mut seed_byte = vec![1];
        seed_byte.extend_from_slice(&[0; 31]);

        let seed = u8_vec_to_binary_string(seed_byte);
        let address = u8_vec_to_binary_string(vec![0; 6 * 4]);
        // let input = u8_vec_to_binary_string(vec![0; 32]);
        let input = [false; 256];

        let circ = build_chain_circuit(0, 2, &seed, &address);

        let out = evaluate(&circ, &[&input]);

        // let outtemp = prf(&seed, &input);

        // let out = (0..outtemp.length as usize)
        //     .map(|v| outtemp.get(v))
        //     .collect::<Vec<_>>();

        println!("{}", bool_vec_to_hex(out));
    }
}
