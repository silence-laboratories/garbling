use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};

use crate::blake2b::create_blake2b_circuit;

/// Converts a vector of `u8` values to a vector of `bool` values
pub fn u8_vec_to_bool_vec(vec_u8: Vec<u8>) -> Vec<bool> {
    let mut output = Vec::with_capacity(vec_u8.len() * 8);
    for byte in vec_u8 {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            output.push(bit != 0);
        }
    }
    output
}

pub fn build_zcash_blake2b_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let msg_ids = builder.new_inputs(256);

    let ints = [6u32, 7, 8];

    let hash_circuit = create_blake2b_circuit(256 + 32);
    for i in ints {
        let index_be = i.to_be_bytes();
        let index_bool = u8_vec_to_bool_vec(index_be.to_vec());
        let index_ids = index_bool
            .iter()
            .map(|v| {
                let val = if *v { 1 } else { 0 };
                builder.constant(val)
            })
            .collect::<Vec<_>>();

        let mut final_msg = msg_ids.clone();
        final_msg.extend_from_slice(&index_ids);

        let hash_ids = builder.add_circuit(&hash_circuit, &[&final_msg]);

        for i in hash_ids {
            builder.output(i);
        }
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use pasta_curves::{
        group::ff::{Field, PrimeField},
        pallas::Scalar,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use sl_compute_common::BinaryString;

    use crate::eval::evaluate;

    use super::*;

    #[test]
    fn test_zcash_blake2b_circuit() {
        let circ = build_zcash_blake2b_circuit();
        let rng = StdRng::from_entropy();

        let scalar = Scalar::random(rng);
        let scalar_bool = u8_vec_to_bool_vec(scalar.to_repr().to_vec());

        let out = evaluate(&circ, &[&scalar_bool]);
        let mut ask_i = BinaryString::new();
        let mut nk_i = BinaryString::new();
        let mut rivk_i = BinaryString::new();
        for i in &out[..512] {
            ask_i.push(*i);
        }
        for i in &out[512..1024] {
            nk_i.push(*i);
        }
        for i in &out[1024..] {
            rivk_i.push(*i);
        }
        println!("ask_i: {:?}", hex::encode(ask_i.value));
        println!("nk_i: {:?}", hex::encode(nk_i.value));
        println!("rivk_i: {:?}", hex::encode(rivk_i.value));
    }
}
