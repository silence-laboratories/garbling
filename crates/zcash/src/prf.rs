use garbled_circuit::circuit::{BinaryCircuit, CircuitBuilder};

use crate::{blake2b::create_blake2b_zcash_circuit, utils::bytes_to_bits_be};

pub fn build_prf_expand_circuit(t: u8) -> BinaryCircuit {
    let t_bits = bytes_to_bits_be(&[t]);

    let mut builder = CircuitBuilder::new();

    let mut sk = builder.new_inputs(32 * 8);
    sk.extend_from_slice(
        &t_bits
            .iter()
            .map(|v| builder.constant(*v))
            .collect::<Vec<_>>(),
    );
    // inputs.extend_from_slice(&vec![
    //     builder.constant(false);
    //     1024 - inputs.len()
    // ]);
    let hash_circ = create_blake2b_zcash_circuit(sk.len());
    let out = builder.add_circuit(&hash_circ, &[&sk]);
    for i in out {
        builder.output(i);
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use crate::{
        eval::evaluate,
        prf::build_prf_expand_circuit,
        utils::{bits_to_bytes_le, bytes_to_bits_be},
    };
    use blake2b_simd::Params;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    /// PRF^expand_Orchard(sk, t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t)
    fn prf_expand(sk: &[u8; 32], t: u8) -> [u8; 64] {
        let mut hasher = Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state();
        hasher.update(sk);
        hasher.update(&[t]);
        let hash = hasher.finalize();
        let mut res = [0u8; 64];
        res.copy_from_slice(hash.as_bytes());
        res
    }

    #[test]
    fn test_prf_expand_circuit() {
        let mut rng = StdRng::from_entropy();
        let mut sk: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let t = 6;
        let circ = build_prf_expand_circuit(t);
        let bits = bytes_to_bits_be(&sk);
        let out = evaluate(&circ, &[&bits]);

        assert_eq!(bits_to_bytes_le(&out), prf_expand(&sk, t).to_vec());
    }
}
