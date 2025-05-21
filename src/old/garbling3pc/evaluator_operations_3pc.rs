use std::collections::HashMap;

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    old::garbling3pc::garbling3pc_errors::ThreePartyEvaluatorError,
    old::garbling2pc::{
        evaluator_operations::BinaryEvaluator,
        exec::{BinaryOperations, ExecutionPrimitives},
    },
    utilities::{hash_function::HashFunction, types::Block},
};

use super::threepartytraits::ThreePartyBinaryEvaluator;

/// Implements the `ThreePartyBinaryEvaluator` trait for `BinaryEvaluator`.
impl<H: HashFunction> ThreePartyBinaryEvaluator for BinaryEvaluator<H> {
    /// Evaluates a garbled binary circuit using the half-gate technique for the
    /// three-party garbled circuits protocol from <https://eprint.iacr.org/2015/931.pdf>.
    ///
    /// This function takes a garbled `BinaryCircuit`, garbler's encoded inputs and
    /// the evaluator's inputs in boolean form to return the encoded outputs.
    ///
    /// # Parameters
    ///
    /// * `circ` - The `BinaryCircuit` to be evaluated.
    /// * `garbler_inputs`: A `HashMap<usize, Block>` which maps the garbler's input
    ///   ids to its correspoding encoded garbler's inputs.
    /// * `evaluator_inputs` - A `HashMap<usize, Block>` which maps the evaluator's input
    ///   ids to its correspoding encoded evaluator's inputs.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    /// * A `HashMap<usize, Block>` which maps the output gate ids to encoded output blocks.
    /// * `Err(EvaluatorError)` - An error if the evaluation fails.
    fn evaluate_threeparty(
        &mut self,
        circ: &BinaryCircuit,
        garbler_inputs: &HashMap<usize, Block>,
        evaluator_inputs: &HashMap<usize, Block>,
    ) -> Result<HashMap<usize, Block>, ThreePartyEvaluatorError> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    if id >= garbler_inputs.len() {
                        return Err(ThreePartyEvaluatorError::GarblerIpLenError(
                            id,
                            garbler_inputs.len(),
                        ));
                    }
                    let input_hash = garbler_inputs.get(&id).unwrap().to_owned();
                    (None, input_hash)
                }
                BinaryGate::EvaluatorInput { id } => {
                    if id >= evaluator_inputs.len() {
                        return Err(ThreePartyEvaluatorError::EvaluatorIpLenError(
                            id,
                            evaluator_inputs.len(),
                        ));
                    }
                    let input_hash = evaluator_inputs.get(&id).unwrap().to_owned();
                    (None, input_hash)
                }
                BinaryGate::Constant { val } => (None, self.constant(val)?),
                BinaryGate::Inv { xid, out } => (
                    out,
                    self.negate(
                        cache[xid]
                            .as_ref()
                            .ok_or(ThreePartyEvaluatorError::CacheItemError(xid))?,
                    )?,
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid]
                            .as_ref()
                            .ok_or(ThreePartyEvaluatorError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(ThreePartyEvaluatorError::CacheItemError(yid))?,
                    )?,
                ),
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => (
                    out,
                    self.and(
                        cache[xid]
                            .as_ref()
                            .ok_or(ThreePartyEvaluatorError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(ThreePartyEvaluatorError::CacheItemError(yid))?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut garbled_output: HashMap<usize, Block> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r]
                .as_ref()
                .ok_or(ThreePartyEvaluatorError::CacheItemError(*r))?;
            let dec = self.output(x)?.unwrap();
            garbled_output.insert(*r, dec);
        }
        Ok(garbled_output)
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::BinaryEvaluator;
    use crate::{
        circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder},
        config::constants::AES_KEY,
        old::garbling3pc::comparison_circ_3pc::build_comparison_circuit_threeparty,
        old::garbling2pc::garbler_operations::BinaryGarbler,
        old::garbling3pc::threepartytraits::{
            ThreePartyBinaryCircuit, ThreePartyBinaryCircuitBuilder, ThreePartyBinaryEvaluator,
            ThreePartyBinaryGarbler,
        },
        utilities::{hash_function::AesHash, utils::bool_vec_to_hex},
    };

    #[test]
    fn test_xor_gate_garbled_3pc() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();
        let garb_input_1 = builder.garbler_input();

        let result = builder.xor(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
        let mut rng = rand::rng();

        for i in 0..2 {
            for j in 0..2 {
                let jinp = rng.random_bool(0.5);
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.decoding_infos.clone(),
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    &circuit.garbler_input_ids,
                    [i != 0].as_slice(),
                    &garble_output.garbler_input_encodings,
                );
                let evaluator_inputs = garbler.get_garbled_inputs_threeparty(
                    &circuit.evaluator_input_ids,
                    &[[jinp].as_slice(), [(j != 0) ^ jinp].as_slice()],
                    &garble_output.evaluator_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate_threeparty(&circuit, &garbler_inputs, &evaluator_inputs)
                    .unwrap();
                let auth = garbler
                    .authenticate_garbled_output(&output, &garble_output.garbled_output_wires);
                assert!(auth);
                let decoutput = evaluator
                    .get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                let z = i ^ j;
                assert!(
                    (z == 1) == decoutput[0],
                    "z: {} output: {:?}",
                    z,
                    decoutput[0]
                )
            }
        }
    }

    #[test]
    fn test_and_gate_garbled_3pc() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();
        let garb_input_1 = builder.garbler_input();

        let result = builder.and(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
        let mut rng = rand::rng();

        for i in 0..2 {
            for j in 0..2 {
                let jinp = rng.random_bool(0.5);
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.decoding_infos.clone(),
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    &circuit.garbler_input_ids,
                    [i != 0].as_slice(),
                    &garble_output.garbler_input_encodings,
                );
                let evaluator_inputs = garbler.get_garbled_inputs_threeparty(
                    &circuit.evaluator_input_ids,
                    &[[jinp].as_slice(), [(j != 0) ^ jinp].as_slice()],
                    &garble_output.evaluator_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate_threeparty(&circuit, &garbler_inputs, &evaluator_inputs)
                    .unwrap();
                let auth = garbler
                    .authenticate_garbled_output(&output, &garble_output.garbled_output_wires);
                assert!(auth);
                let decoutput = evaluator
                    .get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                let z = i & j;
                assert!(
                    (z == 1) == decoutput[0],
                    "z: {} output: {:?} {} {}",
                    z,
                    decoutput[0],
                    i,
                    j
                )
            }
        }
    }

    #[test]
    fn test_not_gate_garbled_3pc() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();

        let result = builder.negate(eval_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
        let mut rng = rand::rng();

        for j in 0..2 {
            let jinp = rng.random_bool(0.5);
            let mut evaluator = BinaryEvaluator::new(
                garble_output.decoding_infos.clone(),
                AesHash::new(AES_KEY),
                garble_output.garbled_circuit.clone(),
            );
            let garbler_inputs = garbler.get_garbled_inputs(
                &circuit.garbler_input_ids,
                [].as_slice(),
                &garble_output.garbler_input_encodings,
            );
            let evaluator_inputs = garbler.get_garbled_inputs_threeparty(
                &circuit.evaluator_input_ids,
                &[[jinp].as_slice(), [(j != 0) ^ jinp].as_slice()],
                &garble_output.evaluator_input_encodings.clone(),
            );
            let output = evaluator
                .evaluate_threeparty(&circuit, &garbler_inputs, &evaluator_inputs)
                .unwrap();
            let auth =
                garbler.authenticate_garbled_output(&output, &garble_output.garbled_output_wires);
            assert!(auth);
            let decoutput = evaluator
                .get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());

            let z = 1 - j;
            assert!(
                (z == 1) == decoutput[0],
                "z: {} output: {:?}",
                z,
                decoutput[0]
            )
        }
    }

    #[test]
    fn test_comparison_circuit_garbled_3pc() {
        let comparison_circuit = build_comparison_circuit_threeparty();
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler
            .garble_threeparty(comparison_circuit.clone())
            .unwrap();
        let mut rng = rand::rng();
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i % 2 != 0;
                let jbit1 = j % 2 != 0;
                let ibit2 = (i / 2) % 2 != 0;
                let jbit2 = (j / 2) % 2 != 0;
                let jinp1 = rng.random_bool(0.5);
                let jinp2 = rng.random_bool(0.5);

                let mut evaluator = BinaryEvaluator::new(
                    garble_output.decoding_infos.clone(),
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    &comparison_circuit.garbler_input_ids,
                    [ibit1, ibit2].as_slice(),
                    &garble_output.garbler_input_encodings,
                );
                let evaluator_inputs = garbler.get_garbled_inputs_threeparty(
                    &comparison_circuit.evaluator_input_ids,
                    &[
                        [jinp1, jinp2].as_slice(),
                        [jbit1 ^ jinp1, jbit2 ^ jinp2].as_slice(),
                    ],
                    &garble_output.evaluator_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate_threeparty(&comparison_circuit, &garbler_inputs, &evaluator_inputs)
                    .unwrap();
                let auth = garbler
                    .authenticate_garbled_output(&output, &garble_output.garbled_output_wires);
                assert!(auth);
                let decoutput = evaluator.get_plaintext_output(
                    comparison_circuit.get_output_gate_ids().to_vec(),
                    output.clone(),
                );

                assert!(
                    (i == j) == decoutput[0],
                    "i: {}, j: {} output: {:?}",
                    i,
                    j,
                    decoutput[0]
                )
            }
        }
    }

    #[test]
    fn test_aes_garbled_3pc() {
        let circuit = BinaryCircuit::parse_threeparty("circuits/aes128.txt").unwrap();
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let mut rng = rand::rng();
        let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
        for i in 0..2 {
            for j in 0..2 {
                let val = j != 0;
                let mut j1 = [false; 128];
                let mut j2 = [false; 128];
                for k in 0..128 {
                    let bit = rng.random_bool(0.5);
                    j1[k] = bit;
                    j2[k] = val ^ bit;
                }
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.decoding_infos.clone(),
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    &circuit.garbler_input_ids,
                    [i != 0; 128].as_slice(),
                    &garble_output.garbler_input_encodings,
                );
                let evaluator_inputs = garbler.get_garbled_inputs_threeparty(
                    &circuit.evaluator_input_ids,
                    &[&j1, &j2],
                    &garble_output.evaluator_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate_threeparty(&circuit, &garbler_inputs, &evaluator_inputs)
                    .unwrap();
                let auth = garbler
                    .authenticate_garbled_output(&output, &garble_output.garbled_output_wires);
                assert!(auth);
                let decoutput = evaluator
                    .get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                let count = 2 * i + j;
                let hexout = bool_vec_to_hex(decoutput);
                if count == 0 {
                    assert_eq!(
                        hexout,
                        "74d42c539a5f3211dc3451f72bd29766".to_string(),
                        "outval: {} realval: 74d42c539a5f3211dc3451f72bd29766",
                        hexout
                    );
                } else if count == 2 {
                    assert_eq!(
                        hexout,
                        "3493fd1ca2122691b3fabee131a46f85".to_string(),
                        "outval: {} realval: 3493fd1ca2122691b3fabee131a46f85",
                        hexout
                    );
                } else if count == 1 {
                    assert_eq!(
                        hexout,
                        "7266b17c4be2ce5f505aa1579331dafc".to_string(),
                        "outval: {} realval: 7266b17c4be2ce5f505aa1579331dafc",
                        hexout
                    );
                } else if count == 3 {
                    assert_eq!(
                        hexout,
                        "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string(),
                        "outval: {} realval: 9e9d5c984a0e8a4d0cf3014d3e84fd3d",
                        hexout
                    );
                }
            }
        }
    }
}
