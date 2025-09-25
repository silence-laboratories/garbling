use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    old::garbling2pc::{
        exec::{BinaryOperations, ExecutionPrimitives},
        plaintext_operations::BinaryPlaintext,
    },
    old::garbling3pc::garbling3pc_errors::BinaryPlaintextError,
};

use super::threepartytraits::ThreePartyBinaryPlaintext;

/// Implements the `ThreePartyBinaryPlaintext` trait for `BinaryPlaintext`.
impl ThreePartyBinaryPlaintext for BinaryPlaintext {
    /// Evaluates a `BinaryCircuit` using plaintext values.
    ///
    /// This function takes a `BinaryCircuit` along with garbler and evaluator
    /// inputs (two inputs, whose xor gives the actual input), processes the
    /// gates sequentially, and returns the output values.
    ///
    /// # Arguments
    ///
    /// * `circ` - The `BinaryCircuit` to evaluate.
    /// * `garbler_inputs` - A slice of boolean values representing the garbler's input.
    /// * `evaluator_inputs` - A slice of pairs of boolean values
    ///   representing the evaluator's input.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    /// - `Ok(Vec<bool>)` - The evaluated output of the circuit as a vector of boolean values.
    /// - `Err(BinaryPlaintextError)` - An error if the evaluation fails.
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: [&[bool]; 2],
    ) -> Result<Vec<bool>, BinaryPlaintextError> {
        let mut cache: Vec<Option<bool>> = vec![None; circ.gates.len()];
        for gate in &circ.gates {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id, wire } => {
                    if id >= garbler_inputs.len() {
                        return Err(BinaryPlaintextError::GarblerIpLenError(
                            id,
                            garbler_inputs.len(),
                        ));
                    }
                    (wire, self.process_garbler_input(id, garbler_inputs[id])?)
                }
                BinaryGate::EvaluatorInput { id, wire } => {
                    if id / 2 >= evaluator_inputs[0].len() {
                        return Err(BinaryPlaintextError::GarblerIpLenError(
                            id,
                            evaluator_inputs[0].len(),
                        ));
                    }

                    if id / 2 >= evaluator_inputs[1].len() {
                        return Err(BinaryPlaintextError::GarblerIpLenError(
                            id,
                            evaluator_inputs[1].len(),
                        ));
                    }
                    if id % 2 == 0 {
                        (
                            wire,
                            self.process_evaluator_input(id, evaluator_inputs[0][id / 2])?,
                        )
                    } else {
                        (
                            wire,
                            self.process_evaluator_input(id, evaluator_inputs[1][id / 2])?,
                        )
                    }
                }
                BinaryGate::Constant { val, wire } => (wire, self.constant(val)?),
                BinaryGate::Inv { xid, out } => (
                    out,
                    self.negate(
                        cache[xid]
                            .as_ref()
                            .ok_or(BinaryPlaintextError::CacheItemError(xid))?,
                    )?,
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid]
                            .as_ref()
                            .ok_or(BinaryPlaintextError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(BinaryPlaintextError::CacheItemError(yid))?,
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
                            .ok_or(BinaryPlaintextError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(BinaryPlaintextError::CacheItemError(yid))?,
                    )?,
                ),
            };
            cache[z_ref] = Some(value)
        }
        let mut outputs = Vec::with_capacity(circ.output_gate_ids.len());
        for r in circ.get_output_gate_ids().iter() {
            let r = cache[*r]
                .as_ref()
                .ok_or(BinaryPlaintextError::CacheItemError(*r))?;
            let out = self.output(r)?;
            outputs.push(out.unwrap())
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::BinaryPlaintext;
    use crate::{
        circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder},
        old::garbling3pc::comparison_circ_3pc::build_comparison_circuit_threeparty,
        old::garbling3pc::threepartytraits::{
            ThreePartyBinaryCircuit, ThreePartyBinaryCircuitBuilder, ThreePartyBinaryPlaintext,
        },
        utilities::utils::bool_vec_to_hex,
    };

    #[test]
    fn test_xor_gate_plain_3pc() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();
        let garb_input_1 = builder.garbler_input();

        let result = builder.xor(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();
        let mut rng = rand::rng();

        for i in 0..2 {
            for j in 0..2 {
                let jinp = rng.gen_bool(0.5);
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate_threeparty(
                        circuit.clone(),
                        [i != 0].as_slice(),
                        [[jinp].as_slice(), [(j != 0) ^ jinp].as_slice()],
                    )
                    .unwrap();
                let z = i ^ j;
                assert!((z == 1) == output[0], "z: {} output: {:?}", z, output[0])
            }
        }
    }

    #[test]
    fn test_and_gate_plain_3pc() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();
        let garb_input_1 = builder.garbler_input();

        let result = builder.and(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();
        let mut rng = rand::rng();

        for i in 0..2 {
            for j in 0..2 {
                let jinp = rng.gen_bool(0.5);
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate_threeparty(
                        circuit.clone(),
                        [i != 0].as_slice(),
                        [[jinp].as_slice(), [(j != 0) ^ jinp].as_slice()],
                    )
                    .unwrap();
                let z = i & j;
                assert!(
                    (z == 1) == output[0],
                    "z: {} output: {:?} {} {}",
                    z,
                    output[0],
                    i,
                    j
                )
            }
        }
    }

    #[test]
    fn test_not_gate_plain_3pc() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();

        let result = builder.negate(eval_input_1);
        builder.output(result);
        let circuit = builder.finish();
        let mut rng = rand::rng();

        for j in 0..2 {
            let jinp = rng.gen_bool(0.5);
            let mut plaintexteval = BinaryPlaintext::new();
            let output = plaintexteval
                .evaluate_threeparty(
                    circuit.clone(),
                    [].as_slice(),
                    [[jinp].as_slice(), [(j != 0) ^ jinp].as_slice()],
                )
                .unwrap();
            let z = 1 - j;
            assert!((z == 1) == output[0], "z: {} output: {:?}", z, output[0])
        }
    }

    #[test]
    fn test_comparison_circuit_plain_3pc() {
        let comparison_circuit = build_comparison_circuit_threeparty();
        let mut rng = rand::rng();
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i % 2 != 0;
                let jbit1 = j % 2 != 0;
                let ibit2 = (i / 2) % 2 != 0;
                let jbit2 = (j / 2) % 2 != 0;
                let jinp1 = rng.gen_bool(0.5);
                let jinp2 = rng.gen_bool(0.5);

                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate_threeparty(
                        comparison_circuit.clone(),
                        [ibit1, ibit2].as_slice(),
                        [
                            [jinp1, jinp2].as_slice(),
                            [jbit1 ^ jinp1, jbit2 ^ jinp2].as_slice(),
                        ],
                    )
                    .unwrap();
                assert!(
                    (i == j) == output[0],
                    "i: {}, j: {} output: {:?}",
                    i,
                    j,
                    output[0]
                )
            }
        }
    }

    #[test]
    fn test_aes_plain_3pc() {
        let circuit = BinaryCircuit::parse_threeparty("circuits/aes128.txt").unwrap();
        let mut rng = rand::rng();
        for i in 0..2 {
            for j in 0..2 {
                let val = j != 0;
                let mut plaintexteval = BinaryPlaintext::new();
                let mut j1 = [false; 128];
                let mut j2 = [false; 128];
                for k in 0..128 {
                    let bit = rng.gen_bool(0.5);
                    j1[k] = bit;
                    j2[k] = val ^ bit;
                }
                let output = plaintexteval
                    .evaluate_threeparty(circuit.clone(), [i != 0; 128].as_slice(), [&j1, &j2])
                    .unwrap();
                let count = 2 * i + j;
                let hexout = bool_vec_to_hex(output);
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
