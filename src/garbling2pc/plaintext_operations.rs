use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::errors::{BinaryOperationsError, BinaryPlaintextError, ExecutionPrimitiveError},
    garbling2pc::exec::{BinaryOperations, ExecutionPrimitives},
};

pub struct BinaryPlaintext;

impl BinaryPlaintext {
    pub fn new() -> Self {
        BinaryPlaintext {}
    }

    pub fn evaluate(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: &[bool],
    ) -> Result<Vec<bool>, BinaryPlaintextError> {
        let mut cache: Vec<Option<bool>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    if id >= garbler_inputs.len() {
                        return Err(BinaryPlaintextError::GarblerIpLenError(
                            id,
                            garbler_inputs.len(),
                        ));
                    }
                    (None, self.process_garbler_input(id, garbler_inputs[id])?)
                }
                BinaryGate::EvaluatorInput { id } => {
                    if id >= evaluator_inputs.len() {
                        return Err(BinaryPlaintextError::EvaluatorIpLenError(
                            id,
                            evaluator_inputs.len(),
                        ));
                    }
                    (
                        None,
                        self.process_evaluator_input(id, evaluator_inputs[id])?,
                    )
                }
                BinaryGate::Constant { val } => (None, self.constant(val)?),
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
            cache[z_ref.unwrap_or(i)] = Some(value)
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

impl Default for BinaryPlaintext {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionPrimitives for BinaryPlaintext {
    type Item = bool;

    fn constant(&mut self, x: u16) -> Result<Self::Item, ExecutionPrimitiveError> {
        Ok(x != 0)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<bool>, ExecutionPrimitiveError> {
        Ok(Some(*x))
    }

    fn process_garbler_input(
        &mut self,
        _id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError> {
        Ok(x)
    }

    fn process_evaluator_input(
        &mut self,
        _id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError> {
        Ok(x)
    }
}

impl BinaryOperations for BinaryPlaintext {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        Ok(x ^ y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        Ok(x & y)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        Ok(!x)
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryPlaintext;
    use crate::{
        circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder},
        customcircuits::comparison::build_comparison_circuit,
        utilities::utils::bool_vec_to_hex,
    };

    #[test]
    fn test_xor_gate_plain() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();

        let result = builder.xor(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        for i in 0..2 {
            for j in 0..2 {
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate(circuit.clone(), [i != 0].as_slice(), [j != 0].as_slice())
                    .unwrap();
                let z = i ^ j;
                assert!((z == 1) == output[0], "z: {} output: {:?}", z, output[0])
            }
        }
    }

    #[test]
    fn test_and_gate_plain() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();

        let result = builder.and(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        for i in 0..2 {
            for j in 0..2 {
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate(circuit.clone(), [i != 0].as_slice(), [j != 0].as_slice())
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
    fn test_not_gate_plain() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();

        let result = builder.negate(eval_input_1);
        builder.output(result);
        let circuit = builder.finish();

        for j in 0..2 {
            let mut plaintexteval = BinaryPlaintext::new();
            let output = plaintexteval
                .evaluate(circuit.clone(), [].as_slice(), [j != 0].as_slice())
                .unwrap();
            let z = 1 - j;
            assert!((z == 1) == output[0], "z: {} output: {:?}", z, output[0])
        }
    }

    #[test]
    fn test_constant_gate_plain() {
        for i in 0..2 {
            for j in 0..2 {
                let mut builder = CircuitBuilder::new();
                let result1 = builder.constant(i);
                let result2 = builder.constant(j);
                let result = builder.xor(result1, result2);
                builder.output(result);
                let circuit = builder.finish();
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate(circuit.clone(), [].as_slice(), [].as_slice())
                    .unwrap();
                let z = i ^ j;
                assert!((z == 1) == output[0], "z: {} output: {:?}", z, output[0])
            }
        }
    }

    #[test]
    fn test_comparison_circuit_plain() {
        let comparison_circuit = build_comparison_circuit();
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i % 2 != 0;
                let jbit1 = j % 2 != 0;
                let ibit2 = (i / 2) % 2 != 0;
                let jbit2 = (j / 2) % 2 != 0;

                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate(
                        comparison_circuit.clone(),
                        [ibit1, ibit2].as_slice(),
                        [jbit1, jbit2].as_slice(),
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
    fn test_aes_plain() {
        let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();
        for i in 0..2 {
            for j in 0..2 {
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval
                    .evaluate(
                        circuit.clone(),
                        [i != 0; 128].as_slice(),
                        [j != 0; 128].as_slice(),
                    )
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
