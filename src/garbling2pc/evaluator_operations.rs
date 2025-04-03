use std::collections::HashMap;

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::{
        constants::Block,
        garbling2pc_errors::{BinaryOperationsError, EvaluatorError, ExecutionPrimitiveError},
    },
    garbling2pc::exec::{BinaryOperations, ExecutionPrimitives},
    utilities::{hash_function::HashFunction, utils::xor_blocks},
};

/// Represents the evaluator's state in a binary garbled circuit protocol.
///
/// This struct implements the evaluator's side of the protocol described in
/// Figure 2 of <https://eprint.iacr.org/2014/756.pdf>.
///
/// # Type Parameters
/// * `H` - A cryptographic hash function that implements the `HashFunction` trait.
#[derive(Clone)]
pub struct BinaryEvaluator<H: HashFunction> {
    /// The evaluator's inputs' encoding received from the garbler
    evaluator_encoding: HashMap<usize, Block>,

    /// The decoding information received from the garbler
    decoding_infos: HashMap<usize, u8>,

    /// The global difference value (Delta) used for garbling
    /// using Free XOR technique received from the garbler
    pub delta: Block,

    /// The cryptographic hash function used for hashing gate labels.
    pub hash: H,

    /// A garbled circuit received from the garbler.
    pub cache: Vec<Block>,

    /// A counter for uniquely indexing gates in the garbled circuit.
    pub gateindex: u128,

    /// A counter for retreiving values from the cache.
    pub currentcacheindex: usize,
}

/// Implementation of the `BinaryEvaluator` struct.
/// This provides methods for evaluating garbled binary circuits and decoding garbled outputs.
impl<H: HashFunction> BinaryEvaluator<H> {
    /// Creates a new `BinaryEvaluator` instance.
    ///
    /// # Arguments
    ///
    /// * `evaluator_encoding` - A `HashMap` mapping evaluator input wire IDs to their encoded garbled values.
    /// * `decoding_infos` - A `HashMap` containing metadata for decoding the final output values.
    /// * `delta` - A `Block` representing the global offset used in garbled circuit evaluation for free-XOR.
    /// * `hash` - A cryptographic hash function instance used for evaluating half-gates.
    /// * `gc` - A `Vec<Block>` containing the garbled circuit representation.
    ///
    /// # Returns
    ///
    /// A new instance of `BinaryGarbler` with initialized values.
    pub fn new(
        evaluator_encoding: HashMap<usize, Block>,
        decoding_infos: HashMap<usize, u8>,
        delta: Block,
        hash: H,
        gc: Vec<Block>,
    ) -> BinaryEvaluator<H> {
        BinaryEvaluator {
            evaluator_encoding,
            decoding_infos,
            delta,
            hash,
            cache: gc,
            gateindex: 0,
            currentcacheindex: 0,
        }
    }

    /// Extracts the least significant bit (LSB) of a given `Block`.
    ///
    /// This function retrieves the LSB from the first byte of the block.
    ///
    /// # Arguments
    ///
    /// * `value` - A 16-byte block representing a wire label.
    ///
    /// # Returns
    ///
    /// The least significant bit (0 or 1) of the first byte.
    pub fn lsb(value: Block) -> u8 {
        value[0] & 1
    }

    /// Increments and retrieves the next available gate index.
    ///
    /// # Returns
    ///
    /// The updated gate index.
    fn get_next_gate_index(&mut self) -> u128 {
        self.gateindex += 1;
        self.gateindex
    }

    /// Increments the `currentcacheindex` and retrieves the next `cache` entry.
    ///
    /// # Returns
    ///
    /// The next `cache` entry.
    fn get_next_cache_value(&mut self) -> Block {
        let op = self.cache[self.currentcacheindex];
        self.currentcacheindex += 1;
        op
    }

    /// Retrieves the plaintext output of the garbled circuit evaluation.
    ///
    /// This function takes the output gate IDs and the corresponding garbled output values
    /// and returns the final decrypted plaintext results.
    ///
    /// # Arguments
    ///
    /// * `output_gates` - A `Vec<usize>` containing the IDs of the circuit's output gates.
    /// * `garbled_output` - A `HashMap<usize, Block>` mapping
    ///   output gate IDs to their respective garbled values.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Vec<bool>, ExecutionPrimitiveError>` where:
    /// - `Ok(Vec<bool>)` contains the final plaintext output values in the order of `output_gates`.
    /// - `Err(ExecutionPrimitiveError)` is returned if an error occurs during decoding.
    pub fn get_plaintext_output(
        &self,
        output_gates: Vec<usize>,
        garbled_output: HashMap<usize, <Self as ExecutionPrimitives>::Item>,
    ) -> Vec<bool> {
        let mut output = Vec::new();
        for x in output_gates {
            let glsb = Self::lsb(*garbled_output.get(&x).unwrap());
            let declsb = self.decoding_infos.get(&x).unwrap().to_owned();
            output.push(glsb ^ declsb != 0)
        }
        output
    }

    /// Evaluates a garbled binary circuit using the half-gate technique.
    ///
    /// This function takes a garbled `BinaryCircuit`, garbler's encoded inputs and
    /// the evaluator's inputs in boolean form to return the encoded outputs.
    ///
    /// # Parameters
    ///
    /// * `circ` - The `BinaryCircuit` to be evaluated.
    /// * `garbler_inputs`: A `HashMap<usize, Block>` which maps the garbler's input
    ///   ids to its correspoding encoded garbler's inputs.
    /// * `evaluator_inputs` - A slice of `bool` containing the evaluator's input values in
    ///   the order of the evaluator's input ids.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    /// * A `HashMap<usize, Block>` which maps the output gate ids to encoded output blocks.
    /// * `Err(EvaluatorError)` - An error if the evaluation fails.
    pub fn evaluate(
        &mut self,
        circ: &BinaryCircuit,
        garbler_inputs: &HashMap<usize, Block>,
        evaluator_inputs: &[bool],
    ) -> Result<HashMap<usize, Block>, EvaluatorError> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    if id >= garbler_inputs.len() {
                        return Err(EvaluatorError::GarblerIpLenError(id, garbler_inputs.len()));
                    }
                    let input_hash = garbler_inputs.get(&id).unwrap().to_owned();
                    (None, input_hash)
                }
                BinaryGate::EvaluatorInput { id } => {
                    if id >= evaluator_inputs.len() {
                        return Err(EvaluatorError::EvaluatorIpLenError(
                            id,
                            evaluator_inputs.len(),
                        ));
                    }
                    let input_hash = self.process_evaluator_input(id, evaluator_inputs[id])?;
                    (None, input_hash)
                }
                BinaryGate::Constant { val } => (None, self.constant(val)?),
                BinaryGate::Inv { xid, out } => (
                    out,
                    self.negate(
                        cache[xid]
                            .as_ref()
                            .ok_or(EvaluatorError::CacheItemError(xid))?,
                    )?,
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid]
                            .as_ref()
                            .ok_or(EvaluatorError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(EvaluatorError::CacheItemError(yid))?,
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
                            .ok_or(EvaluatorError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(EvaluatorError::CacheItemError(yid))?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut garbled_output: HashMap<usize, Block> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r]
                .as_ref()
                .ok_or(EvaluatorError::CacheItemError(*r))?;
            let dec = self.output(x)?.unwrap();
            garbled_output.insert(*r, dec);
        }
        Ok(garbled_output)
    }
}

/// Implements the `ExecutionPrimitives` trait for `BinaryEvaluator`.
impl<H: HashFunction> ExecutionPrimitives for BinaryEvaluator<H> {
    /// The type of values used in the garbled circuit. In this case, `Block`
    /// is used to represent the types used and stored in the garbled circuit.
    type Item = Block;

    /// Processes a constant gate for a Binary Evaluator.
    ///
    /// # Arguments
    ///
    /// * `x` - A `u16` value representing `1` for `True` and `0` for `False`.
    ///   (unused for evaluator)
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn constant(&mut self, _x: u16) -> Result<Self::Item, ExecutionPrimitiveError> {
        Ok(self.get_next_cache_value())
    }

    /// Processes a output gate for a Binary Evaluator.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the gate to be processed.
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value wrapped in `Some()` upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, ExecutionPrimitiveError> {
        Ok(Some(*x))
    }

    /// Processes an input value from the evaluator.
    ///
    /// # Arguments
    ///
    /// * `id` - The identifier for the evaluator input.
    /// * `x` - The value provided as input.
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn process_evaluator_input(
        &mut self,
        id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError> {
        let mut val = self.evaluator_encoding.get(&id).unwrap().to_owned();
        if x {
            val = xor_blocks(val, self.delta);
        }
        Ok(val)
    }

    /// Processes an input value from the garbler.
    ///
    /// # Arguments
    ///
    /// * `_id` - The identifier for the garbler input (unused for evaluator).
    /// * `_x` - The value provided as input (unused for evaluator).
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn process_garbler_input(
        &mut self,
        _id: usize,
        _x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError> {
        Ok(Block::default())
    }
}

/// Implements the `BinaryOperations` trait for `BinaryEvaluator`.
impl<H: HashFunction> BinaryOperations for BinaryEvaluator<H> {
    /// Processes the XOR gate for the evaluator.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the first operand.
    /// * `y` - A reference to the `Block` value of the second operand.
    ///
    /// # Returns
    ///
    /// * The output `Block` value upon successful execution.
    /// * `Err(BinaryOperationsError)` if an error occurs.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        let output = xor_blocks(*x, *y);
        Ok(output)
    }

    /// Processes the AND gate for the evaluator.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the first operand.
    /// * `y` - A reference to the `Block` value of the second operand.
    ///
    /// # Returns
    ///
    /// * The output `Block` value upon successful execution.
    /// * `Err(BinaryOperationsError)` if an error occurs.
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        let s_a = Self::lsb(*x);
        let s_b = Self::lsb(*y);

        let j = self.get_next_gate_index().to_le_bytes();
        let j2 = self.get_next_gate_index().to_le_bytes();

        let t_gen = self.get_next_cache_value();
        let t_eval = self.get_next_cache_value();

        let mut out_gen = self.hash.tccr_hash(*x, j);
        if s_a == 1 {
            out_gen = xor_blocks(out_gen, t_gen);
        }

        let mut out_eval = self.hash.tccr_hash(*y, j2);
        if s_b == 1 {
            out_eval = xor_blocks(out_eval, t_eval);
            out_eval = xor_blocks(out_eval, *x);
        }

        let out = xor_blocks(out_gen, out_eval);

        Ok(out)
    }

    /// Processes the NOT (negation) gate for the evaluator.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the operand.
    ///
    /// # Returns
    ///
    /// * The output `Block` value upon successful execution.
    /// * `Err(BinaryOperationsError)` if an error occurs.
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        Ok(*x)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::BinaryEvaluator;
    use crate::{
        circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder},
        config::constants::AES_KEY,
        customcircuits::comparison::build_comparison_circuit,
        garbling2pc::garbler_operations::BinaryGarbler,
        utilities::{hash_function::AesHash, utils::bool_vec_to_hex},
    };

    #[test]
    fn test_xor_gate_garbled() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();

        let result = builder.xor(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble(&circuit).unwrap();

        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    circuit.clone(),
                    [i != 0].as_slice(),
                    garble_output.garbler_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate(&circuit, &garbler_inputs, [j != 0].as_slice())
                    .unwrap();
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
    fn test_and_gate_garbled() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();

        let result = builder.and(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble(&circuit).unwrap();

        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    circuit.clone(),
                    [i != 0].as_slice(),
                    garble_output.garbler_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate(&circuit, &garbler_inputs, [j != 0].as_slice())
                    .unwrap();
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
    fn test_not_gate_garbled() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();

        let result = builder.negate(eval_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble(&circuit).unwrap();

        for j in 0..2 {
            let mut evaluator = BinaryEvaluator::new(
                garble_output.evaluator_input_encodings.clone(),
                garble_output.decoding_infos.clone(),
                garbler.delta,
                AesHash::new(AES_KEY),
                garble_output.garbled_circuit.clone(),
            );
            let garbler_inputs = garbler.get_garbled_inputs(
                circuit.clone(),
                [].as_slice(),
                garble_output.garbler_input_encodings.clone(),
            );
            let output = evaluator
                .evaluate(&circuit, &garbler_inputs, [j != 0].as_slice())
                .unwrap();
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
    fn test_constant_gate_garbled() {
        for i in 0..2 {
            for j in 0..2 {
                let mut builder = CircuitBuilder::new();
                let result1 = builder.constant(i);
                let result2 = builder.constant(j);
                let result = builder.xor(result1, result2);
                builder.output(result);
                let circuit = builder.finish();
                let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
                let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
                let garble_output = garbler.garble(&circuit).unwrap();
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    circuit.clone(),
                    [].as_slice(),
                    garble_output.garbler_input_encodings,
                );
                let output = evaluator
                    .evaluate(&circuit, &garbler_inputs, [j != 0].as_slice())
                    .unwrap();
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
    fn test_comparison_circuit_garbled() {
        let comparison_circuit = build_comparison_circuit();
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble(&comparison_circuit.clone()).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i % 2 != 0;
                let jbit1 = j % 2 != 0;
                let ibit2 = (i / 2) % 2 != 0;
                let jbit2 = (j / 2) % 2 != 0;

                let mut evaluator = BinaryEvaluator::new(
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    comparison_circuit.clone(),
                    [ibit1, ibit2].as_slice(),
                    garble_output.garbler_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate(
                        &comparison_circuit,
                        &garbler_inputs,
                        [jbit1, jbit2].as_slice(),
                    )
                    .unwrap();
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
    fn test_aes_garbled() {
        let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
        let garble_output = garbler.garble(&circuit).unwrap();
        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let garbler_inputs = garbler.get_garbled_inputs(
                    circuit.clone(),
                    [i != 0; 128].as_slice(),
                    garble_output.garbler_input_encodings.clone(),
                );
                let output = evaluator
                    .evaluate(&circuit, &garbler_inputs, [j != 0; 128].as_slice())
                    .unwrap();
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
