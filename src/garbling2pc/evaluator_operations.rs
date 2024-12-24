use std::{collections::HashMap, fmt::Error};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::constants::Block,
    garbling2pc::exec::{BinaryOperations, ExecutionPrimitives},
    utilities::hash_function::HashFunction,
    utilities::utils::xor_blocks,
};

#[derive(Clone)]
pub struct BinaryEvaluator<H: HashFunction> {
    garbler_encoding: HashMap<usize, Block>,
    evaluator_encoding: HashMap<usize, Block>,
    decoding_infos: HashMap<usize, u8>,
    pub delta: Block,
    pub rng: H,
    pub cache: Vec<Block>,
    pub gateindex: u128,
    pub currentcacheindex: usize,
}

impl<H: HashFunction> BinaryEvaluator<H> {
    pub fn new(
        garbler_encoding: HashMap<usize, Block>,
        evaluator_encoding: HashMap<usize, Block>,
        decoding_infos: HashMap<usize, u8>,
        delta: Block,
        hash: H,
        gc: Vec<Block>,
    ) -> BinaryEvaluator<H> {
        BinaryEvaluator {
            garbler_encoding,
            evaluator_encoding,
            decoding_infos,
            delta,
            rng: hash,
            cache: gc,
            gateindex: 0,
            currentcacheindex: 0,
        }
    }

    fn lsb(value: Block) -> u8 {
        value[0] & 1
    }

    fn get_next_gate_index(&mut self) -> u128 {
        self.gateindex += 1;
        self.gateindex
    }

    fn get_next_cache_value(&mut self) -> Block {
        let op = self.cache[self.currentcacheindex];
        self.currentcacheindex += 1;
        op
    }

    pub fn get_plaintext_output(
        &self,
        output_gates: Vec<usize>,
        garbled_output: HashMap<usize, <BinaryEvaluator<H> as ExecutionPrimitives>::Item>,
    ) -> Vec<bool> {
        let mut output = Vec::new();
        for x in output_gates {
            let glsb = Self::lsb(*garbled_output.get(&x).unwrap());
            let declsb = self.decoding_infos.get(&x).unwrap().to_owned();
            output.push(glsb ^ declsb != 0)
        }
        output
    }

    pub fn evaluate(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: &[bool],
    ) -> Result<HashMap<usize, Block>, Error> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(
                        id < garbler_inputs.len(),
                        "id={} gb_inps.len()={}",
                        id,
                        garbler_inputs.len()
                    );
                    let input_hash = self.process_garbler_input(id, garbler_inputs[id])?;
                    (None, input_hash)
                }
                BinaryGate::EvaluatorInput { id } => {
                    assert!(
                        id < evaluator_inputs.len(),
                        "id={} ev_inps.len()={}",
                        id,
                        evaluator_inputs.len()
                    );
                    let input_hash = self.process_evaluator_input(id, evaluator_inputs[id])?;
                    (None, input_hash)
                }
                BinaryGate::Constant { val } => (None, self.constant(val)?),
                BinaryGate::Inv { xid, out } => {
                    (out, self.negate(cache[xid].as_ref().ok_or(Error)?)?)
                }
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid].as_ref().ok_or(Error)?,
                        cache[yid].as_ref().ok_or(Error)?,
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
                        cache[xid].as_ref().ok_or(Error)?,
                        cache[yid].as_ref().ok_or(Error)?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut garbled_output: HashMap<usize, Block> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or(Error)?;
            let dec = self.output(x)?.unwrap();
            garbled_output.insert(*r, dec);
        }
        Ok(garbled_output)
    }
}

impl<H: HashFunction> ExecutionPrimitives for BinaryEvaluator<H> {
    type Item = Block;

    fn constant(&mut self, _x: u16) -> Result<Self::Item, Error> {
        Ok(self.get_next_cache_value())
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, std::fmt::Error> {
        Ok(Some(*x))
    }

    fn process_evaluator_input(&mut self, id: usize, x: bool) -> Result<Self::Item, Error> {
        let mut val = self.evaluator_encoding.get(&id).unwrap().to_owned();
        if x {
            val = xor_blocks(val, self.delta);
        }
        Ok(val)
    }

    fn process_garbler_input(&mut self, id: usize, x: bool) -> Result<Self::Item, Error> {
        let mut val = self.garbler_encoding.get(&id).unwrap().to_owned();
        if x {
            val = xor_blocks(val, self.delta);
        }
        Ok(val)
    }
}

impl<H: HashFunction> BinaryOperations for BinaryEvaluator<H> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        let output = xor_blocks(*x, *y);
        Ok(output)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        let s_a = Self::lsb(*x);
        let s_b = Self::lsb(*y);

        let j = self.get_next_gate_index().to_le_bytes();
        let j2 = self.get_next_gate_index().to_le_bytes();

        let t_gen = self.get_next_cache_value();
        let t_eval = self.get_next_cache_value();

        let mut out_gen = self.rng.tccr_hash(*x, j);
        if s_a == 1 {
            out_gen = xor_blocks(out_gen, t_gen);
        }

        let mut out_eval = self.rng.tccr_hash(*y, j2);
        if s_b == 1 {
            out_eval = xor_blocks(out_eval, t_eval);
            out_eval = xor_blocks(out_eval, *x);
        }

        let out = xor_blocks(out_gen, out_eval);

        Ok(out)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Error> {
        Ok(*x)
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryEvaluator;
    use crate::{
        circuitop::circuit::BinaryCircuit, circuitop::circuit_builder::CircuitBuilder,
        config::constants::AES_KEY, garbling2pc::garbler_operations::BinaryGarbler,
        utilities::hash_function::AesHash,
    };

    #[test]
    fn test_xor_gate_garbled() {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();

        let result = builder.xor(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
        let garble_output = garbler.garble(circuit.clone()).unwrap();

        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.garbler_input_encodings.clone(),
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let output = evaluator
                    .evaluate(circuit.clone(), [i != 0].as_slice(), [j != 0].as_slice())
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

        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
        let garble_output = garbler.garble(circuit.clone()).unwrap();

        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.garbler_input_encodings.clone(),
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let output = evaluator
                    .evaluate(circuit.clone(), [i != 0].as_slice(), [j != 0].as_slice())
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

        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
        let garble_output = garbler.garble(circuit.clone()).unwrap();

        for j in 0..2 {
            let mut evaluator = BinaryEvaluator::new(
                garble_output.garbler_input_encodings.clone(),
                garble_output.evaluator_input_encodings.clone(),
                garble_output.decoding_infos.clone(),
                garbler.delta,
                AesHash::new(AES_KEY),
                garble_output.garbled_circuit.clone(),
            );
            let output = evaluator
                .evaluate(circuit.clone(), [].as_slice(), [j != 0].as_slice())
                .unwrap();
            let decoutput = evaluator
                .get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
            // let output = circuit.evaluate_plaintext([].as_slice(), [j != 0].as_slice());
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
                let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
                let garble_output = garbler.garble(circuit.clone()).unwrap();
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.garbler_input_encodings.clone(),
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let output = evaluator
                    .evaluate(circuit.clone(), [].as_slice(), [j != 0].as_slice())
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

    pub fn build_comparison_circuit() -> BinaryCircuit {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();
        let eval_input_2 = builder.evaluator_input();
        let garb_input_2 = builder.garbler_input();

        // Compare the bits
        let eq0 = builder.xor(eval_input_1, garb_input_1);
        let eq1 = builder.xor(eval_input_2, garb_input_2);

        let onewire = builder.constant(1);
        let temp1 = builder.and(eq0, eq1);
        let temp2 = builder.xor(eq0, eq1);
        let before_not = builder.xor(temp1, temp2);
        let result = builder.xor(before_not, onewire);
        builder.output(result);

        builder.finish()
    }

    #[test]
    fn test_comparison_circuit_garbled() {
        let comparison_circuit = build_comparison_circuit();
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
        let garble_output = garbler.garble(comparison_circuit.clone()).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i % 2 != 0;
                let jbit1 = j % 2 != 0;
                let ibit2 = (i / 2) % 2 != 0;
                let jbit2 = (j / 2) % 2 != 0;

                let mut evaluator = BinaryEvaluator::new(
                    garble_output.garbler_input_encodings.clone(),
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let output = evaluator
                    .evaluate(
                        comparison_circuit.clone(),
                        [ibit1, ibit2].as_slice(),
                        [jbit1, jbit2].as_slice(),
                    )
                    .unwrap();
                let decoutput = evaluator.get_plaintext_output(
                    comparison_circuit.get_output_gate_ids().to_vec(),
                    output.clone(),
                );

                // let output = comparison_circuit.evaluate_plaintext([ibit1, ibit2].as_slice(), [jbit1, jbit2].as_slice());
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

    fn bool_vec_to_hex(vec: Vec<bool>) -> String {
        let mut hex_string = String::new();

        // Process the vector in chunks of 4 bits
        for chunk in vec.chunks(4) {
            let mut value = 0;

            // Convert each bit to its corresponding position in a nibble (4 bits)
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    value |= 1 << (3 - i); // Shift bits according to position
                }
            }

            // Convert the 4-bit value to a hex digit
            hex_string.push_str(&format!("{:x}", value));
        }

        hex_string
    }

    #[test]
    fn test_aes_garbled() {
        let circuit = BinaryCircuit::parse("circuits/aes128.txt");
        let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
        let garble_output = garbler.garble(circuit.clone()).unwrap();
        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(
                    garble_output.garbler_input_encodings.clone(),
                    garble_output.evaluator_input_encodings.clone(),
                    garble_output.decoding_infos.clone(),
                    garbler.delta,
                    AesHash::new(AES_KEY),
                    garble_output.garbled_circuit.clone(),
                );
                let output = evaluator
                    .evaluate(
                        circuit.clone(),
                        [i != 0; 128].as_slice(),
                        [j != 0; 128].as_slice(),
                    )
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
