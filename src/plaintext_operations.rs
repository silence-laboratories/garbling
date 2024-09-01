use std::fmt::Error;

use crate::{circuit::BinaryCircuit, exec::{BinaryOperations, ExecutionPrimitives}, gate::BinaryGate, threepartytraits::ThreePartyBinaryPlaintext};

pub struct BinaryPlaintext;

impl BinaryPlaintext {    
    pub fn new() -> Self {
        BinaryPlaintext{}
    }

    pub fn evaluate(&mut self, circ: BinaryCircuit, garbler_inputs: &[bool], evaluator_inputs: &[bool]) -> Vec<bool> {   
        if garbler_inputs.len() != circ.num_garbler_inputs() {
            println!("Number of Garbler inputs are inconsistent!!!");
            return Vec::new();
        }

        if evaluator_inputs.len() != circ.num_evaluator_inputs() {
            println!("Number of Evlauator inputs are inconsistent!!!");
            return Vec::new();
        }

        let mut cache : Vec<Option<bool>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(
                        id < garbler_inputs.len(),
                        "id={} gb_inps.len()={}",
                        id,
                        garbler_inputs.len()
                    );
                    (None, self.process_garbler_input(id, garbler_inputs[id].clone()).unwrap())
                },
                BinaryGate::EvaluatorInput { id } => {
                    assert!(
                        id < evaluator_inputs.len(),
                        "id={} ev_inps.len()={}",
                        id,
                        evaluator_inputs.len()
                    );
                    (None, self.process_evaluator_input(id, evaluator_inputs[id].clone()).unwrap())
                },
                BinaryGate::Constant { val } => (
                    None, self.constant(val).unwrap()
                ),
                BinaryGate::Inv { xid, out } => (
                    out, self.negate(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error).unwrap()
                    ).unwrap()
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out, self.xor(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error).unwrap(), 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error).unwrap()
                    ).unwrap()
                ),
                BinaryGate::And { xid, yid, id: _, out } => (
                    out, self.and(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error).unwrap(), 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error).unwrap()
                    ).unwrap()
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut outputs = Vec::with_capacity(circ.output_gate_ids.len());
        for r in circ.get_output_gate_ids().iter() {
            let r = cache[*r].as_ref().ok_or_else(|| Error).unwrap();
            let out = self.output(r).unwrap();
            outputs.push(out.unwrap())
        }
        outputs
    }
}

impl ExecutionPrimitives for BinaryPlaintext {
    type Item = bool;

    fn constant(&mut self, x: u16) -> Result<Self::Item, Error> {
        Ok(x != 0)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<bool>, std::fmt::Error> {
        Ok(Some(*x))
    }

    fn process_garbler_input(&mut self, _id: usize, x: bool) -> Result<Self::Item, Error> {
        Ok(x)
    }
    
    fn process_evaluator_input(&mut self, _id: usize, x: bool) -> Result<Self::Item, Error> {
        Ok(x)
    }
}

impl BinaryOperations for BinaryPlaintext {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        Ok(x ^ y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        Ok(x & y)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Error> {
        Ok(!x)
    }
}

impl ThreePartyBinaryPlaintext for BinaryPlaintext {
    fn evaluate_threeparty(&mut self, circ: BinaryCircuit, garbler_inputs: &[bool], evaluator_inputs: [&[bool]; 2]) -> Vec<bool> {   
        if garbler_inputs.len() != circ.num_garbler_inputs() {
            println!("Number of Garbler inputs are inconsistent!!!");
            return Vec::new();
        }

        if evaluator_inputs[0].len() + evaluator_inputs[1].len() != circ.num_evaluator_inputs() {
            println!("Number of Evlauator inputs are inconsistent!!!");
            return Vec::new();
        }

        let mut cache : Vec<Option<bool>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(
                        id < garbler_inputs.len(),
                        "id={} gb_inps.len()={}",
                        id,
                        garbler_inputs.len()
                    );
                    (None, self.process_garbler_input(id, garbler_inputs[id].clone()).unwrap())
                },
                BinaryGate::EvaluatorInput { id } => {
                    assert!(
                        id/2 < evaluator_inputs[0].len() && id/2 < evaluator_inputs[1].len(),
                        "id={} ev_inps.len()={}",
                        id,
                        evaluator_inputs.len()
                    );
                    if id % 2 == 0 {
                        (None, self.process_evaluator_input(id, evaluator_inputs[0][id/2].clone()).unwrap())
                    }
                    else {
                        (None, self.process_evaluator_input(id, evaluator_inputs[1][id/2].clone()).unwrap())
                    }
                },
                BinaryGate::Constant { val } => (
                    None, self.constant(val).unwrap()
                ),
                BinaryGate::Inv { xid, out } => (
                    out, self.negate(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error).unwrap()
                    ).unwrap()
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out, self.xor(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error).unwrap(), 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error).unwrap()
                    ).unwrap()
                ),
                BinaryGate::And { xid, yid, id: _, out } => (
                    out, self.and(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error).unwrap(), 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error).unwrap()
                    ).unwrap()
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut outputs = Vec::with_capacity(circ.output_gate_ids.len());
        for r in circ.get_output_gate_ids().iter() {
            let r = cache[*r].as_ref().ok_or_else(|| Error).unwrap();
            let out = self.output(r).unwrap();
            outputs.push(out.unwrap())
        }
        outputs
    }
}


#[cfg(test)]
mod tests {
    use crate::{circuit_builder::CircuitBuilder, BinaryCircuit};
    use super::BinaryPlaintext;
    
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
                let output = plaintexteval.evaluate(circuit.clone(), [i != 0].as_slice(), [j != 0].as_slice());
                let z = i ^ j;
                assert!((z == 1) == output[0],
                "z: {} output: {:?}", z, output[0])
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
                let output = plaintexteval.evaluate(circuit.clone(),[i != 0].as_slice(), [j != 0].as_slice());
                let z = i & j;
                assert!((z == 1) == output[0],
                "z: {} output: {:?} {} {}", z, output[0], i, j)
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
        
        for _i in 0..2 {
            for j in 0..2 {
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval.evaluate(circuit.clone(), [].as_slice(), [j != 0].as_slice());
                let z = 1 - j;
                assert!((z == 1) == output[0],
                "z: {} output: {:?}", z, output[0])
            }
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
                let output = plaintexteval.evaluate(circuit.clone(), [].as_slice(), [].as_slice());
                let z = i ^ j;
                assert!((z == 1) == output[0],
                "z: {} output: {:?}", z, output[0])
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
    
        let circuit = builder.finish();
    
        circuit
    }

    #[test]
    fn test_comparison_circuit_plain() {        
        let comparison_circuit = build_comparison_circuit();
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i%2 != 0;
                let jbit1 = j%2 != 0;
                let ibit2 = (i/2)%2 != 0;
                let jbit2 = (j/2)%2 != 0;

                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval.evaluate(comparison_circuit.clone(), [ibit1, ibit2].as_slice(), [jbit1, jbit2].as_slice());
                assert!((i == j) == output[0],
                "i: {}, j: {} output: {:?}", i, j, output[0])
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
    fn test_aes_plain() {
        let circuit = BinaryCircuit::parse("aes128.txt");
        for i in 0..2 {
            for j in 0..2 {
                let mut plaintexteval = BinaryPlaintext::new();
                let output = plaintexteval.evaluate(circuit.clone(), [i != 0; 128].as_slice(), [j != 0; 128].as_slice());
                let count = 2*i + j;
                let hexout = bool_vec_to_hex(output);
                if count == 0 {
                    assert_eq!(hexout, "74d42c539a5f3211dc3451f72bd29766".to_string(), "outval: {} realval: 74d42c539a5f3211dc3451f72bd29766", hexout);
                } else if count == 2 {
                    assert_eq!(hexout, "3493fd1ca2122691b3fabee131a46f85".to_string(), "outval: {} realval: 3493fd1ca2122691b3fabee131a46f85", hexout);
                } else if count == 1 {
                    assert_eq!(hexout, "7266b17c4be2ce5f505aa1579331dafc".to_string(), "outval: {} realval: 7266b17c4be2ce5f505aa1579331dafc", hexout);                    
                } else if count == 3 {
                    assert_eq!(hexout, "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string(), "outval: {} realval: 9e9d5c984a0e8a4d0cf3014d3e84fd3d", hexout);                    
                }
            }
        }
    }
}