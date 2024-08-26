use std::collections::HashMap;
use std::fmt::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::config::constants::BLOCK;
use crate::evaluator_operations::BinaryEvaluator;
use crate::exec::{BinaryOperations, ExecutionPrimitives};
use crate::garbler_operations::BinaryGarbler;
use crate::hash_aes::HashFunction;
use crate::plaintext_operations::BinaryPlaintext;


#[derive(Clone)]
pub enum BinaryGate {
    GarblerInput {
        id: usize,
    },
    EvaluatorInput {
        id: usize,
    },
    Constant {
        val: u16,
    },
    Xor {
        xid: usize,
        yid: usize,
        out: Option<usize>,
    },
    And {
        xid: usize,
        yid: usize,
        id: usize,
        out: Option<usize>,
    },
    Inv {
        xid: usize,
        out: Option<usize>,
    },
}

#[derive(Clone)]
pub struct BinaryCircuit {
    pub gates: Vec<BinaryGate>,
    pub garbler_input_ids: Vec<usize>,
    pub evaluator_input_ids: Vec<usize>,
    pub output_gate_ids: Vec<usize>,
    pub constant_gate_ids: Vec<usize>,    
    pub num_nonfree_gates: usize,
}

impl BinaryCircuit {
    pub fn parse (file_name: &str) -> Self {
        let file = File::open(file_name).expect("Failed to open the circuit file");
        let mut reader = BufReader::new(file).lines();

        let mut num_gates: usize = 0;
        let mut num_wires: usize = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(" ");
            num_gates = parts.next().unwrap().parse().unwrap();
            num_wires = parts.next().unwrap().parse().unwrap();
        }

        let mut output_circuit = Self::new(num_gates);
        let mut num_garbler_inputs = 0;
        let mut num_evaluator_inputs = 0;
        let mut num_outputs = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(" ");
            if let Some(n_input_wires_str) = parts.next() {
                if let Ok(_num_inp_wires) = n_input_wires_str.parse::<u64>() {
                    if _num_inp_wires == 2 {
                        if let Some(num_garbl_inputs) = parts.next() {
                            if let Ok(_num_garbl_inputs) = num_garbl_inputs.parse::<usize>() {
                                if let Some(num_eval_inputs) = parts.next() {
                                    if let Ok(_num_eval_inputs) = num_eval_inputs.parse::<usize>() {
                                        num_garbler_inputs = _num_garbl_inputs;
                                        num_evaluator_inputs = _num_eval_inputs;
                                    }else {
                                        println!("Failed to parse number of inputs");
                                    }
                                }else {
                                    println!("Failed to parse number of inputs");
                                }
                            }else {
                                println!("Failed to parse number of inputs");
                            }
                        }else {
                            println!("Failed to parse number of inputs");
                        }
                    }
                    else {
                        println!("Number of input wires is not 2. Please define two inputs for garbler and evaluator respectively!!!");
                    }
                } else {
                    println!("Failed to parse number of inputs");
                }
            }
        }

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(" ");
            if let Some(n_output_usizes_str) = parts.next() {
                if let Ok(n_output_usizes) = n_output_usizes_str.parse::<usize>() {
                    if n_output_usizes == 1 {
                        if let Some(n_outputs) = parts.next() {
                            if let Ok(n_output) = n_outputs.parse::<usize>() {
                                num_outputs = n_output;
                            }
                        }
                    }
                    else {
                        println!("Number of input wires is not 1");
                    }
                } else {
                    println!("Failed to parse number of outputs");
                }
            }
        }

        let mut id: usize = 0;

        for i in 0..num_garbler_inputs  {
            output_circuit.push_gate(BinaryGate::GarblerInput { id: i });
            output_circuit.push_garbler_input(i);
        }

        for i in 0..num_evaluator_inputs  {
            output_circuit.push_gate(BinaryGate::EvaluatorInput { id: i });
            output_circuit.push_evaluator_input(num_garbler_inputs  + i);
        }

        for i in 0..num_outputs  {
            output_circuit.push_output_gate(num_wires - num_outputs + i)
        }

        for _i in 0..num_gates {
            let num_input: usize;
            let mut _num_output = 0;
            let mut input0: usize = 0;
            let mut input1: usize = 0;
            let mut output: usize = 0;
            let mut gate = String::new();

            if let Some(Ok(line1)) = reader.next() {
                let mut parts = line1.split(" ");
                if let Some(num_inputs_str) = parts.next() {
                    if let Ok(parsed_num_input) = num_inputs_str.parse::<usize>() {
                        num_input = parsed_num_input;
                        _num_output = parts.next().unwrap().parse::<usize>().unwrap();
                        input0 = parts.next().unwrap().parse::<usize>().unwrap();
                        if num_input == 2 {
                            input1 = parts.next().unwrap().parse::<usize>().unwrap()
                        }
                        output = parts.next().unwrap().parse::<usize>().unwrap();
                        if let Some(gate_str) = parts.next() {
                            gate = gate_str.to_string();
                        }
                    }
                }
            }

            if gate == "AND" {
                output_circuit.push_gate(BinaryGate::And { xid: input0, yid: input1, id: id, out: Some(output) });
                id += 1;
            }
            else if gate == "XOR" {
                output_circuit.push_gate(BinaryGate::Xor { xid: input0, yid: input1, out: Some(output) });
            }
            else if gate == "INV" {
                output_circuit.push_gate(BinaryGate::Inv { xid: input0, out: Some(output) });
            }
            else {
                println!("Incorrect file format. gate number: {} from the top", _i);
            }
        }
        output_circuit
    }

    pub fn new(ngates: usize) -> Self {
        let gates: Vec<BinaryGate> = Vec::with_capacity(ngates);
        Self {
            gates,
            garbler_input_ids: Vec::new(),
            evaluator_input_ids: Vec::new(),
            output_gate_ids: Vec::new(),
            constant_gate_ids: Vec::new(),
            num_nonfree_gates: 0,
        }
    }

    pub fn push_gate(&mut self, gate: BinaryGate) {
        self.gates.push(gate);
    }

    pub fn push_output_gate(&mut self, output_gate_id: usize) {
        self.output_gate_ids.push(output_gate_id);
    }
    
    pub fn push_constant_gate(&mut self, constant_gate_id: usize) {
        self.constant_gate_ids.push(constant_gate_id);
    }

    pub fn push_garbler_input(&mut self, garbler_input_id: usize) {
        self.garbler_input_ids.push(garbler_input_id);
    }

    pub fn push_evaluator_input(&mut self, evaluator_input_id: usize) {
        self.evaluator_input_ids.push(evaluator_input_id);
    }

    pub fn get_output_gate_ids(&self) -> &[usize] {
        &self.output_gate_ids
    }

    pub fn get_garbler_input_ids(&self) -> &[usize] {
        &self.garbler_input_ids
    }

    pub fn get_evaluator_input_ids(&self) -> &[usize] {
        &self.evaluator_input_ids
    }

    pub fn increment_nonfree_gates(&mut self) {
        self.num_nonfree_gates += 1;
    }

    pub fn get_num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates
    }
    
    fn num_garbler_inputs(&self) -> usize {
        self.get_garbler_input_ids().len()
    }
    
    fn num_evaluator_inputs(&self) -> usize {
        self.get_evaluator_input_ids().len()
    }
    
    pub fn evaluate_plaintext (&self, garbler_inputs: &[bool], evaluator_inputs: &[bool]) -> Vec<bool> {   
        if garbler_inputs.len() != self.num_garbler_inputs() {
            println!("Number of Garbler inputs are inconsistent!!!");
            return Vec::new();
        }

        if evaluator_inputs.len() != self.num_evaluator_inputs() {
            println!("Number of Evlauator inputs are inconsistent!!!");
            return Vec::new();
        }

        let z = self.eval(&mut BinaryPlaintext, garbler_inputs, evaluator_inputs);       

        z.unwrap()

    }

    fn garbler_evaluate<H: HashFunction>(&self, f: &mut BinaryGarbler<H>) -> 
    Result<(
        HashMap<usize, BLOCK>, 
        HashMap<usize, BLOCK>, 
        Vec<BLOCK>, HashMap<usize, u8>), 
        Error> 
    {
        let mut cache : Vec<Option<BLOCK>> = vec![None; self.gates.len()];
        let mut garbler_input_encodings: HashMap<usize, BLOCK> = HashMap::new();
        let mut evaluator_input_encodings: HashMap<usize, BLOCK> = HashMap::new();
        for (i, gate) in self.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    let input_hash = f.process_garbler_input(id, false)?;
                    garbler_input_encodings.insert(id, input_hash.clone());
                    (None, input_hash)
                },
                BinaryGate::EvaluatorInput { id } => {
                    let input_hash = f.process_evaluator_input(id, false)?;
                    evaluator_input_encodings.insert(id, input_hash.clone());
                    (None, input_hash)
                },
                BinaryGate::Constant { val } => (
                    None, f.constant(val)?
                ),
                BinaryGate::Inv { xid, out } => (
                    out, f.negate(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out, f.xor(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?, 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
                BinaryGate::And { xid, yid, id: _, out } => (
                    out, f.and(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?, 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut decoding_infos: HashMap<usize, u8> = HashMap::new();
        for r in self.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or_else(|| Error)?;
            let dec = f.get_decoding(*x);
            decoding_infos.insert(*r, dec);
        }
        Ok((garbler_input_encodings, evaluator_input_encodings, f.get_garbled_circuit(), decoding_infos))
    }

    pub fn evaluator_evaluate<H: HashFunction>(&self, f: &mut BinaryEvaluator<H>, garbler_inputs: &[bool], evaluator_inputs: &[bool]) -> 
    Result<HashMap<usize, BLOCK>, 
        Error> 
    {
        let mut cache : Vec<Option<BLOCK>> = vec![None; self.gates.len()];
        let mut garbler_input_encodings: HashMap<usize, BLOCK> = HashMap::new();
        let mut evaluator_input_encodings: HashMap<usize, BLOCK> = HashMap::new();
        for (i, gate) in self.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    let input_hash = f.process_garbler_input(id, garbler_inputs[id])?;
                    garbler_input_encodings.insert(id, input_hash.clone());
                    (None, input_hash)
                },
                BinaryGate::EvaluatorInput { id } => {
                    let input_hash = f.process_evaluator_input(id, evaluator_inputs[id])?;
                    evaluator_input_encodings.insert(id, input_hash.clone());
                    (None, input_hash)
                },
                BinaryGate::Constant { val } => (
                    None, f.constant(val)?
                ),
                BinaryGate::Inv { xid, out } => (
                    out, f.negate(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out, f.xor(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?, 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
                BinaryGate::And { xid, yid, id: _, out } => (
                    out, f.and(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?, 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut garbled_output: HashMap<usize, BLOCK> = HashMap::new();
        for r in self.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or_else(|| Error)?;
            let dec = f.output(x)?.unwrap();
            garbled_output.insert(*r, dec);
        }
        Ok(garbled_output)
    }

    pub fn garble<H: HashFunction>(&self, rng: H) -> (
        HashMap<usize, BLOCK>, 
        HashMap<usize, BLOCK>, 
        Vec<BLOCK>, 
        HashMap<usize, u8>,
        BLOCK
    ) {
        let mut garbler = BinaryGarbler::new(rng);
        let (gen, een, gc, din) = self.garbler_evaluate(&mut garbler).unwrap();
        (gen, een, gc, din, garbler.delta)
    }

    pub fn eval<F: BinaryOperations>(&self, f: &mut F, garbler_inputs: &[bool], evaluator_inputs: &[bool]) -> Result<Vec<F::Item>, Error> {
        let mut cache : Vec<Option<F::Item>> = vec![None; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(
                        id < garbler_inputs.len(),
                        "id={} gb_inps.len()={}",
                        id,
                        garbler_inputs.len()
                    );
                    (None, f.process_garbler_input(id, garbler_inputs[id].clone())?)
                },
                BinaryGate::EvaluatorInput { id } => {
                    assert!(
                        id < evaluator_inputs.len(),
                        "id={} ev_inps.len()={}",
                        id,
                        evaluator_inputs.len()
                    );
                    (None, f.process_evaluator_input(id, evaluator_inputs[id].clone())?)
                },
                BinaryGate::Constant { val } => (
                    None, f.constant(val)?
                ),
                BinaryGate::Inv { xid, out } => (
                    out, f.negate(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out, f.xor(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?, 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
                BinaryGate::And { xid, yid, id: _, out } => (
                    out, f.and(
                        cache[xid]
                        .as_ref()
                        .ok_or(Error)?, 
                        cache[yid]
                        .as_ref()
                        .ok_or(Error)?
                    )?
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut outputs = Vec::with_capacity(self.output_gate_ids.len());
        for r in self.get_output_gate_ids().iter() {
            let r = cache[*r].as_ref().ok_or_else(|| Error)?;
            let out = f.output(r)?;
            outputs.push(out.unwrap())
        }
        Ok(outputs)
    }

}

#[derive(Clone)]
pub struct CircuitBuilder<BinaryCircuit> {
    next_ref_id: usize,
    next_garbler_input_id: usize,
    next_evaluator_input_id: usize,
    const_map: HashMap<u16, usize>,
    circ: BinaryCircuit
}

impl CircuitBuilder<BinaryCircuit> {
    
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_id: 0,
            next_garbler_input_id: 0,
            next_evaluator_input_id: 0,
            const_map: HashMap::new(),
            circ: BinaryCircuit::new(0),
        }
    }

    pub fn finish(self) -> BinaryCircuit {
        self.circ
    }

    fn get_next_garbler_input_id(&mut self) -> usize {
        let current = self.next_garbler_input_id;
        self.next_garbler_input_id += 1;
        current
    }

    fn get_next_evaluator_input_id(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 1;
        current
    }

    fn get_next_ciphertext_id(&mut self) -> usize {
        let current = self.circ.get_num_nonfree_gates();
        self.circ.increment_nonfree_gates();
        current
    }

    fn get_next_ref_id(&mut self) -> usize {
        let current = self.next_ref_id;
        self.next_ref_id += 1;
        current
    }

    fn gate(&mut self, gate: BinaryGate) -> usize {
        self.circ.push_gate(gate);
        self.get_next_ref_id()
    }

    pub fn garbler_input(&mut self) -> usize {
        let id = self.get_next_garbler_input_id();
        let r = self.gate(BinaryGate::GarblerInput { id: id });
        self.circ.push_garbler_input(r);
        r
    }

    pub fn evaluator_input(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id();
        let r = self.gate(BinaryGate::EvaluatorInput { id: id });
        self.circ.push_evaluator_input(r);
        r
    }

    pub fn garbler_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.garbler_input());
        }
        output
    }

    pub fn evaluator_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        // 0..number_of_inputs.iter().map(|q| self.evaluator_input()).collect()
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.evaluator_input());
        }
        output
    }

    pub fn xor(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::Xor { xid: xid, yid: yid, out: None };
        self.gate(gate)
    }

    pub fn negate(&mut self, xid: usize) -> usize {
        let gate = BinaryGate::Inv {
            xid: xid,
            out: None,
        };
        self.gate(gate)
    }

    pub fn and(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::And {
            xid: xid,
            yid: yid,
            id: self.get_next_ciphertext_id(),
            out: None,
        };

        self.gate(gate)
    }

    pub fn constant(&mut self, val: u16) -> usize {
        match self.const_map.get(&val) {
            Some(&r) => r,
            None => {
                let gate = BinaryGate::Constant { val };
                let r = self.gate(gate);
                self.const_map.insert(val, r);
                self.circ.push_constant_gate(r);
                r
            }
        }
    }

    pub fn output(&mut self, id: usize) {
        self.circ.push_output_gate(id);
    }

}


#[cfg(test)]
mod tests {
    use crate::{config::constants::AES_KEY, evaluator_operations::BinaryEvaluator, hash_aes::AesHash};

    use super::{BinaryCircuit, CircuitBuilder};


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
                let output = circuit.evaluate_plaintext([i != 0].as_slice(), [j != 0].as_slice());
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
                let output = circuit.evaluate_plaintext([i != 0].as_slice(), [j != 0].as_slice());
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
                let output = circuit.evaluate_plaintext([].as_slice(), [j != 0].as_slice());
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
                let output = circuit.evaluate_plaintext([].as_slice(), [].as_slice());
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

                let output = comparison_circuit.evaluate_plaintext([ibit1, ibit2].as_slice(), [jbit1, jbit2].as_slice());
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
                let output = circuit.evaluate_plaintext([i != 0; 128].as_slice(), [j != 0; 128].as_slice());
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


    #[test]
    fn test_xor_gate_garbled() {
        let mut builder = CircuitBuilder::new();
        
        let eval_input_1 = builder.evaluator_input();
        let garb_input_1 = builder.garbler_input();

        let result = builder.xor(eval_input_1, garb_input_1);
        builder.output(result);
        let circuit = builder.finish();

        
        let (gen, een, gc, din, delta) = circuit.garble(AesHash::new(AES_KEY));
        
        for i in 0..2 {
                for j in 0..2 {
                    let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
                    let output = circuit.evaluator_evaluate(&mut evaluator, [i != 0].as_slice(), [j != 0].as_slice()).unwrap();
                    let decoutput = evaluator.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                    let z = i ^ j;
                    assert!((z == 1) == decoutput[0],
                    "z: {} output: {:?}", z, decoutput[0])
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
        
        let (gen, een, gc, din, delta) = circuit.garble(AesHash::new(AES_KEY));

        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
                let output = circuit.evaluator_evaluate(&mut evaluator, [i != 0].as_slice(), [j != 0].as_slice()).unwrap();
                let decoutput = evaluator.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                let z = i & j;
                assert!((z == 1) == decoutput[0],
                "z: {} output: {:?} {} {}", z, decoutput[0], i, j)
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
        
        let (gen, een, gc, din, delta) = circuit.garble(AesHash::new(AES_KEY));
        
        for _i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
                let output = circuit.evaluator_evaluate(&mut evaluator, [].as_slice(), [j != 0].as_slice()).unwrap();
                let decoutput = evaluator.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                // let output = circuit.evaluate_plaintext([].as_slice(), [j != 0].as_slice());
                let z = 1 - j;
                assert!((z == 1) == decoutput[0],
                "z: {} output: {:?}", z, decoutput[0])
            }
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
                let (gen, een, gc, din, delta) = circuit.garble(AesHash::new(AES_KEY));
                let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
                let output = circuit.evaluator_evaluate(&mut evaluator, [].as_slice(), [j != 0].as_slice()).unwrap();
                let decoutput = evaluator.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                let z = i ^ j;
                assert!((z == 1) == decoutput[0],
                "z: {} output: {:?}", z, decoutput[0])
            }
        }
    }


    #[test]
    fn test_comparison_circuit_garbled() {        
        let comparison_circuit = build_comparison_circuit();
        let (gen, een, gc, din, delta) = comparison_circuit.garble(AesHash::new(AES_KEY));
        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i%2 != 0;
                let jbit1 = j%2 != 0;
                let ibit2 = (i/2)%2 != 0;
                let jbit2 = (j/2)%2 != 0;
                
                let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
                let output = comparison_circuit.evaluator_evaluate(&mut evaluator, [ibit1, ibit2].as_slice(), [jbit1, jbit2].as_slice()).unwrap();
                let decoutput = evaluator.get_plaintext_output(comparison_circuit.get_output_gate_ids().to_vec(), output.clone());

                // let output = comparison_circuit.evaluate_plaintext([ibit1, ibit2].as_slice(), [jbit1, jbit2].as_slice());
                assert!((i == j) == decoutput[0],
                "i: {}, j: {} output: {:?}", i, j, decoutput[0])
            }
        }
    }


    #[test]
    fn test_aes_garbled() {
        let circuit = BinaryCircuit::parse("aes128.txt");
        let (gen, een, gc, din, delta) = circuit.garble(AesHash::new(AES_KEY));
        for i in 0..2 {
            for j in 0..2 {
                let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
                let output = circuit.evaluator_evaluate(&mut evaluator, [i != 0; 128].as_slice(), [j != 0; 128].as_slice()).unwrap();
                let decoutput = evaluator.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), output.clone());
                let count = 2*i + j;
                let hexout = bool_vec_to_hex(decoutput);
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