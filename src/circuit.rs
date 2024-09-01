use std::fmt::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::exec::BinaryOperations;
use crate::gate::BinaryGate;
use crate::threepartytraits::ThreePartyBinaryCircuit;

#[derive(Clone)]
pub struct BinaryCircuit {
    pub gates: Vec<BinaryGate>,
    pub garbler_input_ids: Vec<usize>,
    pub evaluator_input_ids: Vec<usize>,
    pub output_gate_ids: Vec<usize>,
    pub constant_gate_ids: Vec<usize>,    
    pub num_nonfree_gates: usize,
    pub num_wires: usize,
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

        output_circuit.num_wires = num_wires;

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
            num_wires: 0
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
    
    pub fn num_garbler_inputs(&self) -> usize {
        self.get_garbler_input_ids().len()
    }
    
    pub fn num_evaluator_inputs(&self) -> usize {
        self.get_evaluator_input_ids().len()
    }

    pub fn print_circuit<F: BinaryOperations>(&self) -> Result<Vec<F::Item>, Error> {
        for (_i, gate) in self.gates.iter().enumerate() {
            let _ = match *gate {
                BinaryGate::GarblerInput { id } => {
                    println!("Garblerinput: id: {}", self.garbler_input_ids[id])
                },
                BinaryGate::EvaluatorInput { id } => {
                    println!("Evaluatorinput: id: {}", self.evaluator_input_ids[id])
                },
                BinaryGate::Constant { val } => println!("Constantinput: val: {}", val),
                BinaryGate::Inv { xid, out } => println!("InverseGate: inp: {} output: {}", xid, out.unwrap_or(0)),
                BinaryGate::Xor { xid, yid, out } => println!("XorGate: inp1: {} inp2: {} output: {}", xid, yid, out.unwrap_or(0)),
                BinaryGate::And { xid, yid, id: _, out } => println!("AndGate: inp1: {} inp2: {} output: {}", xid, yid, out.unwrap_or(0)),
            };
        }
        for i in self.get_output_gate_ids() {
            println!("output_gates: {}", *i);
        }
        Ok(Vec::new())
    }
}

impl ThreePartyBinaryCircuit for BinaryCircuit {
    fn parse_threeparty(file_name: &str)  -> Self {
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
                    if _num_inp_wires >= 2 {
                        for _ in 0.._num_inp_wires - 1 {
                            if let Some(num_garbl_inputs) = parts.next() {
                                if let Ok(_num_garbl_inputs) = num_garbl_inputs.parse::<usize>() {
                                    num_garbler_inputs = _num_garbl_inputs;
                                } else {
                                    println!("Failed to parse number of inputs");
                                }
                            } else {
                                println!("Failed to parse number of inputs");
                            }
                        }
                        if let Some(num_eval_inputs) = parts.next() {
                            if let Ok(_num_eval_inputs) = num_eval_inputs.parse::<usize>() {
                                num_evaluator_inputs = _num_eval_inputs;
                            }else {
                                println!("Failed to parse number of inputs");
                            }
                        }else {
                            println!("Failed to parse number of inputs");
                        }
                    }
                    else {
                        println!("Number of input wires is not 2 greater than equal to 2. Please define two inputs for garbler and evaluator respectively!!!");
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
            output_circuit.push_gate(BinaryGate::EvaluatorInput { id: 2*i });
            output_circuit.push_evaluator_input(num_garbler_inputs + 3*i);
            output_circuit.push_gate(BinaryGate::EvaluatorInput { id: 2*i + 1 });
            output_circuit.push_evaluator_input(num_garbler_inputs + 3*i + 1);
            output_circuit.push_gate(BinaryGate::Xor { xid: num_garbler_inputs + 3*i, yid: num_garbler_inputs + 3*i + 1, out: Some(num_garbler_inputs + 3*i + 2) });
        }

        
        // for i in 0..num_evaluator_inputs {
        // }

        num_wires += 2*num_evaluator_inputs;
        
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

            if input1 >= num_garbler_inputs {
                if input1 < num_garbler_inputs + num_evaluator_inputs {
                    input1 = input1 - num_garbler_inputs;
                    input1 = num_garbler_inputs + 3*input1 + 2;
                } else {
                    input1 += 2*num_evaluator_inputs;
                }
            }
            
            if input0 >= num_garbler_inputs {
                if input0 < num_garbler_inputs + num_evaluator_inputs {
                    input0 = input0 - num_garbler_inputs;
                    input0 = num_garbler_inputs + 3*input0 + 2;                    
                } else {
                    input0 += 2*num_evaluator_inputs;
                }
            }
            
            if output >= num_garbler_inputs {
                if output < num_garbler_inputs + num_evaluator_inputs {
                    output = output - num_garbler_inputs;
                    output = num_garbler_inputs + 3*output + 2;                    
                } else {
                    output += 2*num_evaluator_inputs;
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
}