use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::circuitop::gate::BinaryGate;
use crate::config::garbling2pc_errors::FileParsingError;

/// Represents a binary circuit composed of various logic gates.
/// This struct keeps track of gates, inputs, outputs, and metadata
/// required for evaluation and is mainly used for garbling circuits.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryCircuit {
    /// A list of all gates in the circuit.
    pub gates: Vec<BinaryGate>,

    /// A list of gate IDs corresponding to the garbler's input wires.
    pub garbler_input_ids: Vec<usize>,

    /// A list of gate IDs corresponding to the evaluator's input wires.
    pub evaluator_input_ids: Vec<usize>,

    /// A list of gate IDs corresponding to the circuit's output wires.
    pub output_gate_ids: Vec<usize>,

    /// A list of gate IDs corresponding to constant values in the circuit.
    pub constant_gate_ids: Vec<usize>,

    /// The number of non-free (i.e., AND) gates in the circuit.
    /// This is used to track the complexity of garbled circuit evaluation.
    pub num_nonfree_gates: usize,

    /// The total number of wires used in the circuit.
    /// This includes inputs, outputs, and intermediate wires.
    pub num_wires: usize,
}

/// Implementation of the `BinaryCircuit` struct.
/// This provides methods for constructing, modifying, and parsing binary circuits.
impl BinaryCircuit {
    /// Parses a circuit definition from a file in the Bristol Fashion format.
    ///
    /// The Bristol Fashion format is a standard plaintext representation of
    /// boolean circuits, commonly used in secure computation protocols.
    /// More details can be found at:  
    /// <https://nigelsmart.github.io/MPC-Circuits/>
    ///
    /// # Arguments
    /// * `file_name` - A string slice representing the path to the circuit file.
    ///
    /// # Returns
    /// * `Ok(Self)` if the file is successfully parsed into a `BinaryCircuit`.
    /// * `Err(FileParsingError)` if there is an issue reading or parsing the file.
    pub fn parse(file_name: &str) -> Result<Self, FileParsingError> {
        let file = File::open(file_name)?;
        let mut reader = BufReader::new(file).lines();

        let mut num_gates: usize = 0;
        let mut num_wires: usize = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            num_gates = parts.next().unwrap().parse()?;
            num_wires = parts.next().unwrap().parse()?;
        }

        let mut output_circuit = Self::new(num_gates);
        let mut num_garbler_inputs = 0;
        let mut num_evaluator_inputs = 0;
        let mut num_outputs = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            if let Some(n_input_wires_str) = parts.next() {
                if let Ok(_num_inp_wires) = n_input_wires_str.parse::<u64>() {
                    if _num_inp_wires == 2 {
                        if let Some(num_garbl_inputs) = parts.next() {
                            if let Ok(_num_garbl_inputs) = num_garbl_inputs.parse::<usize>() {
                                if let Some(num_eval_inputs) = parts.next() {
                                    if let Ok(_num_eval_inputs) = num_eval_inputs.parse::<usize>() {
                                        num_garbler_inputs = _num_garbl_inputs;
                                        num_evaluator_inputs = _num_eval_inputs;
                                    } else {
                                        return Err(FileParsingError::InputNoParsingError());
                                    }
                                } else {
                                    return Err(FileParsingError::InputNoParsingError());
                                }
                            } else {
                                return Err(FileParsingError::InputNoParsingError());
                            }
                        } else {
                            return Err(FileParsingError::InputNoParsingError());
                        }
                    } else {
                        return Err(FileParsingError::InputCountError());
                    }
                } else {
                    return Err(FileParsingError::InputNoParsingError());
                }
            }
        }

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            if let Some(n_output_usizes_str) = parts.next() {
                if let Ok(n_output_usizes) = n_output_usizes_str.parse::<usize>() {
                    if n_output_usizes == 1 {
                        if let Some(n_outputs) = parts.next() {
                            if let Ok(n_output) = n_outputs.parse::<usize>() {
                                num_outputs = n_output;
                            }
                        }
                    } else {
                        return Err(FileParsingError::OutputCountError());
                    }
                } else {
                    return Err(FileParsingError::OutputNoParsingError());
                }
            }
        }

        let mut id: usize = 0;

        output_circuit.num_wires = num_wires;

        for i in 0..num_garbler_inputs {
            output_circuit.push_gate(BinaryGate::GarblerInput { id: i });
            output_circuit.push_garbler_input(i);
        }

        for i in 0..num_evaluator_inputs {
            output_circuit.push_gate(BinaryGate::EvaluatorInput { id: i });
            output_circuit.push_evaluator_input(i);
        }

        for i in 0..num_outputs {
            output_circuit.push_output_gate(num_wires - num_outputs + i)
        }

        for i in 0..num_gates {
            let num_input: usize;
            let mut _num_output = 0;
            let mut input0: usize = 0;
            let mut input1: usize = 0;
            let mut output: usize = 0;
            let mut gate = String::new();

            if let Some(Ok(line1)) = reader.next() {
                let mut parts = line1.split(' ');
                if let Some(num_inputs_str) = parts.next() {
                    if let Ok(parsed_num_input) = num_inputs_str.parse::<usize>() {
                        num_input = parsed_num_input;
                        _num_output = parts.next().unwrap().parse::<usize>()?;
                        input0 = parts.next().unwrap().parse::<usize>()?;
                        if num_input == 2 {
                            input1 = parts.next().unwrap().parse::<usize>()?
                        }
                        output = parts.next().unwrap().parse::<usize>()?;
                        if let Some(gate_str) = parts.next() {
                            gate = gate_str.to_string();
                        }
                    }
                }
            }

            if gate == "AND" {
                output_circuit.push_gate(BinaryGate::And {
                    xid: input0,
                    yid: input1,
                    id,
                    out: Some(output),
                });
                id += 1;
                output_circuit.increment_nonfree_gates();
            } else if gate == "XOR" {
                output_circuit.push_gate(BinaryGate::Xor {
                    xid: input0,
                    yid: input1,
                    out: Some(output),
                });
            } else if gate == "INV" {
                output_circuit.push_gate(BinaryGate::Inv {
                    xid: input0,
                    out: Some(output),
                });
            } else {
                return Err(FileParsingError::FileFormatError(i));
            }
        }
        Ok(output_circuit)
    }

    /// Creates a new `BinaryCircuit` with a specified number of gates.
    ///
    /// # Arguments
    /// * `ngates` - The expected number of gates in the circuit.
    ///
    /// # Returns
    /// * A new `BinaryCircuit` instance with preallocated space for gates.
    pub fn new(ngates: usize) -> Self {
        let gates: Vec<BinaryGate> = Vec::with_capacity(ngates);
        Self {
            gates,
            garbler_input_ids: Vec::new(),
            evaluator_input_ids: Vec::new(),
            output_gate_ids: Vec::new(),
            constant_gate_ids: Vec::new(),
            num_nonfree_gates: 0,
            num_wires: 0,
        }
    }

    /// Adds a new gate to the circuit.
    ///
    /// # Arguments
    /// * `gate` - A `BinaryGate` representing the gate to be added.
    pub fn push_gate(&mut self, gate: BinaryGate) {
        self.gates.push(gate);
    }

    /// Adds an output gate ID to the circuit.
    ///
    /// # Arguments
    /// * `output_gate_id` - The ID of the output gate.
    pub fn push_output_gate(&mut self, output_gate_id: usize) {
        self.output_gate_ids.push(output_gate_id);
    }

    /// Adds a constant gate ID to the circuit.
    ///
    /// # Arguments
    /// * `constant_gate_id` - The ID of the constant gate.
    pub fn push_constant_gate(&mut self, constant_gate_id: usize) {
        self.constant_gate_ids.push(constant_gate_id);
    }

    /// Adds a garbler input gate ID to the circuit.
    ///
    /// # Arguments
    /// * `garbler_input_id` - The ID of the garbler input gate.
    pub fn push_garbler_input(&mut self, garbler_input_id: usize) {
        self.garbler_input_ids.push(garbler_input_id);
    }

    /// Adds an evaluator input gate ID to the circuit.
    ///
    /// # Arguments
    /// * `evaluator_input_id` - The ID of the evaluator input gate.
    pub fn push_evaluator_input(&mut self, evaluator_input_id: usize) {
        self.evaluator_input_ids.push(evaluator_input_id);
    }

    /// Returns a reference to the list of output gate IDs.
    ///
    /// # Returns
    /// * A slice containing the IDs of all output gates in the circuit.
    pub fn get_output_gate_ids(&self) -> &[usize] {
        &self.output_gate_ids
    }

    /// Returns a reference to the list of garbler input gate IDs.
    ///
    /// # Returns
    /// * A slice containing the IDs of all garbler input gates.
    pub fn get_garbler_input_ids(&self) -> &[usize] {
        &self.garbler_input_ids
    }

    /// Returns a reference to the list of evaluator input gate IDs.
    ///
    /// # Returns
    /// * A slice containing the IDs of all evaluator input gates.
    pub fn get_evaluator_input_ids(&self) -> &[usize] {
        &self.evaluator_input_ids
    }

    /// Increments the count of non-free (AND) gates in the circuit.
    pub fn increment_nonfree_gates(&mut self) {
        self.num_nonfree_gates += 1;
    }

    /// Returns the number of non-free (AND) gates in the circuit.
    ///
    /// # Returns
    /// * The number of non-free gates.
    pub fn get_num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates
    }

    /// Returns the number of garbler input gates in the circuit.
    ///
    /// # Returns
    /// * The total count of garbler input gates.
    pub fn num_garbler_inputs(&self) -> usize {
        self.get_garbler_input_ids().len()
    }

    /// Returns the number of evaluator input gates in the circuit.
    ///
    /// # Returns
    /// * The total count of evaluator input gates.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.get_evaluator_input_ids().len()
    }

    /// Prints a textual representation of the circuit.
    pub fn print_circuit(&self) {
        for gate in self.gates.iter() {
            match *gate {
                BinaryGate::GarblerInput { id } => {
                    println!("GarblerInput: id: {}", self.garbler_input_ids[id])
                }
                BinaryGate::EvaluatorInput { id } => {
                    println!("EvaluatorInput: id: {}", self.evaluator_input_ids[id])
                }
                BinaryGate::Constant { val } => println!("Constantinput: val: {}", val),
                BinaryGate::Inv { xid, out } => {
                    println!("InverseGate: inp: {} output: {}", xid, out.unwrap_or(0))
                }
                BinaryGate::Xor { xid, yid, out } => println!(
                    "XorGate: inp1: {} inp2: {} output: {}",
                    xid,
                    yid,
                    out.unwrap_or(0)
                ),
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => println!(
                    "AndGate: inp1: {} inp2: {} output: {}",
                    xid,
                    yid,
                    out.unwrap_or(0)
                ),
            };
        }
        for i in self.get_output_gate_ids() {
            println!("output_gates: {}", *i);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::circuitop::{circuit::BinaryCircuit, gate::BinaryGate};

    #[test]
    fn test_circuit() {
        let circuit = BinaryCircuit::parse("circuits/binmult.txt");

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::GarblerInput { id: 0 },
                BinaryGate::GarblerInput { id: 1 },
                BinaryGate::EvaluatorInput { id: 0 },
                BinaryGate::EvaluatorInput { id: 1 },
                BinaryGate::And {
                    xid: 0,
                    yid: 2,
                    id: 0,
                    out: Some(4),
                },
                BinaryGate::And {
                    xid: 0,
                    yid: 3,
                    id: 1,
                    out: Some(5),
                },
                BinaryGate::And {
                    xid: 1,
                    yid: 2,
                    id: 2,
                    out: Some(6),
                },
                BinaryGate::And {
                    xid: 1,
                    yid: 3,
                    id: 3,
                    out: Some(7),
                },
                BinaryGate::Xor {
                    xid: 5,
                    yid: 6,
                    out: Some(8),
                },
                BinaryGate::Xor {
                    xid: 8,
                    yid: 7,
                    out: Some(9),
                },
            ],
            garbler_input_ids: vec![0, 1],
            evaluator_input_ids: vec![0, 1],
            output_gate_ids: vec![8, 9],
            constant_gate_ids: vec![],
            num_nonfree_gates: 0,
            num_wires: 10,
        };

        assert_eq!(required_circuit, circuit.unwrap());
    }
}
