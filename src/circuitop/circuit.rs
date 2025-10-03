use std::collections::HashMap;

use crate::circuitop::gate::BinaryGate;
use crate::config::errors::FileParsingError;

/// Represents a binary circuit composed of various logic gates.
/// This struct keeps track of gates, inputs, outputs, and metadata
/// required for evaluation and is mainly used for garbling circuits.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryCircuit {
    /// A list of all gates in the circuit.
    pub gates: Vec<BinaryGate>,

    /// A number of inputs in the circuit.
    pub num_inputs: usize,

    /// The list of gate IDs corresponding to the circuit's input wires.
    pub input_gate_ids: Vec<Vec<usize>>,

    /// A list of gate IDs corresponding to the circuit's output wires.
    pub output_gate_ids: Vec<usize>,

    /// A list of gate IDs corresponding to constant values in the circuit.
    pub constant_map: HashMap<u16, usize>,

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
    pub fn parse(file: &str) -> Result<Self, FileParsingError> {
        let mut reader = file.lines();

        let mut num_gates: usize = 0;
        let mut num_wires: usize = 0;

        if let Some(line1) = reader.next() {
            let mut parts = line1.split(' ');
            num_gates = parts.next().unwrap().parse()?;
            num_wires = parts.next().unwrap().parse()?;
        }

        let mut output_circuit = Self::new(num_gates);
        let mut input_sizes = Vec::new();
        let mut num_outputs = 0;

        if let Some(line1) = reader.next() {
            let mut parts = line1.split(' ');
            if let Some(n_input_wires_str) = parts.next() {
                if let Ok(num_inp_wires) = n_input_wires_str.parse::<usize>() {
                    for _ in 0..num_inp_wires {
                        if let Some(num_iplen) = parts.next() {
                            if let Ok(num_iplen) = num_iplen.parse::<usize>() {
                                input_sizes.push(num_iplen);
                            } else {
                                return Err(FileParsingError::InputNoParsingError());
                            }
                        } else {
                            return Err(FileParsingError::InputNoParsingError());
                        }
                    }
                } else {
                    return Err(FileParsingError::InputNoParsingError());
                }
            }
        }

        if let Some(line1) = reader.next() {
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

        let mut totalcount = 0;
        for (ipcnt, i) in input_sizes.iter().enumerate() {
            output_circuit.new_input();
            for j in 0..*i {
                output_circuit.push_gate(BinaryGate::Input {
                    no: ipcnt,
                    id: j,
                    wire: totalcount,
                });
                output_circuit.push_nth_input(ipcnt, j);
                totalcount += 1;
            }
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

            if let Some(line1) = reader.next() {
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
                    out: output,
                });
                id += 1;
                output_circuit.increment_nonfree_gates();
            } else if gate == "XOR" {
                output_circuit.push_gate(BinaryGate::Xor {
                    xid: input0,
                    yid: input1,
                    out: output,
                });
            } else if gate == "INV" {
                output_circuit.push_gate(BinaryGate::Inv {
                    xid: input0,
                    out: output,
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
            num_inputs: 0,
            input_gate_ids: Vec::new(),
            output_gate_ids: Vec::new(),
            constant_map: HashMap::new(),
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
    pub fn push_constant_gate(&mut self, val: u16, constant_gate_id: usize) {
        self.constant_map.insert(val, constant_gate_id);
    }

    /// Adds an input gate ID to the circuit.
    ///
    /// # Arguments
    /// * `garbler_input_id` - The ID of the garbler input gate.
    pub fn new_input(&mut self) {
        self.input_gate_ids.push(vec![]);
        self.num_inputs += 1
    }

    /// Adds an input gate ID to the circuit.
    ///
    /// # Arguments
    /// * `garbler_input_id` - The ID of the garbler input gate.
    pub fn push_nth_input(&mut self, n: usize, input_id: usize) {
        self.input_gate_ids[n].push(input_id);
    }

    /// Adds an input gate ID to the circuit.
    ///
    /// # Arguments
    /// * `garbler_input_id` - The ID of the garbler input gate.
    pub fn push_nth_inputs(&mut self, n: usize, input_id: &[usize]) {
        self.input_gate_ids[n].extend_from_slice(input_id);
    }

    /// Returns a reference to the list of output gate IDs.
    ///
    /// # Returns
    /// * A slice containing the IDs of all output gates in the circuit.
    pub fn get_output_gate_ids(&self) -> &[usize] {
        &self.output_gate_ids
    }

    /// Returns a reference to the list of n-th input gate IDs.
    ///
    /// # Returns
    /// * A slice containing the IDs of all n-th input gates.
    pub fn get_nth_input_ids(&self, n: usize) -> &[usize] {
        &self.input_gate_ids[n]
    }

    /// Returns a reference to the list of all input gate IDs.
    ///
    /// # Returns
    /// * A slice containing the Vectors of IDs of all input gates.
    pub fn get_input_ids(&self) -> &[Vec<usize>] {
        &self.input_gate_ids
    }

    /// Increments the count of non-free (AND) gates in the circuit.
    pub fn increment_nonfree_gates(&mut self) {
        self.num_nonfree_gates += 1;
    }

    /// Increments the count of wires in the circuit.
    pub fn increment_wires(&mut self) {
        self.num_wires += 1;
    }

    /// Returns the number of non-free (AND) gates in the circuit.
    ///
    /// # Returns
    /// * The number of non-free gates.
    pub fn get_num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates
    }

    /// Returns the number of inputs in the circuit.
    ///
    /// # Returns
    /// * The total count of garbler input gates.
    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    /// Returns the number of input gate IDs in the n-th input in the circuit.
    ///
    /// # Returns
    /// * The total count of garbler input gates.
    pub fn num_nth_inputs(&self, n: usize) -> usize {
        self.input_gate_ids[n].len()
    }

    /// Prints a textual representation of the circuit.
    pub fn print_circuit(&self) {
        for gate in self.gates.iter() {
            match *gate {
                BinaryGate::Input { no, id, wire } => {
                    println!("Input: no: {} id: {} wire: {}", no, id, wire)
                }
                BinaryGate::Constant { val, wire: _ } => println!("Constantinput: val: {}", val),
                BinaryGate::Inv { xid, out } => {
                    println!("InverseGate: inp: {} output: {}", xid, out)
                }
                BinaryGate::Xor { xid, yid, out } => {
                    println!("XorGate: inp1: {} inp2: {} output: {}", xid, yid, out)
                }
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => println!("AndGate: inp1: {} inp2: {} output: {}", xid, yid, out),
            };
        }
        for i in self.get_output_gate_ids() {
            println!("output_gates: {}", *i);
        }
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        config::constants::BINMULT_CIRCUIT,
    };

    #[test]
    fn test_circuit() {
        let circuit = BinaryCircuit::parse(BINMULT_CIRCUIT);

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::Input {
                    no: 0,
                    id: 0,
                    wire: 0,
                },
                BinaryGate::Input {
                    no: 0,
                    id: 1,
                    wire: 1,
                },
                BinaryGate::Input {
                    no: 1,
                    id: 0,
                    wire: 2,
                },
                BinaryGate::Input {
                    no: 1,
                    id: 1,
                    wire: 3,
                },
                BinaryGate::And {
                    xid: 0,
                    yid: 2,
                    id: 0,
                    out: 4,
                },
                BinaryGate::And {
                    xid: 0,
                    yid: 3,
                    id: 1,
                    out: 5,
                },
                BinaryGate::And {
                    xid: 1,
                    yid: 2,
                    id: 2,
                    out: 6,
                },
                BinaryGate::And {
                    xid: 1,
                    yid: 3,
                    id: 3,
                    out: 7,
                },
                BinaryGate::Xor {
                    xid: 5,
                    yid: 6,
                    out: 8,
                },
                BinaryGate::Xor {
                    xid: 8,
                    yid: 7,
                    out: 9,
                },
            ],
            num_inputs: 2,
            input_gate_ids: vec![vec![0, 1], vec![0, 1]],
            output_gate_ids: vec![8, 9],
            constant_map: HashMap::new(),
            num_nonfree_gates: 4,
            num_wires: 10,
        };

        assert_eq!(required_circuit, circuit.unwrap());
    }
}
