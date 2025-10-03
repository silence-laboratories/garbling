use std::collections::HashMap;

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::errors::FileParsingError,
};

/// `CircuitBuilder` is a struct used to construct a `BinaryCircuit`.
/// It maintains internal state during the circuit construction process.
/// Once the circuit is built and returned, the builder can either be discarded
/// or reused to construct a new circuit on top of the existing one.
#[derive(Clone)]
pub struct CircuitBuilder<BinaryCircuit> {
    /// Tracks the next available gate ID in the circuit.
    pub next_ref_id: usize,

    /// A mapping of constant values to their corresponding gate IDs.
    /// This allows reuse of constant gates instead of creating duplicates.
    pub const_map: HashMap<u16, usize>,

    /// The binary circuit being constructed.
    /// This is incrementally updated as new gates and inputs are added.
    /// Once the construction is complete, the circuit can be extracted from the builder.
    pub circ: BinaryCircuit,
}

/// Implementation of the `CircuitBuilder` struct.
/// Provides methods to construct and output a `BinaryCircuit`.
impl CircuitBuilder<BinaryCircuit> {
    /// Creates a new, empty `CircuitBuilder` instance.
    /// Initializes all tracking counters to zero and sets up an empty circuit.
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_id: 0,
            const_map: HashMap::new(),
            circ: BinaryCircuit::new(0),
        }
    }

    /// Returns the built `BinaryCircuit`.
    pub fn finish(self) -> BinaryCircuit {
        self.circ
    }

    /// Retrieves the next available input ID for the n-th input.
    fn get_next_nth_input_id(&mut self, n: usize) -> usize {
        let current = self.circ.get_input_ids()[n].len();
        current
    }

    /// Retrieves the next available ciphertext ID for non-free gates.
    /// This ID is used to reference ciphertexts in the circuit.
    fn get_next_ciphertext_id(&mut self) -> usize {
        let current = self.circ.get_num_nonfree_gates();
        self.circ.increment_nonfree_gates();
        current
    }

    /// Retrieves the next available reference ID for a gate and increments the counter.
    fn get_next_ref_id(&mut self) -> usize {
        let current = self.next_ref_id;
        self.next_ref_id += 1;
        current
    }

    /// Adds a new input gate to the circuit.
    /// Returns the reference ID of the created input gate.
    pub fn new_input(&mut self) -> usize {
        let id = self.get_next_nth_input_id(self.circ.num_inputs());
        let gate_id = self.get_next_ref_id();
        self.circ.push_gate(BinaryGate::Input {
            no: self.circ.num_inputs(),
            id,
            wire: gate_id,
        });
        self.circ.new_input();
        self.circ.push_nth_input(self.circ.num_inputs() - 1, id);
        self.circ.increment_wires();
        gate_id
    }

    /// Adds multiple garbler input gates to the circuit.
    /// Returns a vector of reference IDs corresponding to the created inputs.
    pub fn new_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        let mut output: Vec<usize> = Vec::new();
        self.circ.new_input();
        for _i in 0..number_of_inputs {
            let id = self.get_next_nth_input_id(self.circ.num_inputs() - 1);
            let gate_id = self.get_next_ref_id();
            self.circ.push_gate(BinaryGate::Input {
                no: self.circ.num_inputs() - 1,
                id,
                wire: gate_id,
            });
            output.push(gate_id);
            self.circ.push_nth_input(self.circ.num_inputs() - 1, id);
            self.circ.increment_wires();
        }
        output
    }

    /// Adds an XOR gate to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn xor(&mut self, xid: usize, yid: usize) -> usize {
        let out_id = self.get_next_ref_id();
        let gate = BinaryGate::Xor {
            xid,
            yid,
            out: out_id,
        };
        self.circ.push_gate(gate);
        self.circ.increment_wires();
        out_id
    }

    /// Adds a NOT gate (negation) to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn negate(&mut self, xid: usize) -> usize {
        let out_id = self.get_next_ref_id();
        let gate = BinaryGate::Inv { xid, out: out_id };
        self.circ.push_gate(gate);
        self.circ.increment_wires();
        out_id
    }

    /// Adds an AND gate to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn and(&mut self, xid: usize, yid: usize) -> usize {
        let out_id = self.get_next_ref_id();
        let gate = BinaryGate::And {
            xid,
            yid,
            id: self.get_next_ciphertext_id(),
            out: out_id,
        };
        self.circ.push_gate(gate);
        self.circ.increment_wires();
        out_id
    }

    /// Adds a constant gate to the circuit.
    /// If the constant already exists in the circuit, returns its reference ID.
    /// Otherwise, creates a new constant gate, stores it in `const_map`, and returns its reference ID.
    pub fn constant(&mut self, val: u16) -> usize {
        match self.const_map.get(&val) {
            Some(&r) => r,
            None => {
                let out_id = self.get_next_ref_id();
                let gate = BinaryGate::Constant { val, wire: out_id };
                self.circ.push_gate(gate);
                self.const_map.insert(val, out_id);
                self.circ.increment_wires();
                self.circ.push_constant_gate(val, out_id);
                out_id
            }
        }
    }

    /// Marks a gate as an output in the circuit.
    pub fn output(&mut self, id: usize) {
        self.circ.push_output_gate(id);
    }

    /// Takes a file, the input ids and adds the circuit in the file to the circuit.
    /// Returns the resultant output gate ids from the circuit file.
    pub fn parse(
        &mut self,
        file: &str,
        garbler_input_ids: &[usize],
        evaluator_input_ids: &[usize],
    ) -> Result<Vec<usize>, FileParsingError> {
        let mut reader = file.lines();

        let mut num_gates: usize = 0;
        let mut num_wires: usize = 0;

        if let Some(line1) = reader.next() {
            let mut parts = line1.split(' ');
            num_gates = parts.next().unwrap().parse()?;
            num_wires = parts.next().unwrap().parse()?;
        }

        let mut num_garbler_inputs = 0;
        let mut num_evaluator_inputs = 0;
        let mut num_outputs = 0;

        if let Some(line1) = reader.next() {
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

        assert_eq!(num_garbler_inputs, garbler_input_ids.len());
        assert_eq!(num_evaluator_inputs, evaluator_input_ids.len());

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
        let latest_ref = self.next_ref_id;
        let sub_val = num_garbler_inputs + num_evaluator_inputs;

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
                let newinput0: usize;
                if input0 >= sub_val {
                    newinput0 = input0 + latest_ref - sub_val;
                } else if input0 >= num_garbler_inputs {
                    newinput0 = evaluator_input_ids[input0 - num_garbler_inputs];
                } else {
                    newinput0 = garbler_input_ids[input0];
                }

                let newinput1: usize;
                if input1 >= sub_val {
                    newinput1 = input1 + latest_ref - sub_val;
                } else if input1 >= num_garbler_inputs {
                    newinput1 = evaluator_input_ids[input1 - num_garbler_inputs];
                } else {
                    newinput1 = garbler_input_ids[input1];
                }
                self.circ.push_gate(BinaryGate::And {
                    xid: newinput0,
                    yid: newinput1,
                    id,
                    out: output + latest_ref - sub_val,
                });
                self.circ.increment_nonfree_gates();
                id += 1;
            } else if gate == "XOR" {
                let newinput0: usize;
                if input0 >= sub_val {
                    newinput0 = input0 + latest_ref - sub_val;
                } else if input0 >= num_garbler_inputs {
                    newinput0 = evaluator_input_ids[input0 - num_garbler_inputs];
                } else {
                    newinput0 = garbler_input_ids[input0];
                }

                let newinput1: usize;
                if input1 >= sub_val {
                    newinput1 = input1 + latest_ref - sub_val;
                } else if input1 >= num_garbler_inputs {
                    newinput1 = evaluator_input_ids[input1 - num_garbler_inputs];
                } else {
                    newinput1 = garbler_input_ids[input1];
                }
                self.circ.push_gate(BinaryGate::Xor {
                    xid: newinput0,
                    yid: newinput1,
                    out: output + latest_ref - sub_val,
                });
            } else if gate == "INV" {
                let newinput0: usize;
                if input0 >= sub_val {
                    newinput0 = input0 + latest_ref - sub_val;
                } else if input0 >= num_garbler_inputs {
                    newinput0 = evaluator_input_ids[input0 - num_garbler_inputs];
                } else {
                    newinput0 = garbler_input_ids[input0];
                }

                self.circ.push_gate(BinaryGate::Inv {
                    xid: newinput0,
                    out: output + latest_ref - sub_val,
                });
            } else {
                return Err(FileParsingError::FileFormatError(i));
            }
        }

        let mut output_wire_ids = vec![];

        for i in 0..num_outputs {
            output_wire_ids.push(num_wires - num_outputs + latest_ref - sub_val + i);
        }

        self.next_ref_id = num_wires + latest_ref - sub_val;

        Ok(output_wire_ids)
    }

    pub fn add_circuit(
        &mut self,
        other_circuit: &BinaryCircuit,
        input_ids: &[Vec<usize>],
    ) -> Vec<usize> {
        assert_eq!(input_ids.len(), other_circuit.num_inputs());
        (0..input_ids.len())
            .for_each(|i| assert_eq!(input_ids[i].len(), other_circuit.input_gate_ids[i].len()));

        let mut old_to_new_map = HashMap::new();

        for gate in &other_circuit.gates {
            match gate {
                BinaryGate::Xor { xid, yid, out } => {
                    let newx = old_to_new_map.get(xid).unwrap();
                    let newy = old_to_new_map.get(yid).unwrap();
                    let newz = self.xor(*newx, *newy);
                    old_to_new_map.insert(*out, newz);
                }
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => {
                    let newx = old_to_new_map.get(xid).unwrap();
                    let newy = old_to_new_map.get(yid).unwrap();
                    let newz = self.and(*newx, *newy);
                    old_to_new_map.insert(*out, newz);
                }
                BinaryGate::Inv { xid, out } => {
                    let newx = old_to_new_map.get(xid).unwrap();
                    let newz = self.negate(*newx);
                    old_to_new_map.insert(*out, newz);
                }
                BinaryGate::Input { no, id, wire } => {
                    old_to_new_map.insert(*wire, input_ids[*no][*id]);
                }
                BinaryGate::Constant { val, wire } => {
                    old_to_new_map.insert(*wire, self.constant(*val));
                }
            }
        }

        let mut outputs = Vec::new();
        for out in &other_circuit.output_gate_ids {
            outputs.push(*old_to_new_map.get(out).unwrap());
        }

        outputs
    }
}

/// Implements the `Default` trait for `CircuitBuilder<BinaryCircuit>`.
impl Default for CircuitBuilder<BinaryCircuit> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        customcircuits::comparison::build_comparison_circuit,
    };

    #[test]
    fn test_circuit_builder() {
        let circuit = build_comparison_circuit();

        let mut reqconst = HashMap::new();
        reqconst.insert(1, 6);

        let mut constmap = HashMap::new();
        constmap.insert(1, 6);

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
                BinaryGate::Xor {
                    xid: 2,
                    yid: 0,
                    out: 4,
                },
                BinaryGate::Xor {
                    xid: 3,
                    yid: 1,
                    out: 5,
                },
                BinaryGate::Constant { val: 1, wire: 6 },
                BinaryGate::And {
                    xid: 4,
                    yid: 5,
                    id: 0,
                    out: 7,
                },
                BinaryGate::Xor {
                    xid: 4,
                    yid: 5,
                    out: 8,
                },
                BinaryGate::Xor {
                    xid: 7,
                    yid: 8,
                    out: 9,
                },
                BinaryGate::Xor {
                    xid: 9,
                    yid: 6,
                    out: 10,
                },
            ],
            num_inputs: 2,
            input_gate_ids: vec![vec![0, 1], vec![0, 1]],
            output_gate_ids: vec![10],
            constant_map: constmap,
            num_nonfree_gates: 1,
            num_wires: 11,
        };

        assert_eq!(required_circuit, circuit);
    }
}
