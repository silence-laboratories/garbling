use std::collections::HashMap;

use crate::circuitop::{
    circuit::BinaryCircuit,
    gate::{BinaryGate, ID},
};

/// `CircuitBuilder` is a struct used to construct a `BinaryCircuit`.
/// It maintains internal state during the circuit construction
/// process.  Once the circuit is built and returned, the builder can
/// either be discarded or reused to construct a new circuit on top of
/// the existing one.
#[derive(Default)]
pub struct CircuitBuilder {
    /// Tracks the next available gate ID in the circuit.
    next_ref_id: u32,

    /// A mapping of constant values to their corresponding gate IDs.
    /// This allows reuse of constant gates instead of creating
    /// duplicates.
    const_map: HashMap<u16, u32>,

    /// The binary circuit being constructed.  This is incrementally
    /// updated as new gates and inputs are added.  Once the
    /// construction is complete, the circuit can be extracted from
    /// the builder.
    circ: BinaryCircuit,
}

impl CircuitBuilder {
    /// Creates a new, empty `CircuitBuilder` instance.  Initializes
    /// all tracking counters to zero and sets up an empty circuit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the built `BinaryCircuit`.
    pub fn finish(self) -> BinaryCircuit {
        self.circ
    }

    /// Retrieves the next available input ID for the n-th input.
    fn get_next_nth_input_id(&mut self, n: u32) -> u32 {
        self.circ.get_nth_input_ids(n as _).len() as u32
    }

    /// Retrieves the next available ciphertext ID for non-free gates.
    /// This ID is used to reference ciphertexts in the circuit.
    fn get_next_ciphertext_id(&mut self) -> u32 {
        let current = self.circ.get_num_nonfree_gates();
        self.circ.increment_nonfree_gates();
        current as u32
    }

    /// Retrieves the next available reference ID for a gate and
    /// increments the counter.
    fn get_next_ref_id(&mut self) -> u32 {
        let current = self.next_ref_id;
        self.next_ref_id += 1;
        current
    }

    /// Adds a new input gate to the circuit.
    /// Returns the reference ID of the created input gate.
    pub fn new_input(&mut self) -> u32 {
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
    pub fn new_inputs(&mut self, number_of_inputs: u16) -> Vec<u32> {
        let mut output: Vec<u32> = Vec::new();
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

    /// Adds an XOR gate to the circuit.  Returns the reference ID of
    /// the resulting gate.
    pub fn xor(&mut self, xid: u32, yid: u32) -> u32 {
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

    /// Adds a NOT gate (negation) to the circuit.  Returns the
    /// reference ID of the resulting gate.
    pub fn negate(&mut self, xid: u32) -> u32 {
        let out_id = self.get_next_ref_id();
        let gate = BinaryGate::Inv { xid, out: out_id };
        self.circ.push_gate(gate);
        self.circ.increment_wires();
        out_id
    }

    /// Adds an AND gate to the circuit.  Returns the reference ID of
    /// the resulting gate.
    pub fn and(&mut self, xid: u32, yid: u32) -> u32 {
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

    /// Adds a constant gate to the circuit.  If the constant already
    /// exists in the circuit, returns its reference ID.  Otherwise,
    /// creates a new constant gate, stores it in `const_map`, and
    /// returns its reference ID.
    pub fn constant(&mut self, val: u16) -> u32 {
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
    pub fn output(&mut self, id: u32) {
        self.circ.push_output_gate(id);
    }

    pub fn add_circuit(&mut self, other_circuit: &BinaryCircuit, input_ids: &[&[ID]]) -> Vec<ID> {
        assert_eq!(input_ids.len(), other_circuit.num_inputs() as _);
        (0..input_ids.len())
            .for_each(|i| assert_eq!(input_ids[i].len(), other_circuit.input_gate_ids[i].len()));

        let mut old_to_new_map = vec![0; other_circuit.num_wires as usize];

        for gate in &other_circuit.gates {
            match *gate {
                BinaryGate::Xor { xid, yid, out } => {
                    let newx = old_to_new_map[xid as usize];
                    let newy = old_to_new_map[yid as usize];
                    let newz = self.xor(newx, newy);

                    old_to_new_map[out as usize] = newz;
                }

                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => {
                    let newx = old_to_new_map[xid as usize];
                    let newy = old_to_new_map[yid as usize];
                    let newz = self.and(newx, newy);

                    old_to_new_map[out as usize] = newz;
                }

                BinaryGate::Inv { xid, out } => {
                    let newx = old_to_new_map[xid as usize];
                    let newz = self.negate(newx);

                    old_to_new_map[out as usize] = newz;
                }

                BinaryGate::Input { no, id, wire } => {
                    old_to_new_map[wire as usize] = input_ids[no as usize][id as usize];
                }

                BinaryGate::Constant { val, wire } => {
                    old_to_new_map[wire as usize] = self.constant(val);
                }
            }
        }

        other_circuit
            .output_gate_ids
            .iter()
            .map(|&out| old_to_new_map[out as usize])
            .collect()
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
