use std::collections::HashMap;

use crate::circuitop::{circuit::BinaryCircuit, gate::BinaryGate};

/// `CircuitBuilder` is a struct used to construct a `BinaryCircuit`.
/// It maintains internal state during the circuit construction process.
/// Once the circuit is built and returned, the builder can either be discarded
/// or reused to construct a new circuit on top of the existing one.
#[derive(Clone)]
pub struct CircuitBuilder<BinaryCircuit> {
    /// Tracks the next available gate ID in the circuit.
    pub next_ref_id: usize,

    /// Tracks the next available input ID for the garbler.
    pub next_garbler_input_id: usize,

    /// Tracks the next available input ID for the evaluator.
    pub next_evaluator_input_id: usize,

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
            next_garbler_input_id: 0,
            next_evaluator_input_id: 0,
            const_map: HashMap::new(),
            circ: BinaryCircuit::new(0),
        }
    }

    /// Returns the built `BinaryCircuit`.
    pub fn finish(self) -> BinaryCircuit {
        self.circ
    }

    /// Retrieves the next available input ID for the garbler and increments the counter.
    fn get_next_garbler_input_id(&mut self) -> usize {
        let current = self.next_garbler_input_id;
        self.next_garbler_input_id += 1;
        current
    }

    /// Retrieves the next available input ID for the evaluator and increments the counter.
    fn get_next_evaluator_input_id(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 1;
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

    /// Adds a binary gate to the circuit and returns its reference ID.
    pub fn gate(&mut self, gate: BinaryGate) -> usize {
        self.circ.push_gate(gate);
        self.get_next_ref_id()
    }

    /// Adds a new garbler input gate to the circuit.
    /// Returns the reference ID of the created input gate.
    pub fn garbler_input(&mut self) -> usize {
        let id = self.get_next_garbler_input_id();
        let r = self.gate(BinaryGate::GarblerInput { id });
        self.circ.push_garbler_input(id);
        r
    }

    /// Adds a new evaluator input gate to the circuit.
    /// Returns the reference ID of the created input gate.
    pub fn evaluator_input(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id();
        let r = self.gate(BinaryGate::EvaluatorInput { id });
        self.circ.push_evaluator_input(id);
        r
    }

    /// Adds multiple garbler input gates to the circuit.
    /// Returns a vector of reference IDs corresponding to the created inputs.
    pub fn garbler_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.garbler_input());
        }
        output
    }

    /// Adds multiple evaluator input gates to the circuit.
    /// Returns a vector of reference IDs corresponding to the created inputs.
    pub fn evaluator_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        // 0..number_of_inputs.iter().map(|q| self.evaluator_input()).collect()
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.evaluator_input());
        }
        output
    }

    /// Adds an XOR gate to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn xor(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::Xor {
            xid,
            yid,
            out: None,
        };
        self.gate(gate)
    }

    /// Adds a NOT gate (negation) to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn negate(&mut self, xid: usize) -> usize {
        let gate = BinaryGate::Inv { xid, out: None };
        self.gate(gate)
    }

    /// Adds an AND gate to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn and(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::And {
            xid,
            yid,
            id: self.get_next_ciphertext_id(),
            out: None,
        };

        self.gate(gate)
    }

    /// Adds a constant gate to the circuit.
    /// If the constant already exists in the circuit, returns its reference ID.
    /// Otherwise, creates a new constant gate, stores it in `const_map`, and returns its reference ID.
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

    /// Marks a gate as an output in the circuit.
    pub fn output(&mut self, id: usize) {
        self.circ.push_output_gate(id);
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
    use std::vec;

    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        customcircuits::comparison::build_comparison_circuit,
    };

    #[test]
    fn test_circuit_builder() {
        let circuit = build_comparison_circuit();

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::EvaluatorInput { id: 0 },
                BinaryGate::GarblerInput { id: 0 },
                BinaryGate::EvaluatorInput { id: 1 },
                BinaryGate::GarblerInput { id: 1 },
                BinaryGate::Xor {
                    xid: 0,
                    yid: 1,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 2,
                    yid: 3,
                    out: None,
                },
                BinaryGate::Constant { val: 1 },
                BinaryGate::And {
                    xid: 4,
                    yid: 5,
                    id: 0,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 4,
                    yid: 5,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 7,
                    yid: 8,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 9,
                    yid: 6,
                    out: None,
                },
            ],
            garbler_input_ids: [0, 1].to_vec(),
            evaluator_input_ids: vec![0, 1],
            output_gate_ids: vec![10],
            constant_gate_ids: vec![6],
            num_nonfree_gates: 1,
            num_wires: 0,
        };

        assert_eq!(required_circuit, circuit);
    }
}
