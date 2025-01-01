use std::collections::HashMap;

use crate::circuitop::{circuit::BinaryCircuit, gate::BinaryGate};

#[derive(Clone)]
pub struct CircuitBuilder<BinaryCircuit> {
    pub next_ref_id: usize,
    pub next_garbler_input_id: usize,
    pub next_evaluator_input_id: usize,
    pub const_map: HashMap<u16, usize>,
    pub circ: BinaryCircuit,
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

    pub fn gate(&mut self, gate: BinaryGate) -> usize {
        self.circ.push_gate(gate);
        self.get_next_ref_id()
    }

    pub fn garbler_input(&mut self) -> usize {
        let id = self.get_next_garbler_input_id();
        let r = self.gate(BinaryGate::GarblerInput { id });
        self.circ.push_garbler_input(r);
        r
    }

    pub fn evaluator_input(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id();
        let r = self.gate(BinaryGate::EvaluatorInput { id });
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
        let gate = BinaryGate::Xor {
            xid,
            yid,
            out: None,
        };
        self.gate(gate)
    }

    pub fn negate(&mut self, xid: usize) -> usize {
        let gate = BinaryGate::Inv { xid, out: None };
        self.gate(gate)
    }

    pub fn and(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::And {
            xid,
            yid,
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
            garbler_input_ids: [1, 3].to_vec(),
            evaluator_input_ids: vec![0, 2],
            output_gate_ids: vec![10],
            constant_gate_ids: vec![6],
            num_nonfree_gates: 1,
            num_wires: 0,
        };

        assert_eq!(required_circuit, circuit);
    }
}
