use crate::circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder};

use super::threepartytraits::ThreePartyBinaryCircuitBuilder;

/// Implements the `ThreePartyBinaryCircuitBuilder` trait for `CircuitBuilder<BinaryCircuit>`.
impl ThreePartyBinaryCircuitBuilder for CircuitBuilder<BinaryCircuit> {
    /// Retrieves the next available input ID for the evaluator
    /// and increments the counter by 2.
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 2;
        current
    }

    /// Adds two new evaluator input gates and an xor gate between
    /// them to the circuit. Returns the reference ID of the created xor gate.
    fn evaluator_input_threeparty(&mut self) -> usize {
        let r = self.evaluator_input();
        let s = self.evaluator_input();
        self.xor(r, s)
    }

    /// Calls `evaluator_input_threeparty` `number_of_inputs` times.
    fn evaluator_inputs_threeparty(&mut self, number_of_inputs: u16) -> Vec<usize> {
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.evaluator_input_threeparty());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, vec};

    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        old::garbling3pc::comparison_circ_3pc::build_comparison_circuit_threeparty,
    };

    #[test]
    fn test_circuit_builder_3pc() {
        let circuit = build_comparison_circuit_threeparty();

        let mut reqconst = HashMap::new();
        reqconst.insert(1, 10);

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::EvaluatorInput { id: 0, wire: 0 },
                BinaryGate::EvaluatorInput { id: 1, wire: 1 },
                BinaryGate::Xor {
                    xid: 0,
                    yid: 1,
                    out: 2,
                },
                BinaryGate::GarblerInput { id: 0, wire: 3 },
                BinaryGate::EvaluatorInput { id: 2, wire: 4 },
                BinaryGate::EvaluatorInput { id: 3, wire: 5 },
                BinaryGate::Xor {
                    xid: 4,
                    yid: 5,
                    out: 6,
                },
                BinaryGate::GarblerInput { id: 1, wire: 7 },
                BinaryGate::Xor {
                    xid: 2,
                    yid: 3,
                    out: 8,
                },
                BinaryGate::Xor {
                    xid: 6,
                    yid: 7,
                    out: 9,
                },
                BinaryGate::Constant { val: 1, wire: 10 },
                BinaryGate::And {
                    xid: 8,
                    yid: 9,
                    id: 0,
                    out: 11,
                },
                BinaryGate::Xor {
                    xid: 8,
                    yid: 9,
                    out: 12,
                },
                BinaryGate::Xor {
                    xid: 11,
                    yid: 12,
                    out: 13,
                },
                BinaryGate::Xor {
                    xid: 13,
                    yid: 10,
                    out: 14,
                },
            ],
            garbler_input_ids: vec![0, 1],
            evaluator_input_ids: vec![0, 1, 2, 3],
            output_gate_ids: vec![14],
            constant_map: reqconst,
            num_nonfree_gates: 1,
            num_wires: 0,
        };

        assert_eq!(required_circuit, circuit);
    }
}
