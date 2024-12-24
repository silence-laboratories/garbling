use crate::circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder, gate::BinaryGate};

use super::threepartytraits::ThreePartyBinaryCircuitBuilder;

impl ThreePartyBinaryCircuitBuilder for CircuitBuilder<BinaryCircuit> {
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 2;
        current
    }

    fn evaluator_input_threeparty(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id_threeparty();
        let r = self.gate(BinaryGate::EvaluatorInput { id });
        let s = self.gate(BinaryGate::EvaluatorInput { id: id + 1 });
        self.circ.push_evaluator_input(r);
        self.circ.push_evaluator_input(s);
        self.xor(r, s)
    }

    fn evaluator_inputs_threeparty(&mut self, number_of_inputs: u16) -> Vec<usize> {
        // 0..number_of_inputs.iter().map(|q| self.evaluator_input()).collect()
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.evaluator_input());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        garbling3pc::threepartytraits::ThreePartyBinaryCircuitBuilder,
    };

    use super::CircuitBuilder;

    #[test]
    fn test_circuit_builder_3pc() {
        let circuit = build_comparison_circuit_threeparty();

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::EvaluatorInput { id: 0 },
                BinaryGate::EvaluatorInput { id: 1 },
                BinaryGate::Xor {
                    xid: 0,
                    yid: 1,
                    out: None,
                },
                BinaryGate::GarblerInput { id: 0 },
                BinaryGate::EvaluatorInput { id: 2 },
                BinaryGate::EvaluatorInput { id: 3 },
                BinaryGate::Xor {
                    xid: 4,
                    yid: 5,
                    out: None,
                },
                BinaryGate::GarblerInput { id: 1 },
                BinaryGate::Xor {
                    xid: 2,
                    yid: 3,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 6,
                    yid: 7,
                    out: None,
                },
                BinaryGate::Constant { val: 1 },
                BinaryGate::And {
                    xid: 8,
                    yid: 9,
                    id: 0,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 8,
                    yid: 9,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 11,
                    yid: 12,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 13,
                    yid: 10,
                    out: None,
                },
            ],
            garbler_input_ids: vec![3, 7],
            evaluator_input_ids: vec![0, 1, 4, 5],
            output_gate_ids: vec![14],
            constant_gate_ids: vec![10],
            num_nonfree_gates: 1,
            num_wires: 0,
        };

        assert_eq!(required_circuit, circuit);
    }

    pub fn build_comparison_circuit_threeparty() -> BinaryCircuit {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();
        let garb_input_1 = builder.garbler_input();
        let eval_input_2 = builder.evaluator_input_threeparty();
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

        builder.finish()
    }
}
