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
