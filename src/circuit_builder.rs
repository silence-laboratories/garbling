use std::collections::HashMap;

use crate::{circuit::BinaryCircuit, threepartytraits::ThreePartyBinaryCircuitBuilder};
use crate::gate::BinaryGate;


#[derive(Clone)]
pub struct CircuitBuilder<BinaryCircuit> {
    next_ref_id: usize,
    next_garbler_input_id: usize,
    next_evaluator_input_id: usize,
    const_map: HashMap<u16, usize>,
    circ: BinaryCircuit
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

    fn gate(&mut self, gate: BinaryGate) -> usize {
        self.circ.push_gate(gate);
        self.get_next_ref_id()
    }

    pub fn garbler_input(&mut self) -> usize {
        let id = self.get_next_garbler_input_id();
        let r = self.gate(BinaryGate::GarblerInput { id: id });
        self.circ.push_garbler_input(r);
        r
    }

    pub fn evaluator_input(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id();
        let r = self.gate(BinaryGate::EvaluatorInput { id: id });
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
        let gate = BinaryGate::Xor { xid: xid, yid: yid, out: None };
        self.gate(gate)
    }

    pub fn negate(&mut self, xid: usize) -> usize {
        let gate = BinaryGate::Inv {
            xid: xid,
            out: None,
        };
        self.gate(gate)
    }

    pub fn and(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::And {
            xid: xid,
            yid: yid,
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

impl ThreePartyBinaryCircuitBuilder for CircuitBuilder<BinaryCircuit> {
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 2;
        current
    }

    fn evaluator_input_threeparty(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id_threeparty();
        let r = self.gate(BinaryGate::EvaluatorInput { id: id });
        let s = self.gate(BinaryGate::EvaluatorInput { id: id + 1 });
        self.circ.push_evaluator_input(r);
        self.circ.push_evaluator_input(s);
        let z = self.xor(r, s);
        z
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
