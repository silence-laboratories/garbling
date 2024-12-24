use std::fmt::Error;

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    garbling2pc::{
        exec::{BinaryOperations, ExecutionPrimitives},
        plaintext_operations::BinaryPlaintext,
    },
};

use super::threepartytraits::ThreePartyBinaryPlaintext;

impl ThreePartyBinaryPlaintext for BinaryPlaintext {
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: [&[bool]; 2],
    ) -> Vec<bool> {
        if garbler_inputs.len() != circ.num_garbler_inputs() {
            println!("Number of Garbler inputs are inconsistent!!!");
            return Vec::new();
        }

        if evaluator_inputs[0].len() + evaluator_inputs[1].len() != circ.num_evaluator_inputs() {
            println!("Number of Evlauator inputs are inconsistent!!!");
            return Vec::new();
        }

        let mut cache: Vec<Option<bool>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(
                        id < garbler_inputs.len(),
                        "id={} gb_inps.len()={}",
                        id,
                        garbler_inputs.len()
                    );
                    (
                        None,
                        self.process_garbler_input(id, garbler_inputs[id]).unwrap(),
                    )
                }
                BinaryGate::EvaluatorInput { id } => {
                    assert!(
                        id / 2 < evaluator_inputs[0].len() && id / 2 < evaluator_inputs[1].len(),
                        "id={} ev_inps.len()={}",
                        id,
                        evaluator_inputs.len()
                    );
                    if id % 2 == 0 {
                        (
                            None,
                            self.process_evaluator_input(id, evaluator_inputs[0][id / 2])
                                .unwrap(),
                        )
                    } else {
                        (
                            None,
                            self.process_evaluator_input(id, evaluator_inputs[1][id / 2])
                                .unwrap(),
                        )
                    }
                }
                BinaryGate::Constant { val } => (None, self.constant(val).unwrap()),
                BinaryGate::Inv { xid, out } => (
                    out,
                    self.negate(cache[xid].as_ref().ok_or(Error).unwrap())
                        .unwrap(),
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid].as_ref().ok_or(Error).unwrap(),
                        cache[yid].as_ref().ok_or(Error).unwrap(),
                    )
                    .unwrap(),
                ),
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => (
                    out,
                    self.and(
                        cache[xid].as_ref().ok_or(Error).unwrap(),
                        cache[yid].as_ref().ok_or(Error).unwrap(),
                    )
                    .unwrap(),
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut outputs = Vec::with_capacity(circ.output_gate_ids.len());
        for r in circ.get_output_gate_ids().iter() {
            let r = cache[*r].as_ref().ok_or(Error).unwrap();
            let out = self.output(r).unwrap();
            outputs.push(out.unwrap())
        }
        outputs
    }
}
