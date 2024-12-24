use std::{collections::HashMap, fmt::Error};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::constants::Block,
    garbling2pc::{
        evaluator_operations::BinaryEvaluator,
        exec::{BinaryOperations, ExecutionPrimitives},
    },
    utilities::hash_function::HashFunction,
};

use super::threepartytraits::ThreePartyBinaryEvaluator;

impl<H: HashFunction> ThreePartyBinaryEvaluator for BinaryEvaluator<H> {
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: [&[bool]; 2],
    ) -> Result<HashMap<usize, Block>, Error> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.gates.len()];
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(
                        id < garbler_inputs.len(),
                        "id={} gb_inps.len()={}",
                        id,
                        garbler_inputs.len()
                    );
                    let input_hash = self.process_garbler_input(id, garbler_inputs[id])?;
                    (None, input_hash)
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
                BinaryGate::Constant { val } => (None, self.constant(val)?),
                BinaryGate::Inv { xid, out } => {
                    (out, self.negate(cache[xid].as_ref().ok_or(Error)?)?)
                }
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid].as_ref().ok_or(Error)?,
                        cache[yid].as_ref().ok_or(Error)?,
                    )?,
                ),
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => (
                    out,
                    self.and(
                        cache[xid].as_ref().ok_or(Error)?,
                        cache[yid].as_ref().ok_or(Error)?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut garbled_output: HashMap<usize, Block> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or(Error)?;
            let dec = self.output(x)?.unwrap();
            garbled_output.insert(*r, dec);
        }
        Ok(garbled_output)
    }

    fn garbled_evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbled_garbler_inputs: HashMap<usize, Block>,
        garbled_evaluator_inputs: [HashMap<usize, Block>; 2],
    ) -> Result<HashMap<usize, Block>, Error> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.gates.len()];
        // let eval_len = circ.num_evaluator_inputs() / 2;
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    // assert!(
                    //     id < garbler_inputs.len(),
                    //     "id={} gb_inps.len()={}",
                    //     id,
                    //     garbler_inputs.len()
                    // );
                    let input_hash = *garbled_garbler_inputs.get(&id).unwrap();
                    (None, input_hash)
                }
                BinaryGate::EvaluatorInput { id } => {
                    // assert!(
                    //     id/2 < evaluator_inputs[0].len() && id/2 < evaluator_inputs[1].len(),
                    //     "id={} ev_inps.len()={}",
                    //     id,
                    //     evaluator_inputs.len()
                    // );
                    if id % 2 == 0 {
                        (None, *garbled_evaluator_inputs[0].get(&(id / 2)).unwrap())
                    } else {
                        (None, *garbled_evaluator_inputs[1].get(&(id / 2)).unwrap())
                    }
                }
                BinaryGate::Constant { val } => (None, self.constant(val)?),
                BinaryGate::Inv { xid, out } => {
                    (out, self.negate(cache[xid].as_ref().ok_or(Error)?)?)
                }
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid].as_ref().ok_or(Error)?,
                        cache[yid].as_ref().ok_or(Error)?,
                    )?,
                ),
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => (
                    out,
                    self.and(
                        cache[xid].as_ref().ok_or(Error)?,
                        cache[yid].as_ref().ok_or(Error)?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value);
        }
        let mut garbled_output: HashMap<usize, Block> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or(Error)?;
            let dec = self.output(x)?.unwrap();
            garbled_output.insert(*r, dec);
        }
        Ok(garbled_output)
    }
}
