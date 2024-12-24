use std::{collections::HashMap, fmt::Error};

use crate::{
    circuitop::circuit::BinaryCircuit, config::constants::Block,
    garbling2pc::garbler_operations::GarbleOutput,
};

pub trait ThreePartyBinaryCircuit {
    fn parse_threeparty(file_name: &str) -> Self;
}

pub trait ThreePartyBinaryCircuitBuilder {
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize;
    fn evaluator_input_threeparty(&mut self) -> usize;
    fn evaluator_inputs_threeparty(&mut self, number_of_inputs: u16) -> Vec<usize>;
}

pub trait ThreePartyBinaryPlaintext {
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: [&[bool]; 2],
    ) -> Vec<bool>;
}

pub trait ThreePartyBinaryGarbler {
    fn garble_threeparty(&mut self, circ: BinaryCircuit) -> Result<GarbleOutput, Error>;
}

pub trait ThreePartyBinaryEvaluator {
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: [&[bool]; 2],
    ) -> Result<HashMap<usize, Block>, Error>;
    fn garbled_evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbled_garbler_inputs: HashMap<usize, Block>,
        garbled_evaluator_inputs: [HashMap<usize, Block>; 2],
    ) -> Result<HashMap<usize, Block>, Error>;
}
