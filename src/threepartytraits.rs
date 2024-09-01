use std::{collections::HashMap, fmt::Error};

use crate::{circuit::BinaryCircuit, config::constants::BLOCK};

pub trait ThreePartyBinaryCircuit {
    fn parse_threeparty(file_name: &str)-> Self;
}


pub trait ThreePartyBinaryCircuitBuilder {
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize;
    fn evaluator_input_threeparty(&mut self) -> usize;
    fn evaluator_inputs_threeparty(&mut self, number_of_inputs: u16) -> Vec<usize>;    
}

pub trait ThreePartyBinaryPlaintext {
    fn evaluate_threeparty(&mut self, circ: BinaryCircuit, garbler_inputs: &[bool], evaluator_inputs: [&[bool]; 2]) -> Vec<bool>;
}

pub trait ThreePartyBinaryGarbler {
    fn garble_threeparty(&mut self, circ: BinaryCircuit) -> 
    Result<(
    HashMap<usize, BLOCK>, 
    HashMap<usize, BLOCK>, 
    Vec<BLOCK>, HashMap<usize, u8>), 
    Error>;
}

pub trait ThreePartyBinaryEvaluator {
    fn evaluate_threeparty(&mut self, circ: BinaryCircuit, garbler_inputs: &[bool], evaluator_inputs: [&[bool]; 2]) -> 
    Result<HashMap<usize, BLOCK>, Error>;
}