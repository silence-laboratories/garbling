use std::collections::HashMap;

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::{
        constants::Block,
        errors::{
            BinaryPlaintextError, FileParsingError, ThreePartyEvaluatorError,
            ThreePartyGarblerError,
        },
    },
    garbling2pc::garbler_operations::GarbleOutput,
};

/// Trait for any `BinaryCircuit` which implements the three-party secure garbled-circuit
/// protocol from <https://eprint.iacr.org/2015/931.pdf>.
pub trait ThreePartyBinaryCircuit {
    fn parse_threeparty(file_name: &str) -> Result<Self, FileParsingError>
    where
        Self: Sized;
}

/// Trait for any `BinaryCircuitBuilder` which implements the three-party secure garbled-circuit
/// protocol from <https://eprint.iacr.org/2015/931.pdf>.
pub trait ThreePartyBinaryCircuitBuilder {
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize;
    fn evaluator_input_threeparty(&mut self) -> usize;
    fn evaluator_inputs_threeparty(&mut self, number_of_inputs: u16) -> Vec<usize>;
}

/// Trait for any `BinaryPlaintext` which simulates the working of garbled circuit methods from 
/// <https://eprint.iacr.org/2015/931.pdf> in plaintext.
pub trait ThreePartyBinaryPlaintext {
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: &[bool],
        evaluator_inputs: [&[bool]; 2],
    ) -> Result<Vec<bool>, BinaryPlaintextError>;
}

/// Trait for any `BinaryGarbler` which implements the three-party secure garbled-circuit
/// protocol from <https://eprint.iacr.org/2015/931.pdf>.
pub trait ThreePartyBinaryGarbler {
    fn garble_threeparty(
        &mut self,
        circ: BinaryCircuit,
    ) -> Result<GarbleOutput, ThreePartyGarblerError>;
}

/// Trait for any `BinaryEvaluator` which implements the three-party secure garbled-circuit
/// protocol from <https://eprint.iacr.org/2015/931.pdf>.
pub trait ThreePartyBinaryEvaluator {
    fn evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbler_inputs: HashMap<usize, Block>,
        evaluator_inputs: [&[bool]; 2],
    ) -> Result<HashMap<usize, Block>, ThreePartyEvaluatorError>;
    
    fn garbled_evaluate_threeparty(
        &mut self,
        circ: BinaryCircuit,
        garbled_garbler_inputs: HashMap<usize, Block>,
        garbled_evaluator_inputs: [HashMap<usize, Block>; 2],
    ) -> Result<HashMap<usize, Block>, ThreePartyEvaluatorError>;
}
