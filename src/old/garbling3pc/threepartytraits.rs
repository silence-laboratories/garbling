use std::collections::HashMap;

use crate::{
    circuitop::circuit::BinaryCircuit, config::errors::FileParsingError,
    old::garbling2pc::garbler_operations::GarbleOutput, utilities::types::Block,
};

use super::garbling3pc_errors::{
    BinaryPlaintextError, ThreePartyEvaluatorError, ThreePartyGarblerError,
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

    fn get_garbled_inputs_threeparty(
        &self,
        input_ids: &[usize],
        inputs: &[&[bool]; 2],
        input_encodings: &HashMap<usize, Block>,
    ) -> HashMap<usize, Block>;
}

/// Trait for any `BinaryEvaluator` which implements the three-party secure garbled-circuit
/// protocol from <https://eprint.iacr.org/2015/931.pdf>.
pub trait ThreePartyBinaryEvaluator {
    fn evaluate_threeparty(
        &mut self,
        circ: &BinaryCircuit,
        garbler_inputs: &HashMap<usize, Block>,
        evaluator_inputs: &HashMap<usize, Block>,
    ) -> Result<HashMap<usize, Block>, ThreePartyEvaluatorError>;
}
