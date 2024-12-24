use std::fmt::Error;

use crate::{
    circuitop::circuit::BinaryCircuit,
    garbling2pc::garbler_operations::{BinaryGarbler, GarbleOutput},
    utilities::hash_function::HashFunction,
};

use super::threepartytraits::ThreePartyBinaryGarbler;

impl<H: HashFunction> ThreePartyBinaryGarbler for BinaryGarbler<H> {
    fn garble_threeparty(&mut self, circ: BinaryCircuit) -> Result<GarbleOutput, Error> {
        self.garble(circ)
    }
}
