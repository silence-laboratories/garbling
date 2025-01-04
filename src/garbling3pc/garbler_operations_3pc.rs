use rand::{CryptoRng, RngCore};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::errors::ThreePartyGarblerError,
    garbling2pc::garbler_operations::{BinaryGarbler, GarbleOutput},
    utilities::hash_function::HashFunction,
};

use super::threepartytraits::ThreePartyBinaryGarbler;

impl<'a, H: HashFunction, R: RngCore + CryptoRng> ThreePartyBinaryGarbler
    for BinaryGarbler<'a, H, R>
{
    fn garble_threeparty(
        &mut self,
        circ: BinaryCircuit,
    ) -> Result<GarbleOutput, ThreePartyGarblerError> {
        let out = self.garble(circ)?;
        Ok(out)
    }
}
