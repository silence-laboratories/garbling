use rand::{CryptoRng, RngCore};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::garbling3pc_errors::ThreePartyGarblerError,
    garbling2pc::garbler_operations::{BinaryGarbler, GarbleOutput},
    utilities::hash_function::HashFunction,
};

use super::threepartytraits::ThreePartyBinaryGarbler;

/// Implements the `ThreePartyBinaryGarbler` trait for `BinaryGarbler`.
impl<H: HashFunction, R: RngCore + CryptoRng> ThreePartyBinaryGarbler
    for BinaryGarbler<'_, H, R>
{
    /// Garbles a binary circuit using the half-gate technique.
    ///
    /// This function takes a `BinaryCircuit` and generates its garbled version,
    /// which includes encrypted truth tables, encoded wire labels, and output
    /// decoding information.
    ///
    /// # Parameters
    ///
    /// * `circ` - The `BinaryCircuit` to be garbled.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    /// * A `GarbleOutput` which contains:
    ///     - `garbler_input_encodings`: A Hashmap of garbler
    ///         input wire IDs to their wire labels.
    ///     - `evaluator_input_encodings`: A Hashmap of evaluator
    ///         input wire IDs to their wire labels.
    ///     - `garbled_circuit`: The list of `Block` values representing a garbled truth tables.
    ///     - `decoding_infos`: A Hashmap of output wire IDs to their decoding informations.
    ///
    /// * `Err(ThreePartyGarblerError)` - An error if the evaluation fails.
    fn garble_threeparty(
        &mut self,
        circ: BinaryCircuit,
    ) -> Result<GarbleOutput, ThreePartyGarblerError> {
        let out = self.garble(circ)?;
        Ok(out)
    }
}
