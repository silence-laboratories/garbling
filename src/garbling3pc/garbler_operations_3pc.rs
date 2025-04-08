use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::{constants::Block, garbling3pc_errors::ThreePartyGarblerError},
    garbling2pc::garbler_operations::{BinaryGarbler, GarbleOutput},
    utilities::{hash_function::HashFunction, utils::xor_blocks},
};

use super::threepartytraits::ThreePartyBinaryGarbler;

/// Implements the `ThreePartyBinaryGarbler` trait for `BinaryGarbler`.
impl<H: HashFunction, R: RngCore + CryptoRng> ThreePartyBinaryGarbler for BinaryGarbler<'_, H, R> {
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
        let out = self.garble(&circ)?;
        Ok(out)
    }

    /// Returns the garbled version of the inputs for the three party garbling protocol.
    ///
    /// # Arguments
    ///
    /// * `input_ids` - A slice of `usize` containing the ids of the input wires.
    /// * `inputs` - A slice of two slices of `bool` containing the input values in
    ///   the order of the input ids for the three party garbling protocol.
    /// * `input_encodings` - A `HashMap<usize, Block>` which maps the input ids
    ///   to the correspoding encodings of `false` values, as per the Free-XOR technique.
    ///
    /// # Returns
    ///
    /// A `HashMap<usize, Block>` which maps the input ids
    /// to the correspoding encoded inputs.
    fn get_garbled_inputs_threeparty(
        &self,
        input_ids: &[usize],
        inputs: &[&[bool]; 2],
        input_encodings: HashMap<usize, Block>,
    ) -> HashMap<usize, [u8; 16]> {
        let mut garbled_input_encodings = HashMap::new();
        for (count, ids) in input_ids.iter().enumerate() {
            let mut enc = input_encodings.get(ids).unwrap().to_owned();
            let input = if ids % 2 == 0 {
                inputs[0][count / 2]
            } else {
                inputs[1][count / 2]
            };
            if input {
                enc = xor_blocks(enc, self.delta);
            }
            garbled_input_encodings.insert(*ids, enc);
        }
        garbled_input_encodings
    }
}
