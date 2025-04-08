use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::{
        constants::Block,
        garbling2pc_errors::{BinaryOperationsError, ExecutionPrimitiveError, GarblerError},
    },
    garbling2pc::exec::{BinaryOperations, ExecutionPrimitives},
    utilities::{hash_function::HashFunction, utils::xor_blocks},
};

/// Represents the garbler's state in a binary garbled circuit protocol.
///
/// This struct implements the garbler's side of the protocol described in
/// Figure 2 of <https://eprint.iacr.org/2014/756.pdf>.
///
/// # Type Parameters
/// * `H` - A cryptographic hash function that implements the `HashFunction` trait.
/// * `R` - A random number generator that implements `RngCore` and `CryptoRng`.
pub struct BinaryGarbler<'a, H: HashFunction, R: RngCore + CryptoRng> {
    /// The global difference value (Delta) used for garbling using Free XOR technique.
    pub delta: Block,

    /// The cryptographic hash function used for hashing gate labels.
    pub hash: H,

    /// A reference to a random number generator providing cryptographic randomness.
    pub rng: &'a mut R,

    /// A cache storing computed values while garbling.
    pub cache: Vec<Block>,

    /// A counter for uniquely indexing gates in the garbled circuit.
    pub gateindex: u128,

    /// A counter for uniquely indexing output gates.
    pub outputindex: u128,
}

/// Represents the values computed during the garbling of an AND gate
/// using the half-gate technique.
///
/// # Type Parameters
///
/// * `'a` - Lifetime tied to the `BinaryGarbler`.
/// * `H` - A hash function used in the garbling process.
/// * `R` - A cryptographically secure random number generator.
pub struct GarbleAndGateOp<'a, H: HashFunction, R: RngCore + CryptoRng> {
    /// The value to be pushed to the cache for the generator's half-gate computation.
    pub t_gen: <BinaryGarbler<'a, H, R> as ExecutionPrimitives>::Item,

    /// The value to be pushed to the cache for the evaluator's half-gate computation.
    pub t_eval: <BinaryGarbler<'a, H, R> as ExecutionPrimitives>::Item,

    /// The processed output of the AND gate.
    pub out: <BinaryGarbler<'a, H, R> as ExecutionPrimitives>::Item,
}

/// The output of the `garble` function, containing all necessary values
/// for the evaluator to execute the garbled circuit.
///
/// This struct stores the encoded wire labels, the garbled circuit itself, and
/// decoding information required for the final output.
pub struct GarbleOutput {
    /// A mapping from the garbler's input wire IDs to their
    /// corresponding garbled wire labels
    pub garbler_input_encodings: HashMap<usize, Block>,

    /// A mapping from the evaluator's input wire IDs to their
    /// corresponding garbled wire labels
    pub evaluator_input_encodings: HashMap<usize, Block>,

    /// The list of encrypted values representing the garbled circuit's
    /// garbled truth tables.
    pub garbled_circuit: Vec<Block>,

    /// A mapping from output wire IDs to decoding information used
    /// to obtain the plaintext result from the garbled output.
    pub decoding_infos: HashMap<usize, u8>,
}

/// Implementation of the `BinaryGarbler` struct.
/// This provides methods for garbling binary circuits and providing input hashes.
impl<'a, H: HashFunction, R: RngCore + CryptoRng> BinaryGarbler<'a, H, R> {
    /// Creates a new `BinaryGarbler` instance.
    ///
    /// This function initializes the garbler with a cryptographic hash function,
    /// a random number generator, and generates a random delta value for garbling.
    ///
    /// # Arguments
    ///
    /// * `hash` - A cryptographic hash function used for wire label generation.
    /// * `rng` - A mutable reference to a random number generator that implements `RngCore` and `CryptoRng`.
    ///
    /// # Returns
    ///
    /// A new instance of `BinaryGarbler` with initialized values.
    pub fn new(hash: H, rng: &'a mut R) -> BinaryGarbler<'a, H, R> {
        BinaryGarbler {
            delta: Self::get_random_delta(rng),
            hash,
            rng,
            cache: Vec::new(),
            gateindex: 0,
            outputindex: 0,
        }
    }

    /// Extracts the least significant bit (LSB) of a given `Block`.
    ///
    /// This function retrieves the LSB from the first byte of the block.
    ///
    /// # Arguments
    ///
    /// * `value` - A 16-byte block representing a wire label.
    ///
    /// # Returns
    ///
    /// The least significant bit (0 or 1) of the first byte.
    fn lsb(value: Block) -> u8 {
        value[0] & 1
    }

    /// Generates a random Delta value used for garbling.
    ///
    /// This function creates a random 16-byte block and ensures that the
    /// least significant bit is set to 1 as required by the Free XOR technique.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A randomly generated `Block` with the least significant bit set.
    fn get_random_delta(rng: &mut R) -> Block {
        let mut temp = [0u8; 16];
        rng.fill_bytes(&mut temp);
        temp[0] |= 1;
        temp
    }

    /// Increments and retrieves the next available gate index.
    ///
    /// # Returns
    ///
    /// The updated gate index.
    fn get_next_gate_index(&mut self) -> u128 {
        self.gateindex += 1;
        self.gateindex
    }

    /// Increments and retrieves the next available output index.
    ///
    /// # Returns
    ///
    /// The updated output index.
    fn get_next_output_index(&mut self) -> u128 {
        self.outputindex += 1;
        self.outputindex
    }

    /// Garbles an AND gate using the half-gate technique.
    ///
    /// This function takes two wire labels as input and produces the necessary values
    /// for garbling the AND gate.
    ///
    /// # Parameters
    ///
    /// * `a` - The wire label corresponding to the first input to the AND gate.
    /// * `b` - The wire label corresponding to the second input to the AND gate.
    ///
    /// # Returns
    ///
    /// A `GarbleAndGateOp` struct containing:
    /// - `t_gen`: The generator’s half-gate value.
    /// - `t_eval`: The evaluator’s half-gate value.
    /// - `out`: The final output of the AND gate.
    fn garble_and_gate(
        &mut self,
        a: <Self as ExecutionPrimitives>::Item,
        b: <Self as ExecutionPrimitives>::Item,
    ) -> GarbleAndGateOp<'a, H, R> {
        let p_a = Self::lsb(a);
        let p_b = Self::lsb(b);

        let j = self.get_next_gate_index().to_le_bytes();
        let j2 = self.get_next_gate_index().to_le_bytes();

        let (t_gen, out_gen) = self.gen_half_gate(p_a, p_b, a, j);
        let (t_eval, out_eval) = self.eval_half_gate(p_b, a, b, j2);
        let out = xor_blocks(out_gen, out_eval);

        GarbleAndGateOp { t_gen, t_eval, out }
    }

    /// Implements the generator half-gate evaluation for the half-gate
    /// technique.
    ///
    /// # Parameters
    ///
    /// * `p_a` - The least significant bit (LSB) of the wire label `a`.
    /// * `p_b` - The least significant bit (LSB) of the wire label `b`.
    /// * `a` - The wire label corresponding to the first input of the AND gate.
    /// * `j` - A random block used as part of the cryptographic computation.
    ///
    /// # Returns
    ///
    /// * The generator’s half-gate value to be stored in cache.
    /// * An intermediate value used to compute AND gate;s output
    fn gen_half_gate(
        &self,
        p_a: u8,
        p_b: u8,
        a: <Self as ExecutionPrimitives>::Item,
        j: Block,
    ) -> (
        <Self as ExecutionPrimitives>::Item,
        <Self as ExecutionPrimitives>::Item,
    ) {
        let temp1 = self.hash.tccr_hash(a, j);
        let adelta = xor_blocks(a, self.delta);
        let temp2 = self.hash.tccr_hash(adelta, j);
        let mut t_gen = xor_blocks(temp1, temp2);
        let mut out_gen = temp1;
        if p_b == 1 {
            t_gen = xor_blocks(t_gen, self.delta);
        }
        if p_a == 1 {
            out_gen = xor_blocks(out_gen, t_gen);
        }
        (t_gen, out_gen)
    }

    /// Implements the evaluator half-gate evaluation for the half-gate
    /// technique.
    ///
    /// # Parameters
    ///
    /// * `p_b` - The least significant bit (LSB) of the wire label `b`.
    /// * `a` - The wire label corresponding to the first input of the AND gate.
    /// * `b` - The wire label corresponding to the second input of the AND gate.
    /// * `j2` - A random block used as part of the cryptographic computation.
    ///
    /// # Returns
    ///
    /// * The evaluator’s half-gate value to be stored in cache.
    /// * An intermediate value used to compute AND gate;s output
    fn eval_half_gate(
        &self,
        p_b: u8,
        a: <Self as ExecutionPrimitives>::Item,
        b: <Self as ExecutionPrimitives>::Item,
        j2: Block,
    ) -> (
        <Self as ExecutionPrimitives>::Item,
        <Self as ExecutionPrimitives>::Item,
    ) {
        let temp1 = self.hash.tccr_hash(b, j2);
        let bdelta = xor_blocks(b, self.delta);
        let temp2 = self.hash.tccr_hash(bdelta, j2);
        let mut t_eval = xor_blocks(temp1, temp2);
        t_eval = xor_blocks(t_eval, a);
        let mut out_eval = temp1;
        if p_b == 1 {
            let temp3 = xor_blocks(t_eval, a);
            out_eval = xor_blocks(out_eval, temp3);
        }
        (t_eval, out_eval)
    }

    /// Returns a random vlaue to be used for evaluating a constant gate.
    ///
    /// # Returns
    ///
    /// A randomly generated `Block` with it's least significant bit (LSB) set to 1.
    fn zero(&mut self) -> Block {
        let mut randval = [0u8; 16];
        self.rng.fill_bytes(&mut randval);
        randval[0] |= 1;
        randval
    }

    /// Returns the least significant bit (LSB) of the input block.
    ///
    /// # Parameters
    ///
    /// * `x` - The input `Block`.
    ///
    /// # Returns
    ///
    /// Least significant bit (LSB) of the input block.
    pub fn get_decoding(&mut self, x: Block) -> u8 {
        Self::lsb(x)
    }

    /// Returns the least significant bit (LSB) of the input block.
    ///
    /// # Returns
    ///
    /// A vector of `Block` values stored in the cache.
    pub fn get_garbled_circuit(&self) -> Vec<Block> {
        self.cache.clone()
    }

    /// Returns the garbled version of the inputs.
    ///
    /// # Arguments
    ///
    /// * `input_ids` - A slice of `usize` containing the ids of the input wires.
    /// * `inputs` - A slice of `bool` containing the input values in
    ///   the order of the input ids.
    /// * `input_encodings` - A `HashMap<usize, Block>` which maps the input ids
    ///   to the correspoding encodings of `false` values, as per the Free-XOR technique.
    ///
    /// # Returns
    ///
    /// A `HashMap<usize, Block>` which maps the input ids
    /// to the correspoding encoded inputs.
    pub fn get_garbled_inputs(
        &self,
        input_ids: &[usize],
        inputs: &[bool],
        input_encodings: HashMap<usize, Block>,
    ) -> HashMap<usize, [u8; 16]> {
        let mut garbled_input_encodings = HashMap::new();
        for (count, ids) in input_ids.iter().enumerate() {
            let mut enc = input_encodings.get(ids).unwrap().to_owned();
            if inputs[count] {
                enc = xor_blocks(enc, self.delta);
            }
            garbled_input_encodings.insert(*ids, enc);
        }
        garbled_input_encodings
    }

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
    /// * `Err(GarblerError)` - An error if the evaluation fails.
    pub fn garble(&mut self, circ: &BinaryCircuit) -> Result<GarbleOutput, GarblerError> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.gates.len()];
        let mut garbler_input_encodings: HashMap<usize, Block> = HashMap::new();
        let mut evaluator_input_encodings: HashMap<usize, Block> = HashMap::new();
        for (i, gate) in circ.gates.iter().enumerate() {
            let (z_ref, value) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    let input_hash = self.process_garbler_input(id, false)?;
                    garbler_input_encodings.insert(id, input_hash);
                    (None, input_hash)
                }
                BinaryGate::EvaluatorInput { id } => {
                    let input_hash = self.process_evaluator_input(id, false)?;
                    evaluator_input_encodings.insert(id, input_hash);
                    (None, input_hash)
                }
                BinaryGate::Constant { val } => (None, self.constant(val)?),
                BinaryGate::Inv { xid, out } => (
                    out,
                    self.negate(
                        cache[xid]
                            .as_ref()
                            .ok_or(GarblerError::CacheItemError(xid))?,
                    )?,
                ),
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid]
                            .as_ref()
                            .ok_or(GarblerError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(GarblerError::CacheItemError(yid))?,
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
                        cache[xid]
                            .as_ref()
                            .ok_or(GarblerError::CacheItemError(xid))?,
                        cache[yid]
                            .as_ref()
                            .ok_or(GarblerError::CacheItemError(yid))?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut decoding_infos: HashMap<usize, u8> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or(GarblerError::CacheItemError(*r))?;
            let dec = self.get_decoding(*x);
            decoding_infos.insert(*r, dec);
        }
        Ok(GarbleOutput {
            garbler_input_encodings,
            evaluator_input_encodings,
            garbled_circuit: self.get_garbled_circuit(),
            decoding_infos,
        })
    }
}

/// Implements the `ExecutionPrimitives` trait for `BinaryGarbler`.
impl<H: HashFunction, R: RngCore + CryptoRng> ExecutionPrimitives for BinaryGarbler<'_, H, R> {
    /// The type of values used in the garbled circuit. In this case, `Block`
    /// is used to represent the types used and stored in the garbled circuit.
    type Item = Block;

    /// Processes a constant gate for a Binary Garbler.
    ///
    /// # Arguments
    ///
    /// * `x` - A `u16` value representing `1` for `True` and `0` for `False`.
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn constant(&mut self, x: u16) -> Result<Self::Item, ExecutionPrimitiveError> {
        let zerowire = self.zero();
        let mut newwire = zerowire;
        if x == 1 {
            newwire = xor_blocks(newwire, self.delta);
        }
        self.cache.push(newwire);
        Ok(zerowire)
    }

    /// Processes an output gate for a Binary Garbler.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the gate to be processed.
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value wrapped in `Some()` upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, ExecutionPrimitiveError> {
        let i = self.get_next_output_index().to_le_bytes();
        let delta = self.delta;
        let xhash = self.hash.tccr_hash(*x, i);
        let xdhash = self.hash.tccr_hash(xor_blocks(*x, delta), i);
        self.cache.push(xhash);
        self.cache.push(xdhash);
        Ok(Some(xhash))
    }

    /// Processes an input value from the garbler.
    ///
    /// # Arguments
    ///
    /// * `_id` - The identifier for the garbler input (unused for garbler).
    /// * `_x` - The value provided as input (unused for garbler).
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn process_garbler_input(
        &mut self,
        _id: usize,
        _x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError> {
        let mut randval = [0u8; 16];
        self.rng.fill_bytes(&mut randval);
        Ok(randval)
    }

    /// Processes an input value from the evaluator.
    ///
    /// # Arguments
    ///
    /// * `_id` - The identifier for the evaluator input (unused for garbler).
    /// * `_x` - The value provided as input (unused for garbler).
    ///
    /// # Returns
    ///
    /// A result containing
    /// * The output `Block` value upon successful execution.
    /// * `Err(ExecutionPrimitiveError)` if an error occurs.
    fn process_evaluator_input(
        &mut self,
        _id: usize,
        _x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError> {
        let mut randval = [0u8; 16];
        self.rng.fill_bytes(&mut randval);
        Ok(randval)
    }
}

/// Implements the `BinaryOperations` trait for `BinaryGarbler`.
impl<H: HashFunction, R: RngCore + CryptoRng> BinaryOperations for BinaryGarbler<'_, H, R> {
    /// Processes the XOR gate for the garbler.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the first operand.
    /// * `y` - A reference to the `Block` value of the second operand.
    ///
    /// # Returns
    ///
    /// * The output `Block` value upon successful execution.
    /// * `Err(BinaryOperationsError)` if an error occurs.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        let output = xor_blocks(*x, *y);
        Ok(output)
    }

    /// Processes the AND gate for the garbler.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the first operand.
    /// * `y` - A reference to the `Block` value of the second operand.
    ///
    /// # Returns
    ///
    /// * The output `Block` value upon successful execution.
    /// * `Err(BinaryOperationsError)` if an error occurs.
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        let garble_and_gate_op = self.garble_and_gate(*x, *y);
        self.cache.push(garble_and_gate_op.t_gen);
        self.cache.push(garble_and_gate_op.t_eval);
        Ok(garble_and_gate_op.out)
    }

    /// Processes the NOT (negation) gate for the garbler.
    ///
    /// # Arguments
    ///
    /// * `x` - A reference to the `Block` value of the operand.
    ///
    /// # Returns
    ///
    /// * The output `Block` value upon successful execution.
    /// * `Err(BinaryOperationsError)` if an error occurs.
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, BinaryOperationsError> {
        let d = self.delta;
        self.xor(&d, x)
    }
}
