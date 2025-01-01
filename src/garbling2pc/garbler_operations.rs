use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::constants::Block,
    garbling2pc::exec::{BinaryOperations, ExecutionPrimitives},
    utilities::hash_function::HashFunction,
    utilities::utils::xor_blocks,
};

pub struct BinaryGarbler<'a, H: HashFunction, R: RngCore + CryptoRng> {
    pub delta: Block,
    pub hash: H,
    pub rng: &'a mut R,
    pub cache: Vec<Block>,
    pub gateindex: u128,
    pub outputindex: u128,
}

pub struct GarbleAndGateOp<'a, H: HashFunction, R: RngCore + CryptoRng> {
    pub t_gen: <BinaryGarbler<'a, H, R> as ExecutionPrimitives>::Item,
    pub t_eval: <BinaryGarbler<'a, H, R> as ExecutionPrimitives>::Item,
    pub out: <BinaryGarbler<'a, H, R> as ExecutionPrimitives>::Item,
}

pub struct GarbleOutput {
    pub garbler_input_encodings: HashMap<usize, Block>,
    pub evaluator_input_encodings: HashMap<usize, Block>,
    pub garbled_circuit: Vec<Block>,
    pub decoding_infos: HashMap<usize, u8>,
}

impl<'a, H: HashFunction, R: RngCore + CryptoRng> BinaryGarbler<'a, H, R> {
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

    fn lsb(value: Block) -> u8 {
        value[0] & 1
    }

    fn get_random_delta(rng: &mut R) -> Block {
        let mut temp = [0u8; 16];
        rng.fill_bytes(&mut temp);
        temp[0] |= 1;
        temp
    }

    fn get_next_gate_index(&mut self) -> u128 {
        self.gateindex += 1;
        self.gateindex
    }

    fn get_next_output_index(&mut self) -> u128 {
        self.outputindex += 1;
        self.outputindex
    }

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

    fn zero(&mut self) -> Block {
        let mut randval = [0u8; 16];
        self.rng.fill_bytes(&mut randval);
        randval[0] |= 1;
        randval
    }

    pub fn get_decoding(&mut self, x: Block) -> u8 {
        Self::lsb(x)
    }

    pub fn get_garbled_circuit(&self) -> Vec<Block> {
        self.cache.clone()
    }

    pub fn garble(&mut self, circ: BinaryCircuit) -> Result<GarbleOutput, String> {
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
                BinaryGate::Inv { xid, out } => {
                    (out, self.negate(cache[xid].as_ref().ok_or("None")?)?)
                }
                BinaryGate::Xor { xid, yid, out } => (
                    out,
                    self.xor(
                        cache[xid].as_ref().ok_or("None")?,
                        cache[yid].as_ref().ok_or("None")?,
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
                        cache[xid].as_ref().ok_or("None")?,
                        cache[yid].as_ref().ok_or("None")?,
                    )?,
                ),
            };
            cache[z_ref.unwrap_or(i)] = Some(value)
        }
        let mut decoding_infos: HashMap<usize, u8> = HashMap::new();
        for r in circ.get_output_gate_ids().iter() {
            let x = cache[*r].as_ref().ok_or("None")?;
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

impl<'a, H: HashFunction, R: RngCore + CryptoRng> ExecutionPrimitives for BinaryGarbler<'a, H, R> {
    type Item = Block;

    fn constant(&mut self, x: u16) -> Result<Self::Item, String> {
        let zerowire = self.zero();
        let mut newwire = zerowire;
        if x == 1 {
            newwire = xor_blocks(newwire, self.delta);
        }
        self.cache.push(newwire);
        Ok(zerowire)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, String> {
        let i = self.get_next_output_index().to_le_bytes();
        let delta = self.delta;
        let xhash = self.hash.tccr_hash(*x, i);
        let xdhash = self.hash.tccr_hash(xor_blocks(*x, delta), i);
        self.cache.push(xhash);
        self.cache.push(xdhash);
        Ok(Some(xhash))
    }

    fn process_garbler_input(&mut self, _id: usize, _x: bool) -> Result<Self::Item, String> {
        let mut randval = [0u8; 16];
        self.rng.fill_bytes(&mut randval);
        Ok(randval)
    }

    fn process_evaluator_input(&mut self, _id: usize, _x: bool) -> Result<Self::Item, String> {
        let mut randval = [0u8; 16];
        self.rng.fill_bytes(&mut randval);
        Ok(randval)
    }
}

impl<'a, H: HashFunction, R: RngCore + CryptoRng> BinaryOperations for BinaryGarbler<'a, H, R> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, String> {
        let output = xor_blocks(*x, *y);
        Ok(output)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, String> {
        let garble_and_gate_op = self.garble_and_gate(*x, *y);
        self.cache.push(garble_and_gate_op.t_gen);
        self.cache.push(garble_and_gate_op.t_eval);
        Ok(garble_and_gate_op.out)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, String> {
        let d = self.delta;
        self.xor(&d, x)
    }
}
