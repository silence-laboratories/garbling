use std::fmt::Error;

use crate::{config::constants::BLOCK, exec::{BinaryOperations, ExecutionPrimitives}, hash_function::HashFunction, utils::xor_blocks};

#[derive(Clone)]
pub struct BinaryGarbler<H: HashFunction> {
    pub delta: BLOCK, 
    pub rng: H,
    pub cache: Vec<BLOCK>,
    pub gateindex: u128,
    pub outputindex: u128,
}

impl<H: HashFunction> BinaryGarbler<H> {
    pub fn new(mut hash: H) -> BinaryGarbler<H> {
        BinaryGarbler {
            delta: Self::get_random_delta(&mut hash),
            rng: hash,
            cache: Vec::new(),
            gateindex: 0,
            outputindex: 0,
        }
    }

    fn lsb(value: BLOCK) -> u8 {
        value[0] & 1
    }

    fn get_random_delta(hash: &mut H) -> BLOCK {
        let mut temp = hash.get_random_hash();
        temp[0] = temp[0] | 1;
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
    
    fn garble_and_gate(&mut self, 
        a: <BinaryGarbler<H> as ExecutionPrimitives>::Item, 
        b: <BinaryGarbler<H> as ExecutionPrimitives>::Item
    ) -> (<BinaryGarbler<H> as ExecutionPrimitives>::Item, <BinaryGarbler<H> as ExecutionPrimitives>::Item, <BinaryGarbler<H> as ExecutionPrimitives>::Item) {
        let p_a = Self::lsb(a);
        let p_b = Self::lsb(b);

        let j = self.get_next_gate_index().to_le_bytes();
        let j2 = self.get_next_gate_index().to_le_bytes();

        let (t_gen, out_gen) = self.gen_half_gate(p_a, p_b, a, j);
        let (t_eval, out_eval) = self.eval_half_gate(p_b, a, b, j2);
        let out = xor_blocks(out_gen, out_eval);

        (t_gen, t_eval, out)
    }

    fn gen_half_gate(&self, 
        p_a: u8, 
        p_b: u8, 
        a: <BinaryGarbler<H> as ExecutionPrimitives>::Item, j: BLOCK
    ) -> (<BinaryGarbler<H> as ExecutionPrimitives>::Item, <BinaryGarbler<H> as ExecutionPrimitives>::Item) {
        let temp1 = self.rng.tccr_hash(a, j);
        let adelta = xor_blocks(a, self.delta);
        let temp2 = self.rng.tccr_hash(adelta, j);
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

    fn eval_half_gate(&self, p_b: u8, 
        a: <BinaryGarbler<H> as ExecutionPrimitives>::Item, 
        b: <BinaryGarbler<H> as ExecutionPrimitives>::Item, 
        j2: BLOCK
    ) -> (<BinaryGarbler<H> as ExecutionPrimitives>::Item, <BinaryGarbler<H> as ExecutionPrimitives>::Item) {
        let temp1 = self.rng.tccr_hash(b, j2);
        let bdelta = xor_blocks(b, self.delta);
        let temp2 = self.rng.tccr_hash(bdelta, j2);
        let mut t_eval = xor_blocks(temp1, temp2);
        t_eval = xor_blocks(t_eval, a);
        let mut out_eval = temp1;
        if p_b == 1 {
            let temp3 = xor_blocks(t_eval, a);
            out_eval = xor_blocks(out_eval, temp3);
        }
        (t_eval, out_eval)
    }

    fn zero(&self) -> BLOCK {
        let mut randval = self.rng.get_random_hash();
        randval[0] = randval[0] | 1;
        randval
    }

    pub fn get_decoding(&mut self, x: BLOCK) -> u8 {
        Self::lsb(x)
    }
    
    pub fn get_garbled_circuit(&self) -> Vec<BLOCK> {
        self.cache.clone()
    }
}

impl<H: HashFunction> ExecutionPrimitives for BinaryGarbler<H> {
    type Item = BLOCK;

    fn constant(&mut self, x: u16) -> Result<Self::Item, Error> {
        let zerowire = self.zero();
        let mut newwire = zerowire.clone();
        if x == 1 {
            newwire = xor_blocks(newwire, self.delta);
        }
        self.cache.push(newwire.clone());
        Ok(zerowire)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, std::fmt::Error> {
        let i = self.get_next_output_index().to_le_bytes();
        let delta = self.delta;
        let xhash = self.rng.tccr_hash(*x, i);
        let xdhash = self.rng.tccr_hash(xor_blocks(*x, delta), i);
        self.cache.push(xhash);
        self.cache.push(xdhash);
        Ok(Some(xhash))
    }

    fn process_garbler_input(&mut self, _id: usize, _x: bool) -> Result<Self::Item, Error> {
        Ok(self.rng.get_random_hash())
    }
    
    fn process_evaluator_input(&mut self, _id: usize, _x: bool) -> Result<Self::Item, Error> {
        Ok(self.rng.get_random_hash())
    }
}

impl<H: HashFunction> BinaryOperations for BinaryGarbler<H> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        let output = xor_blocks(*x, *y);
        Ok(output)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        let (t_gen, t_eval, out) = self.garble_and_gate(*x, *y);
        self.cache.push(t_gen);
        self.cache.push(t_eval);
        Ok(out)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Error> {
        let d = self.delta;
        self.xor(&d, x)
    }
}