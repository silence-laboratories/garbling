use std::{collections::HashMap, fmt::Error};

use crate::{config::constants::BLOCK, exec::{BinaryOperations, ExecutionPrimitives}, hash_function::HashFunction, utils::xor_blocks};

pub struct BinaryEvaluator<H: HashFunction> {
    garbler_encoding: HashMap<usize, BLOCK>,
    evaluator_encoding: HashMap<usize, BLOCK>,
    decoding_infos: HashMap<usize, u8>,
    pub delta: BLOCK, 
    pub rng: H,
    pub cache: Vec<BLOCK>,
    pub gateindex: u128,
    pub currentcacheindex: usize,
}

impl<H: HashFunction> BinaryEvaluator<H> {
    pub fn new(
        garbler_encoding: HashMap<usize, BLOCK>, 
        evaluator_encoding: HashMap<usize, BLOCK>, 
        decoding_infos: HashMap<usize, u8>,
        delta: BLOCK, 
        hash: H, 
        gc: Vec<BLOCK>
    ) -> BinaryEvaluator<H> {
        BinaryEvaluator {
            garbler_encoding: garbler_encoding,
            evaluator_encoding: evaluator_encoding,
            decoding_infos: decoding_infos,
            delta: delta,
            rng: hash,
            cache: gc,
            gateindex: 0,
            currentcacheindex: 0,
        }
    }

    fn lsb(value: BLOCK) -> u8 {
        value[0] & 1
    }

    fn get_next_gate_index(&mut self) -> u128 {
        self.gateindex += 1;
        self.gateindex
    }

    fn get_next_cache_value(&mut self) -> BLOCK {
        let op = self.cache[self.currentcacheindex];
        self.currentcacheindex += 1;
        op
    }

    pub fn get_plaintext_output (&self, output_gates: Vec<usize>, garbled_output: HashMap<usize, <BinaryEvaluator<H> as ExecutionPrimitives>::Item>) -> Vec<bool> {
        let mut output = Vec::new();
        for x in output_gates {
            let glsb = Self::lsb(*garbled_output.get(&x).unwrap());
            let declsb = self.decoding_infos.get(&x).unwrap().to_owned();
            output.push(glsb ^ declsb != 0)
        }
        output
    }
}


impl<H: HashFunction> ExecutionPrimitives for BinaryEvaluator<H> {
    type Item = BLOCK;

    fn constant(&mut self, _x: u16) -> Result<Self::Item, Error> {
        Ok(self.get_next_cache_value())
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, std::fmt::Error> {
        Ok(Some(*x))
    }

    fn process_evaluator_input(&mut self, id: usize, x: bool) -> Result<Self::Item, Error> {
        let mut val = self.evaluator_encoding.get(&id).unwrap().to_owned();
        if x {
            val = xor_blocks(val, self.delta);
        }
        Ok(val)
    }

    fn process_garbler_input(&mut self, id: usize, x: bool) -> Result<Self::Item, Error> {
        let mut val = self.garbler_encoding.get(&id).unwrap().to_owned();
        if x {
            val = xor_blocks(val, self.delta);
        }
        Ok(val)
    }
}

impl<H: HashFunction> BinaryOperations for BinaryEvaluator<H> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        let output = xor_blocks(*x, *y);
        Ok(output)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        let s_a = Self::lsb(*x);
        let s_b = Self::lsb(*y);
        
        let j = self.get_next_gate_index().to_le_bytes();
        let j2 = self.get_next_gate_index().to_le_bytes();

        let t_gen = self.get_next_cache_value();
        let t_eval = self.get_next_cache_value();

        let mut out_gen = self.rng.tccr_hash(*x, j);
        if s_a == 1 {
            out_gen = xor_blocks(out_gen, t_gen);
        }

        let mut out_eval = self.rng.tccr_hash(*y, j2);
        if s_b == 1 {
            out_eval = xor_blocks(out_eval, t_eval);
            out_eval = xor_blocks(out_eval, *x);
        }

        let out = xor_blocks(out_gen, out_eval);

        Ok(out)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Error> {
        Ok(*x)
    }
}