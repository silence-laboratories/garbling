use std::fmt::Error;

use crate::exec::{BinaryOperations, ExecutionPrimitives};

pub struct BinaryPlaintext;

impl ExecutionPrimitives for BinaryPlaintext {
    type Item = bool;

    fn constant(&mut self, x: u16) -> Result<Self::Item, Error> {
        Ok(x != 0)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<bool>, std::fmt::Error> {
        Ok(Some(*x))
    }

    fn process_garbler_input(&mut self, _id: usize, x: bool) -> Result<Self::Item, Error> {
        Ok(x)
    }
    
    fn process_evaluator_input(&mut self, _id: usize, x: bool) -> Result<Self::Item, Error> {
        Ok(x)
    }
}

impl BinaryOperations for BinaryPlaintext {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        Ok(x ^ y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error> {
        Ok(x & y)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Error> {
        Ok(!x)
    }
}