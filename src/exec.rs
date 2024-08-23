use std::fmt::Error;

pub trait ExecutionPrimitives {

    type Item: Clone;
    
    fn constant(&mut self, x: u16) -> Result<Self::Item, Error>;

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, Error>;

    fn process_garbler_input(&mut self, id: usize, x: bool) -> Result<Self::Item, Error>;
    
    fn process_evaluator_input(&mut self, id: usize, x: bool) -> Result<Self::Item, Error>;
}

pub trait BinaryOperations: ExecutionPrimitives {
    
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error>;

    
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Error>;

    
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Error>;
}