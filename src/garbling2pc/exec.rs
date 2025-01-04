use crate::config::errors::{BinaryOperationsError, ExecutionPrimitiveError};

pub trait ExecutionPrimitives {
    type Item: Clone;

    fn constant(&mut self, x: u16) -> Result<Self::Item, ExecutionPrimitiveError>;

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, ExecutionPrimitiveError>;

    fn process_garbler_input(
        &mut self,
        id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError>;

    fn process_evaluator_input(
        &mut self,
        id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError>;
}

pub trait BinaryOperations: ExecutionPrimitives {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError>;

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError>;

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, BinaryOperationsError>;
}
