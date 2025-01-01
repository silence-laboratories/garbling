pub trait ExecutionPrimitives {
    type Item: Clone;

    fn constant(&mut self, x: u16) -> Result<Self::Item, String>;

    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, String>;

    fn process_garbler_input(&mut self, id: usize, x: bool) -> Result<Self::Item, String>;

    fn process_evaluator_input(&mut self, id: usize, x: bool) -> Result<Self::Item, String>;
}

pub trait BinaryOperations: ExecutionPrimitives {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, String>;

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, String>;

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, String>;
}
