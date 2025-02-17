use crate::config::garbling2pc_errors::{BinaryOperationsError, ExecutionPrimitiveError};

/// Defines the core execution primitives required for implementing a garbled circuit protocol.
///
/// This trait must be implemented by both garblers and evaluators.
/// The associated type `Item` represents the cipher output in the garbling circuit.
pub trait ExecutionPrimitives {
    /// The type of the cipher output in the garbling circuit.
    ///
    /// This type must implement `Clone` since values may need to be duplicated
    /// during execution.
    type Item: Clone;

    /// Processes a constant gate in the garbling circuit.
    ///
    /// # Parameters
    /// - `x`: A `u16` constant value to be processed.
    ///
    /// # Returns
    /// - `Ok(Self::Item)`: If the operation is successful.
    /// - `Err(ExecutionPrimitiveError)`: If an error occurs.
    fn constant(&mut self, x: u16) -> Result<Self::Item, ExecutionPrimitiveError>;

    /// Processes an output gate in the garbling circuit.
    ///
    /// # Parameters
    /// - `x`: A reference to the input item.
    ///
    /// # Returns
    /// - `Ok(Some(Self::Item))`: If the output is successfully produced.
    /// - `Ok(None)`: If no output is required.
    /// - `Err(ExecutionPrimitiveError)`: If an error occurs.
    fn output(&mut self, x: &Self::Item) -> Result<Option<Self::Item>, ExecutionPrimitiveError>;

    /// Processes an input value provided by the garbler.
    ///
    /// # Parameters
    /// - `id`: The unique identifier for the input.
    /// - `x`: A boolean value representing the garbler's input.
    ///
    /// # Returns
    /// - `Ok(Self::Item)`: The processed value.
    /// - `Err(ExecutionPrimitiveError)`: If an error occurs.
    fn process_garbler_input(
        &mut self,
        id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError>;

    /// Processes an input value provided by the evaluator.
    ///
    /// # Parameters
    /// - `id`: The unique identifier for the input.
    /// - `x`: A boolean value representing the evaluator's input.
    ///
    /// # Returns
    /// - `Ok(Self::Item)`: The processed value.
    /// - `Err(ExecutionPrimitiveError)`: If an error occurs.
    fn process_evaluator_input(
        &mut self,
        id: usize,
        x: bool,
    ) -> Result<Self::Item, ExecutionPrimitiveError>;
}

/// Defines binary operations in a garbled circuit protocol.
///
/// This trait extends ExecutionPrimitives and provides operations for
/// binary gates such as XOR, AND, and negation.
///
/// Any garbler or evaluator implementing a garbled circuit protocol over binary inputs,
/// outputs, and gates must implement this trait.
pub trait BinaryOperations: ExecutionPrimitives {
    /// Processes an XOR gate on two input values.
    ///
    /// # Parameters
    /// - `x`: A reference to the first input item.
    /// - `y`: A reference to the second input item.
    ///
    /// # Returns
    /// - `Ok(Self::Item)`: The XOR result.
    /// - `Err(BinaryOperationsError)`: If an error occurs.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError>;

    /// Processes an AND gate on two input values.
    ///
    /// # Parameters
    /// - `x`: A reference to the first input item.
    /// - `y`: A reference to the second input item.
    ///
    /// # Returns
    /// - `Ok(Self::Item)`: The XOR result.
    /// - `Err(BinaryOperationsError)`: If an error occurs.
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, BinaryOperationsError>;

    /// Processes an NOT (negation) gate on an input value.
    ///
    /// # Parameters
    /// - `x`: A reference to the input item.
    ///
    /// # Returns
    /// - `Ok(Self::Item)`: The XOR result.
    /// - `Err(BinaryOperationsError)`: If an error occurs.
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, BinaryOperationsError>;
}
