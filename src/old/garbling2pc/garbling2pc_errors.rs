/// Represents errors that can occur while executing primitives in a garbled circuit.
///
/// These errors may arise when processing constants, outputs, or inputs from the garbler
/// or evaluator.
#[derive(Debug)]
pub enum ExecutionPrimitiveError {
    /// Error that occurs when a constant value cannot be processed.
    ///
    /// The associated string provides additional details about the failure.
    ConstantError(String),

    /// Error that occurs when an output value cannot be produced.
    ///
    /// The associated string provides additional details about the failure.
    OutputError(String),

    /// Error that occurs when processing an input provided by the garbler.
    ///
    /// The associated string provides additional details about the failure.
    GarblerInputError(String),

    /// Error that occurs when processing an input provided by the evaluator.
    ///
    /// The associated string provides additional details about the failure.
    EvaluatorInputError(String),
}

/// Implements the `std::fmt::Display` trait for `ExecutionPrimitiveError`.
impl std::fmt::Display for ExecutionPrimitiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionPrimitiveError::ConstantError(msg) => write!(f, "ConstantError: {}", msg),
            ExecutionPrimitiveError::OutputError(msg) => write!(f, "OutputError: {}", msg),
            ExecutionPrimitiveError::GarblerInputError(msg) => {
                write!(f, "GarblerInputError: {}", msg)
            }
            ExecutionPrimitiveError::EvaluatorInputError(msg) => {
                write!(f, "EvaluatorInputError: {}", msg)
            }
        }
    }
}

/// Represents errors that may occur while performing binary operations (XOR, AND, NEGATE)
/// in a garbled circuit.
#[derive(Debug)]
pub enum BinaryOperationsError {
    /// Error occurring during an XOR operation.
    ///
    /// The provided `String` contains additional details about the failure.
    XorError(String),

    /// Error occurring during an AND operation.
    ///
    /// The provided `String` contains additional details about the failure.
    AndError(String),

    /// Error occurring during a NOT (negation) operation.
    ///
    /// The provided `String` contains additional details about the failure.
    NegateError(String),
}

/// Implements the `std::fmt::Display` trait for `BinaryOperationsError`.
impl std::fmt::Display for BinaryOperationsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOperationsError::XorError(msg) => write!(f, "XorError: {}", msg),
            BinaryOperationsError::AndError(msg) => write!(f, "AndError: {}", msg),
            BinaryOperationsError::NegateError(msg) => write!(f, "NegateError: {}", msg),
        }
    }
}

/// Represents errors that can occur while evaluating a garbled `BinaryCircuit`.
#[derive(Debug)]
pub enum EvaluatorError {
    /// Represents an error that occurs while running a function that
    /// causes an `ExecutionPrimitiveError`
    ExecPrimError(ExecutionPrimitiveError),

    /// Represents an error that occurs while running a function that
    /// causes a `BinaryOperationsError`
    BinOpError(BinaryOperationsError),

    /// Represents an error that occurs when garbler input length is
    /// exceeding the expected threshold.
    ///
    /// # Fields
    /// - `0`: The actual input length received.
    /// - `1`: The expected input length.
    GarblerIpLenError(usize, usize),

    /// Represents an error that occurs when evaluator input length is
    /// exceeding the expected threshold.
    ///
    /// # Fields
    /// - `0`: The actual input length received.
    /// - `1`: The expected input length.
    EvaluatorIpLenError(usize, usize),

    /// Represents an error that occurs when an item being accessed from the
    /// cache does not exist yet.
    ///
    /// # Fields
    /// - `0`: index of the accessed item.
    CacheItemError(usize),
}

/// Implements the `std::fmt::Display` trait for `EvaluatorError`.
impl std::fmt::Display for EvaluatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluatorError::GarblerIpLenError(id, ip_len) => {
                write!(
                    f,
                    "Inconsistent Garbler Input length: id={} garbler input length={}",
                    id, ip_len
                )
            }
            EvaluatorError::EvaluatorIpLenError(id, ip_len) => {
                write!(
                    f,
                    "Inconsistent Evaluator Input length: id={} garbler input length={}",
                    id, ip_len
                )
            }
            EvaluatorError::CacheItemError(ind) => write!(f, "Cache Item not found: index={}", ind),
            EvaluatorError::ExecPrimError(e) => write!(f, "ExecPrimError: {}", e),
            EvaluatorError::BinOpError(e) => write!(f, "BinOpError: {}", e),
        }
    }
}

/// Implements conversion from `ExecutionPrimitiveError` to `EvaluatorError`,
/// allowing automatic conversion when using `?` in functions returning `EvaluatorError`.
impl From<ExecutionPrimitiveError> for EvaluatorError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        EvaluatorError::ExecPrimError(error)
    }
}

/// Implements conversion from `BinaryOperationsError` to `EvaluatorError`,
/// allowing automatic conversion when using `?` in functions returning `EvaluatorError`.
impl From<BinaryOperationsError> for EvaluatorError {
    fn from(error: BinaryOperationsError) -> Self {
        EvaluatorError::BinOpError(error)
    }
}

/// Represents errors that can occur while garbling a `BinaryCircuit`.
#[derive(Debug)]
pub enum GarblerError {
    /// Represents an error that occurs while running a function that
    /// causes an `ExecutionPrimitiveError`
    ExecPrimError(ExecutionPrimitiveError),

    /// Represents an error that occurs while running a function that
    /// causes a `BinaryOperationsError`
    BinOpError(BinaryOperationsError),

    /// Represents an error that occurs when an item being accessed from the
    /// cache does not exist yet.
    ///
    /// # Fields
    /// - `0`: index of the accessed item.
    CacheItemError(usize),
}

/// Implements the `std::fmt::Display` trait for `GarblerError`.
impl std::fmt::Display for GarblerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GarblerError::CacheItemError(ind) => write!(f, "Cache Item not found: index={}", ind),
            GarblerError::ExecPrimError(e) => write!(f, "ExecPrimError: {}", e),
            GarblerError::BinOpError(e) => write!(f, "BinOpError: {}", e),
        }
    }
}

/// Implements conversion from `ExecutionPrimitiveError` to `GarblerError`,
/// allowing automatic conversion when using `?` in functions returning `GarblerError`.
impl From<ExecutionPrimitiveError> for GarblerError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        GarblerError::ExecPrimError(error)
    }
}

/// Implements conversion from `BinaryOperationsError` to `GarblerError`,
/// allowing automatic conversion when using `?` in functions returning `GarblerError`.
impl From<BinaryOperationsError> for GarblerError {
    fn from(error: BinaryOperationsError) -> Self {
        GarblerError::BinOpError(error)
    }
}
