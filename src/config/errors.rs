/// Represents errors that can occur during hashing operations.
#[derive(Debug)]
pub enum HashError {
    /// Error indicating that the input length is invalid.
    ///
    /// # Fields
    /// - `0`: The expected input length.
    /// - `1`: The actual input length received.
    InvalidInputLengthError(usize, usize),
}

/// Implements the `std::fmt::Display` trait for `HashError`.
impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::InvalidInputLengthError(ideal, real) => write!(
                f,
                "InvalidInputLengthError: required=%{} obtained={}",
                ideal, real
            ),
        }
    }
}

/// Represents errors that can occur while parsing a circuit file.
#[derive(Debug)]
pub enum FileParsingError {
    /// Represents an I/O error encountered while reading the file.
    IoError(std::io::Error),

    /// Error indicating that the number of inputs could not be parsed.
    InputNoParsingError(),

    /// Error indicating an invalid number of input wires.
    ///
    /// The circuit must define exactly two input wires: one for the garbler and one for the evaluator.
    InputCountError(),

    /// Error indicating that the number of outputs could not be parsed.
    OutputNoParsingError(),

    /// Error indicating an invalid number of output wires.
    ///
    /// The circuit must define exactly one output wire.
    OutputCountError(),

    /// Error indicating that the circuit file format is incorrect.
    ///
    /// # Fields
    /// - `0`: The line number where the formatting issue occurred.
    FileFormatError(usize),
}

/// Implements the `std::fmt::Display` trait for `FileParsingError`.
impl std::fmt::Display for FileParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileParsingError::IoError(e) => write!(f, "IO error: {}", e),
            FileParsingError::InputNoParsingError() => write!(f, "Failed to parse number of inputs"),
            FileParsingError::InputCountError() => write!(f, "Number of input wires is not 2. Please define two inputs for garbler and evaluator respectively!!!"),
            FileParsingError::OutputNoParsingError() => write!(f, "Failed to parse number of outputs"),
            FileParsingError::OutputCountError() => write!(f, "Number of output wires is not 1"),
            FileParsingError::FileFormatError(line_no) => write!(f, "Incorrect file format. gate number: {} from the top", line_no),
        }
    }
}

/// Implements conversion from `std::io::Error` to `FileParsingError`,
/// allowing automatic conversion when using `?` in functions returning `FileParsingError`.
impl From<std::io::Error> for FileParsingError {
    fn from(error: std::io::Error) -> Self {
        FileParsingError::IoError(error)
    }
}

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

#[derive(Debug)]
pub enum EvaluatorError {
    ExecPrimError(ExecutionPrimitiveError),
    BinOpError(BinaryOperationsError),
    GarblerIpLenError(usize, usize),
    EvaluatorIpLenError(usize, usize),
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

#[derive(Debug)]
pub enum GarblerError {
    ExecPrimError(ExecutionPrimitiveError),
    BinOpError(BinaryOperationsError),
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

#[derive(Debug)]
pub enum ThreePartyEvaluatorError {
    ExecPrimError(ExecutionPrimitiveError),
    BinOpError(BinaryOperationsError),
    GarblerIpLenError(usize, usize),
    EvaluatorIpLenError(usize, usize),
    CacheItemError(usize),
}

/// Implements the `std::fmt::Display` trait for `ThreePartyEvaluatorError`.
impl std::fmt::Display for ThreePartyEvaluatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreePartyEvaluatorError::GarblerIpLenError(id, ip_len) => {
                write!(
                    f,
                    "Inconsistent Garbler Input length: id={} garbler input length={}",
                    id, ip_len
                )
            }
            ThreePartyEvaluatorError::EvaluatorIpLenError(id, ip_len) => {
                write!(
                    f,
                    "Inconsistent Evaluator Input length: id={} garbler input length={}",
                    id, ip_len
                )
            }
            ThreePartyEvaluatorError::CacheItemError(ind) => {
                write!(f, "Cache Item not found: index={}", ind)
            }
            ThreePartyEvaluatorError::ExecPrimError(e) => write!(f, "ExecPrimError: {}", e),
            ThreePartyEvaluatorError::BinOpError(e) => write!(f, "BinOpError: {}", e),
        }
    }
}

/// Implements conversion from `ExecutionPrimitiveError` to `ThreePartyEvaluatorError`,
/// allowing automatic conversion when using `?` in functions returning `ThreePartyEvaluatorError`.
impl From<ExecutionPrimitiveError> for ThreePartyEvaluatorError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        ThreePartyEvaluatorError::ExecPrimError(error)
    }
}

/// Implements conversion from `BinaryOperationsError` to `ThreePartyEvaluatorError`,
/// allowing automatic conversion when using `?` in functions returning `ThreePartyEvaluatorError`.
impl From<BinaryOperationsError> for ThreePartyEvaluatorError {
    fn from(error: BinaryOperationsError) -> Self {
        ThreePartyEvaluatorError::BinOpError(error)
    }
}

#[derive(Debug)]
pub enum ThreePartyGarblerError {
    GarblerError(GarblerError),
}

/// Implements the `std::fmt::Display` trait for `ThreePartyGarblerError`.
impl std::fmt::Display for ThreePartyGarblerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreePartyGarblerError::GarblerError(e) => write!(f, "Garbler Error: {}", e),
        }
    }
}

/// Implements conversion from `GarblerError` to `ThreePartyGarblerError`,
/// allowing automatic conversion when using `?` in functions returning `ThreePartyGarblerError`.
impl From<GarblerError> for ThreePartyGarblerError {
    fn from(value: GarblerError) -> Self {
        ThreePartyGarblerError::GarblerError(value)
    }
}

#[derive(Debug)]
pub enum BinaryPlaintextError {
    ExecPrimError(ExecutionPrimitiveError),
    BinOpError(BinaryOperationsError),
    GarblerIpLenError(usize, usize),
    EvaluatorIpLenError(usize, usize),
    CacheItemError(usize),
}

/// Implements the `std::fmt::Display` trait for `BinaryPlaintextError`.
impl std::fmt::Display for BinaryPlaintextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryPlaintextError::GarblerIpLenError(id, ip_len) => {
                write!(
                    f,
                    "Inconsistent Garbler Input length: id={} garbler input length={}",
                    id, ip_len
                )
            }
            BinaryPlaintextError::EvaluatorIpLenError(id, ip_len) => {
                write!(
                    f,
                    "Inconsistent Evaluator Input length: id={} garbler input length={}",
                    id, ip_len
                )
            }
            BinaryPlaintextError::CacheItemError(ind) => {
                write!(f, "Cache Item not found: index={}", ind)
            }
            BinaryPlaintextError::ExecPrimError(e) => write!(f, "ExecPrimError: {}", e),
            BinaryPlaintextError::BinOpError(e) => write!(f, "BinOpError: {}", e),
        }
    }
}

/// Implements conversion from `ExecutionPrimitiveError` to `BinaryPlaintextError`,
/// allowing automatic conversion when using `?` in functions returning `BinaryPlaintextError`.
impl From<ExecutionPrimitiveError> for BinaryPlaintextError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        BinaryPlaintextError::ExecPrimError(error)
    }
}

/// Implements conversion from `BinaryOperationsError` to `BinaryPlaintextError`,
/// allowing automatic conversion when using `?` in functions returning `BinaryPlaintextError`.
impl From<BinaryOperationsError> for BinaryPlaintextError {
    fn from(error: BinaryOperationsError) -> Self {
        BinaryPlaintextError::BinOpError(error)
    }
}
