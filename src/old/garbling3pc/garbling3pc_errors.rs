
use crate::old::garbling2pc::garbling2pc_errors::{BinaryOperationsError, ExecutionPrimitiveError, GarblerError};

/// Represents errors that can occur while evaluating a garbled `BinaryCircuit`
/// during the three-party garbled-circuit protocol.
#[derive(Debug)]
pub enum ThreePartyEvaluatorError {
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

/// Represents errors that can occur while garbling a `BinaryCircuit`
/// during the three-party garbled-circuit protocol.
#[derive(Debug)]
pub enum ThreePartyGarblerError {
    /// Represents an error that occurs while running a function that
    /// causes a `GarblerError`
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
