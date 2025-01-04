#[derive(Debug)]
pub enum HashError {
    InvalidInputLengthError(usize, usize),
}

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

#[derive(Debug)]
pub enum FileParsingError {
    IoError(std::io::Error),
    InputNoParsingError(),
    InputCountError(),
    OutputNoParsingError(),
    OutputCountError(),
    FileFormatError(usize),
}

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

impl From<std::io::Error> for FileParsingError {
    fn from(error: std::io::Error) -> Self {
        FileParsingError::IoError(error)
    }
}

#[derive(Debug)]
pub enum ExecutionPrimitiveError {
    ConstantError(String),
    OutputError(String),
    GarblerInputError(String),
    EvaluatorInputError(String),
}

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

#[derive(Debug)]
pub enum BinaryOperationsError {
    XorError(String),
    AndError(String),
    NegateError(String),
}

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

impl From<ExecutionPrimitiveError> for EvaluatorError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        EvaluatorError::ExecPrimError(error)
    }
}

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

impl std::fmt::Display for GarblerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GarblerError::CacheItemError(ind) => write!(f, "Cache Item not found: index={}", ind),
            GarblerError::ExecPrimError(e) => write!(f, "ExecPrimError: {}", e),
            GarblerError::BinOpError(e) => write!(f, "BinOpError: {}", e),
        }
    }
}

impl From<ExecutionPrimitiveError> for GarblerError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        GarblerError::ExecPrimError(error)
    }
}

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

impl From<ExecutionPrimitiveError> for ThreePartyEvaluatorError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        ThreePartyEvaluatorError::ExecPrimError(error)
    }
}

impl From<BinaryOperationsError> for ThreePartyEvaluatorError {
    fn from(error: BinaryOperationsError) -> Self {
        ThreePartyEvaluatorError::BinOpError(error)
    }
}

#[derive(Debug)]
pub enum ThreePartyGarblerError {
    GarblerError(GarblerError),
}

impl std::fmt::Display for ThreePartyGarblerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreePartyGarblerError::GarblerError(e) => write!(f, "Garbler Error: {}", e),
        }
    }
}

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

impl From<ExecutionPrimitiveError> for BinaryPlaintextError {
    fn from(error: ExecutionPrimitiveError) -> Self {
        BinaryPlaintextError::ExecPrimError(error)
    }
}

impl From<BinaryOperationsError> for BinaryPlaintextError {
    fn from(error: BinaryOperationsError) -> Self {
        BinaryPlaintextError::BinOpError(error)
    }
}
