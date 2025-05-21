use std::num::ParseIntError;

/// Represents errors that can occur while parsing a circuit file.
#[derive(Debug)]
pub enum FileParsingError {
    /// Represents an I/O error encountered while reading the file.
    IoError(std::io::Error),

    /// Error indicating that the number of inputs could not be parsed.
    InputNoParsingError(),

    ParseIntError(ParseIntError),

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
            FileParsingError::ParseIntError(e) => write!(f, "ParseInt error: {}", e),
        }
    }
}

/// Implements conversion from `std::io::Error` to `FileParsingError`,
/// allowing automatic conversion when using `?` in functions returning `FileParsingError`.
impl From<ParseIntError> for FileParsingError {
    fn from(error: ParseIntError) -> Self {
        FileParsingError::ParseIntError(error)
    }
}

/// Implements conversion from `std::io::Error` to `FileParsingError`,
/// allowing automatic conversion when using `?` in functions returning `FileParsingError`.
impl From<std::io::Error> for FileParsingError {
    fn from(error: std::io::Error) -> Self {
        FileParsingError::IoError(error)
    }
}