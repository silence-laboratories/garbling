use std::num::ParseIntError;

/// Represents errors that can occur while parsing a circuit file.
#[derive(Debug)]
pub enum FileParsingError {
    /// Represents an I/O error encountered while reading the file.
    IoError(std::io::Error),

    /// Error indicating that the number of inputs could not be parsed.
    InputNoParsingError,

    ParseIntError(ParseIntError),

    /// Error indicating that the circuit file format is incorrect.
    ///
    /// # Fields
    /// - `0`: The line number where the formatting issue occurred.
    FileFormatError(usize),
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
