// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

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
                "InvalidInputLengthError: required=%{ideal} obtained={real}"
            ),
        }
    }
}
