/// Represents a 128-bit block of data.
///
/// This is used for representing the output of hashes for
/// the garbled circuit.
pub type Block = [u8; 16];

#[allow(dead_code)]
/// A constant 128-bit AES key initialized with all zeros.
///
/// This can be used as a default or placeholder key in AES-based encryption.
pub const AES_KEY: Block = [0u8; 16];

/// A constant 128-bit hash key initialized with all bytes set to `1`.
///
/// This can be used as a default or placeholder key in cryptographic hash functions.
pub const HASH_KEY: Block = [1u8; 16];
