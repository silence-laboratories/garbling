use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::config::constants::Block;
use crate::config::util_errors::HashError;

/// Trait for any hash function which implements a secure hash function for
/// garbled circuits.
pub trait HashFunction: Clone {
    /// Initializes a hash function with a key.
    fn initialize(&mut self, key: Block);

    /// Returns a correlation robust hash given an input `Block`.
    fn cr_hash(&self, x: Block) -> Block;

    /// Returns a circular correlation robust hash given an
    /// input `Block`.
    fn ccr_hash(&self, x: Block) -> Block;

    /// Returns a tweakable circular correlation robust hash
    /// given an input `Block` and an integer encoded in a `Block`.
    fn tccr_hash(&self, x: Block, i: Block) -> Block;

    /// Returns a hash given an input `Block`.
    fn get_hash(&self, x: &[u8]) -> Result<Block, HashError>;
}

/// Represents a structure of hash function based on AES-128 encryption.
#[derive(Clone)]
pub struct AesHash {
    /// `Aes128` object used for hashing.
    aes: Aes128,
}

/// Implementation for `AesHash`.
impl AesHash {
    /// Takes a key `Block` as input to return a new `AesHash` object.
    pub fn new(key: Block) -> AesHash {
        let aes = Aes128::new(&GenericArray::from(key));
        let mut rngkey = [0u8; 32];
        rngkey[16..(16 + 16)].copy_from_slice(&key);
        rngkey[..16].copy_from_slice(&key);
        AesHash { aes }
    }
}

/// Implements the `HashFunction` trait for `AesHash`.
impl HashFunction for AesHash {
    /// Implementation of the `cr_hash` function for a `AesHash`
    fn cr_hash(&self, x: Block) -> Block {
        let mut output = GenericArray::from(x);
        self.aes.encrypt_block(&mut output);
        let output_needed: Block = output.into();
        output_needed
    }

    /// Implementation of the `ccr_hash` function for a `AesHash`.
    fn ccr_hash(&self, x: Block) -> Block {
        let mut y = [0u8; 16];
        for i in 0..8 {
            y[i] = x[i] ^ x[i + 8];
        }
        y[8..16].copy_from_slice(&x[8..16]);
        self.cr_hash(y)
    }

    /// Implementation of the `tccr_hash` function for a `AesHash`.
    fn tccr_hash(&self, x: Block, i: Block) -> Block {
        let mut y = GenericArray::from(x);
        self.aes.encrypt_block(&mut y);
        let mut block: Block = y.into();
        let mut t = [0u8; 16];
        for m in 0..16 {
            t[m] = block[m] ^ i[m];
        }
        let mut z = GenericArray::from(t);
        self.aes.encrypt_block(&mut z);
        let bz: Block = z.into();
        for m in 0..16 {
            block[m] ^= bz[m]
        }
        block
    }

    /// Implementation of the `get_hash` function for a `AesHash`.
    fn get_hash(&self, input: &[u8]) -> Result<Block, HashError> {
        let mut previous_block = GenericArray::from([0u8; 16]); // Initialize to zero for CBC
        let mut output_block = GenericArray::from([0u8; 16]);

        if input.len() % 16 != 0 {
            return Err(HashError::InvalidInputLengthError(16, input.len()));
        }

        for chunk in input.chunks_exact(16) {
            let mut block = GenericArray::clone_from_slice(chunk);

            // XOR with the previous block (CBC chaining)
            for i in 0..16 {
                block[i] ^= previous_block[i];
            }

            // Encrypt the block
            self.aes.encrypt_block(&mut block);

            // Update the previous block
            previous_block = block;
        }

        output_block.copy_from_slice(&previous_block);

        // Return the final encrypted block as the CBC-MAC
        let mut result = [0u8; 16];
        result.copy_from_slice(&output_block);

        Ok(result)
    }

    /// Implementation of the `initialize` function for a `AesHash`.
    fn initialize(&mut self, key: Block) {
        self.aes = Aes128::new(&GenericArray::from(key));
    }
}

#[cfg(test)]
mod tests {
    use crate::config::constants::AES_KEY;

    use super::{AesHash, HashFunction};

    #[test]
    fn test_hash_function() {
        let input1 = [0u8; 16];
        let input2 = [0u8; 32];
        let function = AesHash::new(AES_KEY);

        let output1 = function.get_hash(&input1).unwrap();
        let output2 = function.get_hash(&input2).unwrap();

        let required_output1 = [
            102, 233, 75, 212, 239, 138, 44, 59, 136, 76, 250, 89, 202, 52, 43, 46,
        ];
        let required_output2 = [
            247, 149, 189, 74, 82, 226, 158, 215, 19, 211, 19, 250, 32, 233, 141, 188,
        ];

        assert_eq!(output1, required_output1);
        assert_eq!(output2, required_output2);
    }
}
