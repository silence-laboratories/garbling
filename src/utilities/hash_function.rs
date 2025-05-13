use aes_gcm::aead::Aead;
use aes_gcm::{aead::generic_array::GenericArray, Aes256Gcm, KeyInit};

use crate::config::constants::{Block, AES_NONCE};
use crate::config::util_errors::HashError;

use super::utils::xor_blocks;

/// Trait for any hash function which implements a secure hash function for
/// garbled circuits.
pub trait HashFunction: Clone {
    /// Initializes a hash function with a key.
    fn initialize(&mut self, key: Block);

    /// Returns a correlation robust hash given an input `Block`.
    fn cr_hash(&self, x: &Block) -> Block;

    /// Returns a circular correlation robust hash given an
    /// input `Block`.
    fn ccr_hash(&self, x: &Block) -> Block;

    /// Returns a tweakable circular correlation robust hash
    /// given an input `Block`.
    fn tccr_hash(&self, x: &Block, i: &Block) -> Block;

    /// Returns a hash given an input `Block`.
    fn get_hash(&self, input: &[u8]) -> Result<Block, HashError>;
}

/// Represents a structure of hash function based on AES-128 encryption.
#[derive(Clone)]
pub struct AesHash {
    /// `Aes128` object used for hashing.
    key: Block,
}

/// Implementation for `AesHash`.
impl AesHash {
    /// Takes a key `Block` as input to return a new `AesHash` object.
    pub fn new(key: Block) -> AesHash {
        AesHash { key }
    }

    fn aes_call(key: Block, msg: Block) -> Block {
        let keyar = GenericArray::from(key);
        let aes = Aes256Gcm::new(&keyar);
        let noncear = GenericArray::from(AES_NONCE);
        let ciphertext_with_tag = aes.encrypt(&noncear, msg.as_ref()).unwrap();
        let ciphertext = &ciphertext_with_tag[..ciphertext_with_tag.len() - 16];
        let output: Block = ciphertext.try_into().unwrap();
        output
    }

    /// Pads input using Merkle–Damgård-style padding
    /// (msg + 0x80 + zero padding + length in 8 bytes) % 32 = 0
    fn md_pad(input: &[u8]) -> Vec<Block> {
        let input_len_bits = (input.len() as u64) * 8;

        let mut padded = input.to_vec();

        padded.push(0x80);

        while (padded.len() + 8) % 32 != 0 {
            padded.push(0x00);
        }

        padded.extend_from_slice(&input_len_bits.to_be_bytes());

        // Convert to blocks
        assert!(padded.len() % 32 == 0);
        padded
            .chunks(32)
            .map(|chunk| {
                let mut block = [0u8; 32];
                block.copy_from_slice(chunk);
                block
            })
            .collect()
    }

    /// Davies–Meyer hash: H_i = E(M_i, H_{i-1}) ⊕ H_{i-1}
    pub fn hash(&self, input: &[u8]) -> Block {
        let padded_blocks = AesHash::md_pad(input);

        let mut h = self.key; // Initial value: all-zero block

        for block in padded_blocks {
            let cipher_output = AesHash::aes_call(block, h);
            for i in 0..32 {
                h[i] ^= cipher_output[i]; // XOR output with previous hash
            }
        }
        h
    }
}

/// Implements the `HashFunction` trait for `AesHash`.
impl HashFunction for AesHash {
    /// Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// The function computes `H(x) ⊕ x`.
    fn cr_hash(&self, x: &Block) -> Block {
        let hashval = self.get_hash(x).unwrap();
        xor_blocks(hashval, x.to_owned())
    }

    /// Circular Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// The function computes `cr_hash(σ(x))` where `σ(xL || xR) = (xR ⊕ xL) || xL`
    fn ccr_hash(&self, x: &Block) -> Block {
        let mut y = [0u8; 32];
        for i in 0..16 {
            y[i] = x[i] ^ x[i + 16];
        }
        y[16..32].copy_from_slice(&x[16..32]);
        self.cr_hash(&y)
    }

    /// Tweakable circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.4).
    ///
    /// The function computes `H(H(x) ⊕ i) ⊕ H(x)`.
    fn tccr_hash(&self, x: &Block, i: &Block) -> Block {
        let hash1 = self.get_hash(x).unwrap();
        let y = xor_blocks(hash1, i.to_owned());
        let hash2 = self.get_hash(&y).unwrap();
        xor_blocks(hash1, hash2)
    }

    /// Implementation of the `get_hash` function for a `AesHash`.
    fn get_hash(&self, input: &[u8]) -> Result<Block, HashError> {
        let result = self.hash(input);
        Ok(result)
    }

    /// Implementation of the `initialize` function for a `AesHash`.
    fn initialize(&mut self, key: Block) {
        self.key = key;
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
            253, 30, 201, 134, 123, 192, 96, 252, 172, 151, 209, 103, 59, 101, 203, 233, 227, 100,
            67, 110, 110, 146, 144, 85, 217, 59, 6, 118, 119, 182, 209, 188,
        ];
        let required_output2 = [
            106, 127, 246, 29, 159, 172, 238, 129, 13, 40, 232, 134, 53, 201, 156, 189, 115, 157,
            92, 224, 115, 121, 125, 184, 101, 20, 250, 17, 187, 179, 205, 114,
        ];

        assert_eq!(output1, required_output1);
        assert_eq!(output2, required_output2);
    }
}
