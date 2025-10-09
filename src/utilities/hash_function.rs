use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes_gcm::{aead::generic_array::GenericArray, KeyInit};

use crate::utilities::types::BLOCK_SIZE;

use super::types::Block;
use super::utils::xor_blocks;

/// Trait for any hash function which implements a secure hash function for
/// garbled circuits.
pub trait HashFunction {
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
    fn get_hash(&self, input: &[u8]) -> Block;
}

/// Represents a structure of hash function based on AES-128 encryption.
#[derive(Clone, Copy)]
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

    fn aes_call(key: Block, msg: [u8; 16]) -> [u8; 16] {
        let keyar = GenericArray::from(key);
        let aes = Aes128::new(&keyar);
        let mut msgar = GenericArray::from(msg);
        aes.encrypt_block(&mut msgar);
        msgar.into()
    }

    /// Pads input using Merkle–Damgård-style padding
    /// (msg + 0x80 + zero padding + length in 8 bytes) % BLOCK_SIZE = 0
    fn md_pad(input: &[u8]) -> Vec<Block> {
        let input_len_bits = (input.len() as u64) * 8;

        let mut padded = input.to_vec();

        padded.push(0x80);

        while (padded.len() + 8) % BLOCK_SIZE != 0 {
            padded.push(0x00);
        }

        padded.extend_from_slice(&input_len_bits.to_be_bytes());

        // Convert to blocks
        assert!(padded.len() % BLOCK_SIZE == 0);
        padded
            .chunks(BLOCK_SIZE)
            .map(|chunk| {
                let mut block = Block::default();
                block.copy_from_slice(chunk);
                block
            })
            .collect()
    }

    // to be changed for reduce block size
    /// Davies–Meyer hash: H_i = E(M_i, H_{i-1}) ⊕ H_{i-1}
    pub fn hash(&self, input: &[u8]) -> Block {
        let padded_blocks = AesHash::md_pad(input);

        let mut h = self.key;

        for block in padded_blocks {
            let cipher_output = AesHash::aes_call(block, h);
            for i in 0..16 {
                h[i] ^= cipher_output[i]; // XOR output with previous hash
            }
        }
        let mut out = Block::default();
        out.copy_from_slice(&h);
        out
    }
}

/// Implements the `HashFunction` trait for `AesHash`.
impl HashFunction for AesHash {
    /// Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// The function computes `H(x) ⊕ x`.
    fn cr_hash(&self, x: &Block) -> Block {
        let hashval = self.get_hash(x);
        xor_blocks(&hashval, x)
    }

    /// Circular Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// The function computes `cr_hash(σ(x))` where `σ(xL || xR) = (xR ⊕ xL) || xL`
    fn ccr_hash(&self, x: &Block) -> Block {
        let mut y = Block::default();
        for i in 0..BLOCK_SIZE / 2 {
            y[i] = x[i] ^ x[i + BLOCK_SIZE / 2];
        }
        y[BLOCK_SIZE / 2..BLOCK_SIZE].copy_from_slice(&x[BLOCK_SIZE / 2..BLOCK_SIZE]);
        self.cr_hash(&y)
    }

    /// Tweakable circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.4).
    ///
    /// The function computes `H(H(x) ⊕ i) ⊕ H(x)`.
    fn tccr_hash(&self, x: &Block, i: &Block) -> Block {
        let hash1 = self.get_hash(x);
        let y = xor_blocks(&hash1, i);
        let hash2 = self.get_hash(&y);
        xor_blocks(&hash1, &hash2)
    }

    /// Implementation of the `get_hash` function for a `AesHash`.
    fn get_hash(&self, input: &[u8]) -> Block {
        self.hash(input)
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
        let input1 = [
            12, 162, 159, 171, 99, 41, 109, 231, 188, 136, 13, 175, 217, 232, 245, 239, 31, 98,
            162, 7, 107, 225, 88, 209, 168, 93, 151, 219, 108, 165, 208, 176, 138, 251, 26, 222,
            208, 10, 222, 35, 145, 101, 76, 5, 1, 166, 11, 75, 192, 73, 215, 27, 61, 225, 131, 246,
            29, 123, 54, 21, 251, 185, 40, 148,
        ];
        let input2 = [
            91, 117, 139, 46, 166, 12, 148, 159, 202, 207, 188, 255, 197, 20, 105, 245, 231, 123,
            40, 30, 81, 29, 115, 244, 83, 231, 83, 26, 70, 31, 69, 4, 16, 204, 166, 244, 5, 169,
            230, 225, 124, 196, 177, 212, 138, 177, 90, 206, 173, 101, 196, 49, 31, 255, 235, 142,
            125, 195, 47, 206, 202, 123, 45, 1,
        ];
        let function = AesHash::new(AES_KEY);

        let output1 = function.get_hash(&input1);
        let output2 = function.get_hash(&input2);

        println!("o1 {:?}\n\no2{:?}", output1, output2);

        let required_output1 = [
            54, 218, 6, 139, 23, 154, 34, 92, 216, 91, 41, 177, 156, 76, 101, 130,
        ];
        let required_output2 = [
            97, 216, 175, 252, 173, 133, 251, 12, 202, 131, 200, 32, 81, 60, 0, 232,
        ];

        assert_eq!(output1, required_output1);
        assert_eq!(output2, required_output2);
    }
}
