// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt},
    Aes128,
};
use aes_gcm::KeyInit;

use crate::utilities::{
    hash_function::HashFunction,
    types::{Block, BLOCK_SIZE},
    utils::xor_blocks,
};

pub fn double_gf2_128_bytes(x: &Block) -> Block {
    let mut result = [0u8; 16];
    let mut carry = 0u8;

    for i in (0..16).rev() {
        let byte = x[i];
        result[i] = (byte << 1) | carry;
        carry = (byte & 0x80) >> 7;
    }

    // If the MSB (bit 127) was set, reduce modulo x^128 + x^7 + x^2 + x + 1
    if carry != 0 {
        result[15] ^= 0x87;
    }

    result
}

/// Represents a structure of hash function based on AES-128 encryption.
#[derive(Clone)]
pub struct AesGarbleHash {
    /// `Aes128` object used for hashing.
    key: Block,
}

/// Implementation for `AesGarbleHash`.
impl AesGarbleHash {
    /// Takes a key `Block` as input to return a new `AesGarbleHash` object.
    pub fn new(key: Block) -> AesGarbleHash {
        AesGarbleHash { key }
    }

    fn aes_call(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
        let keyar = GenericArray::from(key);
        let aes = Aes128::new(&keyar);
        let mut msgar = GenericArray::from(msg);
        aes.encrypt_block(&mut msgar);
        msgar.into()
    }

    pub fn hash(&self, input: &[u8]) -> Block {
        // let padded_blocks = AesGarbleHash::md_pad(input);
        assert!(
            input.len() == BLOCK_SIZE,
            "input length inconsistent. expected {}, found {}",
            BLOCK_SIZE,
            input.len()
        );

        // to be changed for reduce block size.
        let h = self.key;
        let b = input[0..16]
            .to_owned()
            .try_into()
            .expect("Conversion failed");

        // for block in padded_blocks {
        let cipher_output = AesGarbleHash::aes_call(b, h);

        // to be changed for reduce block size
        let mut out = Block::default();
        out.copy_from_slice(&cipher_output);
        out
    }
}

/// Implements the `HashFunction` trait for `AesGarbleHash`.
impl HashFunction for AesGarbleHash {
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
        y[BLOCK_SIZE / 2..BLOCK_SIZE]
            .copy_from_slice(&x[BLOCK_SIZE / 2..BLOCK_SIZE]);
        self.cr_hash(&y)
    }

    /// Tweakable circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.4).
    ///
    /// The function computes `H(H(x) ⊕ i) ⊕ H(x)`.
    fn tccr_hash(&self, x: &Block, i: &Block) -> Block {
        // let two = GF2_256(U256::ONE + U256::ONE);
        // let xval = GF2_256(U256::from_be_bytes(*x));
        // let ival = GF2_256(U256::from_be_bytes(*i));
        // let kval = xval.mul(two).add(ival);
        // self.get_hash(&kval.0.to_be_bytes()).unwrap()

        self.get_hash(&xor_blocks(&double_gf2_128_bytes(x), i))
    }

    /// Implementation of the `get_hash` function for a `AesGarbleHash`.
    fn get_hash(&self, input: &[u8]) -> Block {
        self.hash(input)
    }

    /// Implementation of the `initialize` function for a `AesGarbleHash`.
    fn initialize(&mut self, key: Block) {
        self.key = key;
    }
}
