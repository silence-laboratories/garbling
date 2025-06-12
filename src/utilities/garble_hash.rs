use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt},
    Aes128,
};
use aes_gcm::KeyInit;

use crate::{
    config::util_errors::HashError,
    utilities::{hash_function::HashFunction, types::Block, utils::xor_blocks},
};

pub fn double_gf2_256_bytes(x: Block) -> Block {
    let mut result = Block::default();
    let mut carry = 0u8;

    for i in (0..32).rev() {
        let byte = x[i];
        result[i] = (byte << 1) | carry;
        carry = (byte & 0x80) >> 7;
    }

    // If the MSB (bit 255) was set, reduce modulo x^256 + x^10 + x^5 + x^2 + 1
    if carry != 0 {
        result[28] ^= 0x01 << 2; // x^10
        result[31] ^= 0x01 << 5; // x^5
        result[31] ^= 0x01 << 2; // x^2
        result[31] ^= 0x01 << 0; // x^0
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
            input.len() == 32,
            "input length inconsistent. expected 32, found {}",
            input.len()
        );

        let h1 = self.key[0..16]
            .to_owned()
            .try_into()
            .expect("Conversion failed");
        let b1 = input[0..16]
            .to_owned()
            .try_into()
            .expect("Conversion failed");
        let h2 = self.key[16..32]
            .to_owned()
            .try_into()
            .expect("Conversion failed");
        let b2 = input[16..32]
            .to_owned()
            .try_into()
            .expect("Conversion failed");

        // for block in padded_blocks {
        let cipher_output1 = AesGarbleHash::aes_call(b1, h1);
        let cipher_output2 = AesGarbleHash::aes_call(b2, h2);

        let mut out = Block::default();
        out[0..16].copy_from_slice(&cipher_output1);
        out[16..32].copy_from_slice(&cipher_output2);
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
        let hashval = self.get_hash(x).unwrap();
        xor_blocks(hashval, x.to_owned())
    }

    /// Circular Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// The function computes `cr_hash(σ(x))` where `σ(xL || xR) = (xR ⊕ xL) || xL`
    fn ccr_hash(&self, x: &Block) -> Block {
        let mut y = Block::default();
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
        // let two = GF2_256(U256::ONE + U256::ONE);
        // let xval = GF2_256(U256::from_be_bytes(*x));
        // let ival = GF2_256(U256::from_be_bytes(*i));
        // let kval = xval.mul(two).add(ival);
        // self.get_hash(&kval.0.to_be_bytes()).unwrap()

        self.get_hash(&xor_blocks(double_gf2_256_bytes(*x), *i))
            .unwrap()
    }

    /// Implementation of the `get_hash` function for a `AesGarbleHash`.
    fn get_hash(&self, input: &[u8]) -> Result<Block, HashError> {
        let result = self.hash(input);
        Ok(result)
    }

    /// Implementation of the `initialize` function for a `AesGarbleHash`.
    fn initialize(&mut self, key: Block) {
        self.key = key;
    }
}
