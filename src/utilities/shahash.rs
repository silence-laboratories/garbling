use sha2::{Sha512, Digest};

use crate::config::util_errors::HashError;

use super::{hash_function::HashFunction, types::Block, utils::xor_blocks};


#[derive(Clone, Debug, Default)]
pub struct Sha512Hash {
}

impl Sha512Hash {
    pub fn new() -> Self {
        Sha512Hash {}
    }
}

impl HashFunction for Sha512Hash {
    fn initialize(&mut self, _key: Block) {
    }

    fn cr_hash(&self, x: &Block) -> Block {
        let hashval = self.get_hash(x).unwrap();
        xor_blocks(hashval, x.to_owned())
    }

    fn ccr_hash(&self, x: &Block) -> Block {
        let mut y = [0u8; 32];
        for i in 0..16 {
            y[i] = x[i] ^ x[i + 16];
        }
        y[16..32].copy_from_slice(&x[16..32]);
        self.cr_hash(&y)
    }

    fn tccr_hash(&self, x: &Block, i: &Block) -> Block {
        let hash1 = self.get_hash(x).unwrap();
        let y = xor_blocks(hash1, i.to_owned());
        let hash2 = self.get_hash(&y).unwrap();
        xor_blocks(hash1, hash2)
    }

    fn get_hash(&self, input: &[u8]) -> Result<Block, HashError> {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result: [u8; 64] = hasher.finalize().into();
        let mut output = Block::default();
        output.copy_from_slice(&result[32..64]);
        Ok(output)
    }
}