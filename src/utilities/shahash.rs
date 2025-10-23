// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use sha2::{Digest, Sha512};

use crate::utilities::types::BLOCK_SIZE;

use super::{hash_function::HashFunction, types::Block, utils::xor_blocks};

#[derive(Clone, Debug, Default)]
pub struct Sha512Hash {}

impl Sha512Hash {
    pub fn new() -> Self {
        Sha512Hash {}
    }
}

impl HashFunction for Sha512Hash {
    fn initialize(&mut self, _key: Block) {}

    fn cr_hash(&self, x: &Block) -> Block {
        let hashval = self.get_hash(x);
        xor_blocks(&hashval, x)
    }

    fn ccr_hash(&self, x: &Block) -> Block {
        let mut y = Block::default();
        for i in 0..BLOCK_SIZE / 2 {
            y[i] = x[i] ^ x[i + BLOCK_SIZE / 2];
        }
        y[BLOCK_SIZE / 2..BLOCK_SIZE]
            .copy_from_slice(&x[BLOCK_SIZE / 2..BLOCK_SIZE]);
        self.cr_hash(&y)
    }

    fn tccr_hash(&self, x: &Block, i: &Block) -> Block {
        let hash1 = self.get_hash(x);
        let y = xor_blocks(&hash1, i);
        let hash2 = self.get_hash(&y);
        xor_blocks(&hash1, &hash2)
    }

    fn get_hash(&self, input: &[u8]) -> Block {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result: [u8; BLOCK_SIZE * 4] = hasher.finalize().into();
        let mut output = Block::default();
        output.copy_from_slice(&result[BLOCK_SIZE * 3..BLOCK_SIZE * 4]);

        output
    }
}
