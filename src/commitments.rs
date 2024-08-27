use crate::{config::constants::BLOCK, hash_function::HashFunction};

pub trait Commitment {
    fn commit(&self, message: BLOCK, witness: BLOCK) -> BLOCK;
    fn verify(&self, message: BLOCK, witness: BLOCK, commmitment: BLOCK) -> bool;
}

pub struct HashCommitment<H: HashFunction> {
    hash: H
}

impl<H: HashFunction> HashCommitment<H> {
    pub fn new(hash: H) -> Self {
        HashCommitment {
            hash: hash
        }
    }
}

impl<H: HashFunction> Commitment for HashCommitment<H> {
    fn commit(&self, message: BLOCK, witness: BLOCK) -> BLOCK {
        let mut temp = [0u8; 32];
        for i in 0..16 {
            temp[i] = message[i];
            temp[i+16] = witness[i+16];
        }
        self.hash.get_hash(&temp)
    }

    fn verify(&self, message: BLOCK, witness: BLOCK, commitment: BLOCK) -> bool {
        let mut temp = [0u8; 32];
        for i in 0..16 {
            temp[i] = message[i];
            temp[i+16] = witness[i+16];
        }
        self.hash.get_hash(&temp) == commitment
    }
}

