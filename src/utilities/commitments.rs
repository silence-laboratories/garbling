use crate::{config::constants::Block, utilities::hash_function::HashFunction};

pub trait Commitment {
    fn commit(&self, message: Block, witness: Block) -> Block;
    fn verify(&self, message: Block, witness: Block, commmitment: Block) -> bool;
}

pub struct HashCommitment<H: HashFunction> {
    hash: H,
}

impl<H: HashFunction> HashCommitment<H> {
    pub fn new(hash: H) -> Self {
        HashCommitment { hash }
    }
}

impl<H: HashFunction> Commitment for HashCommitment<H> {
    fn commit(&self, message: Block, witness: Block) -> Block {
        let mut temp = [0u8; 32];
        temp[..16].copy_from_slice(&message);
        temp[16..(16 + 16)].copy_from_slice(&witness);
        self.hash.get_hash(&temp)
    }

    fn verify(&self, message: Block, witness: Block, commitment: Block) -> bool {
        let mut temp = [0u8; 32];
        temp[..16].copy_from_slice(&message);
        temp[16..(16 + 16)].copy_from_slice(&witness);
        self.hash.get_hash(&temp) == commitment
    }
}
