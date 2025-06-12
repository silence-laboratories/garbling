use crate::utilities::{hash_function::HashFunction, types::BLOCK_SIZE};

use super::types::Block;

/// Trait for any `Commitment` scheme which implements commit
/// and the verify function
pub trait Commitment {
    /// Returns a cryptographic commitment given a message and witness `Block`s.
    fn commit(&self, message: Block, witness: Block) -> Block;

    /// Returns whether a given commitment `Block` is consistent with
    /// a given message and witness `Block`.
    fn verify(&self, message: Block, witness: Block, commitment: Block) -> bool;
}

/// Represents a structure composed of a hash function.
/// This structure is used to implement a commitment scheme.
pub struct HashCommitment<H: HashFunction> {
    /// `HashFunction` object used for creating and verifying commitments.
    hash: H,
}

/// Implementation for `HashCommitment`.
impl<H: HashFunction> HashCommitment<H> {
    /// Takes a `HashFunction` object as input to
    /// return a new `HashCommitment` object
    pub fn new(hash: H) -> Self {
        HashCommitment { hash }
    }
}

/// Implements the `BinaryOperations` trait for `BinaryEvaluator`.
impl<H: HashFunction> Commitment for HashCommitment<H> {
    /// Implementation of the `commit` function for a `HashCommitment`
    fn commit(&self, message: Block, witness: Block) -> Block {
        let mut temp = [0u8; BLOCK_SIZE * 2];
        temp[..BLOCK_SIZE].copy_from_slice(&message);
        temp[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&witness);
        self.hash.get_hash(&temp).unwrap()
    }

    /// Implementation of the `verify` function for a `HashCommitment`
    fn verify(&self, message: Block, witness: Block, commitment: Block) -> bool {
        let mut temp = [0u8; BLOCK_SIZE * 2];
        temp[..BLOCK_SIZE].copy_from_slice(&message);
        temp[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&witness);
        self.hash.get_hash(&temp).unwrap() == commitment
    }
}

#[cfg(test)]
mod tests {
    use crate::utilities::{
        shahash::Sha512Hash,
        types::{Block, BLOCK_SIZE},
    };

    use super::{Commitment, HashCommitment};

    #[test]
    fn test_commitments() {
        let hash = Sha512Hash::new();

        let commitment = HashCommitment::new(hash);

        let message1 = Block::default();
        let witness1 = Block::default();
        let commitment1 = commitment.commit(message1, witness1);
        assert!(commitment.verify(message1, witness1, commitment1));

        let message2 = [1u8; BLOCK_SIZE];
        let witness2 = [1u8; BLOCK_SIZE];
        let commitment2 = commitment.commit(message2, witness2);
        assert!(commitment.verify(message2, witness2, commitment2));
    }
}
