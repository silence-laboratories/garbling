// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::utilities::{hash_function::HashFunction, utils::ct_eq};

use super::types::Block;

/// Trait for any `Commitment` scheme which implements commit
/// and the verify function
pub trait Commitment {
    /// Returns a cryptographic commitment given a message and witness `Block`s.
    fn commit(&self, message: &Block, witness: &Block) -> Block;

    /// Returns whether a given commitment `Block` is consistent with
    /// a given message and witness `Block`.
    fn verify(
        &self,
        message: &Block,
        witness: &Block,
        commitment: &Block,
    ) -> bool;
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
    #[inline(always)]
    fn commit(&self, message: &Block, witness: &Block) -> Block {
        self.hash.get_hash(&[*message, *witness].concat())
    }

    /// Implementation of the `verify` function for a `HashCommitment`
    #[inline(always)]
    fn verify(
        &self,
        message: &Block,
        witness: &Block,
        commitment: &Block,
    ) -> bool {
        ct_eq(
            &self.hash.get_hash(&[*message, *witness].concat()),
            commitment,
        )
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
        let commitment1 = commitment.commit(&message1, &witness1);
        assert!(commitment.verify(&message1, &witness1, &commitment1));

        let message2 = [1u8; BLOCK_SIZE];
        let witness2 = [1u8; BLOCK_SIZE];
        let commitment2 = commitment.commit(&message2, &witness2);
        assert!(commitment.verify(&message2, &witness2, &commitment2));
    }
}
