use crate::{config::constants::Block, utilities::hash_function::HashFunction};

pub trait Commitment {
    fn commit(&self, message: Block, witness: Block) -> Block;
    fn verify(&self, message: Block, witness: Block, commitment: Block) -> bool;
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

#[cfg(test)]
mod tests {
    use crate::{config::constants::AES_KEY, utilities::hash_function::AesHash};

    use super::{Commitment, HashCommitment};

    #[test]
    fn test_commitments() {
        let hash = AesHash::new(AES_KEY);

        let commitment = HashCommitment::new(hash);

        let message1 = [0u8; 16];
        let witness1 = [0u8; 16];
        let commitment1 = commitment.commit(message1, witness1);
        assert!(commitment.verify(message1, witness1, commitment1));

        let message2 = [1u8; 16];
        let witness2 = [1u8; 16];
        let commitment2 = commitment.commit(message2, witness2);
        assert!(commitment.verify(message2, witness2, commitment2));
    }
}
