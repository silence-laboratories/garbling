use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};
use rand::Rng;

use crate::config::constants::BLOCK;

pub trait HashFunction: Clone {
    fn initialize(&mut self, key: BLOCK);
    fn cr_hash(&self, x: BLOCK) -> BLOCK;
    fn ccr_hash(&self, x: BLOCK) -> BLOCK;
    fn tccr_hash(&self, x: BLOCK, i: BLOCK) -> BLOCK;
    fn get_random_hash(&self) -> BLOCK;
    fn get_hash(&self, x: &[u8]) -> BLOCK;
}


#[derive(Clone)]
pub struct AesHash {
    aes: Aes128,
}

impl AesHash {
    pub fn new(key: BLOCK) -> AesHash {
        let aes = Aes128::new(&GenericArray::from(key));
        AesHash {aes}
    }
}

impl HashFunction for AesHash {
    fn cr_hash(&self, x: BLOCK) -> BLOCK {
        let mut output = GenericArray::from(x);
        self.aes.encrypt_block(&mut output);
        let output_needed: BLOCK = output.try_into().expect("Conversion Failed!!!");
        output_needed
    }

    fn ccr_hash(&self, x: BLOCK) -> BLOCK {
        let mut y = [0u8; 16];
        for i in 0..8 {
            y[i] = x[i] ^ x[i+8];
        }
        for i in 8..16 {
            y[i] = x[i];
        }
        self.cr_hash(y)
    } 

    fn tccr_hash(&self, x: BLOCK, i: BLOCK) -> BLOCK {
        let mut y = GenericArray::from(x);
        self.aes.encrypt_block(&mut y);
        let mut block: BLOCK= y.try_into().expect("Conversion Failed!!!");
        let mut t = [0u8; 16];
        for m in 0..16 {
            t[m] = block[m] ^ i[m];
        }
        let mut z = GenericArray::from(t);
        self.aes.encrypt_block(&mut z);
        let bz: BLOCK = z.try_into().expect("Conversion Failed!!!");
        for m in 0..16 {
            block[m] = bz[m] ^ block[m]
        }
        block
    }

    fn get_random_hash(&self) -> BLOCK {
        let mut rng = rand::thread_rng(); 
        let bytes: BLOCK = rng.gen();
        let mut output = GenericArray::from(bytes);
        self.aes.encrypt_block(&mut output);
        let output_needed: BLOCK = output.try_into().expect("Conversion Failed!!!");
        output_needed
    }

    fn get_hash(&self, input: &[u8]) -> BLOCK {
        let mut previous_block = GenericArray::from([0u8; 16]); // Initialize to zero for CBC
        let mut output_block = GenericArray::from([0u8; 16]);

        if input.len() % 16 != 0 {
            println!("Invalid length input!!!!");
            return  [0u8; 16];
        }

        for chunk in input.chunks_exact(16) {
            let mut block = GenericArray::clone_from_slice(chunk);

            // XOR with the previous block (CBC chaining)
            for i in 0..16 {
                block[i] ^= previous_block[i];
            }

            // Encrypt the block
            self.aes.encrypt_block(&mut block);

            // Update the previous block
            previous_block = block;
        }

        output_block.copy_from_slice(&previous_block);

        // Return the final encrypted block as the CBC-MAC
        let mut result = [0u8; 16];
        result.copy_from_slice(&output_block);

        result
    }
    
    fn initialize(&mut self, key: BLOCK) {
        self.aes = Aes128::new(&GenericArray::from(key));
    }
}