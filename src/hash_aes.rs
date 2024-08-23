use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};
use rand::Rng;

use crate::config::constants::BLOCK;

#[derive(Clone)]
pub struct AesHash {
    aes: Aes128,
}

impl AesHash {
    pub fn new(key: BLOCK) -> AesHash {
        let aes = Aes128::new(&GenericArray::from(key));
        AesHash {aes}
    }

    pub fn cr_hash(&self, x: BLOCK) -> BLOCK {
        let mut output = GenericArray::from(x);
        self.aes.encrypt_block(&mut output);
        let output_needed: BLOCK = output.try_into().expect("Conversion Failed!!!");
        output_needed
    }

    pub fn ccr_hash(&self, x: BLOCK) -> BLOCK {
        let mut y = [0u8; 16];
        for i in 0..8 {
            y[i] = x[i] ^ x[i+8];
        }
        for i in 8..16 {
            y[i] = x[i];
        }
        self.cr_hash(y)
    } 

    pub fn tccr_hash(&self, x: BLOCK, i: BLOCK) -> BLOCK {
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

    pub fn get_random_hash(&self) -> BLOCK {
        let mut rng = rand::thread_rng(); 
        let bytes: BLOCK = rng.gen();
        let mut output = GenericArray::from(bytes);
        self.aes.encrypt_block(&mut output);
        let output_needed: BLOCK = output.try_into().expect("Conversion Failed!!!");
        output_needed
    }
}

