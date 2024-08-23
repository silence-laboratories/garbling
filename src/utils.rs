use crate::config::constants::BLOCK;

pub fn xor_blocks(array1: BLOCK, array2: BLOCK) -> BLOCK {
    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = array1[i] ^ array2[i];
    }
    output
}