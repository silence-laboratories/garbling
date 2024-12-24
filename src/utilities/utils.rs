use crate::config::constants::Block;

pub fn xor_blocks(array1: Block, array2: Block) -> Block {
    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = array1[i] ^ array2[i];
    }
    output
}
