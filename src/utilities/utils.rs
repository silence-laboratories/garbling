use super::types::Block;

/// Returns the bitwise xor, given two 128-bit blocks
pub fn xor_blocks(array1: Block, array2: Block) -> Block {
    let mut output = Block::default();
    for i in 0..array1.len() {
        output[i] = array1[i] ^ array2[i];
    }
    output
}

/// Converts a vector of boolean values to a hexadecimal string.
pub fn bool_vec_to_hex(vec: Vec<bool>) -> String {
    let mut hex_string = String::new();

    // Process the vector in chunks of 4 bits
    for chunk in vec.chunks(4) {
        let mut value = 0;

        // Convert each bit to its corresponding position in a nibble (4 bits)
        for (i, bit) in chunk.iter().enumerate() {
            if *bit {
                value |= 1 << (3 - i); // Shift bits according to position
            }
        }

        // Convert the 4-bit value to a hex digit
        hex_string.push_str(&format!("{:x}", value));
    }

    hex_string
}

pub fn lsb(value: Block) -> u8 {
    value[0] & 1
}
