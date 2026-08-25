// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use subtle::ConstantTimeEq;

use super::types::Block;

/// Returns the bitwise xor, given two 128-bit blocks
#[inline(always)]
pub fn xor_blocks(array1: &Block, array2: &Block) -> Block {
    std::array::from_fn(|i| array1[i] ^ array2[i])
}

/// Compares two blocks in constant time.
///
/// Use this in place of `==` wherever one of the operands is a secret, such
/// as a zero label or a commitment witness.
#[inline]
pub fn ct_eq(a: &Block, b: &Block) -> bool {
    a.ct_eq(b).into()
}

/// Returns whether `x` equals `a` or `b`, in constant time.
///
/// Both comparisons are always performed and combined without branching, so
/// neither the result nor which of the two matched is revealed by timing.
#[inline]
pub fn ct_eq_either(x: &Block, a: &Block, b: &Block) -> bool {
    (x.ct_eq(a) | x.ct_eq(b)).into()
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
        hex_string.push_str(&format!("{value:x}"));
    }

    hex_string
}

#[inline(always)]
pub fn lsb(value: &Block) -> u8 {
    value[0] & 1
}
