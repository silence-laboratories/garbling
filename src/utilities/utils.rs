// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use subtle::{Choice, ConstantTimeEq};

use super::types::Block;

/// Returns the bitwise xor, given two 128-bit blocks
#[inline(always)]
pub fn xor_blocks(array1: &Block, array2: &Block) -> Block {
    std::array::from_fn(|i| array1[i] ^ array2[i])
}

/// Constant-time equality of two blocks.
#[inline(always)]
pub fn blocks_ct_eq(a: &Block, b: &Block) -> Choice {
    a.ct_eq(b)
}

/// Returns whether `label` equals `a` or `b`, in constant time.
///
/// Used when checking that a received Yao label is one of `{W₀, W₀⊕Δ}` without
/// leaking which via early-exit `==` or short-circuit `||`.
#[inline(always)]
pub fn label_in_pair(label: &Block, a: &Block, b: &Block) -> bool {
    bool::from(blocks_ct_eq(label, a) | blocks_ct_eq(label, b))
}

/// Returns whether `label` equals `f_label` or `f_label ⊕ delta`, in constant time.
#[inline(always)]
pub fn label_matches_wire(
    label: &Block,
    f_label: &Block,
    delta: &Block,
) -> bool {
    let other = xor_blocks(f_label, delta);
    label_in_pair(label, f_label, &other)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_in_pair_accepts_either_endpoint() {
        let w0 = [1u8; 16];
        let delta = [2u8; 16];
        let w1 = xor_blocks(&w0, &delta);
        assert!(label_matches_wire(&w0, &w0, &delta));
        assert!(label_matches_wire(&w1, &w0, &delta));
        assert!(!label_matches_wire(&[0xffu8; 16], &w0, &delta));
    }
}
