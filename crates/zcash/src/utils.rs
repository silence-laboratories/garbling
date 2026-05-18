// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub(crate) fn bytes_to_bits_le(
    bytes: &[u8],
) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| ((byte >> i) & 1) == 1))
}

pub(crate) fn bits_to_bytes_le(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |byte, (i, &bit)| {
                if bit {
                    // First bit is LSB (1), last bit is MSB (128)
                    byte | (1 << i)
                } else {
                    byte
                }
            })
        })
        .collect()
}
