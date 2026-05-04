// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::Field;
use pasta_curves::pallas::Scalar;

pub fn get_evaluation(
    party_points: &[Scalar],
    evals: &[Scalar],
    eval_point: &Scalar,
) -> Scalar {
    let lcoeff = get_lagrange_coeff_list(party_points, eval_point, |x| x);

    evals
        .iter()
        .zip(lcoeff)
        .fold(Scalar::ZERO, |acc, (ev, lc)| acc + *ev * lc)
}

pub(crate) fn get_lagrange_coeff_list<'a, K, T>(
    party_points: &'a [T],
    eval_point: &'a Scalar,
    k: K,
) -> impl Iterator<Item = Scalar> + 'a
where
    K: Fn(&T) -> &Scalar + 'a,
{
    party_points.iter().map(move |x_i| {
        let x_i = k(x_i);
        let mut coeff = Scalar::ONE;
        for x_j in party_points {
            let x_j = k(x_j);
            if x_i != x_j {
                let num = x_j.sub(eval_point);
                let sub = x_j.sub(x_i);
                // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
                coeff *= num * sub.invert().unwrap();
            }
        }
        coeff
    })
}

/// Converts a vector of bytes to a vector of bool values in big endian
pub fn bytes_to_bits_be(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    // go from most significant byte to least significant
    for &byte in bytes.iter() {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    bits
}

/// Converts a vector of bytes to a vector of bool values in little endian
pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    // go from least significant byte to most significant
    for &byte in bytes.iter().rev() {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    bits
}

pub fn bits_to_bytes_be(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |byte, (i, &bit)| {
                if bit {
                    // First bit is MSB (128), last bit is LSB (1)
                    byte | (1 << (7 - i))
                } else {
                    byte
                }
            })
        })
        .collect()
}

pub fn bits_to_bytes_le(bits: &[bool]) -> Vec<u8> {
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
