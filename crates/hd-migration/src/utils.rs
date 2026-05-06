// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::borrow::Borrow;

#[cfg(test)]
use k256::{elliptic_curve::subtle::ConstantTimeEq, NonZeroScalar, Scalar};

use crate::types::HardDerivationError;

#[cfg(test)]
pub(crate) use garbled_circuit::functionality::utils::run_init;

/// Converts `u8` values to an iterator of `bool` values.
pub(crate) fn u8_vec_to_bool_vec<I, B>(bytes: I) -> impl Iterator<Item = bool>
where
    I: IntoIterator<Item = B>,
    B: Borrow<u8>,
{
    bytes.into_iter().flat_map(|byte| {
        let byte = *byte.borrow();
        (0..8).rev().map(move |i| ((byte >> i) & 1) != 0)
    })
}

/// Converts `bool` values to a vector of `u8` values.
pub(crate) fn bool_vec_to_u8_vec<I, B>(
    bits: I,
) -> Result<Vec<u8>, HardDerivationError>
where
    I: IntoIterator<Item = B>,
    B: Borrow<bool>,
{
    let mut output = Vec::new();
    let mut byte = 0u8;
    let mut bit_count = 0usize;

    for bit in bits {
        if *bit.borrow() {
            byte |= 1 << (7 - (bit_count % 8)); // MSB-first
        }

        bit_count += 1;
        if bit_count % 8 == 0 {
            output.push(byte);
            byte = 0;
        }
    }

    if bit_count % 8 != 0 {
        return Err(HardDerivationError::InvalidMessage);
    }

    Ok(output)
}

/// Converts a vector of bytes to a vector of bool values in little endian
pub(crate) fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    // go from least significant byte to most significant
    for &byte in bytes.iter().rev() {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }

    bits
}

#[cfg(test)]
pub(crate) fn get_lagrange_coeff_list<'a, K, T>(
    party_points: &'a [T],
    eval_point: &'a Scalar,
    k: K,
) -> impl Iterator<Item = Scalar> + 'a
where
    K: Fn(&T) -> &NonZeroScalar + 'a,
{
    party_points.iter().map(move |x_i| {
        let x_i = k(x_i);
        let mut coeff = Scalar::ONE;
        for x_j in party_points {
            let x_j = k(x_j);
            if x_i.ct_ne(x_j).into() {
                let num = x_j.sub(eval_point);
                let sub = x_j.sub(x_i);
                // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
                coeff *= num.as_ref() * &sub.invert().unwrap();
            }
        }
        coeff
    })
}

#[cfg(test)]
pub(crate) fn get_evaluation(
    party_points: &[NonZeroScalar],
    evals: &[Scalar],
    eval_point: &Scalar,
) -> Scalar {
    let lcoeff = get_lagrange_coeff_list(party_points, eval_point, |x| x);

    evals
        .iter()
        .zip(lcoeff)
        .fold(Scalar::ZERO, |acc, (ev, lc)| acc + *ev * lc)
}
