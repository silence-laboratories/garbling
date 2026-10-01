// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use blake2::{digest::consts::U16, Blake2b, Digest};

use crate::utilities::{hash_function::HashFunction, types::Block};

/// BLAKE2b with a digest truncated to a single `Block`, i.e. BLAKE2b-128.
type Blake2b128 = Blake2b<U16>;

/// Represents a structure of hash function based on BLAKE2b.
///
/// This is the counterpart of
/// [`AesGarbleHash`](crate::utilities::garble_hash::AesGarbleHash) for
/// deployments that prefer to use Blake2b hash instead of a block cipher.
/// The two differ in more than the primitive. The correlation robustness
/// variants of `AesGarbleHash` wrap AES in the feedforward and doubling
/// constructions needed to build a hash out of a permutation, whereas BLAKE2b
/// is already a hash function, so each variant here is the plain digest of its
/// inputs and adds nothing on top.
///
/// The hash is unkeyed, so, unlike `AesGarbleHash`, it takes no `crs` and
/// [`HashFunction::initialize`] has no effect.
#[derive(Clone, Debug, Default)]
pub struct BlakeGarbleHash {}

/// Implementation for `BlakeGarbleHash`.
impl BlakeGarbleHash {
    /// Returns a new `BlakeGarbleHash` object.
    pub fn new() -> BlakeGarbleHash {
        BlakeGarbleHash {}
    }

    /// Returns the BLAKE2b-128 digest of `parts` concatenated in order.
    fn blake2b(parts: &[&[u8]]) -> Block {
        let mut hasher = <Blake2b128 as Digest>::new();

        for part in parts {
            hasher.update(part);
        }

        hasher.finalize().into()
    }
}

/// Implements the `HashFunction` trait for `BlakeGarbleHash`.
impl HashFunction for BlakeGarbleHash {
    /// Correlation-robust hash function for 128-bit inputs. Any hash
    /// modeled as a random oracle is CCR.
    ///
    /// The function computes `H(x)`.
    fn cr_hash(&self, x: &Block) -> Block {
        self.get_hash(x)
    }

    /// Circular correlation-robust hash function for 128-bit inputs.
    /// Any hash modeled as a random oracle is CCR.
    ///
    /// The function computes `H(x)`.
    fn ccr_hash(&self, x: &Block) -> Block {
        self.get_hash(x)
    }

    /// Tweakable circular correlation robust hash function.
    ///
    /// The function computes `H(x || i)`. Both arguments are fixed-width
    /// `Block`s, so the concatenation is unambiguous and needs no length
    /// framing.
    fn tccr_hash(&self, x: &Block, i: &Block) -> Block {
        Self::blake2b(&[x, i])
    }

    /// Implementation of the `get_hash` function for a `BlakeGarbleHash`.
    fn get_hash(&self, input: &[u8]) -> Block {
        Self::blake2b(&[input])
    }

    /// Implementation of the `initialize` function for a `BlakeGarbleHash`.
    ///
    /// BLAKE2b is used unkeyed here, so there is no key to install.
    fn initialize(&mut self, _key: Block) {}
}
