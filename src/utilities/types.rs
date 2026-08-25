// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::sync::atomic::{compiler_fence, Ordering};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroize;

use crate::utilities::utils::xor_blocks;

pub const BLOCK_SIZE: usize = 16;

/// Represents a 128-bit block of data.
///
/// This is used for representing the output of hashes for
/// the garbled circuit.
pub type Block = [u8; BLOCK_SIZE];

pub const ZBLOCK: Block = [0u8; BLOCK_SIZE];

pub enum MapArg<'a, T> {
    Scalar(T),
    Vector(&'a [T]),
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct YaoGarblerShare {
    pub delta: Block,
    pub f_label: Block,
}

/// `YaoGarblerShare` is `Copy`, so it cannot implement `Drop` and therefore
/// cannot be wiped automatically. Holders of long lived garbler shares should
/// call this before dropping them.
impl Zeroize for YaoGarblerShare {
    fn zeroize(&mut self) {
        self.delta.zeroize();
        self.f_label.zeroize();
    }
}

impl YaoGarblerShare {
    pub fn xor(&self, other: &Self) -> Self {
        assert_eq!(self.delta, other.delta);
        Self {
            delta: self.delta,
            f_label: xor_blocks(&self.f_label, &other.f_label),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct YaoEvaluatorShare {
    pub label: Block,
}

impl Zeroize for YaoEvaluatorShare {
    fn zeroize(&mut self) {
        self.label.zeroize();
    }
}

impl YaoEvaluatorShare {
    pub fn xor(&self, other: &Self) -> Self {
        Self {
            label: xor_blocks(&self.label, &other.label),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum YaoShare {
    G(YaoGarblerShare),
    E(YaoEvaluatorShare),
}

impl From<YaoGarblerShare> for YaoShare {
    fn from(share: YaoGarblerShare) -> Self {
        YaoShare::G(share)
    }
}

impl From<YaoEvaluatorShare> for YaoShare {
    fn from(share: YaoEvaluatorShare) -> Self {
        YaoShare::E(share)
    }
}

impl Zeroize for YaoShare {
    fn zeroize(&mut self) {
        match self {
            YaoShare::G(share) => share.zeroize(),
            YaoShare::E(share) => share.zeroize(),
        }
    }
}

impl YaoShare {
    pub fn xor(&self, other: &Self) -> Self {
        match (self, other) {
            (YaoShare::G(lhs), YaoShare::G(rhs)) => YaoShare::G(lhs.xor(rhs)),
            (YaoShare::E(lhs), YaoShare::E(rhs)) => YaoShare::E(lhs.xor(rhs)),
            _ => panic!("YaoShare::xor requires matching share variants"),
        }
    }

    pub fn as_garbler(&self) -> &YaoGarblerShare {
        match self {
            YaoShare::G(share) => share,
            _ => panic!("Garbler must hold a garbler Yao share"),
        }
    }

    pub fn as_evaluator(&self) -> &YaoEvaluatorShare {
        match self {
            YaoShare::E(share) => share,
            _ => panic!("Evaluator must hold an evaluator Yao share"),
        }
    }

    pub fn into_garbler(self) -> Option<YaoGarblerShare> {
        match self {
            YaoShare::G(share) => Some(share),
            _ => None,
        }
    }

    pub fn into_evaluator(self) -> Option<YaoEvaluatorShare> {
        match self {
            YaoShare::E(share) => Some(share),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct GarblerSetup {
    pub comm_crs: Block,
    pub prf: ChaCha8Rng,
    pub delta: Block,
    pub party_id: usize,
}

impl GarblerSetup {
    /// Clears the global offset and resets the label PRF.
    ///
    /// `delta` is the value whose disclosure breaks the whole construction,
    /// and the PRF state reproduces every wire label of the session, so
    /// neither should outlive the setup in freed memory. This runs
    /// automatically on drop; call it directly to wipe earlier.
    pub fn wipe(&mut self) {
        self.delta.zeroize();
        self.comm_crs.zeroize();

        // `rand_chacha` implements neither `Zeroize` nor `Drop`, so the
        // ChaCha state cannot be wiped through its public API. Overwriting it
        // with a zero-seeded generator replaces the key and counter in place;
        // the fence keeps the compiler from discarding the write as dead.
        self.prf = ChaCha8Rng::from_seed([0u8; 32]);
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for GarblerSetup {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Debug)]
pub struct EvaluatorSetup {
    pub comm_crs: Block,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum YaoSetup {
    G(GarblerSetup),
    E(EvaluatorSetup),
}

impl YaoSetup {
    pub fn as_garbler(&self) -> Option<&GarblerSetup> {
        match self {
            YaoSetup::G(g) => Some(g),
            _ => None,
        }
    }

    pub fn as_garbler_mut(&mut self) -> Option<&mut GarblerSetup> {
        match self {
            YaoSetup::G(g) => Some(g),
            _ => None,
        }
    }

    pub fn as_evaluator(&self) -> Option<&EvaluatorSetup> {
        match self {
            YaoSetup::E(e) => Some(e),
            _ => None,
        }
    }

    pub fn rng(&mut self) -> Option<&mut ChaCha8Rng> {
        match self {
            YaoSetup::G(g) => Some(&mut g.prf),
            _ => None,
        }
    }
}

impl From<GarblerSetup> for YaoSetup {
    fn from(value: GarblerSetup) -> Self {
        YaoSetup::G(value)
    }
}

impl From<EvaluatorSetup> for YaoSetup {
    fn from(value: EvaluatorSetup) -> Self {
        YaoSetup::E(value)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use zeroize::Zeroize;

    use super::{
        Block, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare, YaoShare,
        BLOCK_SIZE,
    };

    #[test]
    fn zeroize_clears_share_secrets() {
        let mut garbler = YaoGarblerShare {
            delta: [0xa5; BLOCK_SIZE],
            f_label: [0x5a; BLOCK_SIZE],
        };
        garbler.zeroize();
        assert_eq!(garbler.delta, Block::default());
        assert_eq!(garbler.f_label, Block::default());

        let mut evaluator = YaoEvaluatorShare {
            label: [0x5a; BLOCK_SIZE],
        };
        evaluator.zeroize();
        assert_eq!(evaluator.label, Block::default());

        let mut share = YaoShare::G(YaoGarblerShare {
            delta: [0xa5; BLOCK_SIZE],
            f_label: [0x5a; BLOCK_SIZE],
        });
        share.zeroize();
        assert_eq!(*share.as_garbler(), YaoGarblerShare::default());
    }

    /// Dropping a `GarblerSetup` must clear the offset and reset the label
    /// PRF, so neither survives in the memory the setup occupied.
    #[test]
    fn dropping_garbler_setup_clears_delta_and_prf() {
        let mut setup = GarblerSetup {
            comm_crs: [0x11; BLOCK_SIZE],
            prf: ChaCha8Rng::from_seed([7; 32]),
            delta: [0xa5; BLOCK_SIZE],
            party_id: 0,
        };

        // What the PRF would have produced had it not been reset.
        let mut live = Block::default();
        {
            use rand::RngCore;
            ChaCha8Rng::from_seed([7; 32]).fill_bytes(&mut live);
        }

        // `Drop` delegates to `wipe`, so this exercises the same code.
        setup.wipe();

        assert_eq!(setup.delta, Block::default());
        assert_eq!(setup.comm_crs, Block::default());

        let mut after = Block::default();
        {
            use rand::RngCore;
            setup.prf.fill_bytes(&mut after);
        }
        assert_ne!(after, live);
    }
}
