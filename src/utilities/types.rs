// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::utilities::{label_prf::LabelPrf, utils::xor_blocks};

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

#[derive(Clone, Default, PartialEq)]
pub struct YaoGarblerShare {
    pub delta: Block,
    pub f_label: Block,
}

impl Zeroize for YaoGarblerShare {
    fn zeroize(&mut self) {
        self.delta.zeroize();
        self.f_label.zeroize();
    }
}

impl Drop for YaoGarblerShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for YaoGarblerShare {}

impl fmt::Debug for YaoGarblerShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YaoGarblerShare")
            .field("delta", &"[redacted]")
            .field("f_label", &"[redacted]")
            .finish()
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

#[derive(Clone, Default, PartialEq)]
pub struct YaoEvaluatorShare {
    pub label: Block,
}

impl Zeroize for YaoEvaluatorShare {
    fn zeroize(&mut self) {
        self.label.zeroize();
    }
}

impl Drop for YaoEvaluatorShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for YaoEvaluatorShare {}

impl fmt::Debug for YaoEvaluatorShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YaoEvaluatorShare")
            .field("label", &"[redacted]")
            .finish()
    }
}

impl YaoEvaluatorShare {
    pub fn xor(&self, other: &Self) -> Self {
        Self {
            label: xor_blocks(&self.label, &other.label),
        }
    }
}

#[derive(Clone, PartialEq)]
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

impl Drop for YaoShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for YaoShare {}

impl fmt::Debug for YaoShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YaoShare::G(_) => f.write_str("YaoShare::G([redacted])"),
            YaoShare::E(_) => f.write_str("YaoShare::E([redacted])"),
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
        match &self {
            YaoShare::G(share) => Some(share.clone()),
            _ => None,
        }
    }

    pub fn into_evaluator(self) -> Option<YaoEvaluatorShare> {
        match &self {
            YaoShare::E(share) => Some(share.clone()),
            _ => None,
        }
    }
}

pub struct GarblerSetup {
    /// Evaluator-chosen CRS used only for input commitments.
    pub comm_crs: Block,
    /// Garbler-shared key for circuit garbling / evaluation hashes.
    pub garble_key: Block,
    pub prf: LabelPrf,
    pub delta: Block,
    pub party_id: usize,
}

impl fmt::Debug for GarblerSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GarblerSetup")
            .field("comm_crs", &"[redacted]")
            .field("garble_key", &"[redacted]")
            .field("prf", &self.prf)
            .field("delta", &"[redacted]")
            .field("party_id", &self.party_id)
            .finish()
    }
}

impl GarblerSetup {
    /// Wipes key material held by the setup.
    pub fn wipe(&mut self) {
        self.comm_crs.zeroize();
        self.garble_key.zeroize();
        self.delta.zeroize();
        self.prf.zeroize();
    }
}

impl Drop for GarblerSetup {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub struct EvaluatorSetup {
    /// Evaluator-chosen CRS used only for input commitments.
    pub comm_crs: Block,
    /// Garbler-shared key for circuit garbling / evaluation hashes.
    pub garble_key: Block,
}

impl fmt::Debug for EvaluatorSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvaluatorSetup")
            .field("comm_crs", &"[redacted]")
            .field("garble_key", &"[redacted]")
            .finish()
    }
}

impl EvaluatorSetup {
    pub fn wipe(&mut self) {
        self.comm_crs.zeroize();
        self.garble_key.zeroize();
    }
}

impl Drop for EvaluatorSetup {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[allow(clippy::large_enum_variant)]
pub enum YaoSetup {
    G(GarblerSetup),
    E(EvaluatorSetup),
}

impl fmt::Debug for YaoSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YaoSetup::G(_) => f.write_str("YaoSetup::G([redacted])"),
            YaoSetup::E(_) => f.write_str("YaoSetup::E([redacted])"),
        }
    }
}

impl YaoSetup {
    /// Key used to seed the circuit garbling hash (`AesHash` / `AesGarbleHash`).
    pub fn garble_key(&self) -> Block {
        match self {
            YaoSetup::G(g) => g.garble_key,
            YaoSetup::E(e) => e.garble_key,
        }
    }

    /// Evaluator CRS used to seed input-commitment hashes only.
    pub fn comm_crs(&self) -> Block {
        match self {
            YaoSetup::G(g) => g.comm_crs,
            YaoSetup::E(e) => e.comm_crs,
        }
    }

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

    pub fn rng(&mut self) -> Option<&mut LabelPrf> {
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
    use rand::{RngCore, SeedableRng};

    use super::{
        Block, EvaluatorSetup, GarblerSetup, YaoEvaluatorShare,
        YaoGarblerShare, YaoShare, BLOCK_SIZE,
    };
    use crate::utilities::label_prf::LabelPrf;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn yao_shares_zeroize_on_drop() {
        assert_zeroize_on_drop::<YaoGarblerShare>();
        assert_zeroize_on_drop::<YaoEvaluatorShare>();
        assert_zeroize_on_drop::<YaoShare>();

        let original = YaoShare::G(YaoGarblerShare {
            delta: [0xa5; BLOCK_SIZE],
            f_label: [0x5a; BLOCK_SIZE],
        });
        let clone = original.clone();
        drop(original);
        assert_eq!(
            clone.as_garbler(),
            &YaoGarblerShare {
                delta: [0xa5; BLOCK_SIZE],
                f_label: [0x5a; BLOCK_SIZE],
            }
        );
    }

    #[test]
    fn zeroize_clears_yao_shares() {
        let mut garbler = YaoGarblerShare {
            delta: [0xa5; BLOCK_SIZE],
            f_label: [0x5a; BLOCK_SIZE],
        };
        garbler.zeroize();
        assert_eq!(garbler, YaoGarblerShare::default());

        let mut evaluator = YaoEvaluatorShare {
            label: [0x5a; BLOCK_SIZE],
        };
        evaluator.zeroize();
        assert_eq!(evaluator, YaoEvaluatorShare::default());

        let mut share = YaoShare::G(YaoGarblerShare {
            delta: [0xa5; BLOCK_SIZE],
            f_label: [0x5a; BLOCK_SIZE],
        });
        share.zeroize();
        assert_eq!(share.as_garbler(), &YaoGarblerShare::default());
    }

    #[test]
    fn wipe_clears_setup_key_material() {
        let mut garbler = GarblerSetup {
            comm_crs: [0x11; BLOCK_SIZE],
            garble_key: [0x22; BLOCK_SIZE],
            prf: LabelPrf::from_seed([7; 32]),
            delta: [0xa5; BLOCK_SIZE],
            party_id: 0,
        };
        garbler.wipe();
        assert_eq!(garbler.comm_crs, Block::default());
        assert_eq!(garbler.garble_key, Block::default());
        assert_eq!(garbler.delta, Block::default());

        let mut evaluator = EvaluatorSetup {
            comm_crs: [0x33; BLOCK_SIZE],
            garble_key: [0x44; BLOCK_SIZE],
        };
        evaluator.wipe();
        assert_eq!(evaluator.comm_crs, Block::default());
        assert_eq!(evaluator.garble_key, Block::default());

        // Confirm the old label stream is unavailable after the setup is
        // wiped.
        let mut after = Block::default();
        garbler.prf.fill_bytes(&mut after);
        let mut original = Block::default();
        LabelPrf::from_seed([7; 32]).fill_bytes(&mut original);
        assert_ne!(after, original);
    }
}
