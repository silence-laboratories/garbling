// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand_chacha::ChaCha8Rng;

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
