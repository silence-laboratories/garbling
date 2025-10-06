use crate::{
    functionality::utils::{FixedExternalSize, Wrap},
    utilities::utils::xor_blocks,
};

pub const BLOCK_SIZE: usize = 16;

/// Represents a 128-bit block of data.
///
/// This is used for representing the output of hashes for
/// the garbled circuit.
pub type Block = [u8; BLOCK_SIZE];

pub enum MapArg<T> {
    Scalar(T),
    Vector(Vec<T>),
}

pub struct TBlock(Block);

impl Wrap for TBlock {
    fn external_size(&self) -> usize {
        TBlock::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..BLOCK_SIZE].copy_from_slice(&self.0);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut block = Block::default();
        block.copy_from_slice(&buffer[0..BLOCK_SIZE]);
        Some(TBlock(block))
    }
}

impl FixedExternalSize for TBlock {
    const SIZE: usize = BLOCK_SIZE;
}

pub fn block_vec2tblock_vec(x: &[Block]) -> Vec<TBlock> {
    let out: Vec<TBlock> = x.iter().map(|item| TBlock(*item)).collect();
    out
}

pub fn tblock_vec2block_vec(x: &[TBlock]) -> Vec<Block> {
    let out: Vec<Block> = x.iter().map(|item| item.0).collect();
    out
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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GarblerSetup {
    pub comm_crs: Block,
    pub prf_key: [u8; 32],
    pub delta: Block,
}

#[derive(Clone, Debug)]
pub struct EvaluatorSetup {
    pub comm_crs: Block,
}

#[derive(Debug)]
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

    pub fn as_evaluator(&self) -> Option<&EvaluatorSetup> {
        match self {
            YaoSetup::E(e) => Some(e),
            _ => None,
        }
    }
}
