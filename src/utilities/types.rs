use sl_compute::transport::proto::{FixedExternalSize, Wrap};

/// Represents a 128-bit block of data.
///
/// This is used for representing the output of hashes for
/// the garbled circuit.
pub type Block = [u8; 32];

pub struct TBlock(Block);

impl Wrap for TBlock {
    fn external_size(&self) -> usize {
        TBlock::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..32].copy_from_slice(&self.0);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut block = Block::default();
        block.copy_from_slice(&buffer[0..32]);
        Some(TBlock(block))
    }
}

impl FixedExternalSize for TBlock {
    const SIZE: usize = 32;
}

pub fn block_vec2tblock_vec(x: &[Block]) -> Vec<TBlock> {
    let out: Vec<TBlock> = x.iter().map(|item| TBlock(*item)).collect();
    out
}

pub fn tblock_vec2block_vec(x: &[TBlock]) -> Vec<Block> {
    let out: Vec<Block> = x.iter().map(|item| item.0).collect();
    out
}

#[derive(Clone, Debug, Default)]
pub struct YaoGarblerShare {
    pub delta: Block,
    pub f_label: Block,
}

#[derive(Clone, Debug, Default)]
pub struct YaoEvaluatorShare {
    pub label: Block,
}

#[derive(Clone, Debug, Default)]
pub struct YaoShare {
    pub g_share: Option<YaoGarblerShare>,
    pub e_share: Option<YaoEvaluatorShare>,
}

#[derive(Clone, Debug, Default)]
pub struct GarblerSetup {
    pub comm_crs: Block,
    pub prf_key: Block,
    pub delta: Block,
}

#[derive(Clone, Debug, Default)]
pub struct EvaluatorSetup {
    pub comm_crs: Block,
}

#[derive(Clone, Debug, Default)]
pub struct YaoSetup {
    pub g_setup: Option<GarblerSetup>,
    pub e_setup: Option<EvaluatorSetup>,
}
