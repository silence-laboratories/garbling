use crate::utilities::types::{Block, BLOCK_SIZE};

#[allow(dead_code)]
/// A constant 128-bit AES key initialized with all zeros.
///
/// This can be used as a default or placeholder key in AES-based encryption.
pub const AES_KEY: Block = [1u8; BLOCK_SIZE];

/// A constant 128-bit AES key initialized with all zeros.
///
/// This can be used as a default or placeholder key in AES-based encryption.
pub const AES_NONCE: [u8; 12] = [1u8; 12];

/// A constant 128-bit hash key initialized with all bytes set to `1`.
///
/// This can be used as a default or placeholder key in cryptographic hash functions.
pub const HASH_KEY: Block = [1u8; BLOCK_SIZE];

pub const INPUT_YAO_FUNC_MSG1: i32 = 200;

pub const INPUT_YAO_FROM_FUNC_MSG1: i32 = 201;
pub const INPUT_YAO_FROM_FUNC_MSG2: i32 = 202;
pub const INPUT_YAO_FROM_FUNC_MSG3: i32 = 203;

/// msg1 tag for input yao from all protocol
pub const INPUT_YAO_FROM_ALL_MSG1: u32 = 216;

/// msg2 tag for input yao from all protocol
pub const INPUT_YAO_FROM_ALL_MSG2: u32 = 217;

/// msg1 tag for input yao from all protocol
pub const INPUT_YAO_FROM_ALL_MSG3: u32 = 218;

pub const OUTPUT_YAO_FUNC_MSG1: i32 = 204;
pub const OUTPUT_YAO_FUNC_MSG2: i32 = 205;

pub const OUTPUT_YAO_TO_FUNC_MSG1: i32 = 206;

pub const SETUP_YAO_FUNC_MSG1: i32 = 207;
pub const SETUP_YAO_FUNC_MSG2: i32 = 208;

pub const YAO_CIRC_EVAL_FUNC_MSG1: i32 = 209;
pub const YAO_CIRC_EVAL_FUNC_MSG2: i32 = 210;

pub const B2Y_FUNC_MSG1: u32 = 211;

pub const Y2B_FUNC_MSG1: u32 = 212;
pub const Y2B_FUNC_MSG2: u32 = 213;
pub const Y2B_FUNC_MSG3: u32 = 214;
pub const Y2B_FUNC_MSG4: u32 = 215;
