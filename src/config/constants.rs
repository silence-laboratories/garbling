// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub const INPUT_YAO_FUNC_MSG1: u32 = 200;

pub const INPUT_YAO_FROM_FUNC_MSG1: u32 = 201;
pub const INPUT_YAO_FROM_FUNC_MSG2: u32 = 202;
pub const INPUT_YAO_FROM_FUNC_MSG3: u32 = 203;

/// msg1 tag for input yao from all protocol
pub const INPUT_YAO_FROM_ALL_MSG1: u32 = 216;

/// msg2 tag for input yao from all protocol
pub const INPUT_YAO_FROM_ALL_MSG2: u32 = 217;

/// msg1 tag for input yao from all protocol
pub const INPUT_YAO_FROM_ALL_MSG3: u32 = 218;

pub const OUTPUT_YAO_FUNC_MSG1: u32 = 204;
pub const OUTPUT_YAO_FUNC_MSG2: u32 = 205;

pub const OUTPUT_YAO_TO_FUNC_MSG1: u32 = 206;

pub const SETUP_YAO_FUNC_MSG1: u32 = 207;
pub const SETUP_YAO_FUNC_MSG2: u32 = 208;
pub const SETUP_YAO_FUNC_MSG3: u32 = 219;

pub const YAO_CIRC_EVAL_FUNC_MSG1: u32 = 209;
pub const YAO_CIRC_EVAL_FUNC_MSG2: u32 = 210;

pub const B2Y_FUNC_MSG1: u32 = 211;

pub const Y2B_FUNC_MSG1: u32 = 212;
pub const Y2B_FUNC_MSG2: u32 = 213;
pub const Y2B_FUNC_MSG3: u32 = 214;
pub const Y2B_FUNC_MSG4: u32 = 215;

#[cfg(test)]
pub const AES128_CIRCUIT: &str = include_str!("../../circuits/aes128.txt");
