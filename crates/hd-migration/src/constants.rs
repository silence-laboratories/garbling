// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use k256::elliptic_curve::Curve;

pub const SECP256_K1_Q: k256::U256 = k256::Secp256k1::ORDER;

// pub const X25519_Q: U256 =
//     U256::from_be_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

/// msg1 tag for setup protocol
pub const RECONSTRUCT_SHAMIR_MSG1: u32 = 201;

/// msg2 tag for setup protocol
pub const RECONSTRUCT_SHAMIR_MSG2: u32 = 217;

/// msg1 tag for yao to scalar rss protocol
pub const YAO_TO_RSS_MSG1: u32 = 212;

/// msg2 tag for yao to scalar rss protocol
pub const YAO_TO_RSS_MSG2: u32 = 213;

/// msg3 tag for yao to scalar rss protocol
pub const YAO_TO_RSS_MSG3: u32 = 214;

/// msg4 tag for yao to scalar rss protocol
pub const YAO_TO_RSS_MSG4: u32 = 215;

/// msg4 tag for yao to scalar rss protocol
pub const COMMON_RAND_MSG: u32 = 219;
