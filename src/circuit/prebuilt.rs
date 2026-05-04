// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::circuit::BinaryCircuit;

// Kept public for the crate's benchmarks, but this remains an internal
// build-artifact decoder and is not a stable public API.
#[doc(hidden)]
pub fn decode(bytes: &[u8]) -> BinaryCircuit {
    BinaryCircuit::from_compact_bytes(bytes)
}

#[cfg(feature = "circuit-sha512")]
pub fn sha512() -> &'static BinaryCircuit {
    use std::sync::OnceLock;

    static CIRCUIT: std::sync::OnceLock<BinaryCircuit> = OnceLock::new();
    CIRCUIT.get_or_init(|| {
        decode(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/circuits/sha512.bin"
        )))
    })
}

#[cfg(feature = "circuit-blake2b")]
pub fn blake2b() -> &'static BinaryCircuit {
    use std::sync::OnceLock;

    static CIRCUIT: OnceLock<BinaryCircuit> = OnceLock::new();
    CIRCUIT.get_or_init(|| {
        decode(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/circuits/blake2b.bin"
        )))
    })
}
