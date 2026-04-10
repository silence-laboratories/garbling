use std::sync::OnceLock;

use crate::circuit::BinaryCircuit;

pub fn decode(bytes: &[u8]) -> BinaryCircuit {
    BinaryCircuit::from_compact_bytes(bytes)
}

pub fn sha512() -> &'static BinaryCircuit {
    static CIRCUIT: OnceLock<BinaryCircuit> = OnceLock::new();
    CIRCUIT.get_or_init(|| {
        decode(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/circuits/sha512.bin"
        )))
    })
}
