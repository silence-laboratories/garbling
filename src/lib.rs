// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub mod circuit;

/// Compatibility shim for the previous `circuitop` module layout.
pub mod circuitop {
    pub mod circuit {
        pub use crate::circuit::{BinaryCircuit, CircuitBuilder};
    }

    pub mod circuit_builder {
        pub use crate::circuit::CircuitBuilder;
    }

    pub mod gate {
        pub use crate::circuit::{BinaryGate, ID};
    }

    pub mod prebuilt {
        pub use crate::circuit::prebuilt::*;
    }
}

pub mod config;

pub mod utilities;

pub mod customcircuits;

pub mod functionality;
