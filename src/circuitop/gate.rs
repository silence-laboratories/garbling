// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

/// Identifier type used for wires and gate outputs inside a circuit.
pub type ID = u32;

/// Represents a binary gate in a Boolean circuit.
///
/// The circuit representation is wire-oriented: each variant stores the input
/// wire IDs it reads from and the output wire ID it writes to.
#[derive(Clone, Debug, PartialEq)]
pub enum BinaryGate {
    /// An input wire belonging to party/input group `no`.
    ///
    /// `id` is the position within that input group and `wire` is the global
    /// wire ID used by subsequent gates.
    Input { no: u32, id: u32, wire: u32 },

    /// A constant-valued wire.
    ///
    /// # Fields
    /// * `val` - Boolean value stored on the wire.
    /// * `wire` - Global wire ID carrying that constant.
    Constant { val: bool, wire: u32 },

    /// A free XOR gate.
    ///
    /// # Fields
    /// * `xid` - First input wire ID.
    /// * `yid` - Second input wire ID.
    /// * `out` - Output wire ID.
    Xor { xid: u32, yid: u32, out: u32 },

    /// An AND gate.
    ///
    /// # Fields
    /// * `xid` - First input wire ID.
    /// * `yid` - Second input wire ID.
    /// * `id` - Sequential identifier of the non-free gate, used when
    ///   indexing garbled tables/ciphertexts.
    /// * `out` - Output wire ID.
    And {
        xid: u32,
        yid: u32,
        id: u32,
        out: u32,
    },

    /// An inverter (NOT) gate.
    ///
    /// # Fields
    /// * `xid` - Input wire ID.
    /// * `out` - Output wire ID.
    Inv { xid: u32, out: u32 },
}
