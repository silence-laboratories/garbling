pub type ID = u32;

/// Represents a binary gate in a Boolean circuit.
///
/// Each variant corresponds to a different type of gate that
/// can appear in a circuit.
#[derive(Clone, Debug, PartialEq)]
pub enum BinaryGate {
    /// Represents an input gate.
    Input { no: u32, id: u32, wire: u32 },

    /// Represents a constant value gate.
    ///
    /// # Fields
    /// * `val` - The constant value stored in the gate.
    Constant { val: u16, wire: u32 },

    /// Represents an XOR gate, which performs a bitwise XOR operation.
    ///
    /// # Fields
    /// * `xid` - The ID of the first input wire.
    /// * `yid` - The ID of the second input wire.
    /// * `out` - The optional ID of the output wire.
    Xor { xid: u32, yid: u32, out: u32 },

    /// Represents an AND gate, which performs a bitwise AND operation.
    ///
    /// # Fields
    /// * `xid` - The ID of the first input wire.
    /// * `yid` - The ID of the second input wire.
    /// * `id` - The unique identifier for this AND gate (used for garbling).
    /// * `out` - The optional ID of the output wire.
    And {
        xid: u32,
        yid: u32,
        id: u32,
        out: u32,
    },

    /// Represents an inverter (NOT gate), which negates a bit.
    ///
    /// # Fields
    /// * `xid` - The ID of the input wire.
    /// * `out` - The optional ID of the output wire.
    Inv { xid: u32, out: u32 },
}
