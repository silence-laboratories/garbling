// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Owned Boolean-circuit representation used by the garbling code.

use crate::config::errors::FileParsingError;

pub mod prebuilt;

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

/// Represents a Boolean circuit together with the metadata needed for
/// evaluation and garbling.
///
/// Construct circuits through [`CircuitBuilder::finish`] or
/// [`BinaryCircuit::parse`].
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryCircuit {
    /// Gates in topological order.
    gates: Vec<BinaryGate>,

    /// Number of logical input groups/parties.
    num_inputs: u32,

    /// For each input group, the local input IDs belonging to that group.
    ///
    /// The entries are local positions within each group, not global wire IDs.
    input_gate_ids: Vec<Vec<ID>>,

    /// Global wire IDs exposed as circuit outputs.
    output_gate_ids: Vec<ID>,

    /// Wire carrying the `false` constant, if present.
    false_wire: Option<ID>,

    /// Wire carrying the `true` constant, if present.
    true_wire: Option<ID>,

    /// Number of non-free gates, currently the number of `AND` gates.
    num_nonfree_gates: usize,

    /// Total number of wires allocated by the circuit.
    num_wires: u32,
}

const COMPACT_MAGIC: [u8; 4] = *b"GCB1";
const COMPACT_VERSION: u16 = 2;

const TAG_INPUT: u8 = 0;
const TAG_CONST_FALSE: u8 = 1;
const TAG_CONST_TRUE: u8 = 2;
const TAG_XOR: u8 = 3;
const TAG_AND: u8 = 4;
const TAG_INV: u8 = 5;

struct CompactReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CompactReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u8(&mut self) -> u8 {
        let byte = *self.bytes.get(self.pos).unwrap_or_else(|| {
            panic!("invalid compact circuit: unexpected EOF")
        });
        self.pos += 1;
        byte
    }

    fn read_u16(&mut self) -> u16 {
        let end = self.pos + 2;
        let chunk = self.bytes.get(self.pos..end).unwrap_or_else(|| {
            panic!("invalid compact circuit: unexpected EOF")
        });
        self.pos = end;
        u16::from_le_bytes([chunk[0], chunk[1]])
    }

    fn read_u32(&mut self) -> u32 {
        let end = self.pos + 4;
        let chunk = self.bytes.get(self.pos..end).unwrap_or_else(|| {
            panic!("invalid compact circuit: unexpected EOF")
        });
        self.pos = end;
        u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
    }

    fn read_u24(&mut self) -> u32 {
        let end = self.pos + 3;
        let chunk = self.bytes.get(self.pos..end).unwrap_or_else(|| {
            panic!("invalid compact circuit: unexpected EOF")
        });
        self.pos = end;
        u32::from_le_bytes([chunk[0], chunk[1], chunk[2], 0])
    }

    fn finish(self) {
        assert_eq!(
            self.pos,
            self.bytes.len(),
            "invalid compact circuit: {} trailing bytes",
            self.bytes.len() - self.pos,
        );
    }
}

impl BinaryCircuit {
    /// Parses a Bristol Fashion circuit from its textual contents.
    ///
    /// The Bristol Fashion format is a standard plaintext representation of
    /// Boolean circuits commonly used in MPC tooling. More details:
    /// <https://nigelsmart.github.io/MPC-Circuits/>
    ///
    /// # Arguments
    /// * `file` - Entire file contents to parse.
    ///
    /// # Returns
    /// * `Ok(Self)` if parsing succeeds.
    /// * `Err(FileParsingError)` if the input is missing required sections or a
    ///   gate line cannot be decoded.
    pub fn parse(file: &str) -> Result<Self, FileParsingError> {
        let mut reader = file.lines();

        let (num_gates, num_wires) = reader
            .next()
            .map(|line1| line1.split_whitespace())
            .and_then(|mut parts| {
                let num_gates = parts.next().and_then(|s| s.parse().ok())?;
                let num_wires = parts.next().and_then(|s| s.parse().ok())?;

                Some((num_gates, num_wires))
            })
            .ok_or(FileParsingError::InputNoParsingError)?;

        let input_sizes = reader
            .next()
            .map(|line| line.split_whitespace())
            .and_then(|mut parts| {
                let num_inp_wires =
                    parts.next().and_then(|s| s.parse().ok())?;
                let mut input_sizes = Vec::with_capacity(num_inp_wires);
                for _ in 0..num_inp_wires {
                    let num_iplen =
                        parts.next().and_then(|s| s.parse().ok())?;
                    input_sizes.push(num_iplen);
                }

                Some(input_sizes)
            })
            .ok_or(FileParsingError::InputNoParsingError)?;

        let num_outputs = reader
            .next()
            .map(|line| line.split_whitespace())
            .and_then(|mut parts| {
                let n_output_usizes: usize =
                    parts.next().and_then(|s| s.parse().ok())?;

                (n_output_usizes == 1)
                    .then(|| parts.next().and_then(|s| s.parse().ok()))
                    .flatten()
            })
            .ok_or(FileParsingError::InputNoParsingError)?;

        let mut gates = Vec::with_capacity(num_gates);
        let num_inputs = input_sizes.len() as u32;
        let mut input_gate_ids = Vec::with_capacity(input_sizes.len());
        let output_gate_ids = (0..num_outputs)
            .map(|i| num_wires - num_outputs + i)
            .collect();

        let mut totalcount = 0;
        for (ipcnt, &width) in input_sizes.iter().enumerate() {
            let mut ids = Vec::with_capacity(width as usize);
            for id in 0..width {
                gates.push(BinaryGate::Input {
                    no: ipcnt as u32,
                    id,
                    wire: totalcount,
                });
                ids.push(id);
                totalcount += 1;
            }
            input_gate_ids.push(ids);
        }

        let mut num_nonfree_gates = 0usize;

        for i in 0..num_gates {
            let gate = reader
                .next()
                .map(|line| line.split_whitespace())
                .and_then(|mut parts| {
                    let num_input: u32 =
                        parts.next().and_then(|s| s.parse().ok())?;
                    let _num_output: u32 =
                        parts.next().and_then(|s| s.parse().ok())?;
                    let input0 = parts.next().and_then(|s| s.parse().ok())?;

                    let input1 = if num_input == 2 {
                        parts.next().and_then(|s| s.parse().ok())?
                    } else {
                        0
                    };

                    let output = parts.next().and_then(|s| s.parse().ok())?;

                    Some(match parts.next()? {
                        "AND" => {
                            let gate = BinaryGate::And {
                                xid: input0,
                                yid: input1,
                                id: num_nonfree_gates as u32,
                                out: output,
                            };
                            num_nonfree_gates += 1;

                            gate
                        }

                        "XOR" => BinaryGate::Xor {
                            xid: input0,
                            yid: input1,
                            out: output,
                        },

                        "INV" => BinaryGate::Inv {
                            xid: input0,
                            out: output,
                        },

                        _ => return None,
                    })
                })
                .ok_or(FileParsingError::FileFormatError(i))?;

            gates.push(gate);
        }

        Ok(Self {
            gates,
            num_inputs,
            input_gate_ids,
            output_gate_ids,
            false_wire: None,
            true_wire: None,
            num_nonfree_gates,
            num_wires,
        })
    }

    /// Decodes a trusted compact circuit artifact emitted at build time.
    ///
    /// Assumptions:
    /// - `bytes` were produced by this crate's `build.rs`
    /// - the artifact format is private to this crate and not a public input
    ///   format
    /// - the encoded circuit follows the same invariants as
    ///   [`BinaryCircuit::parse`], including one gate per wire and valid wire
    ///   references
    ///
    /// This function is intended for embedded prebuilt assets. It validates
    /// internal consistency with `assert!` and will panic if those assumptions
    /// are violated.
    pub(crate) fn from_compact_bytes(bytes: &[u8]) -> Self {
        let mut reader = CompactReader::new(bytes);

        let mut magic = [0u8; 4];
        for byte in &mut magic {
            *byte = reader.read_u8();
        }
        assert_eq!(
            magic, COMPACT_MAGIC,
            "invalid compact circuit: bad magic"
        );

        let version = reader.read_u16();
        assert_eq!(
            version, COMPACT_VERSION,
            "invalid compact circuit: unsupported version {version}",
        );

        let _reserved = reader.read_u16();
        let num_wires = reader.read_u32();
        let num_inputs = reader.read_u32();
        let num_outputs = reader.read_u32();
        let num_gates = reader.read_u32();

        let mut input_sizes = Vec::with_capacity(num_inputs as usize);
        for _ in 0..num_inputs {
            input_sizes.push(reader.read_u32());
        }

        let max_wire = num_wires.saturating_sub(1);
        let mut output_gate_ids = Vec::with_capacity(num_outputs as usize);
        for _ in 0..num_outputs {
            let wire = reader.read_u24();
            assert!(
                wire < num_wires,
                "invalid compact circuit: output wire {wire} out of range 0..={max_wire}",
            );
            output_gate_ids.push(wire);
        }

        let mut input_gate_ids = Vec::with_capacity(input_sizes.len());
        for &size in &input_sizes {
            input_gate_ids.push(Vec::with_capacity(size as usize));
        }

        assert_eq!(
            num_gates,
            num_wires,
            "invalid compact circuit: {num_gates} gates for {num_wires} wires",
        );

        let mut gates = Vec::with_capacity(num_gates as usize);
        let mut false_wire = None;
        let mut true_wire = None;
        let mut and_count = 0u32;

        for _ in 0..num_gates {
            let gate = match reader.read_u8() {
                TAG_INPUT => {
                    let no = reader.read_u32();
                    let wire = reader.read_u24();
                    let ids = input_gate_ids.get_mut(no as usize).unwrap_or_else(|| {
                        panic!("invalid compact circuit: input group {no} out of range")
                    });
                    assert!(
                        wire < num_wires,
                        "invalid compact circuit: wire {wire} out of range 0..={max_wire}",
                    );

                    let id = ids.len() as u32;
                    ids.push(id);
                    BinaryGate::Input { no, id, wire }
                }

                TAG_CONST_FALSE => {
                    let wire = reader.read_u24();
                    assert!(
                        wire < num_wires,
                        "invalid compact circuit: wire {wire} out of range 0..={max_wire}",
                    );
                    false_wire = Some(wire);
                    BinaryGate::Constant { val: false, wire }
                }

                TAG_CONST_TRUE => {
                    let wire = reader.read_u24();
                    assert!(
                        wire < num_wires,
                        "invalid compact circuit: wire {wire} out of range 0..={max_wire}",
                    );
                    true_wire = Some(wire);
                    BinaryGate::Constant { val: true, wire }
                }

                TAG_XOR => {
                    let xid = reader.read_u24();
                    let yid = reader.read_u24();
                    let out = reader.read_u24();
                    assert!(
                        xid < num_wires,
                        "invalid compact circuit: wire {xid} out of range 0..={max_wire}",
                    );
                    assert!(
                        yid < num_wires,
                        "invalid compact circuit: wire {yid} out of range 0..={max_wire}",
                    );
                    assert!(
                        out < num_wires,
                        "invalid compact circuit: wire {out} out of range 0..={max_wire}",
                    );

                    BinaryGate::Xor { xid, yid, out }
                }

                TAG_AND => {
                    let xid = reader.read_u24();
                    let yid = reader.read_u24();
                    let out = reader.read_u24();
                    assert!(
                        xid < num_wires,
                        "invalid compact circuit: wire {xid} out of range 0..={max_wire}",
                    );
                    assert!(
                        yid < num_wires,
                        "invalid compact circuit: wire {yid} out of range 0..={max_wire}",
                    );
                    assert!(
                        out < num_wires,
                        "invalid compact circuit: wire {out} out of range 0..={max_wire}",
                    );

                    let gate = BinaryGate::And {
                        xid,
                        yid,
                        id: and_count,
                        out,
                    };
                    and_count += 1;
                    gate
                }

                TAG_INV => {
                    let xid = reader.read_u24();
                    let out = reader.read_u24();
                    assert!(
                        xid < num_wires,
                        "invalid compact circuit: wire {xid} out of range 0..={max_wire}",
                    );
                    assert!(
                        out < num_wires,
                        "invalid compact circuit: wire {out} out of range 0..={max_wire}",
                    );

                    BinaryGate::Inv { xid, out }
                }

                tag => panic!("invalid compact circuit: invalid tag {tag}"),
            };

            gates.push(gate);
        }

        reader.finish();

        Self {
            gates,
            num_inputs,
            input_gate_ids,
            output_gate_ids,
            false_wire,
            true_wire,
            num_nonfree_gates: and_count as usize,
            num_wires,
        }
    }

    /// Returns the gates in topological order.
    pub fn gates(&self) -> &[BinaryGate] {
        &self.gates
    }

    /// Returns the circuit output wire IDs.
    pub fn output_gate_ids(&self) -> &[ID] {
        &self.output_gate_ids
    }

    /// Returns the circuit output wire IDs.
    pub fn get_output_gate_ids(&self) -> &[ID] {
        self.output_gate_ids()
    }

    /// Returns the local input IDs for the `n`th input group.
    pub fn get_nth_input_ids(&self, n: usize) -> &[ID] {
        &self.input_gate_ids[n]
    }

    /// Returns the local input-ID lists for all input groups.
    pub fn input_gate_ids(&self) -> &[Vec<ID>] {
        &self.input_gate_ids
    }

    /// Returns the local input-ID lists for all input groups.
    pub fn get_input_ids(&self) -> &[Vec<ID>] {
        self.input_gate_ids()
    }

    /// Returns the total number of constant wires in the circuit.
    pub fn num_constant_gates(&self) -> usize {
        usize::from(self.false_wire.is_some())
            + usize::from(self.true_wire.is_some())
    }

    /// Returns the number of non-free gates.
    pub fn num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates
    }

    /// Returns the number of non-free gates.
    pub fn get_num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates()
    }

    /// Returns the total number of wires allocated by the circuit.
    pub fn num_wires(&self) -> u32 {
        self.num_wires
    }

    /// Returns the number of logical input groups.
    pub fn num_inputs(&self) -> u32 {
        self.num_inputs
    }

    /// Returns the number of wires in the `n`th input group.
    pub fn num_nth_inputs(&self, n: usize) -> usize {
        self.input_gate_ids[n].len()
    }

    /// Prints a human-readable dump of the circuit to standard output.
    pub fn print_circuit(&self) {
        for gate in &self.gates {
            match gate {
                BinaryGate::Input { no, id, wire } => {
                    println!("Input: no: {no} id: {id} wire: {wire}")
                }

                BinaryGate::Constant { val, wire: _ } => {
                    println!("Constantinput: val: {val}")
                }

                BinaryGate::Inv { xid, out } => {
                    println!("InverseGate: inp: {xid} output: {out}")
                }

                BinaryGate::Xor { xid, yid, out } => {
                    println!("XorGate: inp1: {xid} inp2: {yid} output: {out}")
                }

                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => {
                    println!("AndGate: inp1: {xid} inp2: {yid} output: {out}")
                }
            };
        }

        for i in self.get_output_gate_ids() {
            println!("output_gates: {}", *i);
        }
    }

    /// Evaluates the Boolean circuit on plain `bool` inputs.
    #[cfg(any(test, feature = "test-support"))]
    pub fn evaluate(&self, inputs: &[&[bool]]) -> Vec<bool> {
        let mut wires = vec![false; self.num_wires() as usize];

        for gate in self.gates() {
            let (out_wire, value) = match *gate {
                BinaryGate::Input { no, id, wire } => {
                    (wire, inputs[no as usize][id as usize])
                }
                BinaryGate::Constant { val, wire } => (wire, val),
                BinaryGate::Xor { xid, yid, out } => {
                    (out, wires[xid as usize] ^ wires[yid as usize])
                }
                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => (out, wires[xid as usize] & wires[yid as usize]),
                BinaryGate::Inv { xid, out } => (out, !wires[xid as usize]),
            };

            wires[out_wire as usize] = value;
        }

        self.get_output_gate_ids()
            .iter()
            .map(|&wire| wires[wire as usize])
            .collect()
    }
}

/// Builder used to allocate wires and append gates into a [`BinaryCircuit`].
///
/// The builder owns the circuit parts under construction and keeps track of the
/// next wire ID, cached constant wires, and the numbering of non-free gates.
#[derive(Default)]
pub struct CircuitBuilder {
    /// Next global wire ID to allocate.
    next_ref_id: u32,

    /// Cached wire for the `false` constant, if already emitted.
    false_wire: Option<ID>,

    /// Cached wire for the `true` constant, if already emitted.
    true_wire: Option<ID>,

    /// Gates accumulated in topological order.
    gates: Vec<BinaryGate>,

    /// Number of logical input groups/parties.
    num_inputs: u32,

    /// Local input IDs grouped by input party.
    input_gate_ids: Vec<Vec<ID>>,

    /// Output wire IDs.
    output_gate_ids: Vec<ID>,

    /// Number of non-free gates, currently the number of `AND` gates.
    num_nonfree_gates: usize,
}

impl CircuitBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes the builder and returns the constructed circuit.
    pub fn finish(self) -> BinaryCircuit {
        BinaryCircuit {
            gates: self.gates,
            num_inputs: self.num_inputs,
            input_gate_ids: self.input_gate_ids,
            output_gate_ids: self.output_gate_ids,
            false_wire: self.false_wire,
            true_wire: self.true_wire,
            num_nonfree_gates: self.num_nonfree_gates,
            num_wires: self.next_ref_id,
        }
    }

    /// Returns the next local input index inside input group `n`.
    fn get_next_nth_input_id(&mut self, n: u32) -> u32 {
        self.input_gate_ids[n as usize].len() as u32
    }

    /// Allocates the next non-free-gate identifier.
    fn get_next_ciphertext_id(&mut self) -> u32 {
        let current = self.num_nonfree_gates;
        self.num_nonfree_gates += 1;
        current as u32
    }

    /// Allocates the next global wire ID.
    fn get_next_ref_id(&mut self) -> u32 {
        let current = self.next_ref_id;
        self.next_ref_id += 1;
        current
    }

    /// Adds a new input group containing a single input wire.
    ///
    /// Returns the global wire ID of that input.
    pub fn new_input(&mut self) -> u32 {
        let no = self.num_inputs;
        self.input_gate_ids.push(Vec::with_capacity(1));
        self.num_inputs += 1;

        let id = self.get_next_nth_input_id(no);
        let gate_id = self.get_next_ref_id();

        self.gates.push(BinaryGate::Input {
            no,
            id,
            wire: gate_id,
        });
        self.input_gate_ids[no as usize].push(id);

        gate_id
    }

    /// Adds one input group containing `number_of_inputs` wires.
    ///
    /// Returns their global wire IDs in order.
    pub fn new_inputs(&mut self, number_of_inputs: u16) -> Vec<u32> {
        let mut output = Vec::new();
        let no = self.num_inputs;
        self.input_gate_ids
            .push(Vec::with_capacity(number_of_inputs as usize));
        self.num_inputs += 1;

        for _ in 0..number_of_inputs {
            let id = self.get_next_nth_input_id(no);
            let gate_id = self.get_next_ref_id();
            self.gates.push(BinaryGate::Input {
                no,
                id,
                wire: gate_id,
            });
            output.push(gate_id);
            self.input_gate_ids[no as usize].push(id);
        }

        output
    }

    /// Appends an XOR gate and returns its output wire ID.
    pub fn xor(&mut self, xid: u32, yid: u32) -> u32 {
        let out = self.get_next_ref_id();
        self.gates.push(BinaryGate::Xor { xid, yid, out });
        out
    }

    /// Appends an inverter gate and returns its output wire ID.
    pub fn negate(&mut self, xid: u32) -> u32 {
        let out = self.get_next_ref_id();
        self.gates.push(BinaryGate::Inv { xid, out });
        out
    }

    /// Appends an AND gate and returns its output wire ID.
    pub fn and(&mut self, xid: u32, yid: u32) -> u32 {
        let out = self.get_next_ref_id();
        let id = self.get_next_ciphertext_id();
        self.gates.push(BinaryGate::And { xid, yid, id, out });
        out
    }

    /// Returns the wire ID for a Boolean constant value, creating the wire if
    /// necessary.
    pub fn constant(&mut self, val: bool) -> u32 {
        let cached_wire = if val { self.true_wire } else { self.false_wire };

        if let Some(wire) = cached_wire {
            return wire;
        }

        let wire = self.get_next_ref_id();
        self.gates.push(BinaryGate::Constant { val, wire });
        if val {
            self.true_wire = Some(wire);
        } else {
            self.false_wire = Some(wire);
        }
        wire
    }

    /// Marks an existing wire as a circuit output.
    pub fn output(&mut self, id: u32) {
        self.output_gate_ids.push(id);
    }

    /// Copies `other_circuit` into this builder with all wire references
    /// remapped to the current circuit.
    ///
    /// `input_ids` supplies the concrete wires that should replace each input
    /// group of `other_circuit`. The outer slice must have one entry per input
    /// group, and each inner slice must match that group's width.
    ///
    /// The returned vector contains the remapped output wire IDs of the
    /// embedded circuit.
    pub fn add_circuit(
        &mut self,
        other_circuit: &BinaryCircuit,
        input_ids: &[&[ID]],
    ) -> Vec<ID> {
        assert_eq!(input_ids.len(), other_circuit.num_inputs() as usize);
        (0..input_ids.len()).for_each(|i| {
            assert_eq!(
                input_ids[i].len(),
                other_circuit.get_nth_input_ids(i).len()
            )
        });

        let mut old_to_new_map = vec![0; other_circuit.num_wires() as usize];

        for gate in other_circuit.gates() {
            match *gate {
                BinaryGate::Xor { xid, yid, out } => {
                    let newx = old_to_new_map[xid as usize];
                    let newy = old_to_new_map[yid as usize];
                    let newz = self.xor(newx, newy);
                    old_to_new_map[out as usize] = newz;
                }

                BinaryGate::And {
                    xid,
                    yid,
                    id: _,
                    out,
                } => {
                    let newx = old_to_new_map[xid as usize];
                    let newy = old_to_new_map[yid as usize];
                    let newz = self.and(newx, newy);
                    old_to_new_map[out as usize] = newz;
                }

                BinaryGate::Inv { xid, out } => {
                    let newx = old_to_new_map[xid as usize];
                    let newz = self.negate(newx);
                    old_to_new_map[out as usize] = newz;
                }

                BinaryGate::Input { no, id, wire } => {
                    old_to_new_map[wire as usize] =
                        input_ids[no as usize][id as usize];
                }

                BinaryGate::Constant { val, wire } => {
                    old_to_new_map[wire as usize] = self.constant(val);
                }
            }
        }

        other_circuit
            .get_output_gate_ids()
            .iter()
            .map(|&out| old_to_new_map[out as usize])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BinaryCircuit, BinaryGate, COMPACT_MAGIC, COMPACT_VERSION, TAG_INPUT,
    };
    use crate::customcircuits::comparison::build_comparison_circuit;

    const AES128_CIRCUIT: &str = include_str!("../circuits/aes128.txt");
    const BINMULT_CIRCUIT: &str = include_str!("../circuits/binmult.txt");
    const BINMULT_GATES: &[BinaryGate] = &[
        BinaryGate::Input {
            no: 0,
            id: 0,
            wire: 0,
        },
        BinaryGate::Input {
            no: 0,
            id: 1,
            wire: 1,
        },
        BinaryGate::Input {
            no: 1,
            id: 0,
            wire: 2,
        },
        BinaryGate::Input {
            no: 1,
            id: 1,
            wire: 3,
        },
        BinaryGate::And {
            xid: 0,
            yid: 2,
            id: 0,
            out: 4,
        },
        BinaryGate::And {
            xid: 0,
            yid: 3,
            id: 1,
            out: 5,
        },
        BinaryGate::And {
            xid: 1,
            yid: 2,
            id: 2,
            out: 6,
        },
        BinaryGate::And {
            xid: 1,
            yid: 3,
            id: 3,
            out: 7,
        },
        BinaryGate::Xor {
            xid: 5,
            yid: 6,
            out: 8,
        },
        BinaryGate::Xor {
            xid: 8,
            yid: 7,
            out: 9,
        },
    ];
    const COMPARISON_GATES: &[BinaryGate] = &[
        BinaryGate::Input {
            no: 0,
            id: 0,
            wire: 0,
        },
        BinaryGate::Input {
            no: 0,
            id: 1,
            wire: 1,
        },
        BinaryGate::Input {
            no: 1,
            id: 0,
            wire: 2,
        },
        BinaryGate::Input {
            no: 1,
            id: 1,
            wire: 3,
        },
        BinaryGate::Xor {
            xid: 2,
            yid: 0,
            out: 4,
        },
        BinaryGate::Xor {
            xid: 3,
            yid: 1,
            out: 5,
        },
        BinaryGate::Constant { val: true, wire: 6 },
        BinaryGate::And {
            xid: 4,
            yid: 5,
            id: 0,
            out: 7,
        },
        BinaryGate::Xor {
            xid: 4,
            yid: 5,
            out: 8,
        },
        BinaryGate::Xor {
            xid: 7,
            yid: 8,
            out: 9,
        },
        BinaryGate::Xor {
            xid: 9,
            yid: 6,
            out: 10,
        },
    ];

    enum TestCompactGate {
        Input { no: u32, wire: u32 },
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u24(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes()[..3]);
    }

    fn encode_test_compact(
        num_wires: u32,
        input_sizes: &[u32],
        output_gate_ids: &[u32],
        gates: &[TestCompactGate],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&COMPACT_MAGIC);
        push_u16(&mut bytes, COMPACT_VERSION);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, num_wires);
        push_u32(&mut bytes, input_sizes.len() as u32);
        push_u32(&mut bytes, output_gate_ids.len() as u32);
        push_u32(&mut bytes, gates.len() as u32);

        for &len in input_sizes {
            push_u32(&mut bytes, len);
        }

        for &output in output_gate_ids {
            push_u24(&mut bytes, output);
        }

        for gate in gates {
            match *gate {
                TestCompactGate::Input { no, wire } => {
                    bytes.push(TAG_INPUT);
                    push_u32(&mut bytes, no);
                    push_u24(&mut bytes, wire);
                }
            }
        }

        bytes
    }

    #[test]
    fn test_circuit() {
        let circuit = BinaryCircuit::parse(BINMULT_CIRCUIT);

        let required_circuit = BinaryCircuit {
            gates: BINMULT_GATES.to_vec(),
            num_inputs: 2,
            input_gate_ids: vec![vec![0, 1], vec![0, 1]],
            output_gate_ids: vec![8, 9],
            false_wire: None,
            true_wire: None,
            num_nonfree_gates: 4,
            num_wires: 10,
        };

        assert_eq!(required_circuit, circuit.unwrap());
    }

    fn assert_prebuilt_matches_parse(bytes: &[u8], source: &str) {
        let circuit = BinaryCircuit::from_compact_bytes(bytes);
        let parsed = BinaryCircuit::parse(source).unwrap();

        assert_eq!(parsed, circuit);
    }

    #[test]
    fn test_prebuilt_circuits_match_parse() {
        let aes128 =
            include_bytes!(concat!(env!("OUT_DIR"), "/circuits/aes128.bin"));
        assert_prebuilt_matches_parse(aes128, AES128_CIRCUIT);

        let binmult =
            include_bytes!(concat!(env!("OUT_DIR"), "/circuits/binmult.bin"));
        assert_prebuilt_matches_parse(binmult, BINMULT_CIRCUIT);
    }

    #[test]
    #[should_panic]
    fn test_compact_rejects_out_of_range_input_wire() {
        let bytes = encode_test_compact(
            1,
            &[1],
            &[0],
            &[TestCompactGate::Input { no: 0, wire: 1 }],
        );

        BinaryCircuit::from_compact_bytes(&bytes);
    }

    #[test]
    fn test_circuit_builder() {
        let circuit = build_comparison_circuit();
        assert_eq!(circuit.gates(), COMPARISON_GATES);
        assert_eq!(circuit.get_input_ids(), &[vec![0, 1], vec![0, 1]]);
        assert_eq!(circuit.get_output_gate_ids(), &[10]);
        assert_eq!(circuit.num_constant_gates(), 1);
        assert_eq!(circuit.get_num_nonfree_gates(), 1);
        assert_eq!(circuit.num_wires(), 11);
    }
}
