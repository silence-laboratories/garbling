// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Owned Boolean-circuit representation used by the garbling code.

use std::collections::HashMap;

use crate::circuitop::gate::{BinaryGate, ID};
use crate::config::errors::FileParsingError;

/// Represents a Boolean circuit together with the metadata needed for
/// evaluation and garbling.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BinaryCircuit {
    /// Gates in topological order.
    pub gates: Vec<BinaryGate>,

    /// Number of logical input groups/parties.
    pub num_inputs: u32,

    /// For each input group, the local input IDs belonging to that group.
    ///
    /// The entries are local positions within each group, not global wire IDs.
    pub input_gate_ids: Vec<Vec<ID>>,

    /// Global wire IDs exposed as circuit outputs.
    pub output_gate_ids: Vec<ID>,

    /// Mapping from a Boolean constant value to the wire carrying it.
    pub constant_map: HashMap<bool, ID>,

    /// Number of non-free gates, currently the number of `AND` gates.
    pub num_nonfree_gates: usize,

    /// Total number of wires allocated by the circuit.
    pub num_wires: u32,
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

        let mut output_circuit = Self::new(num_gates);

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

        output_circuit.num_wires = num_wires;

        let mut totalcount = 0;
        for (ipcnt, &i) in input_sizes.iter().enumerate() {
            output_circuit.new_input();
            for j in 0..i {
                output_circuit.push_gate(BinaryGate::Input {
                    no: ipcnt as u32,
                    id: j,
                    wire: totalcount,
                });
                output_circuit.push_nth_input(ipcnt as u32, j);
                totalcount += 1;
            }
        }

        for i in 0..num_outputs {
            output_circuit.push_output_gate(num_wires - num_outputs + i)
        }

        let mut id: u32 = 0;

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
                                id,
                                out: output,
                            };
                            id += 1;
                            output_circuit.increment_nonfree_gates();

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

            output_circuit.push_gate(gate);
        }

        Ok(output_circuit)
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
        let mut constant_map = HashMap::new();
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
                    constant_map.insert(false, wire);
                    BinaryGate::Constant { val: false, wire }
                }

                TAG_CONST_TRUE => {
                    let wire = reader.read_u24();
                    assert!(
                        wire < num_wires,
                        "invalid compact circuit: wire {wire} out of range 0..={max_wire}",
                    );
                    constant_map.insert(true, wire);
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
            constant_map,
            num_nonfree_gates: and_count as usize,
            num_wires,
        }
    }

    /// Creates an empty circuit with capacity reserved for `ngates`.
    ///
    /// # Arguments
    /// * `ngates` - Expected number of gates.
    pub fn new(ngates: usize) -> Self {
        let gates: Vec<BinaryGate> = Vec::with_capacity(ngates);
        Self {
            gates,
            num_inputs: 0,
            input_gate_ids: Vec::new(),
            output_gate_ids: Vec::new(),
            constant_map: HashMap::new(),
            num_nonfree_gates: 0,
            num_wires: 0,
        }
    }

    /// Appends a gate to the circuit.
    pub fn push_gate(&mut self, gate: BinaryGate) {
        self.gates.push(gate);
    }

    /// Registers an output wire.
    pub fn push_output_gate(&mut self, output_gate_id: u32) {
        self.output_gate_ids.push(output_gate_id);
    }

    /// Records the wire used for a Boolean constant value.
    pub fn push_constant_gate(&mut self, val: bool, constant_gate_id: u32) {
        self.constant_map.insert(val, constant_gate_id);
    }

    /// Starts a new logical input group.
    pub fn new_input(&mut self) {
        self.input_gate_ids.push(vec![]);
        self.num_inputs += 1
    }

    /// Appends a local input ID to the `n`th input group.
    pub fn push_nth_input(&mut self, n: u32, input_id: u32) {
        self.input_gate_ids[n as usize].push(input_id);
    }

    /// Appends several local input IDs to the `n`th input group.
    pub fn push_nth_inputs(&mut self, n: usize, input_id: &[u32]) {
        self.input_gate_ids[n].extend_from_slice(input_id);
    }

    /// Returns the circuit output wire IDs.
    pub fn get_output_gate_ids(&self) -> &[ID] {
        &self.output_gate_ids
    }

    /// Returns the local input IDs for the `n`th input group.
    pub fn get_nth_input_ids(&self, n: usize) -> &[ID] {
        &self.input_gate_ids[n]
    }

    /// Returns the local input-ID lists for all input groups.
    pub fn get_input_ids(&self) -> &[Vec<ID>] {
        &self.input_gate_ids
    }

    /// Increments the number of non-free gates.
    pub fn increment_nonfree_gates(&mut self) {
        self.num_nonfree_gates += 1;
    }

    /// Increments the wire count after allocating a new output wire.
    pub fn increment_wires(&mut self) {
        self.num_wires += 1;
    }

    /// Returns the number of non-free gates.
    pub fn get_num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates
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
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use super::{BinaryCircuit, COMPACT_MAGIC, COMPACT_VERSION, TAG_INPUT};
    use crate::circuitop::gate::BinaryGate;

    const AES128_CIRCUIT: &str = include_str!("../../circuits/aes128.txt");
    const BINMULT_CIRCUIT: &str = include_str!("../../circuits/binmult.txt");

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
            gates: vec![
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
            ],
            num_inputs: 2,
            input_gate_ids: vec![vec![0, 1], vec![0, 1]],
            output_gate_ids: vec![8, 9],
            constant_map: HashMap::new(),
            num_nonfree_gates: 4,
            num_wires: 10,
        };

        assert_eq!(required_circuit, circuit.unwrap());
    }

    #[test]
    fn test_prebuilt_aes128() {
        let bytes =
            include_bytes!(concat!(env!("OUT_DIR"), "/circuits/aes128.bin"));
        let circuit = BinaryCircuit::from_compact_bytes(bytes);
        let parsed = BinaryCircuit::parse(AES128_CIRCUIT).unwrap();

        assert_eq!(parsed, circuit);
    }

    #[test]
    fn test_prebuilt_binmult() {
        let bytes =
            include_bytes!(concat!(env!("OUT_DIR"), "/circuits/binmult.bin"));
        let circuit = BinaryCircuit::from_compact_bytes(bytes);
        let parsed = BinaryCircuit::parse(BINMULT_CIRCUIT).unwrap();

        assert_eq!(parsed, circuit);
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
}
