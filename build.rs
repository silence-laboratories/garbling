use std::{fs, io, path::PathBuf};

// Compact circuit artifacts are a private build-time format shared with
// `BinaryCircuit::from_compact_bytes`. The decoder assumes these bytes come
// from this build script, not from untrusted callers or external files.
//
// The encoder currently targets the subset of Bristol Fashion used by the
// checked-in `circuits/*.txt` assets:
// - exactly one output group
// - only `AND`, `XOR`, and `INV` gates in the textual source
// - no explicit constant gates in the textual source
// - wire IDs must fit in 24 bits
const MAGIC: [u8; 4] = *b"GCB1";
const VERSION: u16 = 2;
const MAX_COMPACT_WIRE: u32 = 0x00FF_FFFF;

const TAG_INPUT: u8 = 0;
const TAG_XOR: u8 = 3;
const TAG_AND: u8 = 4;
const TAG_INV: u8 = 5;

#[derive(Clone, Copy)]
enum Gate {
    Input { no: u32, wire: u32 },
    Xor { xid: u32, yid: u32, out: u32 },
    And { xid: u32, yid: u32, out: u32 },
    Inv { xid: u32, out: u32 },
}

struct Circuit {
    gates: Vec<Gate>,
    input_sizes: Vec<u32>,
    output_gate_ids: Vec<u32>,
    num_wires: u32,
}

fn main() -> io::Result<()> {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let circuits_dir = manifest_dir.join("circuits");
    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("circuits");

    fs::create_dir_all(&out_dir)?;

    println!("cargo:rerun-if-changed={}", circuits_dir.display());

    for entry in fs::read_dir(&circuits_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
            continue;
        }

        println!("cargo:rerun-if-changed={}", path.display());
        let circuit = parse_bristol(&fs::read_to_string(&path)?)?;
        let encoded = encode_compact(&circuit);

        let output_name = path.file_stem().unwrap();
        let output_path = out_dir.join(output_name).with_extension("bin");
        fs::write(output_path, encoded)?;
    }

    Ok(())
}

fn parse_bristol(file: &str) -> io::Result<Circuit> {
    let mut reader = file.lines();

    let (num_gates, num_wires) = reader
        .next()
        .map(|line| line.split_whitespace())
        .and_then(|mut parts| {
            let num_gates = parts.next()?.parse::<usize>().ok()?;
            let num_wires = parts.next()?.parse::<u32>().ok()?;
            Some((num_gates, num_wires))
        })
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid header")
        })?;

    let input_sizes = reader
        .next()
        .map(|line| line.split_whitespace())
        .and_then(|mut parts| {
            let groups = parts.next()?.parse::<usize>().ok()?;
            let mut input_sizes = Vec::with_capacity(groups);
            for _ in 0..groups {
                input_sizes.push(parts.next()?.parse::<u32>().ok()?);
            }
            Some(input_sizes)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid input section",
            )
        })?;

    let num_outputs = reader
        .next()
        .map(|line| line.split_whitespace())
        .and_then(|mut parts| {
            let groups = parts.next()?.parse::<usize>().ok()?;
            (groups == 1)
                .then(|| parts.next()?.parse::<u32>().ok())
                .flatten()
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid output section",
            )
        })?;

    let mut gates = Vec::with_capacity(num_wires as usize);

    for (group_no, &group_size) in input_sizes.iter().enumerate() {
        for _ in 0..group_size {
            gates.push(Gate::Input {
                no: group_no as u32,
                wire: gates.len() as u32,
            });
        }
    }

    let outputs_start =
        num_wires.checked_sub(num_outputs).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid output wires")
        })?;
    let output_gate_ids = (outputs_start..num_wires).collect();

    for gate_index in 0..num_gates {
        let gate = reader
            .next()
            .map(|line| line.split_whitespace())
            .and_then(|mut parts| {
                let num_input = parts.next()?.parse::<u32>().ok()?;
                let _num_output = parts.next()?.parse::<u32>().ok()?;
                let input0 = parts.next()?.parse::<u32>().ok()?;
                let input1 = if num_input == 2 {
                    parts.next()?.parse::<u32>().ok()?
                } else {
                    0
                };
                let output = parts.next()?.parse::<u32>().ok()?;

                Some(match parts.next()? {
                    "AND" => Gate::And {
                        xid: input0,
                        yid: input1,
                        out: output,
                    },
                    "XOR" => Gate::Xor {
                        xid: input0,
                        yid: input1,
                        out: output,
                    },
                    "INV" => Gate::Inv {
                        xid: input0,
                        out: output,
                    },
                    _ => return None,
                })
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid gate at line {}", gate_index + 4),
                )
            })?;

        gates.push(gate);
    }

    Ok(Circuit {
        gates,
        input_sizes,
        output_gate_ids,
        num_wires,
    })
}

fn encode_compact(circuit: &Circuit) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    push_u16(&mut bytes, VERSION);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, circuit.num_wires);
    push_u32(&mut bytes, circuit.input_sizes.len() as u32);
    push_u32(&mut bytes, circuit.output_gate_ids.len() as u32);
    push_u32(&mut bytes, circuit.gates.len() as u32);

    for &len in &circuit.input_sizes {
        push_u32(&mut bytes, len);
    }

    for &output in &circuit.output_gate_ids {
        ensure_compact_wire(output);
        push_u24(&mut bytes, output);
    }

    for gate in &circuit.gates {
        match *gate {
            Gate::Input { no, wire } => {
                bytes.push(TAG_INPUT);
                push_u32(&mut bytes, no);
                ensure_compact_wire(wire);
                push_u24(&mut bytes, wire);
            }
            Gate::Xor { xid, yid, out } => {
                bytes.push(TAG_XOR);
                ensure_compact_wire(xid);
                ensure_compact_wire(yid);
                ensure_compact_wire(out);
                push_u24(&mut bytes, xid);
                push_u24(&mut bytes, yid);
                push_u24(&mut bytes, out);
            }
            Gate::And { xid, yid, out } => {
                bytes.push(TAG_AND);
                ensure_compact_wire(xid);
                ensure_compact_wire(yid);
                ensure_compact_wire(out);
                push_u24(&mut bytes, xid);
                push_u24(&mut bytes, yid);
                push_u24(&mut bytes, out);
            }
            Gate::Inv { xid, out } => {
                bytes.push(TAG_INV);
                ensure_compact_wire(xid);
                ensure_compact_wire(out);
                push_u24(&mut bytes, xid);
                push_u24(&mut bytes, out);
            }
        }
    }

    bytes
}

fn ensure_compact_wire(value: u32) {
    assert!(
        value <= MAX_COMPACT_WIRE,
        "wire index {value} does not fit into 24 bits"
    );
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
