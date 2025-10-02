use std::collections::HashMap;

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    utilities::{
        hash_function::HashFunction,
        types::{Block, YaoEvaluatorShare, BLOCK_SIZE},
        utils::{lsb, xor_blocks},
    },
};

pub fn evaluate_functionality<H>(
    circuit: &BinaryCircuit,
    input_encoding_shares: &[Vec<YaoEvaluatorShare>],
    f: &[Block],
    hash: &H,
) -> HashMap<usize, YaoEvaluatorShare>
where
    H: HashFunction,
{
    let mut f_index = 0;
    let mut w: Vec<Option<Block>> = vec![None; circuit.gates.len()];

    for (i, gate) in circuit.gates.iter().enumerate() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let label = &input_encoding_shares[no][id];
                (wire, label.label)
            }
            BinaryGate::Constant { val: _, wire } => {
                let op_label = f[f_index];
                f_index += 1;
                (wire, op_label)
            }
            BinaryGate::Xor { xid, yid, out } => {
                let x_label = w[xid].as_ref().unwrap();
                let y_label = w[yid].as_ref().unwrap();
                (out, xor_blocks(*x_label, *y_label))
            }
            BinaryGate::And {
                xid,
                yid,
                id: _,
                out,
            } => {
                let x_label = w[xid].as_ref().unwrap();
                let y_label = w[yid].as_ref().unwrap();
                let k0 = (2 * i - 1) as u128;
                let k1 = 2 * i as u128;
                let mut k0_bytes = Block::default();
                let mut k1_bytes = Block::default();
                k0_bytes[(BLOCK_SIZE - 16)..].copy_from_slice(&k0.to_le_bytes());
                k1_bytes[(BLOCK_SIZE - 16)..].copy_from_slice(&k1.to_le_bytes());

                let sx = lsb(*x_label);
                let sy = lsb(*y_label);

                let g0 = f[f_index];
                f_index += 1;
                let g1 = f[f_index];
                f_index += 1;

                let w_out_p1 = hash.tccr_hash(x_label, &k0_bytes);
                let w_out_p2 = hash.tccr_hash(y_label, &k1_bytes);

                let w_out_p3 = if sx == 1 {
                    xor_blocks(xor_blocks(w_out_p1, w_out_p2), g0)
                } else {
                    xor_blocks(w_out_p1, w_out_p2)
                };

                let w_out = if sy == 1 {
                    xor_blocks(xor_blocks(*x_label, g1), w_out_p3)
                } else {
                    w_out_p3
                };
                (out, w_out)
            }
            BinaryGate::Inv { xid, out } => {
                let x_label = w[xid].as_ref().unwrap();
                (out, *x_label)
            }
        };
        w[out_gate] = Some(f_label);
    }
    let mut outputs: HashMap<usize, YaoEvaluatorShare> = HashMap::new();
    for r in circuit.get_output_gate_ids().iter() {
        let x = w[*r].as_ref().unwrap();
        outputs.insert(*r, YaoEvaluatorShare { label: *x });
    }

    outputs
}
