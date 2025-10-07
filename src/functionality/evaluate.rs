use std::collections::HashMap;

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    utilities::{
        hash_function::HashFunction,
        types::{Block, YaoEvaluatorShare, YaoShare, BLOCK_SIZE},
        utils::{lsb, xor_blocks},
    },
};

pub fn evaluate_functionality<T, H>(
    circuit: &BinaryCircuit,
    input_encoding_shares: &[Vec<YaoShare>],
    f: &[Block],
    hash: &H,
) -> HashMap<u32, T>
where
    H: HashFunction,
    T: From<YaoEvaluatorShare>,
{
    let mut f_index = 0;
    let mut w = vec![[0; BLOCK_SIZE]; circuit.gates.len()];

    for (i, gate) in circuit.gates.iter().enumerate() {
        let (out_gate, f_label) = match gate {
            &BinaryGate::Input { no, id, wire } => {
                let share = input_encoding_shares[no as usize][id as usize].as_evaluator();
                (wire, share.label)
            }

            &BinaryGate::Constant { val: _, wire } => {
                let op_label = f[f_index];
                f_index += 1;
                (wire, op_label)
            }

            &BinaryGate::Xor { xid, yid, out } => {
                let x_label = &w[xid as usize];
                let y_label = &w[yid as usize];
                (out, xor_blocks(x_label, y_label))
            }

            &BinaryGate::And {
                xid,
                yid,
                id: _,
                out,
            } => {
                let x_label = &w[xid as usize];
                let y_label = &w[yid as usize];

                let k0 = (2 * i) as u128;
                let k1 = (2 * i + 1) as u128;
                let k0_bytes = k0.to_le_bytes();
                let k1_bytes = k1.to_le_bytes();

                let sx = lsb(x_label);
                let sy = lsb(y_label);

                let g0 = &f[f_index];
                f_index += 1;
                let g1 = &f[f_index];
                f_index += 1;

                let w_out_p1 = hash.tccr_hash(x_label, &k0_bytes);
                let w_out_p2 = hash.tccr_hash(y_label, &k1_bytes);

                let w_out_p3 = if sx == 1 {
                    xor_blocks(&xor_blocks(&w_out_p1, &w_out_p2), g0)
                } else {
                    xor_blocks(&w_out_p1, &w_out_p2)
                };

                let w_out = if sy == 1 {
                    xor_blocks(&xor_blocks(x_label, g1), &w_out_p3)
                } else {
                    w_out_p3
                };

                (out, w_out)
            }

            &BinaryGate::Inv { xid, out } => {
                let x_label = w[xid as usize];
                (out, x_label)
            }
        };

        w[out_gate as usize] = f_label;
    }

    let mut outputs = HashMap::new();
    for &r in circuit.get_output_gate_ids() {
        let label = w[r as usize];
        outputs.insert(r, T::from(YaoEvaluatorShare { label }));
    }

    outputs
}
