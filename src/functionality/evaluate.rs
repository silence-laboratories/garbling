// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use zeroize::Zeroize;

use crate::{
    circuit::{BinaryCircuit, BinaryGate},
    utilities::{
        hash_function::HashFunction,
        types::{Block, YaoEvaluatorShare, YaoShare, ZBLOCK},
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
    let mut w = vec![ZBLOCK; circuit.num_wires() as usize];

    for (i, gate) in circuit.gates().iter().enumerate() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let share = input_encoding_shares[no as usize][id as usize]
                    .as_evaluator();
                (wire, share.label)
            }

            BinaryGate::Constant { val: _, wire } => {
                let op_label = f[f_index];
                f_index += 1;
                (wire, op_label)
            }

            BinaryGate::Xor { xid, yid, out } => {
                let x_label = &w[xid as usize];
                let y_label = &w[yid as usize];
                (out, xor_blocks(x_label, y_label))
            }

            BinaryGate::And {
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

            BinaryGate::Inv { xid, out } => {
                let x_label = w[xid as usize];
                (out, x_label)
            }
        };

        w[out_gate as usize] = f_label;
    }

    let outputs = circuit
        .get_output_gate_ids()
        .iter()
        .map(|&r| {
            let label = w[r as usize];
            (r, T::from(YaoEvaluatorShare { label }))
        })
        .collect();

    // The table holds the evaluator's label for every wire in the circuit.
    w.zeroize();

    outputs
}
