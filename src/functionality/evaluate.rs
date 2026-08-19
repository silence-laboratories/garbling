// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use crate::{
    circuit::{BinaryCircuit, BinaryGate},
    functionality::utils_dep::ProtocolError,
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
) -> Result<HashMap<u32, T>, ProtocolError>
where
    H: HashFunction,
    T: From<YaoEvaluatorShare>,
{
    if input_encoding_shares.len() != circuit.num_inputs() as usize
        || input_encoding_shares
            .iter()
            .zip(circuit.input_gate_ids())
            .any(|(shares, ids)| shares.len() != ids.len())
    {
        return Err(ProtocolError::InvalidLength);
    }

    if input_encoding_shares
        .iter()
        .flatten()
        .any(|share| !matches!(share, YaoShare::E(_)))
    {
        return Err(ProtocolError::InvalidShare);
    }

    let expected_f_len =
        2 * circuit.num_nonfree_gates() + circuit.num_constant_gates();
    if f.len() != expected_f_len {
        return Err(ProtocolError::InvalidLength);
    }

    let mut f_index = 0;
    let mut w = vec![ZBLOCK; circuit.num_wires() as usize];

    for (i, gate) in circuit.gates().iter().enumerate() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let YaoShare::E(share) =
                    &input_encoding_shares[no as usize][id as usize]
                else {
                    return Err(ProtocolError::InvalidShare);
                };
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

    Ok(circuit
        .get_output_gate_ids()
        .iter()
        .map(|&r| {
            let label = w[r as usize];
            (r, T::from(YaoEvaluatorShare { label }))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::{
        customcircuits::comparison::build_comparison_circuit,
        functionality::utils_dep::ProtocolError,
        utilities::{
            garble_hash::AesGarbleHash,
            types::{YaoGarblerShare, BLOCK_SIZE},
        },
    };

    use super::*;

    #[test]
    fn rejects_invalid_evaluator_inputs() {
        let circuit = build_comparison_circuit();
        let hash = AesGarbleHash::new([0; BLOCK_SIZE]);
        let tables = vec![
            [0; BLOCK_SIZE];
            2 * circuit.num_nonfree_gates()
                + circuit.num_constant_gates()
        ];
        let garbler_inputs = circuit
            .input_gate_ids()
            .iter()
            .map(|ids| {
                ids.iter()
                    .map(|_| {
                        YaoShare::G(YaoGarblerShare {
                            delta: [0; BLOCK_SIZE],
                            f_label: [0; BLOCK_SIZE],
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let err = evaluate_functionality::<YaoShare, _>(
            &circuit,
            &garbler_inputs,
            &tables,
            &hash,
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidShare));

        let evaluator_inputs = circuit
            .input_gate_ids()
            .iter()
            .map(|ids| {
                ids.iter()
                    .map(|_| {
                        YaoShare::E(YaoEvaluatorShare {
                            label: [0; BLOCK_SIZE],
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let err = evaluate_functionality::<YaoShare, _>(
            &circuit,
            &evaluator_inputs,
            &[],
            &hash,
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidLength));
    }
}
