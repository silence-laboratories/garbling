// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};

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
    let mut f_index = 0;
    let mut w = Zeroizing::new(vec![ZBLOCK; circuit.num_wires() as usize]);

    for (i, gate) in circuit.gates().iter().enumerate() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let share = input_encoding_shares
                    .get(no as usize)
                    .and_then(|v| v.get(id as usize))
                    .ok_or(ProtocolError::InvalidLength)?
                    .as_evaluator();
                (wire, share.label)
            }

            BinaryGate::Constant { val: _, wire } => {
                let op_label =
                    *f.get(f_index).ok_or(ProtocolError::InvalidLength)?;
                f_index += 1;
                (wire, op_label)
            }

            BinaryGate::Xor { xid, yid, out } => {
                let x_label = w
                    .get(xid as usize)
                    .ok_or(ProtocolError::InvalidLength)?;
                let y_label = w
                    .get(yid as usize)
                    .ok_or(ProtocolError::InvalidLength)?;
                (out, xor_blocks(x_label, y_label))
            }

            BinaryGate::And {
                xid,
                yid,
                id: _,
                out,
            } => {
                let x_label = w
                    .get(xid as usize)
                    .ok_or(ProtocolError::InvalidLength)?;
                let y_label = w
                    .get(yid as usize)
                    .ok_or(ProtocolError::InvalidLength)?;

                let k0 = (2 * i) as u128;
                let k1 = (2 * i + 1) as u128;
                let k0_bytes = k0.to_le_bytes();
                let k1_bytes = k1.to_le_bytes();

                let sx = lsb(x_label);
                let sy = lsb(y_label);

                let g0 =
                    f.get(f_index).ok_or(ProtocolError::InvalidLength)?;
                f_index += 1;
                let g1 =
                    f.get(f_index).ok_or(ProtocolError::InvalidLength)?;
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
                let x_label = *w
                    .get(xid as usize)
                    .ok_or(ProtocolError::InvalidLength)?;
                (out, x_label)
            }
        };

        *w.get_mut(out_gate as usize)
            .ok_or(ProtocolError::InvalidLength)? = f_label;
    }

    let outputs = circuit
        .get_output_gate_ids()
        .iter()
        .map(|&r| {
            let label =
                *w.get(r as usize).ok_or(ProtocolError::InvalidLength)?;
            Ok((r, T::from(YaoEvaluatorShare { label })))
        })
        .collect();

    // The table holds the evaluator's label for every wire in the circuit.
    w.zeroize();

    outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::hash_function::AesHash;

    #[test]
    fn rejects_short_garbled_tables() {
        let circuit =
            BinaryCircuit::parse("1 3\n2 1 1\n1 1\n2 1 0 1 2 AND\n").unwrap();
        let hash = AesHash::new([0; 16]);
        let inputs = vec![
            vec![YaoShare::E(YaoEvaluatorShare { label: [1; 16] })],
            vec![YaoShare::E(YaoEvaluatorShare { label: [2; 16] })],
        ];
        let err = evaluate_functionality::<YaoEvaluatorShare, _>(
            &circuit,
            &inputs,
            &[],
            &hash,
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidLength));
    }

    #[test]
    fn rejects_missing_input_share() {
        let circuit =
            BinaryCircuit::parse("1 3\n2 1 1\n1 1\n2 1 0 1 2 AND\n").unwrap();
        let hash = AesHash::new([0; 16]);
        let err = evaluate_functionality::<YaoEvaluatorShare, _>(
            &circuit,
            &[],
            &[[0; 16], [0; 16]],
            &hash,
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidLength));
    }
}
