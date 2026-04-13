// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use rand::RngCore;

use crate::{
    circuit::{BinaryCircuit, BinaryGate},
    utilities::{
        hash_function::HashFunction,
        types::{Block, GarblerSetup, YaoGarblerShare, YaoShare, BLOCK_SIZE},
        utils::{lsb, xor_blocks},
    },
};

pub fn garble_functionality<T, H>(
    circuit: &BinaryCircuit,
    input_shares: &[Vec<YaoShare>],
    setup: &mut GarblerSetup,
    hash: &H,
) -> (Vec<Block>, HashMap<u32, T>)
where
    H: HashFunction,
    T: From<YaoGarblerShare>,
{
    let mut w = vec![[0; BLOCK_SIZE]; circuit.num_wires() as usize];

    let mut f: Vec<Block> = vec![];

    for (i, gate) in circuit.gates().iter().enumerate() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let share =
                    input_shares[no as usize][id as usize].as_garbler();
                (wire, share.f_label)
            }

            BinaryGate::Constant { val, wire } => {
                let mut zerowire = Block::default();
                setup.prf.fill_bytes(&mut zerowire);
                zerowire[0] |= 1;
                let mut newwire = zerowire;
                if val {
                    newwire = xor_blocks(&newwire, &setup.delta);
                }
                f.push(newwire);
                (wire, zerowire)
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
                let xp_label = xor_blocks(x_label, &setup.delta);
                let y_label = &w[yid as usize];
                let yp_label = xor_blocks(y_label, &setup.delta);

                let k0 = (2 * i) as u128;
                let k1 = (2 * i + 1) as u128;
                let k0_bytes = k0.to_le_bytes();
                let k1_bytes = k1.to_le_bytes();

                let px = lsb(x_label);
                let py = lsb(y_label);

                let g0_p1 = hash.tccr_hash(x_label, &k0_bytes);
                let g0_p2 = hash.tccr_hash(&xp_label, &k0_bytes);
                let g0 = if py == 1 {
                    xor_blocks(&xor_blocks(&g0_p1, &g0_p2), &setup.delta)
                } else {
                    xor_blocks(&g0_p1, &g0_p2)
                };

                let g1_p1 = hash.tccr_hash(y_label, &k1_bytes);
                let g1_p2 = hash.tccr_hash(&yp_label, &k1_bytes);
                let g1 = xor_blocks(&xor_blocks(&g1_p1, &g1_p2), x_label);

                f.push(g0);
                f.push(g1);

                let w_out_p1 = if px == 1 { &g0_p2 } else { &g0_p1 };
                let w_out_p2 = if py == 1 { &g1_p2 } else { &g1_p1 };

                let w_out = if px * py == 1 {
                    xor_blocks(&xor_blocks(w_out_p1, w_out_p2), &setup.delta)
                } else {
                    xor_blocks(w_out_p1, w_out_p2)
                };

                (out, w_out)
            }

            BinaryGate::Inv { xid, out } => {
                let x_label = &w[xid as usize];
                (out, xor_blocks(x_label, &setup.delta))
            }
        };

        w[out_gate as usize] = f_label;
    }

    let mut outputs = HashMap::new();
    for &r in circuit.get_output_gate_ids() {
        let f_label = w[r as usize];
        outputs.insert(
            r,
            T::from(YaoGarblerShare {
                delta: setup.delta,
                f_label,
            }),
        );
    }

    (f, outputs)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use crate::{
        circuit::prebuilt,
        customcircuits::comparison::build_comparison_circuit,
        utilities::garble_hash::AesGarbleHash,
    };

    use super::*;

    fn aes128_circuit() -> BinaryCircuit {
        prebuilt::decode(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/circuits/aes128.bin"
        )))
    }

    #[test]
    fn test_garble_functionality() {
        let circuit = aes128_circuit();

        let mut setup = GarblerSetup {
            comm_crs: Block::default(),
            prf: ChaCha8Rng::from_seed([0; 32]),
            delta: Block::default(),
            party_id: 0,
        };

        let hash = AesGarbleHash::new(Block::default());

        let gin: Vec<Vec<_>> = circuit
            .input_gate_ids()
            .iter()
            .map(|v| {
                v.iter()
                    .map(|_| YaoGarblerShare {
                        delta: setup.delta,
                        f_label: Block::default(),
                    })
                    .map(From::from)
                    .collect()
            })
            .collect();

        let (f, _o): (_, HashMap<u32, YaoShare>) =
            garble_functionality(&circuit, &gin, &mut setup, &hash);

        println!("cir: gates.len() {}", circuit.gates().len());
        let nonfree = circuit.get_num_nonfree_gates();
        println!("cir: num_nonfree_gates {nonfree}");
        println!("cir: num_constant_gates {}", circuit.num_constant_gates());
        println!(
            "cir: 2*num_constant_gates + num_nonfree_gates {}",
            2 * nonfree + circuit.num_constant_gates()
        );

        println!("f {}\n\n\n\n\n\n\n", f.len());

        let circuit = build_comparison_circuit();

        let mut setup = GarblerSetup {
            comm_crs: Block::default(),
            prf: ChaCha8Rng::from_seed([0; 32]),
            delta: Block::default(),
            party_id: 0,
        };

        let hash = AesGarbleHash::new(Block::default());

        let gin: Vec<Vec<_>> = circuit
            .input_gate_ids()
            .iter()
            .map(|v| {
                v.iter()
                    .map(|_| YaoGarblerShare {
                        delta: setup.delta,
                        f_label: Block::default(),
                    })
                    .map(From::from)
                    .collect()
            })
            .collect();

        circuit.print_circuit();

        let (f, _o): (_, HashMap<u32, YaoShare>) =
            garble_functionality(&circuit, &gin, &mut setup, &hash);

        println!("cir: gates.len() {}", circuit.gates().len());
        let nonfree = circuit.get_num_nonfree_gates();
        println!("cir: num_nonfree_gates {nonfree}");
        println!("cir: num_constant_gates {}", circuit.num_constant_gates());
        println!(
            "cir: 2*num_constant_gates + num_nonfree_gates {}",
            2 * nonfree as usize + circuit.num_constant_gates()
        );

        println!("f {}", f.len());
    }
}
