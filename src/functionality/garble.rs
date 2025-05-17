use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::garbling2pc_errors::GarblerError,
    utilities::{
        hash_function::HashFunction,
        types::{Block, GarblerSetup, YaoGarblerShare},
        utils::{lsb, xor_blocks},
    },
};

pub fn garble_functionality<R, H>(
    circuit: &BinaryCircuit,
    garbler_input_shares: &HashMap<usize, YaoGarblerShare>,
    evaluator_input_shares: &HashMap<usize, YaoGarblerShare>,
    setup: &GarblerSetup,
    rng: &mut R,
    hash: &H,
) -> Result<(Vec<Block>, HashMap<usize, YaoGarblerShare>), GarblerError>
where
    R: RngCore + CryptoRng,
    H: HashFunction,
{
    let mut w: Vec<Option<Block>> = vec![None; circuit.gates.len()];

    let mut f: Vec<Block> = vec![];

    for (i, gate) in circuit.gates.iter().enumerate() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::GarblerInput { id } => {
                let label_option = garbler_input_shares.get(&id);
                let label = label_option.unwrap();
                assert_eq!(label.delta, setup.delta);
                (None, label.f_label)
            }
            BinaryGate::EvaluatorInput { id } => {
                let label_option = evaluator_input_shares.get(&id);
                let label = label_option.unwrap();
                assert_eq!(label.delta, setup.delta);
                (None, label.f_label)
            }
            BinaryGate::Constant { val } => {
                let mut zerowire = Block::default();
                rng.fill_bytes(&mut zerowire);
                zerowire[0] |= 1;
                let mut newwire = zerowire;
                if val == 1 {
                    newwire = xor_blocks(newwire, setup.delta);
                }
                f.push(newwire);
                (None, zerowire)
            }
            BinaryGate::Xor { xid, yid, out } => {
                let x_label = w[xid].as_ref().ok_or(GarblerError::CacheItemError(xid))?;
                let y_label = w[yid].as_ref().ok_or(GarblerError::CacheItemError(yid))?;
                (out, xor_blocks(*x_label, *y_label))
            }
            BinaryGate::And {
                xid,
                yid,
                id: _,
                out,
            } => {
                let x_label = w[xid].as_ref().ok_or(GarblerError::CacheItemError(xid))?;
                let xp_label = xor_blocks(*x_label, setup.delta);
                let y_label = w[yid].as_ref().ok_or(GarblerError::CacheItemError(yid))?;
                let yp_label = xor_blocks(*y_label, setup.delta);
                let k0 = (2 * i - 1) as u128;
                let k1 = 2 * i as u128;
                let mut k0_bytes = Block::default();
                let mut k1_bytes = Block::default();
                k0_bytes[16..32].copy_from_slice(&k0.to_le_bytes());
                k1_bytes[16..32].copy_from_slice(&k1.to_le_bytes());

                let px = lsb(*x_label);
                let py = lsb(*y_label);

                let g0_p1 = hash.tccr_hash(x_label, &k0_bytes);
                let g0_p2 = hash.tccr_hash(&xp_label, &k0_bytes);
                let g0 = if py == 1 {
                    xor_blocks(xor_blocks(g0_p1, g0_p2), setup.delta)
                } else {
                    xor_blocks(g0_p1, g0_p2)
                };

                let g1_p1 = hash.tccr_hash(y_label, &k1_bytes);
                let g1_p2 = hash.tccr_hash(&yp_label, &k1_bytes);
                let g1 = xor_blocks(xor_blocks(g1_p1, g1_p2), *x_label);

                f.push(g0);
                f.push(g1);

                let w_out_p1 = if px == 1 {
                    hash.tccr_hash(&xp_label, &k0_bytes)
                } else {
                    hash.tccr_hash(x_label, &k0_bytes)
                };
                let w_out_p2 = if py == 1 {
                    hash.tccr_hash(&yp_label, &k1_bytes)
                } else {
                    hash.tccr_hash(y_label, &k1_bytes)
                };

                let w_out = if px * py == 1 {
                    xor_blocks(xor_blocks(w_out_p1, w_out_p2), setup.delta)
                } else {
                    xor_blocks(w_out_p1, w_out_p2)
                };
                (out, w_out)
            }
            BinaryGate::Inv { xid, out } => {
                let x_label = w[xid].as_ref().ok_or(GarblerError::CacheItemError(xid))?;
                (out, xor_blocks(*x_label, setup.delta))
            }
        };
        w[out_gate.unwrap_or(i)] = Some(f_label);
    }
    let mut outputs = HashMap::new();
    for r in circuit.get_output_gate_ids().iter() {
        let x = w[*r].as_ref().ok_or(GarblerError::CacheItemError(*r))?;
        outputs.insert(
            *r,
            YaoGarblerShare {
                delta: setup.delta,
                f_label: *x,
            },
        );
    }

    Ok((f, outputs))
}

#[cfg(test)]
mod tests {

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use crate::{
        circuitop::circuit::BinaryCircuit,
        customcircuits::comparison::build_comparison_circuit,
        utilities::{
            hash_function::AesHash,
            types::{Block, GarblerSetup, YaoGarblerShare},
        },
    };

    use super::garble_functionality;

    #[test]
    fn test_garble_functionality() {
        let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();

        let setup = GarblerSetup {
            comm_crs: Block::default(),
            prf_key: Block::default(),
            delta: Block::default(),
        };

        let mut rng = ChaCha8Rng::from_seed(setup.prf_key);
        let hash = AesHash::new(Block::default());

        let g = circuit
            .garbler_input_ids
            .iter()
            .map(|&id| {
                (
                    id,
                    YaoGarblerShare {
                        delta: setup.delta,
                        f_label: Block::default(),
                    },
                )
            })
            .collect();

        let e = circuit
            .evaluator_input_ids
            .iter()
            .map(|&id| {
                (
                    id,
                    YaoGarblerShare {
                        delta: setup.delta,
                        f_label: Block::default(),
                    },
                )
            })
            .collect();

        let (f, _o) = garble_functionality(&circuit, &g, &e, &setup, &mut rng, &hash).unwrap();

        println!(
            "cir: garbler_input_ids.len() {}",
            circuit.garbler_input_ids.len()
        );
        println!(
            "cir: evaluator_input_ids.len() {}",
            circuit.evaluator_input_ids.len()
        );
        println!("cir: gates.len() {}", circuit.gates.len());
        println!("cir: num_nonfree_gates {}", circuit.num_nonfree_gates);
        println!(
            "cir: constant_gate_ids.len() {}",
            circuit.constant_gate_ids.len()
        );
        println!(
            "cir: 2*constant_gate_ids.len() + num_nonfree_gates {}",
            2 * circuit.num_nonfree_gates + circuit.constant_gate_ids.len()
        );

        println!("f {}\n\n\n\n\n\n\n", f.len());

        let circuit = build_comparison_circuit();

        let setup = GarblerSetup {
            comm_crs: Block::default(),
            prf_key: Block::default(),
            delta: Block::default(),
        };

        let mut rng = ChaCha8Rng::from_seed(setup.prf_key);
        let hash = AesHash::new(Block::default());

        let g = circuit
            .garbler_input_ids
            .iter()
            .map(|&id| {
                (
                    id,
                    YaoGarblerShare {
                        delta: setup.delta,
                        f_label: Block::default(),
                    },
                )
            })
            .collect();

        let e = circuit
            .evaluator_input_ids
            .iter()
            .map(|&id| {
                (
                    id,
                    YaoGarblerShare {
                        delta: setup.delta,
                        f_label: Block::default(),
                    },
                )
            })
            .collect();

        let (f, _o) = garble_functionality(&circuit, &g, &e, &setup, &mut rng, &hash).unwrap();

        println!(
            "cir: garbler_input_ids.len() {}",
            circuit.garbler_input_ids.len()
        );
        println!(
            "cir: evaluator_input_ids.len() {}",
            circuit.evaluator_input_ids.len()
        );
        println!("cir: gates.len() {}", circuit.gates.len());
        println!("cir: num_nonfree_gates {}", circuit.num_nonfree_gates);
        println!(
            "cir: constant_gate_ids.len() {}",
            circuit.constant_gate_ids.len()
        );
        println!(
            "cir: 2*constant_gate_ids.len() + num_nonfree_gates {}",
            2 * circuit.num_nonfree_gates + circuit.constant_gate_ids.len()
        );

        println!("f {}", f.len());
    }
}
