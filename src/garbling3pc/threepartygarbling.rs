use std::collections::HashMap;

use rand::{rngs::ThreadRng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::constants::{Block, HASH_KEY},
    garbling2pc::{evaluator_operations::BinaryEvaluator, garbler_operations::BinaryGarbler},
    garbling3pc::threepartytraits::ThreePartyBinaryEvaluator,
    utilities::{
        commitments::{Commitment, HashCommitment},
        hash_function::AesHash,
        utils::xor_blocks,
    },
};

use super::threepartytraits::ThreePartyBinaryGarbler;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg1 {
    pub x: Vec<bool>,
    pub comm_crs: Block,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg1Abs {
    pub p1_data: ThreePGMsg1,
    pub p2_data: ThreePGMsg1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg3Coms {
    pub b_values: Vec<bool>,
    pub gc: Vec<Block>,
    pub delta: Block,
    pub p1_commitments: HashMap<(usize, usize), Block>,
    pub p2_commitments: HashMap<(usize, usize), Block>,
    pub p3_commitments: HashMap<(usize, usize), Block>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg3Decoms {
    pub x12_decom: Vec<(Block, Block)>,
    pub x34_decom: Vec<(Block, Block)>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg3 {
    pub com_vals: ThreePGMsg3Coms,
    pub decom_vals: ThreePGMsg3Decoms,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg4 {
    garbled_op: HashMap<usize, [u8; 16]>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGParty12StateR1 {
    x: Vec<bool>,
    comm_crs: Block,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGParty3StateR1 {
    x3: Vec<bool>,
    x4: Vec<bool>,
    comm_crs: Block,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGPartyStateR2 {
    prf_seed: Block,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGPartyIntStateR3 {
    delta: Block,
    b_vec: [Vec<bool>; 3],
    garbling_encoding: HashMap<usize, Block>,
    evaluator_encoding: HashMap<usize, Block>,
    decoding_info: HashMap<usize, u8>,
    p1_decommitments: HashMap<(usize, usize), (Block, Block)>,
    p2_decommitments: HashMap<(usize, usize), (Block, Block)>,
    p3_decommitments: HashMap<(usize, usize), (Block, Block)>,
}

pub fn threepg_create_msg1_p3(input: &[bool], rng: &mut ThreadRng) -> ThreePGMsg1Abs {
    let comm_crs: Block = rng.gen();
    let mut x3 = Vec::new();
    for _ in 0..input.len() {
        x3.push(rng.gen_bool(0.5));
    }
    let mut x4 = Vec::new();
    for i in 0..input.len() {
        x4.push(x3[i] ^ input[i]);
    }
    // println!("x3: {:?} x4: {:?}", x3, x4);
    ThreePGMsg1Abs {
        p1_data: ThreePGMsg1 { x: x3, comm_crs },
        p2_data: ThreePGMsg1 { x: x4, comm_crs },
    }
}

pub fn threepg_process_msg1_p12(msg1_recv: &ThreePGMsg1) -> ThreePGParty12StateR1 {
    ThreePGParty12StateR1 {
        comm_crs: msg1_recv.comm_crs,
        x: msg1_recv.x.clone(),
    }
}

pub fn threepg_process_msg1_p3(msg1: &ThreePGMsg1Abs) -> ThreePGParty3StateR1 {
    ThreePGParty3StateR1 {
        comm_crs: msg1.p1_data.comm_crs,
        x3: msg1.p1_data.x.clone(),
        x4: msg1.p2_data.x.clone(),
    }
}

pub fn threepg_create_msg2_p1(rng: &mut ThreadRng) -> Block {
    let prf_seed: Block = rng.gen();
    prf_seed
}

pub fn threepg_process_msg2_p12(prf_seed: &Block) -> ThreePGPartyStateR2 {
    ThreePGPartyStateR2 {
        prf_seed: *prf_seed,
    }
}

pub fn threepg_create_msg3_p1(
    p1_ip_nos: usize,
    p2_ip_nos: usize,
    p3_ip_nos: usize,
    input_p1: &[bool],
    p1_state_r1: &ThreePGParty12StateR1,
    prf_seed: &Block,
    circuit: &BinaryCircuit,
) -> Result<(ThreePGMsg3, ThreePGPartyIntStateR3), String> {
    let hash = AesHash::new(HASH_KEY);
    let mut rng_key: [u8; 32] = [0u8; 32];
    rng_key[..16].copy_from_slice(prf_seed);
    rng_key[16..(16 + 16)].copy_from_slice(prf_seed);
    if p1_ip_nos + p2_ip_nos != circuit.num_garbler_inputs() {
        return Err("Garbler Input Size inconsistent".to_string());
    }

    if p3_ip_nos * 2 != circuit.num_evaluator_inputs() {
        return Err("Evaluator Input Size inconsistent".to_string());
    }
    let mut rng = ChaCha8Rng::from_seed(rng_key);
    let mut garbler = BinaryGarbler::new(hash.clone(), &mut rng);
    let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
    let delta = garbler.delta;
    let mut b_vec = [
        Vec::with_capacity(p1_ip_nos),
        Vec::with_capacity(p2_ip_nos),
        Vec::with_capacity(2 * p3_ip_nos),
    ];
    for _ in 0..p1_ip_nos {
        b_vec[0].push(rng.gen_bool(0.5));
    }
    for _ in 0..p2_ip_nos {
        b_vec[1].push(rng.gen_bool(0.5));
    }
    for _ in 0..2 * p3_ip_nos {
        b_vec[2].push(rng.gen_bool(0.5));
    }

    let hash_commit = HashCommitment::new(AesHash::new(p1_state_r1.comm_crs));

    let mut p1_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p1_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();
    let mut p2_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p2_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();
    let mut p3_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p3_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();

    for j in 0..p1_ip_nos {
        let g_en_j_origin = *garble_output.garbler_input_encodings.get(&j).unwrap();
        for a in 0..2 {
            let g_en_j = if b_vec[0][j] ^ (a != 0) {
                xor_blocks(g_en_j_origin, delta)
            } else {
                g_en_j_origin
            };
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(g_en_j, witness);
            p1_commitments.insert((j, a), commitment);
            p1_decommitments.insert((j, a), (g_en_j, witness));
        }
    }

    for j in 0..p2_ip_nos {
        let g_en_j_origin = *garble_output
            .garbler_input_encodings
            .get(&(p1_ip_nos + j))
            .unwrap();
        for a in 0..2 {
            let g_en_j = if b_vec[1][j] ^ (a != 0) {
                xor_blocks(g_en_j_origin, delta)
            } else {
                g_en_j_origin
            };
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(g_en_j, witness);
            p2_commitments.insert((j, a), commitment);
            p2_decommitments.insert((j, a), (g_en_j, witness));
        }
    }

    for j in 0..p3_ip_nos {
        let e_en_j_origin = *garble_output
            .evaluator_input_encodings
            .get(&(2 * j))
            .unwrap();
        for a in 0..2 {
            let e_en_j = if b_vec[2][j] ^ (a != 0) {
                xor_blocks(e_en_j_origin, delta)
            } else {
                e_en_j_origin
            };
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(e_en_j, witness);
            p3_commitments.insert((j, a), commitment);
            p3_decommitments.insert((j, a), (e_en_j, witness));
        }
    }

    for j in 0..p3_ip_nos {
        let e_en_j_origin = *garble_output
            .evaluator_input_encodings
            .get(&(2 * j + 1))
            .unwrap();
        for a in 0..2 {
            let e_en_j = if b_vec[2][p3_ip_nos + j] ^ (a != 0) {
                xor_blocks(e_en_j_origin, delta)
            } else {
                e_en_j_origin
            };
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(e_en_j, witness);
            p3_commitments.insert((p3_ip_nos + j, a), commitment);
            p3_decommitments.insert((p3_ip_nos + j, a), (e_en_j, witness));
        }
    }

    let mut x1_decom: Vec<(Block, Block)> = Vec::new();
    let mut x3_decom: Vec<(Block, Block)> = Vec::new();
    for (i, input_p1_i) in input_p1.iter().enumerate().take(p1_ip_nos) {
        let val = b_vec[0][i] ^ input_p1_i;
        if val {
            x1_decom.push(*p1_decommitments.get(&(i, 1)).unwrap());
        } else {
            x1_decom.push(*p1_decommitments.get(&(i, 0)).unwrap());
        }
    }
    // println!("x1_decom: {:?}\n", x1_decom);

    for (i, b_i) in b_vec[2].iter().enumerate().take(p3_ip_nos) {
        let val = b_i ^ p1_state_r1.x[i];
        if val {
            x3_decom.push(*p3_decommitments.get(&(i, 1)).unwrap());
        } else {
            x3_decom.push(*p3_decommitments.get(&(i, 0)).unwrap());
        }
    }
    // println!("x3_decom: {:?}\n", x3_decom);

    Ok((
        ThreePGMsg3 {
            com_vals: ThreePGMsg3Coms {
                b_values: b_vec[2].clone(),
                gc: garble_output.garbled_circuit,
                delta,
                p1_commitments,
                p2_commitments,
                p3_commitments,
            },
            decom_vals: ThreePGMsg3Decoms {
                x12_decom: x1_decom,
                x34_decom: x3_decom,
            },
        },
        ThreePGPartyIntStateR3 {
            delta,
            b_vec,
            garbling_encoding: garble_output.garbler_input_encodings,
            decoding_info: garble_output.decoding_infos,
            evaluator_encoding: garble_output.evaluator_input_encodings,
            p1_decommitments,
            p2_decommitments,
            p3_decommitments,
        },
    ))
}

pub fn threepg_create_msg3_p2(
    p1_ip_nos: usize,
    p2_ip_nos: usize,
    p3_ip_nos: usize,
    input_p2: &[bool],
    p2_state_r1: &ThreePGParty12StateR1,
    prf_seed: &Block,
    circuit: &BinaryCircuit,
) -> Result<(ThreePGMsg3, ThreePGPartyIntStateR3), String> {
    let hash = AesHash::new(HASH_KEY);

    let mut rng_key: [u8; 32] = [0u8; 32];
    rng_key[..16].copy_from_slice(prf_seed);
    rng_key[16..(16 + 16)].copy_from_slice(prf_seed);
    if p1_ip_nos + p2_ip_nos != circuit.num_garbler_inputs() {
        return Err("Garbler Input Size inconsistent".to_string());
    }

    if p3_ip_nos * 2 != circuit.num_evaluator_inputs() {
        return Err("Evaluator Input Size inconsistent".to_string());
    }

    println!("1 {}\n", p3_ip_nos);
    let mut rng = ChaCha8Rng::from_seed(rng_key);
    let mut garbler = BinaryGarbler::new(hash.clone(), &mut rng);
    let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
    let delta = garbler.delta;
    let mut b_vec = [
        Vec::with_capacity(p1_ip_nos),
        Vec::with_capacity(p2_ip_nos),
        Vec::with_capacity(2 * p3_ip_nos),
    ];
    for _ in 0..p1_ip_nos {
        b_vec[0].push(rng.gen_bool(0.5));
    }
    for _ in 0..p2_ip_nos {
        b_vec[1].push(rng.gen_bool(0.5));
    }
    for _ in 0..2 * p3_ip_nos {
        b_vec[2].push(rng.gen_bool(0.5));
    }

    // println!("p2 b_vec {:?}", b_vec);

    let hash_commit = HashCommitment::new(AesHash::new(p2_state_r1.comm_crs));

    let mut p1_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p1_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();
    let mut p2_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p2_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();
    let mut p3_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p3_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();

    // println!("garbler input encodings: {:?}\n", garble_output.garbler_input_encodings);
    // println!("evaluator input encodings: {:?}\n", garble_output.evaluator_input_encodings);

    for j in 0..p1_ip_nos {
        let g_en_j_origin = *garble_output.garbler_input_encodings.get(&j).unwrap();
        for a in 0..2 {
            let g_en_j = if b_vec[0][j] ^ (a != 0) {
                xor_blocks(g_en_j_origin, delta)
            } else {
                g_en_j_origin
            };
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(g_en_j, witness);
            p1_commitments.insert((j, a), commitment);
            p1_decommitments.insert((j, a), (g_en_j, witness));
        }
    }

    // println!("p1 commitments: {:?}\n", p1_commitments);
    // println!("p1 decommitments: {:?}\n", p1_decommitments);

    for j in 0..p2_ip_nos {
        let g_en_j_origin = *garble_output
            .garbler_input_encodings
            .get(&(p1_ip_nos + j))
            .unwrap();
        for a in 0..2 {
            let g_en_j = if b_vec[1][j] ^ (a != 0) {
                xor_blocks(g_en_j_origin, delta)
            } else {
                g_en_j_origin
            };
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(g_en_j, witness);
            p2_commitments.insert((j, a), commitment);
            p2_decommitments.insert((j, a), (g_en_j, witness));
        }
    }

    // println!("p2 commitments: {:?}\n", p2_commitments);
    // println!("p2 decommitments: {:?}\n", p2_decommitments);

    for j in 0..p3_ip_nos {
        let e_en_j_origin = *garble_output
            .evaluator_input_encodings
            .get(&(2 * j))
            .unwrap();
        for a in 0..2 {
            let e_en_j = if b_vec[2][j] ^ (a != 0) {
                xor_blocks(e_en_j_origin, delta)
            } else {
                e_en_j_origin
            };
            // println!("{} {} {:?}", j, a, e_en_j);
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(e_en_j, witness);
            p3_commitments.insert((j, a), commitment);
            p3_decommitments.insert((j, a), (e_en_j, witness));
        }
    }

    for j in 0..p3_ip_nos {
        let e_en_j_origin = *garble_output
            .evaluator_input_encodings
            .get(&(2 * j + 1))
            .unwrap();
        for a in 0..2 {
            let e_en_j = if b_vec[2][p3_ip_nos + j] ^ (a != 0) {
                xor_blocks(e_en_j_origin, delta)
            } else {
                e_en_j_origin
            };
            // println!("{} {} {:?}", p3_ip_nos + j, a, e_en_j);
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(e_en_j, witness);
            p3_commitments.insert((p3_ip_nos + j, a), commitment);
            p3_decommitments.insert((p3_ip_nos + j, a), (e_en_j, witness));
        }
    }

    // println!("p3 commitments: {:?}\n", p3_commitments);
    // println!("p3 decommitments: {:?}\n", p3_decommitments);

    let mut x2_decom: Vec<(Block, Block)> = Vec::new();
    let mut x4_decom: Vec<(Block, Block)> = Vec::new();
    let len1 = b_vec[1].len();
    if len1 != input_p2.len() {
        println!("input lengths not consistent");
    }
    for (i, input_p2_i) in input_p2.iter().enumerate().take(p2_ip_nos) {
        let val = b_vec[1][i] ^ input_p2_i;
        if val {
            x2_decom.push(*p2_decommitments.get(&(i, 1)).unwrap());
        } else {
            x2_decom.push(*p2_decommitments.get(&(i, 0)).unwrap());
        }
    }

    // println!("x2_decom {:?}\n", x2_decom);

    for i in 0..p3_ip_nos {
        let val = b_vec[2][p3_ip_nos + i] ^ p2_state_r1.x[i];
        if val {
            x4_decom.push(*p3_decommitments.get(&(i + p3_ip_nos, 1)).unwrap());
        } else {
            x4_decom.push(*p3_decommitments.get(&(i + p3_ip_nos, 0)).unwrap());
        }
    }

    // println!("x4_decom {:?}\n", x4_decom);

    Ok((
        ThreePGMsg3 {
            com_vals: ThreePGMsg3Coms {
                b_values: b_vec[2].clone(),
                gc: garble_output.garbled_circuit,
                delta,
                p1_commitments,
                p2_commitments,
                p3_commitments,
            },
            decom_vals: ThreePGMsg3Decoms {
                x12_decom: x2_decom,
                x34_decom: x4_decom,
            },
        },
        ThreePGPartyIntStateR3 {
            delta,
            b_vec,
            garbling_encoding: garble_output.garbler_input_encodings,
            decoding_info: garble_output.decoding_infos,
            evaluator_encoding: garble_output.evaluator_input_encodings,
            p1_decommitments,
            p2_decommitments,
            p3_decommitments,
        },
    ))
}

pub fn threepg_create_msg4_p3(
    state_r1: &ThreePGParty3StateR1,
    msg3_recv_p1: &ThreePGMsg3,
    msg3_recv_p2: &ThreePGMsg3,
    circuit: &BinaryCircuit,
) -> Option<ThreePGMsg4> {
    if msg3_recv_p1.com_vals != msg3_recv_p2.com_vals {
        return None;
    }

    let commitment = HashCommitment::new(AesHash::new(state_r1.comm_crs));

    let p1_ip_nos = msg3_recv_p1.com_vals.p1_commitments.len() / 2;
    let p2_ip_nos = msg3_recv_p1.com_vals.p2_commitments.len() / 2;
    let p3_ip_nos = msg3_recv_p1.com_vals.p3_commitments.len() / 4;

    println!("2 {}\n", p3_ip_nos);
    let mut garbled_garbler_inputs: HashMap<usize, Block> =
        HashMap::with_capacity(p1_ip_nos + p2_ip_nos);
    let mut garbled_evaluator_inputs: HashMap<usize, Block> = HashMap::with_capacity(p3_ip_nos);
    let mut garbled_evaluator_inputs_2: HashMap<usize, Block> = HashMap::with_capacity(p3_ip_nos);

    let comm = &msg3_recv_p1.com_vals.p1_commitments;
    let decom = &msg3_recv_p1.decom_vals.x12_decom;
    for (i, decom_i) in decom.iter().enumerate().take(p1_ip_nos) {
        let (message, witness) = decom_i;
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if commitment.verify(*message, *witness, comt) {
            garbled_garbler_inputs.insert(i, *message);
            // println!("1 0");
        } else {
            comt = *comm.get(&(i, 1)).unwrap();
            if commitment.verify(*message, *witness, comt) {
                garbled_garbler_inputs.insert(i, *message);
                // println!("1 1");
            } else {
                return None;
            }
        }
    }

    // println!("x2");
    // println!("x2_decom {:?}\n", msg3_recv_p2.decom_vals.x12_decom);

    let comm = &msg3_recv_p1.com_vals.p2_commitments;
    let decom = &msg3_recv_p2.decom_vals.x12_decom;
    for (i, decom_i) in decom.iter().enumerate().take(p2_ip_nos) {
        let (message, witness) = decom_i;
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if commitment.verify(*message, *witness, comt) {
            garbled_garbler_inputs.insert(p1_ip_nos + i, *message);
            // println!("2 0");
        } else {
            comt = *comm.get(&(i, 1)).unwrap();
            if commitment.verify(*message, *witness, comt) {
                garbled_garbler_inputs.insert(p1_ip_nos + i, *message);
                // println!("2 1");
            } else {
                return None;
            }
        }
    }

    // println!("garbled garbler inputs: {:?}\n", garbled_garbler_inputs);
    // println!("x3");

    let comm = &msg3_recv_p1.com_vals.p3_commitments;
    let decom = &msg3_recv_p1.decom_vals.x34_decom;
    let bvals = &msg3_recv_p1.com_vals.b_values;
    let x3 = &state_r1.x3;
    for i in 0..p3_ip_nos {
        let aval = bvals[i] ^ x3[i];
        let (message, witness) = decom[i];
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if aval {
            comt = *comm.get(&(i, 1)).unwrap();
        }
        if commitment.verify(message, witness, comt) {
            garbled_evaluator_inputs.insert(i, message);
            // println!("3 0");
        } else {
            return None;
        }
    }

    // println!("x4");

    let comm = &msg3_recv_p2.com_vals.p3_commitments;
    let decom = &msg3_recv_p2.decom_vals.x34_decom;
    let x4 = &state_r1.x4;
    for i in 0..p3_ip_nos {
        let aval = bvals[i + p3_ip_nos] ^ x4[i];
        let (message, witness) = decom[i];
        let mut comt = *comm.get(&(p3_ip_nos + i, 0)).unwrap();
        if aval {
            comt = *comm.get(&(p3_ip_nos + i, 1)).unwrap();
        }
        if commitment.verify(message, witness, comt) {
            garbled_evaluator_inputs_2.insert(i, message);
            // println!("4 0");
        } else {
            return None;
        }
    }

    // println!("garbled evaluator inputs: {:?}\n", garbled_evaluator_inputs);
    // println!("garbled evaluator inputs 2: {:?}\n", garbled_evaluator_inputs_2);

    let hash = AesHash::new(HASH_KEY);
    let mut eval = BinaryEvaluator::new(
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        msg3_recv_p1.com_vals.delta,
        hash,
        msg3_recv_p1.com_vals.gc.clone(),
    );

    // println!(
    //     "garb: {:?}\ngarb2: {:?}",
    //     garbled_evaluator_inputs, garbled_evaluator_inputs_2
    // );
    let dec = eval
        .garbled_evaluate_threeparty(
            circuit.clone(),
            garbled_garbler_inputs,
            [garbled_evaluator_inputs, garbled_evaluator_inputs_2],
        )
        .unwrap();
    // let op = eval.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), dec.clone());

    // // println!("op: {:?} ", op);

    Some(ThreePGMsg4 { garbled_op: dec })
}

pub fn threepg_process_msg4_p12(
    msg4_recv: &ThreePGMsg4,
    msg3: &ThreePGMsg3,
    circuit: &BinaryCircuit,
    int_r3: &ThreePGPartyIntStateR3,
) {
    let hash = AesHash::new(HASH_KEY);
    let eval = BinaryEvaluator::new(
        int_r3.garbling_encoding.clone(),
        int_r3.evaluator_encoding.clone(),
        int_r3.decoding_info.clone(),
        int_r3.delta,
        hash,
        msg3.com_vals.gc.clone(),
    );
    let op = eval.get_plaintext_output(
        circuit.get_output_gate_ids().to_vec(),
        msg4_recv.garbled_op.clone(),
    );

    println!("output: {:?}", op);

    assert!(op[0]);
}

// pub fn threepg_soft_decode(msg4: &ThreePGMsg4, circuit: &BinaryCircuit) {
//     let mut output = Vec::new();
//     for gate in circuit.get_output_gate_ids() {
//         if let Some(x) = msg4.garbled_op.get(gate) {
//             output.push(x[0] != 0);
//         }
//     }

//     println!("output: {:?}", output);
// }

pub fn test_run_3party_garbling(
    circuit: &BinaryCircuit,
    input_p1: &[bool],
    input_p2: &[bool],
    input_p3: &[bool],
) {
    let mut rng_comm = rand::thread_rng();

    let inputlen_p1 = input_p1.len();
    let inputlen_p2 = input_p2.len();
    let inputlen_p3 = input_p3.len();

    // Round 1

    let msg1_p3 = threepg_create_msg1_p3(input_p3, &mut rng_comm);

    // P3 sends msg1_p3.p1_data and msg1_p3.p2_data to P1 and P2 respectively
    let state_r1_p1 = threepg_process_msg1_p12(&msg1_p3.p1_data);
    let state_r1_p2 = threepg_process_msg1_p12(&msg1_p3.p2_data);
    let state_r1_p3 = threepg_process_msg1_p3(&msg1_p3);

    // Round 2

    let prf_seed_p1 = threepg_create_msg2_p1(&mut rng_comm);

    // P1 sends prf_seed_p1 to P2
    let state_r2_p1 = threepg_process_msg2_p12(&prf_seed_p1);
    let state_r2_p2 = threepg_process_msg2_p12(&prf_seed_p1);

    // Round 3

    let (msg3_p1, int_r3_p1) = threepg_create_msg3_p1(
        inputlen_p1,
        inputlen_p2,
        inputlen_p3,
        input_p1,
        &state_r1_p1,
        &state_r2_p1.prf_seed,
        circuit,
    )
    .unwrap();
    let (msg3_p2, int_r3_p2) = threepg_create_msg3_p2(
        inputlen_p1,
        inputlen_p2,
        inputlen_p3,
        input_p2,
        &state_r1_p2,
        &state_r2_p2.prf_seed,
        circuit,
    )
    .unwrap();

    // P1 sends msg3_p1 and P2 sends msg3_p2 respectively to P3
    let msg4_p3 = threepg_create_msg4_p3(&state_r1_p3, &msg3_p1, &msg3_p2, circuit).unwrap();

    // Round 4

    // P3 sends msg4_p3 to P1 and P2
    threepg_process_msg4_p12(&msg4_p3, &msg3_p1, circuit, &int_r3_p1);
    threepg_process_msg4_p12(&msg4_p3, &msg3_p2, circuit, &int_r3_p2);

    // P3 decodes to get the output
    // threepg_soft_decode(&msg4_p3, &circuit);

    // println!("{:?}", int_r3_p1.decoding_info.clone());
}

#[cfg(test)]
mod tests {
    use crate::customcircuits::comparison::build_comparison_circuit_threeparty;

    use super::test_run_3party_garbling;

    #[test]
    pub fn test_three_party_garbling() {
        for _ in 0..1000 {
            test_3pgarbling_comparison();
        }
    }

    fn test_3pgarbling_comparison() {
        let input_p1 = vec![false];
        let input_p2 = vec![false];
        let input_p3 = vec![false, false];
        let circuit = build_comparison_circuit_threeparty();

        test_run_3party_garbling(&circuit, &input_p1, &input_p2, &input_p3);
    }
}
