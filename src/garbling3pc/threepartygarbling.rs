use std::collections::HashMap;

use rand::{rngs::ThreadRng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::constants::HASH_KEY,
    garbling2pc::{evaluator_operations::BinaryEvaluator, garbler_operations::BinaryGarbler},
    garbling3pc::threepartytraits::ThreePartyBinaryEvaluator,
    utilities::{
        commitments::{Commitment, HashCommitment},
        hash_function::AesHash,
        types::Block,
        utils::xor_blocks,
    },
};

use super::threepartytraits::ThreePartyBinaryGarbler;

/// Type for the three-party garbled-circuit protocol's message 1
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg1 {
    /// x3 for P1 and x4 for P3.
    pub x: Vec<bool>,

    /// Common random string for instantiating commitments.
    pub comm_crs: Block,
}

/// Abstract type for the three-party garbled-circuit protocol's message 1
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg1Abs {
    /// Msg1 to be sent from P3 to P1.
    pub p1_data: ThreePGMsg1,

    /// Msg1 to be sent from P3 to P2.
    pub p2_data: ThreePGMsg1,
}

/// Type for the three-party garbled-circuit protocol's message 3
/// which stores random pads, garbled circuits and commitments.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg3Coms {
    /// Random pads for P3's inputs.
    pub b_values: Vec<bool>,

    /// Garbled Circuit.
    pub gc: Vec<Block>,

    /// Global delta value for the Free-XOR technique.
    pub delta: Block,

    /// Commitments generated on P1's inputs.
    pub p1_commitments: HashMap<(usize, usize), Block>,

    /// Commitments generated on P2's inputs.
    pub p2_commitments: HashMap<(usize, usize), Block>,

    /// Commitments generated on P3's inputs.
    pub p3_commitments: HashMap<(usize, usize), Block>,
}

/// Type for the three-party garbled-circuit protocol's message 3
/// which stores decommitments.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg3Decoms {
    /// Decommitments generated on P1's inputs by
    /// P1 and P2's inputs by P2.
    pub x12_decom: Vec<(Block, Block)>,

    /// Decommitments generated on x3 by P1 and x4 by P2.
    pub x34_decom: Vec<(Block, Block)>,
}

/// Abstract type for the three-party garbled-circuit protocol's message 3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg3 {
    /// Commitments and random values.
    pub com_vals: ThreePGMsg3Coms,

    /// Decommitments.
    pub decom_vals: ThreePGMsg3Decoms,
}

/// Type for the three-party garbled-circuit protocol's message 4.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGMsg4 {
    /// Garbled output.
    garbled_op: HashMap<usize, Block>,
}

/// Type for the three-party garbled-circuit protocol's output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGOutput {
    /// Output vector.
    output: Vec<bool>,
}

/// Type for the three-party garbled-circuit protocol's state after
/// R1 maintained by P1 and P2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGParty12StateR1 {
    /// x3 received by P1 and x4 received by P2
    x: Vec<bool>,

    /// Common random string for instantiating commitments.
    comm_crs: Block,
}

/// Type for the three-party garbled-circuit protocol's state after
/// R1 maintained by P3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGParty3StateR1 {
    /// x3 generated.
    x3: Vec<bool>,

    /// x4 generated.
    x4: Vec<bool>,

    /// Common random string for instantiating commitments.
    comm_crs: Block,
}

/// Type for the three-party garbled-circuit protocol's state after
/// R2 maintained by all parties.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGPartyStateR2 {
    /// prf_seed used for generating all random values.
    prf_seed: Block,
}

/// Type for the three-party garbled-circuit protocol's state after
/// R2 maintained by parties P1 and P2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGParty12StateR3 {
    /// Global delta value for the Free-XOR technique.
    delta: Block,

    /// Random pads for all inputs.
    b_vec: [Vec<bool>; 3],

    /// Garbled Circuit.
    gc: Vec<Block>,

    /// Encoding of garbler's input gates, corresponding to false values
    garbler_encoding: HashMap<usize, Block>,

    /// Encoding of evaluator's input gates, corresponding to false values
    evaluator_encoding: HashMap<usize, Block>,

    /// Decoding information of the output gates
    decoding_info: HashMap<usize, u8>,

    /// Commitments generated on P1's inputs.
    pub p1_commitments: HashMap<(usize, usize), Block>,

    /// Commitments generated on P2's inputs.
    pub p2_commitments: HashMap<(usize, usize), Block>,

    /// Commitments generated on P3's inputs.
    pub p3_commitments: HashMap<(usize, usize), Block>,

    /// Commitments generated on P1's inputs.
    p1_decommitments: HashMap<(usize, usize), (Block, Block)>,

    /// Commitments generated on P2's inputs.
    p2_decommitments: HashMap<(usize, usize), (Block, Block)>,

    /// Commitments generated on P3's inputs.
    p3_decommitments: HashMap<(usize, usize), (Block, Block)>,
}

/// Type for the three-party garbled-circuit protocol's state after
/// R3 maintained by party P3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGParty3StateR3 {
    /// msg3 sent to P3 by P1.
    msg3_p1: ThreePGMsg3,

    /// msg3 sent to P3 by P2.
    msg3_p2: ThreePGMsg3,
}

/// Type for the three-party garbled-circuit protocol's state after
/// R3 maintained by all parties.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreePGPartyStateR4 {
    /// msg4 generated by P3 and broadcasted to all parties.
    msg4: ThreePGMsg4,
}

/// Generates msg1 of the three-party garbled-circuit protocol, and run by P3.
pub fn threepg_create_msg1_p3(input: &[bool], rng: &mut ThreadRng) -> ThreePGMsg1Abs {
    let comm_crs: Block = rng.random();
    let mut x3 = Vec::new();
    for _ in 0..input.len() {
        x3.push(rng.random_bool(0.5));
    }
    let mut x4 = Vec::new();
    for i in 0..input.len() {
        x4.push(x3[i] ^ input[i]);
    }
    ThreePGMsg1Abs {
        p1_data: ThreePGMsg1 { x: x3, comm_crs },
        p2_data: ThreePGMsg1 { x: x4, comm_crs },
    }
}

/// Processes msg1 of the three-party garbled-circuit protocol, and run by P1 and P2.
pub fn threepg_process_msg1_p12(msg1_recv: &ThreePGMsg1) -> ThreePGParty12StateR1 {
    ThreePGParty12StateR1 {
        comm_crs: msg1_recv.comm_crs,
        x: msg1_recv.x.clone(),
    }
}

/// Processes msg1 of the three-party garbled-circuit protocol, and run by P3.
pub fn threepg_process_msg1_p3(msg1: &ThreePGMsg1Abs) -> ThreePGParty3StateR1 {
    ThreePGParty3StateR1 {
        comm_crs: msg1.p1_data.comm_crs,
        x3: msg1.p1_data.x.clone(),
        x4: msg1.p2_data.x.clone(),
    }
}

/// Generates msg2 of the three-party garbled-circuit protocol, and run by P1.
pub fn threepg_create_msg2_p1(rng: &mut ThreadRng) -> Block {
    let prf_seed: Block = rng.random();
    prf_seed
}

/// Processes msg2 of the three-party garbled-circuit protocol, and run by P1 and P2.
pub fn threepg_process_msg2_p12(prf_seed: &Block) -> ThreePGPartyStateR2 {
    ThreePGPartyStateR2 {
        prf_seed: *prf_seed,
    }
}

/// Generates and processes msg3 of the three-party garbled-circuit protocol, and run by P1.
pub fn threepg_create_msg3_p1(
    p1_ip_nos: usize,
    p2_ip_nos: usize,
    p3_ip_nos: usize,
    input_p1: &[bool],
    p1_state_r1: &ThreePGParty12StateR1,
    prf_seed: &Block,
    circuit: &BinaryCircuit,
) -> Result<(ThreePGMsg3, ThreePGParty12StateR3), String> {
    let hash = AesHash::new(HASH_KEY);
    let rng_key: [u8; 32] = *prf_seed;
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
        b_vec[0].push(rng.random_bool(0.5));
    }
    for _ in 0..p2_ip_nos {
        b_vec[1].push(rng.random_bool(0.5));
    }
    for _ in 0..2 * p3_ip_nos {
        b_vec[2].push(rng.random_bool(0.5));
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
            let witness: Block = rng.random();
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
            let witness: Block = rng.random();
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
            let witness: Block = rng.random();
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
            let witness: Block = rng.random();
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

    for (i, b_i) in b_vec[2].iter().enumerate().take(p3_ip_nos) {
        let val = b_i ^ p1_state_r1.x[i];
        if val {
            x3_decom.push(*p3_decommitments.get(&(i, 1)).unwrap());
        } else {
            x3_decom.push(*p3_decommitments.get(&(i, 0)).unwrap());
        }
    }

    Ok((
        ThreePGMsg3 {
            com_vals: ThreePGMsg3Coms {
                b_values: b_vec[2].clone(),
                gc: garble_output.garbled_circuit.clone(),
                delta,
                p1_commitments: p1_commitments.clone(),
                p2_commitments: p2_commitments.clone(),
                p3_commitments: p3_commitments.clone(),
            },
            decom_vals: ThreePGMsg3Decoms {
                x12_decom: x1_decom,
                x34_decom: x3_decom,
            },
        },
        ThreePGParty12StateR3 {
            delta,
            b_vec,
            gc: garble_output.garbled_circuit,
            garbler_encoding: garble_output.garbler_input_encodings,
            decoding_info: garble_output.decoding_infos,
            evaluator_encoding: garble_output.evaluator_input_encodings,
            p1_commitments,
            p2_commitments,
            p3_commitments,
            p1_decommitments,
            p2_decommitments,
            p3_decommitments,
        },
    ))
}

/// Generates and processes msg3 of the three-party garbled-circuit protocol, and run by P2.
pub fn threepg_create_msg3_p2(
    p1_ip_nos: usize,
    p2_ip_nos: usize,
    p3_ip_nos: usize,
    input_p2: &[bool],
    p2_state_r1: &ThreePGParty12StateR1,
    prf_seed: &Block,
    circuit: &BinaryCircuit,
) -> Result<(ThreePGMsg3, ThreePGParty12StateR3), String> {
    let hash = AesHash::new(HASH_KEY);

    let rng_key: [u8; 32] = *prf_seed;
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
        b_vec[0].push(rng.random_bool(0.5));
    }
    for _ in 0..p2_ip_nos {
        b_vec[1].push(rng.random_bool(0.5));
    }
    for _ in 0..2 * p3_ip_nos {
        b_vec[2].push(rng.random_bool(0.5));
    }

    let hash_commit = HashCommitment::new(AesHash::new(p2_state_r1.comm_crs));

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
            let witness: Block = rng.random();
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
            let witness: Block = rng.random();
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
            let witness: Block = rng.random();
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
            let witness: Block = rng.random();
            let commitment = hash_commit.commit(e_en_j, witness);
            p3_commitments.insert((p3_ip_nos + j, a), commitment);
            p3_decommitments.insert((p3_ip_nos + j, a), (e_en_j, witness));
        }
    }

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

    for i in 0..p3_ip_nos {
        let val = b_vec[2][p3_ip_nos + i] ^ p2_state_r1.x[i];
        if val {
            x4_decom.push(*p3_decommitments.get(&(i + p3_ip_nos, 1)).unwrap());
        } else {
            x4_decom.push(*p3_decommitments.get(&(i + p3_ip_nos, 0)).unwrap());
        }
    }

    Ok((
        ThreePGMsg3 {
            com_vals: ThreePGMsg3Coms {
                b_values: b_vec[2].clone(),
                gc: garble_output.garbled_circuit.clone(),
                delta,
                p1_commitments: p1_commitments.clone(),
                p2_commitments: p2_commitments.clone(),
                p3_commitments: p3_commitments.clone(),
            },
            decom_vals: ThreePGMsg3Decoms {
                x12_decom: x2_decom,
                x34_decom: x4_decom,
            },
        },
        ThreePGParty12StateR3 {
            delta,
            b_vec,
            gc: garble_output.garbled_circuit,
            garbler_encoding: garble_output.garbler_input_encodings,
            decoding_info: garble_output.decoding_infos,
            evaluator_encoding: garble_output.evaluator_input_encodings,
            p1_commitments,
            p2_commitments,
            p3_commitments,
            p1_decommitments,
            p2_decommitments,
            p3_decommitments,
        },
    ))
}

/// Processes msg3 of the three-party garbled-circuit protocol, and run by P3.
pub fn threepg_process_msg3_p3(
    msg3_recv_p1: &ThreePGMsg3,
    msg3_recv_p2: &ThreePGMsg3,
) -> ThreePGParty3StateR3 {
    ThreePGParty3StateR3 {
        msg3_p1: msg3_recv_p1.clone(),
        msg3_p2: msg3_recv_p2.clone(),
    }
}

/// Generates msg4 of the three-party garbled-circuit protocol, and run by P3.
pub fn threepg_create_msg4_p3(
    state_r1: &ThreePGParty3StateR1,
    state_r3: &ThreePGParty3StateR3,
    circuit: &BinaryCircuit,
) -> Option<ThreePGMsg4> {
    if state_r3.msg3_p1.com_vals != state_r3.msg3_p2.com_vals {
        return None;
    }

    let commitment = HashCommitment::new(AesHash::new(state_r1.comm_crs));

    let p1_ip_nos = state_r3.msg3_p1.com_vals.p1_commitments.len() / 2;
    let p2_ip_nos = state_r3.msg3_p1.com_vals.p2_commitments.len() / 2;
    let p3_ip_nos = state_r3.msg3_p1.com_vals.p3_commitments.len() / 4;

    let mut garbled_garbler_inputs: HashMap<usize, Block> =
        HashMap::with_capacity(p1_ip_nos + p2_ip_nos);
    let mut garbled_evaluator_inputs: HashMap<usize, Block> = HashMap::with_capacity(2 * p3_ip_nos);

    let comm = &state_r3.msg3_p1.com_vals.p1_commitments;
    let decom = &state_r3.msg3_p1.decom_vals.x12_decom;
    for (i, decom_i) in decom.iter().enumerate().take(p1_ip_nos) {
        let (message, witness) = decom_i;
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if commitment.verify(*message, *witness, comt) {
            garbled_garbler_inputs.insert(i, *message);
        } else {
            comt = *comm.get(&(i, 1)).unwrap();
            if commitment.verify(*message, *witness, comt) {
                garbled_garbler_inputs.insert(i, *message);
            } else {
                return None;
            }
        }
    }

    let comm = &state_r3.msg3_p1.com_vals.p2_commitments;
    let decom = &state_r3.msg3_p2.decom_vals.x12_decom;
    for (i, decom_i) in decom.iter().enumerate().take(p2_ip_nos) {
        let (message, witness) = decom_i;
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if commitment.verify(*message, *witness, comt) {
            garbled_garbler_inputs.insert(p1_ip_nos + i, *message);
        } else {
            comt = *comm.get(&(i, 1)).unwrap();
            if commitment.verify(*message, *witness, comt) {
                garbled_garbler_inputs.insert(p1_ip_nos + i, *message);
            } else {
                return None;
            }
        }
    }

    let comm = &state_r3.msg3_p1.com_vals.p3_commitments;
    let decom = &state_r3.msg3_p1.decom_vals.x34_decom;
    let bvals = &state_r3.msg3_p1.com_vals.b_values;
    let x3 = &state_r1.x3;
    for i in 0..p3_ip_nos {
        let aval = bvals[i] ^ x3[i];
        let (message, witness) = decom[i];
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if aval {
            comt = *comm.get(&(i, 1)).unwrap();
        }
        if commitment.verify(message, witness, comt) {
            garbled_evaluator_inputs.insert(2 * i, message);
        } else {
            return None;
        }
    }

    let comm = &state_r3.msg3_p2.com_vals.p3_commitments;
    let decom = &state_r3.msg3_p2.decom_vals.x34_decom;
    let x4 = &state_r1.x4;
    for i in 0..p3_ip_nos {
        let aval = bvals[i + p3_ip_nos] ^ x4[i];
        let (message, witness) = decom[i];
        let mut comt = *comm.get(&(p3_ip_nos + i, 0)).unwrap();
        if aval {
            comt = *comm.get(&(p3_ip_nos + i, 1)).unwrap();
        }
        if commitment.verify(message, witness, comt) {
            garbled_evaluator_inputs.insert(2 * i + 1, message);
        } else {
            return None;
        }
    }

    let hash = AesHash::new(HASH_KEY);
    let mut eval = BinaryEvaluator::new(HashMap::new(), hash, state_r3.msg3_p1.com_vals.gc.clone());

    let dec = eval
        .evaluate_threeparty(circuit, &garbled_garbler_inputs, &garbled_evaluator_inputs)
        .unwrap();

    Some(ThreePGMsg4 { garbled_op: dec })
}

/// Processes msg4 of the three-party garbled-circuit protocol, and run by all parties.
pub fn threepg_process_msg4(msg4_recv: &ThreePGMsg4) -> ThreePGPartyStateR4 {
    ThreePGPartyStateR4 {
        msg4: msg4_recv.clone(),
    }
}

/// Generates the output of the three-party garbled-circuit protocol, and run by P1 and P2.
pub fn threepg_create_msg5_p12(
    state_r4: &ThreePGPartyStateR4,
    circuit: &BinaryCircuit,
    state_r3: &ThreePGParty12StateR3,
) -> ThreePGOutput {
    let hash = AesHash::new(HASH_KEY);
    let eval = BinaryEvaluator::new(state_r3.decoding_info.clone(), hash, state_r3.gc.clone());
    let op = eval.get_plaintext_output(
        circuit.get_output_gate_ids().to_vec(),
        state_r4.msg4.garbled_op.clone(),
    );

    ThreePGOutput { output: op }
}

/// Processes and generates the output of the three-party garbled-circuit protocol, and run by P3.
pub fn threepg_process_output_p3(
    out_recv_p1: &ThreePGOutput,
    out_recv_p2: &ThreePGOutput,
) -> ThreePGOutput {
    assert_eq!(out_recv_p1.output, out_recv_p2.output);
    out_recv_p1.clone()
}

pub fn test_run_3party_garbling(
    circuit: &BinaryCircuit,
    input_p1: &[bool],
    input_p2: &[bool],
    input_p3: &[bool],
) -> (Vec<bool>, Vec<bool>, Vec<bool>) {
    let mut rng_comm = rand::rng();

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

    let (msg3_p1, state_r3_p1) = threepg_create_msg3_p1(
        inputlen_p1,
        inputlen_p2,
        inputlen_p3,
        input_p1,
        &state_r1_p1,
        &state_r2_p1.prf_seed,
        circuit,
    )
    .unwrap();
    let (msg3_p2, state_r3_p2) = threepg_create_msg3_p2(
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

    let state_r3_p3 = threepg_process_msg3_p3(&msg3_p1, &msg3_p2);

    // Round 4

    let msg4_p3 = threepg_create_msg4_p3(&state_r1_p3, &state_r3_p3, circuit).unwrap();

    // P3 sends msg4_p3 to P1 and P2

    let state_r4_p1 = threepg_process_msg4(&msg4_p3);
    let state_r4_p2 = threepg_process_msg4(&msg4_p3);

    // Round 5

    let op_p1 = threepg_create_msg5_p12(&state_r4_p1, circuit, &state_r3_p1);
    let op_p2 = threepg_create_msg5_p12(&state_r4_p2, circuit, &state_r3_p2);

    // P1 and P2 sends op_p1 and op_p2 respectively to P3 which compares them and outputs it
    let op_p3 = threepg_process_output_p3(&op_p1, &op_p2);

    (op_p1.output, op_p2.output, op_p3.output)
}

#[cfg(test)]
mod tests {
    use crate::{
        circuitop::circuit::BinaryCircuit,
        customcircuits::comparison::build_comparison_circuit_threeparty,
        garbling3pc::threepartytraits::ThreePartyBinaryCircuit, utilities::utils::bool_vec_to_hex,
    };

    use super::test_run_3party_garbling;

    #[test]
    pub fn test_three_party_garbling_comparison() {
        for _ in 0..50 {
            test_3pgarbling_comparison();
        }
    }

    #[test]
    pub fn test_three_party_garbling_aes() {
        for _ in 0..50 {
            test_3pgarbling_aes();
        }
    }

    fn test_3pgarbling_comparison() {
        let input_p1 = vec![false];
        let input_p2 = vec![false];
        let input_p3 = vec![false, false];
        let circuit = build_comparison_circuit_threeparty();

        let (op_p1, op_p2, op_p3) =
            test_run_3party_garbling(&circuit, &input_p1, &input_p2, &input_p3);

        assert!(op_p1[0]);
        assert!(op_p2[0]);
        assert!(op_p3[0]);
    }

    fn test_3pgarbling_aes() {
        let circuit = BinaryCircuit::parse_threeparty("circuits/aes128.txt").unwrap();

        for i in 0..2 {
            for j in 0..2 {
                let input_p1 = vec![i != 0; 64];
                let input_p2 = vec![i != 0; 64];
                let input_p3 = vec![j != 0; 128];

                let (op_p1, op_p2, op_p3) =
                    test_run_3party_garbling(&circuit, &input_p1, &input_p2, &input_p3);

                assert_eq!(op_p1, op_p2);
                assert_eq!(op_p3, op_p2);

                let hexout_p1 = bool_vec_to_hex(op_p1);

                let count = 2 * i + j;
                if count == 0 {
                    assert_eq!(
                        hexout_p1,
                        "74d42c539a5f3211dc3451f72bd29766".to_string(),
                        "outval: {} realval: 74d42c539a5f3211dc3451f72bd29766",
                        hexout_p1
                    );
                } else if count == 2 {
                    assert_eq!(
                        hexout_p1,
                        "3493fd1ca2122691b3fabee131a46f85".to_string(),
                        "outval: {} realval: 3493fd1ca2122691b3fabee131a46f85",
                        hexout_p1
                    );
                } else if count == 1 {
                    assert_eq!(
                        hexout_p1,
                        "7266b17c4be2ce5f505aa1579331dafc".to_string(),
                        "outval: {} realval: 7266b17c4be2ce5f505aa1579331dafc",
                        hexout_p1
                    );
                } else if count == 3 {
                    assert_eq!(
                        hexout_p1,
                        "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string(),
                        "outval: {} realval: 9e9d5c984a0e8a4d0cf3014d3e84fd3d",
                        hexout_p1
                    );
                }
            }
        }
    }
}
