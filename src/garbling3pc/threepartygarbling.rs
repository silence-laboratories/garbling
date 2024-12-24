use rand::{rngs::ThreadRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::HashMap;

use crate::circuitop::circuit::BinaryCircuit;
use crate::config::constants::Block;
use crate::garbling2pc::{
    evaluator_operations::BinaryEvaluator, garbler_operations::BinaryGarbler,
};
use crate::garbling3pc::threepartytraits::ThreePartyBinaryEvaluator;
use crate::utilities::{
    commitments::{Commitment, HashCommitment},
    hash_function::{AesHash, HashFunction},
    utils::xor_blocks,
};

use super::threepartytraits::ThreePartyBinaryGarbler;

#[derive(Clone, Debug, PartialEq)]
pub struct ThreePGM1 {
    x: Vec<bool>,
    comm_crs: Block,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThreePGM1Abs {
    p0_data: ThreePGM1,
    p1_data: ThreePGM1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThreePGM3 {
    b_values: Vec<bool>,
    gc: Vec<Block>,
    delta: Block,
    p0_commitments: HashMap<(usize, usize), Block>,
    p1_commitments: HashMap<(usize, usize), Block>,
    p2_commitments: HashMap<(usize, usize), Block>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThreePGM4 {
    x12_decom: Vec<(Block, Block)>,
    x34_decom: Vec<(Block, Block)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThreepgProcessM12OP {
    delta: Block,
    b_vec: [Vec<bool>; 3],
    garbling_encoding: HashMap<usize, Block>,
    evaluator_encoding: HashMap<usize, Block>,
    decoding_info: HashMap<usize, u8>,
    p0_decommitments: HashMap<(usize, usize), (Block, Block)>,
    p1_decommitments: HashMap<(usize, usize), (Block, Block)>,
    p2_decommitments: HashMap<(usize, usize), (Block, Block)>,
}

pub struct ThreepgProcessM3M4CreateM5P2<H: HashFunction> {
    pub x3struct: ThreePGM1,
    pub x4struct: ThreePGM1,
    pub commitment: HashCommitment<H>,
    pub prf_seed: Block,
    pub m3_recv_p0: ThreePGM3,
    pub m3_recv_p1: ThreePGM3,
    pub m4_recv_p0: ThreePGM4,
    pub m4_recv_p1: ThreePGM4,
    pub circuit: BinaryCircuit,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThreePGM5 {
    garbled_op: HashMap<usize, [u8; 16]>,
}

pub fn threepg_create_m1_p2(input: Vec<bool>, rng: &mut ThreadRng) -> ThreePGM1Abs {
    let comm_crs: Block = rng.gen();
    let mut x3 = Vec::new();
    for _ in 0..input.len() {
        x3.push(rng.gen_bool(0.5));
    }
    let mut x4 = Vec::new();
    for i in 0..input.len() {
        x4.push(x3[i] ^ input[i]);
    }
    ThreePGM1Abs {
        p0_data: ThreePGM1 { x: x3, comm_crs },
        p1_data: ThreePGM1 { x: x4, comm_crs },
    }
}

pub fn threepg_create_m2_p0(rng: &mut ThreadRng) -> Block {
    let prf_seed: Block = rng.gen();
    prf_seed
}

pub fn threepg_process_m1_m2_create_m3_p0_p1(
    p0_ip_nos: usize,
    p1_ip_nos: usize,
    p2_ip_nos: usize,
    m1_recv: ThreePGM1,
    prf_seed: Block,
    circuit: BinaryCircuit,
) -> Option<(ThreePGM3, ThreepgProcessM12OP)> {
    let hash = AesHash::new(prf_seed);
    let mut garbler = BinaryGarbler::new(hash.clone());
    let garble_output = garbler.garble_threeparty(circuit.clone()).unwrap();
    let delta = garbler.delta;

    let mut rng_key: [u8; 32] = [0u8; 32];
    rng_key[..16].copy_from_slice(&prf_seed);
    rng_key[16..(16 + 16)].copy_from_slice(&prf_seed);
    if p0_ip_nos + p1_ip_nos != circuit.num_garbler_inputs() {
        return None;
    }

    if p2_ip_nos != circuit.num_evaluator_inputs() / 2 {
        return None;
    }
    let mut rng = ChaChaRng::from_seed(rng_key);
    let mut b_vec = [
        Vec::with_capacity(p0_ip_nos),
        Vec::with_capacity(p1_ip_nos),
        Vec::with_capacity(2 * p2_ip_nos),
    ];
    for _ in 0..p0_ip_nos {
        b_vec[0].push(rng.gen_bool(0.5));
    }
    for _ in 0..p1_ip_nos {
        b_vec[1].push(rng.gen_bool(0.5));
    }
    for _ in 0..2 * p2_ip_nos {
        b_vec[2].push(rng.gen_bool(0.5));
    }

    let hash_commit = HashCommitment::new(AesHash::new(m1_recv.comm_crs));

    let mut p0_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p0_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();
    let mut p1_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p1_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();
    let mut p2_commitments: HashMap<(usize, usize), Block> = HashMap::new();
    let mut p2_decommitments: HashMap<(usize, usize), (Block, Block)> = HashMap::new();

    for j in 0..p0_ip_nos {
        let mut g_en_j = *garble_output.garbler_input_encodings.get(&j).unwrap();
        for a in 0..2 {
            if b_vec[0][j] ^ (a != 0) {
                g_en_j = xor_blocks(g_en_j, delta);
            }
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(g_en_j, witness);
            p0_commitments.insert((j, a), commitment);
            p0_decommitments.insert((j, a), (g_en_j, witness));
        }
    }
    for j in 0..p1_ip_nos {
        let mut g_en_j = *garble_output
            .garbler_input_encodings
            .get(&(p0_ip_nos + j))
            .unwrap();
        for a in 0..2 {
            if b_vec[1][j] ^ (a != 0) {
                g_en_j = xor_blocks(g_en_j, delta);
            }
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(g_en_j, witness);
            p1_commitments.insert((j, a), commitment);
            p1_decommitments.insert((j, a), (g_en_j, witness));
        }
    }
    for j in 0..p2_ip_nos {
        let mut e_en_j = *garble_output
            .evaluator_input_encodings
            .get(&(2 * j))
            .unwrap();
        for a in 0..2 {
            if b_vec[2][j] ^ (a != 0) {
                e_en_j = xor_blocks(e_en_j, delta);
            }
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(e_en_j, witness);
            p2_commitments.insert((j, a), commitment);
            p2_decommitments.insert((j, a), (e_en_j, witness));
        }
    }

    for j in 0..p2_ip_nos {
        let mut e_en_j = *garble_output
            .evaluator_input_encodings
            .get(&(2 * j + 1))
            .unwrap();
        for a in 0..2 {
            if b_vec[2][j] ^ (a != 0) {
                e_en_j = xor_blocks(e_en_j, delta);
            }
            let witness: Block = rng.gen();
            let commitment = hash_commit.commit(e_en_j, witness);
            p2_commitments.insert((p2_ip_nos + j, a), commitment);
            p2_decommitments.insert((p2_ip_nos + j, a), (e_en_j, witness));
        }
    }
    Some((
        ThreePGM3 {
            b_values: b_vec[2].clone(),
            gc: garble_output.garbled_circuit,
            delta,
            p0_commitments,
            p1_commitments,
            p2_commitments,
        },
        ThreepgProcessM12OP {
            delta,
            b_vec,
            garbling_encoding: garble_output.garbler_input_encodings,
            decoding_info: garble_output.decoding_infos,
            evaluator_encoding: garble_output.evaluator_input_encodings,
            p0_decommitments,
            p1_decommitments,
            p2_decommitments,
        },
    ))
}

pub fn threepg_create_m4_p0(
    x3struct: ThreePGM1,
    input: Vec<bool>,
    m12_process: ThreepgProcessM12OP,
) -> ThreePGM4 {
    let mut x1_decom: Vec<(Block, Block)> = Vec::new();
    let mut x3_decom: Vec<(Block, Block)> = Vec::new();
    let len1 = m12_process.b_vec[0].len();
    if len1 != input.len() {
        println!("input lengths not consistent");
    }
    let b = m12_process.b_vec[0].clone();
    for i in 0..len1 {
        let val = b[i] ^ input[i];
        if val {
            x1_decom.push(*m12_process.p0_decommitments.get(&(i, 1)).unwrap());
        } else {
            x1_decom.push(*m12_process.p0_decommitments.get(&(i, 0)).unwrap());
        }
    }
    let b = m12_process.b_vec[2].clone();
    for (i, b_i) in b.iter().enumerate().take(x3struct.x.len()) {
        let val = b_i ^ x3struct.x[i];
        if val {
            x3_decom.push(*m12_process.p2_decommitments.get(&(i, 1)).unwrap());
        } else {
            x3_decom.push(*m12_process.p2_decommitments.get(&(i, 0)).unwrap());
        }
    }

    ThreePGM4 {
        x12_decom: x1_decom,
        x34_decom: x3_decom,
    }
}

pub fn threepg_create_m4_p1(
    x4struct: ThreePGM1,
    input: Vec<bool>,
    m12_process: ThreepgProcessM12OP,
) -> ThreePGM4 {
    let mut x2_decom: Vec<(Block, Block)> = Vec::new();
    let mut x4_decom: Vec<(Block, Block)> = Vec::new();
    let len1 = m12_process.b_vec[1].len();
    if len1 != input.len() {
        println!("input lengths not consistent");
    }
    let b = m12_process.b_vec[1].clone();
    for i in len1 / 2..len1 {
        let val = b[i] ^ input[i];
        if val {
            x2_decom.push(*m12_process.p1_decommitments.get(&(i, 1)).unwrap());
        } else {
            x2_decom.push(*m12_process.p1_decommitments.get(&(i, 0)).unwrap());
        }
    }

    let b = m12_process.b_vec[2].clone();
    let len2 = m12_process.b_vec[2].len() / 2;
    for i in 0..x4struct.x.len() {
        let val = b[len2 + i] ^ x4struct.x[i];
        if val {
            x4_decom.push(*m12_process.p2_decommitments.get(&(i + len2, 1)).unwrap());
        } else {
            x4_decom.push(*m12_process.p2_decommitments.get(&(i + len2, 0)).unwrap());
        }
    }

    ThreePGM4 {
        x12_decom: x2_decom,
        x34_decom: x4_decom,
    }
}

pub fn threepg_process_m3_m4_create_m5_p2<H: HashFunction>(
    input: ThreepgProcessM3M4CreateM5P2<H>,
) -> Option<ThreePGM5> {
    if input.m3_recv_p0 != input.m3_recv_p1 {
        return None;
    }
    let p0_ip_nos = input.m3_recv_p0.p0_commitments.len() / 2;
    let p1_ip_nos = input.m3_recv_p0.p1_commitments.len() / 2;
    let p2_ip_nos = input.m3_recv_p0.p2_commitments.len() / 2;

    let mut garbled_garbler_inputs: HashMap<usize, Block> =
        HashMap::with_capacity(p0_ip_nos + p1_ip_nos);
    let mut garbled_evaluator_inputs: HashMap<usize, Block> = HashMap::with_capacity(p2_ip_nos / 2);
    let mut garbled_evaluator_inputs_2: HashMap<usize, Block> =
        HashMap::with_capacity(p2_ip_nos / 2);
    println!("{}", p2_ip_nos);

    println!("x1");

    let comm = input.m3_recv_p0.p0_commitments;
    let decom = input.m4_recv_p0.x12_decom;
    for (i, decom_i) in decom.iter().enumerate().take(p0_ip_nos) {
        let (message, witness) = decom_i;
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if input.commitment.verify(*message, *witness, comt) {
            garbled_garbler_inputs.insert(i, *message);
            println!("1 0");
        } else {
            comt = *comm.get(&(i, 1)).unwrap();
            if input.commitment.verify(*message, *witness, comt) {
                garbled_garbler_inputs.insert(i, *message);
                println!("1 1");
            } else {
                return None;
            }
        }
    }

    println!("x2");

    let comm = input.m3_recv_p0.p1_commitments;
    let decom = input.m4_recv_p1.x12_decom;
    for (i, decom_i) in decom.iter().enumerate().take(p1_ip_nos) {
        let (message, witness) = decom_i;
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if input.commitment.verify(*message, *witness, comt) {
            garbled_garbler_inputs.insert(p0_ip_nos + i, comt);
            println!("2 0");
        } else {
            comt = *comm.get(&(i, 1)).unwrap();
            if input.commitment.verify(*message, *witness, comt) {
                garbled_garbler_inputs.insert(p0_ip_nos + i, comt);
                println!("2 1");
            } else {
                return None;
            }
        }
    }

    println!("x3");

    let comm = input.m3_recv_p0.p2_commitments;
    let decom = input.m4_recv_p0.x34_decom;
    let bvals = input.m3_recv_p0.b_values;
    let x3 = input.x3struct.x;
    // let mut com_crs = HashCommitment::new(AesHash::new(x3struct.comm_crs));
    for i in 0..p2_ip_nos / 2 {
        let aval = bvals[i] ^ x3[i];
        let (message, witness) = decom[i];
        let mut comt = *comm.get(&(i, 0)).unwrap();
        if aval {
            comt = *comm.get(&(i, 1)).unwrap();
        }
        if input.commitment.verify(message, witness, comt) {
            garbled_evaluator_inputs.insert(i, message);
            println!("3 0");
        } else {
            return None;
        }
    }

    println!("x4");

    let comm = input.m3_recv_p1.p2_commitments;
    let decom = input.m4_recv_p1.x34_decom;
    let x4 = input.x4struct.x;
    for i in 0..p2_ip_nos / 2 {
        let aval = bvals[i + p2_ip_nos / 2] ^ x4[i];
        let (message, witness) = decom[i];
        let mut comt = *comm.get(&(p2_ip_nos / 2 + i, 0)).unwrap();
        if aval {
            comt = *comm.get(&(p2_ip_nos / 2 + i, 1)).unwrap();
        }
        if input.commitment.verify(message, witness, comt) {
            garbled_evaluator_inputs_2.insert(i, message);
            println!("4 0");
        } else {
            return None;
        }
    }

    let hash = AesHash::new(input.prf_seed);
    let mut eval = BinaryEvaluator::new(
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        input.m3_recv_p0.delta,
        hash,
        input.m3_recv_p0.gc,
    );

    println!(
        "garb: {:?}\ngarb2: {:?}",
        garbled_evaluator_inputs, garbled_evaluator_inputs_2
    );
    let dec = eval
        .garbled_evaluate_threeparty(
            input.circuit.clone(),
            garbled_garbler_inputs,
            [garbled_evaluator_inputs, garbled_evaluator_inputs_2],
        )
        .unwrap();
    // let op = eval.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), dec.clone());

    // println!("op: {:?} ", op);

    Some(ThreePGM5 { garbled_op: dec })
}

pub fn threepg_process_m5_p0_p1(
    m5_recv: ThreePGM5,
    m3: ThreePGM3,
    circuit: BinaryCircuit,
    prf_seed: Block,
    m12_process: ThreepgProcessM12OP,
) {
    let hash = AesHash::new(prf_seed);
    let eval = BinaryEvaluator::new(
        m12_process.garbling_encoding,
        m12_process.evaluator_encoding,
        m12_process.decoding_info,
        m12_process.delta,
        hash,
        m3.gc,
    );
    let op = eval.get_plaintext_output(circuit.get_output_gate_ids().to_vec(), m5_recv.garbled_op);

    println!("output: {:?}", op);
}

#[cfg(test)]
mod tests {
    use crate::garbling3pc::threepartygarbling::{
        threepg_process_m3_m4_create_m5_p2, threepg_process_m5_p0_p1,
    };
    use crate::garbling3pc::threepartytraits::ThreePartyBinaryCircuitBuilder;
    use crate::{
        circuitop::circuit::BinaryCircuit,
        circuitop::circuit_builder::CircuitBuilder,
        utilities::{commitments::HashCommitment, hash_function::AesHash, utils::xor_blocks},
    };

    use super::ThreepgProcessM3M4CreateM5P2;
    use super::{
        threepg_create_m1_p2, threepg_create_m2_p0, threepg_create_m4_p0, threepg_create_m4_p1,
        threepg_process_m1_m2_create_m3_p0_p1,
    };
    // use super::{threepg_create_m4_p0, threepg_create_m4_p1, threepg_process_m1_m2_create_m3_p0, threepg_process_m1_m2_create_m3_p1};

    #[test]
    fn test1() {
        let mut rng_comm = rand::thread_rng();
        let input_p0 = vec![false];
        let input_p1 = vec![false];
        let input_p2 = vec![false, false];

        let m1 = threepg_create_m1_p2(input_p2, &mut rng_comm);
        let prf_seed = threepg_create_m2_p0(&mut rng_comm);
        let circuit = build_comparison_circuit_threeparty();

        let (m3_p0, m3_o_p0) = threepg_process_m1_m2_create_m3_p0_p1(
            circuit.num_garbler_inputs() / 2,
            circuit.num_garbler_inputs() / 2,
            circuit.num_evaluator_inputs() / 2,
            m1.p0_data.clone(),
            prf_seed,
            circuit.clone(),
        )
        .unwrap();
        println!("x3: {:?} x4: {:?}", m1.p0_data.x, m1.p1_data.x);
        let (m3_p1, m3_o_p1) = threepg_process_m1_m2_create_m3_p0_p1(
            circuit.num_garbler_inputs() / 2,
            circuit.num_garbler_inputs() / 2,
            circuit.num_evaluator_inputs() / 2,
            m1.p1_data.clone(),
            prf_seed,
            circuit.clone(),
        )
        .unwrap();
        println!("x3enc: {:?}", m3_o_p0.evaluator_encoding);
        for x in m3_o_p0.evaluator_encoding.clone().keys() {
            let zerval = *m3_o_p0.evaluator_encoding.get(x).unwrap();
            let oneval = xor_blocks(m3_o_p0.delta, zerval);
            println!("{} zero: {:?}", x, zerval);
            println!("{} one: {:?}", x, oneval);
        }
        let m4_p0 = threepg_create_m4_p0(m1.p0_data.clone(), input_p0.clone(), m3_o_p0.clone());
        let m4_p1 = threepg_create_m4_p1(m1.p1_data.clone(), input_p1.clone(), m3_o_p1.clone());

        let x = threepg_process_m3_m4_create_m5_p2(ThreepgProcessM3M4CreateM5P2 {
            x3struct: m1.p0_data.clone(),
            x4struct: m1.p1_data.clone(),
            commitment: HashCommitment::new(AesHash::new(m1.p0_data.comm_crs)),
            prf_seed,
            m3_recv_p0: m3_p0.clone(),
            m3_recv_p1: m3_p1.clone(),
            m4_recv_p0: m4_p0.clone(),
            m4_recv_p1: m4_p1.clone(),
            circuit: circuit.clone(),
        })
        .unwrap();

        threepg_process_m5_p0_p1(
            x.clone(),
            m3_p0.clone(),
            circuit.clone(),
            prf_seed,
            m3_o_p0.clone(),
        );
    }

    pub fn build_comparison_circuit_threeparty() -> BinaryCircuit {
        let mut builder = CircuitBuilder::new();

        let eval_input_1 = builder.evaluator_input_threeparty();
        let garb_input_1 = builder.garbler_input();
        let eval_input_2 = builder.evaluator_input_threeparty();
        let garb_input_2 = builder.garbler_input();

        // Compare the bits
        let eq0 = builder.xor(eval_input_1, garb_input_1);
        let eq1 = builder.xor(eval_input_2, garb_input_2);

        let onewire = builder.constant(1);
        let temp1 = builder.and(eq0, eq1);
        let temp2 = builder.xor(eq0, eq1);
        let before_not = builder.xor(temp1, temp2);
        let result = builder.xor(before_not, onewire);
        builder.output(result);

        builder.finish()
    }
}
