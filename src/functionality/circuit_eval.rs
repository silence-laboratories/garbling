use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use sl_compute::transport::{
    proto::{FilteredMsgRelay, MessageTag, Relay},
    setup::{common::MPCEncryption, CommonSetupMessage},
    types::ProtocolError,
    utils::{receive_from_parties, send_to_party, TagOffsetCounter},
};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::constants::{YAO_CIRC_EVAL_FUNC_MSG1, YAO_CIRC_EVAL_FUNC_MSG2},
    functionality::evaluate::evaluate_functionality,
    utilities::{
        hash_function::HashFunction,
        types::{
            block_vec2tblock_vec, tblock_vec2block_vec, Block, MapArg, TBlock, YaoEvaluatorShare,
            YaoGarblerShare, YaoSetup, YaoShare, BLOCK_SIZE,
        },
    },
};

use super::garble::garble_functionality;

pub fn yao_circuit_eval_process_msg1_p2<H>(
    g_input: &HashMap<usize, YaoShare>,
    e_input: &HashMap<usize, YaoShare>,
    fs: &[Block],
    circuit: &BinaryCircuit,
    hash: &H,
) -> HashMap<usize, YaoShare>
where
    H: HashFunction,
{
    let g_shares: HashMap<usize, YaoEvaluatorShare> = g_input
        .iter()
        .map(|(&ind, share)| {
            assert!(share.e_share.is_some());
            (ind, share.e_share.clone().unwrap())
        })
        .collect();

    let e_shares: HashMap<usize, YaoEvaluatorShare> = e_input
        .iter()
        .map(|(&ind, share)| {
            assert!(share.e_share.is_some());
            (ind, share.e_share.clone().unwrap())
        })
        .collect();

    let out = evaluate_functionality(circuit, &g_shares, &e_shares, fs, hash);

    out.iter()
        .map(|(&id, val)| {
            (
                id,
                YaoShare {
                    g_share: None,
                    e_share: Some(val.clone()),
                },
            )
        })
        .collect()
}

pub fn yao_circuit_eval_create_msg1_p01<G, H>(
    g_input: &HashMap<usize, YaoShare>,
    e_input: &HashMap<usize, YaoShare>,
    yao_setup: &YaoSetup,
    circuit: &BinaryCircuit,
    rng: &mut Option<G>,
    hash: &H,
) -> (Vec<Block>, HashMap<usize, YaoShare>)
where
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    assert!(yao_setup.g_setup.is_some());

    let g_shares: HashMap<usize, YaoGarblerShare> = g_input
        .iter()
        .map(|(&ind, share)| {
            assert!(share.g_share.is_some());
            (ind, share.g_share.clone().unwrap())
        })
        .collect();

    let e_shares: HashMap<usize, YaoGarblerShare> = e_input
        .iter()
        .map(|(&ind, share)| {
            assert!(share.g_share.is_some());
            (ind, share.g_share.clone().unwrap())
        })
        .collect();

    let r = rng.as_mut().unwrap();

    let (f, out_shares) = garble_functionality(
        circuit,
        &g_shares,
        &e_shares,
        &yao_setup.g_setup.clone().unwrap(),
        r,
        hash,
    );
    let out: HashMap<usize, YaoShare> = out_shares
        .iter()
        .map(|(&id, element)| {
            (
                id,
                YaoShare {
                    g_share: Some(element.clone()),
                    e_share: None,
                },
            )
        })
        .collect();

    (f, out)
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_circuit_eval_functionality<T, R, G, H>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    g_input: &HashMap<usize, YaoShare>,
    e_input: &HashMap<usize, YaoShare>,
    circuit: &BinaryCircuit,
    rng: &mut Option<G>,
    hash: &H,
    yao_setup: &YaoSetup,
) -> Result<HashMap<usize, YaoShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let output;
    let party_id = setup.participant_index();

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG1.try_into().unwrap(), tag_offset);

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG2.try_into().unwrap(), tag_offset);

    if party_id == 2 {
        relay.ask_messages(setup, tag1, true).await?;
        relay.ask_messages(setup, tag2, true).await?;

        let len = (2 * circuit.num_nonfree_gates + circuit.constant_map.len()) * BLOCK_SIZE;

        let hashes: Vec<[u8; 32]> =
            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay).await?;

        let hashes = hashes[0];

        let tfs: Vec<Vec<TBlock>> =
            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay).await?;

        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

        let hashout: [u8; 32] = fs
            .iter()
            .fold(Sha256::new(), Digest::chain_update)
            .finalize()
            .into();

        if hashout != hashes {
            return Err(ProtocolError::VerificationError);
        }

        output = yao_circuit_eval_process_msg1_p2(g_input, e_input, &fs, circuit, hash);
    } else {
        let (f, out) =
            yao_circuit_eval_create_msg1_p01(g_input, e_input, yao_setup, circuit, rng, hash);

        if party_id == 0 {
            let hashval: [u8; 32] = f
                .iter()
                .fold(Sha256::new(), Digest::chain_update)
                .finalize()
                .into();
            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
        } else {
            let tf = block_vec2tblock_vec(&f);
            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
        }
        output = out;
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_map_circuit_eval_functionality<T, R, G, H>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    g_inputs: &MapArg<HashMap<usize, YaoShare>>,
    e_inputs: &MapArg<HashMap<usize, YaoShare>>,
    circuits: &MapArg<BinaryCircuit>,
    rng: &mut Option<G>,
    hash: &H,
    yao_setup: &YaoSetup,
) -> Result<Vec<HashMap<usize, YaoShare>>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let party_id = setup.participant_index();

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG1.try_into().unwrap(), tag_offset);

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG2.try_into().unwrap(), tag_offset);

    let mut output = Vec::new();

    if party_id == 2 {
        relay.ask_messages(setup, tag1, true).await?;
        relay.ask_messages(setup, tag2, true).await?;
        match circuits {
            MapArg::Scalar(circuit) => match g_inputs {
                MapArg::Scalar(g_input) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        let len = (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                            * BLOCK_SIZE;

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        let temp =
                            yao_circuit_eval_process_msg1_p2(g_input, e_input, &fs, circuit, hash);

                        output.push(temp);
                    }
                    MapArg::Vector(e_inputs) => {
                        let len = (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                            * BLOCK_SIZE
                            * e_inputs.len();

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        let complen = 2 * circuit.num_nonfree_gates + circuit.constant_map.len();

                        output = e_inputs
                            .iter()
                            .zip(fs.chunks_exact(complen))
                            .map(|(e, f)| {
                                yao_circuit_eval_process_msg1_p2(g_input, e, f, circuit, hash)
                            })
                            .collect();
                    }
                },
                MapArg::Vector(g_inputs) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        let len = (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                            * BLOCK_SIZE
                            * g_inputs.len();

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        let complen = 2 * circuit.num_nonfree_gates + circuit.constant_map.len();

                        output = g_inputs
                            .iter()
                            .zip(fs.chunks_exact(complen))
                            .map(|(g, f)| {
                                yao_circuit_eval_process_msg1_p2(g, e_input, f, circuit, hash)
                            })
                            .collect();
                    }
                    MapArg::Vector(e_inputs) => {
                        assert_eq!(e_inputs.len(), g_inputs.len());
                        let len = (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                            * BLOCK_SIZE
                            * g_inputs.len();

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        let complen = 2 * circuit.num_nonfree_gates + circuit.constant_map.len();

                        output = g_inputs
                            .iter()
                            .zip(e_inputs.iter())
                            .zip(fs.chunks_exact(complen))
                            .map(|((g, e), f)| {
                                yao_circuit_eval_process_msg1_p2(g, e, f, circuit, hash)
                            })
                            .collect();
                    }
                },
            },
            MapArg::Vector(circuits) => match g_inputs {
                MapArg::Scalar(g_input) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        let mut len = 0;
                        for circuit in circuits {
                            len += (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                                * BLOCK_SIZE;
                        }

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        let mut len = 0;
                        output = circuits
                            .iter()
                            .map(|circuit| {
                                let complen =
                                    2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                                let f = fs[len..len + complen].to_vec();
                                let out = yao_circuit_eval_process_msg1_p2(
                                    g_input, e_input, &f, circuit, hash,
                                );
                                len += complen;
                                out
                            })
                            .collect();
                    }
                    MapArg::Vector(e_inputs) => {
                        assert_eq!(e_inputs.len(), circuits.len());

                        let mut len = 0;
                        for circuit in circuits {
                            len += (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                                * BLOCK_SIZE;
                        }

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        len = 0;
                        output = circuits
                            .iter()
                            .zip(e_inputs)
                            .map(|(circuit, e)| {
                                let complen =
                                    2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                                let f = fs[len..len + complen].to_vec();
                                let out =
                                    yao_circuit_eval_process_msg1_p2(g_input, e, &f, circuit, hash);
                                len += complen;
                                out
                            })
                            .collect();
                    }
                },
                MapArg::Vector(g_inputs) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        assert_eq!(g_inputs.len(), circuits.len());

                        let mut len = 0;
                        for circuit in circuits {
                            len += (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                                * BLOCK_SIZE;
                        }

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        len = 0;
                        output = circuits
                            .iter()
                            .zip(g_inputs)
                            .map(|(circuit, g)| {
                                let complen =
                                    2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                                let f = fs[len..len + complen].to_vec();
                                let out =
                                    yao_circuit_eval_process_msg1_p2(g, e_input, &f, circuit, hash);
                                len += complen;
                                out
                            })
                            .collect();
                    }
                    MapArg::Vector(e_inputs) => {
                        assert_eq!(g_inputs.len(), circuits.len());
                        assert_eq!(e_inputs.len(), circuits.len());

                        let mut len = 0;
                        for circuit in circuits {
                            len += (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                                * BLOCK_SIZE;
                        }

                        let hashes: Vec<[u8; 32]> =
                            receive_from_parties(setup, mpc_encryption, tag2, 32, vec![0], relay)
                                .await?;

                        let hashes = hashes[0];

                        let tfs: Vec<Vec<TBlock>> =
                            receive_from_parties(setup, mpc_encryption, tag1, len, vec![1], relay)
                                .await?;

                        let fs: Vec<Block> = tblock_vec2block_vec(&tfs[0]);

                        let hashout: [u8; 32] = fs
                            .iter()
                            .fold(Sha256::new(), Digest::chain_update)
                            .finalize()
                            .into();

                        if hashout != hashes {
                            return Err(ProtocolError::VerificationError);
                        }

                        len = 0;
                        output = circuits
                            .iter()
                            .zip(g_inputs)
                            .zip(e_inputs)
                            .map(|((circuit, g), e)| {
                                let complen =
                                    2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                                let f = fs[len..len + complen].to_vec();
                                let out = yao_circuit_eval_process_msg1_p2(g, e, &f, circuit, hash);
                                len += complen;
                                out
                            })
                            .collect();
                    }
                },
            },
        }
    } else {
        match circuits {
            MapArg::Scalar(circuit) => match g_inputs {
                MapArg::Scalar(g_input) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        let (f, out) = yao_circuit_eval_create_msg1_p01(
                            g_input, e_input, yao_setup, circuit, rng, hash,
                        );

                        if party_id == 0 {
                            let hashval: [u8; 32] = f
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&f);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        let temp = out;
                        output.push(temp);
                    }
                    MapArg::Vector(e_inputs) => {
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = e_inputs
                            .iter()
                            .map(|e_input| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                },
                MapArg::Vector(g_inputs) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = g_inputs
                            .iter()
                            .map(|g_input| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                    MapArg::Vector(e_inputs) => {
                        assert_eq!(e_inputs.len(), g_inputs.len());
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = g_inputs
                            .iter()
                            .zip(e_inputs)
                            .map(|(g_input, e_input)| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                },
            },
            MapArg::Vector(circuits) => match g_inputs {
                MapArg::Scalar(g_input) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = circuits
                            .iter()
                            .map(|circuit| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                    MapArg::Vector(e_inputs) => {
                        assert_eq!(e_inputs.len(), circuits.len());
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = circuits
                            .iter()
                            .zip(e_inputs)
                            .map(|(circuit, e_input)| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                },
                MapArg::Vector(g_inputs) => match e_inputs {
                    MapArg::Scalar(e_input) => {
                        assert_eq!(g_inputs.len(), circuits.len());
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = circuits
                            .iter()
                            .zip(g_inputs)
                            .map(|(circuit, g_input)| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                    MapArg::Vector(e_inputs) => {
                        assert_eq!(e_inputs.len(), circuits.len());
                        assert_eq!(g_inputs.len(), circuits.len());
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<usize, YaoShare>>) = circuits
                            .iter()
                            .zip(g_inputs)
                            .zip(e_inputs)
                            .map(|((circuit, g_input), e_input)| {
                                yao_circuit_eval_create_msg1_p01(
                                    g_input, e_input, yao_setup, circuit, rng, hash,
                                )
                            })
                            .collect();

                        let fvec = f.iter().flatten().cloned().collect::<Vec<_>>();

                        if party_id == 0 {
                            let hashval: [u8; 32] = fvec
                                .iter()
                                .fold(Sha256::new(), Digest::chain_update)
                                .finalize()
                                .into();
                            send_to_party(setup, mpc_encryption, tag2, hashval, 2, relay).await?;
                        } else {
                            let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;
                        }

                        output = out;
                    }
                },
            },
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use merlin::Transcript;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sl_compute::{
        mpc::preprocess::Seed,
        transport::{
            init::run_init,
            proto::FilteredMsgRelay,
            setup::{common::SetupMessage, CommonSetupMessage},
            types::ProtocolError,
            utils::TagOffsetCounter,
        },
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    use crate::{
        circuitop::circuit::BinaryCircuit,
        customcircuits::comparison::build_comparison_circuit,
        functionality::{
            circuit_eval::yao_map_circuit_eval_functionality,
            input::{
                batch_input_yao_from_functionality, batch_input_yao_functionality,
                input_yao_from_functionality, input_yao_functionality,
            },
            output::{
                batch_output_yao_functionality, batch_output_yao_to_functionality,
                output_yao_functionality, output_yao_to_functionality, validate_yao_share,
            },
            setup::setup_yao_functionality,
        },
        utilities::{
            commitments::HashCommitment, garble_hash::AesGarbleHash, shahash::Sha512Hash,
            types::MapArg, utils::bool_vec_to_hex,
        },
    };

    use super::yao_circuit_eval_functionality;

    async fn test_run_entire_flow<T, R>(
        setup: T,
        seed: Seed,
        circuit: BinaryCircuit,
        garb_input: Vec<bool>,
        eval_input: Vec<bool>,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: CommonSetupMessage,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);

        let mut init_seed = [0u8; 32];
        let mut common_randomness_seed = [0u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"seed", &seed);
        transcript.challenge_bytes(b"init-seed", &mut init_seed);
        transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

        let (_sid, mut mpc_encryption) = run_init(&setup, init_seed, &mut relay).await?;
        let mut tag_offset_counter = TagOffsetCounter::new();
        let yao_setup = setup_yao_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
        )
        .await?;

        let mut gin = HashMap::new();
        let mut ein = HashMap::new();
        let mut notgin = HashMap::new();
        let mut notein = HashMap::new();

        let (mut rng, hash, comm) = if setup.participant_index() == 2 {
            let hash = AesGarbleHash::new(yao_setup.e_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(Sha512Hash::new());
            (None, hash, comm)
        } else {
            let hash = AesGarbleHash::new(yao_setup.g_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(Sha512Hash::new());
            let r = ChaCha8Rng::from_seed(yao_setup.g_setup.clone().unwrap().prf_key);
            (Some(r), hash, comm)
        };

        let mut count = 0;

        while count < 32 && count < circuit.garbler_input_ids.len() {
            let id = circuit.garbler_input_ids[count];
            let inp = garb_input[count];
            count += 1;
            let out = input_yao_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &inp,
                &mut rng,
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            gin.insert(id, out);
        }

        while count < 2 * 32 && count < circuit.garbler_input_ids.len() {
            let id = circuit.garbler_input_ids[count];
            let inp = garb_input[count];
            count += 1;
            let out = if setup.participant_index() == 0 {
                input_yao_from_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    &Some(inp),
                    0,
                    &mut rng,
                    &hash,
                    &comm,
                    &yao_setup,
                )
                .await?
            } else {
                input_yao_from_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    &None,
                    0,
                    &mut rng,
                    &hash,
                    &comm,
                    &yao_setup,
                )
                .await?
            };
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            gin.insert(id, out);
        }

        while count < 3 * 32 && count < circuit.garbler_input_ids.len() {
            let id = circuit.garbler_input_ids[count];
            let inp = garb_input[count];
            count += 1;
            let out = if setup.participant_index() == 1 {
                input_yao_from_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    &Some(inp),
                    1,
                    &mut rng,
                    &hash,
                    &comm,
                    &yao_setup,
                )
                .await?
            } else {
                input_yao_from_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    &None,
                    1,
                    &mut rng,
                    &hash,
                    &comm,
                    &yao_setup,
                )
                .await?
            };
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            gin.insert(id, out);
        }

        while count < 4 * 32 && count < circuit.garbler_input_ids.len() {
            let id = circuit.garbler_input_ids[count];
            let inp = garb_input[count];
            count += 1;
            let out = if setup.participant_index() == 2 {
                input_yao_from_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    &Some(inp),
                    2,
                    &mut rng,
                    &hash,
                    &comm,
                    &yao_setup,
                )
                .await?
            } else {
                input_yao_from_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    &None,
                    2,
                    &mut rng,
                    &hash,
                    &comm,
                    &yao_setup,
                )
                .await?
            };
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            gin.insert(id, out);
        }

        for (id, inp) in circuit.evaluator_input_ids.iter().zip(&eval_input) {
            let out = input_yao_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                inp,
                &mut rng,
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            ein.insert(*id, out);
            let out = input_yao_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &!inp,
                &mut rng,
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            notein.insert(*id, out);
        }

        for (id, inp) in circuit.garbler_input_ids.iter().zip(&garb_input) {
            let out = input_yao_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &!inp,
                &mut rng,
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &out,
            )
            .await?;
            assert!(cor);
            notgin.insert(*id, out);
        }

        let out_sh = yao_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &gin,
            &ein,
            &circuit,
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case1_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Scalar(gin.clone()),
            &MapArg::Vector(vec![ein.clone(), notein.clone()]),
            &MapArg::Scalar(circuit.clone()),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case2_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Vector(vec![gin.clone(), notgin.clone()]),
            &MapArg::Scalar(ein.clone()),
            &MapArg::Scalar(circuit.clone()),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case3_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Vector(vec![gin.clone(), notgin.clone()]),
            &MapArg::Vector(vec![ein.clone(), notein.clone()]),
            &MapArg::Scalar(circuit.clone()),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case4_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Scalar(gin.clone()),
            &MapArg::Scalar(ein.clone()),
            &MapArg::Vector(vec![circuit.clone(), circuit.clone()]),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case5_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Scalar(gin.clone()),
            &MapArg::Vector(vec![ein.clone(), notein.clone()]),
            &MapArg::Vector(vec![circuit.clone(), circuit.clone()]),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case6_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Vector(vec![gin.clone(), notgin.clone()]),
            &MapArg::Scalar(ein.clone()),
            &MapArg::Vector(vec![circuit.clone(), circuit.clone()]),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case7_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Vector(vec![gin.clone(), notgin.clone()]),
            &MapArg::Vector(vec![ein.clone(), notein.clone()]),
            &MapArg::Vector(vec![circuit.clone(), circuit.clone()]),
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let mut op = vec![];

        for i in &circuit.output_gate_ids {
            let cor: bool = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(i).unwrap(),
            )
            .await?;
            assert!(cor);
            let output = output_yao_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(i).unwrap(),
            )
            .await?;
            op.push(output);

            let op1 = output_yao_to_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                0,
                out_sh.get(i).unwrap(),
            )
            .await?;
            if setup.participant_index() == 0 {
                assert_eq!(output, op1.unwrap())
            }

            let op2 = output_yao_to_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                1,
                out_sh.get(i).unwrap(),
            )
            .await?;
            if setup.participant_index() == 1 {
                assert_eq!(output, op2.unwrap())
            }

            let op3 = output_yao_to_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                2,
                out_sh.get(i).unwrap(),
            )
            .await?;
            if setup.participant_index() == 2 {
                assert_eq!(output, op3.unwrap())
            }
        }

        println!("\nCase 1 outputs: ");

        for out_sh in outs_case1_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        println!("\nCase 2 outputs: ");

        for out_sh in outs_case2_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        println!("\nCase 3 outputs: ");

        for out_sh in outs_case3_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        println!("\nCase 4 outputs: ");

        for out_sh in outs_case4_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        println!("\nCase 5 outputs: ");

        for out_sh in outs_case5_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        println!("\nCase 6 outputs: ");

        for out_sh in outs_case6_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        println!("\nCase 7 outputs: ");

        for out_sh in outs_case7_sh {
            let mut opt = vec![];
            for i in &circuit.output_gate_ids {
                let cor: bool = validate_yao_share(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
                    &mut mpc_encryption,
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                opt.push(output);
            }
            let hexout = bool_vec_to_hex(opt);
            if setup.participant_index() == 0 {
                println!("{}", hexout);
            }
        }

        Ok((setup.participant_index(), op))
    }

    async fn batched_test_run_entire_flow<T, R>(
        setup: T,
        seed: Seed,
        circuit: BinaryCircuit,
        garb_input: Vec<bool>,
        eval_input: Vec<bool>,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: CommonSetupMessage,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);

        let mut init_seed = [0u8; 32];
        let mut common_randomness_seed = [0u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"seed", &seed);
        transcript.challenge_bytes(b"init-seed", &mut init_seed);
        transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

        let (_sid, mut mpc_encryption) = run_init(&setup, init_seed, &mut relay).await?;
        let mut tag_offset_counter = TagOffsetCounter::new();
        let yao_setup = setup_yao_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
        )
        .await?;

        let mut gin = HashMap::new();
        let mut ein = HashMap::new();

        let (mut rng, hash, comm) = if setup.participant_index() == 2 {
            let hash = AesGarbleHash::new(yao_setup.e_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(Sha512Hash::new());
            (None, hash, comm)
        } else {
            let hash = AesGarbleHash::new(yao_setup.g_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(Sha512Hash::new());
            let r = ChaCha8Rng::from_seed(yao_setup.g_setup.clone().unwrap().prf_key);
            (Some(r), hash, comm)
        };

        let mut count = 0;

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 32 && count < circuit.garbler_input_ids.len() {
            ids.push(circuit.garbler_input_ids[count]);
            inps.push(garb_input[count]);
            count += 1;
        }
        let outs = batch_input_yao_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &inps,
            &mut rng,
            &yao_setup,
        )
        .await?;
        for (out, id) in outs.iter().zip(ids) {
            gin.insert(id, out.clone());
        }

        println!("{} finished input g 0", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 2 * 32 && count < circuit.garbler_input_ids.len() {
            ids.push(circuit.garbler_input_ids[count]);
            inps.push(Some(garb_input[count]));
            count += 1;
        }
        let outs = if setup.participant_index() == 0 {
            batch_input_yao_from_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &inps,
                0,
                &mut rng,
                &hash,
                &comm,
                &yao_setup,
            )
            .await?
        } else {
            batch_input_yao_from_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &vec![None; inps.len()],
                0,
                &mut rng,
                &hash,
                &comm,
                &yao_setup,
            )
            .await?
        };
        for (out, id) in outs.iter().zip(ids) {
            gin.insert(id, out.clone());
        }

        println!("{} finished input g 1", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 3 * 32 && count < circuit.garbler_input_ids.len() {
            ids.push(circuit.garbler_input_ids[count]);
            inps.push(Some(garb_input[count]));
            count += 1;
        }
        let outs = if setup.participant_index() == 1 {
            batch_input_yao_from_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &inps,
                1,
                &mut rng,
                &hash,
                &comm,
                &yao_setup,
            )
            .await?
        } else {
            batch_input_yao_from_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &vec![None; inps.len()],
                1,
                &mut rng,
                &hash,
                &comm,
                &yao_setup,
            )
            .await?
        };
        for (out, id) in outs.iter().zip(ids) {
            gin.insert(id, out.clone());
        }

        println!("{} finished input g 2", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 4 * 32 && count < circuit.garbler_input_ids.len() {
            ids.push(circuit.garbler_input_ids[count]);
            inps.push(Some(garb_input[count]));
            count += 1;
        }
        let outs = if setup.participant_index() == 2 {
            batch_input_yao_from_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &inps,
                2,
                &mut rng,
                &hash,
                &comm,
                &yao_setup,
            )
            .await?
        } else {
            batch_input_yao_from_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                &vec![None; inps.len()],
                2,
                &mut rng,
                &hash,
                &comm,
                &yao_setup,
            )
            .await?
        };
        for (out, id) in outs.iter().zip(ids) {
            gin.insert(id, out.clone());
        }

        println!("{} finished input g 3", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        for (id, inp) in circuit.evaluator_input_ids.iter().zip(eval_input) {
            ids.push(*id);
            inps.push(inp);
        }
        let outs = batch_input_yao_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &inps,
            &mut rng,
            &yao_setup,
        )
        .await?;
        for (out, id) in outs.iter().zip(ids) {
            ein.insert(id, out.clone());
        }

        println!("{} finished input e", setup.participant_index());

        let out_sh = yao_circuit_eval_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &gin,
            &ein,
            &circuit,
            &mut rng,
            &hash,
            &yao_setup,
        )
        .await?;

        let mut shares = vec![];

        for i in circuit.output_gate_ids {
            let cor: bool = validate_yao_share(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(&i).unwrap(),
            )
            .await?;
            assert!(cor);
            shares.push(out_sh.get(&i).unwrap().clone());
        }

        let op = batch_output_yao_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &shares,
        )
        .await?;

        let op1 = batch_output_yao_to_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            0,
            &shares,
        )
        .await?;

        let op2 = batch_output_yao_to_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            1,
            &shares,
        )
        .await?;

        let op3 = batch_output_yao_to_functionality(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            2,
            &shares,
        )
        .await?;

        for i in 0..op.len() {
            if setup.participant_index() == 0 {
                assert_eq!(op[i], op1[i].unwrap())
            }
            if setup.participant_index() == 1 {
                assert_eq!(op[i], op2[i].unwrap())
            }
            if setup.participant_index() == 2 {
                assert_eq!(op[i], op3[i].unwrap())
            }
        }
        Ok((setup.participant_index(), op))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn setup_entire_flow(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
        use sha2::{Digest, Sha256};
        use sl_compute::transport::setup::{NoSigningKey, NoVerifyingKey, ProtocolParticipant};
        use sl_mpc_mate::message::InstanceId;
        use std::time::Duration;

        let instance = instance.unwrap_or_else(rand::random);

        // a signing key for each party.
        let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
            .take(3usize)
            .collect();

        let party_vk: Vec<NoVerifyingKey> = party_sk
            .iter()
            .enumerate()
            .map(|(party_id, _)| NoVerifyingKey::new(party_id))
            .collect();

        party_sk
            .into_iter()
            .enumerate()
            .map(|(party_id, sk)| {
                SetupMessage::new(InstanceId::new(instance), sk, party_id, party_vk.clone())
                    .with_ttl(Duration::from_secs(1000))
            })
            .map(|setup| {
                let mixin = [setup.participant_index() as u8 + 1];

                (
                    setup,
                    Sha256::new()
                        .chain_update(instance)
                        .chain_update(b"party-seed")
                        .chain_update(mixin)
                        .finalize()
                        .into(),
                )
            })
            .collect::<Vec<_>>()
    }

    async fn sim_entire_flow<S, R>(
        coord: S,
        circuit: BinaryCircuit,
        gin: Vec<bool>,
        ein: Vec<bool>,
        batched: bool,
    ) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_entire_flow(None);
        sim_parties_entire_flow(parties, coord, circuit, gin, ein, batched).await
    }

    async fn sim_parties_entire_flow<S, R>(
        parties: Vec<(SetupMessage, [u8; 32])>,
        coord: S,
        circuit: BinaryCircuit,
        gin: Vec<bool>,
        ein: Vec<bool>,
        batched: bool,
    ) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, seed) in parties {
            let relay = coord.connect().await.unwrap();

            if batched {
                jset.spawn(batched_test_run_entire_flow(
                    setup,
                    seed,
                    circuit.clone(),
                    gin.clone(),
                    ein.clone(),
                    relay,
                ));
            } else {
                jset.spawn(test_run_entire_flow(
                    setup,
                    seed,
                    circuit.clone(),
                    gin.clone(),
                    ein.clone(),
                    relay,
                ));
            }
        }

        let mut results = vec![];

        while let Some(fini) = jset.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            let res = fini.unwrap();
            results.push(res);
        }

        results.sort_by_key(|r| r.0);
        results.into_iter().map(|r| r.1).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_entire_flow() {
        let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();
        let batched = false;
        for i in 0..2 {
            for j in 0..2 {
                let gin = vec![i != 0; 128];
                let ein = vec![j != 0; 128];
                let output = sim_entire_flow(
                    SimpleMessageRelay::new(),
                    circuit.clone(),
                    gin,
                    ein,
                    batched,
                )
                .await;
                assert_eq!(output[0], output[1]);
                assert_eq!(output[2], output[1]);
                let count = 2 * i + j;
                let hexout = bool_vec_to_hex(output[0].clone());
                if count == 0 {
                    assert_eq!(
                        hexout,
                        "74d42c539a5f3211dc3451f72bd29766".to_string(),
                        "outval: {} realval: 74d42c539a5f3211dc3451f72bd29766",
                        hexout
                    );
                } else if count == 2 {
                    assert_eq!(
                        hexout,
                        "3493fd1ca2122691b3fabee131a46f85".to_string(),
                        "outval: {} realval: 3493fd1ca2122691b3fabee131a46f85",
                        hexout
                    );
                } else if count == 1 {
                    assert_eq!(
                        hexout,
                        "7266b17c4be2ce5f505aa1579331dafc".to_string(),
                        "outval: {} realval: 7266b17c4be2ce5f505aa1579331dafc",
                        hexout
                    );
                } else if count == 3 {
                    assert_eq!(
                        hexout,
                        "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string(),
                        "outval: {} realval: 9e9d5c984a0e8a4d0cf3014d3e84fd3d",
                        hexout
                    );
                }
            }
        }

        let circuit = build_comparison_circuit();

        for i in 0..3 {
            for j in 0..3 {
                let ibit1 = i % 2 != 0;
                let jbit1 = j % 2 != 0;
                let ibit2 = (i / 2) % 2 != 0;
                let jbit2 = (j / 2) % 2 != 0;

                let gin = vec![ibit1, ibit2];
                let ein = vec![jbit1, jbit2];
                let output = sim_entire_flow(
                    SimpleMessageRelay::new(),
                    circuit.clone(),
                    gin,
                    ein,
                    batched,
                )
                .await;
                assert_eq!(output[0], output[1]);
                assert_eq!(output[2], output[1]);
                assert!(
                    (i == j) == output[0][0],
                    "i: {}, j: {} output: {:?}",
                    i,
                    j,
                    output[0]
                )
            }
        }
    }
}
