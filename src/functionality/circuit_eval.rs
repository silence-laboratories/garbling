use std::collections::HashMap;

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::constants::{YAO_CIRC_EVAL_FUNC_MSG1, YAO_CIRC_EVAL_FUNC_MSG2},
    functionality::{
        evaluate::evaluate_functionality,
        utils::{receive_from_parties, send_to_party, FilteredMsgRelay},
        utils_dep::{ProtocolError, ProtocolParticipant, TagOffsetCounter},
    },
    utilities::{
        hash_function::HashFunction,
        types::{Block, GarblerSetup, MapArg, YaoSetup, YaoShare, BLOCK_SIZE},
    },
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use sl_messages::{message::MessageTag, relay::Relay};

use super::garble::garble_functionality;

pub fn yao_circuit_eval_process_msg1_p2<H>(
    input: &[Vec<YaoShare>],
    fs: &[Block],
    circuit: &BinaryCircuit,
    hash: &H,
) -> HashMap<u32, YaoShare>
where
    H: HashFunction,
{
    evaluate_functionality(circuit, input, fs, hash)
}

fn yao_circuit_eval_create_msg1_p01<G, H>(
    input: &[Vec<YaoShare>],
    garble_setup: &GarblerSetup,
    circuit: &BinaryCircuit,
    rng: &mut G,
    hash: &H,
) -> (Vec<Block>, HashMap<u32, YaoShare>)
where
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    garble_functionality(circuit, input, garble_setup, rng, hash)
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_circuit_eval_functionality<T, R, G, H>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &[Vec<YaoShare>],
    circuit: &BinaryCircuit,
    rng: Option<&mut G>,
    hash: &H,
    yao_setup: &YaoSetup,
) -> Result<HashMap<u32, YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG1, tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG2, tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    let output = yao_circuit_eval_functionality_inner(
        setup, relay, input, circuit, rng, hash, yao_setup, tag1, tag2,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
async fn yao_circuit_eval_functionality_inner<T, R, G, H>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[Vec<YaoShare>],
    circuit: &BinaryCircuit,
    rng: Option<&mut G>,
    hash: &H,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<HashMap<u32, YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let party_id = setup.participant_index();

    assert_eq!(input.len(), circuit.num_inputs() as _);
    (0..input.len()).for_each(|i| assert_eq!(input[i].len(), circuit.input_gate_ids[i].len()));

    match yao_setup {
        YaoSetup::E(_) => {
            let hashes: Vec<[u8; 32]> = receive_from_parties(setup, tag2, &[0], relay).await?;

            let fs: Vec<Vec<Block>> = receive_from_parties(setup, tag1, &[1], relay).await?;

            let mut hasher = Sha256::new();
            for i in &fs[0] {
                hasher.update(i);
            }

            let hashout: [u8; 32] = hasher.finalize().into();

            assert_eq!(hashout, hashes[0]);

            Ok(yao_circuit_eval_process_msg1_p2(
                input, &fs[0], circuit, hash,
            ))
        }

        YaoSetup::G(g) => {
            let (f, out) = yao_circuit_eval_create_msg1_p01(input, g, circuit, rng.unwrap(), hash);
            // let tf = block_vec2tblock_vec(&f);

            if party_id == 0 {
                let mut hval = Vec::new();
                for i in f {
                    hval.extend_from_slice(&i);
                }
                let mut hasher = Sha256::new();
                hasher.update(hval);
                let hashval: [u8; 32] = hasher.finalize().into();
                send_to_party(setup, tag2, hashval, 2, relay).await?;
            } else {
                send_to_party(setup, tag1, f, 2, relay).await?;
            }

            Ok(out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_map_circuit_eval_functionality<'a, T, R, G, H>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    inputs: &MapArg<'a, &[Vec<YaoShare>]>,
    circuits: &MapArg<'a, &'a BinaryCircuit>,
    rng: Option<&mut G>,
    hash: &H,
    yao_setup: &YaoSetup,
) -> Result<Vec<HashMap<u32, YaoShare>>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG1, tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(YAO_CIRC_EVAL_FUNC_MSG2, tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    let output = yao_map_circuit_eval_functionality_inner(
        setup, relay, inputs, circuits, rng, hash, yao_setup, tag1, tag2,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
async fn yao_map_circuit_eval_functionality_inner<'a, T, R, G, H>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    inputs: &MapArg<'a, &[Vec<YaoShare>]>,
    circuits: &MapArg<'a, &'a BinaryCircuit>,
    rng: Option<&mut G>,
    hash: &H,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<Vec<HashMap<u32, YaoShare>>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let party_id = setup.participant_index();

    let mut output = Vec::new();

    match yao_setup {
        YaoSetup::E(_e) => match *circuits {
            MapArg::Scalar(circuit) => match *inputs {
                MapArg::Scalar(input) => {
                    let hashes: Vec<[u8; 32]> =
                        receive_from_parties(setup, tag2, &[0], relay).await?;

                    let fs: Vec<Vec<Block>> =
                        receive_from_parties(setup, tag1, &[1], relay).await?;

                    let mut hasher = Sha256::new();
                    for i in &fs[0] {
                        hasher.update(i);
                    }

                    let hashout: [u8; 32] = hasher.finalize().into();

                    assert_eq!(hashout, hashes[0]);

                    let temp = yao_circuit_eval_process_msg1_p2(input, &fs[0], circuit, hash);

                    output.push(temp);
                }

                MapArg::Vector(input) => {
                    let hashes: Vec<[u8; 32]> =
                        receive_from_parties(setup, tag2, &[0], relay).await?;

                    let fs: Vec<Vec<Block>> =
                        receive_from_parties(setup, tag1, &[1], relay).await?;

                    let mut hasher = Sha256::new();

                    for f in &fs {
                        for i in f {
                            hasher.update(i);
                        }
                    }

                    let hashout: [u8; 32] = hasher.finalize().into();

                    assert_eq!(hashout, hashes[0]);

                    let complen = 2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                    let mut temp = Vec::new();
                    (0..input.len()).for_each(|i| {
                        let f = fs[0][complen * i..complen * (i + 1)].to_vec();
                        let out = yao_circuit_eval_process_msg1_p2(input[i], &f, circuit, hash);
                        temp.push(out);
                    });
                    output = temp;
                }
            },

            MapArg::Vector(circuits) => match inputs {
                MapArg::Scalar(input) => {
                    let hashes: Vec<[u8; 32]> =
                        receive_from_parties(setup, tag2, &[0], relay).await?;

                    let fs: Vec<Vec<Block>> =
                        receive_from_parties(setup, tag1, &[1], relay).await?;

                    let mut hasher = Sha256::new();
                    for f in &fs {
                        for i in f {
                            hasher.update(i);
                        }
                    }

                    let hashout: [u8; 32] = hasher.finalize().into();

                    assert_eq!(hashout, hashes[0]);

                    let mut temp = Vec::new();
                    let mut len = 0;
                    circuits.iter().for_each(|circuit| {
                        let complen = 2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                        let f = fs[0][len..len + complen].to_vec();
                        let out = yao_circuit_eval_process_msg1_p2(input, &f, circuit, hash);
                        len += complen;
                        temp.push(out);
                    });

                    output = temp;
                }

                &MapArg::Vector(input) => {
                    assert_eq!(input.len(), circuits.len());

                    let hashes: Vec<[u8; 32]> =
                        receive_from_parties(setup, tag2, &[0], relay).await?;

                    let fs: Vec<Vec<Block>> =
                        receive_from_parties(setup, tag1, &[1], relay).await?;

                    let mut hasher = Sha256::new();
                    for f in &fs {
                        for i in f {
                            hasher.update(i);
                        }
                    }

                    let hashout: [u8; 32] = hasher.finalize().into();

                    assert_eq!(hashout, hashes[0]);

                    let mut temp = Vec::new();
                    let mut len = 0;
                    circuits.iter().zip(input).for_each(|(circuit, ip)| {
                        let complen = 2 * circuit.num_nonfree_gates + circuit.constant_map.len();
                        let f = fs[0][len..len + complen].to_vec();
                        let out = yao_circuit_eval_process_msg1_p2(ip, &f, circuit, hash);
                        len += complen;
                        temp.push(out);
                    });
                    output = temp;
                }
            },
        },

        YaoSetup::G(g) => {
            let rng = rng.unwrap();

            match circuits {
                MapArg::Scalar(circuit) => match inputs {
                    MapArg::Scalar(input) => {
                        let (f, out) =
                            yao_circuit_eval_create_msg1_p01(input, g, circuit, rng, hash);
                        // let tf = block_vec2tblock_vec(&f);

                        if party_id == 0 {
                            let mut hval = Vec::new();
                            for i in f {
                                hval.extend_from_slice(&i);
                            }

                            let mut hasher = Sha256::new();
                            hasher.update(hval);

                            let hashval: [u8; 32] = hasher.finalize().into();

                            send_to_party(setup, tag2, hashval, 2, relay).await?;
                        } else {
                            send_to_party(setup, tag1, f, 2, relay).await?;
                        }

                        let temp = out;
                        output.push(temp);
                    }

                    &MapArg::Vector(input) => {
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<u32, YaoShare>>) = input
                            .iter()
                            .map(|ip| yao_circuit_eval_create_msg1_p01(ip, g, circuit, rng, hash))
                            .collect();

                        let len = (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                            * BLOCK_SIZE
                            * input.len();

                        let mut fvec = Vec::with_capacity(len);
                        for vec in f {
                            for b in vec {
                                fvec.push(b);
                            }
                        }

                        if party_id == 0 {
                            let mut hval = Vec::new();
                            for i in fvec {
                                hval.extend_from_slice(&i);
                            }
                            let mut hasher = Sha256::new();
                            hasher.update(hval);
                            let hashval: [u8; 32] = hasher.finalize().into();
                            send_to_party(setup, tag2, hashval, 2, relay).await?;
                        } else {
                            // let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, tag1, fvec, 2, relay).await?;
                        }

                        let temp = out;
                        output = temp;
                    }
                },

                &MapArg::Vector(circuits) => match inputs {
                    MapArg::Scalar(input) => {
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<u32, YaoShare>>) = circuits
                            .iter()
                            .map(|circuit| {
                                yao_circuit_eval_create_msg1_p01(input, g, circuit, rng, hash)
                            })
                            .collect();

                        let mut len = 0;
                        for circuit in circuits {
                            len += (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                                * BLOCK_SIZE;
                        }

                        let mut fvec = Vec::with_capacity(len);
                        for vec in f {
                            for b in vec {
                                fvec.push(b);
                            }
                        }

                        if party_id == 0 {
                            let mut hval = Vec::new();
                            for i in fvec {
                                hval.extend_from_slice(&i);
                            }
                            let mut hasher = Sha256::new();
                            hasher.update(hval);
                            let hashval: [u8; 32] = hasher.finalize().into();
                            send_to_party(setup, tag2, hashval, 2, relay).await?;
                        } else {
                            // let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, tag1, fvec, 2, relay).await?;
                        }

                        let temp = out;
                        output = temp;
                    }

                    &MapArg::Vector(input) => {
                        assert_eq!(input.len(), circuits.len());
                        let (f, out): (Vec<Vec<Block>>, Vec<HashMap<u32, YaoShare>>) = circuits
                            .iter()
                            .zip(input)
                            .map(|(circuit, ip)| {
                                yao_circuit_eval_create_msg1_p01(ip, g, circuit, rng, hash)
                            })
                            .collect();

                        let mut len = 0;
                        for circuit in circuits {
                            len += (2 * circuit.num_nonfree_gates + circuit.constant_map.len())
                                * BLOCK_SIZE;
                        }

                        let mut fvec = Vec::with_capacity(len);
                        for vec in f {
                            for b in vec {
                                fvec.push(b);
                            }
                        }

                        if party_id == 0 {
                            let mut hval = Vec::new();
                            for i in fvec {
                                hval.extend_from_slice(&i);
                            }
                            let mut hasher = Sha256::new();
                            hasher.update(hval);
                            let hashval: [u8; 32] = hasher.finalize().into();
                            send_to_party(setup, tag2, hashval, 2, relay).await?;
                        } else {
                            // let tf = block_vec2tblock_vec(&fvec);
                            send_to_party(setup, tag1, fvec, 2, relay).await?;
                        }

                        let temp = out;
                        output = temp;
                    }
                },
            }
        }
    };

    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use merlin::Transcript;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sl_messages::relay::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    use crate::{
        circuitop::circuit::BinaryCircuit,
        config::constants::AES128_CIRCUIT,
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
            utils::{FilteredMsgRelay, SetupMessage},
            utils_dep::{ProtocolError, ProtocolParticipant, TagOffsetCounter},
        },
        utilities::{
            commitments::HashCommitment,
            garble_hash::AesGarbleHash,
            shahash::Sha512Hash,
            types::{MapArg, YaoSetup},
            utils::bool_vec_to_hex,
        },
    };

    use super::yao_circuit_eval_functionality;

    async fn test_run_entire_flow<T, R>(
        setup: T,
        circuit: Arc<BinaryCircuit>,
        garb_input: Vec<bool>,
        eval_input: Vec<bool>,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);
        let mut init_seed = [0u8; 32];
        let mut common_randomness_seed = [0u8; 32];
        let mut transcript = Transcript::new(b"test");

        transcript.challenge_bytes(b"init-seed", &mut init_seed);
        transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

        let mut tag_offset_counter = TagOffsetCounter::new();
        let yao_setup =
            setup_yao_functionality(&setup, &mut tag_offset_counter, &mut relay).await?;

        let (mut rng, hash, comm) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesGarbleHash::new(e.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                (None, hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesGarbleHash::new(g.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                let r = ChaCha8Rng::from_seed(g.prf_key);
                (Some(r), hash, comm)
            }
        };

        let mut count = 0;

        let mut inputs = [vec![], vec![]];
        let mut notinputs = [vec![], vec![]];

        while count < 32 && count < circuit.input_gate_ids[0].len() {
            let inp = garb_input[count];
            count += 1;
            let out = input_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                inp,
                rng.as_mut(),
                &yao_setup,
            )
            .await?;

            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);

            inputs[0].push(out);
        }

        while count < 2 * 32 && count < circuit.input_gate_ids[0].len() {
            let inp = garb_input[count];
            count += 1;
            let out = if setup.participant_index() == 0 {
                input_yao_from_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    inp,
                    0,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?
            } else {
                input_yao_from_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    false,
                    0,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?
            };

            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);

            inputs[0].push(out);
        }

        while count < 3 * 32 && count < circuit.input_gate_ids[0].len() {
            let inp = garb_input[count];
            count += 1;
            let out = if setup.participant_index() == 1 {
                input_yao_from_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    inp,
                    1,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?
            } else {
                input_yao_from_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    false,
                    1,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?
            };

            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);

            inputs[0].push(out);
        }

        while count < 4 * 32 && count < circuit.input_gate_ids[0].len() {
            let inp = garb_input[count];
            count += 1;
            let out = if setup.participant_index() == 2 {
                input_yao_from_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    inp,
                    2,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?
            } else {
                input_yao_from_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    false,
                    2,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?
            };

            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);

            inputs[0].push(out);
        }

        for (_, &inp) in circuit.input_gate_ids[1].iter().zip(&eval_input) {
            let out = input_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                inp,
                rng.as_mut(),
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);
            inputs[1].push(out);
            let out = input_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                !inp,
                rng.as_mut(),
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);
            notinputs[1].push(out);
        }

        for (_, inp) in circuit.input_gate_ids[0].iter().zip(&garb_input) {
            let out = input_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                !inp,
                rng.as_mut(),
                &yao_setup,
            )
            .await?;
            let cor = validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &out).await?;
            assert!(cor);
            notinputs[0].push(out);
        }

        let out_sh = yao_circuit_eval_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &inputs,
            &circuit,
            rng.as_mut(),
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case1_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Vector(&[&inputs, &notinputs]),
            &MapArg::Scalar(&circuit),
            rng.as_mut(),
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case2_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Scalar(&inputs),
            &MapArg::Vector(&[&circuit, &circuit]),
            rng.as_mut(),
            &hash,
            &yao_setup,
        )
        .await?;

        let outs_case3_sh = yao_map_circuit_eval_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &MapArg::Vector(&[&inputs, &notinputs]),
            &MapArg::Vector(&[&circuit, &circuit]),
            rng.as_mut(),
            &hash,
            &yao_setup,
        )
        .await?;

        let mut op = vec![];

        for i in &circuit.output_gate_ids {
            let cor: bool = validate_yao_share(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(i).unwrap(),
            )
            .await?;
            assert!(cor);
            let output = output_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(i).unwrap(),
            )
            .await?;
            op.push(output);

            let op1 = output_yao_to_functionality(
                &setup,
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
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
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
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
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
                    &mut tag_offset_counter,
                    &mut relay,
                    out_sh.get(i).unwrap(),
                )
                .await?;
                assert!(cor);
                let output = output_yao_functionality(
                    &setup,
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
        circuit: Arc<BinaryCircuit>,
        garb_input: Vec<bool>,
        eval_input: Vec<bool>,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);

        let mut init_seed = [0u8; 32];
        let mut common_randomness_seed = [0u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);
        transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

        let mut tag_offset_counter = TagOffsetCounter::new();
        let yao_setup =
            setup_yao_functionality(&setup, &mut tag_offset_counter, &mut relay).await?;

        let (mut rng, hash, comm) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesGarbleHash::new(e.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                (None, hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesGarbleHash::new(g.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                let r = ChaCha8Rng::from_seed(g.prf_key);
                (Some(r), hash, comm)
            }
        };

        let mut count = 0;

        let mut inputs = vec![vec![], vec![]];

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 32 && count < circuit.input_gate_ids[0].len() {
            ids.push(circuit.input_gate_ids[0][count]);
            inps.push(garb_input[count]);
            count += 1;
        }
        let outs = batch_input_yao_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &inps,
            rng.as_mut(),
            &yao_setup,
        )
        .await?;
        inputs[0].extend_from_slice(&outs);

        println!("{} finished input g 0", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 2 * 32 && count < circuit.input_gate_ids[0].len() {
            ids.push(circuit.input_gate_ids[0][count]);
            inps.push(Some(garb_input[count]));
            count += 1;
        }
        let outs = if setup.participant_index() == 0 {
            batch_input_yao_from_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &inps,
                0,
                rng.as_mut(),
                &comm,
                &yao_setup,
            )
            .await?
        } else {
            batch_input_yao_from_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &vec![None; inps.len()],
                0,
                rng.as_mut(),
                &comm,
                &yao_setup,
            )
            .await?
        };
        inputs[0].extend_from_slice(&outs);

        println!("{} finished input g 1", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 3 * 32 && count < circuit.input_gate_ids[0].len() {
            ids.push(circuit.input_gate_ids[0][count]);
            inps.push(Some(garb_input[count]));
            count += 1;
        }
        let outs = if setup.participant_index() == 1 {
            batch_input_yao_from_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &inps,
                1,
                rng.as_mut(),
                &comm,
                &yao_setup,
            )
            .await?
        } else {
            batch_input_yao_from_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &vec![None; inps.len()],
                1,
                rng.as_mut(),
                &comm,
                &yao_setup,
            )
            .await?
        };
        inputs[0].extend_from_slice(&outs);

        println!("{} finished input g 2", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        while count < 4 * 32 && count < circuit.input_gate_ids[0].len() {
            ids.push(circuit.input_gate_ids[0][count]);
            inps.push(Some(garb_input[count]));
            count += 1;
        }
        let outs = if setup.participant_index() == 2 {
            batch_input_yao_from_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &inps,
                2,
                rng.as_mut(),
                &comm,
                &yao_setup,
            )
            .await?
        } else {
            batch_input_yao_from_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &vec![None; inps.len()],
                2,
                rng.as_mut(),
                &comm,
                &yao_setup,
            )
            .await?
        };
        inputs[0].extend_from_slice(&outs);

        println!("{} finished input g 3", setup.participant_index());

        let mut ids = vec![];
        let mut inps = vec![];
        for (id, inp) in circuit.input_gate_ids[1].iter().zip(eval_input) {
            ids.push(*id);
            inps.push(inp);
        }
        let outs = batch_input_yao_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &inps,
            rng.as_mut(),
            &yao_setup,
        )
        .await?;
        inputs[1].extend_from_slice(&outs);

        println!("{} finished input e", setup.participant_index());

        let out_sh = yao_circuit_eval_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &inputs,
            &circuit,
            rng.as_mut(),
            &hash,
            &yao_setup,
        )
        .await?;

        let mut shares = vec![];

        for i in &circuit.output_gate_ids {
            let cor: bool = validate_yao_share(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(i).unwrap(),
            )
            .await?;

            assert!(cor);
            shares.push(out_sh.get(i).unwrap().clone());
        }

        let op =
            batch_output_yao_functionality(&setup, &mut tag_offset_counter, &mut relay, &shares)
                .await?;

        let op1 = batch_output_yao_to_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            0,
            &shares,
        )
        .await?;

        let op2 = batch_output_yao_to_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            1,
            &shares,
        )
        .await?;

        let op3 = batch_output_yao_to_functionality(
            &setup,
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
        use std::time::Duration;

        use crate::functionality::utils::{NoSigningKey, NoVerifyingKey};

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
                use sl_messages::message::InstanceId;

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
        circuit: Arc<BinaryCircuit>,
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
        circuit: Arc<BinaryCircuit>,
        gin: Vec<bool>,
        ein: Vec<bool>,
        batched: bool,
    ) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, _) in parties {
            let relay = coord.connect().await.unwrap();

            if batched {
                jset.spawn(batched_test_run_entire_flow(
                    setup,
                    circuit.clone(),
                    gin.clone(),
                    ein.clone(),
                    relay,
                ));
            } else {
                jset.spawn(test_run_entire_flow(
                    setup,
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
        let circuit = Arc::new(BinaryCircuit::parse(AES128_CIRCUIT).unwrap());
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

        let circuit = Arc::new(build_comparison_circuit());

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
