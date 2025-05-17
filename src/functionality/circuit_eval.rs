use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
use sl_compute::transport::{
    proto::{FilteredMsgRelay, MessageTag, Relay},
    setup::{common::MPCEncryption, CommonSetupMessage},
    types::ProtocolError,
    utils::{receive_from_parties, send_to_party, TagOffsetCounter},
};

use crate::{
    circuitop::circuit::BinaryCircuit,
    config::constants::YAO_CIRC_EVAL_FUNC_MSG1,
    functionality::evaluate::evaluate_functionality,
    utilities::{
        hash_function::HashFunction,
        types::{
            block_vec2tblock_vec, tblock_vec2block_vec, Block, TBlock, YaoEvaluatorShare,
            YaoGarblerShare, YaoSetup, YaoShare,
        },
    },
};

use super::garble::garble_functionality;

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
    relay.ask_messages(setup, tag1, true).await?;

    if party_id == 2 {
        let len = (2 * circuit.num_nonfree_gates + circuit.constant_gate_ids.len()) * 32;

        let tfs: Vec<Vec<TBlock>> =
            receive_from_parties(setup, mpc_encryption, tag1, len, vec![0, 1], relay).await?;

        let fs: Vec<Vec<Block>> = tfs.iter().map(|f| tblock_vec2block_vec(f)).collect();

        assert_eq!(fs[0], fs[1]);

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

        let out = evaluate_functionality(circuit, &g_shares, &e_shares, &fs[0], hash).unwrap();

        output = out
            .iter()
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
    } else {
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
        )
        .unwrap();
        let tf = block_vec2tblock_vec(&f);

        send_to_party(setup, mpc_encryption, tag1, tf, 2, relay).await?;

        output = out_shares
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
            input::{input_yao_from_functionality, input_yao_functionality},
            output::{output_yao_functionality, validate_yao_share},
            setup::setup_yao_functionality,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash, utils::bool_vec_to_hex},
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

        let (mut rng, hash, mut comm) = if setup.participant_index() == 2 {
            let hash = AesHash::new(yao_setup.e_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(hash.clone());
            (None, hash, comm)
        } else {
            let hash = AesHash::new(yao_setup.g_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(hash.clone());
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
                    &mut comm,
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
                    &mut comm,
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
                    &mut comm,
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
                    &mut comm,
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
                    &mut comm,
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
                    &mut comm,
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

        for (id, inp) in circuit.evaluator_input_ids.iter().zip(eval_input) {
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
            ein.insert(*id, out);
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

        let mut op = vec![];

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
            let output = output_yao_functionality(
                &setup,
                &mut mpc_encryption,
                &mut tag_offset_counter,
                &mut relay,
                out_sh.get(&i).unwrap(),
            )
            .await?;
            op.push(output);
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
    ) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_entire_flow(None);
        sim_parties_entire_flow(parties, coord, circuit, gin, ein).await
    }

    async fn sim_parties_entire_flow<S, R>(
        parties: Vec<(SetupMessage, [u8; 32])>,
        coord: S,
        circuit: BinaryCircuit,
        gin: Vec<bool>,
        ein: Vec<bool>,
    ) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, seed) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_run_entire_flow(
                setup,
                seed,
                circuit.clone(),
                gin.clone(),
                ein.clone(),
                relay,
            ));
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
        for i in 0..2 {
            for j in 0..2 {
                let gin = vec![i != 0; 128];
                let ein = vec![j != 0; 128];
                let output =
                    sim_entire_flow(SimpleMessageRelay::new(), circuit.clone(), gin, ein).await;
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
                let output =
                    sim_entire_flow(SimpleMessageRelay::new(), circuit.clone(), gin, ein).await;
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
