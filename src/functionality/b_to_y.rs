use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
use sl_compute_common::BinaryShare;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    circuitop::circuit_builder::CircuitBuilder,
    config::constants::B2Y_FUNC_MSG1,
    functionality::{
        evaluate::evaluate_functionality,
        garble::garble_functionality,
        utils::{receive_from_parties, send_to_party},
        utils_dep::{
            FilteredMsgRelay, FixedExternalSize, ProtocolError, ProtocolParticipant,
            TagOffsetCounter, Wrap,
        },
    },
    utilities::{
        commitments::Commitment,
        hash_function::HashFunction,
        shahash::Sha512Hash,
        types::{Block, YaoEvaluatorShare, YaoGarblerShare, YaoSetup, YaoShare, BLOCK_SIZE},
        utils::xor_blocks,
    },
};

#[derive(Clone, Debug, Default)]
pub(crate) struct B2YMsg1 {
    label_1: Block,
    false_com: Block,
    true_com: Block,
    decom: (Block, Block),
    hash: Block,
}

impl Wrap for B2YMsg1 {
    fn external_size(&self) -> usize {
        BLOCK_SIZE * 6
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..BLOCK_SIZE].copy_from_slice(&self.label_1);
        buffer[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&self.false_com);
        buffer[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&self.true_com);
        buffer[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&self.decom.0);
        buffer[BLOCK_SIZE * 4..BLOCK_SIZE * 5].copy_from_slice(&self.decom.1);
        buffer[BLOCK_SIZE * 5..BLOCK_SIZE * 6].copy_from_slice(&self.hash);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut label_1 = Block::default();
        label_1.copy_from_slice(&buffer[0..BLOCK_SIZE]);

        let mut false_com = Block::default();
        false_com.copy_from_slice(&buffer[BLOCK_SIZE..BLOCK_SIZE * 2]);

        let mut true_com = Block::default();
        true_com.copy_from_slice(&buffer[BLOCK_SIZE * 2..BLOCK_SIZE * 3]);

        let mut decom0 = Block::default();
        decom0.copy_from_slice(&buffer[BLOCK_SIZE * 3..BLOCK_SIZE * 4]);

        let mut decom1 = Block::default();
        decom1.copy_from_slice(&buffer[BLOCK_SIZE * 4..BLOCK_SIZE * 5]);

        let mut hash = Block::default();
        hash.copy_from_slice(&buffer[BLOCK_SIZE * 5..BLOCK_SIZE * 6]);

        Some(Self {
            label_1,
            false_com,
            true_com,
            decom: (decom0, decom1),
            hash,
        })
    }
}

impl FixedExternalSize for B2YMsg1 {
    const SIZE: usize = BLOCK_SIZE * 6;
}

fn bit_to_yao_create_msg1_p1<C, R>(
    share: &BinaryShare,
    delta: &Block,
    rng: &mut R,
    comm: &C,
) -> (B2YMsg1, YaoGarblerShare, YaoGarblerShare, YaoGarblerShare)
where
    C: Commitment,
    R: CryptoRng + RngCore,
{
    let x1 = share.value2;
    let x3 = share.value1 ^ share.value2;

    let mut label_1f = Block::default();
    rng.fill_bytes(&mut label_1f);

    let mut witness_2f = Block::default();
    rng.fill_bytes(&mut witness_2f);
    let mut label_2f = Block::default();
    rng.fill_bytes(&mut label_2f);
    let comm_2f = comm.commit(label_2f, witness_2f);

    let mut witness_2t = Block::default();
    rng.fill_bytes(&mut witness_2t);
    let label_2t = xor_blocks(label_2f, *delta);
    let comm_2t = comm.commit(label_2t, witness_2t);

    let mut witness_3f = Block::default();
    rng.fill_bytes(&mut witness_3f);
    let mut label_3f = Block::default();
    rng.fill_bytes(&mut label_3f);
    let comm_3f = comm.commit(label_3f, witness_3f);

    let mut witness_3t = Block::default();
    rng.fill_bytes(&mut witness_3t);
    let label_3t = xor_blocks(label_3f, *delta);
    let comm_3t = comm.commit(label_3t, witness_3t);

    let mut h2_init = [0u8; BLOCK_SIZE * 2];
    h2_init[0..BLOCK_SIZE].copy_from_slice(&comm_2f);
    h2_init[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&comm_2t);

    let shahash = Sha512Hash::new();
    let hash_val = shahash.get_hash(&h2_init).unwrap();

    let label_1 = if x1 {
        xor_blocks(label_1f, *delta)
    } else {
        label_1f
    };

    (
        B2YMsg1 {
            label_1,
            false_com: comm_3f,
            true_com: comm_3t,
            decom: if x3 {
                (label_3t, witness_3t)
            } else {
                (label_3f, witness_3f)
            },
            hash: hash_val,
        },
        YaoGarblerShare {
            delta: *delta,
            f_label: label_1f,
        },
        YaoGarblerShare {
            delta: *delta,
            f_label: label_2f,
        },
        YaoGarblerShare {
            delta: *delta,
            f_label: label_3f,
        },
    )
}

fn bit_to_yao_create_msg1_p2<C, R>(
    share: &BinaryShare,
    delta: &Block,
    rng: &mut R,
    comm: &C,
) -> (B2YMsg1, YaoGarblerShare, YaoGarblerShare, YaoGarblerShare)
where
    C: Commitment,
    R: CryptoRng + RngCore,
{
    let x2 = share.value2;
    let x1 = share.value1 ^ share.value2;

    let mut label_1f = Block::default();
    rng.fill_bytes(&mut label_1f);

    let mut witness_2f = Block::default();
    rng.fill_bytes(&mut witness_2f);
    let mut label_2f = Block::default();
    rng.fill_bytes(&mut label_2f);
    let comm_2f = comm.commit(label_2f, witness_2f);

    let mut witness_2t = Block::default();
    rng.fill_bytes(&mut witness_2t);
    let label_2t = xor_blocks(label_2f, *delta);
    let comm_2t = comm.commit(label_2t, witness_2t);

    let mut witness_3f = Block::default();
    rng.fill_bytes(&mut witness_3f);
    let mut label_3f = Block::default();
    rng.fill_bytes(&mut label_3f);
    let comm_3f = comm.commit(label_3f, witness_3f);

    let mut witness_3t = Block::default();
    rng.fill_bytes(&mut witness_3t);
    let label_3t = xor_blocks(label_3f, *delta);
    let comm_3t = comm.commit(label_3t, witness_3t);

    let mut h3_init = [0u8; BLOCK_SIZE * 2];
    h3_init[0..BLOCK_SIZE].copy_from_slice(&comm_3f);
    h3_init[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&comm_3t);

    let shahash = Sha512Hash::new();
    let hash_val = shahash.get_hash(&h3_init).unwrap();

    let label_1 = if x1 {
        xor_blocks(label_1f, *delta)
    } else {
        label_1f
    };

    (
        B2YMsg1 {
            label_1,
            false_com: comm_2f,
            true_com: comm_2t,
            decom: if x2 {
                (label_2t, witness_2t)
            } else {
                (label_2f, witness_2f)
            },
            hash: hash_val,
        },
        YaoGarblerShare {
            delta: *delta,
            f_label: label_1f,
        },
        YaoGarblerShare {
            delta: *delta,
            f_label: label_2f,
        },
        YaoGarblerShare {
            delta: *delta,
            f_label: label_3f,
        },
    )
}

fn bit_to_yao_process_msg1_p3<C>(
    share: &BinaryShare,
    msg1_p1: &B2YMsg1,
    msg1_p2: &B2YMsg1,
    comm: &C,
) -> (YaoEvaluatorShare, YaoEvaluatorShare, YaoEvaluatorShare)
where
    C: Commitment,
{
    let x3 = share.value2;
    let x2 = share.value1 ^ share.value2;

    assert_eq!(msg1_p1.label_1, msg1_p2.label_1);

    let shahash = Sha512Hash::new();
    let mut h2_init = [0u8; BLOCK_SIZE * 2];
    h2_init[0..BLOCK_SIZE].copy_from_slice(&msg1_p2.false_com);
    h2_init[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&msg1_p2.true_com);
    let h2 = shahash.get_hash(&h2_init).unwrap();
    assert_eq!(h2, msg1_p1.hash);

    let mut h3_init = [0u8; BLOCK_SIZE * 2];
    h3_init[0..BLOCK_SIZE].copy_from_slice(&msg1_p1.false_com);
    h3_init[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&msg1_p1.true_com);
    let h3 = shahash.get_hash(&h3_init).unwrap();
    assert_eq!(h3, msg1_p2.hash);

    if x2 {
        assert!(comm.verify(msg1_p2.decom.0, msg1_p2.decom.1, msg1_p2.true_com))
    } else {
        assert!(comm.verify(msg1_p2.decom.0, msg1_p2.decom.1, msg1_p2.false_com))
    }

    if x3 {
        assert!(comm.verify(msg1_p1.decom.0, msg1_p1.decom.1, msg1_p1.true_com))
    } else {
        assert!(comm.verify(msg1_p1.decom.0, msg1_p1.decom.1, msg1_p1.false_com))
    }

    (
        YaoEvaluatorShare {
            label: msg1_p1.label_1,
        },
        YaoEvaluatorShare {
            label: msg1_p2.decom.0,
        },
        YaoEvaluatorShare {
            label: msg1_p1.decom.0,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn binary_to_yao_functionality<T, R, C, G, H>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &BinaryShare,
    yao_setup: &YaoSetup,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let party_id = setup.participant_index();
    assert!(yao_setup.e_setup.is_some() | yao_setup.g_setup.is_some());

    let mut builder = CircuitBuilder::new();
    let x1 = builder.garbler_input();
    let x2 = builder.garbler_input();
    let x3 = builder.garbler_input();
    let x4 = builder.xor(x1, x2);
    let x5 = builder.xor(x4, x3);
    builder.output(x5);
    let circuit = builder.finish();

    let tag_offset = tag_offset_counter.next_value();
    let tag = MessageTag::tag1(B2Y_FUNC_MSG1, tag_offset);
    relay.ask_messages(setup, tag, true).await?;
    match party_id {
        0 => {
            assert!(yao_setup.g_setup.is_some());
            let mut r = rng.as_mut().unwrap();
            let yaosetup = yao_setup.clone().g_setup.unwrap();
            let (msg1, share_x1, share_x2, share_x3) =
                bit_to_yao_create_msg1_p1(share, &yaosetup.delta, &mut r, comm);

            send_to_party(setup, tag, msg1, 2, relay).await?;

            let mut gin = HashMap::new();
            gin.insert(circuit.garbler_input_ids[0], share_x1);
            gin.insert(circuit.garbler_input_ids[1], share_x2);
            gin.insert(circuit.garbler_input_ids[2], share_x3);

            let (_, outshares) =
                garble_functionality(&circuit, &gin, &HashMap::new(), &yaosetup, &mut r, hash);

            Ok(YaoShare {
                g_share: Some(outshares.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                e_share: None,
            })
        }
        1 => {
            assert!(yao_setup.g_setup.is_some());
            let mut r = rng.as_mut().unwrap();
            let yaosetup = yao_setup.clone().g_setup.unwrap();
            let (msg1, share_x1, share_x2, share_x3) =
                bit_to_yao_create_msg1_p2(share, &yaosetup.delta, &mut r, comm);

            send_to_party(setup, tag, msg1, 2, relay).await?;

            let mut gin = HashMap::new();
            gin.insert(circuit.garbler_input_ids[0], share_x1);
            gin.insert(circuit.garbler_input_ids[1], share_x2);
            gin.insert(circuit.garbler_input_ids[2], share_x3);

            let (_, outshares) =
                garble_functionality(&circuit, &gin, &HashMap::new(), &yaosetup, &mut r, hash);

            Ok(YaoShare {
                g_share: Some(outshares.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                e_share: None,
            })
        }
        _ => {
            assert!(yao_setup.e_setup.is_some());

            let msg = B2YMsg1::default();

            let recv: Vec<B2YMsg1> =
                receive_from_parties(setup, tag, msg.external_size(), vec![0, 1], relay).await?;

            let msg1_p1 = recv[0].clone();
            let msg1_p2 = recv[1].clone();

            let (share_x1, share_x2, share_x3) =
                bit_to_yao_process_msg1_p3(share, &msg1_p1, &msg1_p2, comm);

            let mut gin = HashMap::new();
            gin.insert(circuit.garbler_input_ids[0], share_x1);
            gin.insert(circuit.garbler_input_ids[1], share_x2);
            gin.insert(circuit.garbler_input_ids[2], share_x3);

            let outshares = evaluate_functionality(&circuit, &gin, &HashMap::new(), &[], hash);

            Ok(YaoShare {
                g_share: None,
                e_share: Some(outshares.get(&circuit.output_gate_ids[0]).unwrap().clone()),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn batch_binary_to_yao_functionality<T, R, C, G, H>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &[BinaryShare],
    yao_setup: &YaoSetup,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let party_id = setup.participant_index();
    assert!(yao_setup.e_setup.is_some() | yao_setup.g_setup.is_some());

    let batch_size = share.len();

    let mut builder = CircuitBuilder::new();
    let x1 = builder.garbler_input();
    let x2 = builder.garbler_input();
    let x3 = builder.garbler_input();
    let x4 = builder.xor(x1, x2);
    let x5 = builder.xor(x4, x3);
    builder.output(x5);
    let circuit = builder.finish();

    let tag_offset = tag_offset_counter.next_value();
    let tag = MessageTag::tag1(B2Y_FUNC_MSG1, tag_offset);
    relay.ask_messages(setup, tag, true).await?;
    match party_id {
        0 => {
            assert!(yao_setup.g_setup.is_some());
            let yaosetup = yao_setup.clone().g_setup.unwrap();

            let mut r = rng.as_mut().unwrap();

            let mut msg1s = Vec::new();
            let mut outputs = Vec::new();

            (0..batch_size).for_each(|i| {
                let (msg1, share_x1, share_x2, share_x3) =
                    bit_to_yao_create_msg1_p1(&share[i], &yaosetup.delta, &mut r, comm);
                msg1s.push(msg1);

                let mut gin = HashMap::new();
                gin.insert(circuit.garbler_input_ids[0], share_x1);
                gin.insert(circuit.garbler_input_ids[1], share_x2);
                gin.insert(circuit.garbler_input_ids[2], share_x3);

                let (_, outshares) =
                    garble_functionality(&circuit, &gin, &HashMap::new(), &yaosetup, &mut r, hash);

                let output = YaoShare {
                    g_share: Some(outshares.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                    e_share: None,
                };
                outputs.push(output);
            });

            send_to_party(setup, tag, msg1s, 2, relay).await?;

            Ok(outputs)
        }
        1 => {
            assert!(yao_setup.g_setup.is_some());
            let yaosetup = yao_setup.clone().g_setup.unwrap();

            let mut r = rng.as_mut().unwrap();

            let mut msg1s = Vec::new();
            let mut outputs = Vec::new();

            (0..batch_size).for_each(|i| {
                let (msg1, share_x1, share_x2, share_x3) =
                    bit_to_yao_create_msg1_p2(&share[i], &yaosetup.delta, &mut r, comm);
                msg1s.push(msg1);

                let mut gin = HashMap::new();
                gin.insert(circuit.garbler_input_ids[0], share_x1);
                gin.insert(circuit.garbler_input_ids[1], share_x2);
                gin.insert(circuit.garbler_input_ids[2], share_x3);

                let (_, outshares) =
                    garble_functionality(&circuit, &gin, &HashMap::new(), &yaosetup, &mut r, hash);

                let output = YaoShare {
                    g_share: Some(outshares.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                    e_share: None,
                };
                outputs.push(output);
            });

            send_to_party(setup, tag, msg1s, 2, relay).await?;

            Ok(outputs)
        }
        _ => {
            assert!(yao_setup.e_setup.is_some());

            let msg = B2YMsg1::default();

            let recv: Vec<Vec<B2YMsg1>> = receive_from_parties(
                setup,
                tag,
                msg.external_size() * batch_size,
                vec![0, 1],
                relay,
            )
            .await?;

            let msg1_p1 = recv[0].clone();
            let msg1_p2 = recv[1].clone();

            let mut outputs = Vec::new();
            for i in 0..batch_size {
                let (share_x1, share_x2, share_x3) =
                    bit_to_yao_process_msg1_p3(&share[i], &msg1_p1[i], &msg1_p2[i], comm);
                let mut gin = HashMap::new();
                gin.insert(circuit.garbler_input_ids[0], share_x1);
                gin.insert(circuit.garbler_input_ids[1], share_x2);
                gin.insert(circuit.garbler_input_ids[2], share_x3);

                let outshares = evaluate_functionality(&circuit, &gin, &HashMap::new(), &[], hash);

                let output = YaoShare {
                    g_share: None,
                    e_share: Some(outshares.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                };
                outputs.push(output);
            }
            Ok(outputs)
        }
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use sl_compute_common::{BinaryString, BinaryStringShare};
    use sl_messages::relay::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    use crate::{
        functionality::{
            output::batch_output_yao_functionality,
            setup::setup_yao_functionality,
            utils_dep::{
                FilteredMsgRelay, ProtocolError, ProtocolParticipant, SetupMessage,
                TagOffsetCounter,
            },
        },
        utilities::{
            commitments::HashCommitment, garble_hash::AesGarbleHash, shahash::Sha512Hash,
            types::Block,
        },
    };

    use super::{batch_binary_to_yao_functionality, binary_to_yao_functionality};

    async fn test_run_b_to_y<T, R>(
        setup: T,
        s: BinaryString,
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
        let key = BinaryStringShare::from_constant(&s, setup.participant_index());

        let mut yao_out = vec![];

        for i in 0..key.length as usize {
            let share = key.get_binary_share(i);
            let out = binary_to_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &share,
                &yao_setup,
                &mut rng,
                &hash,
                &comm,
            )
            .await?;
            yao_out.push(out);
        }

        let act_out =
            batch_output_yao_functionality(&setup, &mut tag_offset_counter, &mut relay, &yao_out)
                .await?;

        let mut o = BinaryString::new();
        for i in act_out {
            o.push(i);
        }

        assert_eq!(o, s);

        let op = vec![];
        Ok((setup.participant_index(), op))
    }

    async fn batch_test_run_b_to_y<T, R>(
        setup: T,
        s: BinaryString,
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

        let key = BinaryStringShare::from_constant(&s, setup.participant_index());

        let mut yao_bin = vec![];
        for i in 0..key.length as usize {
            yao_bin.push(key.get_binary_share(i));
        }

        let yao_out = batch_binary_to_yao_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &yao_bin,
            &yao_setup,
            &mut rng,
            &hash,
            &comm,
        )
        .await?;

        let act_out =
            batch_output_yao_functionality(&setup, &mut tag_offset_counter, &mut relay, &yao_out)
                .await?;

        let mut o = BinaryString::new();
        for i in act_out {
            o.push(i);
        }

        assert_eq!(o, s);
        let op = vec![];
        Ok((setup.participant_index(), op))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn setup_b_to_y(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
        use sha2::{Digest, Sha256};
        use std::time::Duration;

        use crate::functionality::utils_dep::{NoSigningKey, NoVerifyingKey};

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

    async fn sim_b_to_y<S, R>(coord: S, s: BinaryString, batch: bool) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_b_to_y(None);
        sim_parties_b_to_y(parties, coord, s, batch).await
    }

    async fn sim_parties_b_to_y<S, R>(
        parties: Vec<(SetupMessage, [u8; 32])>,
        coord: S,
        s: BinaryString,
        batch: bool,
    ) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, _) in parties {
            let relay = coord.connect().await.unwrap();
            if batch {
                jset.spawn(batch_test_run_b_to_y(setup, s.clone(), relay));
            } else {
                jset.spawn(test_run_b_to_y(setup, s.clone(), relay));
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
    async fn test_b_to_y() {
        let batch = true;
        let mut rng = StdRng::from_os_rng();
        let mut s = Block::default();
        rng.fill_bytes(&mut s);
        let val = BinaryString {
            length: (s.len() * 8) as u64,
            value: s.to_vec(),
        };
        let _ = sim_b_to_y(SimpleMessageRelay::new(), val.clone(), !batch).await;
        let _ = sim_b_to_y(SimpleMessageRelay::new(), val.clone(), batch).await;
    }
}
