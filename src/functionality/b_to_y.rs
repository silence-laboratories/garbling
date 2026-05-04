// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{CryptoRng, RngCore};

use sl_compute_common::BinaryShare;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    config::constants::B2Y_FUNC_MSG1,
    functionality::{
        utils::{
            receive_from_parties, send_to_party, FilteredMsgRelay,
            FixedExternalSize, Wrap,
        },
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::Commitment,
        hash_function::HashFunction,
        shahash::Sha512Hash,
        types::{
            Block, YaoEvaluatorShare, YaoGarblerShare, YaoSetup, YaoShare,
            BLOCK_SIZE,
        },
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
        let buffer = self.label_1.encode(buffer);
        let buffer = self.false_com.encode(buffer);
        let buffer = self.true_com.encode(buffer);
        let buffer = self.decom.0.encode(buffer);
        let buffer = self.decom.1.encode(buffer);
        self.hash.encode(buffer);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let (&label_1, buffer) = buffer.split_first_chunk()?;
        let (&false_com, buffer) = buffer.split_first_chunk()?;
        let (&true_com, buffer) = buffer.split_first_chunk()?;
        let (&decom0, buffer) = buffer.split_first_chunk()?;
        let (&decom1, buffer) = buffer.split_first_chunk()?;
        let (&hash, _) = buffer.split_first_chunk()?;

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

    let comm_2f = comm.commit(&label_2f, &witness_2f);

    let mut witness_2t = Block::default();
    rng.fill_bytes(&mut witness_2t);

    let label_2t = xor_blocks(&label_2f, delta);
    let comm_2t = comm.commit(&label_2t, &witness_2t);

    let mut witness_3f = Block::default();
    rng.fill_bytes(&mut witness_3f);

    let mut label_3f = Block::default();
    rng.fill_bytes(&mut label_3f);

    let comm_3f = comm.commit(&label_3f, &witness_3f);

    let mut witness_3t = Block::default();
    rng.fill_bytes(&mut witness_3t);

    let label_3t = xor_blocks(&label_3f, delta);
    let comm_3t = comm.commit(&label_3t, &witness_3t);

    let shahash = Sha512Hash::new();
    let hash_val = shahash.get_hash(&[comm_2f, comm_2t].concat());

    let label_1 = if x1 {
        xor_blocks(&label_1f, delta)
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
    let comm_2f = comm.commit(&label_2f, &witness_2f);

    let mut witness_2t = Block::default();
    rng.fill_bytes(&mut witness_2t);

    let label_2t = xor_blocks(&label_2f, delta);
    let comm_2t = comm.commit(&label_2t, &witness_2t);

    let mut witness_3f = Block::default();
    rng.fill_bytes(&mut witness_3f);

    let mut label_3f = Block::default();
    rng.fill_bytes(&mut label_3f);
    let comm_3f = comm.commit(&label_3f, &witness_3f);

    let mut witness_3t = Block::default();
    rng.fill_bytes(&mut witness_3t);

    let label_3t = xor_blocks(&label_3f, delta);
    let comm_3t = comm.commit(&label_3t, &witness_3t);

    let hash_val = Sha512Hash::new().get_hash(&[comm_3f, comm_3t].concat());

    let label_1 = if x1 {
        xor_blocks(&label_1f, delta)
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
) -> Result<
    (YaoEvaluatorShare, YaoEvaluatorShare, YaoEvaluatorShare),
    ProtocolError,
>
where
    C: Commitment,
{
    let x3 = share.value2;
    let x2 = share.value1 ^ share.value2;

    if msg1_p1.label_1 != msg1_p2.label_1 {
        return Err(ProtocolError::InconsistentMessage);
    }

    let shahash = Sha512Hash::new();

    let h2 =
        shahash.get_hash(&[msg1_p2.false_com, msg1_p2.true_com].concat());
    if h2 != msg1_p1.hash {
        return Err(ProtocolError::InvalidShare);
    }

    let h3 =
        shahash.get_hash(&[msg1_p1.false_com, msg1_p1.true_com].concat());
    if h3 != msg1_p2.hash {
        return Err(ProtocolError::InvalidShare);
    }

    let msg1_p2_valid = if x2 {
        comm.verify(&msg1_p2.decom.0, &msg1_p2.decom.1, &msg1_p2.true_com)
    } else {
        comm.verify(&msg1_p2.decom.0, &msg1_p2.decom.1, &msg1_p2.false_com)
    };

    if !msg1_p2_valid {
        return Err(ProtocolError::CommitmentVerificationFailed);
    }

    let msg1_p1_valid = if x3 {
        comm.verify(&msg1_p1.decom.0, &msg1_p1.decom.1, &msg1_p1.true_com)
    } else {
        comm.verify(&msg1_p1.decom.0, &msg1_p1.decom.1, &msg1_p1.false_com)
    };

    if !msg1_p1_valid {
        return Err(ProtocolError::CommitmentVerificationFailed);
    }

    Ok((
        YaoEvaluatorShare {
            label: msg1_p1.label_1,
        },
        YaoEvaluatorShare {
            label: msg1_p2.decom.0,
        },
        YaoEvaluatorShare {
            label: msg1_p1.decom.0,
        },
    ))
}

pub async fn binary_to_yao_functionality<T, R, C>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    share: &BinaryShare,
    yao_setup: &mut YaoSetup,
    comm: &C,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag = relay.next_tag(B2Y_FUNC_MSG1);

    match yao_setup {
        YaoSetup::G(yaosetup) => {
            if yaosetup.party_id == 0 {
                let (msg1, share_x1, share_x2, share_x3) =
                    bit_to_yao_create_msg1_p1(
                        share,
                        &yaosetup.delta,
                        &mut yaosetup.prf,
                        comm,
                    );

                send_to_party(setup, tag, &msg1, 2, relay).await?;

                let temp = share_x1.xor(&share_x2);
                let out = temp.xor(&share_x3);

                Ok(YaoShare::G(out))
            } else {
                let (msg1, share_x1, share_x2, share_x3) =
                    bit_to_yao_create_msg1_p2(
                        share,
                        &yaosetup.delta,
                        &mut yaosetup.prf,
                        comm,
                    );

                send_to_party(setup, tag, &msg1, 2, relay).await?;

                let temp = share_x1.xor(&share_x2);
                let out = temp.xor(&share_x3);

                Ok(YaoShare::G(out))
            }
        }

        YaoSetup::E(_e) => {
            let recv: Vec<B2YMsg1> =
                receive_from_parties(setup, tag, &[0, 1], relay).await?;

            let msg1_p1 = &recv[0];
            let msg1_p2 = &recv[1];

            let (share_x1, share_x2, share_x3) =
                bit_to_yao_process_msg1_p3(share, msg1_p1, msg1_p2, comm)?;

            let temp = share_x1.xor(&share_x2);
            let out = temp.xor(&share_x3);

            Ok(YaoShare::E(out))
        }
    }
}

pub async fn batch_binary_to_yao_functionality<T, R, C>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[BinaryShare],
    yao_setup: &mut YaoSetup,
    comm: &C,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag = relay.next_tag(B2Y_FUNC_MSG1);

    let batch_size = shares.len();

    match yao_setup {
        YaoSetup::G(yaosetup) => {
            if yaosetup.party_id == 0 {
                let mut msg1s = Vec::with_capacity(batch_size);

                let outputs = shares
                    .iter()
                    .map(|share| {
                        let (msg1, share_x1, share_x2, share_x3) =
                            bit_to_yao_create_msg1_p1(
                                share,
                                &yaosetup.delta,
                                &mut yaosetup.prf,
                                comm,
                            );

                        msg1s.push(msg1);

                        let temp = share_x1.xor(&share_x2);
                        let out = temp.xor(&share_x3);

                        YaoShare::G(out)
                    })
                    .collect();

                send_to_party(setup, tag, &msg1s, 2, relay).await?;

                Ok(outputs)
            } else {
                let mut msg1s = Vec::with_capacity(batch_size);

                let outputs = shares
                    .iter()
                    .map(|share| {
                        let (msg1, share_x1, share_x2, share_x3) =
                            bit_to_yao_create_msg1_p2(
                                share,
                                &yaosetup.delta,
                                &mut yaosetup.prf,
                                comm,
                            );

                        msg1s.push(msg1);

                        let temp = share_x1.xor(&share_x2);
                        let out = temp.xor(&share_x3);

                        YaoShare::G(out)
                    })
                    .collect();

                send_to_party(setup, tag, &msg1s, 2, relay).await?;

                Ok(outputs)
            }
        }

        YaoSetup::E(_e) => {
            let recv: Vec<Vec<B2YMsg1>> =
                receive_from_parties(setup, tag, &[0, 1], relay).await?;

            let msg1_p1 = &recv[0];
            let msg1_p2 = &recv[1];

            let outputs = shares
                .iter()
                .enumerate()
                .map(|(i, share)| {
                    let (share_x1, share_x2, share_x3) =
                        bit_to_yao_process_msg1_p3(
                            share,
                            &msg1_p1[i],
                            &msg1_p2[i],
                            comm,
                        )?;

                    let temp = share_x1.xor(&share_x2);
                    let out = temp.xor(&share_x3);

                    Ok::<YaoShare, ProtocolError>(YaoShare::E(out))
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(outputs)
        }
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use sl_compute_common::{BinaryString, BinaryStringShare};
    use sl_messages::relay::{
        MessageRelayService, Relay, SimpleMessageRelay,
    };
    use sl_messages::setup::ProtocolParticipant;
    use tokio::task::JoinSet;

    use crate::{
        functionality::{
            output::batch_output_yao_functionality,
            setup::setup_yao_functionality,
            utils::{FilteredMsgRelay, SetupMessage},
            utils_dep::ProtocolError,
        },
        utilities::{
            commitments::HashCommitment,
            garble_hash::AesGarbleHash,
            shahash::Sha512Hash,
            types::{Block, YaoSetup},
        },
    };

    use super::{
        batch_binary_to_yao_functionality, binary_to_yao_functionality,
    };

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
        relay.init_abort(&setup).await?;

        let mut init_seed = [0u8; 32];
        let mut common_randomness_seed = [0u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);
        transcript.challenge_bytes(
            b"common-randomness-seed",
            &mut common_randomness_seed,
        );

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let (_, comm) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesGarbleHash::new(e.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                (hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesGarbleHash::new(g.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                (hash, comm)
            }
        };

        let key =
            BinaryStringShare::from_constant(&s, setup.participant_index());

        let mut yao_out = vec![];

        for i in 0..key.length as usize {
            let share = key.get_binary_share(i);
            let out = binary_to_yao_functionality(
                &setup,
                &mut relay,
                &share,
                &mut yao_setup,
                &comm,
            )
            .await?;
            yao_out.push(out);
        }

        let act_out =
            batch_output_yao_functionality(&setup, &mut relay, &yao_out)
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
        relay.init_abort(&setup).await?;

        let mut init_seed = [0u8; 32];
        let mut common_randomness_seed = [0u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);
        transcript.challenge_bytes(
            b"common-randomness-seed",
            &mut common_randomness_seed,
        );

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let (_, comm) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesGarbleHash::new(e.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                (hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesGarbleHash::new(g.comm_crs);
                let comm = HashCommitment::new(Sha512Hash::new());
                (hash, comm)
            }
        };

        let key =
            BinaryStringShare::from_constant(&s, setup.participant_index());

        let mut yao_bin = vec![];
        for i in 0..key.length as usize {
            yao_bin.push(key.get_binary_share(i));
        }

        let yao_out = batch_binary_to_yao_functionality(
            &setup,
            &mut relay,
            &yao_bin,
            &mut yao_setup,
            &comm,
        )
        .await?;

        let act_out =
            batch_output_yao_functionality(&setup, &mut relay, &yao_out)
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
    fn setup_b_to_y(
        instance: Option<[u8; 32]>,
    ) -> Vec<(SetupMessage, [u8; 32])> {
        use sha2::{Digest, Sha256};
        use std::time::Duration;

        use sl_messages::setup::keys::{NoSigningKey, NoVerifyingKey};

        let instance = instance.unwrap_or_else(rand::random);

        // a signing key for each party.
        let party_sk: Vec<NoSigningKey> =
            std::iter::repeat_with(|| NoSigningKey)
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

                SetupMessage::new(
                    InstanceId::new(instance),
                    sk,
                    party_id,
                    party_vk.clone(),
                )
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

    async fn sim_b_to_y<S, R>(
        coord: S,
        s: BinaryString,
        batch: bool,
    ) -> Vec<Vec<bool>>
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
                println!("error {err}");
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
        let mut rng = StdRng::from_entropy();
        let mut s = Block::default();
        rng.fill_bytes(&mut s);
        let val = BinaryString {
            length: (s.len() * 8) as u64,
            value: s.to_vec(),
        };
        let _ =
            sim_b_to_y(SimpleMessageRelay::new(), val.clone(), !batch).await;
        let _ =
            sim_b_to_y(SimpleMessageRelay::new(), val.clone(), batch).await;
    }
}
