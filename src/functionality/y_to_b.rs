use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use sl_compute_common::BinaryShare;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    config::constants::{Y2B_FUNC_MSG1, Y2B_FUNC_MSG2, Y2B_FUNC_MSG3, Y2B_FUNC_MSG4},
    functionality::{
        utils::{receive_from_parties, send_to_party, FilteredMsgRelay},
        utils_dep::{ProtocolError, ProtocolParticipant, TagOffsetCounter},
    },
    utilities::{
        commitments::Commitment,
        types::{Block, GarblerSetup, YaoGarblerShare, YaoSetup, YaoShare, BLOCK_SIZE},
        utils::{lsb, xor_blocks},
    },
};

fn create_yao_to_binary_msg1(yao_setup: &GarblerSetup) -> (bool, Block, Block) {
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let y = rng.random_bool(0.5);
    let mut wyr = Block::default();
    rng.fill_bytes(&mut wyr);

    let wr0 = if y {
        xor_blocks(wyr, yao_setup.delta)
    } else {
        wyr
    };
    (y, wyr, wr0)
}

fn create_yao_to_binary_msg2<C, G>(
    wr0: &Block,
    comm: &C,
    rng: &mut G,
    input: &YaoGarblerShare,
) -> (Block, Block, Block, Block, Block, Block)
where
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let p = lsb(input.f_label);

    let wz0 = xor_blocks(*wr0, input.f_label);
    let mut wit0 = Block::default();
    rng.fill_bytes(&mut wit0);

    let wz1 = xor_blocks(wz0, input.delta);
    let mut wit1 = Block::default();
    rng.fill_bytes(&mut wit1);

    let (com0, com1) = if p == 0 {
        (comm.commit(wz0, wit0), comm.commit(wz1, wit1))
    } else {
        (comm.commit(wz1, wit0), comm.commit(wz0, wit1))
    };

    (com0, com1, wz0, wz1, wit0, wit1)
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_to_binary_functionality<T, G, C, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &YaoShare,
    rng: &mut Option<G>,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<BinaryShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let mut relay = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(Y2B_FUNC_MSG1, tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(Y2B_FUNC_MSG2, tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag3 = MessageTag::tag1(Y2B_FUNC_MSG3, tag_offset);
    relay.ask_messages(setup, tag3, true).await?;

    let output = yao_to_binary_functionality_inner(
        setup, &mut relay, input, rng, comm, yao_setup, tag1, tag2, tag3,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_to_binary_functionality_inner<T, G, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
    rng: &mut Option<G>,
    comm: &C,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
    tag2: MessageTag,
    tag3: MessageTag,
) -> Result<BinaryShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let party_id = setup.participant_index();

    match party_id {
        0 => {
            assert!(yao_setup.g_setup.is_some());
            let yaosetup = yao_setup.g_setup.clone().unwrap();
            let (y, wyr, wr0) = create_yao_to_binary_msg1(&yaosetup);
            let mut msg = [0u8; BLOCK_SIZE + 1];
            msg[0..BLOCK_SIZE].copy_from_slice(&wyr);
            if y {
                msg[BLOCK_SIZE] = 1;
            }
            send_to_party(setup, tag1, msg, 2, relay).await?;
            send_to_party(setup, tag1, wr0, 1, relay).await?;

            let r = rng.as_mut().unwrap();

            let (com0, com1, _, _, wit0, wit1) =
                create_yao_to_binary_msg2(&wr0, comm, r, &input.clone().g_share.unwrap());

            let mut msg = [0u8; BLOCK_SIZE * 4];
            msg[0..BLOCK_SIZE].copy_from_slice(&com0);
            msg[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&com1);
            msg[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&wit0);
            msg[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&wit1);

            send_to_party(setup, tag2, msg, 2, relay).await?;
            let p = lsb(input.clone().g_share.unwrap().f_label) != 0;
            Ok(BinaryShare {
                value1: p ^ y,
                value2: p,
            })
        }
        1 => {
            let msg1s: Vec<Block> =
                receive_from_parties(setup, tag1, BLOCK_SIZE, vec![0], relay).await?;
            let mut wr0 = Block::default();
            wr0.copy_from_slice(&msg1s[0]);

            let r = rng.as_mut().unwrap();

            let (com0, com1, wz0, wz1, _, _) =
                create_yao_to_binary_msg2(&wr0, comm, r, &input.clone().g_share.unwrap());

            let mut msg = [0u8; BLOCK_SIZE * 4];
            msg[0..BLOCK_SIZE].copy_from_slice(&com0);
            msg[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&com1);

            send_to_party(setup, tag2, msg, 2, relay).await?;

            let msg2s: Vec<Block> =
                receive_from_parties(setup, tag3, BLOCK_SIZE, vec![2], relay).await?;
            let mut wxz = Block::default();
            wxz.copy_from_slice(&msg2s[0]);

            let val1 = wxz == wz0;
            let val2 = wxz == wz1;

            assert_eq!(
                yao_setup.g_setup.clone().unwrap().delta,
                input.g_share.clone().unwrap().delta
            );
            assert!(val1 || val2);

            let pz = (lsb(wxz) ^ lsb(wr0)) != 0;
            let p = lsb(input.clone().g_share.unwrap().f_label) != 0;
            Ok(BinaryShare {
                value1: pz ^ p,
                value2: pz,
            })
        }
        _ => {
            let msg1s: Vec<[u8; BLOCK_SIZE + 1]> =
                receive_from_parties(setup, tag1, BLOCK_SIZE + 1, vec![0], relay).await?;
            let mut wyr = Block::default();
            wyr.copy_from_slice(&msg1s[0][0..BLOCK_SIZE]);
            let y = msg1s[0][BLOCK_SIZE] != 0;

            let yaoshare = input.e_share.clone().unwrap();

            let wxz = xor_blocks(yaoshare.label, wyr);

            send_to_party(setup, tag3, wxz, 1, relay).await?;

            let msg2s: Vec<Vec<u8>> =
                receive_from_parties(setup, tag2, BLOCK_SIZE * 4, vec![0, 1], relay).await?;

            let mut com0 = Block::default();
            let mut com1 = Block::default();
            let mut com01 = Block::default();
            let mut com11 = Block::default();
            let mut wit0 = Block::default();
            let mut wit1 = Block::default();

            com0.copy_from_slice(&msg2s[0][0..BLOCK_SIZE]);
            com1.copy_from_slice(&msg2s[0][BLOCK_SIZE..BLOCK_SIZE * 2]);
            com01.copy_from_slice(&msg2s[1][0..BLOCK_SIZE]);
            com11.copy_from_slice(&msg2s[1][BLOCK_SIZE..BLOCK_SIZE * 2]);
            wit0.copy_from_slice(&msg2s[0][BLOCK_SIZE * 2..BLOCK_SIZE * 3]);
            wit1.copy_from_slice(&msg2s[0][BLOCK_SIZE * 3..BLOCK_SIZE * 4]);

            assert_eq!(com0, com01);
            assert_eq!(com1, com11);

            let px = lsb(yaoshare.label) != 0;
            if px ^ y {
                assert!(comm.verify(wxz, wit1, com1))
            } else {
                assert!(comm.verify(wxz, wit0, com0))
            }

            let pz = px ^ y;
            Ok(BinaryShare {
                value1: y ^ pz,
                value2: y,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn batch_yao_to_binary_functionality<T, G, C, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &[YaoShare],
    rng: &mut Option<G>,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let mut relay = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(Y2B_FUNC_MSG1, tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(Y2B_FUNC_MSG2, tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag3 = MessageTag::tag1(Y2B_FUNC_MSG3, tag_offset);
    relay.ask_messages(setup, tag3, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag4 = MessageTag::tag1(Y2B_FUNC_MSG4, tag_offset);
    relay.ask_messages(setup, tag4, true).await?;

    let output = batch_yao_to_binary_functionality_inner(
        setup, &mut relay, input, rng, comm, yao_setup, tag1, tag2, tag3, tag4,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn batch_yao_to_binary_functionality_inner<T, G, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[YaoShare],
    rng: &mut Option<G>,
    comm: &C,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
    tag2: MessageTag,
    tag3: MessageTag,
    tag4: MessageTag,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let party_id = setup.participant_index();
    let batch_size = input.len();

    match party_id {
        0 => {
            assert!(yao_setup.g_setup.is_some());
            let yaosetup = yao_setup.g_setup.clone().unwrap();

            let mut msgs = Vec::new();
            let mut wr0msgs = Vec::new();
            let mut msg2s = Vec::new();
            let r = rng.as_mut().unwrap();

            let mut outputs = Vec::new();

            (0..batch_size).for_each(|i| {
                let (y, wyr, wr0) = create_yao_to_binary_msg1(&yaosetup);
                let mut msg = [0u8; BLOCK_SIZE + 1];
                msg[0..BLOCK_SIZE].copy_from_slice(&wyr);
                if y {
                    msg[BLOCK_SIZE] = 1;
                }

                for i in msg {
                    msgs.push(i);
                }
                for i in wr0 {
                    wr0msgs.push(i);
                }
                let (com0, com1, _, _, wit0, wit1) =
                    create_yao_to_binary_msg2(&wr0, comm, r, &input[i].clone().g_share.unwrap());
                for i in com0 {
                    msg2s.push(i);
                }
                for i in com1 {
                    msg2s.push(i);
                }
                for i in wit0 {
                    msg2s.push(i);
                }
                for i in wit1 {
                    msg2s.push(i);
                }

                let p = lsb(input[i].clone().g_share.unwrap().f_label) != 0;

                let op = BinaryShare {
                    value1: p ^ y,
                    value2: p,
                };

                outputs.push(op);
            });
            send_to_party(setup, tag1, msgs, 2, relay).await?;
            send_to_party(setup, tag1, wr0msgs, 1, relay).await?;

            send_to_party(setup, tag2, msg2s, 2, relay).await?;
            Ok(outputs)
        }
        1 => {
            let r = rng.as_mut().unwrap();

            let msg1s: Vec<Vec<u8>> =
                receive_from_parties(setup, tag1, BLOCK_SIZE * batch_size, vec![0], relay).await?;

            let mut outputs = Vec::new();
            let mut msgs = Vec::new();
            let mut wr0s = Vec::new();
            let mut wz0s = Vec::new();
            let mut wz1s = Vec::new();

            (0..batch_size).for_each(|i| {
                let mut wr0 = Block::default();
                wr0.copy_from_slice(&msg1s[0][BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)]);
                let (com0, com1, wz0, wz1, _, _) =
                    create_yao_to_binary_msg2(&wr0, comm, r, &input[i].clone().g_share.unwrap());

                for i in com0 {
                    msgs.push(i);
                }
                for i in com1 {
                    msgs.push(i);
                }
                wr0s.push(wr0);
                wz0s.push(wz0);
                wz1s.push(wz1);
            });
            send_to_party(setup, tag4, msgs, 2, relay).await?;

            let msg2s: Vec<Vec<u8>> =
                receive_from_parties(setup, tag3, BLOCK_SIZE * batch_size, vec![2], relay).await?;

            for i in 0..batch_size {
                let mut wxz = Block::default();
                wxz.copy_from_slice(&msg2s[0][BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)]);

                let val1 = wxz == wz0s[i];
                let val2 = wxz == wz1s[i];

                assert!(val1 || val2);

                let pz = (lsb(wxz) ^ lsb(wr0s[i])) != 0;
                let p = lsb(input[i].clone().g_share.unwrap().f_label) != 0;
                let op = BinaryShare {
                    value1: pz ^ p,
                    value2: pz,
                };
                outputs.push(op)
            }
            Ok(outputs)
        }
        _ => {
            let msg1s: Vec<Vec<u8>> =
                receive_from_parties(setup, tag1, (BLOCK_SIZE + 1) * batch_size, vec![0], relay)
                    .await?;

            let mut wxzs = Vec::new();
            let mut outputs = Vec::new();
            let mut ys = Vec::new();
            let mut wxzs_store = Vec::new();

            (0..batch_size).for_each(|i| {
                let mut wyr = Block::default();
                wyr.copy_from_slice(
                    &msg1s[0][(BLOCK_SIZE + 1) * i..((BLOCK_SIZE + 1) * i + BLOCK_SIZE)],
                );
                let y = msg1s[0][(BLOCK_SIZE + 1) * i + BLOCK_SIZE] != 0;
                let yaoshare = input[i].e_share.clone().unwrap();
                let wxz = xor_blocks(yaoshare.label, wyr);
                for i in wxz {
                    wxzs.push(i);
                }
                wxzs_store.push(wxz);
                ys.push(y);
            });

            send_to_party(setup, tag3, wxzs, 1, relay).await?;

            let msg2s_0: Vec<Vec<u8>> =
                receive_from_parties(setup, tag2, BLOCK_SIZE * 4 * batch_size, vec![0], relay)
                    .await?;

            let msg2s_1: Vec<Vec<u8>> =
                receive_from_parties(setup, tag4, BLOCK_SIZE * 2 * batch_size, vec![1], relay)
                    .await?;

            for i in 0..batch_size {
                let yaoshare = input[i].e_share.clone().unwrap();

                let mut com0 = Block::default();
                let mut com1 = Block::default();
                let mut com01 = Block::default();
                let mut com11 = Block::default();
                let mut wit0 = Block::default();
                let mut wit1 = Block::default();

                com0.copy_from_slice(
                    &msg2s_0[0][BLOCK_SIZE * 4 * i..(BLOCK_SIZE * 4 * i + BLOCK_SIZE)],
                );
                com1.copy_from_slice(
                    &msg2s_0[0]
                        [(BLOCK_SIZE * 4 * i + BLOCK_SIZE)..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)],
                );
                com01.copy_from_slice(
                    &msg2s_1[0][BLOCK_SIZE * 2 * i..(BLOCK_SIZE * 2 * i + BLOCK_SIZE)],
                );
                com11.copy_from_slice(
                    &msg2s_1[0]
                        [(BLOCK_SIZE * 2 * i + BLOCK_SIZE)..(BLOCK_SIZE * 2 * i + BLOCK_SIZE * 2)],
                );
                wit0.copy_from_slice(
                    &msg2s_0[0][(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)
                        ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)],
                );
                wit1.copy_from_slice(
                    &msg2s_0[0][(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)
                        ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 4)],
                );

                assert_eq!(com0, com01);
                assert_eq!(com1, com11);

                let px = lsb(yaoshare.label) != 0;
                if px ^ ys[i] {
                    assert!(comm.verify(wxzs_store[i], wit1, com1))
                } else {
                    assert!(comm.verify(wxzs_store[i], wit0, com0))
                }

                let pz = px ^ ys[i];
                let op = BinaryShare {
                    value1: ys[i] ^ pz,
                    value2: ys[i],
                };
                outputs.push(op)
            }
            Ok(outputs)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    /// OPEN_MSG
    pub const OPEN_MSG: u32 = 3;
    use merlin::Transcript;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sl_compute_common::{Binary, BinaryShare, ServerState};
    use sl_messages::{
        message::MessageTag,
        relay::{MessageRelayService, Relay, SimpleMessageRelay},
    };
    use tokio::task::JoinSet;

    use crate::{
        circuitop::circuit::BinaryCircuit,
        functionality::{
            circuit_eval::yao_circuit_eval_functionality,
            input::batch_input_yao_functionality,
            output::validate_yao_share,
            setup::setup_yao_functionality,
            utils::{p2p_send_to_next_receive_from_prev, run_common_randomness, FilteredMsgRelay},
            utils_dep::{ProtocolError, ProtocolParticipant, SetupMessage, TagOffsetCounter},
        },
        utilities::{
            commitments::HashCommitment, garble_hash::AesGarbleHash, shahash::Sha512Hash,
            utils::bool_vec_to_hex,
        },
    };

    use super::{batch_yao_to_binary_functionality, yao_to_binary_functionality};

    async fn test_run_y_to_b<T, R>(setup: T, relay: R) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut init_seed = [0u8; 32];
        let common_randomness_seed = [setup.participant_index() as u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);

        let mut tag_offset_counter = TagOffsetCounter::new();

        let common_randomness =
            run_common_randomness(&setup, &common_randomness_seed, &mut relay).await?;

        let mut serverstate = ServerState::new(common_randomness);

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

        let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();

        for x in 0..2 {
            for y in 0..2 {
                let key = vec![x != 0; 128];
                let msg = vec![y != 0; 128];

                let mut joint = [false; 256];
                joint[0..128].copy_from_slice(&key);
                joint[128..256].copy_from_slice(&msg);

                let jointsh = batch_input_yao_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &joint,
                    &mut rng,
                    &yao_setup,
                )
                .await?;

                for i in jointsh.clone() {
                    let val =
                        validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &i).await?;
                    assert!(val);
                }

                let mut keysh = HashMap::new();
                let mut msgsh = HashMap::new();

                for (i, ind) in circuit.garbler_input_ids.iter().enumerate() {
                    keysh.insert(i, jointsh[*ind].clone());
                }
                for (i, ind) in circuit.evaluator_input_ids.iter().enumerate() {
                    msgsh.insert(i, jointsh[128 + ind].clone());
                }

                let output = yao_circuit_eval_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &keysh,
                    &msgsh,
                    &circuit,
                    &mut rng,
                    &hash,
                    &yao_setup,
                )
                .await?;

                let mut out_yao = vec![];
                for id in &circuit.output_gate_ids {
                    out_yao.push(output.get(id).unwrap().clone());
                }

                let mut out_bin = vec![];
                for i in &out_yao {
                    let val =
                        validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, i).await?;
                    assert!(val);
                    let temp = yao_to_binary_functionality(
                        &setup,
                        &mut tag_offset_counter,
                        &mut relay,
                        i,
                        &mut rng,
                        &comm,
                        &yao_setup,
                    )
                    .await?;
                    out_bin.push(temp);
                }

                let act_out = run_batch_open_binary_share(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &out_bin,
                    &mut serverstate,
                )
                .await?;

                let count = 2 * x + y;

                if count == 0 {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "74d42c539a5f3211dc3451f72bd29766".to_string()
                    );
                } else if count == 1 {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "7266b17c4be2ce5f505aa1579331dafc".to_string()
                    );
                } else if count == 2 {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "3493fd1ca2122691b3fabee131a46f85".to_string()
                    );
                } else {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string()
                    );
                }
            }
        }

        let op = vec![];
        Ok((setup.participant_index(), op))
    }

    /// Run batch Open Binary Share protocol
    pub async fn run_batch_open_binary_share<T, R>(
        setup: &T,
        tag_offset_counter: &mut TagOffsetCounter,
        relay: &mut R,
        shares: &[BinaryShare],
        serverstate: &mut ServerState,
    ) -> Result<Vec<Binary>, ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut r = FilteredMsgRelay::new(relay);
        let tag_offset = tag_offset_counter.next_value();
        r.ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
            .await?;

        let msg: Vec<u8> = shares.iter().map(|share| share.value1 as u8).collect();

        let msg_from_prev = p2p_send_to_next_receive_from_prev(
            setup,
            MessageTag::tag1(OPEN_MSG, tag_offset),
            msg,
            &mut r,
        )
        .await?;

        let output: Vec<bool> = shares
            .iter()
            .zip(msg_from_prev.iter())
            .map(|(share, v)| share.value2 ^ (*v == 1u8))
            .collect();

        // add to UnverifiedList
        for v in output.iter() {
            serverstate.unverified_list.push(*v);
        }
        // serverstate.unverified_list.append_bytes_with_padding(&vec_bool_to_vec_bytes(&output));

        Ok(output)
    }

    async fn batch_test_run_y_to_b<T, R>(
        setup: T,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut init_seed = [0u8; 32];
        let common_randomness_seed = [setup.participant_index() as u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);

        let mut tag_offset_counter = TagOffsetCounter::new();

        let common_randomness =
            run_common_randomness(&setup, &common_randomness_seed, &mut relay).await?;

        let mut serverstate = ServerState::new(common_randomness);

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

        let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();

        for x in 0..2 {
            for y in 0..2 {
                let key = vec![x != 0; 128];
                let msg = vec![y != 0; 128];

                let mut joint = [false; 256];
                joint[0..128].copy_from_slice(&key);
                joint[128..256].copy_from_slice(&msg);

                let jointsh = batch_input_yao_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &joint,
                    &mut rng,
                    &yao_setup,
                )
                .await?;

                for i in jointsh.clone() {
                    let val =
                        validate_yao_share(&setup, &mut tag_offset_counter, &mut relay, &i).await?;
                    assert!(val);
                }

                let mut keysh = HashMap::new();
                let mut msgsh = HashMap::new();

                for (i, ind) in circuit.garbler_input_ids.iter().enumerate() {
                    keysh.insert(i, jointsh[*ind].clone());
                }
                for (i, ind) in circuit.evaluator_input_ids.iter().enumerate() {
                    msgsh.insert(i, jointsh[128 + ind].clone());
                }

                let output = yao_circuit_eval_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &keysh,
                    &msgsh,
                    &circuit,
                    &mut rng,
                    &hash,
                    &yao_setup,
                )
                .await?;

                let mut out_yao = vec![];
                for id in &circuit.output_gate_ids {
                    out_yao.push(output.get(id).unwrap().clone());
                }

                let out_bin = batch_yao_to_binary_functionality(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &out_yao,
                    &mut rng,
                    &comm,
                    &yao_setup,
                )
                .await?;

                let act_out = run_batch_open_binary_share(
                    &setup,
                    &mut tag_offset_counter,
                    &mut relay,
                    &out_bin,
                    &mut serverstate,
                )
                .await?;

                let count = 2 * x + y;

                if count == 0 {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "74d42c539a5f3211dc3451f72bd29766".to_string()
                    );
                } else if count == 1 {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "7266b17c4be2ce5f505aa1579331dafc".to_string()
                    );
                } else if count == 2 {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "3493fd1ca2122691b3fabee131a46f85".to_string()
                    );
                } else {
                    assert_eq!(
                        bool_vec_to_hex(act_out),
                        "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string()
                    );
                }
            }
        }

        let op = vec![];
        Ok((setup.participant_index(), op))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn setup_y_to_b(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
        use sha2::{Digest, Sha256};
        use sl_messages::message::InstanceId;
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

    async fn sim_y_to_b<S, R>(coord: S, batch: bool) -> Vec<Vec<bool>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_y_to_b(None);
        sim_parties_y_to_b(parties, coord, batch).await
    }

    async fn sim_parties_y_to_b<S, R>(
        parties: Vec<(SetupMessage, [u8; 32])>,
        coord: S,
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
                jset.spawn(batch_test_run_y_to_b(setup, relay));
            } else {
                jset.spawn(test_run_y_to_b(setup, relay));
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
    async fn test_y_to_b() {
        let batch = true;
        let _ = sim_y_to_b(SimpleMessageRelay::new(), !batch).await;
        let _ = sim_y_to_b(SimpleMessageRelay::new(), batch).await;
    }
}
