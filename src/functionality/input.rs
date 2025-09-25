use std::{collections::HashMap, vec};

use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};
use sl_compute_common::BinaryString;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    circuitop::circuit_builder::CircuitBuilder,
    config::constants::{
        INPUT_YAO_FROM_ALL_MSG1, INPUT_YAO_FROM_ALL_MSG2, INPUT_YAO_FROM_ALL_MSG3,
        INPUT_YAO_FROM_FUNC_MSG1, INPUT_YAO_FROM_FUNC_MSG2, INPUT_YAO_FUNC_MSG1,
    },
    functionality::{
        evaluate::evaluate_functionality,
        utils::{receive_from_parties, send_to_party, FilteredMsgRelay, Wrap},
        utils_dep::{ProtocolError, ProtocolParticipant, TagOffsetCounter},
    },
    utilities::{
        commitments::Commitment,
        hash_function::HashFunction,
        types::{
            block_vec2tblock_vec, tblock_vec2block_vec, Block, GarblerSetup, TBlock,
            YaoEvaluatorShare, YaoGarblerShare, YaoSetup, YaoShare, BLOCK_SIZE,
        },
        utils::xor_blocks,
    },
};

use super::garble::garble_functionality;

fn input_yao_functionality_create_msg1<G>(
    rng: &mut G,
    input: &bool,
    yao_setup: &GarblerSetup,
) -> (Block, YaoGarblerShare)
where
    G: RngCore + CryptoRng,
{
    let mut w0 = Block::default();
    rng.fill_bytes(&mut w0);

    let wi = if *input {
        xor_blocks(w0, yao_setup.delta)
    } else {
        w0
    };

    (
        wi,
        YaoGarblerShare {
            delta: yao_setup.delta,
            f_label: w0,
        },
    )
}

pub async fn input_yao_functionality<T, R, G>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &bool,
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let mut r = FilteredMsgRelay::new(relay);
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let output = input_yao_functionality_inner(setup, &mut r, input, rng, yao_setup, tag1).await?;
    Ok(output)
}

pub async fn input_yao_functionality_inner<T, R, G>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &bool,
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let party_id = setup.participant_index();

    let output: YaoShare;

    if party_id == 0 || party_id == 1 {
        assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
        let r = rng.as_mut().unwrap();
        let (msg1, share) =
            input_yao_functionality_create_msg1(r, input, &yao_setup.g_setup.clone().unwrap());

        send_to_party(setup, tag1, msg1, 2, relay).await?;

        output = YaoShare {
            g_share: Some(share),
            e_share: None,
        }
    } else {
        let msg1s: Vec<Block> = receive_from_parties(
            setup,
            tag1,
            Block::default().external_size(),
            vec![0, 1],
            relay,
        )
        .await?;

        let msg1_p1 = msg1s[0];
        let msg1_p2 = msg1s[1];

        assert_eq!(msg1_p1, msg1_p2);

        output = YaoShare {
            g_share: None,
            e_share: Some(YaoEvaluatorShare { label: msg1_p1 }),
        };
    }
    Ok(output)
}

pub async fn batch_input_yao_functionality<T, R, G>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &[bool],
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let mut r = FilteredMsgRelay::new(relay);
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let output =
        batch_input_yao_functionality_inner(setup, &mut r, input, rng, yao_setup, tag1).await?;
    Ok(output)
}

pub async fn batch_input_yao_functionality_inner<T, R, G>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[bool],
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let batch_len = input.len();
    let party_id = setup.participant_index();

    let mut output = vec![YaoShare::default(); batch_len];

    if party_id == 0 || party_id == 1 {
        assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
        let r = rng.as_mut().unwrap();

        let mut msg1 = vec![0u8; BLOCK_SIZE * batch_len];

        for i in 0..batch_len {
            let (msg1t, share) = input_yao_functionality_create_msg1(
                r,
                &input[i],
                &yao_setup.g_setup.clone().unwrap(),
            );

            msg1[BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)].copy_from_slice(&msg1t);

            output[i] = YaoShare {
                g_share: Some(share),
                e_share: None,
            }
        }

        send_to_party(setup, tag1, msg1, 2, relay).await?;
    } else {
        let msg1s: Vec<Vec<u8>> = receive_from_parties(
            setup,
            tag1,
            batch_len * Block::default().external_size(),
            vec![0, 1],
            relay,
        )
        .await?;

        let msg1_p1 = msg1s[0].clone();
        let msg1_p2 = msg1s[1].clone();

        assert_eq!(msg1_p1, msg1_p2);

        for i in 0..batch_len {
            let mut label = Block::default();
            label.copy_from_slice(&msg1_p1[BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)]);
            output[i] = YaoShare {
                g_share: None,
                e_share: Some(YaoEvaluatorShare { label }),
            };
        }
    }
    Ok(output)
}

fn input_yao_from_functionality_12_create_msg1<C, G>(
    comm: &C,
    rng: &mut G,
    yao_setup: &GarblerSetup,
) -> (Block, Block, (Block, Block), (Block, Block), bool)
where
    G: RngCore + CryptoRng,
    C: Commitment,
{
    let b = rng.next_u32() % 2 == 0;
    let mut w0 = Block::default();
    rng.fill_bytes(&mut w0);

    let mut witness_0 = Block::default();
    rng.fill_bytes(&mut witness_0);

    let mut witness_1 = Block::default();
    rng.fill_bytes(&mut witness_1);

    // a = 0 => c0 = Com(Wb) => c0 = w0 if b=0 and w1 if b=1 => c0 = if not b {w0} else {w1}
    // a = 1 => c1 = Com(W!b) => c1 = w1 if b=0 and w0 if b=0 => c1 = if not b {w1} else {w0}
    let comm_0 = if !b {
        comm.commit(w0, witness_0)
    } else {
        comm.commit(xor_blocks(w0, yao_setup.delta), witness_1)
    };
    let comm_1 = if b {
        comm.commit(w0, witness_0)
    } else {
        comm.commit(xor_blocks(w0, yao_setup.delta), witness_1)
    };

    (
        comm_0,
        comm_1,
        (w0, witness_0),
        (xor_blocks(w0, yao_setup.delta), witness_1),
        b,
    )
}

fn input_yao_from_functionality_3_create_msg1(input: &bool) -> (bool, bool) {
    let mut rng = StdRng::from_entropy();
    let x1 = rng.gen_bool(0.5);
    let x2 = x1 ^ input;
    (x1, x2)
}

fn input_yao_from_functionality_3_create_msg2<C, G>(
    comm: &C,
    rng: &mut G,
    yao_setup: &GarblerSetup,
) -> [Block; 10]
where
    G: RngCore + CryptoRng,
    C: Commitment,
{
    let mut w01 = Block::default();
    rng.fill_bytes(&mut w01);

    let mut w02 = Block::default();
    rng.fill_bytes(&mut w02);

    let mut witness1f = Block::default();
    rng.fill_bytes(&mut witness1f);
    let comm1f = comm.commit(w01, witness1f);

    let mut witness1t = Block::default();
    rng.fill_bytes(&mut witness1t);
    let comm1t = comm.commit(xor_blocks(yao_setup.delta, w01), witness1t);

    let mut witness2f = Block::default();
    rng.fill_bytes(&mut witness2f);
    let comm2f = comm.commit(w02, witness2f);

    let mut witness2t = Block::default();
    rng.fill_bytes(&mut witness2t);
    let comm2t = comm.commit(xor_blocks(yao_setup.delta, w02), witness2t);

    [
        comm1f, comm1t, comm2f, comm2t, w01, w02, witness1f, witness1t, witness2f, witness2t,
    ]
}

#[allow(clippy::too_many_arguments)]
pub async fn input_yao_from_functionality<T, C, R, G, H>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &Option<bool>,
    pid: usize,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let mut r = FilteredMsgRelay::new(relay);
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG1.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG2.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag2, true).await?;

    let output = input_yao_from_functionality_inner(
        setup, &mut r, input, pid, rng, hash, comm, yao_setup, tag1, tag2,
    )
    .await?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn input_yao_from_functionality_inner<T, C, R, G, H>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &Option<bool>,
    pid: usize,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let output;
    let party_id = setup.participant_index();

    let mut builder = CircuitBuilder::new();
    let x1 = builder.garbler_input();
    let x2 = builder.evaluator_input();
    let out = builder.xor(x1, x2);
    builder.output(out);
    let circuit = builder.finish();

    if pid == 0 || pid == 1 {
        if party_id == 0 || party_id == 1 {
            assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
            let r = rng.as_mut().unwrap();
            let (com0, com1, (w0, wit0), (w1, wit1), _b) =
                input_yao_from_functionality_12_create_msg1(
                    comm,
                    r,
                    &yao_setup.g_setup.clone().unwrap(),
                );

            let mut send = vec![0u8; BLOCK_SIZE * 4];
            send[0..BLOCK_SIZE].copy_from_slice(&com0);
            send[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&com1);

            if party_id == pid {
                if input.unwrap() {
                    send[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&w1);
                    send[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&wit1);
                } else {
                    send[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&w0);
                    send[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&wit0);
                }
            }

            send_to_party(setup, tag1, send, 2, relay).await?;

            output = YaoShare {
                g_share: Some(YaoGarblerShare {
                    delta: yao_setup.g_setup.clone().unwrap().delta,
                    f_label: w0,
                }),
                e_share: None,
            };
        } else {
            let com_decom: Vec<[u8; BLOCK_SIZE * 4]> = receive_from_parties(
                setup,
                tag1,
                4 * Block::default().external_size(),
                vec![0, 1],
                relay,
            )
            .await?;
            let mut coms_0 = [0u8; BLOCK_SIZE * 2];
            coms_0.copy_from_slice(&com_decom[0][0..BLOCK_SIZE * 2]);
            let mut coms_1 = [0u8; BLOCK_SIZE * 2];
            coms_1.copy_from_slice(&com_decom[1][0..BLOCK_SIZE * 2]);
            assert_eq!(coms_0, coms_1);

            let mut com0 = Block::default();
            com0.copy_from_slice(&coms_0[0..BLOCK_SIZE]);
            let mut com1 = Block::default();
            com1.copy_from_slice(&coms_0[BLOCK_SIZE..BLOCK_SIZE * 2]);

            let mut msg = Block::default();
            msg.copy_from_slice(&com_decom[pid][BLOCK_SIZE * 2..BLOCK_SIZE * 3]);
            let mut wit = Block::default();
            wit.copy_from_slice(&com_decom[pid][BLOCK_SIZE * 3..BLOCK_SIZE * 4]);

            let v1 = comm.verify(msg, wit, com0);
            let v2 = comm.verify(msg, wit, com1);

            assert!(v1 || v2);
            assert!(!(v1 && v2));

            output = YaoShare {
                g_share: None,
                e_share: Some(YaoEvaluatorShare { label: msg }),
            }
        }
    } else if party_id == 2 {
        let (x1, x2) = input_yao_from_functionality_3_create_msg1(&input.unwrap());
        let mut val1: u8 = 0;
        let mut val2: u8 = 0;
        if x1 {
            val1 += 1;
        }
        if x2 {
            val2 += 1;
        }
        send_to_party(setup, tag1, val1, 0, relay).await?;
        send_to_party(setup, tag1, val2, 1, relay).await?;

        let msg: Vec<[u8; 6 * BLOCK_SIZE]> =
            receive_from_parties(setup, tag2, 6 * BLOCK_SIZE, vec![0, 1], relay).await?;

        let mut allcoms_p1 = [0u8; 4 * BLOCK_SIZE];
        allcoms_p1.copy_from_slice(&msg[0][0..4 * BLOCK_SIZE]);
        let mut allcoms_p2 = [0u8; 4 * BLOCK_SIZE];
        allcoms_p2.copy_from_slice(&msg[1][0..4 * BLOCK_SIZE]);
        assert_eq!(allcoms_p2, allcoms_p1);

        let mut com_1f = Block::default();
        com_1f.copy_from_slice(&msg[0][0..BLOCK_SIZE]);

        let mut com_1t = Block::default();
        com_1t.copy_from_slice(&msg[0][BLOCK_SIZE..BLOCK_SIZE * 2]);

        let mut com_2f = Block::default();
        com_2f.copy_from_slice(&msg[0][BLOCK_SIZE * 2..BLOCK_SIZE * 3]);

        let mut com_2t = Block::default();
        com_2t.copy_from_slice(&msg[0][BLOCK_SIZE * 3..BLOCK_SIZE * 4]);

        let mut label_1 = Block::default();
        label_1.copy_from_slice(&msg[0][BLOCK_SIZE * 4..BLOCK_SIZE * 5]);

        let mut label_2 = Block::default();
        label_2.copy_from_slice(&msg[1][BLOCK_SIZE * 4..BLOCK_SIZE * 5]);

        let mut witness_1 = Block::default();
        witness_1.copy_from_slice(&msg[0][BLOCK_SIZE * 5..BLOCK_SIZE * 6]);

        let mut witness_2 = Block::default();
        witness_2.copy_from_slice(&msg[1][BLOCK_SIZE * 5..BLOCK_SIZE * 6]);

        if x1 {
            assert!(comm.verify(label_1, witness_1, com_1t));
        } else {
            assert!(comm.verify(label_1, witness_1, com_1f));
        }
        if x2 {
            assert!(comm.verify(label_2, witness_2, com_2t));
        } else {
            assert!(comm.verify(label_2, witness_2, com_2f));
        }
        let mut gin = HashMap::new();
        gin.insert(
            circuit.garbler_input_ids[0],
            YaoEvaluatorShare { label: label_1 },
        );

        let mut ein = HashMap::new();
        ein.insert(
            circuit.evaluator_input_ids[0],
            YaoEvaluatorShare { label: label_2 },
        );
        let outmap = evaluate_functionality(&circuit, &gin, &ein, &[], hash);

        output = YaoShare {
            g_share: None,
            e_share: Some(outmap.get(&circuit.output_gate_ids[0]).unwrap().clone()),
        }
    } else {
        let xs: Vec<u8> = receive_from_parties(setup, tag1, 1, vec![2], relay).await?;
        let x_val = xs[0] % 2 == 1;

        let ysetup: GarblerSetup = yao_setup.g_setup.clone().unwrap();

        let rngval = rng.as_mut().unwrap();

        let msg2vals = input_yao_from_functionality_3_create_msg2(comm, rngval, &ysetup);

        let mut msg = [0u8; 6 * BLOCK_SIZE];

        msg[0..BLOCK_SIZE].copy_from_slice(&msg2vals[0]);
        msg[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&msg2vals[1]);
        msg[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&msg2vals[2]);
        msg[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&msg2vals[3]);

        let (label, wit) = if party_id == 0 {
            if x_val {
                (xor_blocks(msg2vals[4], ysetup.delta), msg2vals[7])
            } else {
                (msg2vals[4], msg2vals[6])
            }
        } else if x_val {
            (xor_blocks(msg2vals[5], ysetup.delta), msg2vals[9])
        } else {
            (msg2vals[5], msg2vals[8])
        };
        msg[BLOCK_SIZE * 4..BLOCK_SIZE * 5].copy_from_slice(&label);
        msg[BLOCK_SIZE * 5..BLOCK_SIZE * 6].copy_from_slice(&wit);

        send_to_party(setup, tag2, msg, 2, relay).await?;

        let mut gin = HashMap::new();
        gin.insert(
            circuit.garbler_input_ids[0],
            YaoGarblerShare {
                delta: ysetup.delta,
                f_label: msg2vals[4],
            },
        );

        let mut ein = HashMap::new();
        ein.insert(
            circuit.evaluator_input_ids[0],
            YaoGarblerShare {
                delta: ysetup.delta,
                f_label: msg2vals[5],
            },
        );

        let (_, outmap) = garble_functionality(&circuit, &gin, &ein, &ysetup, rngval, hash);

        output = YaoShare {
            g_share: Some(outmap.get(&circuit.output_gate_ids[0]).unwrap().clone()),
            e_share: None,
        };
    }

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn batch_input_yao_from_functionality<T, C, R, G, H>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &[Option<bool>],
    pid: usize,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let mut r = FilteredMsgRelay::new(relay);
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG1.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG2.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag2, true).await?;

    let output = batch_input_yao_from_functionality_inner(
        setup, &mut r, input, pid, rng, hash, comm, yao_setup, tag1, tag2,
    )
    .await?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn batch_input_yao_from_functionality_inner<T, C, R, G, H>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[Option<bool>],
    pid: usize,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
    yao_setup: &YaoSetup,
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let party_id = setup.participant_index();
    let batch_size = input.len();
    let mut output = vec![YaoShare::default(); batch_size];

    let mut builder = CircuitBuilder::new();
    let x1 = builder.garbler_input();
    let x2 = builder.evaluator_input();
    let out = builder.xor(x1, x2);
    builder.output(out);
    let circuit = builder.finish();

    if pid == 0 || pid == 1 {
        if party_id == 0 || party_id == 1 {
            assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
            let r = rng.as_mut().unwrap();
            let mut send = vec![0u8; batch_size * BLOCK_SIZE * 4];

            for i in 0..batch_size {
                let (com0, com1, (w0, wit0), (w1, wit1), _b) =
                    input_yao_from_functionality_12_create_msg1(
                        comm,
                        r,
                        &yao_setup.g_setup.clone().unwrap(),
                    );

                send[BLOCK_SIZE * 4 * i..(BLOCK_SIZE * 4 * i + BLOCK_SIZE)].copy_from_slice(&com0);
                send[(BLOCK_SIZE * 4 * i + BLOCK_SIZE)..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)]
                    .copy_from_slice(&com1);
                if party_id == pid {
                    if input[i].unwrap() {
                        send[(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)]
                            .copy_from_slice(&w1);
                        send[(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 4)]
                            .copy_from_slice(&wit1);
                    } else {
                        send[(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)]
                            .copy_from_slice(&w0);
                        send[(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 4)]
                            .copy_from_slice(&wit0);
                    }
                }
                output[i] = YaoShare {
                    g_share: Some(YaoGarblerShare {
                        delta: yao_setup.g_setup.clone().unwrap().delta,
                        f_label: w0,
                    }),
                    e_share: None,
                };
            }

            send_to_party(setup, tag1, send, 2, relay).await?;
        } else {
            let com_decom: Vec<Vec<u8>> = receive_from_parties(
                setup,
                tag1,
                batch_size * 4 * Block::default().external_size(),
                vec![0, 1],
                relay,
            )
            .await?;

            (0..batch_size).for_each(|i| {
                let mut coms_0 = [0u8; BLOCK_SIZE * 2];
                coms_0.copy_from_slice(
                    &com_decom[0][BLOCK_SIZE * 4 * i..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)],
                );
                let mut coms_1 = [0u8; BLOCK_SIZE * 2];
                coms_1.copy_from_slice(
                    &com_decom[1][BLOCK_SIZE * 4 * i..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)],
                );
                assert_eq!(coms_0, coms_1);

                let mut com0 = Block::default();
                com0.copy_from_slice(&coms_0[0..BLOCK_SIZE]);
                let mut com1 = Block::default();
                com1.copy_from_slice(&coms_0[BLOCK_SIZE..BLOCK_SIZE * 2]);

                let mut msg = Block::default();
                msg.copy_from_slice(
                    &com_decom[pid][(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)
                        ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)],
                );
                let mut wit = Block::default();
                wit.copy_from_slice(
                    &com_decom[pid][(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)
                        ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 4)],
                );

                let v1 = comm.verify(msg, wit, com0);
                let v2 = comm.verify(msg, wit, com1);

                assert!(v1 || v2);
                assert!(!(v1 && v2));

                output[i] = YaoShare {
                    g_share: None,
                    e_share: Some(YaoEvaluatorShare { label: msg }),
                }
            });
        }
    } else if party_id == 2 {
        let mut val1 = BinaryString::new();
        let mut val2 = BinaryString::new();
        (0..batch_size).for_each(|i| {
            let (x1, x2) = input_yao_from_functionality_3_create_msg1(&input[i].unwrap());
            val1.push(x1);
            val2.push(x2);
        });
        send_to_party(setup, tag1, val1.value.clone(), 0, relay).await?;
        send_to_party(setup, tag1, val2.value.clone(), 1, relay).await?;

        let msg: Vec<Vec<u8>> =
            receive_from_parties(setup, tag2, batch_size * 6 * BLOCK_SIZE, vec![0, 1], relay)
                .await?;

        (0..batch_size).for_each(|i| {
            let mut allcoms_p1 = [0u8; 4 * BLOCK_SIZE];
            allcoms_p1.copy_from_slice(
                &msg[0][6 * BLOCK_SIZE * i..(6 * BLOCK_SIZE * i + 4 * BLOCK_SIZE)],
            );
            let mut allcoms_p2 = [0u8; 4 * BLOCK_SIZE];
            allcoms_p2.copy_from_slice(
                &msg[1][6 * BLOCK_SIZE * i..(6 * BLOCK_SIZE * i + 4 * BLOCK_SIZE)],
            );
            assert_eq!(allcoms_p2, allcoms_p1);

            let mut com_1f = Block::default();
            com_1f.copy_from_slice(&msg[0][6 * BLOCK_SIZE * i..(6 * BLOCK_SIZE * i + BLOCK_SIZE)]);

            let mut com_1t = Block::default();
            com_1t.copy_from_slice(
                &msg[0][(6 * BLOCK_SIZE * i + BLOCK_SIZE)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 2)],
            );

            let mut com_2f = Block::default();
            com_2f.copy_from_slice(
                &msg[0]
                    [(6 * BLOCK_SIZE * i + BLOCK_SIZE * 2)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 3)],
            );

            let mut com_2t = Block::default();
            com_2t.copy_from_slice(
                &msg[0]
                    [(6 * BLOCK_SIZE * i + BLOCK_SIZE * 3)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 4)],
            );

            let mut label_1 = Block::default();
            label_1.copy_from_slice(
                &msg[0]
                    [(6 * BLOCK_SIZE * i + BLOCK_SIZE * 4)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 5)],
            );

            let mut label_2 = Block::default();
            label_2.copy_from_slice(
                &msg[1]
                    [(6 * BLOCK_SIZE * i + BLOCK_SIZE * 4)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 5)],
            );

            let mut witness_1 = Block::default();
            witness_1.copy_from_slice(
                &msg[0]
                    [(6 * BLOCK_SIZE * i + BLOCK_SIZE * 5)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 6)],
            );

            let mut witness_2 = Block::default();
            witness_2.copy_from_slice(
                &msg[1]
                    [(6 * BLOCK_SIZE * i + BLOCK_SIZE * 5)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 6)],
            );

            if val1.get(i) {
                assert!(comm.verify(label_1, witness_1, com_1t));
            } else {
                assert!(comm.verify(label_1, witness_1, com_1f));
            }
            if val2.get(i) {
                assert!(comm.verify(label_2, witness_2, com_2t));
            } else {
                assert!(comm.verify(label_2, witness_2, com_2f));
            }
            let mut gin = HashMap::new();
            gin.insert(
                circuit.garbler_input_ids[0],
                YaoEvaluatorShare { label: label_1 },
            );

            let mut ein = HashMap::new();
            ein.insert(
                circuit.evaluator_input_ids[0],
                YaoEvaluatorShare { label: label_2 },
            );
            let outmap = evaluate_functionality(&circuit, &gin, &ein, &[], hash);

            output[i] = YaoShare {
                g_share: None,
                e_share: Some(outmap.get(&circuit.output_gate_ids[0]).unwrap().clone()),
            }
        });
    } else {
        let mut recv = BinaryString::new();
        for _ in 0..batch_size {
            recv.push(false);
        }

        let xs: Vec<Vec<u8>> =
            receive_from_parties(setup, tag1, recv.value.len(), vec![2], relay).await?;

        recv.value = xs[0].clone();

        let mut msg = vec![0u8; batch_size * 6 * BLOCK_SIZE];

        for i in 0..batch_size {
            let x_val = recv.get(i);

            let ysetup: GarblerSetup = yao_setup.g_setup.clone().unwrap();

            let rngval = rng.as_mut().unwrap();

            let msg2vals = input_yao_from_functionality_3_create_msg2(comm, rngval, &ysetup);

            msg[6 * BLOCK_SIZE * i..(6 * BLOCK_SIZE * i + BLOCK_SIZE)]
                .copy_from_slice(&msg2vals[0]);
            msg[(6 * BLOCK_SIZE * i + BLOCK_SIZE)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 2)]
                .copy_from_slice(&msg2vals[1]);
            msg[(6 * BLOCK_SIZE * i + BLOCK_SIZE * 2)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 3)]
                .copy_from_slice(&msg2vals[2]);
            msg[(6 * BLOCK_SIZE * i + BLOCK_SIZE * 3)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 4)]
                .copy_from_slice(&msg2vals[3]);
            let (label, wit) = if party_id == 0 {
                if x_val {
                    (xor_blocks(msg2vals[4], ysetup.delta), msg2vals[7])
                } else {
                    (msg2vals[4], msg2vals[6])
                }
            } else if x_val {
                (xor_blocks(msg2vals[5], ysetup.delta), msg2vals[9])
            } else {
                (msg2vals[5], msg2vals[8])
            };
            msg[(6 * BLOCK_SIZE * i + BLOCK_SIZE * 4)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 5)]
                .copy_from_slice(&label);
            msg[(6 * BLOCK_SIZE * i + BLOCK_SIZE * 5)..(6 * BLOCK_SIZE * i + BLOCK_SIZE * 6)]
                .copy_from_slice(&wit);
            let mut gin = HashMap::new();
            gin.insert(
                circuit.garbler_input_ids[0],
                YaoGarblerShare {
                    delta: ysetup.delta,
                    f_label: msg2vals[4],
                },
            );

            let mut ein = HashMap::new();
            ein.insert(
                circuit.evaluator_input_ids[0],
                YaoGarblerShare {
                    delta: ysetup.delta,
                    f_label: msg2vals[5],
                },
            );

            let (_, outmap) = garble_functionality(&circuit, &gin, &ein, &ysetup, rngval, hash);

            output[i] = YaoShare {
                g_share: Some(outmap.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                e_share: None,
            };
        }

        send_to_party(setup, tag2, msg, 2, relay).await?;
    }

    Ok(output)
}

/// Msg1 for Input Yao from all protocol generated by garblers
#[derive(Debug)]
pub struct InputYaoAllMsg1p22 {
    com_i1_0: Vec<Block>,
    com_i2_0: Vec<Block>,
    com_i1_1: Vec<Block>,
    com_i2_1: Vec<Block>,
    w: Vec<Block>,
    wit: Vec<Block>,
}

impl InputYaoAllMsg1p22 {
    fn encode(&self) -> Vec<TBlock> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.com_i1_0);
        buffer.extend_from_slice(&self.com_i2_0);
        buffer.extend_from_slice(&self.com_i1_1);
        buffer.extend_from_slice(&self.com_i2_1);
        buffer.extend_from_slice(&self.w);
        buffer.extend_from_slice(&self.wit);

        block_vec2tblock_vec(&buffer)
    }

    fn decode(
        input: &[TBlock],
        input_p1_len: usize,
        input_p2_len: usize,
        from_party: usize,
    ) -> Self {
        let buffer = tblock_vec2block_vec(input);
        let mut com_i1_0 = vec![Block::default(); input_p1_len];
        let mut com_i2_0 = vec![Block::default(); input_p2_len];
        let mut com_i1_1 = vec![Block::default(); input_p1_len];
        let mut com_i2_1 = vec![Block::default(); input_p2_len];
        let (mut w, mut wit) = if from_party == 0 {
            (
                vec![Block::default(); input_p1_len],
                vec![Block::default(); input_p1_len],
            )
        } else {
            (
                vec![Block::default(); input_p2_len],
                vec![Block::default(); input_p2_len],
            )
        };

        let mut ids = 0;
        com_i1_0.copy_from_slice(&buffer[ids..ids + input_p1_len]);
        ids += input_p1_len;
        com_i2_0.copy_from_slice(&buffer[ids..ids + input_p2_len]);
        ids += input_p2_len;
        com_i1_1.copy_from_slice(&buffer[ids..ids + input_p1_len]);
        ids += input_p1_len;
        com_i2_1.copy_from_slice(&buffer[ids..ids + input_p2_len]);
        ids += input_p2_len;
        if from_party == 0 {
            w.copy_from_slice(&buffer[ids..ids + input_p1_len]);
            ids += input_p1_len;
            wit.copy_from_slice(&buffer[ids..ids + input_p1_len]);
        } else {
            w.copy_from_slice(&buffer[ids..ids + input_p2_len]);
            ids += input_p2_len;
            wit.copy_from_slice(&buffer[ids..ids + input_p2_len]);
        }

        Self {
            com_i1_0,
            com_i2_0,
            com_i1_1,
            com_i2_1,
            w,
            wit,
        }
    }
}

fn encode_vec_bool(input: Vec<bool>) -> Vec<u8> {
    let mut o = BinaryString::new();
    for i in input {
        o.push(i);
    }
    o.value
}

fn decode_vec_bool(input: Vec<u8>, length: usize) -> Vec<bool> {
    let x = BinaryString {
        length: length as u64,
        value: input,
    };
    let mut o = Vec::new();
    for j in 0..length {
        o.push(x.get(j));
    }
    o
}

fn input_yao_from_all_functionality_12_create_msg1<C, G>(
    comm: &C,
    rng: &mut G,
    yao_setup: &GarblerSetup,
    input: &[bool],
    i1_len: usize,
    i2_len: usize,
    party_id: usize,
) -> (
    InputYaoAllMsg1p22,
    Vec<YaoGarblerShare>,
    Vec<YaoGarblerShare>,
)
where
    G: RngCore + CryptoRng,
    C: Commitment,
{
    let mut com_i1_0: Vec<Block> = Vec::with_capacity(i1_len);
    let mut com_i2_0: Vec<Block> = Vec::with_capacity(i2_len);
    let mut com_i1_1: Vec<Block> = Vec::with_capacity(i1_len);
    let mut com_i2_1: Vec<Block> = Vec::with_capacity(i2_len);
    let mut w: Vec<Block> = Vec::new();
    let mut wit: Vec<Block> = Vec::new();
    let mut i1_shares = Vec::with_capacity(i1_len);
    let mut i2_shares = Vec::with_capacity(i2_len);
    (0..i1_len).for_each(|i| {
        let b = rng.next_u32() % 2 == 0;
        let mut w0 = Block::default();
        rng.fill_bytes(&mut w0);

        let mut witness_0 = Block::default();
        rng.fill_bytes(&mut witness_0);

        let mut witness_1 = Block::default();
        rng.fill_bytes(&mut witness_1);

        // a = 0 => c0 = Com(Wb) => c0 = w0 if b=0 and w1 if b=1 => c0 = if not b {w0} else {w1}
        // a = 1 => c1 = Com(W!b) => c1 = w1 if b=0 and w0 if b=0 => c1 = if not b {w1} else {w0}
        let comm_0 = if !b {
            comm.commit(w0, witness_0)
        } else {
            comm.commit(xor_blocks(w0, yao_setup.delta), witness_1)
        };
        let comm_1 = if b {
            comm.commit(w0, witness_0)
        } else {
            comm.commit(xor_blocks(w0, yao_setup.delta), witness_1)
        };

        com_i1_0.push(comm_0);
        com_i1_1.push(comm_1);
        i1_shares.push(YaoGarblerShare {
            delta: yao_setup.delta,
            f_label: w0,
        });

        if party_id == 1 {
            if input[i] {
                w.push(xor_blocks(w0, yao_setup.delta));
                wit.push(witness_1);
            } else {
                w.push(w0);
                wit.push(witness_0);
            }
        }
    });

    (0..i2_len).for_each(|i| {
        let b = rng.next_u32() % 2 == 0;
        let mut w0 = Block::default();
        rng.fill_bytes(&mut w0);

        let mut witness_0 = Block::default();
        rng.fill_bytes(&mut witness_0);

        let mut witness_1 = Block::default();
        rng.fill_bytes(&mut witness_1);

        // a = 0 => c0 = Com(Wb) => c0 = w0 if b=0 and w1 if b=1 => c0 = if not b {w0} else {w1}
        // a = 1 => c1 = Com(W!b) => c1 = w1 if b=0 and w0 if b=0 => c1 = if not b {w1} else {w0}
        let comm_0 = if !b {
            comm.commit(w0, witness_0)
        } else {
            comm.commit(xor_blocks(w0, yao_setup.delta), witness_1)
        };
        let comm_1 = if b {
            comm.commit(w0, witness_0)
        } else {
            comm.commit(xor_blocks(w0, yao_setup.delta), witness_1)
        };

        com_i2_0.push(comm_0);
        com_i2_1.push(comm_1);
        i2_shares.push(YaoGarblerShare {
            delta: yao_setup.delta,
            f_label: w0,
        });

        if party_id == 2 {
            if input[i] {
                w.push(xor_blocks(w0, yao_setup.delta));
                wit.push(witness_1);
            } else {
                w.push(w0);
                wit.push(witness_0);
            }
        }
    });

    (
        InputYaoAllMsg1p22 {
            com_i1_0,
            com_i2_0,
            com_i1_1,
            com_i2_1,
            w,
            wit,
        },
        i1_shares,
        i2_shares,
    )
}

/// Msg2 for Input Yao from all protocol generated by garblers
#[derive(Debug)]
pub struct InputYaoAllMsg2p22 {
    comm_1f: Vec<Block>,
    comm_1t: Vec<Block>,
    comm_2f: Vec<Block>,
    comm_2t: Vec<Block>,
    w: Vec<Block>,
    wit: Vec<Block>,
}

impl InputYaoAllMsg2p22 {
    fn encode(&self) -> Vec<TBlock> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.comm_1f);
        buffer.extend_from_slice(&self.comm_1t);
        buffer.extend_from_slice(&self.comm_2f);
        buffer.extend_from_slice(&self.comm_2t);
        buffer.extend_from_slice(&self.w);
        buffer.extend_from_slice(&self.wit);

        block_vec2tblock_vec(&buffer)
    }

    fn decode(input: &[TBlock], input_p3_len: usize) -> Self {
        let buffer = tblock_vec2block_vec(input);
        let mut comm_1f = vec![Block::default(); input_p3_len];
        let mut comm_1t = vec![Block::default(); input_p3_len];
        let mut comm_2f = vec![Block::default(); input_p3_len];
        let mut comm_2t = vec![Block::default(); input_p3_len];
        let mut w = vec![Block::default(); input_p3_len];
        let mut wit = vec![Block::default(); input_p3_len];

        let mut ids = 0;
        comm_1f.copy_from_slice(&buffer[ids..ids + input_p3_len]);
        ids += input_p3_len;
        comm_1t.copy_from_slice(&buffer[ids..ids + input_p3_len]);
        ids += input_p3_len;
        comm_2f.copy_from_slice(&buffer[ids..ids + input_p3_len]);
        ids += input_p3_len;
        comm_2t.copy_from_slice(&buffer[ids..ids + input_p3_len]);
        ids += input_p3_len;
        w.copy_from_slice(&buffer[ids..ids + input_p3_len]);
        ids += input_p3_len;
        wit.copy_from_slice(&buffer[ids..ids + input_p3_len]);

        Self {
            comm_1f,
            comm_1t,
            comm_2f,
            comm_2t,
            w,
            wit,
        }
    }
}

fn input_yao_from_all_functionality_12_create_msg2<C, G>(
    comm: &C,
    rng: &mut G,
    i3_len: usize,
    msg1_recv: &[bool],
    party_id: usize,
    yao_setup: &GarblerSetup,
) -> (InputYaoAllMsg2p22, Vec<YaoGarblerShare>)
where
    G: RngCore + CryptoRng,
    C: Commitment,
{
    let mut i3_shares = Vec::new();
    let mut comm_1f = Vec::with_capacity(i3_len);
    let mut comm_1t = Vec::with_capacity(i3_len);
    let mut comm_2f = Vec::with_capacity(i3_len);
    let mut comm_2t = Vec::with_capacity(i3_len);
    let mut w = Vec::with_capacity(i3_len);
    let mut wit = Vec::with_capacity(i3_len);

    (0..i3_len).for_each(|i| {
        let mut w01 = Block::default();
        rng.fill_bytes(&mut w01);

        let mut w02 = Block::default();
        rng.fill_bytes(&mut w02);

        let mut witness1f = Block::default();
        rng.fill_bytes(&mut witness1f);
        let comm1f = comm.commit(w01, witness1f);

        let mut witness1t = Block::default();
        rng.fill_bytes(&mut witness1t);
        let comm1t = comm.commit(xor_blocks(yao_setup.delta, w01), witness1t);

        let mut witness2f = Block::default();
        rng.fill_bytes(&mut witness2f);
        let comm2f = comm.commit(w02, witness2f);

        let mut witness2t = Block::default();
        rng.fill_bytes(&mut witness2t);
        let comm2t = comm.commit(xor_blocks(yao_setup.delta, w02), witness2t);

        let (msg, witness) = if party_id == 1 {
            if msg1_recv[i] {
                (xor_blocks(w01, yao_setup.delta), witness1t)
            } else {
                (w01, witness1f)
            }
        } else if msg1_recv[i] {
            (xor_blocks(w02, yao_setup.delta), witness2t)
        } else {
            (w02, witness2f)
        };

        i3_shares.push(YaoGarblerShare {
            delta: yao_setup.delta,
            f_label: xor_blocks(w01, w02),
        });
        comm_1f.push(comm1f);
        comm_1t.push(comm1t);
        comm_2f.push(comm2f);
        comm_2t.push(comm2t);
        w.push(msg);
        wit.push(witness);
    });

    (
        InputYaoAllMsg2p22 {
            comm_1f,
            comm_1t,
            comm_2f,
            comm_2t,
            w,
            wit,
        },
        i3_shares,
    )
}

fn input_yao_from_all_functionality_3_create_msg1(input: &[bool]) -> (Vec<bool>, Vec<bool>) {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut x1vals = Vec::with_capacity(input.len());
    let mut x2vals = Vec::with_capacity(input.len());
    (0..input.len()).for_each(|i| {
        let x1 = rng.gen_bool(0.5);
        let x2 = x1 ^ input[i];
        x1vals.push(x1);
        x2vals.push(x2);
    });
    (x1vals, x2vals)
}

fn input_yao_from_all_functionality_3_process_msg1<C>(
    comm: &C,
    msg1_recv_p2: &InputYaoAllMsg1p22,
    msg1_recv_p3: &InputYaoAllMsg1p22,
) -> (Vec<YaoEvaluatorShare>, Vec<YaoEvaluatorShare>)
where
    C: Commitment,
{
    assert_eq!(msg1_recv_p2.com_i1_0, msg1_recv_p3.com_i1_0);
    assert_eq!(msg1_recv_p2.com_i1_1, msg1_recv_p3.com_i1_1);
    assert_eq!(msg1_recv_p2.com_i2_0, msg1_recv_p3.com_i2_0);
    assert_eq!(msg1_recv_p2.com_i2_1, msg1_recv_p3.com_i2_1);

    let mut i1_shares = Vec::new();
    let mut i2_shares = Vec::new();

    for (((com0, com1), msg), wit) in msg1_recv_p2
        .com_i1_0
        .iter()
        .zip(&msg1_recv_p2.com_i1_1)
        .zip(&msg1_recv_p2.w)
        .zip(&msg1_recv_p2.wit)
    {
        let v1 = comm.verify(*msg, *wit, *com0);
        let v2 = comm.verify(*msg, *wit, *com1);

        assert!(v1 || v2);
        assert!(!(v1 && v2));

        i1_shares.push(YaoEvaluatorShare { label: *msg });
    }

    for (((com0, com1), msg), wit) in msg1_recv_p2
        .com_i2_0
        .iter()
        .zip(&msg1_recv_p2.com_i2_1)
        .zip(&msg1_recv_p3.w)
        .zip(&msg1_recv_p3.wit)
    {
        let v1 = comm.verify(*msg, *wit, *com0);
        let v2 = comm.verify(*msg, *wit, *com1);

        assert!(v1 || v2);
        assert!(!(v1 && v2));

        i2_shares.push(YaoEvaluatorShare { label: *msg });
    }

    (i1_shares, i2_shares)
}

fn input_yao_from_all_functionality_3_process_msg2<C>(
    comm: &C,
    msg2_recv_p2: &InputYaoAllMsg2p22,
    msg2_recv_p3: &InputYaoAllMsg2p22,
    i3_len: usize,
    msg1_p2: &[bool],
    msg1_p3: &[bool],
) -> Vec<YaoEvaluatorShare>
where
    C: Commitment,
{
    assert_eq!(msg2_recv_p2.comm_1f, msg2_recv_p3.comm_1f);
    assert_eq!(msg2_recv_p2.comm_1t, msg2_recv_p3.comm_1t);
    assert_eq!(msg2_recv_p2.comm_2f, msg2_recv_p3.comm_2f);
    assert_eq!(msg2_recv_p2.comm_2t, msg2_recv_p3.comm_2t);

    let mut i3_shares = Vec::new();

    for i in 0..i3_len {
        let com_1f = msg2_recv_p2.comm_1f[i];
        let com_1t = msg2_recv_p2.comm_1t[i];
        let com_2f = msg2_recv_p2.comm_2f[i];
        let com_2t = msg2_recv_p2.comm_2t[i];

        let label_1 = msg2_recv_p2.w[i];
        let label_2 = msg2_recv_p3.w[i];
        let witness_1 = msg2_recv_p2.wit[i];
        let witness_2 = msg2_recv_p3.wit[i];

        if msg1_p2[i] {
            assert!(comm.verify(label_1, witness_1, com_1t));
        } else {
            assert!(comm.verify(label_1, witness_1, com_1f));
        }
        if msg1_p3[i] {
            assert!(comm.verify(label_2, witness_2, com_2t));
        } else {
            assert!(comm.verify(label_2, witness_2, com_2f));
        }

        i3_shares.push(YaoEvaluatorShare {
            label: xor_blocks(label_1, label_2),
        });
    }

    i3_shares
}

/// Takes a vector of private boolean values from each party as input and returns yao-shares of the values.
#[allow(clippy::too_many_arguments)]
pub async fn run_batch_input_from_all_yao<S, R, G, C>(
    setup: &S,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &[bool],
    input_p1_len: usize,
    input_p2_len: usize,
    input_p3_len: usize,
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
    comm: &C,
) -> Result<(Vec<YaoShare>, Vec<YaoShare>, Vec<YaoShare>), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
{
    let mut relay = FilteredMsgRelay::new(relay);

    let tag1 = MessageTag::tag1(INPUT_YAO_FROM_ALL_MSG1, tag_offset_counter.next_value());
    let tag2 = MessageTag::tag1(INPUT_YAO_FROM_ALL_MSG2, tag_offset_counter.next_value());
    let tag3 = MessageTag::tag1(INPUT_YAO_FROM_ALL_MSG3, tag_offset_counter.next_value());

    let output = run_batch_input_from_all_yao_inner(
        setup,
        &mut relay,
        input,
        input_p1_len,
        input_p2_len,
        input_p3_len,
        rng,
        yao_setup,
        comm,
        tag1,
        tag2,
        tag3,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
async fn run_batch_input_from_all_yao_inner<S, R, G, C>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    input: &[bool],
    input_p1_len: usize,
    input_p2_len: usize,
    input_p3_len: usize,
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
    comm: &C,
    tag1: MessageTag,
    tag2: MessageTag,
    tag3: MessageTag,
) -> Result<(Vec<YaoShare>, Vec<YaoShare>, Vec<YaoShare>), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
{
    let party_id = setup.participant_index();

    relay.ask_messages(setup, tag1, true).await?;
    relay.ask_messages(setup, tag2, true).await?;
    relay.ask_messages(setup, tag3, true).await?;

    let out = if party_id == 2 {
        let (msg1_to_p1, msg1_to_p2) = input_yao_from_all_functionality_3_create_msg1(input);

        let msg1_enc_to_p1 = encode_vec_bool(msg1_to_p1.clone());
        let msg1_enc_to_p2 = encode_vec_bool(msg1_to_p2.clone());

        send_to_party(setup, tag1, msg1_enc_to_p1, 0, relay).await?;
        send_to_party(setup, tag1, msg1_enc_to_p2, 1, relay).await?;

        let msg1s_p1: Vec<Vec<TBlock>> = receive_from_parties(
            setup,
            tag1,
            (4 * input_p1_len + 2 * input_p2_len) * BLOCK_SIZE,
            vec![0],
            relay,
        )
        .await?;

        let msg1s_p2: Vec<Vec<TBlock>> = receive_from_parties(
            setup,
            tag3,
            (2 * input_p1_len + 4 * input_p2_len) * BLOCK_SIZE,
            vec![1],
            relay,
        )
        .await?;

        let msg1_p1 = InputYaoAllMsg1p22::decode(&msg1s_p1[0], input_p1_len, input_p2_len, 0);

        let msg1_p2 = InputYaoAllMsg1p22::decode(&msg1s_p2[0], input_p1_len, input_p2_len, 1);

        let (i1_shares, i2_shares) =
            input_yao_from_all_functionality_3_process_msg1(comm, &msg1_p1, &msg1_p2);

        let msg2s: Vec<Vec<TBlock>> =
            receive_from_parties(setup, tag2, 6 * input_p3_len * 16, vec![0, 1], relay).await?;

        let msg2_p1 = InputYaoAllMsg2p22::decode(&msg2s[0], input_p3_len);
        let msg2_p2 = InputYaoAllMsg2p22::decode(&msg2s[1], input_p3_len);

        let i3_shares = input_yao_from_all_functionality_3_process_msg2(
            comm,
            &msg2_p1,
            &msg2_p2,
            input_p3_len,
            &msg1_to_p1,
            &msg1_to_p2,
        );

        let i1_out: Vec<YaoShare> = i1_shares
            .iter()
            .map(|v| YaoShare {
                g_share: None,
                e_share: Some(v.clone()),
            })
            .collect();
        let i2_out: Vec<YaoShare> = i2_shares
            .iter()
            .map(|v| YaoShare {
                g_share: None,
                e_share: Some(v.clone()),
            })
            .collect();
        let i3_out: Vec<YaoShare> = i3_shares
            .iter()
            .map(|v| YaoShare {
                g_share: None,
                e_share: Some(v.clone()),
            })
            .collect();

        (i1_out, i2_out, i3_out)
    } else {
        let r = rng.as_mut().unwrap();

        let (msg1, i1_shares, i2_shares) = input_yao_from_all_functionality_12_create_msg1(
            comm,
            r,
            &yao_setup.g_setup.clone().unwrap(),
            input,
            input_p1_len,
            input_p2_len,
            party_id + 1,
        );

        let buf = msg1.encode();

        let tag = if party_id == 0 { tag1 } else { tag3 };

        send_to_party(setup, tag, buf, 2, relay).await?;

        let temp = vec![false; input_p3_len];

        let msg1s: Vec<Vec<u8>> =
            receive_from_parties(setup, tag1, encode_vec_bool(temp).len(), vec![2], relay).await?;

        let msg1 = decode_vec_bool(msg1s[0].clone(), input_p3_len);

        let (msg2, i3_shares) = input_yao_from_all_functionality_12_create_msg2(
            comm,
            r,
            input_p3_len,
            &msg1,
            party_id + 1,
            &yao_setup.g_setup.clone().unwrap(),
        );

        let buf = msg2.encode();
        send_to_party(setup, tag2, buf, 2, relay).await?;
        let i1_out: Vec<YaoShare> = i1_shares
            .iter()
            .map(|v| YaoShare {
                g_share: Some(v.clone()),
                e_share: None,
            })
            .collect();
        let i2_out: Vec<YaoShare> = i2_shares
            .iter()
            .map(|v| YaoShare {
                g_share: Some(v.clone()),
                e_share: None,
            })
            .collect();
        let i3_out: Vec<YaoShare> = i3_shares
            .iter()
            .map(|v| YaoShare {
                g_share: Some(v.clone()),
                e_share: None,
            })
            .collect();

        (i1_out, i2_out, i3_out)
    };
    Ok(out)
}
