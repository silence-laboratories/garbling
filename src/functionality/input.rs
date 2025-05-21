use std::{collections::HashMap, vec};

use rand::{CryptoRng, Rng, RngCore};
use sl_compute::{
    transport::{
        proto::{FilteredMsgRelay, MessageTag, Relay, Wrap},
        setup::{common::MPCEncryption, CommonSetupMessage},
        types::ProtocolError,
        utils::{receive_from_parties, send_to_party, TagOffsetCounter},
    },
    types::BinaryString,
};

use crate::{
    circuitop::circuit_builder::CircuitBuilder,
    config::constants::{INPUT_YAO_FROM_FUNC_MSG1, INPUT_YAO_FROM_FUNC_MSG2, INPUT_YAO_FUNC_MSG1},
    functionality::evaluate::evaluate_functionality,
    utilities::{
        commitments::Commitment,
        hash_function::HashFunction,
        types::{Block, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare, YaoSetup, YaoShare},
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
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &bool,
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
) -> Result<YaoShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let party_id = setup.participant_index();

    let output: YaoShare;
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    if party_id == 0 || party_id == 1 {
        assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
        let r = rng.as_mut().unwrap();
        let (msg1, share) =
            input_yao_functionality_create_msg1(r, input, &yao_setup.g_setup.clone().unwrap());

        send_to_party(setup, mpc_encryption, tag1, msg1, 2, relay).await?;

        output = YaoShare {
            g_share: Some(share),
            e_share: None,
        }
    } else {
        let msg1s: Vec<Block> = receive_from_parties(
            setup,
            mpc_encryption,
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
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &[bool],
    rng: &mut Option<G>,
    yao_setup: &YaoSetup,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let batch_len = input.len();
    let party_id = setup.participant_index();

    let mut output = vec![YaoShare::default(); batch_len];
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    if party_id == 0 || party_id == 1 {
        assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
        let r = rng.as_mut().unwrap();

        let mut msg1 = vec![0u8; 32 * batch_len];

        for i in 0..batch_len {
            let (msg1t, share) = input_yao_functionality_create_msg1(
                r,
                &input[i],
                &yao_setup.g_setup.clone().unwrap(),
            );

            msg1[32 * i..32 * (i + 1)].copy_from_slice(&msg1t);

            output[i] = YaoShare {
                g_share: Some(share),
                e_share: None,
            }
        }

        send_to_party(setup, mpc_encryption, tag1, msg1, 2, relay).await?;
    } else {
        let msg1s: Vec<Vec<u8>> = receive_from_parties(
            setup,
            mpc_encryption,
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
            label.copy_from_slice(&msg1_p1[32 * i..32 * (i + 1)]);
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
    let mut rng = rand::rng();
    let x1 = rng.random_bool(0.5);
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
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &Option<bool>,
    pid: usize,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<YaoShare, ProtocolError>
where
    T: CommonSetupMessage,
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

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG2.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

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

            let mut send = vec![0u8; 128];
            send[0..32].copy_from_slice(&com0);
            send[32..64].copy_from_slice(&com1);

            if party_id == pid {
                if input.unwrap() {
                    send[64..96].copy_from_slice(&w1);
                    send[96..128].copy_from_slice(&wit1);
                } else {
                    send[64..96].copy_from_slice(&w0);
                    send[96..128].copy_from_slice(&wit0);
                }
            }

            send_to_party(setup, mpc_encryption, tag1, send, 2, relay).await?;

            output = YaoShare {
                g_share: Some(YaoGarblerShare {
                    delta: yao_setup.g_setup.clone().unwrap().delta,
                    f_label: w0,
                }),
                e_share: None,
            };
        } else {
            let com_decom: Vec<[u8; 128]> = receive_from_parties(
                setup,
                mpc_encryption,
                tag1,
                4 * Block::default().external_size(),
                vec![0, 1],
                relay,
            )
            .await?;
            let mut coms_0 = [0u8; 64];
            coms_0.copy_from_slice(&com_decom[0][0..64]);
            let mut coms_1 = [0u8; 64];
            coms_1.copy_from_slice(&com_decom[1][0..64]);
            assert_eq!(coms_0, coms_1);

            let mut com0 = Block::default();
            com0.copy_from_slice(&coms_0[0..32]);
            let mut com1 = Block::default();
            com1.copy_from_slice(&coms_0[32..64]);

            let mut msg = Block::default();
            msg.copy_from_slice(&com_decom[pid][64..96]);
            let mut wit = Block::default();
            wit.copy_from_slice(&com_decom[pid][96..128]);

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
        send_to_party(setup, mpc_encryption, tag1, val1, 0, relay).await?;
        send_to_party(setup, mpc_encryption, tag1, val2, 1, relay).await?;

        let msg: Vec<[u8; 6 * 32]> =
            receive_from_parties(setup, mpc_encryption, tag2, 6 * 32, vec![0, 1], relay).await?;

        let mut allcoms_p1 = [0u8; 4 * 32];
        allcoms_p1.copy_from_slice(&msg[0][0..4 * 32]);
        let mut allcoms_p2 = [0u8; 4 * 32];
        allcoms_p2.copy_from_slice(&msg[1][0..4 * 32]);
        assert_eq!(allcoms_p2, allcoms_p1);

        let mut com_1f = Block::default();
        com_1f.copy_from_slice(&msg[0][0..32]);

        let mut com_1t = Block::default();
        com_1t.copy_from_slice(&msg[0][32..32 * 2]);

        let mut com_2f = Block::default();
        com_2f.copy_from_slice(&msg[0][32 * 2..32 * 3]);

        let mut com_2t = Block::default();
        com_2t.copy_from_slice(&msg[0][32 * 3..32 * 4]);

        let mut label_1 = Block::default();
        label_1.copy_from_slice(&msg[0][32 * 4..32 * 5]);

        let mut label_2 = Block::default();
        label_2.copy_from_slice(&msg[1][32 * 4..32 * 5]);

        let mut witness_1 = Block::default();
        witness_1.copy_from_slice(&msg[0][32 * 5..32 * 6]);

        let mut witness_2 = Block::default();
        witness_2.copy_from_slice(&msg[1][32 * 5..32 * 6]);

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
        let xs: Vec<u8> =
            receive_from_parties(setup, mpc_encryption, tag1, 1, vec![2], relay).await?;
        let x_val = xs[0] % 2 == 1;

        let ysetup: GarblerSetup = yao_setup.g_setup.clone().unwrap();

        let rngval = rng.as_mut().unwrap();

        let msg2vals = input_yao_from_functionality_3_create_msg2(comm, rngval, &ysetup);

        let mut msg = [0u8; 6 * 32];

        msg[0..32].copy_from_slice(&msg2vals[0]);
        msg[32..32 * 2].copy_from_slice(&msg2vals[1]);
        msg[32 * 2..32 * 3].copy_from_slice(&msg2vals[2]);
        msg[32 * 3..32 * 4].copy_from_slice(&msg2vals[3]);

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
        msg[32 * 4..32 * 5].copy_from_slice(&label);
        msg[32 * 5..32 * 6].copy_from_slice(&wit);

        send_to_party(setup, mpc_encryption, tag2, msg, 2, relay).await?;

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

        let (_, outmap) =
            garble_functionality(&circuit, &gin, &ein, &ysetup, rngval, hash);

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
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &[Option<bool>],
    pid: usize,
    rng: &mut Option<G>,
    hash: &H,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: CommonSetupMessage,
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

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(INPUT_YAO_FROM_FUNC_MSG2.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    if pid == 0 || pid == 1 {
        if party_id == 0 || party_id == 1 {
            assert!(yao_setup.g_setup.is_some() && yao_setup.e_setup.is_none());
            let r = rng.as_mut().unwrap();
            let mut send = vec![0u8; batch_size * 128];

            for i in 0..batch_size {
                let (com0, com1, (w0, wit0), (w1, wit1), _b) =
                    input_yao_from_functionality_12_create_msg1(
                        comm,
                        r,
                        &yao_setup.g_setup.clone().unwrap(),
                    );

                send[128 * i..(128 * i + 32)].copy_from_slice(&com0);
                send[(128 * i + 32)..(128 * i + 64)].copy_from_slice(&com1);
                if party_id == pid {
                    if input[i].unwrap() {
                        send[(128 * i + 64)..(128 * i + 96)].copy_from_slice(&w1);
                        send[(128 * i + 96)..(128 * i + 128)].copy_from_slice(&wit1);
                    } else {
                        send[(128 * i + 64)..(128 * i + 96)].copy_from_slice(&w0);
                        send[(128 * i + 96)..(128 * i + 128)].copy_from_slice(&wit0);
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

            send_to_party(setup, mpc_encryption, tag1, send, 2, relay).await?;
        } else {
            let com_decom: Vec<Vec<u8>> = receive_from_parties(
                setup,
                mpc_encryption,
                tag1,
                batch_size * 4 * Block::default().external_size(),
                vec![0, 1],
                relay,
            )
            .await?;

            (0..batch_size).for_each(|i| {
                let mut coms_0 = [0u8; 64];
                coms_0.copy_from_slice(&com_decom[0][128 * i..(128 * i + 64)]);
                let mut coms_1 = [0u8; 64];
                coms_1.copy_from_slice(&com_decom[1][128 * i..(128 * i + 64)]);
                assert_eq!(coms_0, coms_1);

                let mut com0 = Block::default();
                com0.copy_from_slice(&coms_0[0..32]);
                let mut com1 = Block::default();
                com1.copy_from_slice(&coms_0[32..64]);

                let mut msg = Block::default();
                msg.copy_from_slice(&com_decom[pid][(128 * i + 64)..(128 * i + 96)]);
                let mut wit = Block::default();
                wit.copy_from_slice(&com_decom[pid][(128 * i + 96)..(128 * i + 128)]);

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
        send_to_party(setup, mpc_encryption, tag1, val1.value.clone(), 0, relay).await?;
        send_to_party(setup, mpc_encryption, tag1, val2.value.clone(), 1, relay).await?;

        let msg: Vec<Vec<u8>> = receive_from_parties(
            setup,
            mpc_encryption,
            tag2,
            batch_size * 6 * 32,
            vec![0, 1],
            relay,
        )
        .await?;

        (0..batch_size).for_each(|i| {
            let mut allcoms_p1 = [0u8; 4 * 32];
            allcoms_p1.copy_from_slice(&msg[0][6 * 32 * i..(6 * 32 * i + 4 * 32)]);
            let mut allcoms_p2 = [0u8; 4 * 32];
            allcoms_p2.copy_from_slice(&msg[1][6 * 32 * i..(6 * 32 * i + 4 * 32)]);
            assert_eq!(allcoms_p2, allcoms_p1);

            let mut com_1f = Block::default();
            com_1f.copy_from_slice(&msg[0][6 * 32 * i..(6 * 32 * i + 32)]);

            let mut com_1t = Block::default();
            com_1t.copy_from_slice(&msg[0][(6 * 32 * i + 32)..(6 * 32 * i + 32 * 2)]);

            let mut com_2f = Block::default();
            com_2f.copy_from_slice(&msg[0][(6 * 32 * i + 32 * 2)..(6 * 32 * i + 32 * 3)]);

            let mut com_2t = Block::default();
            com_2t.copy_from_slice(&msg[0][(6 * 32 * i + 32 * 3)..(6 * 32 * i + 32 * 4)]);

            let mut label_1 = Block::default();
            label_1.copy_from_slice(&msg[0][(6 * 32 * i + 32 * 4)..(6 * 32 * i + 32 * 5)]);

            let mut label_2 = Block::default();
            label_2.copy_from_slice(&msg[1][(6 * 32 * i + 32 * 4)..(6 * 32 * i + 32 * 5)]);

            let mut witness_1 = Block::default();
            witness_1.copy_from_slice(&msg[0][(6 * 32 * i + 32 * 5)..(6 * 32 * i + 32 * 6)]);

            let mut witness_2 = Block::default();
            witness_2.copy_from_slice(&msg[1][(6 * 32 * i + 32 * 5)..(6 * 32 * i + 32 * 6)]);

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

        let xs: Vec<Vec<u8>> = receive_from_parties(
            setup,
            mpc_encryption,
            tag1,
            recv.value.len(),
            vec![2],
            relay,
        )
        .await?;

        recv.value = xs[0].clone();

        let mut msg = vec![0u8; batch_size * 6 * 32];

        for i in 0..batch_size {
            let x_val = recv.get(i);

            let ysetup: GarblerSetup = yao_setup.g_setup.clone().unwrap();

            let rngval = rng.as_mut().unwrap();

            let msg2vals = input_yao_from_functionality_3_create_msg2(comm, rngval, &ysetup);

            msg[6 * 32 * i..(6 * 32 * i + 32)].copy_from_slice(&msg2vals[0]);
            msg[(6 * 32 * i + 32)..(6 * 32 * i + 32 * 2)].copy_from_slice(&msg2vals[1]);
            msg[(6 * 32 * i + 32 * 2)..(6 * 32 * i + 32 * 3)].copy_from_slice(&msg2vals[2]);
            msg[(6 * 32 * i + 32 * 3)..(6 * 32 * i + 32 * 4)].copy_from_slice(&msg2vals[3]);
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
            msg[(6 * 32 * i + 32 * 4)..(6 * 32 * i + 32 * 5)].copy_from_slice(&label);
            msg[(6 * 32 * i + 32 * 5)..(6 * 32 * i + 32 * 6)].copy_from_slice(&wit);
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

            let (_, outmap) =
                garble_functionality(&circuit, &gin, &ein, &ysetup, rngval, hash);

            output[i] = YaoShare {
                g_share: Some(outmap.get(&circuit.output_gate_ids[0]).unwrap().clone()),
                e_share: None,
            };
        }

        send_to_party(setup, mpc_encryption, tag2, msg, 2, relay).await?;
    }

    Ok(output)
}
