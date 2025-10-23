// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use sl_compute_common::BinaryShare;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    config::constants::{
        Y2B_FUNC_MSG1, Y2B_FUNC_MSG2, Y2B_FUNC_MSG3, Y2B_FUNC_MSG4,
    },
    functionality::{
        utils::{receive_from_parties, send_to_party, FilteredMsgRelay},
        utils_dep::{ProtocolError, ProtocolParticipant},
    },
    utilities::{
        commitments::Commitment,
        types::{
            Block, GarblerSetup, YaoGarblerShare, YaoSetup, YaoShare,
            BLOCK_SIZE,
        },
        utils::{lsb, xor_blocks},
    },
};

fn create_yao_to_binary_msg1(
    yao_setup: &GarblerSetup,
) -> (bool, Block, Block) {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let y = rng.gen_bool(0.5);
    let wyr = rng.gen();

    let wr0 = if y {
        xor_blocks(&wyr, &yao_setup.delta)
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
    let p = lsb(&input.f_label);

    let wz0 = xor_blocks(wr0, &input.f_label);
    let mut wit0 = Block::default();
    rng.fill_bytes(&mut wit0);

    let wz1 = xor_blocks(&wz0, &input.delta);
    let mut wit1 = Block::default();
    rng.fill_bytes(&mut wit1);

    let (com0, com1) = if p == 0 {
        (comm.commit(&wz0, &wit0), comm.commit(&wz1, &wit1))
    } else {
        (comm.commit(&wz1, &wit0), comm.commit(&wz0, &wit1))
    };

    (com0, com1, wz0, wz1, wit0, wit1)
}

#[allow(clippy::too_many_arguments)]
pub async fn yao_to_binary_functionality<T, G, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
    rng: Option<&mut G>,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<BinaryShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let tag1 = relay.next_tag(Y2B_FUNC_MSG1);
    let tag2 = relay.next_tag(Y2B_FUNC_MSG2);
    let tag3 = relay.next_tag(Y2B_FUNC_MSG3);

    let output = yao_to_binary_functionality_inner(
        setup, relay, input, rng, comm, yao_setup, tag1, tag2, tag3,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
async fn yao_to_binary_functionality_inner<T, G, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
    rng: Option<&mut G>,
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

    match yao_setup {
        YaoSetup::G(yaosetup) => {
            let garbler_share = input.as_garbler();

            if party_id == 0 {
                let (y, wyr, wr0) = create_yao_to_binary_msg1(yaosetup);
                let mut msg = [0u8; BLOCK_SIZE + 1];
                msg[0..BLOCK_SIZE].copy_from_slice(&wyr);
                if y {
                    msg[BLOCK_SIZE] = 1;
                }
                send_to_party(setup, tag1, msg, 2, relay).await?;
                send_to_party(setup, tag1, wr0, 1, relay).await?;

                let r = rng.unwrap();

                let (com0, com1, _, _, wit0, wit1) =
                    create_yao_to_binary_msg2(&wr0, comm, r, garbler_share);

                let mut msg = [0u8; BLOCK_SIZE * 4];
                msg[0..BLOCK_SIZE].copy_from_slice(&com0);
                msg[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&com1);
                msg[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&wit0);
                msg[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&wit1);

                send_to_party(setup, tag2, msg, 2, relay).await?;
                let p = lsb(&garbler_share.f_label) != 0;
                Ok(BinaryShare {
                    value1: p ^ y,
                    value2: p,
                })
            } else {
                assert!(party_id == 1);

                let msg1s: Vec<Block> =
                    receive_from_parties(setup, tag1, &[0], relay).await?;
                let wr0 = &msg1s[0];

                let r = rng.unwrap();

                let (com0, com1, wz0, wz1, _, _) =
                    create_yao_to_binary_msg2(wr0, comm, r, garbler_share);

                let mut msg = [0u8; BLOCK_SIZE * 4];
                msg[0..BLOCK_SIZE].copy_from_slice(&com0);
                msg[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&com1);

                send_to_party(setup, tag2, msg, 2, relay).await?;

                let msg2s: Vec<Block> =
                    receive_from_parties(setup, tag3, &[2], relay).await?;
                let mut wxz = Block::default();
                wxz.copy_from_slice(&msg2s[0]);

                let val1 = wxz == wz0;
                let val2 = wxz == wz1;

                assert_eq!(yaosetup.delta, garbler_share.delta);
                assert!(val1 || val2);

                let pz = (lsb(&wxz) ^ lsb(wr0)) != 0;
                let p = lsb(&garbler_share.f_label) != 0;
                Ok(BinaryShare {
                    value1: pz ^ p,
                    value2: pz,
                })
            }
        }

        YaoSetup::E(_e) => {
            let msg1s: Vec<[u8; BLOCK_SIZE + 1]> =
                receive_from_parties(setup, tag1, &[0], relay).await?;
            let mut wyr = Block::default();
            wyr.copy_from_slice(&msg1s[0][0..BLOCK_SIZE]);
            let y = msg1s[0][BLOCK_SIZE] != 0;

            let yaoshare = input.as_evaluator();

            let wxz = xor_blocks(&yaoshare.label, &wyr);

            send_to_party(setup, tag3, wxz, 1, relay).await?;

            let msg2s: Vec<Vec<u8>> =
                receive_from_parties(setup, tag2, &[0, 1], relay).await?;

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

            let px = lsb(&yaoshare.label) != 0;
            if px ^ y {
                assert!(comm.verify(&wxz, &wit1, &com1))
            } else {
                assert!(comm.verify(&wxz, &wit0, &com0))
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
    relay: &mut FilteredMsgRelay<R>,
    input: &[YaoShare],
    rng: Option<&mut G>,
    comm: &C,
    yao_setup: &YaoSetup,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
    G: RngCore + CryptoRng,
{
    let tag1 = relay.next_tag(Y2B_FUNC_MSG1);
    let tag2 = relay.next_tag(Y2B_FUNC_MSG2);
    let tag3 = relay.next_tag(Y2B_FUNC_MSG3);
    let tag4 = relay.next_tag(Y2B_FUNC_MSG4);

    let output = batch_yao_to_binary_functionality_inner(
        setup, relay, input, rng, comm, yao_setup, tag1, tag2, tag3, tag4,
    )
    .await?;

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
async fn batch_yao_to_binary_functionality_inner<T, G, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[YaoShare],
    rng: Option<&mut G>,
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

    match yao_setup {
        YaoSetup::G(yaosetup) => {
            let r = rng.unwrap();

            if party_id == 0 {
                let mut msgs = Vec::new();
                let mut wr0msgs = Vec::new();
                let mut msg2s = Vec::new();

                let outputs = input
                    .iter()
                    .map(YaoShare::as_garbler)
                    .map(|share| {
                        let (y, wyr, wr0) =
                            create_yao_to_binary_msg1(yaosetup);
                        let mut msg = [0u8; BLOCK_SIZE + 1];

                        msg[0..BLOCK_SIZE].copy_from_slice(&wyr);
                        if y {
                            msg[BLOCK_SIZE] = 1;
                        }

                        msgs.extend_from_slice(&msg);

                        wr0msgs.extend_from_slice(&wr0);

                        let (com0, com1, _, _, wit0, wit1) =
                            create_yao_to_binary_msg2(&wr0, comm, r, share);

                        msg2s.extend_from_slice(&com0);

                        msg2s.extend_from_slice(&com1);

                        msg2s.extend_from_slice(&wit0);

                        msg2s.extend_from_slice(&wit1);

                        let p = lsb(&share.f_label) != 0;

                        BinaryShare {
                            value1: p ^ y,
                            value2: p,
                        }
                    })
                    .collect::<Vec<_>>();

                send_to_party(setup, tag1, msgs, 2, relay).await?;
                send_to_party(setup, tag1, wr0msgs, 1, relay).await?;
                send_to_party(setup, tag2, msg2s, 2, relay).await?;

                Ok(outputs)
            } else {
                assert!(party_id == 1);

                let msg1s: Vec<Vec<u8>> =
                    receive_from_parties(setup, tag1, &[0], relay).await?;

                let mut msgs = Vec::new();
                let mut wr0s = Vec::new();
                let mut wz0s = Vec::new();
                let mut wz1s = Vec::new();

                input.iter().map(YaoShare::as_garbler).enumerate().for_each(
                    |(i, share)| {
                        let mut wr0 = Block::default();
                        wr0.copy_from_slice(
                            &msg1s[0][BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)],
                        );

                        let (com0, com1, wz0, wz1, _, _) =
                            create_yao_to_binary_msg2(&wr0, comm, r, share);

                        msgs.extend_from_slice(&com0);

                        msgs.extend_from_slice(&com1);

                        wr0s.push(wr0);
                        wz0s.push(wz0);
                        wz1s.push(wz1);
                    },
                );

                send_to_party(setup, tag4, msgs, 2, relay).await?;

                let msg2s: Vec<Vec<u8>> =
                    receive_from_parties(setup, tag3, &[2], relay).await?;

                Ok(input
                    .iter()
                    .map(YaoShare::as_garbler)
                    .enumerate()
                    .map(|(i, share)| {
                        let wxz = <&Block>::try_from(
                            &msg2s[0][BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)],
                        )
                        .unwrap();

                        let val1 = wxz == &wz0s[i];
                        let val2 = wxz == &wz1s[i];

                        assert!(val1 || val2);

                        let pz = (lsb(wxz) ^ lsb(&wr0s[i])) != 0;

                        let p = lsb(&share.f_label) != 0;

                        BinaryShare {
                            value1: pz ^ p,
                            value2: pz,
                        }
                    })
                    .collect())
            }
        }

        YaoSetup::E(_e) => {
            let msg1s: Vec<Vec<u8>> =
                receive_from_parties(setup, tag1, &[0], relay).await?;

            let mut wxzs = Vec::new();
            let mut ys = Vec::new();
            let mut wxzs_store = Vec::new();

            input
                .iter()
                .map(YaoShare::as_evaluator)
                .enumerate()
                .for_each(|(i, share)| {
                    let mut wyr = Block::default();
                    wyr.copy_from_slice(
                        &msg1s[0][(BLOCK_SIZE + 1) * i
                            ..((BLOCK_SIZE + 1) * i + BLOCK_SIZE)],
                    );
                    let y = msg1s[0][(BLOCK_SIZE + 1) * i + BLOCK_SIZE] != 0;

                    let wxz = xor_blocks(&share.label, &wyr);

                    wxzs.extend_from_slice(&wxz);

                    wxzs_store.push(wxz);

                    ys.push(y);
                });

            send_to_party(setup, tag3, wxzs, 1, relay).await?;

            let msg2s_0: Vec<Vec<u8>> =
                receive_from_parties(setup, tag2, &[0], relay).await?;

            let msg2s_1: Vec<Vec<u8>> =
                receive_from_parties(setup, tag4, &[1], relay).await?;

            let outputs = input
                .iter()
                .map(YaoShare::as_evaluator)
                .enumerate()
                .map(|(i, share)| {
                    // We pass a slice that is guaranteed to have the
                    // correct length to <&Block::try_from(); the
                    // conversion can’t fail

                    let com0 = <&Block>::try_from(
                        &msg2s_0[0][BLOCK_SIZE * 4 * i
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE)],
                    )
                    .unwrap();

                    let com1 = <&Block>::try_from(
                        &msg2s_0[0][(BLOCK_SIZE * 4 * i + BLOCK_SIZE)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)],
                    )
                    .unwrap();

                    let com01 = <&Block>::try_from(
                        &msg2s_1[0][BLOCK_SIZE * 2 * i
                            ..(BLOCK_SIZE * 2 * i + BLOCK_SIZE)],
                    )
                    .unwrap();

                    let com11 = <&Block>::try_from(
                        &msg2s_1[0][(BLOCK_SIZE * 2 * i + BLOCK_SIZE)
                            ..(BLOCK_SIZE * 2 * i + BLOCK_SIZE * 2)],
                    )
                    .unwrap();

                    let wit0 = <&Block>::try_from(
                        &msg2s_0[0][(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 2)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)],
                    )
                    .unwrap();

                    let wit1 = <&Block>::try_from(
                        &msg2s_0[0][(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 3)
                            ..(BLOCK_SIZE * 4 * i + BLOCK_SIZE * 4)],
                    )
                    .unwrap();

                    assert_eq!(com0, com01);
                    assert_eq!(com1, com11);

                    let px = lsb(&share.label) != 0;
                    if px ^ ys[i] {
                        assert!(comm.verify(&wxzs_store[i], wit1, com1))
                    } else {
                        assert!(comm.verify(&wxzs_store[i], wit0, com0))
                    }

                    let pz = px ^ ys[i];

                    BinaryShare {
                        value1: ys[i] ^ pz,
                        value2: ys[i],
                    }
                })
                .collect();

            Ok(outputs)
        }
    }
}

#[cfg(test)]
mod tests {

    /// OPEN_MSG
    pub const OPEN_MSG: u32 = 3;
    use merlin::Transcript;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use sl_compute_common::{Binary, BinaryShare, ServerState};
    use sl_messages::relay::{
        MessageRelayService, Relay, SimpleMessageRelay,
    };
    use tokio::task::JoinSet;

    use crate::{
        circuitop::circuit::BinaryCircuit,
        config::constants::AES128_CIRCUIT,
        functionality::{
            circuit_eval::yao_circuit_eval_functionality,
            input::batch_input_yao_functionality,
            output::validate_yao_share,
            setup::setup_yao_functionality,
            utils::{
                p2p_send_to_next_receive_from_prev, run_common_randomness,
                FilteredMsgRelay, SetupMessage,
            },
            utils_dep::{ProtocolError, ProtocolParticipant},
        },
        utilities::{
            commitments::HashCommitment, garble_hash::AesGarbleHash,
            shahash::Sha512Hash, types::YaoSetup, utils::bool_vec_to_hex,
        },
    };

    use super::{
        batch_yao_to_binary_functionality, yao_to_binary_functionality,
    };

    async fn test_run_y_to_b<T, R>(
        setup: T,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);

        let mut init_seed = [0u8; 32];
        let common_randomness_seed = [setup.participant_index() as u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);

        let common_randomness = run_common_randomness(
            &setup,
            &common_randomness_seed,
            &mut relay,
        )
        .await?;

        let mut serverstate = ServerState::new(common_randomness);

        let yao_setup = setup_yao_functionality(&setup, &mut relay).await?;

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

        let circuit = BinaryCircuit::parse(AES128_CIRCUIT).unwrap();

        for x in 0..2 {
            for y in 0..2 {
                let key = vec![x != 0; 128];
                let msg = vec![y != 0; 128];

                let mut joint = [false; 256];
                joint[0..128].copy_from_slice(&key);
                joint[128..256].copy_from_slice(&msg);

                let jointsh = batch_input_yao_functionality(
                    &setup,
                    &mut relay,
                    &joint,
                    rng.as_mut(),
                    &yao_setup,
                )
                .await?;

                for i in &jointsh {
                    let val =
                        validate_yao_share(&setup, &mut relay, i).await?;
                    assert!(val);
                }

                let mut inputs = [vec![], vec![]];
                inputs[0].extend_from_slice(&jointsh[..128]);
                inputs[1].extend_from_slice(&jointsh[128..]);

                let output = yao_circuit_eval_functionality(
                    &setup,
                    &mut relay,
                    &inputs,
                    &circuit,
                    rng.as_mut(),
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
                        validate_yao_share(&setup, &mut relay, i).await?;
                    assert!(val);
                    let temp = yao_to_binary_functionality(
                        &setup,
                        &mut relay,
                        i,
                        rng.as_mut(),
                        &comm,
                        &yao_setup,
                    )
                    .await?;
                    out_bin.push(temp);
                }

                let act_out = run_batch_open_binary_share(
                    &setup,
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
        r: &mut FilteredMsgRelay<R>,
        shares: &[BinaryShare],
        serverstate: &mut ServerState,
    ) -> Result<Vec<Binary>, ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let tag = r.next_tag(OPEN_MSG);
        let msg: Vec<u8> =
            shares.iter().map(|share| share.value1 as u8).collect();

        let msg_from_prev =
            p2p_send_to_next_receive_from_prev(setup, tag, msg, r).await?;

        let output: Vec<bool> = shares
            .iter()
            .zip(&msg_from_prev)
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
        let mut relay = FilteredMsgRelay::new(relay);

        let mut init_seed = [0u8; 32];
        let common_randomness_seed = [setup.participant_index() as u8; 32];
        let mut transcript = Transcript::new(b"test");
        transcript.challenge_bytes(b"init-seed", &mut init_seed);

        let common_randomness = run_common_randomness(
            &setup,
            &common_randomness_seed,
            &mut relay,
        )
        .await?;

        let mut serverstate = ServerState::new(common_randomness);

        let yao_setup = setup_yao_functionality(&setup, &mut relay).await?;

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

        let circuit = BinaryCircuit::parse(AES128_CIRCUIT).unwrap();

        for x in 0..2 {
            for y in 0..2 {
                let key = vec![x != 0; 128];
                let msg = vec![y != 0; 128];

                let mut joint = [false; 256];
                joint[0..128].copy_from_slice(&key);
                joint[128..256].copy_from_slice(&msg);

                let jointsh = batch_input_yao_functionality(
                    &setup,
                    &mut relay,
                    &joint,
                    rng.as_mut(),
                    &yao_setup,
                )
                .await?;

                for i in &jointsh {
                    let val =
                        validate_yao_share(&setup, &mut relay, i).await?;
                    assert!(val);
                }

                let mut inputs = vec![vec![], vec![]];
                inputs[0].extend_from_slice(&jointsh[..128]);
                inputs[1].extend_from_slice(&jointsh[128..]);

                let output = yao_circuit_eval_functionality(
                    &setup,
                    &mut relay,
                    &inputs,
                    &circuit,
                    rng.as_mut(),
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
                    &mut relay,
                    &out_yao,
                    rng.as_mut(),
                    &comm,
                    &yao_setup,
                )
                .await?;

                let act_out = run_batch_open_binary_share(
                    &setup,
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
    fn setup_y_to_b(
        instance: Option<[u8; 32]>,
    ) -> Vec<(SetupMessage, [u8; 32])> {
        use sha2::{Digest, Sha256};
        use sl_messages::message::InstanceId;
        use std::time::Duration;

        use crate::functionality::utils::{NoSigningKey, NoVerifyingKey};

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
