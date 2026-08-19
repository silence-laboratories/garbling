// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use sl_compute_common::BinaryShare;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    config::constants::{
        Y2B_FUNC_MSG1, Y2B_FUNC_MSG2, Y2B_FUNC_MSG3, Y2B_FUNC_MSG4,
    },
    functionality::{
        utils::{
            receive_from_one_party, receive_from_parties, send_to_party,
            Byte, FilteredMsgRelay,
        },
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::Commitment,
        types::{
            Block, GarblerSetup, YaoGarblerShare, YaoSetup, YaoShare, ZBLOCK,
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

pub async fn yao_to_binary_functionality<T, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
    comm: &C,
    yao_setup: &mut YaoSetup,
) -> Result<BinaryShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag1 = relay.next_tag(Y2B_FUNC_MSG1);
    let tag2 = relay.next_tag(Y2B_FUNC_MSG2);
    let tag3 = relay.next_tag(Y2B_FUNC_MSG3);

    match yao_setup {
        YaoSetup::G(g) => {
            let party_id = setup.participant_index();
            if party_id > 1 || party_id != g.party_id {
                return Err(ProtocolError::InvalidMessage);
            }
            let YaoShare::G(garbler_share) = input else {
                return Err(ProtocolError::InvalidShare);
            };
            if garbler_share.delta != g.delta {
                return Err(ProtocolError::InvalidShare);
            }

            if g.party_id == 0 {
                let (y, wyr, wr0) = create_yao_to_binary_msg1(g);
                send_to_party(setup, tag1, &(wyr, y as u8), 2, relay).await?;
                send_to_party(setup, tag1, &wr0, 1, relay).await?;

                let (com0, com1, _, _, wit0, wit1) =
                    create_yao_to_binary_msg2(
                        &wr0,
                        comm,
                        &mut g.prf,
                        garbler_share,
                    );

                send_to_party(
                    setup,
                    tag2,
                    &((com0, com1), (wit0, wit1)),
                    2,
                    relay,
                )
                .await?;

                let p = lsb(&garbler_share.f_label) != 0;
                Ok(BinaryShare {
                    value1: p ^ y,
                    value2: p,
                })
            } else {
                let wr0: Block =
                    receive_from_one_party(setup, tag1, 0, relay).await?;

                let (com0, com1, wz0, wz1, _, _) = create_yao_to_binary_msg2(
                    &wr0,
                    comm,
                    &mut g.prf,
                    garbler_share,
                );

                send_to_party(
                    setup,
                    tag2,
                    &((com0, com1), (ZBLOCK, ZBLOCK)),
                    2,
                    relay,
                )
                .await?;

                let wxz: Block =
                    receive_from_one_party(setup, tag3, 2, relay).await?;

                let val1 = wxz == wz0;
                let val2 = wxz == wz1;

                if !(val1 || val2) {
                    return Err(ProtocolError::InvalidShare);
                }

                let pz = (lsb(&wxz) ^ lsb(&wr0)) != 0;
                let p = lsb(&garbler_share.f_label) != 0;

                Ok(BinaryShare {
                    value1: pz ^ p,
                    value2: pz,
                })
            }
        }

        YaoSetup::E(_e) => {
            if setup.participant_index() != 2 {
                return Err(ProtocolError::InvalidMessage);
            }
            let YaoShare::E(yaoshare) = input else {
                return Err(ProtocolError::InvalidShare);
            };

            let (wyr, Byte(y)): (Block, Byte) =
                receive_from_one_party(setup, tag1, 0, relay).await?;

            let y = y != 0;

            let wxz = xor_blocks(&yaoshare.label, &wyr);

            send_to_party(setup, tag3, &wxz, 1, relay).await?;

            let msg2s: Vec<((Block, Block), (Block, Block))> =
                receive_from_parties(setup, tag2, &[0, 1], relay).await?;

            if msg2s.len() != 2 {
                return Err(ProtocolError::MissingMessage);
            }

            let (com0, com1) = &msg2s[0].0;
            let (com01, com11) = &msg2s[1].0;
            let (wit0, wit1) = &msg2s[0].1;

            if com0 != com01 || com1 != com11 {
                return Err(ProtocolError::InconsistentMessage);
            }

            let px = lsb(&yaoshare.label) != 0;
            let verified = if px ^ y {
                comm.verify(&wxz, wit1, com1)
            } else {
                comm.verify(&wxz, wit0, com0)
            };

            if !verified {
                return Err(ProtocolError::CommitmentVerificationFailed);
            }

            let pz = px ^ y;
            Ok(BinaryShare {
                value1: y ^ pz,
                value2: y,
            })
        }
    }
}

pub async fn batch_yao_to_binary_functionality<T, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[YaoShare],
    comm: &C,
    yao_setup: &mut YaoSetup,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag1 = relay.next_tag(Y2B_FUNC_MSG1);
    let tag2 = relay.next_tag(Y2B_FUNC_MSG2);
    let tag3 = relay.next_tag(Y2B_FUNC_MSG3);
    let tag4 = relay.next_tag(Y2B_FUNC_MSG4);

    match yao_setup {
        YaoSetup::G(yaosetup) => {
            let party_id = setup.participant_index();
            if party_id > 1 || party_id != yaosetup.party_id {
                return Err(ProtocolError::InvalidMessage);
            }
            if input.iter().any(|share| {
                !matches!(share, YaoShare::G(g) if g.delta == yaosetup.delta)
            }) {
                return Err(ProtocolError::InvalidShare);
            }

            if yaosetup.party_id == 0 {
                let mut msgs = Vec::new();
                let mut wr0msgs = Vec::new();
                let mut msg2s = Vec::new();

                let outputs = input
                    .iter()
                    .map(YaoShare::as_garbler)
                    .map(|share| {
                        let (y, wyr, wr0) =
                            create_yao_to_binary_msg1(yaosetup);

                        msgs.push((wyr, y as u8));

                        wr0msgs.push(wr0);

                        let (com0, com1, _, _, wit0, wit1) =
                            create_yao_to_binary_msg2(
                                &wr0,
                                comm,
                                &mut yaosetup.prf,
                                share,
                            );

                        msg2s.push(((com0, com1), (wit0, wit1)));

                        let p = lsb(&share.f_label) != 0;

                        BinaryShare {
                            value1: p ^ y,
                            value2: p,
                        }
                    })
                    .collect::<Vec<_>>();

                send_to_party(setup, tag1, &msgs, 2, relay).await?;
                send_to_party(setup, tag1, &wr0msgs, 1, relay).await?;
                send_to_party(setup, tag2, &msg2s, 2, relay).await?;

                Ok(outputs)
            } else {
                let msg1s: Vec<Block> =
                    receive_from_one_party(setup, tag1, 0, relay).await?;

                if msg1s.len() != input.len() {
                    return Err(ProtocolError::InvalidMessage);
                }

                let mut msgs = Vec::new();
                let mut wr0s = Vec::with_capacity(input.len());
                let mut wz0s = Vec::with_capacity(input.len());
                let mut wz1s = Vec::with_capacity(input.len());

                for (share, &wr0) in
                    input.iter().map(YaoShare::as_garbler).zip(&msg1s)
                {
                    let (com0, com1, wz0, wz1, _, _) =
                        create_yao_to_binary_msg2(
                            &wr0,
                            comm,
                            &mut yaosetup.prf,
                            share,
                        );

                    msgs.push((com0, com1));

                    wr0s.push(wr0);
                    wz0s.push(wz0);
                    wz1s.push(wz1);
                }

                send_to_party(setup, tag4, &msgs, 2, relay).await?;

                let msg2s: Vec<Block> =
                    receive_from_one_party(setup, tag3, 2, relay).await?;

                if msg2s.len() != input.len() {
                    return Err(ProtocolError::InvalidMessage);
                }

                input
                    .iter()
                    .map(YaoShare::as_garbler)
                    .zip(&msg2s)
                    .zip(&wr0s)
                    .zip(&wz0s)
                    .zip(&wz1s)
                    .map(|((((share, wxz), wr0s_i), wz0s_i), wz1s_i)| {
                        let val1 = wxz == wz0s_i;
                        let val2 = wxz == wz1s_i;

                        if !(val1 || val2) {
                            return Err(ProtocolError::InvalidShare);
                        }

                        let pz = (lsb(wxz) ^ lsb(wr0s_i)) != 0;
                        let p = lsb(&share.f_label) != 0;

                        Ok(BinaryShare {
                            value1: pz ^ p,
                            value2: pz,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            }
        }

        YaoSetup::E(_e) => {
            if setup.participant_index() != 2 {
                return Err(ProtocolError::InvalidMessage);
            }
            if input.iter().any(|share| !matches!(share, YaoShare::E(_))) {
                return Err(ProtocolError::InvalidShare);
            }

            let msg1s: Vec<(Block, u8)> =
                receive_from_one_party(setup, tag1, 0, relay).await?;

            if msg1s.len() != input.len() {
                return Err(ProtocolError::InvalidMessage);
            }

            let mut ys = Vec::with_capacity(input.len());
            let mut wxzs_store = Vec::with_capacity(input.len());

            let wxzs = input
                .iter()
                .map(YaoShare::as_evaluator)
                .zip(&msg1s)
                .map(|(share, (wyr, y))| {
                    let y = y != &0;
                    let wxz = xor_blocks(&share.label, wyr);

                    wxzs_store.push(wxz);
                    ys.push(y);

                    wxz
                })
                .collect::<Vec<_>>();

            send_to_party(setup, tag3, &wxzs, 1, relay).await?;

            // ((Block, Block), (Block, Block))
            let msg2s_0: Vec<((Block, Block), (Block, Block))> =
                receive_from_one_party(setup, tag2, 0, relay).await?;

            let msg2s_1: Vec<(Block, Block)> =
                receive_from_one_party(setup, tag4, 1, relay).await?;

            if msg2s_0.len() != input.len() {
                return Err(ProtocolError::InvalidMessage);
            }

            if msg2s_1.len() != input.len() {
                return Err(ProtocolError::InvalidMessage);
            }

            input
                .iter()
                .map(YaoShare::as_evaluator)
                .zip(&msg2s_0)
                .zip(&msg2s_1)
                .zip(&ys)
                .zip(&wxzs_store)
                .map(|((((share, m0), m1), &ys_i), wxzs_store_i)| {
                    let (com0, com1) = &m0.0;
                    let (com01, com11) = &m1;
                    let (wit0, wit1) = &m0.1;

                    if com0 != com01 || com1 != com11 {
                        return Err(ProtocolError::InconsistentMessage);
                    }

                    let px = lsb(&share.label) != 0;
                    let verified = if px ^ ys_i {
                        comm.verify(wxzs_store_i, wit1, com1)
                    } else {
                        comm.verify(wxzs_store_i, wit0, com0)
                    };

                    if !verified {
                        return Err(
                            ProtocolError::CommitmentVerificationFailed,
                        );
                    }

                    let pz = px ^ ys_i;

                    Ok(BinaryShare {
                        value1: ys_i ^ pz,
                        value2: ys_i,
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        }
    }
}

#[cfg(test)]
mod tests {
    /// OPEN_MSG
    pub const OPEN_MSG: u32 = 3;

    use merlin::Transcript;
    use tokio::task::JoinSet;

    use sl_compute_common::{Binary, BinaryShare, ServerState};
    use sl_messages::{
        relay::{MessageRelayService, Relay, SimpleMessageRelay},
        setup::{
            keys::{NoSigningKey, NoVerifyingKey},
            ProtocolParticipant,
        },
    };

    use crate::{
        circuit::{prebuilt, BinaryCircuit},
        functionality::{
            circuit_eval::yao_circuit_eval_functionality,
            input::batch_input_yao_functionality,
            output::validate_yao_share,
            setup::setup_yao_functionality,
            utils::{
                p2p_send_to_next_receive_from_prev, run_common_randomness,
                FilteredMsgRelay, SetupMessage,
            },
            utils_dep::ProtocolError,
        },
        utilities::{
            commitments::HashCommitment, garble_hash::AesGarbleHash,
            shahash::Sha512Hash, types::YaoSetup, utils::bool_vec_to_hex,
        },
    };

    use super::{
        batch_yao_to_binary_functionality, yao_to_binary_functionality,
    };

    fn aes128_circuit() -> BinaryCircuit {
        prebuilt::decode(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/circuits/aes128.bin"
        )))
    }

    async fn test_run_y_to_b<T, R>(
        setup: T,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        T: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);
        relay.init_abort(&setup).await?;

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

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let (hash, comm) = match &yao_setup {
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

        let circuit = aes128_circuit();

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
                    &mut yao_setup,
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
                    &hash,
                    &mut yao_setup,
                )
                .await?;

                let mut out_yao = vec![];
                for id in circuit.output_gate_ids() {
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
                        &comm,
                        &mut yao_setup,
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
        relay.init_abort(&setup).await?;

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

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let (hash, comm) = match &yao_setup {
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

        let circuit = aes128_circuit();

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
                    &mut yao_setup,
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
                    &hash,
                    &mut yao_setup,
                )
                .await?;

                let mut out_yao = vec![];
                for id in circuit.output_gate_ids() {
                    out_yao.push(output.get(id).unwrap().clone());
                }

                let out_bin = batch_yao_to_binary_functionality(
                    &setup,
                    &mut relay,
                    &out_yao,
                    &comm,
                    &mut yao_setup,
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
                println!("error {err}");
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
