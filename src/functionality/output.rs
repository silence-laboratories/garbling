// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use sl_compute_common::BinaryString;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    config::constants::{
        OUTPUT_YAO_FUNC_MSG1, OUTPUT_YAO_FUNC_MSG2, OUTPUT_YAO_TO_FUNC_MSG1,
    },
    functionality::{
        utils::{
            check_len, packed_bytes, receive_from_one_party,
            receive_from_parties, send_to_party, FilteredMsgRelay,
        },
        utils_dep::ProtocolError,
    },
    utilities::{
        types::{Block, YaoShare},
        utils::{lsb, xor_blocks},
    },
};

pub async fn validate_yao_share<T, R>(
    setup: &T,
    r: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
) -> Result<bool, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = r.next_tag(OUTPUT_YAO_FUNC_MSG1);

    match input {
        YaoShare::E(share) => {
            send_to_party(setup, tag1, &share.label, 0, r).await?;
            send_to_party(setup, tag1, &share.label, 1, r).await?;

            Ok(true)
        }

        YaoShare::G(share) => {
            let out: Block =
                receive_from_one_party(setup, tag1, 2, r).await?;
            let val1 = share.f_label == out;
            let val2 = xor_blocks(&share.f_label, &share.delta) == out;

            Ok(val1 || val2)
        }
    }
}

pub async fn output_yao_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
) -> Result<bool, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(OUTPUT_YAO_FUNC_MSG1);
    let tag2 = relay.next_tag(OUTPUT_YAO_FUNC_MSG2);

    match input {
        YaoShare::G(share) => {
            let wxs: Block =
                receive_from_one_party(setup, tag1, 2, relay).await?;

            let t1 = wxs == share.f_label;
            let t2 = wxs == xor_blocks(&share.f_label, &share.delta);

            if !(t1 || t2) {
                return Err(ProtocolError::InvalidShare);
            }

            let out = (lsb(&wxs) ^ lsb(&share.f_label)) as u16;

            send_to_party(setup, tag2, &out, 2, relay).await?;

            Ok(out != 0)
        }

        YaoShare::E(share) => {
            send_to_party(setup, tag1, &share.label, 0, relay).await?;
            send_to_party(setup, tag1, &share.label, 1, relay).await?;

            let outs: Vec<u16> =
                receive_from_parties(setup, tag2, &[0, 1], relay).await?;

            check_len(outs.len(), 2)?;

            if outs[0] != outs[1] {
                return Err(ProtocolError::InconsistentMessage);
            }

            Ok(outs[0] != 0)
        }
    }
}

pub async fn batch_output_yao_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[YaoShare],
) -> Result<Vec<bool>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(OUTPUT_YAO_FUNC_MSG1);
    let tag2 = relay.next_tag(OUTPUT_YAO_FUNC_MSG2);

    let batch_size = input.len();
    let mut output = vec![false; batch_size];
    let party_id = setup.participant_index();

    if party_id == 0 || party_id == 1 {
        let wxs: Vec<Block> =
            receive_from_one_party(setup, tag1, 2, relay).await?;

        if wxs.len() != input.len() {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut xval = BinaryString::new();

        for i in 0..batch_size {
            let share = input[i].as_garbler();

            let wx = wxs[i];

            let t1 = wx == share.f_label;
            let t2 = wx == xor_blocks(&share.f_label, &share.delta);

            if !(t1 || t2) {
                return Err(ProtocolError::InvalidShare);
            }

            let out = (lsb(&wx) ^ lsb(&share.f_label)) != 0;
            output[i] = out;
            xval.push(out);
        }

        send_to_party(setup, tag2, &xval.value, 2, relay).await?;
    } else {
        let msg = input
            .iter()
            .map(YaoShare::as_evaluator)
            .map(|s| s.label)
            .collect::<Vec<Block>>();

        send_to_party(setup, tag1, &msg, 0, relay).await?;
        send_to_party(setup, tag1, &msg, 1, relay).await?;

        let outs: Vec<Vec<u8>> =
            receive_from_parties(setup, tag2, &[0, 1], relay).await?;

        check_len(outs.len(), 2)?;
        check_len(outs[0].len(), packed_bytes(batch_size))?;

        if outs[0] != outs[1] {
            return Err(ProtocolError::InconsistentMessage);
        }

        let mut xval = BinaryString::new_with_zeros(batch_size);
        xval.value = outs[0].clone();

        (0..batch_size).for_each(|i| {
            output[i] = xval.get(i);
        });
    }

    Ok(output)
}

pub async fn output_yao_to_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    pid: usize,
    input: &YaoShare,
) -> Result<Option<bool>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(OUTPUT_YAO_TO_FUNC_MSG1);

    let mut output = None;
    let party_id = setup.participant_index();

    if pid == 2 {
        match input {
            YaoShare::E(share) => {
                let ds: Vec<u16> =
                    receive_from_parties(setup, tag1, &[0, 1], relay).await?;

                if ds.len() < 2 || ds[0] != ds[1] {
                    return Err(ProtocolError::InconsistentMessage);
                }

                output = Some((ds[0] as u8 ^ lsb(&share.label)) != 0);
            }

            YaoShare::G(share) => {
                send_to_party(
                    setup,
                    tag1,
                    &(lsb(&share.f_label) as u16),
                    2,
                    relay,
                )
                .await?;
            }
        }
    } else if party_id == 2 {
        let share = input.as_evaluator();

        send_to_party(setup, tag1, &share.label, pid, relay).await?;
    } else if party_id == pid {
        let share = input.as_garbler();

        let wxs: Block =
            receive_from_one_party(setup, tag1, 2, relay).await?;

        let t1 = wxs == share.f_label;
        let t2 = wxs == xor_blocks(&share.f_label, &share.delta);

        if !(t1 || t2) {
            return Err(ProtocolError::InvalidShare);
        }

        output = Some((lsb(&wxs) ^ lsb(&share.f_label)) != 0)
    }

    Ok(output)
}

pub async fn batch_output_yao_to_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    pid: usize,
    input: &[YaoShare],
) -> Result<Vec<Option<bool>>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(OUTPUT_YAO_TO_FUNC_MSG1);

    let batch_size = input.len();
    let mut output = vec![None; batch_size];
    let party_id = setup.participant_index();

    if pid == 2 {
        if party_id == 2 {
            let mut d = BinaryString::new_with_zeros(batch_size);

            let mut ds: Vec<Vec<u8>> =
                receive_from_parties(setup, tag1, &[0, 1], relay).await?;
            if ds.len() != 2 || ds[0] != ds[1] {
                return Err(ProtocolError::InconsistentMessage);
            }
            check_len(ds[0].len(), packed_bytes(batch_size))?;
            d.value = ds.pop().unwrap(); // can't fail, ds.len() == 2;

            for i in 0..batch_size {
                let share = input[i].as_evaluator();
                output[i] = Some(d.get(i) ^ (lsb(&share.label) != 0));
            }
        } else {
            let mut msg = BinaryString::new();

            (0..batch_size).for_each(|i| {
                let share = input[i].as_garbler();

                msg.push(lsb(&share.f_label) != 0);
            });

            send_to_party(setup, tag1, &msg.value, 2, relay).await?;
        }
    } else if party_id == 2 {
        let msg = input
            .iter()
            .map(YaoShare::as_evaluator)
            .map(|e| e.label)
            .collect::<Vec<Block>>();

        send_to_party(setup, tag1, &msg, pid, relay).await?;
    } else if party_id == pid {
        let wxs: Vec<Block> =
            receive_from_one_party(setup, tag1, 2, relay).await?;

        if wxs.len() != batch_size {
            return Err(ProtocolError::InvalidMessage);
        }

        for (i, (wx, share)) in wxs.into_iter().zip(input).enumerate() {
            let share = share.as_garbler();

            let t1 = wx == share.f_label;
            let t2 = wx == xor_blocks(&share.f_label, &share.delta);

            if !(t1 || t2) {
                return Err(ProtocolError::InvalidShare);
            }

            output[i] = Some((lsb(&wx) ^ lsb(&share.f_label)) != 0);
        }
    }

    Ok(output)
}
