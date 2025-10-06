use sl_compute_common::BinaryString;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    config::constants::{OUTPUT_YAO_FUNC_MSG1, OUTPUT_YAO_FUNC_MSG2, OUTPUT_YAO_TO_FUNC_MSG1},
    functionality::{
        utils::{receive_from_parties, send_to_party, FilteredMsgRelay, Wrap},
        utils_dep::{ProtocolError, ProtocolParticipant, TagOffsetCounter},
    },
    utilities::{
        types::{Block, YaoShare, BLOCK_SIZE},
        utils::{lsb, xor_blocks},
    },
};
use std::vec;

pub async fn validate_yao_share<T, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &YaoShare,
) -> Result<bool, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let party_id = setup.participant_index();

    let mut r = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG1, tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    if party_id == 2 {
        let share = input.as_evaluator();
        send_to_party(setup, tag1, share.label, 0, &mut r).await?;
        send_to_party(setup, tag1, share.label, 1, &mut r).await?;
        Ok(true)
    } else {
        let out: Vec<Block> = receive_from_parties(setup, tag1, BLOCK_SIZE, &[2], &mut r).await?;
        let share = input.as_garbler();
        let val1 = share.f_label == out[0];
        let val2 = xor_blocks(&share.f_label, &share.delta) == out[0];

        Ok(val1 || val2)
    }
}

pub async fn output_yao_functionality<T, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &YaoShare,
) -> Result<bool, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let mut r = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG1, tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG2, tag_offset);
    r.ask_messages(setup, tag2, true).await?;

    let output = output_yao_functionality_inner(setup, &mut r, input, tag1, tag2).await?;
    Ok(output)
}

pub async fn output_yao_functionality_inner<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<bool, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let output;
    let party_id = setup.participant_index();

    if party_id == 0 || party_id == 1 {
        let share = input.as_garbler();

        let wxs: Vec<Block> = receive_from_parties(setup, tag1, BLOCK_SIZE, &[2], relay).await?;

        let t1 = wxs[0] == share.f_label;
        let t2 = wxs[0] == xor_blocks(&share.f_label, &share.delta);

        assert!(t1 || t2);
        let out = (lsb(&wxs[0]) ^ lsb(&share.f_label)) as u16;

        send_to_party(setup, tag2, out, 2, relay).await?;
        output = out != 0;
    } else {
        let share = input.as_evaluator();

        send_to_party(setup, tag1, share.label, 0, relay).await?;
        send_to_party(setup, tag1, share.label, 1, relay).await?;

        let outs: Vec<u16> =
            receive_from_parties(setup, tag2, 0u16.external_size(), &[0, 1], relay).await?;

        assert_eq!(outs[0], outs[1]);
        output = outs[0] != 0;
    }

    Ok(output)
}

pub async fn batch_output_yao_functionality<T, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    input: &[YaoShare],
) -> Result<Vec<bool>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let mut r = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG1, tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG2, tag_offset);
    r.ask_messages(setup, tag2, true).await?;

    let output = batch_output_yao_functionality_inner(setup, &mut r, input, tag1, tag2).await?;
    Ok(output)
}

pub async fn batch_output_yao_functionality_inner<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[YaoShare],
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<Vec<bool>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let batch_size = input.len();
    let mut output = vec![false; batch_size];
    let party_id = setup.participant_index();

    if party_id == 0 || party_id == 1 {
        let wxs: Vec<Vec<u8>> =
            receive_from_parties(setup, tag1, BLOCK_SIZE * batch_size, &[2], relay).await?;

        let mut xval = BinaryString::new();

        for i in 0..batch_size {
            let share = input[i].as_garbler();

            let mut wx = Block::default();
            wx.copy_from_slice(&wxs[0][BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)]);

            let t1 = wx == share.f_label;
            let t2 = wx == xor_blocks(&share.f_label, &share.delta);

            assert!(t1 || t2);
            let out = (lsb(&wx) ^ lsb(&share.f_label)) != 0;
            output[i] = out;
            xval.push(out);
        }

        send_to_party(setup, tag2, xval.value, 2, relay).await?;
    } else {
        let mut msg = vec![0u8; BLOCK_SIZE * batch_size];
        let mut xval = BinaryString::new();
        for i in 0..batch_size {
            let share = input[i].as_evaluator();
            msg[BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)].copy_from_slice(&share.label);
            xval.push(false);
        }

        send_to_party(setup, tag1, msg.clone(), 0, relay).await?;
        send_to_party(setup, tag1, msg, 1, relay).await?;

        let outs: Vec<Vec<u8>> =
            receive_from_parties(setup, tag2, xval.value.len(), &[0, 1], relay).await?;

        assert_eq!(outs[0], outs[1]);
        xval.value = outs[0].clone();

        (0..batch_size).for_each(|i| {
            output[i] = xval.get(i);
        });
    }

    Ok(output)
}

pub async fn output_yao_to_functionality<T, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    pid: usize,
    input: &YaoShare,
) -> Result<Option<bool>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let mut r = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_TO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let output = output_yao_to_functionality_inner(setup, &mut r, pid, input, tag1).await?;
    Ok(output)
}

pub async fn output_yao_to_functionality_inner<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    pid: usize,
    input: &YaoShare,
    tag1: MessageTag,
) -> Result<Option<bool>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let mut output = None;
    let party_id = setup.participant_index();

    if pid == 2 {
        if party_id == 2 {
            let share = input.as_evaluator();

            let ds: Vec<u16> =
                receive_from_parties(setup, tag1, 0u16.external_size(), &[0, 1], relay).await?;

            assert_eq!(ds[0], ds[1]);
            output = Some((ds[0] as u8 ^ lsb(&share.label)) != 0);
        } else {
            let share = input.as_garbler();

            send_to_party(setup, tag1, lsb(&share.f_label) as u16, 2, relay).await?;
        }
    } else if party_id == 2 {
        let share = input.as_evaluator();

        send_to_party(setup, tag1, share.label, pid, relay).await?;
    } else if party_id == pid {
        let share = input.as_garbler();

        let wxs: Vec<Block> = receive_from_parties(setup, tag1, BLOCK_SIZE, &[2], relay).await?;

        let t1 = wxs[0] == share.f_label;
        let t2 = wxs[0] == xor_blocks(&share.f_label, &share.delta);

        assert!(t1 || t2);
        output = Some((lsb(&wxs[0]) ^ lsb(&share.f_label)) != 0)
    }

    Ok(output)
}

pub async fn batch_output_yao_to_functionality_inner<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    pid: usize,
    input: &[YaoShare],
    tag1: MessageTag,
) -> Result<Vec<Option<bool>>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let batch_size = input.len();
    let mut output = vec![None; batch_size];
    let party_id = setup.participant_index();

    if pid == 2 {
        if party_id == 2 {
            let mut d = BinaryString::new();
            for _ in 0..batch_size {
                d.push(false);
            }
            let ds: Vec<Vec<u8>> =
                receive_from_parties(setup, tag1, d.value.len(), &[0, 1], relay).await?;
            assert_eq!(ds[0], ds[1]);
            d.value = ds[0].clone();

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

            send_to_party(setup, tag1, msg.value, 2, relay).await?;
        }
    } else if party_id == 2 {
        let mut msg = vec![0u8; BLOCK_SIZE * batch_size];

        for i in 0..batch_size {
            let share = input[i].as_evaluator();
            msg[BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)].copy_from_slice(&share.label);
        }
        send_to_party(setup, tag1, msg, pid, relay).await?;
    } else if party_id == pid {
        let wxs: Vec<Vec<u8>> =
            receive_from_parties(setup, tag1, BLOCK_SIZE * batch_size, &[2], relay).await?;

        for i in 0..batch_size {
            let share = input[i].as_garbler();

            let mut wx = Block::default();
            wx.copy_from_slice(&wxs[0][BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)]);

            let t1 = wx == share.f_label;
            let t2 = wx == xor_blocks(&share.f_label, &share.delta);

            assert!(t1 || t2);
            output[i] = Some((lsb(&wx) ^ lsb(&share.f_label)) != 0);
        }
    }

    Ok(output)
}

pub async fn batch_output_yao_to_functionality<T, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut R,
    pid: usize,
    input: &[YaoShare],
) -> Result<Vec<Option<bool>>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let mut r = FilteredMsgRelay::new(relay);

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_TO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    r.ask_messages(setup, tag1, true).await?;

    let output = batch_output_yao_to_functionality_inner(setup, &mut r, pid, input, tag1).await?;
    Ok(output)
}
