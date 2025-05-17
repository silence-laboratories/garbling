use std::vec;

use sl_compute::transport::{
    proto::{FilteredMsgRelay, MessageTag, Relay, Wrap},
    setup::{common::MPCEncryption, CommonSetupMessage},
    types::ProtocolError,
    utils::{receive_from_parties, send_to_party, TagOffsetCounter},
};

use crate::{
    config::constants::{OUTPUT_YAO_FUNC_MSG1, OUTPUT_YAO_FUNC_MSG2, OUTPUT_YAO_TO_FUNC_MSG1},
    utilities::{
        types::{Block, YaoShare},
        utils::{lsb, xor_blocks},
    },
};

pub async fn validate_yao_share<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
) -> Result<bool, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_id = setup.participant_index();
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    if party_id == 2 {
        send_to_party(
            setup,
            mpc_encryption,
            tag1,
            input.e_share.clone().unwrap().label,
            0,
            relay,
        )
        .await?;
        send_to_party(
            setup,
            mpc_encryption,
            tag1,
            input.e_share.clone().unwrap().label,
            1,
            relay,
        )
        .await?;
        Ok(true)
    } else {
        let out: Vec<Block> =
            receive_from_parties(setup, mpc_encryption, tag1, 32, vec![2], relay).await?;
        let share = input.g_share.clone().unwrap();
        let val1 = share.f_label == out[0];
        let val2 = xor_blocks(share.f_label, share.delta) == out[0];

        Ok(val1 || val2)
    }
}

pub async fn output_yao_functionality<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    input: &YaoShare,
) -> Result<bool, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let output;
    let party_id = setup.participant_index();
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(OUTPUT_YAO_FUNC_MSG2.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    if party_id == 0 || party_id == 1 {
        assert!(input.g_share.is_some());
        let share = input.g_share.clone().unwrap();

        let wxs: Vec<Block> =
            receive_from_parties(setup, mpc_encryption, tag1, 32, vec![2], relay).await?;

        let t1 = wxs[0] == share.f_label;
        let t2 = wxs[0] == xor_blocks(share.f_label, share.delta);

        assert!(t1 || t2);
        let out = (lsb(wxs[0]) ^ lsb(share.f_label)) as u16;

        send_to_party(setup, mpc_encryption, tag2, out, 2, relay).await?;
        output = out != 0;
    } else {
        assert!(input.e_share.is_some());
        let share = input.e_share.clone().unwrap();

        send_to_party(setup, mpc_encryption, tag1, share.label, 0, relay).await?;
        send_to_party(setup, mpc_encryption, tag1, share.label, 1, relay).await?;

        let outs: Vec<u16> = receive_from_parties(
            setup,
            mpc_encryption,
            tag2,
            0u16.external_size(),
            vec![0, 1],
            relay,
        )
        .await?;

        assert_eq!(outs[0], outs[1]);
        output = outs[0] != 0;
    }

    Ok(output)
}

pub async fn output_yao_to_functionality<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    pid: usize,
    input: &YaoShare,
) -> Result<Option<bool>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut output = None;
    let party_id = setup.participant_index();
    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(OUTPUT_YAO_TO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;

    if pid == 2 {
        if party_id == 2 {
            assert!(input.e_share.is_some());
            let share = input.e_share.clone().unwrap();

            let ds: Vec<u16> = receive_from_parties(
                setup,
                mpc_encryption,
                tag1,
                0u16.external_size(),
                vec![0, 1],
                relay,
            )
            .await?;

            assert_eq!(ds[0], ds[1]);
            output = Some((ds[0] as u8 ^ lsb(share.label)) != 0);
        } else {
            assert!(input.g_share.is_some());
            let share = input.g_share.clone().unwrap();

            send_to_party(
                setup,
                mpc_encryption,
                tag1,
                lsb(share.f_label) as u16,
                2,
                relay,
            )
            .await?;
        }
    } else if party_id == 2 {
        let share = input.e_share.clone().unwrap();

        send_to_party(setup, mpc_encryption, tag1, share.label, pid, relay).await?;
    } else if party_id == pid {
        assert!(input.g_share.is_some());
        let share = input.g_share.clone().unwrap();

        let wxs: Vec<Block> =
            receive_from_parties(setup, mpc_encryption, tag1, 32, vec![2], relay).await?;

        let t1 = wxs[0] == share.f_label;
        let t2 = wxs[0] == xor_blocks(share.f_label, share.delta);

        assert!(t1 || t2);
        output = Some((lsb(wxs[0]) ^ lsb(share.f_label)) != 0)
    }

    Ok(output)
}
