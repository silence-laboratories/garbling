use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_compute_common::CommonRandomness;
use sl_messages::{
    message::MessageTag,
    pairs::Pairs,
    relay::{MessageSendError, Relay},
    signed::SignedMessage,
};

#[cfg(any(test, feature = "test-support"))]
use crate::functionality::utils_dep::SetupMessage;
use crate::functionality::utils_dep::{
    check_abort, FilteredMsgRelay, ProtocolError, ProtocolParticipant, Round, Wrap,
    ABORT_MESSAGE_TAG,
};

/// Party sends a message to other party
pub async fn send_to_party<P, R, T>(
    setup: &P,
    tag: MessageTag,
    msg: T,
    to_party: usize,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<(), MessageSendError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let mut buf = vec![0; msg.external_size()];
    msg.encode(&mut buf);

    let mut msg = SignedMessage::<(), _>::new(
        &setup.msg_id(Some(to_party), tag),
        setup.message_ttl(),
        0,
        msg.external_size(),
    );
    let (_, t) = msg.payload();
    t.copy_from_slice(&buf);
    let buffer = msg.sign(setup.signer());

    relay.send(buffer).await?;

    Ok(())
}

/// Party receives a message from other party
pub async fn receive_from_parties<P, R, T>(
    setup: &P,
    tag: MessageTag,
    message_size: usize,
    from_parties: Vec<usize>,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<Vec<T>, ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let mut p0 = Pairs::new();

    let mut round = Round::new(from_parties.len(), tag, relay);
    while let Some((msg, party_id, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_id, ProtocolError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
            continue;
        }

        // We got message with a right TAG but from not expected party.
        if !from_parties.contains(&party_id) {
            round.put_back(&msg, tag, party_id);
            continue;
        }

        let (_, buf) =
            SignedMessage::<(), _>::verify_with_trailer(&msg, setup.verifier(party_id)).unwrap();

        let (_buf, v1) = T::decode(buf, message_size).ok_or(ProtocolError::InvalidMessage)?;

        p0.push(party_id, v1);
    }

    Ok(p0.into())
}

/// Party sends a message to next party and receives a message from previous party
pub async fn p2p_send_to_next_receive_from_prev<P, R, T>(
    setup: &P,
    tag: MessageTag,
    msg: T,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<T, ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let next_party_id = (3 + 1 + setup.participant_index()) % 3;
    let prev_party_id = (3 - 1 + setup.participant_index()) % 3;
    let message_size = msg.external_size();

    let buffer = {
        let mut buf = vec![0; msg.external_size()];
        msg.encode(&mut buf);
        let mut msg = SignedMessage::<(), _>::new(
            &setup.msg_id(Some(next_party_id), tag),
            setup.message_ttl(),
            0,
            msg.external_size(),
        );
        let (_, t) = msg.payload();
        t.copy_from_slice(&buf);
        msg.sign(setup.signer())
    };

    relay.send(buffer).await?;

    let mut round = Round::new(1, tag, relay);
    while let Some((msg, party_id, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_id, ProtocolError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
            continue;
        }

        // We got message with a right TAG but from not expected party.
        if party_id != prev_party_id {
            round.put_back(&msg, tag, party_id);
            continue;
        }

        let (_, buf) =
            SignedMessage::<(), _>::verify_with_trailer(&msg, setup.verifier(party_id)).unwrap();

        let (_buf, v1) = T::decode(buf, message_size).ok_or(ProtocolError::InvalidMessage)?;

        return Ok(v1);
    }

    Err(ProtocolError::InvalidMessage)
}

/// Generate setup messages and seeds for DKG parties.
#[cfg(any(test, feature = "test-support"))]
pub fn run_init(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
    use std::time::Duration;

    use sl_messages::message::InstanceId;

    use crate::functionality::utils_dep::{NoSigningKey, NoVerifyingKey};

    let n = 3;

    let instance = instance.unwrap_or_else(rand::random);

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(n as usize)
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
                .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
        })
        .map(|setup| {
            use sha2::{Digest, Sha256};

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

/// Implementation of the Protocol 2.3.1.
pub async fn run_common_randomness<T, R>(
    setup: &T,
    seed: &[u8; 32],
    relay: &mut FilteredMsgRelay<R>,
) -> Result<CommonRandomness, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    pub const COMMON_RAND_MSG: MessageTag = MessageTag::tag(2);
    relay.ask_messages(setup, COMMON_RAND_MSG, true).await?;

    let mut rng = ChaCha20Rng::from_seed(*seed);
    let key_next: [u8; 32] = rng.random();

    let key_prev =
        p2p_send_to_next_receive_from_prev(setup, COMMON_RAND_MSG, key_next, relay).await?;

    if key_prev == key_next {
        return Err(ProtocolError::VerificationError);
    }

    Ok(CommonRandomness::new(key_prev, key_next))
}
