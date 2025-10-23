// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    time::Duration,
};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use signature::{SignatureEncoding, Signer, Verifier};

use sl_compute_common::{BinaryString, CommonRandomness};
use sl_messages::{
    message::{InstanceId, MessageTag, MsgHdr, MsgId},
    pairs::Pairs,
    relay::{MessageSendError, Relay},
    signed::SignedMessage,
    BytesMut,
};

use crate::functionality::utils_dep::{
    Error, ProtocolError, ProtocolParticipant,
};

/// custom message relay
pub struct FilteredMsgRelay<R> {
    relay: R,
    in_buf: Vec<(BytesMut, usize, MessageTag)>,
    expected: HashMap<MsgId, (usize, MessageTag)>,
    unexpected: HashMap<MsgId, BytesMut>,
    party_index: usize,
}

impl<R: Relay> FilteredMsgRelay<R> {
    /// Construct a FilteredMsgRelay by wrapping up a Relay object
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            expected: HashMap::new(),
            unexpected: HashMap::new(),
            in_buf: vec![],
            party_index: usize::MAX,
        }
    }

    /// Mark message with ID as expected and associate pair (party-id,
    /// tag) with it.
    pub async fn expect_message(
        &mut self,
        id: MsgId,
        tag: MessageTag,
        party_id: usize,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(&id, ttl).await?;
        if let Some(msg) = self.unexpected.remove(&id) {
            self.in_buf.push((msg, party_id, tag));
        }
        self.expected.insert(id, (party_id, tag));

        Ok(())
    }

    fn put_back(
        &mut self,
        msg: &[u8],
        tag: MessageTag,
        party_id: usize,
    ) -> bool {
        // TODO Should we ASK it again?

        msg.try_into()
            .map(|id| self.expected.insert(id, (party_id, tag)))
            .is_ok()
    }

    /// Receive an expected message with given tag, and return a
    /// party-id associated with it.
    pub async fn recv(
        &mut self,
        tag: MessageTag,
    ) -> Result<(BytesMut, usize, bool), Error> {
        if let Some(idx) = self.in_buf.iter().position(|ent| ent.2 == tag) {
            let (msg, p, _) = self.in_buf.swap_remove(idx);
            return Ok((msg, p, false));
        }

        loop {
            let msg = self.relay.next().await.ok_or(Error::Recv)?;

            if let Ok(id) = <&MsgId>::try_from(msg.as_ref()) {
                if let Some(&(p, t)) = self.expected.get(id) {
                    self.expected.remove(id);
                    match t {
                        ABORT_MESSAGE_TAG => {
                            return Ok((msg, p, true));
                        }

                        _ if t == tag => {
                            return Ok((msg, p, false));
                        }

                        _ => {
                            // some expected but not required right
                            // now message.
                            self.in_buf.push((msg, p, t));
                        }
                    }
                } else {
                    self.unexpected.insert(*id, msg);
                }
            }
        }
    }

    /// Add expected messages and Ask underlying message relay to
    /// receive them.
    pub async fn ask_messages<P: ProtocolParticipant>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        p2p: bool,
    ) -> Result<usize, MessageSendError> {
        self.ask_messages_from_iter(
            setup,
            tag,
            setup.all_other_parties(),
            p2p,
        )
        .await
    }

    /// Ask set of messages with a given `tag` from a set of `parties`.
    ///
    /// Filter out own `party_index` from `parties`.
    ///
    /// Returns number of messages with the same tag.
    ///
    pub async fn ask_messages_from_iter<P, I>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        from_parties: I,
        p2p: bool,
    ) -> Result<usize, MessageSendError>
    where
        P: ProtocolParticipant,
        I: IntoIterator<Item = usize>,
    {
        let my_party_index = setup.participant_index();
        let receiver = p2p.then_some(my_party_index);
        let mut count = 0;
        for sender_index in from_parties.into_iter() {
            if sender_index == my_party_index {
                continue;
            }

            count += 1;

            let id = setup.msg_id_from(sender_index, receiver, tag);
            self.expect_message(id, tag, sender_index, setup.message_ttl())
                .await?;
        }

        self.party_index = my_party_index;

        Ok(count)
    }
}

/// Structure to receive a round of messages
pub struct Round<'a, R> {
    tag: MessageTag,
    count: usize,
    pub(crate) relay: &'a mut FilteredMsgRelay<R>,
}

impl<'a, R: Relay> Round<'a, R> {
    /// Create a new round with a given number of messages to receive.
    pub fn new(
        count: usize,
        tag: MessageTag,
        relay: &'a mut FilteredMsgRelay<R>,
    ) -> Self {
        Self { count, tag, relay }
    }

    /// Receive next message in the round.
    /// On success returns Ok(Some(message, party_index, is_abort_flag)).
    /// At the end of the round it returns Ok(None).
    ///
    pub async fn recv(
        &mut self,
    ) -> Result<Option<(BytesMut, usize, bool)>, Error> {
        Ok(if self.count > 0 {
            let msg = self.relay.recv(self.tag).await;
            if msg.is_err() {
                for (id, (p, t)) in &self.relay.expected {
                    if t == &self.tag {
                        eprintln!("waiting for {:X} {} {:?}", id, p, t);
                    }
                }
            }
            let msg = msg?;
            self.count -= 1;
            Some(msg)
        } else {
            None
        })
    }

    /// It is possible to receive a invalid message with a correct ID.
    /// In this case, it have to put the message id back into
    /// relay.expected table and increment a counter of waiting
    /// messages in the round.
    pub fn put_back(&mut self, msg: &[u8], tag: MessageTag, party_id: usize) {
        if self.relay.put_back(msg, tag, party_id) {
            self.count += 1;
        }
    }
}

impl<R> Deref for FilteredMsgRelay<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.relay
    }
}

impl<R> DerefMut for FilteredMsgRelay<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.relay
    }
}

/// the message contains error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

// /// Create an Abort Message.
// pub fn create_abort_message<P>(setup: &P) -> Bytes
// where
//     P: ProtocolParticipant,
// {
//     SignedMessage::<(), _>::new(
//         &setup.msg_id(None, ABORT_MESSAGE_TAG),
//         setup.message_ttl(),
//         0,
//         0,
//     )
//     .sign(setup.signer())
// }

/// Returns passed error if msg is a vaild abort message.
fn check_abort<P: ProtocolParticipant, E>(
    setup: &P,
    msg: &[u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(), E> {
    SignedMessage::<(), _>::verify(msg, setup.verifier(party_id))
        .map_or(Ok(()), |_| Err(err(party_id)))
}

/// Party sends a message to other party
pub async fn send_to_party<P, R, T>(
    setup: &P,
    tag: MessageTag,
    message: T,
    to_party: usize,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<(), MessageSendError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let mut msg = SignedMessage::<(), _>::new(
        &setup.msg_id(Some(to_party), tag),
        setup.message_ttl(),
        MsgHdr::ONE_RECEIVER | (to_party as u16 & 0xff),
        message.external_size(),
    );
    let (_, t) = msg.payload();
    message.encode(t);
    let buffer = msg.sign(setup.signer());

    relay.send(buffer).await?;

    Ok(())
}

/// Party receives a message from other party
pub async fn receive_from_parties<T, P, R>(
    setup: &P,
    tag: MessageTag,
    from_parties: &[usize],
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

        let v1 = SignedMessage::<(), _>::verify_with_trailer(
            &msg,
            setup.verifier(party_id),
        )
        .and_then(|(_, buf)| T::read(buf))
        .ok_or(ProtocolError::InvalidMessage)?;

        p0.push(party_id, v1);
    }

    Ok(p0.into())
}

/// Party sends a message to next party and receives a message from previous party
pub async fn p2p_send_to_next_receive_from_prev<P, R, T>(
    setup: &P,
    tag: MessageTag,
    message: T,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<T, ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let next_party_id = (3 + 1 + setup.participant_index()) % 3;
    let prev_party_id = (3 - 1 + setup.participant_index()) % 3;

    let buffer = {
        let mut msg = SignedMessage::<(), _>::new(
            &setup.msg_id(Some(next_party_id), tag),
            setup.message_ttl(),
            MsgHdr::ONE_RECEIVER | (next_party_id as u16 & 0xff),
            message.external_size(),
        );
        let (_, t) = msg.payload();
        message.encode(t);
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

        let v1 = SignedMessage::<(), _>::verify_with_trailer(
            &msg,
            setup.verifier(party_id),
        )
        .and_then(|(_, buf)| T::read(buf))
        .ok_or(ProtocolError::InvalidMessage)?;

        return Ok(v1);
    }

    Err(ProtocolError::InvalidMessage)
}

/// Type of empty signature.
#[derive(Clone)]
pub struct NoSignature;

impl SignatureEncoding for NoSignature {
    type Repr = [u8; 0];
}

impl<'a> TryFrom<&'a [u8]> for NoSignature {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if !value.is_empty() {
            return Err(());
        }
        Ok(NoSignature)
    }
}

impl TryInto<[u8; 0]> for NoSignature {
    type Error = ();

    fn try_into(self) -> Result<[u8; 0], Self::Error> {
        Ok([0; 0])
    }
}

pub struct NoSigningKey;

impl Signer<NoSignature> for NoSigningKey {
    fn try_sign(&self, _msg: &[u8]) -> Result<NoSignature, signature::Error> {
        Ok(NoSignature)
    }
}

/// A verifying key for NoSignature. Verification always succeeds. In
/// this case verifying key used as an idenitity ID and communication
/// uses a secure transport and there is no need to verify
/// authenticity of the messages.
#[derive(Clone)]
pub struct NoVerifyingKey(Vec<u8>);

impl NoVerifyingKey {
    pub fn new(id: usize) -> Self {
        NoVerifyingKey((id as u64).to_be_bytes().into())
    }
}

impl<T: Into<Vec<u8>>> From<T> for NoVerifyingKey {
    fn from(value: T) -> Self {
        NoVerifyingKey(value.into())
    }
}

impl AsRef<[u8]> for NoVerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Verifier<NoSignature> for NoVerifyingKey {
    fn verify(
        &self,
        _: &[u8],
        _: &NoSignature,
    ) -> Result<(), signature::Error> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
> {
    n: usize,
    party_id: usize,
    sk: SK,
    vk: Vec<VK>,
    inst: InstanceId,
    ttl: Duration,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> SetupMessage<SK, VK, MS> {
    pub fn new(
        inst: InstanceId,
        sk: SK,
        party_id: usize,
        vk: Vec<VK>,
    ) -> Self {
        Self {
            n: 3,
            party_id,
            sk,
            vk,
            inst,
            ttl: Duration::from_secs(1000),
            marker: PhantomData,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_instance_id(mut self, inst: InstanceId) -> Self {
        self.inst = inst;
        self
    }
}

impl<SK, VK, MS> ProtocolParticipant for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    type MessageSignature = MS;
    type MessageSigner = SK;
    type MessageVerifier = VK;

    fn total_participants(&self) -> usize {
        self.n
    }

    fn participant_index(&self) -> usize {
        self.party_id
    }

    fn instance_id(&self) -> &InstanceId {
        &self.inst
    }

    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
    }
}

/// Generate setup messages and seeds for parties.
#[cfg(any(test, feature = "test-support"))]
pub fn run_init(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
    use std::time::Duration;

    use sl_messages::message::InstanceId;

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
            SetupMessage::new(
                InstanceId::new(instance),
                sk,
                party_id,
                party_vk.clone(),
            )
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
    const COMMON_RAND_MSG: MessageTag = MessageTag::tag(2);
    relay.ask_messages(setup, COMMON_RAND_MSG, true).await?;

    let mut rng = ChaCha20Rng::from_seed(*seed);
    let key_next: [u8; 32] = rng.gen();

    let key_prev = p2p_send_to_next_receive_from_prev(
        setup,
        COMMON_RAND_MSG,
        key_next,
        relay,
    )
    .await?;

    if key_prev == key_next {
        return Err(ProtocolError::VerificationError);
    }

    Ok(CommonRandomness::new(key_prev, key_next))
}

/// A type with fixed size of external representation.
pub trait FixedExternalSize: Sized {
    /// Size of an external representation of Self
    const SIZE: usize;
}

/// A type with some external represention.
pub trait Wrap: Sized {
    /// Size of external representation in bytes
    fn external_size(&self) -> usize;

    /// Serialize a value into passed buffer
    fn write(&self, buffer: &mut [u8]);

    /// Deserialize value from given buffer
    fn read(buffer: &[u8]) -> Option<Self>;

    /// Encode a value into passed buffer and return remaining bytes.
    fn encode<'a>(&self, buf: &'a mut [u8]) -> &'a mut [u8] {
        let (buf, rest) = buf.split_at_mut(self.external_size());
        self.write(buf);
        rest
    }

    /// Decode a value from `input` buffer using `size` bytes.
    /// Return remaining bytes and decoded value.
    fn decode(input: &[u8], size: usize) -> Option<(&[u8], Self)> {
        let (input, rest) = input.split_at_checked(size)?;
        Some((rest, Self::read(input)?))
    }
}

impl Wrap for () {
    fn external_size(&self) -> usize {
        0
    }

    fn write(&self, _buffer: &mut [u8]) {}

    fn read(_buffer: &[u8]) -> Option<Self> {
        Some(())
    }
}

impl FixedExternalSize for () {
    const SIZE: usize = 0;
}

impl<const N: usize> FixedExternalSize for [u8; N] {
    const SIZE: usize = N;
}

impl<const N: usize> Wrap for [u8; N] {
    fn external_size(&self) -> usize {
        N
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Self::try_from(buffer).ok()
    }
}

impl<T: Wrap + FixedExternalSize> Wrap for Vec<T> {
    fn external_size(&self) -> usize {
        self.len() * T::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        for (b, v) in buffer.chunks_exact_mut(T::SIZE).zip(self) {
            v.write(b);
        }
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer
            .chunks_exact(T::SIZE)
            .map(T::read)
            .collect::<Option<Vec<T>>>()
    }
}

impl FixedExternalSize for u8 {
    const SIZE: usize = 1;
}

impl Wrap for u8 {
    fn external_size(&self) -> usize {
        1
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0] = *self;
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer.first().cloned()
    }
}

impl Wrap for u16 {
    fn external_size(&self) -> usize {
        2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..2].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(u16::from_le_bytes(buffer[..2].try_into().ok()?))
    }
}

impl Wrap for u32 {
    fn external_size(&self) -> usize {
        4
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..4].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(u32::from_le_bytes(buffer[..4].try_into().ok()?))
    }
}

impl Wrap for u64 {
    fn external_size(&self) -> usize {
        8
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..8].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(u64::from_le_bytes(buffer[..4].try_into().ok()?))
    }
}

impl Wrap for BinaryString {
    fn external_size(&self) -> usize {
        4 + self.value.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        let buffer = (self.length as u32).encode(buffer);
        buffer.copy_from_slice(&self.value);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let (buffer, length) = u32::decode(buffer, 4)?;
        let value = buffer.get(..length as usize)?.to_vec();

        Some(BinaryString {
            length: length as _,
            value,
        })
    }
}
