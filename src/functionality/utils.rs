// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{marker::PhantomData, time::Duration};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use signature::{SignatureEncoding, Signer, Verifier};

use sl_compute_common::{BinaryString, CommonRandomness};
use sl_messages::{
    message::{InstanceId, MessageTag, MsgHdr},
    pairs::Pairs,
    relay::{BufferedError, BufferedMsgRelay, MessageSendError, Relay},
    setup::{
        MessageRound, ProtocolParticipant, RoundMode, ABORT_MESSAGE_TAG,
    },
    signed::SignedMessage,
};

use crate::functionality::utils_dep::ProtocolError;

const MAX_BUFFERED_MESSAGES: usize = 2;

/// custom message relay
pub struct FilteredMsgRelay<R: Relay> {
    inner: BufferedMsgRelay<R>,
    abort: MessageRound,
    tag_counter: u32,
}

impl<R: Relay> FilteredMsgRelay<R> {
    /// Construct a FilteredMsgRelay by wrapping up a Relay object
    pub fn new(relay: R) -> Self {
        Self {
            inner: BufferedMsgRelay::new(relay),
            abort: MessageRound::default(),
            tag_counter: 0,
        }
    }

    pub async fn init_abort<P: ProtocolParticipant>(
        &mut self,
        setup: &P,
    ) -> Result<usize, MessageSendError> {
        self.abort = MessageRound::broadcast(setup, ABORT_MESSAGE_TAG);
        self.abort.ask_pending(&self.inner).await
    }

    pub fn tag_counter(&self) -> u32 {
        self.tag_counter
    }

    pub fn next_tag(&mut self, tag: u32) -> MessageTag {
        let next_counter = self.tag_counter.wrapping_add(1);
        self.tag_counter = next_counter;
        MessageTag::tag1(tag, next_counter)
    }
}

/// Party sends a message to other party
pub async fn send_to_party<P, R, T>(
    setup: &P,
    tag: MessageTag,
    message: &T,
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

    relay.inner.send(buffer).await?;

    Ok(())
}

pub async fn receive_from_one_party<T, P, R>(
    setup: &P,
    tag: MessageTag,
    from_party: usize,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<T, ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let round =
        MessageRound::from_parties(setup, tag, [from_party], RoundMode::P2P);

    round.ask_pending(&relay.inner).await?;

    let mut received = None;
    relay
        .inner
        .process_signed(
            setup,
            MAX_BUFFERED_MESSAGES,
            round,
            Some(&relay.abort),
            |_: &(), trailer, _| {
                let val =
                    T::read(trailer).ok_or(BufferedError::InvalidMessage)?;
                received = Some(val);
                Ok::<_, BufferedError>(())
            },
        )
        .await?;

    received.ok_or(ProtocolError::MissingMessage)
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
    let round =
        MessageRound::from_parties(setup, tag, from_parties, RoundMode::P2P);

    round.ask_pending(&relay.inner).await?;

    let mut p0 = Pairs::new();

    relay
        .inner
        .process_signed(
            setup,
            MAX_BUFFERED_MESSAGES,
            round,
            Some(&relay.abort),
            |_: &(), trailer, party_id| {
                let val =
                    T::read(trailer).ok_or(BufferedError::InvalidMessage)?;
                p0.push(party_id, val);
                Ok::<_, BufferedError>(())
            },
        )
        .await?;

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

    relay.inner.send(buffer).await?;

    receive_from_one_party(setup, tag, prev_party_id, relay).await
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
            .with_ttl(Duration::from_secs(1000))
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

    let mut rng = ChaCha20Rng::from_seed(*seed);
    let key_next: [u8; 32] = rng.r#gen();

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

pub struct Byte(pub u8);

impl FixedExternalSize for Byte {
    const SIZE: usize = 1;
}

impl Wrap for Byte {
    fn external_size(&self) -> usize {
        1
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0] = self.0;
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer.first().cloned().map(Byte)
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
        let bytes: [u8; 2] = buffer.get(..2)?.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
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
        let bytes: [u8; 4] = buffer.get(..4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
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
        let bytes: [u8; 8] = buffer.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

impl Wrap for BinaryString {
    fn external_size(&self) -> usize {
        self.value.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        self.value.write(buffer)
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let value = Vec::<u8>::read(buffer)?;
        Some(BinaryString {
            length: value.len() as u64 * 8,
            value,
        })
    }
}

impl<T1, T2> FixedExternalSize for (T1, T2)
where
    T1: FixedExternalSize,
    T2: FixedExternalSize,
{
    const SIZE: usize = T1::SIZE + T2::SIZE;
}

impl<T1, T2> Wrap for (T1, T2)
where
    T1: Wrap + FixedExternalSize,
    T2: Wrap + FixedExternalSize,
{
    fn external_size(&self) -> usize {
        T1::SIZE + T2::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        self.1.encode(self.0.encode(buffer));
    }

    fn read(b: &[u8]) -> Option<Self> {
        let (b, t1) = T1::decode(b, T1::SIZE)?;

        Some((t1, T2::read(b)?))
    }
}

impl<T1, T2, T3> FixedExternalSize for (T1, T2, T3)
where
    T1: FixedExternalSize,
    T2: FixedExternalSize,
    T3: FixedExternalSize,
{
    const SIZE: usize = T1::SIZE + T2::SIZE + T3::SIZE;
}

impl<T1, T2, T3> Wrap for (T1, T2, T3)
where
    T1: Wrap + FixedExternalSize,
    T2: Wrap + FixedExternalSize,
    T3: Wrap + FixedExternalSize,
{
    fn external_size(&self) -> usize {
        T1::SIZE + T2::SIZE + T3::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        let buffer = self.0.encode(buffer);
        let buffer = self.1.encode(buffer);
        self.2.write(buffer);
    }

    fn read(b: &[u8]) -> Option<Self> {
        let (b, t1) = T1::decode(b, T1::SIZE)?;
        let (b, t2) = T2::decode(b, T2::SIZE)?;

        Some((t1, t2, T3::read(b)?))
    }
}

impl<T1, T2, T3, T4> FixedExternalSize for (T1, T2, T3, T4)
where
    T1: FixedExternalSize,
    T2: FixedExternalSize,
    T3: FixedExternalSize,
    T4: FixedExternalSize,
{
    const SIZE: usize = T1::SIZE + T2::SIZE + T3::SIZE + T4::SIZE;
}

impl<T1, T2, T3, T4> Wrap for (T1, T2, T3, T4)
where
    T1: Wrap + FixedExternalSize,
    T2: Wrap + FixedExternalSize,
    T3: Wrap + FixedExternalSize,
    T4: Wrap + FixedExternalSize,
{
    fn external_size(&self) -> usize {
        T1::SIZE + T2::SIZE + T3::SIZE + T4::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        let buffer = self.0.encode(buffer);
        let buffer = self.1.encode(buffer);
        let buffer = self.2.encode(buffer);
        self.3.write(buffer);
    }

    fn read(b: &[u8]) -> Option<Self> {
        let (b, t1) = T1::decode(b, T1::SIZE)?;
        let (b, t2) = T2::decode(b, T2::SIZE)?;
        let (b, t3) = T3::decode(b, T3::SIZE)?;
        Some((t1, t2, t3, T4::read(b)?))
    }
}
