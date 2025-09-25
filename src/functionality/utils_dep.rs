use std::{
    collections::HashMap,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    time::Duration,
};

use bytemuck::{AnyBitPattern, NoUninit};
use crypto_bigint::U256;
use signature::{SignatureEncoding, Signer, Verifier};
use sl_compute_common::{Binary, BinaryString};
use sl_messages::{
    encrypted::{EncryptedMessage, EncryptionScheme},
    message::{InstanceId, MessageTag, MsgId},
    pairs::Pairs,
    relay::{MessageSendError, Relay},
    signed::SignedMessage,
    Bytes, BytesMut,
};
use sl_mpc_mate::ByteArray;

/// Counter for tag offset.
#[derive(Default)]
pub struct TagOffsetCounter(u32);

impl TagOffsetCounter {
    /// New counter initialized by 0.
    pub fn new() -> Self {
        Self(0)
    }

    /// Increment counter and return next value
    pub fn next_value(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(1);
        self.0
    }
}

/// the message contains error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

/// Create an Abort Message.
pub fn create_abort_message<P>(setup: &P) -> Bytes
where
    P: ProtocolParticipant,
{
    SignedMessage::<(), _>::new(
        &setup.msg_id(None, ABORT_MESSAGE_TAG),
        setup.message_ttl(),
        0,
        0,
    )
    .sign(setup.signer())
}

/// Returns passed error if msg is a vaild abort message.
pub fn check_abort<P: ProtocolParticipant, E>(
    setup: &P,
    msg: &[u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(), E> {
    SignedMessage::<(), _>::verify(msg, setup.verifier(party_id))
        .map_or(Ok(()), |_| Err(err(party_id)))
}

/// An iterator for parties in range 0..total except me.
pub struct AllOtherParties {
    total: usize,
    me: usize,
    curr: usize,
}

impl Iterator for AllOtherParties {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let val = self.curr;

            if val >= self.total {
                return None;
            }

            self.curr += 1;

            if val != self.me {
                return Some(val);
            }
        }
    }
}

impl ExactSizeIterator for AllOtherParties {
    fn len(&self) -> usize {
        self.total - 1
    }
}

/// A type that provides protocol participant details.
///
/// Construction of a value of this type should carefully validate the
/// verifying keys of all parties. It is crucial to recognize the keys
/// of all participants using either a database of known keys or X.509
/// certificates.
///
/// The type defines how messages will be signed and how to verify the
/// signatures.
///
pub trait ProtocolParticipant {
    /// Type of a signature, added at end of all broadcast messages
    /// passed between participants.
    type MessageSignature: SignatureEncoding;

    /// Type to sign broadcast messages, some kind of a SecretKey.
    type MessageSigner: Signer<Self::MessageSignature>;

    /// Type to verify signed message, a verifying key. `AsRef<[u8]>` is
    /// used to get external representation of the key to derive
    /// message ID.
    type MessageVerifier: Verifier<Self::MessageSignature> + AsRef<[u8]>;

    /// Returns total number of participants of a distributed
    /// protocol.
    fn total_participants(&self) -> usize;

    /// Returns the verifying key for messages from a participant with
    /// the given index.
    fn verifier(&self, index: usize) -> &Self::MessageVerifier;

    /// Returns a signer to sign messages from the participant.
    fn signer(&self) -> &Self::MessageSigner;

    /// Returns an index of the participant in a protocol.
    /// This is a value in range 0..self.total_participants()
    fn participant_index(&self) -> usize;

    /// Returns the protocol's execution instance ID.
    ///
    /// Each execution of a distributed protocol requires a unique
    /// instance ID to derive the IDs of all messages within that
    /// execution.
    fn instance_id(&self) -> &InstanceId;

    /// Returns message Time To Live.
    fn message_ttl(&self) -> Duration;

    /// Returns a reference to participant's own verifier.
    fn participant_verifier(&self) -> &Self::MessageVerifier {
        self.verifier(self.participant_index())
    }

    /// Returns an iterator of all participant's indexes except own one.
    fn all_other_parties(&self) -> AllOtherParties {
        AllOtherParties {
            curr: 0,
            total: self.total_participants(),
            me: self.participant_index(),
        }
    }

    /// Generates an ID for a message from this party to another party,
    /// or for a broadcast message if the receiver is `None`.
    fn msg_id(&self, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        self.msg_id_from(self.participant_index(), receiver, tag)
    }

    /// Generates an ID for a message from a given sender to a given
    /// receiver.  The receiver is identified by its index and is
    /// `None` for a broadcast message.
    fn msg_id_from(&self, sender: usize, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        let receiver = receiver
            .map(|p| self.verifier(p))
            .map(AsRef::<[u8]>::as_ref);

        MsgId::new(
            self.instance_id(),
            self.verifier(sender).as_ref(),
            receiver.as_ref().map(AsRef::as_ref),
            tag,
        )
    }

    /// Hash of the setup message received from the initiator that
    /// starts the protocol execution.
    fn setup_hash(&self) -> &[u8] {
        &[]
    }
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
        if input.len() < size {
            return None;
        }
        let (input, rest) = input.split_at(size);
        Some((rest, Self::read(input)?))
    }
}

/// Relay Errors
pub enum Error {
    /// Abort
    Abort(usize),
    /// Recv
    Recv,
    /// Send
    Send,
    /// InvalidMessage
    InvalidMessage,
}

/// Structure to receive a round of messages
pub struct Round<'a, R> {
    tag: MessageTag,
    count: usize,
    pub(crate) relay: &'a mut FilteredMsgRelay<R>,
}

impl<'a, R: Relay> Round<'a, R> {
    /// Create a new round with a given number of messages to receive.
    pub fn new(count: usize, tag: MessageTag, relay: &'a mut FilteredMsgRelay<R>) -> Self {
        Self { count, tag, relay }
    }

    /// Receive next message in the round.
    /// On success returns Ok(Some(message, party_index, is_abort_flag)).
    /// At the end of the round it returns Ok(None).
    ///
    pub async fn recv(&mut self) -> Result<Option<(BytesMut, usize, bool)>, Error> {
        Ok(if self.count > 0 {
            let msg = self.relay.recv(self.tag).await;
            if msg.is_err() {
                for (id, (p, t)) in &self.relay.expected {
                    if t == &self.tag {
                        println!("waiting for {:X} {} {:?}", id, p, t);
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

    /// Receiver all messages in the round, verify, decode and pass to
    /// given handler.
    pub async fn of_signed_messages<T, F, S, E>(
        mut self,
        setup: &S,
        mut handler: F,
    ) -> Result<(), E>
    where
        T: AnyBitPattern + NoUninit,
        S: ProtocolParticipant,
        F: FnMut(&T, usize) -> Result<(), E>,
        E: From<Error>,
    {
        while let Some((msg, party_idx, is_abort)) = self.recv().await? {
            if is_abort {
                check_abort(setup, &msg, party_idx, Error::Abort)?;
                self.put_back(&msg, ABORT_MESSAGE_TAG, party_idx);
                continue;
            }

            let vk = setup.verifier(party_idx);
            let Some(msg) = SignedMessage::<T, _>::verify(&msg, vk) else {
                // We got message with a right ID but with broken
                // signature, ignore it.
                self.put_back(&msg, self.tag, party_idx);
                continue;
            };

            handler(msg, party_idx)?;
        }

        Ok(())
    }

    /// Receiver all messages in the round, decrypt, decode and pass
    /// to given handler.
    pub async fn of_encrypted_messages<T, F, P, E, S>(
        mut self,
        setup: &P,
        scheme: &mut S,
        mut handler: F,
    ) -> Result<(), E>
    where
        T: AnyBitPattern + NoUninit,
        F: FnMut(&T, usize, &[u8], &mut S) -> Result<Option<Bytes>, E>,
        P: ProtocolParticipant,
        E: From<Error>,
        S: EncryptionScheme,
    {
        while let Some((mut msg, party_index, is_abort)) = self.recv().await? {
            if is_abort {
                check_abort(setup, &msg, party_index, Error::Abort)?;
                self.put_back(&msg, ABORT_MESSAGE_TAG, party_index);
                continue;
            }

            let Some(payload) = scheme.decrypt::<T>(msg.as_mut(), 0, party_index) else {
                // We got a message with right ID but broken content,
                // ignore it.
                self.put_back(&msg, self.tag, party_index);
                continue;
            };

            if let Some(response) = handler(payload.body(), party_index, payload.trailer(), scheme)?
            {
                self.relay.send(response).await.map_err(|_| Error::Send)?;
            }
        }

        Ok(())
    }

    /// Broadcast 4 values and collect 4 values from others in the round
    pub async fn broadcast_4<P, T1, T2, T3, T4>(
        self,
        setup: &P,
        msg: (T1, T2, T3, T4),
    ) -> Result<
        (
            Pairs<T1, usize>,
            Pairs<T2, usize>,
            Pairs<T3, usize>,
            Pairs<T4, usize>,
        ),
        Error,
    >
    where
        P: ProtocolParticipant,
        T1: Wrap,
        T2: Wrap,
        T3: Wrap,
        T4: Wrap,
    {
        let my_party_id = setup.participant_index();

        let sizes = [
            msg.0.external_size(),
            msg.1.external_size(),
            msg.2.external_size(),
            msg.3.external_size(),
        ];
        let trailer: usize = sizes.iter().sum();

        let buffer = {
            // Do not hold SignedMessage across an await point to avoid
            // forcing ProtocolParticipant::MessageSignature to be Send
            // in case if the future returned by run() have to be Send.
            let mut buffer = SignedMessage::<(), _>::new(
                &setup.msg_id(None, self.tag),
                setup.message_ttl(),
                0,
                trailer,
            );

            let (_, mut out) = buffer.payload();

            out = msg.0.encode(out);
            out = msg.1.encode(out);
            out = msg.2.encode(out);
            msg.3.encode(out);

            buffer.sign(setup.signer())
        };

        self.relay.send(buffer).await.map_err(|_| Error::Send)?;

        let (mut p0, mut p1, mut p2, mut p3) = self.recv_broadcast_4(setup, &sizes).await?;

        p0.push(my_party_id, msg.0);
        p1.push(my_party_id, msg.1);
        p2.push(my_party_id, msg.2);
        p3.push(my_party_id, msg.3);

        Ok((p0, p1, p2, p3))
    }

    /// Receive broadcasted 4 values from all parties in the round and
    /// collect them into 4 Pairs vectors.
    pub async fn recv_broadcast_4<P, T1, T2, T3, T4>(
        mut self,
        setup: &P,
        sizes: &[usize; 4],
    ) -> Result<
        (
            Pairs<T1, usize>,
            Pairs<T2, usize>,
            Pairs<T3, usize>,
            Pairs<T4, usize>,
        ),
        Error,
    >
    where
        P: ProtocolParticipant,
        T1: Wrap,
        T2: Wrap,
        T3: Wrap,
        T4: Wrap,
    {
        let mut p0 = Pairs::new();
        let mut p1 = Pairs::new();
        let mut p2 = Pairs::new();
        let mut p3 = Pairs::new();

        while let Some((msg, party_id, is_abort)) = self.recv().await? {
            if is_abort {
                check_abort(setup, &msg, party_id, Error::Abort)?;
                self.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
                continue;
            }

            let Some((_, buf)) =
                SignedMessage::<(), _>::verify_with_trailer(&msg, setup.verifier(party_id))
            else {
                // We got message with a right ID but with broken signature.
                self.put_back(&msg, self.tag, party_id);
                continue;
            };

            let (buf, v1) = T1::decode(buf, sizes[0]).ok_or(Error::InvalidMessage)?;
            let (buf, v2) = T2::decode(buf, sizes[1]).ok_or(Error::InvalidMessage)?;
            let (buf, v3) = T3::decode(buf, sizes[2]).ok_or(Error::InvalidMessage)?;
            let (_bu, v4) = T4::decode(buf, sizes[3]).ok_or(Error::InvalidMessage)?;

            p0.push(party_id, v1);
            p1.push(party_id, v2);
            p2.push(party_id, v3);
            p3.push(party_id, v4);
        }

        Ok((p0, p1, p2, p3))
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
/// Protocol errors
pub enum ProtocolError {
    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message or invalid message data length")]
    InvalidMessage,

    /// Missing message
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Verification Error
    #[error("Verification Error")]
    VerificationError,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),
}

impl From<MessageSendError> for ProtocolError {
    fn from(_err: MessageSendError) -> Self {
        ProtocolError::SendMessage
    }
}

impl From<Error> for ProtocolError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => ProtocolError::AbortProtocol(p as _),
            Error::Recv => ProtocolError::MissingMessage,
            Error::Send => ProtocolError::SendMessage,
            Error::InvalidMessage => ProtocolError::InvalidMessage,
        }
    }
}

/// custom message relay
pub struct FilteredMsgRelay<R> {
    relay: R,
    in_buf: Vec<(BytesMut, usize, MessageTag)>,
    expected: HashMap<MsgId, (usize, MessageTag)>,
}

impl<R: Relay> FilteredMsgRelay<R> {
    /// Construct a FilteredMsgRelay by wrapping up a Relay object
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            expected: HashMap::new(),
            in_buf: vec![],
        }
    }

    // /// Return underlying relay object
    // pub fn into_inner(self) -> R {
    //     self.relay
    // }

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
        self.expected.insert(id, (party_id, tag));

        Ok(())
    }

    fn put_back(&mut self, msg: &[u8], tag: MessageTag, party_id: usize) -> bool {
        // TODO Should we ASK it again?

        msg.try_into()
            .map(|id| self.expected.insert(id, (party_id, tag)))
            .is_ok()
    }

    /// Receive an expected message with given tag, and return a
    /// party-id associated with it.
    pub async fn recv(&mut self, tag: MessageTag) -> Result<(BytesMut, usize, bool), Error> {
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
        self.ask_messages_from_iter(setup, tag, setup.all_other_parties(), p2p)
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
            self.expect_message(
                setup.msg_id_from(sender_index, receiver, tag),
                tag,
                sender_index,
                setup.message_ttl(),
            )
            .await?;
        }

        Ok(count)
    }

    /// The same as `ask_messages_from_iter()` by accepts slice of indices
    pub async fn ask_messages_from_slice<'a, P, I>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        from_parties: I,
        p2p: bool,
    ) -> Result<usize, MessageSendError>
    where
        P: ProtocolParticipant,
        I: IntoIterator<Item = &'a usize>,
    {
        self.ask_messages_from_iter(setup, tag, from_parties.into_iter().copied(), p2p)
            .await
    }

    /// Create a round
    pub fn round(&mut self, count: usize, tag: MessageTag) -> Round<'_, R> {
        Round::new(count, tag, self)
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

impl<const N: usize> FixedExternalSize for ByteArray<N> {
    const SIZE: usize = N;
}

impl<const N: usize> Wrap for ByteArray<N> {
    fn external_size(&self) -> usize {
        self.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = Self::default();
        value.copy_from_slice(buffer);
        Some(value)
    }
}

impl<const N: usize> Wrap for [u8; N] {
    fn external_size(&self) -> usize {
        N
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; N];
        value.copy_from_slice(buffer);
        Some(value)
    }
}

impl<T: Wrap + FixedExternalSize> Wrap for Vec<T> {
    fn external_size(&self) -> usize {
        self.len() * T::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        for (v, b) in self.iter().zip(buffer.chunks_exact_mut(T::SIZE)) {
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
        Some(buffer[0])
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
        Some(u16::from_le_bytes(buffer[..2].try_into().unwrap()))
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
        Some(u64::from_le_bytes(buffer[..8].try_into().unwrap()))
    }
}

impl Wrap for BinaryString {
    fn external_size(&self) -> usize {
        self.get_external_size()
    }

    fn write(&self, buffer: &mut [u8]) {
        let (l, v) = buffer.split_at_mut(mem::size_of::<u64>());
        self.length.write(l);
        v[..self.length_in_bytes()].copy_from_slice(&self.value);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let (l, v) = buffer.split_at(mem::size_of::<u64>());
        let length = u64::read(l)?;
        let value = v
            .chunks_exact(1)
            .map(u8::read)
            .collect::<Option<Vec<u8>>>()?;

        Some(BinaryString { length, value })
    }
}

impl FixedExternalSize for Binary {
    const SIZE: usize = 1;
}

impl Wrap for Binary {
    fn external_size(&self) -> usize {
        1
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0] = *self as u8;
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(buffer[0] == 1)
    }
}

impl Wrap for U256 {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.to_be_bytes())
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(U256::from_be_slice(buffer))
    }
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
    fn verify(&self, _: &[u8], _: &NoSignature) -> Result<(), signature::Error> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct SetupMessage<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature> {
    n: usize,
    party_id: usize,
    sk: SK,
    vk: Vec<VK>,
    inst: InstanceId,
    ttl: Duration,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> SetupMessage<SK, VK, MS> {
    pub fn new(inst: InstanceId, sk: SK, party_id: usize, vk: Vec<VK>) -> Self {
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
