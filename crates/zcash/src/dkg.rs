// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Serialize, de::DeserializeOwned};

use multi_party_schnorr::{
    common::{redpallas::RedPallasPoint, traits::Round},
    keygen::{self, KeygenParty, Keyshare, R0, R1, R2},
};

use garbled_circuit::functionality::utils_dep::ProtocolError;

use crate::derivation_session as drv;

pub use drv::DerivedOrchardKeys;

const PARTICIPANTS: u8 = 3;
/// Shamir threshold for the fixed 3-party DKG + derivation pipeline.
///
/// Downstream code (`reconstruct_shamir_share`, RSS conversion, batch input)
/// assumes a degree-1 polynomial (2-of-3). Other thresholds are unsound:
/// threshold 1 gives every party the full secret; threshold 3 is degree-2 and
/// fails the line-consistency check.
const SHAMIR_THRESHOLD: u8 = 2;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    from_id: u8,
    to_id: Option<u8>,
    payload: Vec<u8>,
}

pub trait MessageRouting {
    fn src_party_id(&self) -> u8;
    fn dst_party_id(&self) -> Option<u8>;
}

impl Message {
    pub fn new(payload: Vec<u8>, from: u8) -> Self {
        Self {
            from_id: from,
            to_id: None,
            payload,
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    pub fn sender(&self) -> u8 {
        self.from_id
    }

    pub fn receiver(&self) -> Option<u8> {
        self.to_id
    }

    pub fn encode<T: Serialize + MessageRouting>(msg: T) -> Self {
        let mut buffer = vec![];
        ciborium::into_writer(&msg, &mut buffer)
            .expect("CBOR serialization failure");
        Message {
            from_id: msg.src_party_id(),
            to_id: msg.dst_party_id(),
            payload: buffer,
        }
    }

    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, ProtocolError> {
        ciborium::from_reader(self.payload.as_slice())
            .map_err(|_| ProtocolError::InvalidMessage)
    }

    pub fn decode_vec<T: DeserializeOwned>(
        msgs: &[Message],
    ) -> Result<Vec<T>, ProtocolError> {
        msgs.iter().map(Self::decode).collect()
    }

    pub fn encode_vec<T: Serialize + MessageRouting>(
        msgs: Vec<T>,
    ) -> Vec<Message> {
        msgs.into_iter().map(Self::encode).collect()
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
enum Phase {
    Init(KeygenParty<R0, RedPallasPoint>),
    WaitMsg1(KeygenParty<R1<RedPallasPoint>, RedPallasPoint>),
    WaitMsg2(KeygenParty<R2, RedPallasPoint>),
    Derivation {
        share: Keyshare<RedPallasPoint>,
        drv: Box<drv::Session>,
    },
    Share {
        share: Keyshare<RedPallasPoint>,
        keys: DerivedOrchardKeys,
    },
    Failed {
        reason: String,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Session {
    phase: Phase,
    pending: Vec<Message>,
    party_id: u8,
}

impl Session {
    /// Creates a new 2-of-3 DKG session for one party.
    ///
    /// `threshold` must be [`SHAMIR_THRESHOLD`] (2). The derivation pipeline
    /// reconstructs Shamir shares by interpolating a line through two points
    /// and checking the third; it is only correct for a degree-1 sharing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        threshold: u8,
        party_id: u8,
        secret_key: Vec<u8>,
        public_keys: Vec<u8>,
        seed: Option<Vec<u8>>,
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        if threshold != SHAMIR_THRESHOLD {
            return Err(ProtocolError::InvalidMessage);
        }

        if party_id >= PARTICIPANTS {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut rng = maybe_seeded_rng(seed)?;
        let secret_key = secret_key_from_bytes(&secret_key)?;
        let public_keys = convert_public_keys(public_keys, PARTICIPANTS)?;
        let my_public_key = secret_key.public_key();

        if !public_keys
            .iter()
            .any(|(id, pk)| *id == party_id && pk == &my_public_key)
        {
            return Err(ProtocolError::InvalidMessage);
        }

        let party = KeygenParty::new(
            SHAMIR_THRESHOLD,
            PARTICIPANTS,
            party_id,
            Arc::new(secret_key),
            public_keys,
            None,
            None,
            rng.r#gen(),
            extra_data,
        )
        .map_err(|_| ProtocolError::InvalidMessage)?;

        Ok(Self {
            phase: Phase::Init(party),
            pending: Vec::new(),
            party_id,
        })
    }

    pub fn create_first_message(&mut self) -> Result<Message, ProtocolError> {
        let party = match core::mem::replace(
            &mut self.phase,
            Phase::Failed {
                reason: "invalid state".into(),
            },
        ) {
            Phase::Init(party) => party,
            Phase::Failed { reason } => {
                self.phase = Phase::Failed { reason };
                return Err(ProtocolError::InvalidMessage);
            }
            other => {
                self.phase = other;
                return Err(ProtocolError::InvalidMessage);
            }
        };

        match party.process(()) {
            Ok((next, msg)) => {
                self.phase = Phase::WaitMsg1(next);
                let msg = Message::encode(msg);
                self.pending.push(msg.clone());
                Ok(msg)
            }
            Err(err) => self.fail(err),
        }
    }

    /// Receives one message from the transport layer.
    ///
    /// Assumes the transport does not deliver duplicate messages.
    pub fn recv_message(
        &mut self,
        msg: Message,
    ) -> Result<Vec<Message>, ProtocolError> {
        if self.is_finished() {
            return Ok(vec![]);
        }

        if msg.sender() >= PARTICIPANTS || msg.sender() == self.party_id {
            return Err(ProtocolError::InvalidMessage);
        }

        if let Some(to) = msg.receiver() {
            if to != self.party_id {
                return Err(ProtocolError::InvalidMessage);
            }
        }

        self.pending.push(msg);

        if self.is_derivation() || self.pending.len() == PARTICIPANTS as usize
        {
            let messages = core::mem::take(&mut self.pending);
            let outgoing = self.handle_messages(messages)?;
            self.retain_self_broadcasts(&outgoing);
            Ok(outgoing)
        } else {
            Ok(vec![])
        }
    }

    fn handle_messages(
        &mut self,
        messages: Vec<Message>,
    ) -> Result<Vec<Message>, ProtocolError> {
        match core::mem::replace(
            &mut self.phase,
            Phase::Failed {
                reason: "invalid state".into(),
            },
        ) {
            Phase::WaitMsg1(party) => {
                let msgs = decode_vec::<keygen::KeygenMsg1>(&messages)?;
                match party.process(msgs) {
                    Ok((next, msg)) => {
                        self.phase = Phase::WaitMsg2(next);
                        Ok(vec![Message::encode(msg)])
                    }
                    Err(err) => self.fail(err),
                }
            }

            Phase::WaitMsg2(party) => {
                let msgs = decode_vec::<keygen::KeygenMsg2<RedPallasPoint>>(
                    &messages,
                )?;
                match party.process(msgs) {
                    Ok(share) => {
                        let (drv, drv_messages) = drv::Session::new(
                            self.party_id,
                            *share.shamir_share(),
                        )?;
                        self.phase = Phase::Derivation {
                            share,
                            drv: Box::new(drv),
                        };
                        let outgoing = Message::encode_vec(drv_messages);
                        self.retain_self_broadcasts(&outgoing);
                        Ok(outgoing)
                    }
                    Err(err) => self.fail(err),
                }
            }

            Phase::Derivation { share, mut drv } => {
                let msgs = decode_vec::<drv::Message>(&messages)?;
                let mut outgoing = vec![];
                match drv.handle_messages(msgs, &mut outgoing)? {
                    drv::DerivationStatus::Waiting => {
                        self.phase = Phase::Derivation { share, drv };
                    }
                    drv::DerivationStatus::Complete => {
                        let keys = drv.derived_keys().unwrap().clone();
                        self.phase = Phase::Share { share, keys };
                    }
                    drv::DerivationStatus::Aborted(by_party) => {
                        return self.fail(ProtocolError::AbortProtocol(
                            by_party as usize,
                        ));
                    }
                }
                let outgoing = Message::encode_vec(outgoing);
                self.retain_self_broadcasts(&outgoing);
                Ok(outgoing)
            }

            Phase::Init(party) => {
                self.phase = Phase::Init(party);
                Err(ProtocolError::InvalidMessage)
            }

            Phase::Share { share, keys } => {
                self.phase = Phase::Share { share, keys };
                Err(ProtocolError::InvalidMessage)
            }

            Phase::Failed { reason } => {
                self.phase = Phase::Failed { reason };
                Err(ProtocolError::InvalidMessage)
            }
        }
    }

    pub fn into_keyshare(
        self,
    ) -> Result<Keyshare<RedPallasPoint>, ProtocolError> {
        match self.phase {
            Phase::Share { share, .. } => Ok(share),
            Phase::Failed { .. } => Err(ProtocolError::InvalidMessage),
            _ => Err(ProtocolError::MissingMessage),
        }
    }

    pub fn derived_keys(&self) -> Option<&DerivedOrchardKeys> {
        match &self.phase {
            Phase::Share { keys, .. } => Some(keys),
            _ => None,
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.phase, Phase::Share { .. } | Phase::Failed { .. })
    }

    pub fn state_name(&self) -> String {
        match &self.phase {
            Phase::Init(_) => String::from("init"),
            Phase::WaitMsg1(_) => String::from("wait1"),
            Phase::WaitMsg2(_) => String::from("wait2"),
            Phase::Derivation { drv, .. } => drv.current_phase_name(),
            Phase::Share { .. } => String::from("share"),
            Phase::Failed { .. } => String::from("failed"),
        }
    }

    fn retain_self_broadcasts(&mut self, outgoing: &[Message]) {
        for msg in outgoing {
            if msg.receiver().is_none() {
                self.pending.push(msg.clone());
            }
        }
    }

    fn is_derivation(&self) -> bool {
        matches!(self.phase, Phase::Derivation { .. })
    }

    fn fail<T>(
        &mut self,
        err: impl core::fmt::Display,
    ) -> Result<T, ProtocolError> {
        let reason = format!("party: {} {}", self.party_id, err);
        self.phase = Phase::Failed { reason };
        Err(ProtocolError::InvalidMessage)
    }
}

impl MessageRouting for keygen::KeygenMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for keygen::KeygenMsg2<RedPallasPoint> {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for drv::Message {
    fn src_party_id(&self) -> u8 {
        self.sender()
    }

    fn dst_party_id(&self) -> Option<u8> {
        self.receiver()
    }
}

fn maybe_seeded_rng(
    seed: Option<Vec<u8>>,
) -> Result<ChaCha20Rng, ProtocolError> {
    let seed = match seed {
        None => rand::random(),
        Some(seed) => seed
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength)?,
    };

    Ok(ChaCha20Rng::from_seed(seed))
}

fn secret_key_from_bytes(
    bytes: &[u8],
) -> Result<crypto_box::SecretKey, ProtocolError> {
    let key: [u8; crypto_box::KEY_SIZE] =
        bytes.try_into().map_err(|_| ProtocolError::InvalidLength)?;
    Ok(crypto_box::SecretKey::from_bytes(key))
}

fn convert_public_keys(
    keys: Vec<u8>,
    participants: u8,
) -> Result<Vec<(u8, crypto_box::PublicKey)>, ProtocolError> {
    if keys.len() != participants as usize * crypto_box::KEY_SIZE {
        return Err(ProtocolError::InvalidLength);
    }

    let mut result = Vec::with_capacity(participants as usize);
    for (idx, chunk) in keys.chunks(crypto_box::KEY_SIZE).enumerate() {
        let key: [u8; crypto_box::KEY_SIZE] =
            chunk.try_into().map_err(|_| ProtocolError::InvalidLength)?;
        result.push((idx as u8, crypto_box::PublicKey::from_bytes(key)));
    }

    Ok(result)
}

fn decode_vec<T: DeserializeOwned>(
    messages: &[Message],
) -> Result<Vec<T>, ProtocolError> {
    messages
        .iter()
        .map(|msg| {
            ciborium::from_reader(msg.payload.as_slice())
                .map_err(|_| ProtocolError::InvalidMessage)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use rand::RngCore;

    use super::*;

    #[test]
    fn message_roundtrip() {
        let msg = Message::new(vec![1, 2, 3], 7);
        assert_eq!(msg.sender(), 7);
        assert_eq!(msg.receiver(), None);
        assert_eq!(msg.payload(), vec![1, 2, 3]);
    }

    #[test]
    fn decode_invalid_message_returns_error() {
        let msg = Message::new(vec![], 7);
        assert!(matches!(
            msg.decode::<u32>(),
            Err(ProtocolError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_invalid_party_id() {
        let secret = vec![0u8; crypto_box::KEY_SIZE];
        let public_keys = vec![0u8; 3 * crypto_box::KEY_SIZE];
        match Session::new(1, 3, secret, public_keys, None, None) {
            Err(ProtocolError::InvalidMessage) => {}
            other => panic!("unexpected result: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn rejects_unsupported_threshold() {
        let secret = vec![0u8; crypto_box::KEY_SIZE];
        let public_keys = vec![0u8; 3 * crypto_box::KEY_SIZE];
        for threshold in [0u8, 1, 3] {
            match Session::new(
                threshold,
                0,
                secret.clone(),
                public_keys.clone(),
                None,
                None,
            ) {
                Err(ProtocolError::InvalidMessage) => {}
                other => panic!(
                    "threshold {threshold} should be rejected, got {:?}",
                    other.map(|_| ())
                ),
            }
        }
    }

    #[test]
    fn rejects_invalid_receiver() {
        let secrets = [
            vec![7u8; crypto_box::KEY_SIZE],
            vec![8u8; crypto_box::KEY_SIZE],
            vec![9u8; crypto_box::KEY_SIZE],
        ];
        let public_keys = secrets
            .iter()
            .flat_map(|secret| {
                secret_key_from_bytes(secret)
                    .unwrap()
                    .public_key()
                    .to_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>();

        let mut session =
            Session::new(2, 0, secrets[0].clone(), public_keys, None, None)
                .unwrap();
        let msg = Message {
            from_id: 1,
            to_id: Some(2),
            payload: vec![1, 2, 3],
        };

        assert!(matches!(
            session.recv_message(msg),
            Err(ProtocolError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_invalid_sender() {
        let secret = vec![7u8; crypto_box::KEY_SIZE];
        let secret_key = secret_key_from_bytes(&secret).unwrap();
        let public = secret_key.public_key().to_bytes();
        let public_keys = [public, public, public]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let mut session =
            Session::new(2, 0, secret, public_keys, None, None).unwrap();
        let msg = Message {
            from_id: 3,
            to_id: Some(0),
            payload: vec![1, 2, 3],
        };

        assert!(matches!(
            session.recv_message(msg),
            Err(ProtocolError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_self_sender() {
        let secret = vec![7u8; crypto_box::KEY_SIZE];
        let secret_key = secret_key_from_bytes(&secret).unwrap();
        let public = secret_key.public_key().to_bytes();
        let public_keys = [public, public, public]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let mut session =
            Session::new(2, 0, secret, public_keys, None, None).unwrap();
        let msg = Message {
            from_id: 0,
            to_id: Some(0),
            payload: vec![1, 2, 3],
        };

        assert!(matches!(
            session.recv_message(msg),
            Err(ProtocolError::InvalidMessage)
        ));
    }

    #[test]
    fn ignores_messages_after_failure() {
        let secret = vec![7u8; crypto_box::KEY_SIZE];
        let secret_key = secret_key_from_bytes(&secret).unwrap();
        let public = secret_key.public_key().to_bytes();
        let public_keys = [public, public, public]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let mut session =
            Session::new(2, 0, secret, public_keys, None, None).unwrap();
        session.phase = Phase::Failed {
            reason: "done".into(),
        };

        let msg = Message {
            from_id: 1,
            to_id: Some(2),
            payload: vec![1, 2, 3],
        };

        assert!(session.recv_message(msg).unwrap().is_empty());
        assert!(matches!(session.phase, Phase::Failed { .. }));
    }

    fn generate_dkg_material(
        rng: &mut impl RngCore,
        participants: usize,
    ) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut secrets = Vec::with_capacity(participants);
        let mut public_keys =
            Vec::with_capacity(participants * crypto_box::KEY_SIZE);

        for _ in 0..participants {
            let mut secret = vec![0u8; crypto_box::KEY_SIZE];
            rng.fill_bytes(&mut secret);
            let secret_key = secret_key_from_bytes(&secret).unwrap();
            public_keys
                .extend_from_slice(&secret_key.public_key().to_bytes());
            secrets.push(secret);
        }

        (secrets, public_keys)
    }

    fn dkg_session_inner(parties: &mut [Session]) {
        let mut queue: VecDeque<Message> = VecDeque::new();
        for party in parties.iter_mut() {
            queue.push_back(party.create_first_message().unwrap());
        }

        let mut steps = 0usize;
        let max_steps = 10_000usize;

        while let Some(msg) = queue.pop_front() {
            steps += 1;
            assert!(steps <= max_steps, "dkg session exceeded step limit");

            if let Some(to) = msg.receiver() {
                let outgoing =
                    parties[usize::from(to)].recv_message(msg).unwrap();
                queue.extend(outgoing);
            } else {
                let sender = usize::from(msg.sender());
                for (pid, party) in parties.iter_mut().enumerate() {
                    if pid == sender {
                        continue;
                    }
                    let outgoing = party.recv_message(msg.clone()).unwrap();
                    queue.extend(outgoing);
                }
            }
        }

        assert!(parties.iter().all(|party| party.is_finished()));
    }

    #[test]
    fn test_dkg_session_execution() {
        let mut rng = rand::thread_rng();
        let (secrets, public_keys) = generate_dkg_material(&mut rng, 3);

        let mut parties = (0..3)
            .map(|pid| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                Session::new(
                    2,
                    pid as u8,
                    secrets[pid].clone(),
                    public_keys.clone(),
                    Some(seed.to_vec()),
                    None,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        dkg_session_inner(&mut parties);

        let keys = parties[0].derived_keys().unwrap().clone();
        assert!(
            parties
                .iter()
                .all(|party| party.derived_keys() == Some(&keys))
        );
    }
}
