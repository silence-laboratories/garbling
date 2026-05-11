// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

mod context;
mod message;
mod phase;
mod phases;
mod serde_types;

use pasta_curves::pallas::Scalar;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use garbled_circuit::functionality::utils_dep::ProtocolError;

use self::{
    context::Context,
    message::MessageBody,
    phase::{Phase, PhaseHandleResult},
    phases::setup_yao::SetupYaoState,
    serde_types::SerializableBlock,
};

pub use message::Message;

pub const DERIVATION_PARTIES: u8 = 3;

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedOrchardKeys {
    pub ask: [u8; 32],
    pub nk: [u8; 32],
    pub rivk: [u8; 32],
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    context: Context,
    phase: Phase,
    pending: Vec<Message>,
}

pub(crate) fn setup_delta_from_seed(prf_seed: [u8; 32]) -> SerializableBlock {
    let mut rng = ChaCha8Rng::from_seed(prf_seed);
    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);
    delta[0] |= 1;
    SerializableBlock(delta)
}

pub(crate) fn prev_party(party_id: u8) -> u8 {
    (party_id + 2) % 3
}

pub(crate) fn next_party(party_id: u8) -> u8 {
    (party_id + 1) % 3
}

#[derive(Clone, Debug, PartialEq)]
pub enum DerivationStatus {
    Waiting,
    Complete,
    Aborted(u8),
}

impl Session {
    /// Creates a new derivation session for one party.
    ///
    /// Returns the session and any initial outbound messages.
    pub fn new(
        party_id: u8,
        shamir_share: Scalar,
        seed: [u8; 32],
    ) -> Result<(Self, Vec<Message>), ProtocolError> {
        if party_id >= DERIVATION_PARTIES {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut context = Context {
            party_id,
            shamir_share: shamir_share.into(),
            seed,
            yao_setup: None,
            common_randomness: None,
        };
        let mut outgoing = Vec::new();
        let phase = SetupYaoState::start(&mut context, &mut outgoing)?;
        let session = Self {
            context,
            phase,
            pending: Vec::new(),
        };

        Ok((session, outgoing))
    }

    /// Processes one incoming message and appends any generated outbound messages.
    pub fn handle_messages(
        &mut self,
        messages: Vec<Message>,
        outgoing: &mut Vec<Message>,
    ) -> Result<DerivationStatus, ProtocolError> {
        match &self.phase {
            Phase::Done(_) => return Ok(DerivationStatus::Complete),
            Phase::Aborted(f) => return Ok(DerivationStatus::Aborted(*f)),
            _ => {}
        }

        for message in &messages {
            if matches!(message.body, MessageBody::Abort) {
                // Abort is broadcast; the `to` field is ignored.
                self.pending.clear();
                self.phase = Phase::Aborted(message.from);
                return Ok(DerivationStatus::Aborted(message.from));
            }

            if message.to != self.context.party_id() {
                return Err(ProtocolError::InvalidMessage);
            }
        }

        for message in messages {
            self.pending.push(message);
        }

        let mut progressed = true;
        while progressed {
            progressed = false;
            let mut idx = 0;
            while idx < self.pending.len() {
                let message = self.pending.remove(idx);
                match self.phase.handle_message(
                    &mut self.context,
                    outgoing,
                    message,
                )? {
                    PhaseHandleResult::Consumed(next) => {
                        if let Some(next) = next {
                            self.phase = next;
                            if matches!(self.phase, Phase::Done(_)) {
                                self.pending.clear();
                                return Ok(DerivationStatus::Complete);
                            }
                        }
                        progressed = true;
                        break;
                    }
                    PhaseHandleResult::NotReady(message) => {
                        self.pending.insert(idx, message);
                        idx += 1;
                    }
                }
            }
        }

        match &self.phase {
            Phase::Done(_) => Ok(DerivationStatus::Complete),
            _ => Ok(DerivationStatus::Waiting),
        }
    }

    /// Returns the derived Orchard keys, if the session is complete.
    pub fn derived_keys(&self) -> Option<&DerivedOrchardKeys> {
        match &self.phase {
            Phase::Done(keys) => Some(keys),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use pasta_curves::pallas::{Base, Scalar};
    use rand::{SeedableRng, rngs::StdRng};

    use garbled_circuit::functionality::utils::run_init;
    use sl_messages::{
        relay::SimpleMessageRelay, setup::ProtocolParticipant,
    };

    use crate::{
        derivation::run_derivation_with_seed,
        derivation_session::message::{
            CommonRandomnessMessage, Message, MessageBody, SetupYaoMessage,
        },
    };

    use super::*;

    fn generate_shamir_shares(seed: [u8; 32]) -> [Scalar; 3] {
        let mut rng = StdRng::from_seed(seed);
        let secret = Scalar::random(&mut rng);
        let coeff = Scalar::random(&mut rng);
        core::array::from_fn::<_, 3, _>(|idx| {
            let point = Scalar::from((idx + 1) as u64);
            secret + coeff * point
        })
    }

    fn run_session_derivation(
        shares: [Scalar; 3],
        seed: [u8; 32],
    ) -> (DerivedOrchardKeys, Vec<Session>) {
        let mut sessions = Vec::new();
        let mut queue = Vec::new();
        for (party_id, share) in shares.into_iter().enumerate() {
            let (session, outgoing) =
                Session::new(party_id as u8, share, seed).unwrap();
            queue.extend(outgoing);
            sessions.push(session);
        }

        let mut steps = 0usize;
        while !queue.is_empty() && steps < 100 {
            steps += 1;
            let pos = queue
                .iter()
                .position(|message| {
                    let to = usize::from(message.to);
                    let mut probe = sessions[to].clone();
                    let mut probe_outgoing = Vec::new();
                    probe
                        .handle_messages(
                            vec![message.clone()],
                            &mut probe_outgoing,
                        )
                        .is_ok()
                })
                .expect("at least one queued message is deliverable");
            let message = queue.remove(pos);
            let to = usize::from(message.to);
            sessions[to]
                .handle_messages(vec![message], &mut queue)
                .unwrap();
        }

        assert!(queue.is_empty());
        assert!(steps < 100);
        assert!(
            sessions
                .iter()
                .all(|session| session.derived_keys().is_some())
        );
        let keys = sessions[0].derived_keys().unwrap().clone();
        assert_eq!(Some(&keys), sessions[1].derived_keys());
        assert_eq!(Some(&keys), sessions[2].derived_keys());
        (keys, sessions)
    }

    async fn run_relay_derivation(
        shares: [Scalar; 3],
        seeds: [[u8; 32]; 3],
    ) -> [(Scalar, Base, Scalar); 3] {
        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            let party_id = setup.participant_index();
            parties.spawn(run_derivation_with_seed(
                setup,
                shares[party_id],
                relay,
                seeds[party_id],
            ));
        }

        let mut keys = [None, None, None];
        while let Some(result) = parties.join_next().await {
            let share = result
                .expect("relay derivation task should not panic")
                .expect("relay derivation should complete");
            let slot = keys
                .iter()
                .position(Option::is_none)
                .expect("space for three parties");
            keys[slot] = Some(share);
        }

        keys.map(|key| key.expect("all parties completed"))
    }

    fn derived_tuple(keys: &DerivedOrchardKeys) -> (Scalar, Base, Scalar) {
        let ask = Option::<Scalar>::from(Scalar::from_repr(keys.ask))
            .expect("session ask should be canonical");
        let nk = Option::<Base>::from(Base::from_repr(keys.nk))
            .expect("session nk should be canonical");
        let rivk = Option::<Scalar>::from(Scalar::from_repr(keys.rivk))
            .expect("session rivk should be canonical");
        (ask, nk, rivk)
    }

    #[test]
    fn rejects_invalid_party_id() {
        let err = Session::new(3, Scalar::ONE, [7u8; 32])
            .expect_err("party id 3 is invalid");
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_wrong_destination() {
        let (mut session, _outgoing) =
            Session::new(0, Scalar::ONE, [7u8; 32]).unwrap();
        let msg = Message {
            from: 2,
            to: 1,
            body: MessageBody::SetupYao(SetupYaoMessage::CommCrs(
                SerializableBlock([0; 16]),
            )),
        };
        let mut outgoing = Vec::new();
        let err = session
            .handle_messages(vec![msg], &mut outgoing)
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn starts_setup_for_evaluator() {
        let (_session, outgoing) =
            Session::new(2, Scalar::ONE, [7u8; 32]).unwrap();

        assert_eq!(outgoing.len(), 3);
    }

    #[cfg(feature = "session")]
    #[test]
    fn session_roundtrips_through_serde() {
        let (session, _outgoing) =
            Session::new(0, Scalar::ONE, [7u8; 32]).unwrap();
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&session, &mut bytes).unwrap();
        let restored: Session =
            ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(session, restored);
    }

    #[test]
    fn completed_session_stays_complete_after_finish() {
        let shares = generate_shamir_shares([3u8; 32]);
        let (keys, mut sessions) = run_session_derivation(shares, [10u8; 32]);

        let mut outgoing = Vec::new();
        let status = sessions[0]
            .handle_messages(Vec::new(), &mut outgoing)
            .unwrap();
        assert!(matches!(status, DerivationStatus::Complete));
        assert!(outgoing.is_empty());
        assert_eq!(sessions[0].derived_keys(), Some(&keys));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn session_matches_run_derivation_with_seed() {
        let shares = generate_shamir_shares([13u8; 32]);

        let relay_keys = run_relay_derivation(
            shares,
            [[21u8; 32], [22u8; 32], [23u8; 32]],
        )
        .await;
        assert_eq!(relay_keys[0], relay_keys[1]);
        assert_eq!(relay_keys[0], relay_keys[2]);

        let (session_keys, _sessions) =
            run_session_derivation(shares, [21u8; 32]);
        assert_eq!(derived_tuple(&session_keys), relay_keys[0]);
    }

    #[test]
    fn buffers_early_common_randomness_message() {
        let shares = generate_shamir_shares([17u8; 32]);
        let mut sessions = Vec::new();
        let mut queue = Vec::new();
        for (party_id, share) in shares.into_iter().enumerate() {
            let (session, outgoing) =
                Session::new(party_id as u8, share, [19u8; 32]).unwrap();
            queue.extend(outgoing);
            sessions.push(session);
        }

        let crs_to_p0 = queue
            .iter()
            .position(|message| {
                message.to == 0
                    && matches!(
                        message.body,
                        MessageBody::SetupYao(SetupYaoMessage::CommCrs(_))
                    )
            })
            .expect("CRS for p0 should exist");
        let message = queue.remove(crs_to_p0);
        sessions[0]
            .handle_messages(vec![message], &mut queue)
            .unwrap();

        let key_next_to_p1 = queue
            .iter()
            .position(|message| {
                message.to == 1
                    && matches!(
                        message.body,
                        MessageBody::CommonRandomness(
                            CommonRandomnessMessage::KeyNext(_)
                        )
                    )
            })
            .expect("early key-next for p1 should exist");
        let message = queue.remove(key_next_to_p1);
        let status = sessions[1]
            .handle_messages(vec![message], &mut queue)
            .unwrap();
        assert!(matches!(status, DerivationStatus::Waiting));

        let crs_to_p1 = queue
            .iter()
            .position(|message| {
                message.to == 1
                    && matches!(
                        message.body,
                        MessageBody::SetupYao(SetupYaoMessage::CommCrs(_))
                    )
            })
            .expect("CRS for p1 should exist");
        let message = queue.remove(crs_to_p1);
        sessions[1]
            .handle_messages(vec![message], &mut queue)
            .unwrap();

        let prf_seed_to_p1 = queue
            .iter()
            .position(|message| {
                message.to == 1
                    && matches!(
                        message.body,
                        MessageBody::SetupYao(SetupYaoMessage::PrfSeed(_))
                    )
            })
            .expect("PRF seed for p1 should exist");
        let message = queue.remove(prf_seed_to_p1);
        sessions[1]
            .handle_messages(vec![message], &mut queue)
            .unwrap();

        let mut steps = 0usize;
        while !queue.is_empty() && steps < 200 {
            steps += 1;
            let pos = queue
                .iter()
                .position(|message| {
                    let to = usize::from(message.to);
                    let mut probe = sessions[to].clone();
                    let mut probe_outgoing = Vec::new();
                    probe
                        .handle_messages(
                            vec![message.clone()],
                            &mut probe_outgoing,
                        )
                        .is_ok()
                })
                .expect("at least one queued message is deliverable");
            let message = queue.remove(pos);
            let to = usize::from(message.to);
            sessions[to]
                .handle_messages(vec![message], &mut queue)
                .unwrap();
        }

        assert!(queue.is_empty());
        assert!(steps < 200);
        assert!(sessions.iter().all(|s| s.derived_keys().is_some()));
    }

    #[test]
    fn duplicate_stale_message_is_rejected() {
        let (mut s0, o0) = Session::new(0, Scalar::ONE, [10; 32]).unwrap();
        let (_s1, _o1) = Session::new(1, Scalar::from(2), [11; 32]).unwrap();
        let (_s2, o2) = Session::new(2, Scalar::from(3), [12; 32]).unwrap();

        let crs_to_p0 = o0
            .iter()
            .chain(o2.iter())
            .find(|message| message.to == 0)
            .cloned()
            .unwrap();

        let mut outgoing = Vec::new();
        let first = s0
            .handle_messages(vec![crs_to_p0.clone()], &mut outgoing)
            .unwrap();
        let second = s0
            .handle_messages(vec![crs_to_p0], &mut outgoing)
            .unwrap_err();

        assert!(matches!(first, DerivationStatus::Waiting));
        assert!(matches!(second, ProtocolError::InvalidMessage));
    }

    #[test]
    fn handles_abort_messages() {
        let (mut p0, _outgoing) =
            Session::new(0, Scalar::ONE, [10; 32]).unwrap();

        let message = Message::abort(2);
        let mut outgoing = Vec::new();
        let status =
            p0.handle_messages(vec![message], &mut outgoing).unwrap();
        assert!(matches!(status, DerivationStatus::Aborted(2)));
        assert!(outgoing.is_empty());

        let status = p0.handle_messages(Vec::new(), &mut outgoing).unwrap();
        assert!(matches!(status, DerivationStatus::Aborted(2)));
    }
}
