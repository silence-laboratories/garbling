// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::FromUniformBytes;
use pasta_curves::pallas::{Point, Scalar};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512};

use garbled_circuit::functionality::utils_dep::ProtocolError;
use sl_secret_sharing::shamir::{
    finalize_shamir_to_rss, reconstruct_shamir_share,
};

use crate::{
    derivation_session::{
        Context,
        message::{Message, MessageBody, ShamirToRssMessage},
        next_party,
        phase::{Phase, PhaseHandleResult},
        phases::batch_input_yao::BatchInputYaoState,
        prev_party,
        serde_types::SerializableScalar,
    },
    shamir_to_rss::scalar_rss_to_shamir,
};

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ShamirToRssState {
    r_prev: SerializableScalar,
    r_next: SerializableScalar,
    padded_shamir: SerializableScalar,
    next_party: u8,
    prev_party: u8,
    from_next: Option<ShamirToRssMessage>,
    from_prev: Option<ShamirToRssMessage>,
}

impl ShamirToRssState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        share: Scalar,
        key_prev: [u8; 32],
        key_next: [u8; 32],
    ) -> Result<Phase, ProtocolError> {
        let mut f_prev = ChaCha20Rng::from_seed(key_prev);
        let mut f_next = ChaCha20Rng::from_seed(key_next);

        let mut r_prev_bytes = [0u8; 32];
        let mut r_next_bytes = [0u8; 32];
        f_prev.fill_bytes(&mut r_prev_bytes);
        f_next.fill_bytes(&mut r_next_bytes);

        let r_prev = scalar_from_random_bytes(r_prev_bytes);
        let r_next = scalar_from_random_bytes(r_next_bytes);
        let r_shamir = scalar_rss_to_shamir::<Point>(
            r_prev,
            r_next,
            usize::from(ctx.party_id()),
        );
        let padded_shamir = share + r_shamir;
        let padded_msg = ShamirToRssMessage(padded_shamir.into());

        outgoing.push(Message {
            from: ctx.party_id(),
            to: prev_party(ctx.party_id()),
            body: MessageBody::ShamirToRss(padded_msg.clone()),
        });
        outgoing.push(Message {
            from: ctx.party_id(),
            to: next_party(ctx.party_id()),
            body: MessageBody::ShamirToRss(padded_msg),
        });

        Ok(Phase::ShamirToRss(ShamirToRssState {
            r_prev: r_prev.into(),
            r_next: r_next.into(),
            padded_shamir: padded_shamir.into(),
            next_party: next_party(ctx.party_id()),
            prev_party: prev_party(ctx.party_id()),
            from_next: None,
            from_prev: None,
        }))
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        input: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        if matches!(input.body, MessageBody::BatchInputYao(_))
            && input.from != ctx.party_id()
        {
            return Ok(PhaseHandleResult::NotReady(input));
        }
        route_padded_message(
            &mut self.from_next,
            &mut self.from_prev,
            self.next_party,
            self.prev_party,
            input,
        )?;
        match (&self.from_next, &self.from_prev) {
            (
                Some(ShamirToRssMessage(share_next)),
                Some(ShamirToRssMessage(share_prev)),
            ) => {
                let padded = reconstruct_shamir_share(
                    self.padded_shamir.to_scalar()?,
                    share_next.to_scalar()?,
                    share_prev.to_scalar()?,
                    [Scalar::from(1), Scalar::from(2), Scalar::from(3)],
                    usize::from(ctx.party_id()),
                )
                .ok_or(ProtocolError::VerificationError)?;

                let (rss_prev, rss_next) = finalize_shamir_to_rss(
                    padded,
                    self.r_prev.to_scalar()?,
                    self.r_next.to_scalar()?,
                    usize::from(ctx.party_id()),
                );

                BatchInputYaoState::start(
                    ctx,
                    outgoing,
                    rss_prev.into(),
                    rss_next.into(),
                )
                .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
            }
            _ => Ok(PhaseHandleResult::Consumed(None)),
        }
    }
}

fn route_padded_message(
    from_next: &mut Option<ShamirToRssMessage>,
    from_prev: &mut Option<ShamirToRssMessage>,
    next_party: u8,
    prev_party: u8,
    message: Message,
) -> Result<(), ProtocolError> {
    let MessageBody::ShamirToRss(body) = message.body else {
        return Err(ProtocolError::InvalidMessage);
    };
    if message.from == next_party {
        if from_next.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else if message.from == prev_party {
        if from_prev.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else {
        Err(ProtocolError::InvalidMessage)
    }
}

fn scalar_from_random_bytes(bytes: [u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"zcash.scalar_from_random_bytes.v1");
    hasher.update(bytes);

    let mut uniform_bytes = [0u8; 64];
    uniform_bytes.copy_from_slice(&hasher.finalize());
    Scalar::from_uniform_bytes(&uniform_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation_session::serde_types::SerializableScalar;

    #[test]
    fn rejects_wrong_sender() {
        let mut from_next = None;
        let mut from_prev = None;
        let err = route_padded_message(
            &mut from_next,
            &mut from_prev,
            1,
            2,
            Message {
                from: 0,
                to: 1,
                body: MessageBody::ShamirToRss(ShamirToRssMessage(
                    SerializableScalar([0; 32]),
                )),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_wrong_body() {
        let mut from_next = None;
        let mut from_prev = None;
        let err = route_padded_message(
            &mut from_next,
            &mut from_prev,
            1,
            2,
            Message {
                from: 1,
                to: 0,
                body: MessageBody::SetupYao(
                    crate::derivation_session::message::SetupYaoMessage::CommCrs(
                        crate::derivation_session::serde_types::SerializableBlock(
                            [0; 16],
                        ),
                    ),
                ),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_duplicate_from_same_side() {
        let mut from_next = None;
        let mut from_prev = None;
        let msg = Message {
            from: 1,
            to: 0,
            body: MessageBody::ShamirToRss(ShamirToRssMessage(
                SerializableScalar([0; 32]),
            )),
        };
        route_padded_message(
            &mut from_next,
            &mut from_prev,
            1,
            2,
            msg.clone(),
        )
        .unwrap();
        let err =
            route_padded_message(&mut from_next, &mut from_prev, 1, 2, msg)
                .unwrap_err();
        assert!(matches!(err, ProtocolError::InconsistentMessage));
    }
}
