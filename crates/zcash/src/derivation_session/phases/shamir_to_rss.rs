// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use ff::FromUniformBytes;
use pasta_curves::pallas::{Point, Scalar};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

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
        serde_types::{SecretBytes32, SerializableScalar},
    },
    shamir_to_rss::scalar_rss_to_shamir,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ShamirToRssState {
    r_prev: SerializableScalar,
    r_next: SerializableScalar,
    padded_shamir: SerializableScalar,
    from_next: Option<ShamirToRssMessage>,
    from_prev: Option<ShamirToRssMessage>,
}

impl ShamirToRssState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        key_prev: SecretBytes32,
        key_next: SecretBytes32,
    ) -> Result<Phase, ProtocolError> {
        // Only the first 32 bytes of each keyed stream are needed here.  A
        // stateful ChaCha20Rng would retain its expanded key until drop, but
        // rand_chacha 0.3 does not zeroize that state.
        let r_prev_bytes = first_chacha20_bytes(key_prev.expose());
        let r_next_bytes = first_chacha20_bytes(key_next.expose());
        let share = ctx.shamir_share().to_scalar()?;

        let r_prev = scalar_from_random_bytes(&r_prev_bytes);
        let r_next = scalar_from_random_bytes(&r_next_bytes);
        let r_shamir = scalar_rss_to_shamir::<Point>(
            r_prev,
            r_next,
            ctx.party_id() as usize,
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

        let next_party = next_party(ctx.party_id());
        let prev_party = prev_party(ctx.party_id());

        route_padded_message(
            &mut self.from_next,
            &mut self.from_prev,
            next_party,
            prev_party,
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

/// Returns the first 32 bytes of the stream used by the legacy
/// `ChaCha20Rng::from_seed(seed)` construction.
///
/// This intentionally uses a one-shot `chacha20::ChaCha20` rather than
/// `rand_chacha::ChaCha20Rng`: `ShamirToRssState::start` consumes exactly one
/// 32-byte sample, and the direct cipher is zeroized on drop through the
/// `chacha20/zeroize` feature.  With a zero counter, zero stream identifier,
/// and the same key, its output is byte-for-byte compatible with the initial
/// output of `ChaCha20Rng`.
///
/// If compatibility with the legacy derivation is ever deliberately dropped,
/// this helper can instead be replaced by a one-shot domain-separated KDF,
/// such as HKDF-SHA-512 (or HMAC-SHA-512) keyed by `seed`.  That alternative
/// would avoid ChaCha20 entirely, but it is a protocol change: both this
/// session path and the legacy `CommonRandomness`/`shamir_to_rss` path must be
/// changed together, the derivation version/domain must be bumped, and mixed
/// old/new parties must be rejected or explicitly unsupported.  The KDF must
/// still produce 64 bytes before `Scalar::from_uniform_bytes` to retain the
/// current unbiased reduction behavior.
fn first_chacha20_bytes(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0u8; 32]);
    let mut cipher = ChaCha20::new(
        chacha20::Key::from_slice(seed),
        chacha20::Nonce::from_slice(&[0u8; 12]),
    );
    cipher.apply_keystream(&mut output[..]);
    output
}

fn scalar_from_random_bytes(bytes: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"zcash.scalar_from_random_bytes.v1");
    hasher.update(bytes);

    let mut uniform_bytes = Zeroizing::new([0u8; 64]);
    uniform_bytes.copy_from_slice(&hasher.finalize());
    Scalar::from_uniform_bytes(&uniform_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation_session::serde_types::SerializableScalar;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn first_chacha20_bytes_matches_legacy_rng() {
        for seed_byte in [0, 1, 0x5a, 0xff] {
            let seed = [seed_byte; 32];
            let mut legacy = ChaCha20Rng::from_seed(seed);
            let mut expected = [0u8; 32];
            legacy.fill_bytes(&mut expected);

            assert_eq!(first_chacha20_bytes(&seed).as_ref(), &expected);
        }
    }

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
