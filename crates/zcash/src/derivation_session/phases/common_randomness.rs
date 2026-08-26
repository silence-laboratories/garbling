// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use garbled_circuit::functionality::utils_dep::ProtocolError;

use crate::derivation_session::{
    Context,
    message::{CommonRandomnessMessage, Message, MessageBody},
    next_party,
    phase::{Phase, PhaseHandleResult},
    phases::shamir_to_rss::ShamirToRssState,
    prev_party,
    serde_types::SecretBytes32,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CommonRandomnessState {
    key_next: SecretBytes32,
    from: u8,
}

impl CommonRandomnessState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
    ) -> Result<Phase, ProtocolError> {
        let key_next = SecretBytes32::from(
            ctx.derive_32(b"common-randomness/key-next", 0),
        );

        outgoing.push(Message {
            from: ctx.party_id(),
            to: next_party(ctx.party_id()),
            body: MessageBody::CommonRandomness(
                CommonRandomnessMessage::KeyNext(key_next.clone()),
            ),
        });

        Ok(Phase::CommonRandomness(CommonRandomnessState {
            key_next,
            from: prev_party(ctx.party_id()),
        }))
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        input: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        if matches!(input.body, MessageBody::ShamirToRss(_))
            && input.from != ctx.party_id()
        {
            return Ok(PhaseHandleResult::NotReady(input));
        }

        if input.from != self.from {
            return Err(ProtocolError::InvalidMessage);
        }

        if !matches!(input.body, MessageBody::CommonRandomness(_)) {
            return Err(ProtocolError::InvalidMessage);
        }

        let MessageBody::CommonRandomness(CommonRandomnessMessage::KeyNext(
            key_prev,
        )) = input.body
        else {
            return Err(ProtocolError::InvalidMessage);
        };

        if key_prev == self.key_next {
            return Err(ProtocolError::VerificationError);
        }

        ShamirToRssState::start(
            ctx,
            outgoing,
            key_prev,
            self.key_next.clone(),
        )
        .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation_session::serde_types::SerializableBlock;
    use pasta_curves::pallas::Scalar;

    fn test_context(party_id: u8) -> Context {
        Context {
            party_id,
            shamir_share: Scalar::from(1u64).into(),
            seed: [9u8; 32].into(),
            yao_setup: None,
        }
    }

    #[test]
    fn rejects_wrong_sender() {
        let mut ctx = test_context(0);
        let mut state = CommonRandomnessState {
            key_next: [2; 32].into(),
            from: 2,
        };
        let mut outgoing = Vec::new();
        let err = state
            .handle_message(
                &mut ctx,
                &mut outgoing,
                Message {
                    from: 1,
                    to: 0,
                    body: MessageBody::CommonRandomness(
                        CommonRandomnessMessage::KeyNext([1; 32].into()),
                    ),
                },
            )
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_wrong_body() {
        let mut ctx = test_context(0);
        let mut state = CommonRandomnessState {
            key_next: [2; 32].into(),
            from: 2,
        };
        let mut outgoing = Vec::new();
        let err = state
            .handle_message(
                &mut ctx,
                &mut outgoing,
                Message {
                    from: 2,
                    to: 0,
                    body: MessageBody::SetupYao(
                        crate::derivation_session::message::SetupYaoMessage::CommCrs(
                            SerializableBlock([0; 16]),
                        ),
                    ),
                },
            )
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_equal_prev_and_next_keys() {
        let mut ctx = test_context(0);
        let mut state = CommonRandomnessState {
            key_next: [2; 32].into(),
            from: 2,
        };
        let mut outgoing = Vec::new();
        let err = state
            .handle_message(
                &mut ctx,
                &mut outgoing,
                Message {
                    from: 2,
                    to: 0,
                    body: MessageBody::CommonRandomness(
                        CommonRandomnessMessage::KeyNext([2; 32].into()),
                    ),
                },
            )
            .unwrap_err();
        assert!(matches!(err, ProtocolError::VerificationError));
    }
}
