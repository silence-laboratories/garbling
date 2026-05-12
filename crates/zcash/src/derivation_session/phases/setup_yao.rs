// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use garbled_circuit::functionality::utils_dep::ProtocolError;

use crate::derivation_session::{
    Context,
    message::{Message, MessageBody, SetupYaoMessage},
    phase::{Phase, PhaseHandleResult},
    phases::common_randomness::CommonRandomnessState,
    serde_types::{SerializableBlock, SerializableYaoSetup},
};

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SetupYaoState {
    WaitCrs,
    WaitPrf { comm_crs: SerializableBlock },
}

impl SetupYaoState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
    ) -> Result<Phase, ProtocolError> {
        match ctx.party_id() {
            2 => {
                let comm_crs = ctx.derive_block(b"setup-yao/comm-crs", 0);
                for to in [0, 1] {
                    outgoing.push(Message {
                        from: ctx.party_id(),
                        to,
                        body: MessageBody::SetupYao(
                            SetupYaoMessage::CommCrs(comm_crs),
                        ),
                    });
                }
                ctx.yao_setup =
                    Some(SerializableYaoSetup::Evaluator { comm_crs });
                CommonRandomnessState::start(ctx, outgoing)
            }
            0 | 1 => Ok(Phase::SetupYao(SetupYaoState::WaitCrs)),
            _ => Err(ProtocolError::InvalidMessage),
        }
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        message: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        match self {
            SetupYaoState::WaitCrs => {
                if message.from == 2 {
                    let MessageBody::SetupYao(SetupYaoMessage::CommCrs(
                        comm_crs,
                    )) = message.body
                    else {
                        return Err(ProtocolError::InvalidMessage);
                    };
                    self.after_crs(ctx, outgoing, comm_crs)
                        .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
                } else {
                    let party_id = ctx.party_id();

                    // matches!() will make code much harder to understand
                    #[allow(clippy::match_like_matches_macro)]
                    #[rustfmt::skip]
                    let is_early_message = match (
                        party_id,
                        message.from,
                        &message.body,
                    ) {
                        (0, 2, MessageBody::CommonRandomness(_)) => true,
                        (1, 0, MessageBody::CommonRandomness(_)) => true,
                        (1, 0, MessageBody::SetupYao(SetupYaoMessage::PrfSeed(_))) => true,
                        _ => false,
                    };

                    if is_early_message {
                        Ok(PhaseHandleResult::NotReady(message))
                    } else {
                        Err(ProtocolError::InvalidMessage)
                    }
                }
            }
            SetupYaoState::WaitPrf { comm_crs } => {
                if matches!(message.body, MessageBody::CommonRandomness(_))
                    && ctx.party_id() == 1
                    && message.from == 0
                {
                    Ok(PhaseHandleResult::NotReady(message))
                } else if message.from == 0 {
                    let MessageBody::SetupYao(SetupYaoMessage::PrfSeed(
                        prf_seed,
                    )) = message.body
                    else {
                        return Err(ProtocolError::InvalidMessage);
                    };
                    ctx.setup_garbler(*comm_crs, prf_seed);
                    CommonRandomnessState::start(ctx, outgoing)
                        .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
                } else {
                    Err(ProtocolError::InvalidMessage)
                }
            }
        }
    }

    fn after_crs(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        comm_crs: SerializableBlock,
    ) -> Result<Phase, ProtocolError> {
        match ctx.party_id() {
            0 => {
                let prf_seed = ctx.derive_32(b"setup-yao/prf-seed", 0);
                outgoing.push(Message {
                    from: ctx.party_id(),
                    to: 1,
                    body: MessageBody::SetupYao(SetupYaoMessage::PrfSeed(
                        prf_seed,
                    )),
                });
                ctx.setup_garbler(comm_crs, prf_seed);
                CommonRandomnessState::start(ctx, outgoing)
            }
            1 => Ok(Phase::SetupYao(SetupYaoState::WaitPrf { comm_crs })),
            _ => Err(ProtocolError::InvalidMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation_session::message::CommonRandomnessMessage;
    use pasta_curves::pallas::Scalar;

    fn test_context(party_id: u8) -> Context {
        Context {
            party_id,
            shamir_share: Scalar::from(1u64).into(),
            seed: [7u8; 32],
            yao_setup: None,
        }
    }

    #[test]
    fn rejects_wait_crs_wrong_sender() {
        let mut ctx = test_context(0);
        let mut state = SetupYaoState::WaitCrs;
        let mut outgoing = Vec::new();
        let err = state
            .handle_message(
                &mut ctx,
                &mut outgoing,
                Message {
                    from: 1,
                    to: 0,
                    body: MessageBody::SetupYao(SetupYaoMessage::CommCrs(
                        SerializableBlock([0; 16]),
                    )),
                },
            )
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_wait_crs_wrong_body() {
        let mut ctx = test_context(0);
        let mut state = SetupYaoState::WaitCrs;
        let mut outgoing = Vec::new();
        let err = state
            .handle_message(
                &mut ctx,
                &mut outgoing,
                Message {
                    from: 2,
                    to: 0,
                    body: MessageBody::CommonRandomness(
                        CommonRandomnessMessage::KeyNext([0; 32]),
                    ),
                },
            )
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn buffers_wait_crs_early_prf_for_party_one() {
        let mut ctx = test_context(1);
        let mut state = SetupYaoState::WaitCrs;
        let mut outgoing = Vec::new();
        let message = Message {
            from: 0,
            to: 1,
            body: MessageBody::SetupYao(SetupYaoMessage::PrfSeed([0; 32])),
        };

        let result = state
            .handle_message(&mut ctx, &mut outgoing, message.clone())
            .unwrap();

        assert!(
            matches!(result, PhaseHandleResult::NotReady(m) if m == message)
        );
        assert!(outgoing.is_empty());
    }

    #[test]
    fn rejects_wait_prf_wrong_sender() {
        let mut ctx = test_context(1);
        let mut state = SetupYaoState::WaitPrf {
            comm_crs: SerializableBlock([0; 16]),
        };
        let mut outgoing = Vec::new();
        let err = state
            .handle_message(
                &mut ctx,
                &mut outgoing,
                Message {
                    from: 2,
                    to: 1,
                    body: MessageBody::SetupYao(SetupYaoMessage::PrfSeed(
                        [0; 32],
                    )),
                },
            )
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }
}
