// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use garbled_circuit::functionality::utils_dep::ProtocolError;

use super::{
    Context, DerivedOrchardKeys, Message,
    phases::{
        batch_input_yao::BatchInputYaoState,
        circuit_eval::CircuitEvalState,
        common_randomness::CommonRandomnessState,
        output_yao::{
            BatchOutputYaoState, DecodeOutputState, OutputVerificationState,
        },
        setup_yao::SetupYaoState,
        shamir_to_rss::ShamirToRssState,
    },
};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PhaseHandleResult {
    Consumed(Option<Phase>),
    NotReady(Message),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Phase {
    SetupYao(SetupYaoState),
    CommonRandomness(CommonRandomnessState),
    ShamirToRss(ShamirToRssState),
    BatchInputYao(BatchInputYaoState),
    CircuitEval(CircuitEvalState),
    OutputVerification(OutputVerificationState),
    BatchOutput(BatchOutputYaoState),
    DecodeOutput(DecodeOutputState),
    Done(DerivedOrchardKeys),
    Aborted(u8),
}

impl Phase {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Phase::SetupYao(_) => "SetupYao",
            Phase::CommonRandomness(_) => "CommonRandomness",
            Phase::ShamirToRss(_) => "ShamirToRss",
            Phase::BatchInputYao(_) => "BatchInputYao",
            Phase::CircuitEval(_) => "CircuitEval",
            Phase::OutputVerification(_) => "OutputVerification",
            Phase::BatchOutput(_) => "BatchOutput",
            Phase::DecodeOutput(_) => "DecodeOutput",
            Phase::Done(_) => "Done",
            Phase::Aborted(_) => "Aborted",
        }
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        message: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        let result = match self {
            Phase::SetupYao(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::CommonRandomness(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::ShamirToRss(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::BatchInputYao(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::CircuitEval(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::OutputVerification(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::BatchOutput(state) => {
                state.handle_message(ctx, outgoing, message)
            }
            Phase::DecodeOutput(state) => Ok(PhaseHandleResult::Consumed(
                Some(Phase::Done(state.decode()?)),
            )),
            Phase::Done(_) => Ok(PhaseHandleResult::Consumed(None)),
            Phase::Aborted(_) => Ok(PhaseHandleResult::Consumed(None)),
        }?;

        Ok(match result {
            PhaseHandleResult::Consumed(Some(Phase::DecodeOutput(state))) => {
                PhaseHandleResult::Consumed(Some(Phase::Done(
                    state.decode()?,
                )))
            }
            other => other,
        })
    }
}
