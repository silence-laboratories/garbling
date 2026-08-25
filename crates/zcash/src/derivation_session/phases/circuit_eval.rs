// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use garbled_circuit::{
    functionality::{
        evaluate::evaluate_functionality, garble::garble_functionality,
        utils_dep::ProtocolError,
    },
    utilities::{hash_function::AesHash, types::YaoShare},
};

use crate::{
    derivation_session::{
        Context,
        message::{CircuitEvalMessage, Message, MessageBody},
        phase::{Phase, PhaseHandleResult},
        phases::output_yao::OutputVerificationState,
        serde_types::{SerializableBlock, SerializableYaoShare},
    },
    zcash::build_zcash_import_function,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CircuitEvalState {
    inputs: [Vec<SerializableYaoShare>; 6],
    hash_from_p0: Option<CircuitEvalMessage>,
    tables_from_p1: Option<CircuitEvalMessage>,
}

impl CircuitEvalState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        inputs: [Vec<SerializableYaoShare>; 6],
    ) -> Result<Phase, ProtocolError> {
        if ctx.party_id() == 2 {
            return Ok(Phase::CircuitEval(CircuitEvalState {
                inputs,
                hash_from_p0: None,
                tables_from_p1: None,
            }));
        }

        let output = garble_or_hash(ctx, outgoing, &inputs)?;
        OutputVerificationState::start(ctx, outgoing, output)
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        input: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        if matches!(input.body, MessageBody::OutputVerification(_))
            && input.from != ctx.party_id()
        {
            return Ok(PhaseHandleResult::NotReady(input));
        }
        route_circuit(
            &mut self.hash_from_p0,
            &mut self.tables_from_p1,
            Some(input),
        )?;
        if self.hash_from_p0.is_none() || self.tables_from_p1.is_none() {
            return Ok(PhaseHandleResult::Consumed(None));
        }
        let CircuitEvalMessage::Hash(expected_hash) =
            self.hash_from_p0.take().unwrap()
        else {
            return Err(ProtocolError::InvalidMessage);
        };
        let CircuitEvalMessage::GarbledTables(tables) =
            self.tables_from_p1.take().unwrap()
        else {
            return Err(ProtocolError::InvalidMessage);
        };
        let f = tables.iter().map(|b| b.0).collect::<Vec<_>>();
        let actual_hash: [u8; 32] = f
            .iter()
            .fold(Sha256::new(), Digest::chain_update)
            .finalize()
            .into();
        if actual_hash != expected_hash {
            return Err(ProtocolError::InconsistentMessage);
        }
        let circuit = build_zcash_import_function();
        let hash = AesHash::new(ctx.garble_key()?.0);
        let yao_inputs = to_yao_inputs(&self.inputs);
        let output: HashMap<u32, YaoShare> =
            evaluate_functionality(&circuit, &yao_inputs, &f, &hash)?;
        OutputVerificationState::start(ctx, outgoing, output)
            .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
    }
}

fn garble_or_hash(
    ctx: &mut Context,
    outgoing: &mut Vec<Message>,
    inputs: &[Vec<SerializableYaoShare>; 6],
) -> Result<HashMap<u32, YaoShare>, ProtocolError> {
    let mut setup = ctx
        .yao_setup
        .as_ref()
        .ok_or(ProtocolError::MissingMessage)?
        .try_to_yao_setup()?;
    let g = setup
        .as_garbler_mut()
        .ok_or(ProtocolError::InvalidMessage)?;
    let circuit = build_zcash_import_function();
    let hash = AesHash::new(ctx.garble_key()?.0);
    let yao_inputs = to_yao_inputs(inputs);
    let (f, out): (Vec<_>, HashMap<_, YaoShare>) =
        garble_functionality(&circuit, &yao_inputs, g, &hash);
    if ctx.party_id() == 0 {
        let hashval: [u8; 32] = f
            .iter()
            .fold(Sha256::new(), Digest::chain_update)
            .finalize()
            .into();
        outgoing.push(Message {
            from: ctx.party_id(),
            to: 2,
            body: MessageBody::CircuitEval(CircuitEvalMessage::Hash(hashval)),
        });
    } else {
        outgoing.push(Message {
            from: ctx.party_id(),
            to: 2,
            body: MessageBody::CircuitEval(
                CircuitEvalMessage::GarbledTables(
                    f.into_iter().map(SerializableBlock).collect(),
                ),
            ),
        });
    }
    ctx.yao_setup = Some(setup.into());
    Ok(out)
}

fn to_yao_inputs(
    inputs: &[Vec<SerializableYaoShare>; 6],
) -> [Vec<YaoShare>; 6] {
    inputs
        .clone()
        .map(|shares| shares.into_iter().map(Into::into).collect())
}

fn route_circuit(
    hash_from_p0: &mut Option<CircuitEvalMessage>,
    tables_from_p1: &mut Option<CircuitEvalMessage>,
    input: Option<Message>,
) -> Result<(), ProtocolError> {
    let Some(message) = input else {
        return Ok(());
    };
    if !matches!(message.body, MessageBody::CircuitEval(_)) {
        return Err(ProtocolError::InvalidMessage);
    }
    let MessageBody::CircuitEval(body) = message.body else {
        return Err(ProtocolError::InvalidMessage);
    };
    if message.from == 0 {
        if hash_from_p0.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else if message.from == 1 {
        if tables_from_p1.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else {
        Err(ProtocolError::InvalidMessage)
    }
}
