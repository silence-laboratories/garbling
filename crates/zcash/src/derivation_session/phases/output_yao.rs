// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::pallas::{Base, Scalar};

use orchard::{
    keys::FullViewingKey,
    primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
};

use garbled_circuit::{
    functionality::utils_dep::ProtocolError,
    utilities::{
        types::YaoShare,
        utils::{lsb, label_matches_wire},
    },
};

use crate::{
    derivation_session::{
        Context, DerivedOrchardKeys,
        message::{Message, MessageBody, OutputYaoMessage},
        phase::{Phase, PhaseHandleResult},
        serde_types::{SerializableBlock, SerializableYaoShare},
    },
    utils::bits_to_bytes_le,
};

const COMPONENT_BITS: usize = 512;
const OUTPUT_BITS: usize = COMPONENT_BITS * 3;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum OutputVerificationState {
    GarblerWaitLabel {
        verification: SerializableYaoShare,
        component_bits: Vec<SerializableYaoShare>,
    },
    EvaluatorWaitBits {
        component_bits: Vec<SerializableYaoShare>,
        from_p0: Option<OutputYaoMessage>,
        from_p1: Option<OutputYaoMessage>,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BatchOutputYaoState {
    GarblerWaitLabels {
        component_bits: Vec<SerializableYaoShare>,
    },
    EvaluatorWaitBits {
        from_p0: Option<OutputYaoMessage>,
        from_p1: Option<OutputYaoMessage>,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DecodeOutputState {
    bits: Vec<bool>,
}

impl OutputVerificationState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        output: std::collections::HashMap<
            u32,
            garbled_circuit::utilities::types::YaoShare,
        >,
    ) -> Result<Phase, ProtocolError> {
        let circuit = crate::zcash::build_zcash_import_function();
        let out_yao = circuit
            .output_gate_ids()
            .iter()
            .map(|v| {
                SerializableYaoShare::from(output.get(v).unwrap().clone())
            })
            .collect::<Vec<_>>();
        let (verification, component_bits) = out_yao
            .split_first()
            .expect("zcash import circuit should produce a verification bit");
        if ctx.party_id() == 2 {
            let label = verification_label(*verification)?;
            for to in [0, 1] {
                outgoing.push(Message {
                    from: ctx.party_id(),
                    to,
                    body: MessageBody::OutputVerification(
                        OutputYaoMessage::Label(label),
                    ),
                });
            }
            Ok(Phase::OutputVerification(
                OutputVerificationState::EvaluatorWaitBits {
                    component_bits: component_bits.to_vec(),
                    from_p0: None,
                    from_p1: None,
                },
            ))
        } else {
            Ok(Phase::OutputVerification(
                OutputVerificationState::GarblerWaitLabel {
                    verification: *verification,
                    component_bits: component_bits.to_vec(),
                },
            ))
        }
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        input: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        if matches!(input.body, MessageBody::BatchOutput(_))
            && input.from != ctx.party_id()
        {
            return Ok(PhaseHandleResult::NotReady(input));
        }
        match self {
            OutputVerificationState::GarblerWaitLabel {
                verification,
                component_bits,
            } => {
                if input.from != 2
                    || !matches!(
                        input.body,
                        MessageBody::OutputVerification(_)
                    )
                {
                    return Err(ProtocolError::InvalidMessage);
                }
                let MessageBody::OutputVerification(OutputYaoMessage::Label(
                    label,
                )) = input.body
                else {
                    return Err(ProtocolError::InvalidMessage);
                };
                let bit = garbler_verify_one(*verification, label)?;
                outgoing.push(Message {
                    from: ctx.party_id(),
                    to: 2,
                    body: MessageBody::OutputVerification(
                        OutputYaoMessage::Bit(bit),
                    ),
                });
                if !bit {
                    return Err(ProtocolError::VerificationError);
                }
                BatchOutputYaoState::start(
                    ctx,
                    outgoing,
                    component_bits.clone(),
                )
                .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
            }
            OutputVerificationState::EvaluatorWaitBits {
                component_bits,
                from_p0,
                from_p1,
            } => {
                route_output_verification(from_p0, from_p1, Some(input))?;
                if from_p0.is_none() || from_p1.is_none() {
                    return Ok(PhaseHandleResult::Consumed(None));
                }
                let b0 = extract_bit(from_p0)?;
                let b1 = extract_bit(from_p1)?;
                if b0 != b1 {
                    return Err(ProtocolError::InconsistentMessage);
                }
                if !b0 {
                    return Err(ProtocolError::VerificationError);
                }
                BatchOutputYaoState::start(
                    ctx,
                    outgoing,
                    component_bits.clone(),
                )
                .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
            }
        }
    }
}

impl BatchOutputYaoState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        component_bits: Vec<SerializableYaoShare>,
    ) -> Result<Phase, ProtocolError> {
        if ctx.party_id() == 2 {
            let labels = component_bits
                .iter()
                .map(|share| verification_label(*share))
                .collect::<Result<Vec<_>, _>>()?;
            for to in [0, 1] {
                outgoing.push(Message {
                    from: ctx.party_id(),
                    to,
                    body: MessageBody::BatchOutput(OutputYaoMessage::Labels(
                        labels.clone(),
                    )),
                });
            }
            Ok(Phase::BatchOutput(BatchOutputYaoState::EvaluatorWaitBits {
                from_p0: None,
                from_p1: None,
            }))
        } else {
            Ok(Phase::BatchOutput(BatchOutputYaoState::GarblerWaitLabels {
                component_bits,
            }))
        }
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        input: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        match self {
            BatchOutputYaoState::GarblerWaitLabels { component_bits } => {
                if input.from != 2
                    || !matches!(input.body, MessageBody::BatchOutput(_))
                {
                    return Err(ProtocolError::InvalidMessage);
                }
                let MessageBody::BatchOutput(OutputYaoMessage::Labels(
                    labels,
                )) = input.body
                else {
                    return Err(ProtocolError::InvalidMessage);
                };
                let bits = garbler_verify_many(component_bits, &labels)?;
                let encoded = encode_bits(&bits);
                outgoing.push(Message {
                    from: ctx.party_id(),
                    to: 2,
                    body: MessageBody::BatchOutput(OutputYaoMessage::Bits(
                        encoded,
                    )),
                });
                Ok(PhaseHandleResult::Consumed(Some(Phase::DecodeOutput(
                    DecodeOutputState { bits },
                ))))
            }
            BatchOutputYaoState::EvaluatorWaitBits { from_p0, from_p1 } => {
                route_batch_output(from_p0, from_p1, Some(input))?;
                if from_p0.is_none() || from_p1.is_none() {
                    return Ok(PhaseHandleResult::Consumed(None));
                }
                let bits0 = extract_bits(from_p0)?;
                let bits1 = extract_bits(from_p1)?;
                if bits0 != bits1 {
                    return Err(ProtocolError::InconsistentMessage);
                }
                Ok(PhaseHandleResult::Consumed(Some(Phase::DecodeOutput(
                    DecodeOutputState {
                        bits: decode_bits(&bits0, OUTPUT_BITS)?,
                    },
                ))))
            }
        }
    }
}

impl DecodeOutputState {
    pub(crate) fn decode(&self) -> Result<DerivedOrchardKeys, ProtocolError> {
        if self.bits.len() != OUTPUT_BITS {
            return Err(ProtocolError::InvalidMessage);
        }

        let (ask_bits, rem) = self.bits.split_at(COMPONENT_BITS);
        let (nk_bits, rivk_bits) = rem.split_at(COMPONENT_BITS);
        let ask_i = bits_to_bytes_le(ask_bits);
        let nk_i = bits_to_bytes_le(nk_bits);
        let rivk_i = bits_to_bytes_le(rivk_bits);
        let ask = Scalar::from_uniform_bytes(&ask_i.try_into().unwrap());
        let nk = Base::from_uniform_bytes(&nk_i.try_into().unwrap());
        let rivk = Scalar::from_uniform_bytes(&rivk_i.try_into().unwrap());

        let mut ask_eff = ask;
        let ak_bytes = loop {
            let signing_key: SigningKey<SpendAuth> =
                ask_eff.to_repr().try_into().unwrap();
            let vk: VerificationKey<SpendAuth> = (&signing_key).into();
            let ak_bytes: [u8; 32] = (&vk).into();

            if (ak_bytes[31] >> 7) == 1 {
                ask_eff = -ask_eff;
                continue;
            }

            break ak_bytes;
        };

        if ask.is_zero().into() {
            return Err(ProtocolError::VerificationError);
        }

        let mut fvk_bytes = [0u8; 96];
        fvk_bytes[0..32].copy_from_slice(&ak_bytes);
        fvk_bytes[32..64].copy_from_slice(&nk.to_repr());
        fvk_bytes[64..96].copy_from_slice(&rivk.to_repr());

        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or(ProtocolError::VerificationError)?;

        let internal_ivk = fvk.to_ivk(orchard::keys::Scope::Internal);
        let external_ivk = fvk.to_ivk(orchard::keys::Scope::External);

        for ivk in [&internal_ivk, &external_ivk] {
            let ivk_bytes = ivk.to_bytes();

            if ivk_bytes == [0; 64] {
                return Err(ProtocolError::VerificationError);
            }

            if orchard::keys::IncomingViewingKey::from_bytes(&ivk_bytes)
                .into_option()
                .is_none()
            {
                return Err(ProtocolError::VerificationError);
            }
        }

        Ok(DerivedOrchardKeys {
            ask: ask.to_repr(),
            nk: nk.to_repr(),
            rivk: rivk.to_repr(),
            internal_ivk: internal_ivk.to_bytes(),
            external_ivk: external_ivk.to_bytes(),
        })
    }
}

fn verification_label(
    share: SerializableYaoShare,
) -> Result<SerializableBlock, ProtocolError> {
    match YaoShare::from(share) {
        YaoShare::E(e) => Ok(SerializableBlock(e.label)),
        _ => Err(ProtocolError::InvalidShare),
    }
}

fn route_output_verification(
    p0: &mut Option<OutputYaoMessage>,
    p1: &mut Option<OutputYaoMessage>,
    input: Option<Message>,
) -> Result<(), ProtocolError> {
    let Some(message) = input else {
        return Ok(());
    };
    let MessageBody::OutputVerification(body) = message.body else {
        return Err(ProtocolError::InvalidMessage);
    };
    if message.from == 0 {
        if p0.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else if message.from == 1 {
        if p1.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else {
        Err(ProtocolError::InvalidMessage)
    }
}

fn route_batch_output(
    p0: &mut Option<OutputYaoMessage>,
    p1: &mut Option<OutputYaoMessage>,
    input: Option<Message>,
) -> Result<(), ProtocolError> {
    let Some(message) = input else {
        return Ok(());
    };
    let MessageBody::BatchOutput(body) = message.body else {
        return Err(ProtocolError::InvalidMessage);
    };
    if message.from == 0 {
        if p0.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else if message.from == 1 {
        if p1.replace(body).is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        Ok(())
    } else {
        Err(ProtocolError::InvalidMessage)
    }
}

fn extract_bit(
    pending: &mut Option<OutputYaoMessage>,
) -> Result<bool, ProtocolError> {
    let Some(OutputYaoMessage::Bit(bit)) = pending.take() else {
        return Err(ProtocolError::InvalidMessage);
    };
    Ok(bit)
}

fn extract_bits(
    pending: &mut Option<OutputYaoMessage>,
) -> Result<Vec<u8>, ProtocolError> {
    let Some(OutputYaoMessage::Bits(bits)) = pending.take() else {
        return Err(ProtocolError::InvalidMessage);
    };
    Ok(bits)
}

pub(crate) fn garbler_verify_one(
    share: SerializableYaoShare,
    label: SerializableBlock,
) -> Result<bool, ProtocolError> {
    let YaoShare::G(share) = YaoShare::from(share) else {
        return Err(ProtocolError::InvalidShare);
    };
    let wx = label.0;
    if !label_matches_wire(&wx, &share.f_label, &share.delta) {
        return Err(ProtocolError::InvalidShare);
    }
    Ok((lsb(&wx) ^ lsb(&share.f_label)) != 0)
}

pub(crate) fn garbler_verify_many(
    shares: &[SerializableYaoShare],
    labels: &[SerializableBlock],
) -> Result<Vec<bool>, ProtocolError> {
    if shares.len() != labels.len() {
        return Err(ProtocolError::InvalidMessage);
    }
    shares
        .iter()
        .zip(labels)
        .map(|(share, label)| garbler_verify_one(*share, *label))
        .collect()
}

pub(crate) fn encode_bits(input: &[bool]) -> Vec<u8> {
    let mut value = vec![0u8; input.len().div_ceil(8)];
    for (idx, bit) in input.iter().copied().enumerate() {
        if bit {
            value[idx / 8] |= 1 << (idx % 8);
        }
    }
    value
}

fn decode_bits(input: &[u8], len: usize) -> Result<Vec<bool>, ProtocolError> {
    if input.len() != len.div_ceil(8) {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok((0..len)
        .map(|idx| (input[idx / 8] >> (idx % 8)) & 1 == 1)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_output_bit_lengths() {
        let short = decode_bits(&[], OUTPUT_BITS).unwrap_err();
        assert!(matches!(short, ProtocolError::InvalidMessage));

        let long = decode_bits(&[0u8; 193], OUTPUT_BITS).unwrap_err();
        assert!(matches!(long, ProtocolError::InvalidMessage));
    }

    #[test]
    fn decode_rejects_corrupt_persisted_bit_count() {
        let state = DecodeOutputState { bits: Vec::new() };
        let err = state.decode().unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    #[test]
    fn output_routes_reject_cross_phase_bodies() {
        let msg = Message {
            from: 0,
            to: 2,
            body: MessageBody::OutputVerification(OutputYaoMessage::Bit(
                true,
            )),
        };

        let mut p0 = None;
        let mut p1 = None;
        let err =
            route_batch_output(&mut p0, &mut p1, Some(msg)).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }
}
