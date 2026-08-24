// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use ff::PrimeField;
use garbled_circuit::{
    functionality::utils_dep::ProtocolError,
    utilities::{
        commitments::{Commitment, HashCommitment},
        hash_function::AesHash,
        types::{
            Block, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare, YaoShare,
        },
        utils::xor_blocks,
    },
};

use crate::{
    derivation_session::{
        Context,
        message::{
            BatchInputYaoMessage, InputYaoAllMsg1, InputYaoAllMsg2, Message,
            MessageBody,
        },
        phase::{Phase, PhaseHandleResult},
        phases::circuit_eval::CircuitEvalState,
        serde_types::{
            SerializableBlock, SerializableScalar, SerializableYaoShare,
        },
    },
    utils::bytes_to_bits_le,
};

const SHARE_BITS: usize = 256;
const INPUT_BITS: usize = SHARE_BITS * 2;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BatchInputYaoState {
    GarblerWaitEvalBits {
        all_ip: Vec<bool>,
        i1: Vec<SerializableYaoShare>,
        i2: Vec<SerializableYaoShare>,
    },
    EvaluatorWaitMsg1 {
        all_ip_len: usize,
        msg1_to_p0: Vec<bool>,
        msg1_to_p1: Vec<bool>,
        from_p0: Option<BatchInputYaoMessage>,
        from_p1: Option<BatchInputYaoMessage>,
    },
    EvaluatorWaitMsg2 {
        all_ip_len: usize,
        msg1_to_p0: Vec<bool>,
        msg1_to_p1: Vec<bool>,
        i1: Vec<SerializableYaoShare>,
        i2: Vec<SerializableYaoShare>,
        from_p0: Option<BatchInputYaoMessage>,
        from_p1: Option<BatchInputYaoMessage>,
    },
}

impl BatchInputYaoState {
    pub(crate) fn start(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        rss_prev: SerializableScalar,
        rss_next: SerializableScalar,
    ) -> Result<Phase, ProtocolError> {
        let all_ip = all_input_bits(rss_prev, rss_next)?;
        if ctx.party_id() == 2 {
            Self::start_evaluator(ctx, outgoing, all_ip)
        } else {
            Self::start_garbler(ctx, outgoing, all_ip)
        }
    }

    pub(crate) fn handle_message(
        &mut self,
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        input: Message,
    ) -> Result<PhaseHandleResult, ProtocolError> {
        let is_future_message = match ctx.party_id() {
            0 | 1 => matches!(
                input.body,
                MessageBody::OutputVerification(_)
                    | MessageBody::BatchOutput(_)
            ),
            2 => matches!(
                input.body,
                MessageBody::CircuitEval(_)
                    | MessageBody::OutputVerification(_)
                    | MessageBody::BatchOutput(_)
            ),
            _ => false,
        };
        if is_future_message && input.from != ctx.party_id() {
            return Ok(PhaseHandleResult::NotReady(input));
        }
        match self {
            BatchInputYaoState::GarblerWaitEvalBits { all_ip, i1, i2 } => {
                if input.from != 2
                    || !matches!(input.body, MessageBody::BatchInputYao(_))
                {
                    return Err(ProtocolError::InvalidMessage);
                }
                let MessageBody::BatchInputYao(
                    BatchInputYaoMessage::EvaluatorBits(bits),
                ) = input.body
                else {
                    return Err(ProtocolError::InvalidMessage);
                };
                let eval_bits = decode_bits(&bits, all_ip.len())?;
                let mut yao_setup = ctx
                    .yao_setup
                    .as_ref()
                    .ok_or(ProtocolError::MissingMessage)?
                    .try_to_yao_setup()?;
                let comm = commitment(ctx)?;
                let g = yao_setup
                    .as_garbler_mut()
                    .ok_or(ProtocolError::InvalidMessage)?;
                let (msg2, i3) =
                    create_msg2(&comm, all_ip.len(), &eval_bits, g)?;
                ctx.yao_setup = Some(yao_setup.into());
                outgoing.push(Message {
                    from: ctx.party_id(),
                    to: 2,
                    body: MessageBody::BatchInputYao(
                        BatchInputYaoMessage::GarblerI3Commit(msg2),
                    ),
                });
                CircuitEvalState::start(
                    ctx,
                    outgoing,
                    make_inputs(std::mem::take(i1), std::mem::take(i2), i3)?,
                )
                .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
            }
            BatchInputYaoState::EvaluatorWaitMsg1 {
                all_ip_len,
                msg1_to_p0,
                msg1_to_p1,
                from_p0,
                from_p1,
            } => {
                route_batch(from_p0, from_p1, input)?;

                match (&from_p0, &from_p1) {
                    (
                        Some(BatchInputYaoMessage::GarblerInputCommit(
                            msg1_p0,
                        )),
                        Some(BatchInputYaoMessage::GarblerInputCommit(
                            msg1_p1,
                        )),
                    ) => {
                        let comm = commitment(ctx)?;
                        let (i1, i2) = process_msg1(
                            &comm,
                            msg1_p0,
                            msg1_p1,
                            *all_ip_len,
                        )?;
                        *self = BatchInputYaoState::EvaluatorWaitMsg2 {
                            all_ip_len: *all_ip_len,
                            msg1_to_p0: std::mem::take(msg1_to_p0),
                            msg1_to_p1: std::mem::take(msg1_to_p1),
                            i1,
                            i2,
                            from_p0: None,
                            from_p1: None,
                        };
                        Ok(PhaseHandleResult::Consumed(None))
                    }
                    _ => Ok(PhaseHandleResult::Consumed(None)),
                }
            }
            BatchInputYaoState::EvaluatorWaitMsg2 {
                all_ip_len,
                msg1_to_p0,
                msg1_to_p1,
                i1,
                i2,
                from_p0,
                from_p1,
            } => {
                route_batch(from_p0, from_p1, input)?;

                match (&from_p0, &from_p1) {
                    (
                        Some(BatchInputYaoMessage::GarblerI3Commit(msg2_p0)),
                        Some(BatchInputYaoMessage::GarblerI3Commit(msg2_p1)),
                    ) => {
                        let comm = commitment(ctx)?;
                        let i3 = process_msg2(
                            &comm,
                            msg2_p0,
                            msg2_p1,
                            *all_ip_len,
                            msg1_to_p0,
                            msg1_to_p1,
                        )?;
                        CircuitEvalState::start(
                            ctx,
                            outgoing,
                            make_inputs(i1.clone(), i2.clone(), i3)?,
                        )
                        .map(|phase| PhaseHandleResult::Consumed(Some(phase)))
                    }
                    _ => Ok(PhaseHandleResult::Consumed(None)),
                }
            }
        }
    }

    fn start_garbler(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        all_ip: Vec<bool>,
    ) -> Result<Phase, ProtocolError> {
        let mut yao_setup = ctx
            .yao_setup
            .as_ref()
            .ok_or(ProtocolError::MissingMessage)?
            .try_to_yao_setup()?;
        let comm = commitment(ctx)?;
        let g = yao_setup
            .as_garbler_mut()
            .ok_or(ProtocolError::InvalidMessage)?;
        let (msg1, i1, i2) = create_msg1(&comm, g, &all_ip);
        ctx.yao_setup = Some(yao_setup.into());
        outgoing.push(Message {
            from: ctx.party_id(),
            to: 2,
            body: MessageBody::BatchInputYao(
                BatchInputYaoMessage::GarblerInputCommit(msg1),
            ),
        });
        Ok(Phase::BatchInputYao(
            BatchInputYaoState::GarblerWaitEvalBits { all_ip, i1, i2 },
        ))
    }

    fn start_evaluator(
        ctx: &mut Context,
        outgoing: &mut Vec<Message>,
        all_ip: Vec<bool>,
    ) -> Result<Phase, ProtocolError> {
        let (msg1_to_p0, msg1_to_p1) = evaluator_bits(&all_ip);
        outgoing.push(Message {
            from: ctx.party_id(),
            to: 0,
            body: MessageBody::BatchInputYao(
                BatchInputYaoMessage::EvaluatorBits(encode_bits(&msg1_to_p0)),
            ),
        });
        outgoing.push(Message {
            from: ctx.party_id(),
            to: 1,
            body: MessageBody::BatchInputYao(
                BatchInputYaoMessage::EvaluatorBits(encode_bits(&msg1_to_p1)),
            ),
        });
        Ok(Phase::BatchInputYao(
            BatchInputYaoState::EvaluatorWaitMsg1 {
                all_ip_len: all_ip.len(),
                msg1_to_p0,
                msg1_to_p1,
                from_p0: None,
                from_p1: None,
            },
        ))
    }
}

fn commitment(
    ctx: &Context,
) -> Result<HashCommitment<AesHash>, ProtocolError> {
    Ok(HashCommitment::new(AesHash::new(ctx.comm_crs()?.0)))
}

fn all_input_bits(
    rss_prev: SerializableScalar,
    rss_next: SerializableScalar,
) -> Result<Vec<bool>, ProtocolError> {
    Ok(bytes_to_bits_le(&rss_prev.to_scalar()?.to_repr())
        .chain(bytes_to_bits_le(&rss_next.to_scalar()?.to_repr()))
        .collect())
}

fn evaluator_bits(input: &[bool]) -> (Vec<bool>, Vec<bool>) {
    // Sampled independently of the session seed so a reused seed cannot
    // repeat this one-time pad. Matches `run_batch_input_from_all_yao`.
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut p0 = Vec::with_capacity(input.len());
    let mut p1 = Vec::with_capacity(input.len());
    for &bit in input {
        let x0 = rng.gen_bool(0.5);
        p0.push(x0);
        p1.push(x0 ^ bit);
    }
    (p0, p1)
}

fn create_msg1<C: Commitment>(
    comm: &C,
    yao_setup: &mut GarblerSetup,
    input: &[bool],
) -> (
    InputYaoAllMsg1,
    Vec<SerializableYaoShare>,
    Vec<SerializableYaoShare>,
) {
    let mut com_i1_0 = Vec::with_capacity(input.len());
    let mut com_i2_0 = Vec::with_capacity(input.len());
    let mut com_i1_1 = Vec::with_capacity(input.len());
    let mut com_i2_1 = Vec::with_capacity(input.len());
    let mut w = Vec::new();
    let mut wit = Vec::new();
    let mut i1 = Vec::with_capacity(input.len());
    let mut i2 = Vec::with_capacity(input.len());

    for pass in 0..2 {
        for &bit in input {
            let b = yao_setup.prf.next_u32() % 2 == 0;
            let w0 = next_block(&mut yao_setup.prf);
            let witness_0 = next_block(&mut yao_setup.prf);
            let witness_1 = next_block(&mut yao_setup.prf);
            let comm_0 = if !b {
                comm.commit(&w0, &witness_0)
            } else {
                comm.commit(&xor_blocks(&w0, &yao_setup.delta), &witness_1)
            };
            let comm_1 = if b {
                comm.commit(&w0, &witness_0)
            } else {
                comm.commit(&xor_blocks(&w0, &yao_setup.delta), &witness_1)
            };
            if pass == 0 {
                com_i1_0.push(SerializableBlock(comm_0));
                com_i1_1.push(SerializableBlock(comm_1));
                i1.push(
                    YaoShare::G(YaoGarblerShare {
                        delta: yao_setup.delta,
                        f_label: w0,
                    })
                    .into(),
                );
            } else {
                com_i2_0.push(SerializableBlock(comm_0));
                com_i2_1.push(SerializableBlock(comm_1));
                i2.push(
                    YaoShare::G(YaoGarblerShare {
                        delta: yao_setup.delta,
                        f_label: w0,
                    })
                    .into(),
                );
            }
            if yao_setup.party_id == pass {
                if bit {
                    w.push(SerializableBlock(xor_blocks(
                        &w0,
                        &yao_setup.delta,
                    )));
                    wit.push(SerializableBlock(witness_1));
                } else {
                    w.push(SerializableBlock(w0));
                    wit.push(SerializableBlock(witness_0));
                }
            }
        }
    }

    (
        InputYaoAllMsg1 {
            com_i1_0,
            com_i2_0,
            com_i1_1,
            com_i2_1,
            w,
            wit,
        },
        i1,
        i2,
    )
}

fn create_msg2<C: Commitment>(
    comm: &C,
    len: usize,
    msg1_recv: &[bool],
    yao_setup: &mut GarblerSetup,
) -> Result<(InputYaoAllMsg2, Vec<SerializableYaoShare>), ProtocolError> {
    if msg1_recv.len() != len {
        return Err(ProtocolError::InvalidMessage);
    }
    let mut out = InputYaoAllMsg2 {
        comm_1f: Vec::with_capacity(len),
        comm_1t: Vec::with_capacity(len),
        comm_2f: Vec::with_capacity(len),
        comm_2t: Vec::with_capacity(len),
        w: Vec::with_capacity(len),
        wit: Vec::with_capacity(len),
    };
    let mut shares = Vec::with_capacity(len);
    for &choice in msg1_recv.iter().take(len) {
        let w01 = next_block(&mut yao_setup.prf);
        let w02 = next_block(&mut yao_setup.prf);
        let witness1f = next_block(&mut yao_setup.prf);
        let comm1f = comm.commit(&w01, &witness1f);
        let witness1t = next_block(&mut yao_setup.prf);
        let comm1t =
            comm.commit(&xor_blocks(&yao_setup.delta, &w01), &witness1t);
        let witness2f = next_block(&mut yao_setup.prf);
        let comm2f = comm.commit(&w02, &witness2f);
        let witness2t = next_block(&mut yao_setup.prf);
        let comm2t =
            comm.commit(&xor_blocks(&yao_setup.delta, &w02), &witness2t);
        let (msg, witness) = if yao_setup.party_id == 0 {
            if choice {
                (xor_blocks(&w01, &yao_setup.delta), witness1t)
            } else {
                (w01, witness1f)
            }
        } else if choice {
            (xor_blocks(&w02, &yao_setup.delta), witness2t)
        } else {
            (w02, witness2f)
        };
        shares.push(
            YaoShare::G(YaoGarblerShare {
                delta: yao_setup.delta,
                f_label: xor_blocks(&w01, &w02),
            })
            .into(),
        );
        out.comm_1f.push(SerializableBlock(comm1f));
        out.comm_1t.push(SerializableBlock(comm1t));
        out.comm_2f.push(SerializableBlock(comm2f));
        out.comm_2t.push(SerializableBlock(comm2t));
        out.w.push(SerializableBlock(msg));
        out.wit.push(SerializableBlock(witness));
    }
    Ok((out, shares))
}

fn process_msg1<C: Commitment>(
    comm: &C,
    p0: &InputYaoAllMsg1,
    p1: &InputYaoAllMsg1,
    len: usize,
) -> Result<
    (Vec<SerializableYaoShare>, Vec<SerializableYaoShare>),
    ProtocolError,
> {
    validate_msg1(p0, len)?;
    validate_msg1(p1, len)?;
    if p0.com_i1_0 != p1.com_i1_0
        || p0.com_i1_1 != p1.com_i1_1
        || p0.com_i2_0 != p1.com_i2_0
        || p0.com_i2_1 != p1.com_i2_1
    {
        return Err(ProtocolError::InconsistentMessage);
    }
    let i1 = process_input_labels(
        comm,
        &p1.com_i1_0,
        &p1.com_i1_1,
        &p0.w,
        &p0.wit,
        len,
    )?;
    let i2 = process_input_labels(
        comm,
        &p0.com_i2_0,
        &p0.com_i2_1,
        &p1.w,
        &p1.wit,
        len,
    )?;
    Ok((i1, i2))
}

fn validate_msg1(
    msg: &InputYaoAllMsg1,
    len: usize,
) -> Result<(), ProtocolError> {
    if msg.com_i1_0.len() != len
        || msg.com_i2_0.len() != len
        || msg.com_i1_1.len() != len
        || msg.com_i2_1.len() != len
        || msg.w.len() != len
        || msg.wit.len() != len
    {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(())
}

fn process_input_labels<C: Commitment>(
    comm: &C,
    c0: &[SerializableBlock],
    c1: &[SerializableBlock],
    w: &[SerializableBlock],
    wit: &[SerializableBlock],
    len: usize,
) -> Result<Vec<SerializableYaoShare>, ProtocolError> {
    if c0.len() != len
        || c1.len() != len
        || w.len() != len
        || wit.len() != len
    {
        return Err(ProtocolError::InvalidMessage);
    }
    c0.iter()
        .zip(c1)
        .zip(w)
        .zip(wit)
        .map(|(((c0, c1), msg), wit)| {
            let v0 = comm.verify(&msg.0, &wit.0, &c0.0);
            let v1 = comm.verify(&msg.0, &wit.0, &c1.0);
            if v0 == v1 {
                return Err(ProtocolError::InvalidMessage);
            }
            Ok(YaoShare::E(YaoEvaluatorShare { label: msg.0 }).into())
        })
        .collect()
}

fn process_msg2<C: Commitment>(
    comm: &C,
    p0: &InputYaoAllMsg2,
    p1: &InputYaoAllMsg2,
    len: usize,
    msg1_p0: &[bool],
    msg1_p1: &[bool],
) -> Result<Vec<SerializableYaoShare>, ProtocolError> {
    if msg1_p0.len() != len || msg1_p1.len() != len {
        return Err(ProtocolError::InvalidMessage);
    }
    validate_msg2(p0, len)?;
    validate_msg2(p1, len)?;
    if p0.comm_1f != p1.comm_1f
        || p0.comm_1t != p1.comm_1t
        || p0.comm_2f != p1.comm_2f
        || p0.comm_2t != p1.comm_2t
    {
        return Err(ProtocolError::InconsistentMessage);
    }

    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let valid0 = if msg1_p0[i] {
            comm.verify(&p0.w[i].0, &p0.wit[i].0, &p1.comm_1t[i].0)
        } else {
            comm.verify(&p0.w[i].0, &p0.wit[i].0, &p1.comm_1f[i].0)
        };
        let valid1 = if msg1_p1[i] {
            comm.verify(&p1.w[i].0, &p1.wit[i].0, &p0.comm_2t[i].0)
        } else {
            comm.verify(&p1.w[i].0, &p1.wit[i].0, &p0.comm_2f[i].0)
        };
        if !valid0 || !valid1 {
            return Err(ProtocolError::InvalidMessage);
        }
        out.push(
            YaoShare::E(YaoEvaluatorShare {
                label: xor_blocks(&p0.w[i].0, &p1.w[i].0),
            })
            .into(),
        );
    }
    Ok(out)
}

fn validate_msg2(
    msg: &InputYaoAllMsg2,
    len: usize,
) -> Result<(), ProtocolError> {
    if msg.comm_1f.len() != len
        || msg.comm_1t.len() != len
        || msg.comm_2f.len() != len
        || msg.comm_2t.len() != len
        || msg.w.len() != len
        || msg.wit.len() != len
    {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(())
}

fn make_inputs(
    i1: Vec<SerializableYaoShare>,
    i2: Vec<SerializableYaoShare>,
    i3: Vec<SerializableYaoShare>,
) -> Result<[Vec<SerializableYaoShare>; 6], ProtocolError> {
    if i1.len() != INPUT_BITS
        || i2.len() != INPUT_BITS
        || i3.len() != INPUT_BITS
    {
        return Err(ProtocolError::InvalidMessage);
    }
    let (i1_prev, i1_next) = i1.split_at(SHARE_BITS);
    let (i2_prev, i2_next) = i2.split_at(SHARE_BITS);
    let (i3_prev, i3_next) = i3.split_at(SHARE_BITS);
    Ok([
        i1_next.to_vec(),
        i2_next.to_vec(),
        i3_next.to_vec(),
        i1_prev.to_vec(),
        i2_prev.to_vec(),
        i3_prev.to_vec(),
    ])
}

fn route_batch(
    p0: &mut Option<BatchInputYaoMessage>,
    p1: &mut Option<BatchInputYaoMessage>,
    message: Message,
) -> Result<(), ProtocolError> {
    let MessageBody::BatchInputYao(body) = message.body else {
        return Err(ProtocolError::InvalidMessage);
    };
    if message.from == 0 {
        if p0.is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        *p0 = Some(body);
        Ok(())
    } else if message.from == 1 {
        if p1.is_some() {
            return Err(ProtocolError::InconsistentMessage);
        }
        *p1 = Some(body);
        Ok(())
    } else {
        Err(ProtocolError::InvalidMessage)
    }
}

fn next_block(rng: &mut ChaCha8Rng) -> Block {
    let mut out = [0u8; 16];
    rng.fill_bytes(&mut out);
    out
}

fn encode_bits(input: &[bool]) -> Vec<u8> {
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

    fn msg1_with_len(len: usize) -> InputYaoAllMsg1 {
        InputYaoAllMsg1 {
            com_i1_0: vec![SerializableBlock([0; 16]); len],
            com_i2_0: vec![SerializableBlock([0; 16]); len],
            com_i1_1: vec![SerializableBlock([0; 16]); len],
            com_i2_1: vec![SerializableBlock([0; 16]); len],
            w: vec![SerializableBlock([0; 16]); len],
            wit: vec![SerializableBlock([0; 16]); len],
        }
    }

    fn msg2_with_len(len: usize) -> InputYaoAllMsg2 {
        InputYaoAllMsg2 {
            comm_1f: vec![SerializableBlock([0; 16]); len],
            comm_1t: vec![SerializableBlock([0; 16]); len],
            comm_2f: vec![SerializableBlock([0; 16]); len],
            comm_2t: vec![SerializableBlock([0; 16]); len],
            w: vec![SerializableBlock([0; 16]); len],
            wit: vec![SerializableBlock([0; 16]); len],
        }
    }

    #[test]
    fn rejects_wrong_packed_bit_lengths() {
        let short = decode_bits(&[], INPUT_BITS).unwrap_err();
        assert!(matches!(short, ProtocolError::InvalidMessage));

        let long = decode_bits(&[0u8; 65], INPUT_BITS).unwrap_err();
        assert!(matches!(long, ProtocolError::InvalidMessage));
    }

    #[test]
    fn rejects_wrong_batch_input_vector_lengths() {
        let mut msg1 = msg1_with_len(INPUT_BITS);
        msg1.w.pop();
        let err = validate_msg1(&msg1, INPUT_BITS).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));

        let mut msg2 = msg2_with_len(INPUT_BITS);
        msg2.comm_2t.pop();
        let err = validate_msg2(&msg2, INPUT_BITS).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }

    fn dummy_comm() -> HashCommitment<AesHash> {
        HashCommitment::new(AesHash::new([0u8; 16]))
    }

    #[test]
    fn process_msg1_rejects_mismatched_garbler_commitments() {
        let p0 = msg1_with_len(1);
        let mut p1 = p0.clone();
        p1.com_i1_0[0] = SerializableBlock([1; 16]);
        let err = process_msg1(&dummy_comm(), &p0, &p1, 1).unwrap_err();
        assert!(matches!(err, ProtocolError::InconsistentMessage));
    }

    #[test]
    fn process_msg2_rejects_mismatched_garbler_commitments() {
        let p0 = msg2_with_len(1);
        let mut p1 = p0.clone();
        p1.comm_1f[0] = SerializableBlock([1; 16]);
        let err =
            process_msg2(&dummy_comm(), &p0, &p1, 1, &[false], &[false])
                .unwrap_err();
        assert!(matches!(err, ProtocolError::InconsistentMessage));
    }

    #[test]
    fn rejects_short_yao_input_vectors_before_split() {
        let err =
            make_inputs(Vec::new(), Vec::new(), Vec::new()).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage));
    }
}
