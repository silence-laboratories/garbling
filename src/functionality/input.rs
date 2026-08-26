// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use sl_compute_common::BinaryString;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    config::constants::{
        INPUT_YAO_FROM_ALL_MSG1, INPUT_YAO_FROM_ALL_MSG2,
        INPUT_YAO_FROM_ALL_MSG3, INPUT_YAO_FROM_FUNC_MSG1,
        INPUT_YAO_FROM_FUNC_MSG2, INPUT_YAO_FUNC_MSG1,
    },
    functionality::{
        utils::{
            receive_from_one_party, receive_from_parties, send_to_party,
            Byte, FilteredMsgRelay, Wrap,
        },
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::Commitment,
        types::{
            Block, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare,
            YaoSetup, YaoShare, BLOCK_SIZE, ZBLOCK,
        },
        utils::xor_blocks,
    },
};

fn input_yao_functionality_create_msg1(
    input: bool,
    yao_setup: &mut GarblerSetup,
) -> (Zeroizing<Block>, YaoGarblerShare) {
    let w0 = Zeroizing::new(yao_setup.prf.gen::<Block>());

    let wi = Zeroizing::new(if input {
        xor_blocks(&w0, &yao_setup.delta)
    } else {
        *w0
    });

    (
        wi,
        YaoGarblerShare {
            delta: yao_setup.delta,
            f_label: *w0,
        },
    )
}

pub async fn input_yao_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: bool,
    yao_setup: &mut YaoSetup,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(INPUT_YAO_FUNC_MSG1);

    match yao_setup {
        YaoSetup::G(g) => {
            let (msg1, share) = input_yao_functionality_create_msg1(input, g);

            send_to_party(setup, tag1, &msg1, 2, relay).await?;

            Ok(YaoShare::G(share))
        }

        _ => {
            let msg1s: Vec<Zeroizing<Block>> =
                receive_from_parties(setup, tag1, &[0, 1], relay).await?;

            if msg1s.len() != 2 || msg1s[0] != msg1s[1] {
                return Err(ProtocolError::InconsistentMessage);
            }

            Ok(YaoShare::E(YaoEvaluatorShare { label: *msg1s[0] }))
        }
    }
}

pub async fn batch_input_yao_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[bool],
    yao_setup: &mut YaoSetup,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(INPUT_YAO_FUNC_MSG1);

    match yao_setup {
        YaoSetup::G(g) => {
            let (msg1, output): (Vec<Zeroizing<Block>>, Vec<YaoShare>) =
                input
                    .iter()
                    .map(|&i| input_yao_functionality_create_msg1(i, g))
                    .map(|(m, s)| (m, YaoShare::G(s)))
                    .unzip();

            send_to_party(setup, tag1, &msg1, 2, relay).await?;

            Ok(output)
        }

        YaoSetup::E(_) => {
            let msg1s: Vec<Vec<Zeroizing<Block>>> =
                receive_from_parties(setup, tag1, &[0, 1], relay).await?;

            if msg1s.len() != 2
                || msg1s[0].len() != input.len()
                || msg1s[0] != msg1s[1]
            {
                return Err(ProtocolError::InconsistentMessage);
            }

            Ok(msg1s[0]
                .iter()
                .map(|label| {
                    YaoShare::E(YaoEvaluatorShare { label: **label })
                })
                .collect())
        }
    }
}

fn input_yao_from_functionality_12_create_msg1<C>(
    comm: &C,
    yao_setup: &mut GarblerSetup,
) -> Zeroizing<InputYaoFromFunctionality12Secrets>
where
    C: Commitment,
{
    let rng = &mut yao_setup.prf;

    let b = rng.next_u32() % 2 == 0;
    let w0 = next_secret_block(rng);
    let witness_0 = next_secret_block(rng);
    let witness_1 = next_secret_block(rng);

    // a = 0 => c0 = Com(Wb) => c0 = w0 if b=0 and w1 if b=1 => c0 = if not b {w0} else {w1}
    // a = 1 => c1 = Com(W!b) => c1 = w1 if b=0 and w0 if b=0 => c1 = if not b {w1} else {w0}
    let comm_0 = if !b {
        comm.commit(&w0, &witness_0)
    } else {
        let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
        comm.commit(&label, &witness_1)
    };

    let comm_1 = if b {
        comm.commit(&w0, &witness_0)
    } else {
        let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
        comm.commit(&label, &witness_1)
    };

    Zeroizing::new((
        comm_0,
        comm_1,
        (*w0, *witness_0),
        (xor_blocks(&w0, &yao_setup.delta), *witness_1),
        b,
    ))
}

fn input_yao_from_functionality_3_create_msg1(input: bool) -> (bool, bool) {
    let mut rng = StdRng::from_entropy();
    let x1 = rng.gen_bool(0.5);
    let x2 = x1 ^ input;
    (x1, x2)
}

fn input_yao_from_functionality_3_create_msg2<C>(
    comm: &C,
    yao_setup: &mut GarblerSetup,
) -> Zeroizing<[Block; 10]>
where
    C: Commitment,
{
    let rng = &mut yao_setup.prf;

    let w01 = next_secret_block(rng);
    let w02 = next_secret_block(rng);

    let witness1f = next_secret_block(rng);
    let comm1f = comm.commit(&w01, &witness1f);

    let witness1t = next_secret_block(rng);
    let label1t = Zeroizing::new(xor_blocks(&yao_setup.delta, &w01));
    let comm1t = comm.commit(&label1t, &witness1t);

    let witness2f = next_secret_block(rng);
    let comm2f = comm.commit(&w02, &witness2f);

    let witness2t = next_secret_block(rng);
    let label2t = Zeroizing::new(xor_blocks(&yao_setup.delta, &w02));
    let comm2t = comm.commit(&label2t, &witness2t);

    Zeroizing::new([
        comm1f, comm1t, comm2f, comm2t, *w01, *w02, *witness1f, *witness1t,
        *witness2f, *witness2t,
    ])
}

type Block42 = ((Block, Block, Block, Block), (Block, Block));
type InputYaoCommitments = Vec<((Block, Block), (Block, Block))>;
type InputYaoFromFunctionality12Secrets =
    (Block, Block, (Block, Block), (Block, Block), bool);

#[cfg(test)]
type Block22 = ((Block, Block), (Block, Block));

pub async fn input_yao_from_functionality<T, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: bool,
    pid: usize,
    comm: &C,
    yao_setup: &mut YaoSetup,
) -> Result<YaoShare, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag1 = relay.next_tag(INPUT_YAO_FROM_FUNC_MSG1);
    let tag2 = relay.next_tag(INPUT_YAO_FROM_FUNC_MSG2);

    let party_id = setup.participant_index();

    if pid == 0 || pid == 1 {
        match yao_setup {
            YaoSetup::G(g) => {
                let secrets =
                    input_yao_from_functionality_12_create_msg1(comm, g);
                let (com0, com1, (w0, wit0), (w1, wit1), _b) = &*secrets;

                let send = Zeroizing::new((
                    (*com0, *com1),
                    if g.party_id == pid {
                        if input {
                            (*w1, *wit1)
                        } else {
                            (*w0, *wit0)
                        }
                    } else {
                        (ZBLOCK, ZBLOCK)
                    },
                ));

                send_to_party(setup, tag1, &send, 2, relay).await?;

                Ok(YaoShare::G(YaoGarblerShare {
                    delta: g.delta,
                    f_label: *w0,
                }))
            }

            YaoSetup::E(_e) => {
                let com_decom: Zeroizing<InputYaoCommitments> =
                    Zeroizing::new(
                        receive_from_parties(setup, tag1, &[0, 1], relay)
                            .await?,
                    );

                if com_decom.len() != 2 {
                    return Err(ProtocolError::MissingMessage);
                }

                let coms_0 = &com_decom[0].0;
                let coms_1 = &com_decom[1].0;

                if coms_0 != coms_1 {
                    return Err(ProtocolError::InconsistentMessage);
                }

                let (com0, com1) = &coms_0;

                let &(msg, wit) = &com_decom[pid].1;

                let v1 = comm.verify(&msg, &wit, com0);
                let v2 = comm.verify(&msg, &wit, com1);

                if !(v1 || v2) {
                    return Err(ProtocolError::InvalidShare);
                }
                if v1 && v2 {
                    return Err(ProtocolError::InvalidShare);
                }

                Ok(YaoShare::E(YaoEvaluatorShare { label: msg }))
            }
        }
    } else if party_id == 2 {
        let (x1, x2) = input_yao_from_functionality_3_create_msg1(input);

        send_to_party(setup, tag1, &Byte(x1 as u8), 0, relay).await?;
        send_to_party(setup, tag1, &Byte(x2 as u8), 1, relay).await?;

        let msg: Zeroizing<Vec<Block42>> = Zeroizing::new(
            receive_from_parties(setup, tag2, &[0, 1], relay).await?,
        );

        if msg.len() != 2 {
            return Err(ProtocolError::MissingMessage);
        }

        if msg[0].0 != msg[1].0 {
            return Err(ProtocolError::InconsistentMessage);
        }

        let (com_1f, com_1t, com_2f, com_2t) = &msg[0].0;

        let (label_1, witness_1) = &msg[0].1;
        let (label_2, witness_2) = &msg[1].1;

        let label_1_valid = if x1 {
            comm.verify(label_1, witness_1, com_1t)
        } else {
            comm.verify(label_1, witness_1, com_1f)
        };

        if !label_1_valid {
            return Err(ProtocolError::CommitmentVerificationFailed);
        }

        let label_2_valid = if x2 {
            comm.verify(label_2, witness_2, com_2t)
        } else {
            comm.verify(label_2, witness_2, com_2f)
        };

        if !label_2_valid {
            return Err(ProtocolError::CommitmentVerificationFailed);
        }

        let sh1 = YaoEvaluatorShare { label: *label_1 };
        let sh2 = YaoEvaluatorShare { label: *label_2 };
        let out = sh1.xor(&sh2);

        Ok(YaoShare::E(out))
    } else {
        let Byte(xs) = receive_from_one_party(setup, tag1, 2, relay).await?;
        let x_val = xs % 2 == 1;

        let ysetup = yao_setup.as_garbler_mut().unwrap();

        let msg2vals =
            input_yao_from_functionality_3_create_msg2(comm, ysetup);

        let selected = Zeroizing::new(if party_id == 0 {
            if x_val {
                (xor_blocks(&msg2vals[4], &ysetup.delta), msg2vals[7])
            } else {
                (msg2vals[4], msg2vals[6])
            }
        } else if x_val {
            (xor_blocks(&msg2vals[5], &ysetup.delta), msg2vals[9])
        } else {
            (msg2vals[5], msg2vals[8])
        });

        let msg = Zeroizing::new((
            (msg2vals[0], msg2vals[1], msg2vals[2], msg2vals[3]),
            *selected,
        ));

        send_to_party(setup, tag2, &msg, 2, relay).await?;

        let sh1 = YaoGarblerShare {
            delta: ysetup.delta,
            f_label: msg2vals[4],
        };

        let sh2 = YaoGarblerShare {
            delta: ysetup.delta,
            f_label: msg2vals[5],
        };

        let out = sh1.xor(&sh2);

        Ok(YaoShare::G(out))
    }
}

#[cfg(test)]
pub async fn batch_input_yao_from_functionality<T, C, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    input: &[Option<bool>],
    pid: usize,
    comm: &C,
    yao_setup: &mut YaoSetup,
) -> Result<Vec<YaoShare>, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag1 = relay.next_tag(INPUT_YAO_FROM_FUNC_MSG1);
    let tag2 = relay.next_tag(INPUT_YAO_FROM_FUNC_MSG2);

    let party_id = setup.participant_index();
    let batch_size = input.len();
    let mut output = Vec::with_capacity(batch_size);

    if pid == 0 || pid == 1 {
        match yao_setup {
            YaoSetup::G(g) => {
                let send = Zeroizing::new(
                    input
                        .iter()
                        .map(|i| {
                            let secrets =
                                input_yao_from_functionality_12_create_msg1(
                                    comm, g,
                                );
                            let (com0, com1, (w0, wit0), (w1, wit1), _b) =
                                &*secrets;

                            output.push(YaoShare::G(YaoGarblerShare {
                                delta: g.delta,
                                f_label: *w0,
                            }));

                            (
                                (*com0, *com1),
                                if party_id == pid {
                                    if i.unwrap() {
                                        (*w1, *wit1)
                                    } else {
                                        (*w0, *wit0)
                                    }
                                } else {
                                    (ZBLOCK, ZBLOCK)
                                },
                            )
                        })
                        .collect::<Vec<_>>(),
                );

                send_to_party(setup, tag1, &send, 2, relay).await?;
            }

            YaoSetup::E(_) => {
                let com_decom: Zeroizing<Vec<Vec<Block22>>> = Zeroizing::new(
                    receive_from_parties(setup, tag1, &[0, 1], relay).await?,
                );

                if com_decom.len() != 2 {
                    return Err(ProtocolError::MissingMessage);
                }

                if com_decom[0].len() != batch_size
                    || com_decom[1].len() != batch_size
                {
                    return Err(ProtocolError::InvalidMessage);
                }

                for i in 0..batch_size {
                    if com_decom[0][i].0 != com_decom[1][i].0 {
                        return Err(ProtocolError::InconsistentMessage);
                    }

                    let (com0, com1) = &com_decom[0][i].0;
                    let (msg, wit) = &com_decom[pid][i].1;

                    let v1 = comm.verify(msg, wit, com0);
                    let v2 = comm.verify(msg, wit, com1);

                    if !(v1 || v2) {
                        return Err(ProtocolError::InvalidShare);
                    }

                    if v1 && v2 {
                        return Err(ProtocolError::InvalidShare);
                    }

                    output
                        .push(YaoShare::E(YaoEvaluatorShare { label: *msg }));
                }
            }
        }
    } else if party_id == 2 {
        let mut val1 = BinaryString::new();
        let mut val2 = BinaryString::new();
        for i in input {
            let (x1, x2) =
                input_yao_from_functionality_3_create_msg1(i.unwrap());
            val1.push(x1);
            val2.push(x2);
        }

        send_to_party(setup, tag1, &val1, 0, relay).await?;
        send_to_party(setup, tag1, &val2, 1, relay).await?;

        let msg: Zeroizing<Vec<Vec<Block42>>> = Zeroizing::new(
            receive_from_parties(setup, tag2, &[0, 1], relay).await?,
        );

        if msg.len() != 2 {
            return Err(ProtocolError::MissingMessage);
        }

        if msg[0].len() != batch_size || msg[1].len() != batch_size {
            return Err(ProtocolError::InvalidMessage);
        }

        for i in 0..batch_size {
            if msg[0][i].0 != msg[1][i].0 {
                return Err(ProtocolError::InconsistentMessage);
            }

            let (com_1f, com_1t, com_2f, com_2t) = &msg[0][i].0;

            let (label_1, witness_1) = &msg[0][i].1;
            let (label_2, witness_2) = &msg[1][i].1;

            let label_1_valid = if val1.get(i) {
                comm.verify(label_1, witness_1, com_1t)
            } else {
                comm.verify(label_1, witness_1, com_1f)
            };

            if !label_1_valid {
                return Err(ProtocolError::CommitmentVerificationFailed);
            }

            let label_2_valid = if val2.get(i) {
                comm.verify(label_2, witness_2, com_2t)
            } else {
                comm.verify(label_2, witness_2, com_2f)
            };

            if !label_2_valid {
                return Err(ProtocolError::CommitmentVerificationFailed);
            }

            let sh1 = YaoEvaluatorShare { label: *label_1 };
            let sh2 = YaoEvaluatorShare { label: *label_2 };
            let out = sh1.xor(&sh2);

            output.push(YaoShare::E(out));
        }
    } else {
        let ysetup = yao_setup.as_garbler_mut().unwrap();

        let recv: BinaryString =
            receive_from_one_party(setup, tag1, 2, relay).await?;

        let mut msg = Zeroizing::new(Vec::new());

        for (i, output) in output.iter_mut().enumerate() {
            let x_val = recv.get(i);

            let msg2vals =
                input_yao_from_functionality_3_create_msg2(comm, ysetup);

            msg.push((
                (msg2vals[0], msg2vals[1], msg2vals[2], msg2vals[3]),
                if party_id == 0 {
                    if x_val {
                        (xor_blocks(&msg2vals[4], &ysetup.delta), msg2vals[7])
                    } else {
                        (msg2vals[4], msg2vals[6])
                    }
                } else if x_val {
                    (xor_blocks(&msg2vals[5], &ysetup.delta), msg2vals[9])
                } else {
                    (msg2vals[5], msg2vals[8])
                },
            ));

            let sh1 = YaoGarblerShare {
                delta: ysetup.delta,
                f_label: msg2vals[4],
            };

            let sh2 = YaoGarblerShare {
                delta: ysetup.delta,
                f_label: msg2vals[5],
            };

            let out = sh1.xor(&sh2);

            *output = YaoShare::G(out);
        }

        send_to_party(setup, tag2, &msg, 2, relay).await?;
    }

    Ok(output)
}

/// Msg1 for Input Yao from all protocol generated by garblers
#[derive(Zeroize, ZeroizeOnDrop)]
struct InputYaoAllMsg1p22 {
    com_i1_0: Vec<Block>,
    com_i2_0: Vec<Block>,
    com_i1_1: Vec<Block>,
    com_i2_1: Vec<Block>,
    w: Vec<Block>,
    wit: Vec<Block>,
}

impl Wrap for InputYaoAllMsg1p22 {
    fn external_size(&self) -> usize {
        BLOCK_SIZE * 6 * self.w.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        let buffer = self.com_i1_0.encode(buffer);
        let buffer = self.com_i2_0.encode(buffer);
        let buffer = self.com_i1_1.encode(buffer);
        let buffer = self.com_i2_1.encode(buffer);

        let buffer = self.w.encode(buffer);
        self.wit.write(buffer)
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let blocks = buffer.len() / 6;
        let (buffer, com_i1_0) = Wrap::decode(buffer, blocks)?;
        let (buffer, com_i2_0) = Wrap::decode(buffer, blocks)?;
        let (buffer, com_i1_1) = Wrap::decode(buffer, blocks)?;
        let (buffer, com_i2_1) = Wrap::decode(buffer, blocks)?;

        let (buffer, w) = Wrap::decode(buffer, blocks)?;
        let (buffer, wit) = Wrap::decode(buffer, blocks)?;

        buffer.is_empty().then_some(Self {
            com_i1_0,
            com_i2_0,
            com_i1_1,
            com_i2_1,
            w,
            wit,
        })
    }
}

fn encode_vec_bool(input: &[bool]) -> Vec<u8> {
    let mut o = BinaryString::new();
    for &i in input {
        o.push(i);
    }

    o.value
}

fn decode_vec_bool(input: Vec<u8>, length: usize) -> Vec<bool> {
    let x = BinaryString {
        length: length as u64,
        value: input,
    };

    (0..length).map(|j| x.get(j)).collect()
}

fn next_secret_block<R: RngCore>(rng: &mut R) -> Zeroizing<Block> {
    let mut block = Zeroizing::new(Block::default());
    rng.fill_bytes(&mut *block);
    block
}

fn input_yao_from_all_functionality_12_create_msg1<C, T>(
    comm: &C,
    yao_setup: &mut GarblerSetup,
    input: &[bool],
) -> (InputYaoAllMsg1p22, Vec<T>, Vec<T>)
where
    C: Commitment,
    T: From<YaoGarblerShare>,
{
    let i_len = input.len();

    let rng = &mut yao_setup.prf;
    let mut com_i1_0: Vec<Block> = Vec::with_capacity(i_len);
    let mut com_i2_0: Vec<Block> = Vec::with_capacity(i_len);
    let mut com_i1_1: Vec<Block> = Vec::with_capacity(i_len);
    let mut com_i2_1: Vec<Block> = Vec::with_capacity(i_len);

    let mut w: Vec<Block> = Vec::new();
    let mut wit: Vec<Block> = Vec::new();

    let mut i1_shares = Vec::with_capacity(i_len);
    let mut i2_shares = Vec::with_capacity(i_len);

    (0..i_len).for_each(|i| {
        // FIXME: random bit???
        let b = rng.next_u32() % 2 == 0;

        let w0 = next_secret_block(rng);
        let witness_0 = next_secret_block(rng);
        let witness_1 = next_secret_block(rng);

        // a = 0 => c0 = Com(Wb)  => c0 = w0 if b=0 and w1 if b=1 => c0 = if not b {w0} else {w1}
        // a = 1 => c1 = Com(W!b) => c1 = w1 if b=0 and w0 if b=0 => c1 = if not b {w1} else {w0}
        let comm_0 = if !b {
            comm.commit(&w0, &witness_0)
        } else {
            let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
            comm.commit(&label, &witness_1)
        };

        let comm_1 = if b {
            comm.commit(&w0, &witness_0)
        } else {
            let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
            comm.commit(&label, &witness_1)
        };

        com_i1_0.push(comm_0);
        com_i1_1.push(comm_1);

        i1_shares.push(
            YaoGarblerShare {
                delta: yao_setup.delta,
                f_label: *w0,
            }
            .into(),
        );

        if yao_setup.party_id == 0 {
            if input[i] {
                let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
                w.push(*label);
                wit.push(*witness_1);
            } else {
                w.push(*w0);
                wit.push(*witness_0);
            }
        }
    });

    (0..i_len).for_each(|i| {
        // FIXME: random bit???
        let b = rng.next_u32() % 2 == 0;

        let w0 = next_secret_block(rng);
        let witness_0 = next_secret_block(rng);
        let witness_1 = next_secret_block(rng);

        // a = 0 => c0 = Com(Wb)  => c0 = w0 if b=0 and w1 if b=1 => c0 = if not b {w0} else {w1}
        // a = 1 => c1 = Com(W!b) => c1 = w1 if b=0 and w0 if b=0 => c1 = if not b {w1} else {w0}
        let comm_0 = if !b {
            comm.commit(&w0, &witness_0)
        } else {
            let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
            comm.commit(&label, &witness_1)
        };

        let comm_1 = if b {
            comm.commit(&w0, &witness_0)
        } else {
            let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
            comm.commit(&label, &witness_1)
        };

        com_i2_0.push(comm_0);
        com_i2_1.push(comm_1);

        i2_shares.push(
            YaoGarblerShare {
                delta: yao_setup.delta,
                f_label: *w0,
            }
            .into(),
        );

        if yao_setup.party_id == 1 {
            if input[i] {
                let label = Zeroizing::new(xor_blocks(&w0, &yao_setup.delta));
                w.push(*label);
                wit.push(*witness_1);
            } else {
                w.push(*w0);
                wit.push(*witness_0);
            }
        }
    });

    (
        InputYaoAllMsg1p22 {
            com_i1_0,
            com_i2_0,
            com_i1_1,
            com_i2_1,
            w,
            wit,
        },
        i1_shares,
        i2_shares,
    )
}

/// Msg2 for Input Yao from all protocol generated by garblers
#[derive(Zeroize, ZeroizeOnDrop)]
struct InputYaoAllMsg2p22 {
    comm_1f: Vec<Block>,
    comm_1t: Vec<Block>,
    comm_2f: Vec<Block>,
    comm_2t: Vec<Block>,
    w: Vec<Block>,
    wit: Vec<Block>,
}

impl Wrap for InputYaoAllMsg2p22 {
    fn external_size(&self) -> usize {
        BLOCK_SIZE * self.w.len() * 6 + 4
    }

    fn write(&self, buffer: &mut [u8]) {
        let buffer = (self.w.len() as u32).encode(buffer);
        let buffer = self.comm_1f.encode(buffer);
        let buffer = self.comm_1t.encode(buffer);
        let buffer = self.comm_2f.encode(buffer);
        let buffer = self.comm_2t.encode(buffer);
        let buffer = self.w.encode(buffer);
        let _buffer = self.wit.encode(buffer);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let (buffer, len) = u32::decode(buffer, 4)?;

        let len = BLOCK_SIZE * len as usize;

        let (buffer, comm_1f) = Vec::<Block>::decode(buffer, len)?;
        let (buffer, comm_1t) = Vec::<Block>::decode(buffer, len)?;
        let (buffer, comm_2f) = Vec::<Block>::decode(buffer, len)?;
        let (buffer, comm_2t) = Vec::<Block>::decode(buffer, len)?;
        let (buffer, w) = Vec::<Block>::decode(buffer, len)?;
        let (buffer, wit) = Vec::<Block>::decode(buffer, len)?;

        buffer.is_empty().then_some(Self {
            comm_1f,
            comm_1t,
            comm_2f,
            comm_2t,
            w,
            wit,
        })
    }
}

fn input_yao_from_all_functionality_12_create_msg2<C, T>(
    comm: &C,
    i3_len: usize,
    msg1_recv: &[bool],
    yao_setup: &mut GarblerSetup,
) -> Result<(InputYaoAllMsg2p22, Vec<T>), ProtocolError>
where
    C: Commitment,
    T: From<YaoGarblerShare>,
{
    if msg1_recv.len() != i3_len {
        return Err(ProtocolError::InvalidMessage);
    }

    let rng = &mut yao_setup.prf;

    let mut i3_shares = Vec::new();
    let mut comm_1f = Vec::with_capacity(i3_len);
    let mut comm_1t = Vec::with_capacity(i3_len);
    let mut comm_2f = Vec::with_capacity(i3_len);
    let mut comm_2t = Vec::with_capacity(i3_len);
    let mut w = Vec::with_capacity(i3_len);
    let mut wit = Vec::with_capacity(i3_len);

    for &msg1 in msg1_recv {
        let w01 = next_secret_block(rng);
        let w02 = next_secret_block(rng);

        let witness1f = next_secret_block(rng);
        let comm1f = comm.commit(&w01, &witness1f);

        let witness1t = next_secret_block(rng);
        let label1t = Zeroizing::new(xor_blocks(&yao_setup.delta, &w01));
        let comm1t = comm.commit(&label1t, &witness1t);

        let witness2f = next_secret_block(rng);
        let comm2f = comm.commit(&w02, &witness2f);

        let witness2t = next_secret_block(rng);
        let label2t = Zeroizing::new(xor_blocks(&yao_setup.delta, &w02));
        let comm2t = comm.commit(&label2t, &witness2t);

        let msg = Zeroizing::new(if yao_setup.party_id == 0 {
            if msg1 {
                xor_blocks(&w01, &yao_setup.delta)
            } else {
                *w01
            }
        } else if msg1 {
            xor_blocks(&w02, &yao_setup.delta)
        } else {
            *w02
        });
        let witness = Zeroizing::new(if yao_setup.party_id == 0 {
            if msg1 {
                *witness1t
            } else {
                *witness1f
            }
        } else if msg1 {
            *witness2t
        } else {
            *witness2f
        });

        i3_shares.push(
            YaoGarblerShare {
                delta: yao_setup.delta,
                f_label: xor_blocks(&w01, &w02),
            }
            .into(),
        );

        comm_1f.push(comm1f);
        comm_1t.push(comm1t);
        comm_2f.push(comm2f);
        comm_2t.push(comm2t);
        w.push(*msg);
        wit.push(*witness);
    }

    Ok((
        InputYaoAllMsg2p22 {
            comm_1f,
            comm_1t,
            comm_2f,
            comm_2t,
            w,
            wit,
        },
        i3_shares,
    ))
}

fn input_yao_from_all_functionality_3_process_msg1<C, T>(
    comm: &C,
    msg1_recv_p2: &InputYaoAllMsg1p22,
    msg1_recv_p3: &InputYaoAllMsg1p22,
) -> Result<(Vec<T>, Vec<T>), ProtocolError>
where
    C: Commitment,
    T: From<YaoEvaluatorShare>,
{
    if msg1_recv_p2.com_i1_0 != msg1_recv_p3.com_i1_0
        || msg1_recv_p2.com_i1_1 != msg1_recv_p3.com_i1_1
        || msg1_recv_p2.com_i2_0 != msg1_recv_p3.com_i2_0
        || msg1_recv_p2.com_i2_1 != msg1_recv_p3.com_i2_1
    {
        return Err(ProtocolError::InconsistentMessage);
    }

    let i1_shares = msg1_recv_p2
        .com_i1_0
        .iter()
        .zip(&msg1_recv_p2.com_i1_1)
        .zip(&msg1_recv_p2.w)
        .zip(&msg1_recv_p2.wit)
        .map(|(((com0, com1), msg), wit)| {
            let v1 = comm.verify(msg, wit, com0);
            let v2 = comm.verify(msg, wit, com1);

            if v1 == v2 {
                return Err(ProtocolError::InvalidMessage);
            }

            Ok::<_, ProtocolError>(YaoEvaluatorShare { label: *msg }.into())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let i2_shares = msg1_recv_p2
        .com_i2_0
        .iter()
        .zip(&msg1_recv_p2.com_i2_1)
        .zip(&msg1_recv_p3.w)
        .zip(&msg1_recv_p3.wit)
        .map(|(((com0, com1), msg), wit)| {
            let v1 = comm.verify(msg, wit, com0);
            let v2 = comm.verify(msg, wit, com1);

            if v1 == v2 {
                return Err(ProtocolError::InvalidMessage);
            }

            Ok::<_, ProtocolError>(YaoEvaluatorShare { label: *msg }.into())
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((i1_shares, i2_shares))
}

fn validate_input_yao_all_msg2(
    msg: &InputYaoAllMsg2p22,
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

fn input_yao_from_all_functionality_3_process_msg2<C, T>(
    comm: &C,
    msg2_recv_p2: &InputYaoAllMsg2p22,
    msg2_recv_p3: &InputYaoAllMsg2p22,
    i3_len: usize,
    msg1_p2: &[bool],
    msg1_p3: &[bool],
) -> Result<Vec<T>, ProtocolError>
where
    C: Commitment,
    T: From<YaoEvaluatorShare>,
{
    if msg1_p2.len() != i3_len || msg1_p3.len() != i3_len {
        return Err(ProtocolError::InvalidMessage);
    }
    validate_input_yao_all_msg2(msg2_recv_p2, i3_len)?;
    validate_input_yao_all_msg2(msg2_recv_p3, i3_len)?;

    if msg2_recv_p2.comm_1f != msg2_recv_p3.comm_1f
        || msg2_recv_p2.comm_1t != msg2_recv_p3.comm_1t
        || msg2_recv_p2.comm_2f != msg2_recv_p3.comm_2f
        || msg2_recv_p2.comm_2t != msg2_recv_p3.comm_2t
    {
        return Err(ProtocolError::InconsistentMessage);
    }

    let mut i3_shares = Vec::with_capacity(i3_len);

    for i in 0..i3_len {
        let com_1f = &msg2_recv_p2.comm_1f[i];
        let com_1t = &msg2_recv_p2.comm_1t[i];
        let com_2f = &msg2_recv_p2.comm_2f[i];
        let com_2t = &msg2_recv_p2.comm_2t[i];

        let label_1 = &msg2_recv_p2.w[i];
        let label_2 = &msg2_recv_p3.w[i];

        let witness_1 = &msg2_recv_p2.wit[i];
        let witness_2 = &msg2_recv_p3.wit[i];

        if msg1_p2[i] {
            if !(comm.verify(label_1, witness_1, com_1t)) {
                return Err(ProtocolError::InvalidMessage);
            }
        } else if !(comm.verify(label_1, witness_1, com_1f)) {
            return Err(ProtocolError::InvalidMessage);
        }

        if msg1_p3[i] {
            if !(comm.verify(label_2, witness_2, com_2t)) {
                return Err(ProtocolError::InvalidMessage);
            }
        } else if !(comm.verify(label_2, witness_2, com_2f)) {
            return Err(ProtocolError::InvalidMessage);
        }

        i3_shares.push(
            YaoEvaluatorShare {
                label: xor_blocks(label_1, label_2),
            }
            .into(),
        );
    }

    Ok(i3_shares)
}

/// Takes a vector of private boolean values from each party as input
/// and returns yao-shares of the values.
pub async fn run_batch_input_from_all_yao<S, R, C>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    input: &[bool],
    yao_setup: &mut YaoSetup,
    comm: &C,
) -> Result<(Vec<YaoShare>, Vec<YaoShare>, Vec<YaoShare>), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
    C: Commitment,
{
    let tag1 = relay.next_tag(INPUT_YAO_FROM_ALL_MSG1);
    let tag2 = relay.next_tag(INPUT_YAO_FROM_ALL_MSG2);
    let tag3 = relay.next_tag(INPUT_YAO_FROM_ALL_MSG3);

    let out = match yao_setup {
        YaoSetup::E(_) => {
            let mut rng = rand::rngs::StdRng::from_entropy();
            let mut msg1_to_p1 = Vec::with_capacity(input.len());
            let mut msg1_to_p2 = Vec::with_capacity(input.len());

            for &bit in input {
                let x1 = rng.gen_bool(0.5);
                msg1_to_p1.push(x1);
                msg1_to_p2.push(x1 ^ bit);
            }

            let msg1_enc_to_p1 = encode_vec_bool(&msg1_to_p1);
            let msg1_enc_to_p2 = encode_vec_bool(&msg1_to_p2);

            send_to_party(setup, tag1, &msg1_enc_to_p1, 0, relay).await?;
            send_to_party(setup, tag1, &msg1_enc_to_p2, 1, relay).await?;

            let msg1_p1: InputYaoAllMsg1p22 =
                receive_from_one_party(setup, tag1, 0, relay).await?;

            let msg1_p2: InputYaoAllMsg1p22 =
                receive_from_one_party(setup, tag3, 1, relay).await?;

            let (i1_shares, i2_shares) =
                input_yao_from_all_functionality_3_process_msg1(
                    comm, &msg1_p1, &msg1_p2,
                )?;

            let msg2s: Vec<InputYaoAllMsg2p22> =
                receive_from_parties(setup, tag2, &[0, 1], relay).await?;

            if msg2s.len() != 2 {
                return Err(ProtocolError::MissingMessage);
            }

            let i3_shares = input_yao_from_all_functionality_3_process_msg2(
                comm,
                &msg2s[0],
                &msg2s[1],
                input.len(),
                &msg1_to_p1,
                &msg1_to_p2,
            )?;

            (i1_shares, i2_shares, i3_shares)
        }

        YaoSetup::G(g) => {
            let (msg1, i1_shares, i2_shares) =
                input_yao_from_all_functionality_12_create_msg1(
                    comm, g, input,
                );

            let tag = if g.party_id == 0 { tag1 } else { tag3 };

            send_to_party(setup, tag, &msg1, 2, relay).await?;

            let msg1s: Vec<u8> =
                receive_from_one_party(setup, tag1, 2, relay).await?;

            let msg1 = decode_vec_bool(msg1s, input.len());

            let (msg2, i3_shares) =
                input_yao_from_all_functionality_12_create_msg2(
                    comm,
                    input.len(),
                    &msg1,
                    g,
                )?;

            send_to_party(setup, tag2, &msg2, 2, relay).await?;

            (i1_shares, i2_shares, i3_shares)
        }
    };

    Ok(out)
}
