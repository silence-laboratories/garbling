// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use super::serde_types::{SerializableBlock, SerializableScalar};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub(crate) from: u8,
    pub(crate) to: u8,
    pub(crate) body: MessageBody,
}

impl Message {
    /// Creates an abort message.
    ///
    /// Abort is broadcast message, the `to` field is intentionally
    /// ignored by the transport and session logic.
    pub fn abort(from: u8) -> Self {
        Self {
            from,
            to: 0,
            body: MessageBody::Abort,
        }
    }

    /// Returns message sender
    pub fn sender(&self) -> u8 {
        self.from
    }

    /// Returns the receiver, or `None` for broadcast `Abort`
    /// messages.
    pub fn receiver(&self) -> Option<u8> {
        match self.body {
            MessageBody::Abort => None,
            _ => Some(self.to),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum MessageBody {
    SetupYao(SetupYaoMessage),
    CommonRandomness(CommonRandomnessMessage),
    ShamirToRss(ShamirToRssMessage),
    BatchInputYao(BatchInputYaoMessage),
    CircuitEval(CircuitEvalMessage),
    OutputVerification(OutputYaoMessage),
    BatchOutput(OutputYaoMessage),
    Abort,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SetupYaoMessage {
    CommCrs(SerializableBlock),
    PrfSeed {
        seed: [u8; 32],
        comm_crs: SerializableBlock,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CommonRandomnessMessage {
    KeyNext([u8; 32]),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ShamirToRssMessage(pub SerializableScalar);

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BatchInputYaoMessage {
    EvaluatorBits(Vec<u8>),
    GarblerInputCommit(InputYaoAllMsg1),
    GarblerI3Commit(InputYaoAllMsg2),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CircuitEvalMessage {
    Hash([u8; 32]),
    GarbledTables(Vec<SerializableBlock>),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum OutputYaoMessage {
    Label(SerializableBlock),
    Labels(Vec<SerializableBlock>),
    Bit(bool),
    Bits(Vec<u8>),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InputYaoAllMsg1 {
    pub com_i1_0: Vec<SerializableBlock>,
    pub com_i2_0: Vec<SerializableBlock>,
    pub com_i1_1: Vec<SerializableBlock>,
    pub com_i2_1: Vec<SerializableBlock>,
    pub w: Vec<SerializableBlock>,
    pub wit: Vec<SerializableBlock>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InputYaoAllMsg2 {
    pub comm_1f: Vec<SerializableBlock>,
    pub comm_1t: Vec<SerializableBlock>,
    pub comm_2f: Vec<SerializableBlock>,
    pub comm_2t: Vec<SerializableBlock>,
    pub w: Vec<SerializableBlock>,
    pub wit: Vec<SerializableBlock>,
}
