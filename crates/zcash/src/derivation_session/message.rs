// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use super::serde_types::{SerializableBlock, SerializableScalar};

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub from: u8,
    pub to: u8,
    pub body: MessageBody,
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum MessageBody {
    SetupYao(SetupYaoMessage),
    CommonRandomness(CommonRandomnessMessage),
    ShamirToRss(ShamirToRssMessage),
    BatchInputYao(BatchInputYaoMessage),
    CircuitEval(CircuitEvalMessage),
    OutputVerification(OutputYaoMessage),
    BatchOutput(OutputYaoMessage),
    Abort(AbortMessage),
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum SetupYaoMessage {
    CommCrs(SerializableBlock),
    PrfSeed([u8; 32]),
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum CommonRandomnessMessage {
    KeyNext([u8; 32]),
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ShamirToRssMessage(pub SerializableScalar);

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum BatchInputYaoMessage {
    EvaluatorBits(Vec<u8>),
    GarblerInputCommit(InputYaoAllMsg1),
    GarblerI3Commit(InputYaoAllMsg2),
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum CircuitEvalMessage {
    Hash([u8; 32]),
    GarbledTables(Vec<SerializableBlock>),
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum OutputYaoMessage {
    Label(SerializableBlock),
    Labels(Vec<SerializableBlock>),
    Bit(bool),
    Bits(Vec<u8>),
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AbortMessage;

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct InputYaoAllMsg1 {
    pub com_i1_0: Vec<SerializableBlock>,
    pub com_i2_0: Vec<SerializableBlock>,
    pub com_i1_1: Vec<SerializableBlock>,
    pub com_i2_1: Vec<SerializableBlock>,
    pub w: Vec<SerializableBlock>,
    pub wit: Vec<SerializableBlock>,
}

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct InputYaoAllMsg2 {
    pub comm_1f: Vec<SerializableBlock>,
    pub comm_1t: Vec<SerializableBlock>,
    pub comm_2f: Vec<SerializableBlock>,
    pub comm_2t: Vec<SerializableBlock>,
    pub w: Vec<SerializableBlock>,
    pub wit: Vec<SerializableBlock>,
}
