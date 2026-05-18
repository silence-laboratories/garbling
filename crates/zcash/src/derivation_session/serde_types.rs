// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::PrimeField;
use pasta_curves::pallas::Scalar;
use rand_chacha::ChaCha8Rng;

use garbled_circuit::{
    functionality::utils_dep::ProtocolError,
    utilities::types::{
        EvaluatorSetup, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare,
        YaoSetup, YaoShare,
    },
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerializableScalar(pub [u8; 32]);

impl SerializableScalar {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_scalar(&self) -> Result<Scalar, ProtocolError> {
        Option::<Scalar>::from(Scalar::from_repr(self.0))
            .ok_or(ProtocolError::InvalidShare)
    }
}

impl From<Scalar> for SerializableScalar {
    fn from(value: Scalar) -> Self {
        Self(value.to_repr())
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerializableBlock(pub [u8; 16]);

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SerializableYaoSetup {
    Garbler {
        comm_crs: SerializableBlock,
        prf: Box<ChaCha8Rng>,
        delta: SerializableBlock,
        party_id: u8,
    },
    Evaluator {
        comm_crs: SerializableBlock,
    },
}

impl SerializableYaoSetup {
    pub fn try_to_yao_setup(&self) -> Result<YaoSetup, ProtocolError> {
        match self {
            SerializableYaoSetup::Garbler {
                comm_crs,
                prf,
                delta,
                party_id,
            } => Ok(YaoSetup::G(GarblerSetup {
                comm_crs: comm_crs.0,
                prf: (**prf).clone(),
                delta: delta.0,
                party_id: usize::from(*party_id),
            })),
            SerializableYaoSetup::Evaluator { comm_crs } => {
                Ok(YaoSetup::E(EvaluatorSetup {
                    comm_crs: comm_crs.0,
                }))
            }
        }
    }
}

impl From<YaoSetup> for SerializableYaoSetup {
    fn from(value: YaoSetup) -> Self {
        match value {
            YaoSetup::G(g) => SerializableYaoSetup::Garbler {
                comm_crs: SerializableBlock(g.comm_crs),
                prf: Box::new(g.prf),
                delta: SerializableBlock(g.delta),
                party_id: g.party_id as u8,
            },
            YaoSetup::E(e) => SerializableYaoSetup::Evaluator {
                comm_crs: SerializableBlock(e.comm_crs),
            },
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerializableYaoShare {
    Garbler {
        delta: SerializableBlock,
        f_label: SerializableBlock,
    },
    Evaluator {
        label: SerializableBlock,
    },
}

impl From<YaoShare> for SerializableYaoShare {
    fn from(value: YaoShare) -> Self {
        match value {
            YaoShare::G(share) => SerializableYaoShare::Garbler {
                delta: SerializableBlock(share.delta),
                f_label: SerializableBlock(share.f_label),
            },
            YaoShare::E(share) => SerializableYaoShare::Evaluator {
                label: SerializableBlock(share.label),
            },
        }
    }
}

impl From<SerializableYaoShare> for YaoShare {
    fn from(value: SerializableYaoShare) -> Self {
        match value {
            SerializableYaoShare::Garbler { delta, f_label } => {
                YaoShare::G(YaoGarblerShare {
                    delta: delta.0,
                    f_label: f_label.0,
                })
            }
            SerializableYaoShare::Evaluator { label } => {
                YaoShare::E(YaoEvaluatorShare { label: label.0 })
            }
        }
    }
}
