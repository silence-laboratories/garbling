// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::fmt;

use ff::PrimeField;
use pasta_curves::pallas::Scalar;
use zeroize::Zeroize;

use garbled_circuit::{
    functionality::utils_dep::ProtocolError,
    utilities::{
        label_prf::LabelPrf,
        types::{
            EvaluatorSetup, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare,
            YaoSetup, YaoShare,
        },
    },
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone, Eq, PartialEq)]
pub struct SerializableScalar(pub [u8; 32]);

impl fmt::Debug for SerializableScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SerializableScalar(..)")
    }
}

impl Zeroize for SerializableScalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SerializableScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

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
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone, Eq, PartialEq)]
pub struct SerializableBlock(pub [u8; 16]);

impl fmt::Debug for SerializableBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SerializableBlock(..)")
    }
}

impl Zeroize for SerializableBlock {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SerializableBlock {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Serde-compatible storage for secret 32-byte session values.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SecretBytes32(pub(crate) [u8; 32]);

impl SecretBytes32 {
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for SecretBytes32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretBytes32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes32(..)")
    }
}

impl Zeroize for SecretBytes32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A serde-compatible vector whose contents are redacted from debug output
/// and cleared before its allocation is released.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone, Default, PartialEq)]
pub(crate) struct SecretVecU8(pub(crate) Vec<u8>);

impl From<Vec<u8>> for SecretVecU8 {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for SecretVecU8 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for SecretVecU8 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretVecU8(..)")
    }
}

impl Zeroize for SecretVecU8 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretVecU8 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The boolean equivalent of [`SecretVecU8`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone, Default, PartialEq)]
pub(crate) struct SecretVecBool(pub(crate) Vec<bool>);

impl From<Vec<bool>> for SecretVecBool {
    fn from(value: Vec<bool>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for SecretVecBool {
    type Target = [bool];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for SecretVecBool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretVecBool(..)")
    }
}

impl Zeroize for SecretVecBool {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretVecBool {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Stable serialized state shared with `rand_chacha::ChaCha8Rng`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Eq, PartialEq)]
pub struct SerializableLabelPrf {
    seed: [u8; 32],
    stream: u64,
    word_pos: u128,
}

impl SerializableLabelPrf {
    pub(crate) fn from_prf(prf: &LabelPrf) -> Self {
        let (seed, stream, word_pos) = prf.state();
        Self {
            seed,
            stream,
            word_pos,
        }
    }

    pub(crate) fn to_prf(&self) -> LabelPrf {
        LabelPrf::from_state(self.seed, self.stream, self.word_pos)
    }
}

impl fmt::Debug for SerializableLabelPrf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SerializableLabelPrf { .. }")
    }
}

impl Zeroize for SerializableLabelPrf {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.stream.zeroize();
        self.word_pos.zeroize();
    }
}

impl Drop for SerializableLabelPrf {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Eq, PartialEq)]
pub enum SerializableYaoSetup {
    Garbler {
        comm_crs: SerializableBlock,
        garble_key: SerializableBlock,
        prf: Box<SerializableLabelPrf>,
        delta: SerializableBlock,
        party_id: u8,
    },
    Evaluator {
        comm_crs: SerializableBlock,
        garble_key: SerializableBlock,
    },
}

impl fmt::Debug for SerializableYaoSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Garbler { party_id, .. } => formatter
                .debug_struct("SerializableYaoSetup::Garbler")
                .field("party_id", party_id)
                .finish_non_exhaustive(),
            Self::Evaluator { .. } => formatter
                .debug_struct("SerializableYaoSetup::Evaluator")
                .finish_non_exhaustive(),
        }
    }
}

impl Zeroize for SerializableYaoSetup {
    fn zeroize(&mut self) {
        match self {
            Self::Garbler {
                comm_crs,
                garble_key,
                prf,
                delta,
                ..
            } => {
                comm_crs.zeroize();
                garble_key.zeroize();
                prf.zeroize();
                delta.zeroize();
            }
            Self::Evaluator {
                comm_crs,
                garble_key,
            } => {
                comm_crs.zeroize();
                garble_key.zeroize();
            }
        }
    }
}

impl Drop for SerializableYaoSetup {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SerializableYaoSetup {
    pub fn try_to_yao_setup(&self) -> Result<YaoSetup, ProtocolError> {
        match self {
            SerializableYaoSetup::Garbler {
                comm_crs,
                garble_key,
                prf,
                delta,
                party_id,
            } => Ok(YaoSetup::G(GarblerSetup {
                comm_crs: comm_crs.0,
                garble_key: garble_key.0,
                prf: prf.to_prf(),
                delta: delta.0,
                party_id: usize::from(*party_id),
            })),
            SerializableYaoSetup::Evaluator {
                comm_crs,
                garble_key,
            } => Ok(YaoSetup::E(EvaluatorSetup {
                comm_crs: comm_crs.0,
                garble_key: garble_key.0,
            })),
        }
    }
}

impl From<YaoSetup> for SerializableYaoSetup {
    fn from(value: YaoSetup) -> Self {
        match value {
            YaoSetup::G(g) => SerializableYaoSetup::Garbler {
                comm_crs: SerializableBlock(g.comm_crs),
                garble_key: SerializableBlock(g.garble_key),
                prf: Box::new(SerializableLabelPrf::from_prf(&g.prf)),
                delta: SerializableBlock(g.delta),
                party_id: g.party_id as u8,
            },
            YaoSetup::E(e) => SerializableYaoSetup::Evaluator {
                comm_crs: SerializableBlock(e.comm_crs),
                garble_key: SerializableBlock(e.garble_key),
            },
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Eq, PartialEq)]
pub enum SerializableYaoShare {
    Garbler {
        delta: SerializableBlock,
        f_label: SerializableBlock,
    },
    Evaluator {
        label: SerializableBlock,
    },
}

impl fmt::Debug for SerializableYaoShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Garbler { .. } => {
                formatter.write_str("SerializableYaoShare::Garbler(..)")
            }
            Self::Evaluator { .. } => {
                formatter.write_str("SerializableYaoShare::Evaluator(..)")
            }
        }
    }
}

impl Zeroize for SerializableYaoShare {
    fn zeroize(&mut self) {
        match self {
            Self::Garbler { delta, f_label } => {
                delta.zeroize();
                f_label.zeroize();
            }
            Self::Evaluator { label } => label.zeroize(),
        }
    }
}

impl Drop for SerializableYaoShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<YaoShare> for SerializableYaoShare {
    fn from(value: YaoShare) -> Self {
        match &value {
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
        match &value {
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

#[cfg(all(test, feature = "serde"))]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use garbled_circuit::utilities::label_prf::LabelPrf;

    use super::{
        SecretBytes32, SecretVecBool, SecretVecU8, SerializableBlock,
        SerializableLabelPrf, SerializableScalar, SerializableYaoSetup,
        SerializableYaoShare,
    };
    use zeroize::Zeroize;

    #[derive(serde::Serialize)]
    struct LegacyBlock([u8; 16]);

    #[derive(serde::Serialize)]
    enum LegacyYaoSetup {
        Garbler {
            comm_crs: LegacyBlock,
            garble_key: LegacyBlock,
            prf: Box<ChaCha8Rng>,
            delta: LegacyBlock,
            party_id: u8,
        },
        #[allow(dead_code)]
        Evaluator {
            comm_crs: LegacyBlock,
            garble_key: LegacyBlock,
        },
    }

    fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn secret_leaf_wrappers_preserve_encoding() {
        assert_eq!(
            encode(&SerializableBlock([0x11; 16])),
            encode(&LegacyBlock([0x11; 16])),
        );
        assert_eq!(
            encode(&SerializableScalar([0x22; 32])),
            encode(&[0x22; 32]),
        );
        assert_eq!(encode(&SecretBytes32([0x33; 32])), encode(&[0x33; 32]),);
        assert_eq!(
            encode(&SecretVecU8::from(vec![0x44, 0x55])),
            encode(&vec![0x44, 0x55]),
        );
        assert_eq!(
            encode(&SecretVecBool::from(vec![true, false, true])),
            encode(&vec![true, false, true]),
        );
    }

    #[test]
    fn secret_vectors_zeroize_and_redact() {
        let mut bytes = SecretVecU8::from(vec![0x11, 0x22, 0x33]);
        let bytes_capacity = bytes.0.capacity();
        bytes.zeroize();
        assert!(bytes.0.is_empty());
        assert_eq!(bytes.0.capacity(), bytes_capacity);
        assert_eq!(format!("{bytes:?}"), "SecretVecU8(..)");

        let mut bits = SecretVecBool::from(vec![true, false, true]);
        let bits_capacity = bits.0.capacity();
        bits.zeroize();
        assert!(bits.0.is_empty());
        assert_eq!(bits.0.capacity(), bits_capacity);
        assert_eq!(format!("{bits:?}"), "SecretVecBool(..)");
    }

    #[test]
    fn secret_serializable_values_zeroize() {
        let mut scalar = SerializableScalar([0x11; 32]);
        scalar.zeroize();
        assert_eq!(scalar.0, [0; 32]);

        let mut block = SerializableBlock([0x22; 16]);
        block.zeroize();
        assert_eq!(block.0, [0; 16]);

        let mut bytes = SecretBytes32([0x33; 32]);
        bytes.zeroize();
        assert_eq!(bytes.0, [0; 32]);

        let mut share = SerializableYaoShare::Garbler {
            delta: SerializableBlock([0x44; 16]),
            f_label: SerializableBlock([0x55; 16]),
        };
        share.zeroize();
        let SerializableYaoShare::Garbler { delta, f_label } = &share else {
            unreachable!();
        };
        assert_eq!(delta.0, [0; 16]);
        assert_eq!(f_label.0, [0; 16]);

        let mut setup = SerializableYaoSetup::Garbler {
            comm_crs: SerializableBlock([0x66; 16]),
            garble_key: SerializableBlock([0x77; 16]),
            prf: Box::new(SerializableLabelPrf {
                seed: [0x88; 32],
                stream: 9,
                word_pos: 10,
            }),
            delta: SerializableBlock([0x99; 16]),
            party_id: 1,
        };
        setup.zeroize();
        let SerializableYaoSetup::Garbler {
            comm_crs,
            garble_key,
            prf,
            delta,
            ..
        } = &setup
        else {
            unreachable!();
        };
        assert_eq!(comm_crs.0, [0; 16]);
        assert_eq!(garble_key.0, [0; 16]);
        assert_eq!(prf.seed, [0; 32]);
        assert_eq!(prf.stream, 0);
        assert_eq!(prf.word_pos, 0);
        assert_eq!(delta.0, [0; 16]);
    }

    #[test]
    fn label_prf_preserves_rand_chacha_serialized_state() {
        let seed = [0x5a; 32];
        let stream = 0x0123_4567_89ab_cdef;
        let word_pos = (1u128 << 63) + 17;

        let mut old = ChaCha8Rng::from_seed(seed);
        old.set_stream(stream);
        old.set_word_pos(word_pos);

        let new = SerializableLabelPrf::from_prf(&LabelPrf::from_state(
            seed, stream, word_pos,
        ));

        // Box is transparent in serde, so preserving this abstract state also
        // preserves the existing SerializableYaoSetup field encoding.
        assert_eq!(encode(&new), encode(&old));

        let decoded_new: SerializableLabelPrf =
            ciborium::de::from_reader(encode(&old).as_slice()).unwrap();
        let mut decoded_old: ChaCha8Rng =
            ciborium::de::from_reader(encode(&new).as_slice()).unwrap();
        let mut decoded_prf = decoded_new.to_prf();

        let mut old_output = [0u8; 64];
        let mut new_output = [0u8; 64];
        decoded_old.fill_bytes(&mut old_output);
        decoded_prf.fill_bytes(&mut new_output);
        assert_eq!(new_output, old_output);

        let old_setup = LegacyYaoSetup::Garbler {
            comm_crs: LegacyBlock([0x11; 16]),
            garble_key: LegacyBlock([0x22; 16]),
            prf: Box::new(old),
            delta: LegacyBlock([0x33; 16]),
            party_id: 1,
        };
        let new_setup = SerializableYaoSetup::Garbler {
            comm_crs: SerializableBlock([0x11; 16]),
            garble_key: SerializableBlock([0x22; 16]),
            prf: Box::new(new),
            delta: SerializableBlock([0x33; 16]),
            party_id: 1,
        };
        assert_eq!(encode(&new_setup), encode(&old_setup));
    }
}
