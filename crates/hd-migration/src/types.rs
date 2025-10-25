// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crypto_bigint::{Encoding, NonZero, U256};
use group::{
    Group, GroupEncoding,
    ff::{Field, PrimeField},
};

use k256::elliptic_curve::ops::Reduce;
use sl_compute_common::CommonRandomness;
use sl_messages::relay::MessageSendError;

use garbled_circuit::{
    functionality::{
        utils::{FixedExternalSize, Wrap},
        utils_dep::{Error, ProtocolError},
    },
    utilities::types::YaoShare,
};

pub use garbled_circuit::functionality::utils_dep::ProtocolParticipant;

/// Trait to convert any random byte array into a Group scalar.
/// The input bytes need not necessarily be the byte representation of the scalar.
/// The input bytes can be modified to make sure a valid Scalar is returned.
pub trait ScalarFromBytes: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Self;
}

impl ScalarFromBytes for k256::Scalar {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let hval = k256::U256::from_be_slice(&bytes);
        k256::Scalar::reduce(hval)
    }
}

use crate::constants::X25519_Q;
impl ScalarFromBytes for curve25519_dalek::Scalar {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut hval = U256::from_be_bytes(bytes);
        hval = hval.rem(&NonZero::new(X25519_Q).unwrap());
        curve25519_dalek::Scalar::from_bytes_mod_order(hval.to_le_bytes())
    }
}

/// Scalar wrapper for implementing Wrap
pub struct ScalarVal<G: Group + GroupEncoding>(pub G::Scalar);

impl Wrap for ScalarVal<k256::ProjectivePoint> {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.0.to_bytes())
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(buffer)
            .filter(|b| b.len() == 32)
            .map(k256::FieldBytes::from_slice)
            .and_then(|&b| k256::Scalar::from_repr(b).into_option())
            .map(ScalarVal)
    }
}

impl FixedExternalSize for ScalarVal<k256::ProjectivePoint> {
    const SIZE: usize = 32;
}

impl Wrap for ScalarVal<curve25519_dalek::EdwardsPoint> {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.0.as_bytes())
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(buffer)
            .filter(|b| b.len() == 32)
            .map(|b| {
                curve25519_dalek::Scalar::from_bytes_mod_order(
                    b.try_into().unwrap(),
                )
            })
            .map(ScalarVal)
    }
}

impl FixedExternalSize for ScalarVal<curve25519_dalek::EdwardsPoint> {
    const SIZE: usize = 32;
}

/// Converts a vector of `ScalarVal`s to a vector of `Scalar`s
pub fn vec_scalarval_2_scalars<G: Group + GroupEncoding>(
    input: &[ScalarVal<G>],
) -> Vec<G::Scalar> {
    let mut outs = vec![];
    for i in input {
        outs.push(i.0);
    }

    outs
}

/// Converts a vector of `Scalar`s to a vector of `ScalarVal`s
pub fn vec_scalar_2_scalarvals<G: Group + GroupEncoding>(
    input: &[G::Scalar],
) -> Vec<ScalarVal<G>> {
    let mut outs = vec![];
    for &i in input {
        outs.push(ScalarVal(i));
    }

    outs
}

/// error generated during hard derivation
#[derive(thiserror::Error, Debug)]
pub enum HardDerivationError {
    /// Failed to send a message
    #[error("Failed to send a message")]
    SendMessage,

    /// Received an invalid message
    #[error("Received an invalid message")]
    InvalidMessage,

    /// Failed to receive a message
    #[error("Can't recevie required message")]
    MissingMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),
}

impl From<MessageSendError> for HardDerivationError {
    fn from(_: MessageSendError) -> Self {
        HardDerivationError::SendMessage
    }
}

impl From<Error> for HardDerivationError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => HardDerivationError::AbortProtocol(p as _),
            Error::Recv => HardDerivationError::MissingMessage,
            Error::Send => HardDerivationError::SendMessage,
            Error::InvalidMessage => HardDerivationError::InvalidMessage,
        }
    }
}

impl From<ProtocolError> for HardDerivationError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidMessage => {
                HardDerivationError::InvalidMessage
            }
            ProtocolError::MissingMessage => {
                HardDerivationError::MissingMessage
            }
            ProtocolError::SendMessage => HardDerivationError::SendMessage,
            ProtocolError::VerificationError => {
                HardDerivationError::AbortProtocol(usize::MAX)
            }
            ProtocolError::AbortProtocol(v) => {
                HardDerivationError::AbortProtocol(v)
            }
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct PrivKeyShare<T: Group + GroupEncoding> {
    pub prev_share: T::Scalar,
    pub next_share: T::Scalar,
}

impl<G> PrivKeyShare<G>
where
    G: Group + GroupEncoding,
    G::Scalar: Field + ScalarFromBytes,
{
    pub fn get_random_share(
        common_randomness: &mut CommonRandomness,
    ) -> PrivKeyShare<G> {
        let (prev_bytes, next_bytes) = common_randomness.random_32_bytes();
        let prev = G::Scalar::from_bytes(prev_bytes);
        let next = G::Scalar::from_bytes(next_bytes);

        PrivKeyShare::<G> {
            prev_share: prev,
            next_share: next,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct PrivKeyShareDkg<T: Group + GroupEncoding> {
    pub keyshare: PrivKeyShare<T>,
    pub pubkey: T,
}

/// Represents a share for secure hard derivation of child key shares
/// as per BIP32
#[derive(Debug, PartialEq)]
pub struct PrivKeyShareBip<G: Group + GroupEncoding> {
    /// Yao shares of binary representation of the Private key
    pub yao_share: [YaoShare; 256],

    /// Yao shares of binary representation of the chain code
    pub chain_code: [u8; 32],

    /// RSS shares of the private key
    pub keyshare: PrivKeyShare<G>,

    /// The public key corresponding to the private key
    pub pubkey: G,
}
