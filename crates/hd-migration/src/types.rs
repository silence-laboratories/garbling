use crypto_bigint::{Encoding, NonZero, U256};
use garbled_circuit::functionality::{
    utils::{FixedExternalSize, SetupMessage, Wrap},
    utils_dep::{Error, ProtocolError},
};
use group::ff::PrimeField;
use k256::{Scalar, elliptic_curve::ops::Reduce};
use sl_messages::relay::MessageSendError;

use crate::constants::X25519_Q;

/// Trait to convert any random byte array into a Group scalar.
/// The input bytes need not necessarily be the byte representation of the scalar.
/// The input bytes can be modified to make sure a valid Scalar is returned.
pub trait ScalarFromBytes: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Self;
}

impl ScalarFromBytes for k256::Scalar {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let hval = k256::U256::from_be_hex(&hex::encode(bytes));
        k256::Scalar::reduce(hval)
    }
}

impl ScalarFromBytes for curve25519_dalek::Scalar {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut hval = U256::from_be_bytes(bytes);
        hval = hval.rem(&NonZero::new(X25519_Q).unwrap());
        curve25519_dalek::Scalar::from_bytes_mod_order(hval.to_le_bytes())
    }
}

/// Scalar wrapper for implementing Wrap
#[derive(Clone)]
pub struct ScalarVal(pub Scalar);

impl Wrap for ScalarVal {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.0.to_bytes())
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&buffer[..32]);
        Some(ScalarVal(
            k256::Scalar::from_repr_vartime(*k256::FieldBytes::from_slice(&bytes))
                .expect("Conversion Failed"),
        ))
    }
}

impl FixedExternalSize for ScalarVal {
    const SIZE: usize = 32;
}

/// Converts a vector of `ScalarVal`s to a vector of `Scalar`s
pub fn vec_scalarval_2_scalars(input: &[ScalarVal]) -> Vec<Scalar> {
    let mut outs = vec![];
    for i in input {
        outs.push(i.0);
    }
    outs
}

/// Converts a vector of `Scalar`s to a vector of `ScalarVal`s
pub fn vec_scalar_2_scalarvals(input: &[Scalar]) -> Vec<ScalarVal> {
    let mut outs = vec![];
    for i in input {
        outs.push(ScalarVal(*i));
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
            ProtocolError::InvalidMessage => HardDerivationError::InvalidMessage,
            ProtocolError::MissingMessage => HardDerivationError::MissingMessage,
            ProtocolError::SendMessage => HardDerivationError::SendMessage,
            ProtocolError::VerificationError => HardDerivationError::AbortProtocol(usize::MAX),
            ProtocolError::AbortProtocol(v) => HardDerivationError::AbortProtocol(v),
        }
    }
}

pub trait ProtocolParticipant:
    garbled_circuit::functionality::utils_dep::ProtocolParticipant
{
}

impl ProtocolParticipant for SetupMessage {}
