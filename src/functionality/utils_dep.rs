// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use sl_messages::relay::MessageSendError;

/// Relay Errors
pub enum Error {
    /// Abort
    Abort(usize),
    /// Recv
    Recv,
    /// Send
    Send,
    /// InvalidMessage
    InvalidMessage,
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
/// Protocol errors
pub enum ProtocolError {
    /// error while serializing or deserializing or invalid message data length
    #[error(
        "Error while deserializing message or invalid message data length"
    )]
    InvalidMessage,

    /// Parties produced inconsistent messages
    #[error("Inconsistent messages from participants")]
    InconsistentMessage,

    /// Commitment verification failed
    #[error("Commitment verification failed")]
    CommitmentVerificationFailed,

    /// Invalid share or label data received
    #[error("Invalid share data")]
    InvalidShare,

    /// Invalid input length encountered
    #[error("Invalid input length")]
    InvalidLength,

    /// Missing message
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Verification Error
    #[error("Verification Error")]
    VerificationError,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),
}

impl From<MessageSendError> for ProtocolError {
    fn from(_err: MessageSendError) -> Self {
        ProtocolError::SendMessage
    }
}

impl From<Error> for ProtocolError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => ProtocolError::AbortProtocol(p as _),
            Error::Recv => ProtocolError::MissingMessage,
            Error::Send => ProtocolError::SendMessage,
            Error::InvalidMessage => ProtocolError::InvalidMessage,
        }
    }
}
