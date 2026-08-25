// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::PrimeField;
use pasta_curves::pallas::Scalar;
use sl_messages::relay::Relay;
use sl_messages::setup::ProtocolParticipant;
use sl_secret_sharing::shamir::reconstruct_shamir_share;

use garbled_circuit::functionality::{
    utils::FilteredMsgRelay, utils_dep::ProtocolError,
};

/// Decode a peer-supplied Pallas scalar encoding.
///
/// Non-canonical encodings must not panic: return [`ProtocolError::InvalidShare`].
fn scalar_from_canonical_repr(
    bytes: [u8; 32],
) -> Result<Scalar, ProtocolError> {
    Option::<Scalar>::from(Scalar::from_repr(bytes))
        .ok_or(ProtocolError::InvalidShare)
}

/// Function to reconstruct a shamir shared Scalar value to all parties
pub async fn run_reconstruct_pallas_shamir<
    R: Relay,
    S: ProtocolParticipant,
>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &Scalar,
) -> Result<Scalar, ProtocolError> {
    use garbled_circuit::functionality::utils::{
        receive_from_one_party, send_to_party,
    };

    let tag1 = relay.next_tag(1);
    let tag2 = relay.next_tag(2);

    let my_party_id = setup.participant_index();
    let prev_party = (3 + my_party_id - 1) % 3;
    let next_party = (3 + my_party_id + 1) % 3;

    send_to_party(setup, tag1, &share.to_repr(), prev_party, relay).await?;
    send_to_party(setup, tag2, &share.to_repr(), next_party, relay).await?;

    let shares_recv_n: [u8; 32] =
        receive_from_one_party(setup, tag1, next_party, relay).await?;
    let shares_recv_p: [u8; 32] =
        receive_from_one_party(setup, tag2, prev_party, relay).await?;

    let share_prev = scalar_from_canonical_repr(shares_recv_p)?;
    let share_next = scalar_from_canonical_repr(shares_recv_n)?;

    reconstruct_shamir_share(
        *share,
        share_next,
        share_prev,
        [Scalar::from(1), Scalar::from(2), Scalar::from(3)],
        my_party_id,
    )
    .ok_or(ProtocolError::VerificationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_canonical_scalar_encoding() {
        let err = scalar_from_canonical_repr([0xff; 32]).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidShare));
    }

    #[test]
    fn accepts_canonical_scalar_encoding() {
        let s = Scalar::from(7u64);
        assert_eq!(scalar_from_canonical_repr(s.to_repr()).unwrap(), s);
    }
}
