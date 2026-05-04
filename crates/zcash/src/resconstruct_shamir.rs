// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::{Field, PrimeField};
use pasta_curves::pallas::Scalar;
use sl_messages::relay::Relay;
use sl_messages::setup::ProtocolParticipant;

use garbled_circuit::functionality::{
    utils::FilteredMsgRelay, utils_dep::ProtocolError,
};

use crate::utils::get_evaluation;

fn reconstruct_shamir_process_msg1(
    share: &Scalar,
    share_next: &Scalar,
    share_prev: &Scalar,
    party_points: &[Scalar],
    party_id: usize,
) -> Result<Scalar, ProtocolError> {
    let evals = [*share, *share_prev];
    let (ppts, next_eval) = match party_id {
        0 => ([party_points[0], party_points[2]], &party_points[1]),
        1 => ([party_points[1], party_points[0]], &party_points[2]),
        2 => ([party_points[2], party_points[1]], &party_points[0]),
        _ => return Err(ProtocolError::InvalidMessage),
    };

    let next_val = get_evaluation(&ppts, &evals, next_eval);

    if *share_next != next_val {
        return Err(ProtocolError::VerificationError);
    }

    Ok(get_evaluation(&ppts, &evals, &Scalar::ZERO))
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

    let share_prev = &Scalar::from_repr(shares_recv_p).unwrap();
    let share_next = &Scalar::from_repr(shares_recv_n).unwrap();

    let eval_points = (0..3).map(|v| Scalar::from(v + 1)).collect::<Vec<_>>();

    reconstruct_shamir_process_msg1(
        share,
        share_next,
        share_prev,
        &eval_points,
        my_party_id,
    )
}
