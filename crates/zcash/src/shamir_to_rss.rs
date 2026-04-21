use garbled_circuit::functionality::{
    utils::FilteredMsgRelay, utils_dep::ProtocolError,
};

use group::{Group, GroupEncoding};
use pasta_curves::{pallas, pallas::Scalar};
use sl_compute_common::CommonRandomness;
use sl_messages::relay::Relay;
use sl_messages::setup::ProtocolParticipant;

use crate::resconstruct_shamir::run_reconstruct_pallas_shamir;

/// Converts an RSS-shared Scalar value (`PrivKeyShare`) to a shamir shared value
/// for party with id `party_id` for a set of evaluation points.
pub fn scalar_rss_to_shamir<G>(
    prev_share: G::Scalar,
    next_share: G::Scalar,
    party_id: usize,
) -> G::Scalar
where
    G: Group + GroupEncoding,
{
    // helper closure f_A(j) = (j - m)/(-m)

    use std::ops::Sub;

    use group::ff::Field;

    let eval_points =
        (0..3).map(|v| G::Scalar::from(v + 1)).collect::<Vec<_>>();

    let f = |j: G::Scalar, m: G::Scalar| -> G::Scalar {
        let num = j.sub(&m);
        let denom = -m;
        num * denom.invert().unwrap()
    };

    match party_id {
        0 => {
            // subsets containing 1: {1,2} (next_share), {1,3} (prev_share)
            let term12 = next_share * f(eval_points[0], eval_points[2]);
            let term13 = prev_share * f(eval_points[0], eval_points[1]);
            term12 + term13
        }

        1 => {
            // subsets containing 2: {1,2} (prev_share), {2,3} (next_share)
            let term12 = prev_share * f(eval_points[1], eval_points[2]);
            let term23 = next_share * f(eval_points[1], eval_points[0]);
            term12 + term23
        }

        2 => {
            // subsets containing 3: {1,3} (next_share), {2,3} (prev_share)
            let term13 = next_share * f(eval_points[2], eval_points[1]);
            let term23 = prev_share * f(eval_points[2], eval_points[0]);
            term13 + term23
        }

        _ => unreachable!(),
    }
}

fn get_random_pallas_scalar_share(
    common_randomness: &mut CommonRandomness,
) -> (pasta_curves::Fq, pasta_curves::Fq) {
    use multi_party_schnorr::common::traits::ScalarReduce;

    let (prev_bytes, next_bytes) = common_randomness.random_32_bytes();
    let prev: pallas::Scalar = pallas::Scalar::reduce_from_bytes(&prev_bytes);
    let next: pallas::Scalar = pallas::Scalar::reduce_from_bytes(&next_bytes);

    (prev, next)
}

/// Converts a Shamir-shared Scalar valueto an RSS-shared Scalar value (`PrivKeyShare`)
pub async fn run_shamir_to_scalar_rss_pallas<
    R: Relay,
    S: ProtocolParticipant,
>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &pallas::Scalar,
    randomness: &mut CommonRandomness,
) -> Result<(Scalar, Scalar), ProtocolError> {
    use multi_party_schnorr::common::redpallas::RedPallasPoint;

    let my_party_id = setup.participant_index();

    let (r_prev, r_next) = get_random_pallas_scalar_share(randomness);

    let r_shamir =
        scalar_rss_to_shamir::<RedPallasPoint>(r_prev, r_next, my_party_id);

    let padded_shamir = share + r_shamir;

    let padded =
        run_reconstruct_pallas_shamir(setup, relay, &padded_shamir).await?;

    let out_rss = if my_party_id == 0 {
        (padded - r_prev, -r_next)
    } else if my_party_id == 1 {
        (-r_prev, -r_next)
    } else {
        (-r_prev, padded - r_next)
    };

    Ok(out_rss)
}
