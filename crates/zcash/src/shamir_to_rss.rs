// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::FromUniformBytes;
use group::{Group, GroupEncoding};
use pasta_curves::pallas::{Point, Scalar};
use sha2::{Digest, Sha512};

use sl_compute_common::CommonRandomness;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use garbled_circuit::functionality::{
    utils::FilteredMsgRelay, utils_dep::ProtocolError,
};
use sl_secret_sharing::shamir::{finalize_shamir_to_rss, rss_pair_to_shamir};

use crate::reconstruct_shamir::run_reconstruct_pallas_shamir;

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

    use ff::Field;

    let one = G::Scalar::ONE;
    let eval_points = [one, one + one, one + one + one];

    rss_pair_to_shamir(prev_share, next_share, party_id, eval_points)
}

fn get_random_pallas_scalar_share(
    common_randomness: &mut CommonRandomness,
) -> (Scalar, Scalar) {
    let (prev_bytes, next_bytes) = common_randomness.random_32_bytes();
    (
        scalar_from_random_bytes(prev_bytes),
        scalar_from_random_bytes(next_bytes),
    )
}

fn scalar_from_random_bytes(bytes: [u8; 32]) -> Scalar {
    // Expand deterministically to 64 bytes, then rely on the field's
    // uniform-byte reduction instead of a biased truncation/mod-q shortcut.
    //
    // Tradeoff:
    // - This is more expensive than directly reducing the original 32 bytes.
    // - It gives better statistical quality: the old RedPallas
    //   `reduce_from_bytes` path zero-extended 32 bytes to 64 and then called
    //   `from_uniform_bytes`, which still induces modulo bias because only the
    //   low half varied.
    // - Simpler deterministic 32->64-byte expansions such as duplicating the
    //   input or filling the upper half with its bitwise complement were also
    //   considered, but they still feed `from_uniform_bytes` a highly
    //   structured subset of 64-byte inputs.
    // - Hashing first lets all 64 input bytes vary, so `from_uniform_bytes`
    //   gets a full-width deterministic input with negligible bias.
    let mut hasher = Sha512::new();
    hasher.update(b"zcash.scalar_from_random_bytes.v1");
    hasher.update(bytes);

    let mut uniform_bytes = [0u8; 64];
    uniform_bytes.copy_from_slice(&hasher.finalize());
    Scalar::from_uniform_bytes(&uniform_bytes)
}

/// Converts a Shamir-shared Scalar valueto an RSS-shared Scalar value (`PrivKeyShare`)
pub async fn run_shamir_to_scalar_rss_pallas<
    R: Relay,
    S: ProtocolParticipant,
>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &Scalar,
    randomness: &mut CommonRandomness,
) -> Result<(Scalar, Scalar), ProtocolError> {
    let my_party_id = setup.participant_index();

    let (r_prev, r_next) = get_random_pallas_scalar_share(randomness);

    let r_shamir = scalar_rss_to_shamir::<Point>(r_prev, r_next, my_party_id);

    let padded_shamir = share + r_shamir;

    let padded =
        run_reconstruct_pallas_shamir(setup, relay, &padded_shamir).await?;

    let out_rss = finalize_shamir_to_rss(padded, r_prev, r_next, my_party_id);

    Ok(out_rss)
}
