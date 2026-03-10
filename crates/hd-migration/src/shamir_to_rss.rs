// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use k256::{NonZeroScalar, ProjectivePoint, Scalar};

use sl_compute_common::CommonRandomness;
use sl_messages::relay::Relay;

use garbled_circuit::functionality::utils::FilteredMsgRelay;

use crate::{
    reconstruct_shamir::run_reconstruct_shamir,
    types::{HardDerivationError, PrivKeyShare, ProtocolParticipant},
};

/// Converts an RSS-shared Scalar value (`PrivKeyShare`) to a shamir shared value
/// for party with id `party_id` for a set of evaluation points.
pub fn scalar_rss_to_shamir(
    inp: &PrivKeyShare<ProjectivePoint>,
    party_id: usize,
    evaluation_points: &[NonZeroScalar],
) -> Scalar {
    // helper closure f_A(j) = (j - m)/(-m)
    let f = |j: NonZeroScalar, m: NonZeroScalar| -> Scalar {
        let num = j.sub(&m);
        let denom = -m;
        num * denom.invert().unwrap()
    };

    match party_id {
        0 => {
            // subsets containing 1: {1,2} (next_share), {1,3} (prev_share)
            let term12 = inp.next_share
                * f(evaluation_points[0], evaluation_points[2]);
            let term13 = inp.prev_share
                * f(evaluation_points[0], evaluation_points[1]);
            term12 + term13
        }

        1 => {
            // subsets containing 2: {1,2} (prev_share), {2,3} (next_share)
            let term12 = inp.prev_share
                * f(evaluation_points[1], evaluation_points[2]);
            let term23 = inp.next_share
                * f(evaluation_points[1], evaluation_points[0]);
            term12 + term23
        }

        2 => {
            // subsets containing 3: {1,3} (next_share), {2,3} (prev_share)
            let term13 = inp.next_share
                * f(evaluation_points[2], evaluation_points[1]);
            let term23 = inp.prev_share
                * f(evaluation_points[2], evaluation_points[0]);
            term13 + term23
        }

        _ => unreachable!(),
    }
}

/// Converts a Shamir-shared Scalar valueto an RSS-shared Scalar value (`PrivKeyShare`)
pub async fn run_shamir_to_scalar_rss<R: Relay, S: ProtocolParticipant>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &Scalar,
    evaluation_points: &[NonZeroScalar],
    randomness: &mut CommonRandomness,
) -> Result<PrivKeyShare<ProjectivePoint>, HardDerivationError> {
    let my_party_id = setup.participant_index();

    let r_scalar_rss =
        PrivKeyShare::<ProjectivePoint>::get_random_share(randomness);

    let r_shamir =
        scalar_rss_to_shamir(&r_scalar_rss, my_party_id, evaluation_points);

    let padded_shamir = share + r_shamir;

    let padded = run_reconstruct_shamir(
        setup,
        relay,
        &padded_shamir,
        evaluation_points,
    )
    .await?;

    let out_rss = if my_party_id == 0 {
        PrivKeyShare::<ProjectivePoint> {
            prev_share: padded - r_scalar_rss.prev_share,
            next_share: -r_scalar_rss.next_share,
        }
    } else if my_party_id == 1 {
        PrivKeyShare::<ProjectivePoint> {
            prev_share: -r_scalar_rss.prev_share,
            next_share: -r_scalar_rss.next_share,
        }
    } else {
        PrivKeyShare::<ProjectivePoint> {
            prev_share: -r_scalar_rss.prev_share,
            next_share: padded - r_scalar_rss.next_share,
        }
    };

    Ok(out_rss)
}

#[cfg(test)]
mod tests {
    use garbled_circuit::functionality::utils::{
        run_common_randomness, FilteredMsgRelay,
    };
    use k256::{NonZeroScalar, ProjectivePoint, Scalar};
    use rand::{
        rngs::{self, StdRng},
        CryptoRng, RngCore, SeedableRng,
    };

    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::{
        shamir_to_rss::run_shamir_to_scalar_rss,
        types::{
            HardDerivationError, PrivKeyShare, ProtocolParticipant,
            ScalarFromBytes,
        },
        utils::{get_evaluation, run_init},
    };

    async fn test_run_shamir_to_scalar_rss<S, R>(
        setup: S,
        share: Scalar,
        evaluation_points: Vec<NonZeroScalar>,
        relay: R,
    ) -> Result<(usize, PrivKeyShare<ProjectivePoint>), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);
        relay.init_abort(&setup).await?;

        let mut seed = [0u8; 32];
        let mut r = StdRng::from_entropy();
        r.fill_bytes(&mut seed);
        let mut randomness =
            run_common_randomness(&setup, &seed, &mut relay).await?;

        let output = run_shamir_to_scalar_rss(
            &setup,
            &mut relay,
            &share,
            &evaluation_points,
            &mut randomness,
        )
        .await?;

        Ok((setup.participant_index(), output))
    }

    fn random_scalar<R: RngCore + CryptoRng>(r: &mut R) -> Scalar {
        let mut bytes = [0u8; 32];
        r.fill_bytes(&mut bytes);
        Scalar::from_bytes(bytes)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_shamir_to_scalar_rss() {
        let mut rng = rngs::StdRng::from_entropy();

        let x1 = NonZeroScalar::new(random_scalar(&mut rng)).unwrap();
        let x2 = NonZeroScalar::new(random_scalar(&mut rng)).unwrap();
        let x3 = NonZeroScalar::new(random_scalar(&mut rng)).unwrap();

        let evaluationpoints = [x1, x2, x3];

        let s1 = random_scalar(&mut rng);
        let s2 = random_scalar(&mut rng);
        let s3 = get_evaluation(&[x1, x2], &[s1, s2], &x3);

        let shares = [s1, s2, s3];

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        let mut s = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_shamir_to_scalar_rss(
                setup,
                shares[s],
                evaluationpoints.to_vec(),
                relay,
            ));
            s += 1;
        }

        let mut shares = vec![];

        while let Some(fini) = parties.join_next().await {
            if let Err(ref err) = fini {
                println!("error {err:?}");
            } else {
                match fini.unwrap() {
                    Err(err) => panic!("err {err:?}"),
                    Ok(share) => shares.push(share),
                }
            }
        }

        let output = shares[0].1.next_share
            + shares[1].1.next_share
            + shares[2].1.next_share;
        let output2 = shares[0].1.prev_share
            + shares[1].1.prev_share
            + shares[2].1.prev_share;
        let s = get_evaluation(&[x1, x2], &[s1, s2], &Scalar::ZERO);

        assert_eq!(output, s);
        assert_eq!(output2, s);
    }
}
