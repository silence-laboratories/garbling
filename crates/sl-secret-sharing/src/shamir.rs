// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::Field;

fn pair_factor<F: Field>(j: F, m: F) -> F {
    let num = j - m;
    let denom = -m;
    num * denom.invert().unwrap()
}

pub fn interpolate_at<F>(party_points: &[F], evals: &[F], eval_point: F) -> F
where
    F: Field + PartialEq,
{
    assert_eq!(party_points.len(), evals.len());

    evals
        .iter()
        .zip(party_points.iter())
        .fold(F::ZERO, |acc, (eval, x_i)| {
            let coeff = party_points.iter().fold(F::ONE, |coeff, x_j| {
                if x_i == x_j {
                    coeff
                } else {
                    let num = *x_j - eval_point;
                    let denom = *x_j - *x_i;
                    coeff * num * denom.invert().unwrap()
                }
            });
            acc + (*eval * coeff)
        })
}

pub fn rss_pair_to_shamir<F>(
    prev_share: F,
    next_share: F,
    party_id: usize,
    eval_points: [F; 3],
) -> F
where
    F: Field,
{
    match party_id {
        0 => {
            let term12 =
                next_share * pair_factor(eval_points[0], eval_points[2]);
            let term13 =
                prev_share * pair_factor(eval_points[0], eval_points[1]);
            term12 + term13
        }
        1 => {
            let term12 =
                prev_share * pair_factor(eval_points[1], eval_points[2]);
            let term23 =
                next_share * pair_factor(eval_points[1], eval_points[0]);
            term12 + term23
        }
        2 => {
            let term13 =
                next_share * pair_factor(eval_points[2], eval_points[1]);
            let term23 =
                prev_share * pair_factor(eval_points[2], eval_points[0]);
            term13 + term23
        }
        _ => panic!("party_id must be in 0..3"),
    }
}

pub fn finalize_shamir_to_rss<F>(
    padded: F,
    r_prev: F,
    r_next: F,
    party_id: usize,
) -> (F, F)
where
    F: Field,
{
    match party_id {
        0 => (padded - r_prev, -r_next),
        1 => (-r_prev, -r_next),
        2 => (-r_prev, padded - r_next),
        _ => panic!("party_id must be in 0..3"),
    }
}

pub fn reconstruct_shamir_share<F>(
    share: F,
    share_next: F,
    share_prev: F,
    party_points: [F; 3],
    party_id: usize,
) -> Option<F>
where
    F: Field + PartialEq,
{
    let evals = [share, share_prev];
    let (ppts, next_eval) = match party_id {
        0 => ([party_points[0], party_points[2]], party_points[1]),
        1 => ([party_points[1], party_points[0]], party_points[2]),
        2 => ([party_points[2], party_points[1]], party_points[0]),
        _ => return None,
    };

    let next_val = interpolate_at(&ppts, &evals, next_eval);
    if share_next != next_val {
        return None;
    }

    Some(interpolate_at(&ppts, &evals, F::ZERO))
}

#[cfg(test)]
mod tests {
    use k256::Scalar;

    use super::{
        finalize_shamir_to_rss, interpolate_at, reconstruct_shamir_share,
        rss_pair_to_shamir,
    };

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    #[test]
    fn interpolate_matches_linear_polynomial() {
        let points = [scalar(2), scalar(5)];
        let evals = [scalar(11), scalar(29)];

        let at_zero = interpolate_at(&points, &evals, Scalar::ZERO);
        let at_nine = interpolate_at(&points, &evals, scalar(9));

        assert_eq!(at_zero, -Scalar::ONE);
        assert_eq!(at_nine, scalar(53));
    }

    #[test]
    fn reconstruct_shamir_share_rejects_inconsistent_neighbor() {
        let points = [scalar(2), scalar(5), scalar(9)];
        let secret = scalar(7);
        let slope = scalar(3);
        let shares = points.map(|x| secret + slope * x);

        let reconstructed = reconstruct_shamir_share(
            shares[0], shares[1], shares[2], points, 0,
        );
        assert_eq!(reconstructed, Some(secret));

        let invalid = reconstruct_shamir_share(
            shares[0],
            shares[1] + Scalar::ONE,
            shares[2],
            points,
            0,
        );
        assert_eq!(invalid, None);
    }

    #[test]
    fn rss_pair_to_shamir_matches_expected_standard_point_formula() {
        let prev = scalar(5);
        let next = scalar(7);
        let points = [scalar(1), scalar(2), scalar(3)];
        let inv_two = scalar(2).invert().unwrap();
        let inv_three = scalar(3).invert().unwrap();

        let p0 = rss_pair_to_shamir(prev, next, 0, points);
        let p1 = rss_pair_to_shamir(prev, next, 1, points);
        let p2 = rss_pair_to_shamir(prev, next, 2, points);

        assert_eq!(p0, next * (scalar(2) * inv_three) + prev * inv_two);
        assert_eq!(p1, prev * inv_three - next);
        assert_eq!(p2, -(next * inv_two) - (prev + prev));
    }

    #[test]
    fn finalize_shamir_to_rss_uses_party_position() {
        let padded = scalar(17);
        let r_prev = scalar(4);
        let r_next = scalar(9);

        assert_eq!(
            finalize_shamir_to_rss(padded, r_prev, r_next, 0),
            (scalar(13), -scalar(9))
        );
        assert_eq!(
            finalize_shamir_to_rss(padded, r_prev, r_next, 1),
            (-scalar(4), -scalar(9))
        );
        assert_eq!(
            finalize_shamir_to_rss(padded, r_prev, r_next, 2),
            (-scalar(4), scalar(8))
        );
    }
}
