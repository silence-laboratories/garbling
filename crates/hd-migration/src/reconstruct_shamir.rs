// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use k256::{NonZeroScalar, Scalar};
use sl_secret_sharing::shamir::reconstruct_shamir_share;

use sl_messages::relay::Relay;

use garbled_circuit::functionality::utils::{
    receive_from_one_party, send_to_party, FilteredMsgRelay,
};

use crate::{
    constants::RECONSTRUCT_SHAMIR_MSG1,
    types::{HardDerivationError, ProtocolParticipant, ScalarVal},
};

/// Function to reconstruct a shamir shared Scalar value to all parties
pub async fn run_reconstruct_shamir<R: Relay, S: ProtocolParticipant>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &Scalar,
    evaluation_points: &[NonZeroScalar],
) -> Result<Scalar, HardDerivationError> {
    let tag1 = relay.next_tag(RECONSTRUCT_SHAMIR_MSG1);
    let tag2 = relay.next_tag(RECONSTRUCT_SHAMIR_MSG1);

    let my_party_id = setup.participant_index();
    let prev_party = (3 + my_party_id - 1) % 3;
    let next_party = (3 + my_party_id + 1) % 3;

    send_to_party(setup, tag1, &ScalarVal(*share), prev_party, relay).await?;
    send_to_party(setup, tag2, &ScalarVal(*share), next_party, relay).await?;

    let shares_recv_n: ScalarVal =
        receive_from_one_party(setup, tag1, next_party, relay).await?;
    let shares_recv_p: ScalarVal =
        receive_from_one_party(setup, tag2, prev_party, relay).await?;

    let share_prev = &shares_recv_p.0;
    let share_next = &shares_recv_n.0;
    let eval_points = [
        *evaluation_points[0].as_ref(),
        *evaluation_points[1].as_ref(),
        *evaluation_points[2].as_ref(),
    ];

    reconstruct_shamir_share(
        *share,
        *share_next,
        *share_prev,
        eval_points,
        my_party_id,
    )
    .ok_or(HardDerivationError::Internal)
}

#[cfg(test)]
mod tests {

    use garbled_circuit::functionality::utils::FilteredMsgRelay;
    use k256::{NonZeroScalar, Scalar};
    use rand::{rngs, CryptoRng, RngCore, SeedableRng};

    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::{
        reconstruct_shamir::run_reconstruct_shamir,
        types::{HardDerivationError, ProtocolParticipant, ScalarFromBytes},
        utils::{get_evaluation, run_init},
    };

    fn random_scalar<R: RngCore + CryptoRng>(r: &mut R) -> Scalar {
        let mut bytes = [0u8; 32];
        r.fill_bytes(&mut bytes);
        Scalar::from_bytes(bytes)
    }

    async fn test_run_reconstruct_shamir<S, R>(
        setup: S,
        share: Scalar,
        evaluation_points: Vec<NonZeroScalar>,
        relay: R,
    ) -> Result<(usize, Scalar), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);
        relay.init_abort(&setup).await?;

        let output = run_reconstruct_shamir(
            &setup,
            &mut relay,
            &share,
            &evaluation_points,
        )
        .await?;

        Ok((setup.participant_index(), output))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_reconstruct_shamir() {
        let mut rng = rngs::StdRng::from_entropy();

        let x1 = NonZeroScalar::new(random_scalar(&mut rng)).unwrap();
        let x2 = NonZeroScalar::new(random_scalar(&mut rng)).unwrap();
        let x3 = NonZeroScalar::new(random_scalar(&mut rng)).unwrap();

        let evaluationpoints = [x1, x2, x3];

        let s1 = random_scalar(&mut rng);
        let s2 = random_scalar(&mut rng);
        let s3 = get_evaluation(&[x1, x2], &[s1, s2], &x3);

        let s = get_evaluation(&[x1, x2], &[s1, s2], &Scalar::ZERO);

        let shares = [s1, s2, s3];

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        let mut cnt = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_reconstruct_shamir(
                setup,
                shares[cnt],
                evaluationpoints.to_vec(),
                relay,
            ));
            cnt += 1;
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

        assert_eq!(s, shares[0].1);
        assert_eq!(s, shares[1].1);
        assert_eq!(s, shares[2].1);
    }
}
