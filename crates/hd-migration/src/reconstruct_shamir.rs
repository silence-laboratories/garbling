use garbled_circuit::functionality::{
    utils::{FilteredMsgRelay, FixedExternalSize, receive_from_parties, send_to_party},
    utils_dep::TagOffsetCounter,
};
use k256::{NonZeroScalar, Scalar};
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    constants::RECONSTRUCT_SHAMIR_MSG1,
    types::{HardDerivationError, ProtocolParticipant, ScalarVal},
    utils::get_evaluation,
};

pub fn reconstruct_shamir_process_msg1(
    share: &Scalar,
    share_next: &Scalar,
    share_prev: &Scalar,
    party_points: &[NonZeroScalar],
    party_id: &usize,
) -> Scalar {
    let evals = [*share, *share_prev];
    let (ppts, next_eval) = match party_id {
        1 => ([party_points[0], party_points[2]], party_points[1]),
        2 => ([party_points[1], party_points[0]], party_points[2]),
        3 => ([party_points[2], party_points[1]], party_points[0]),
        _ => unreachable!(),
    };

    let next_val = get_evaluation(&ppts, evals.as_ref(), &next_eval);
    assert_eq!(*share_next, next_val);

    get_evaluation(&ppts, &evals, &Scalar::ZERO)
}

/// Function to reconstruct a shamir shared Scalar value to all parties
pub async fn run_reconstruct_shamir<R: Relay, S: ProtocolParticipant>(
    setup: &S,
    relay: &mut R,
    tag_offset_counter: &mut TagOffsetCounter,
    share: &Scalar,
    evaluation_points: &[NonZeroScalar],
) -> Result<Scalar, HardDerivationError> {
    let mut relay = FilteredMsgRelay::new(relay);

    let tag1 = MessageTag::tag1(RECONSTRUCT_SHAMIR_MSG1, tag_offset_counter.next_value());
    let tag2 = MessageTag::tag1(RECONSTRUCT_SHAMIR_MSG1, tag_offset_counter.next_value());
    relay.ask_messages(setup, tag1, true).await?;
    relay.ask_messages(setup, tag2, true).await?;

    let out = run_reconstruct_shamir_inner(setup, &mut relay, share, evaluation_points, tag1, tag2)
        .await?;

    Ok(out)
}

/// Function to reconstruct a shamir shared Scalar value to all parties
pub async fn run_reconstruct_shamir_inner<R: Relay, S: ProtocolParticipant>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &Scalar,
    evaluation_points: &[NonZeroScalar],
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<Scalar, HardDerivationError> {
    let my_party_id = setup.participant_index();
    let prev_party = (3 + my_party_id - 1) % 3;
    let next_party = (3 + my_party_id + 1) % 3;

    send_to_party(setup, tag1, ScalarVal(*share), prev_party, relay).await?;
    send_to_party(setup, tag2, ScalarVal(*share), next_party, relay).await?;

    let shares_recv_n: Vec<ScalarVal> =
        receive_from_parties(setup, tag1, ScalarVal::SIZE, &[next_party], relay).await?;
    let shares_recv_p: Vec<ScalarVal> =
        receive_from_parties(setup, tag2, ScalarVal::SIZE, &[prev_party], relay).await?;

    let share_prev = shares_recv_p[0].0;
    let share_next = shares_recv_n[0].0;
    let out = reconstruct_shamir_process_msg1(
        share,
        &share_next,
        &share_prev,
        evaluation_points,
        &(my_party_id + 1),
    );

    Ok(out)
}

#[cfg(test)]
mod tests {

    use garbled_circuit::functionality::utils_dep::TagOffsetCounter;
    use k256::{NonZeroScalar, Scalar};
    use rand::{CryptoRng, RngCore, SeedableRng, rngs};

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
        let mut relay = relay;

        let mut cnt = TagOffsetCounter::new();

        let output =
            run_reconstruct_shamir(&setup, &mut relay, &mut cnt, &share, &evaluation_points)
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
                    Err(err) => panic!("err {:?}", err),
                    Ok(share) => shares.push(share),
                }
            }
        }

        assert_eq!(s, shares[0].1);
        assert_eq!(s, shares[1].1);
        assert_eq!(s, shares[2].1);
    }
}
