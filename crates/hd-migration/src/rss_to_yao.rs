use garbled_circuit::{
    functionality::{
        circuit_eval::yao_circuit_eval_functionality, input::run_batch_input_from_all_yao,
        output::batch_output_yao_functionality, utils_dep::TagOffsetCounter,
    },
    utilities::{
        commitments::Commitment,
        hash_function::HashFunction,
        types::{YaoSetup, YaoShare},
    },
};
use k256::ProjectivePoint;
use rand::{CryptoRng, RngCore};
use sl_messages::relay::Relay;

use crate::{
    circuits::build_scalar_to_y_verification_circuit,
    types::{HardDerivationError, PrivKeyShare, ProtocolParticipant},
    utils::bytes_to_bits_le,
};

/// Converts an RSS-shared Scalar value (`PrivKeyShare`) to a `YaoShare` value
#[allow(clippy::too_many_arguments)]
pub async fn run_scalar_rss_to_yao<S, R, C, G, H>(
    setup: &S,
    relay: &mut R,
    tag_offset_counter: &mut TagOffsetCounter,
    share: &PrivKeyShare<ProjectivePoint>,
    yao_setup: &YaoSetup,
    mut rng: Option<&mut G>,
    comm: &C,
    hash: &H,
) -> Result<Vec<YaoShare>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    C: Commitment,
    H: HashFunction,
{
    let prev = bytes_to_bits_le(&share.prev_share.to_bytes());
    let next = bytes_to_bits_le(&share.next_share.to_bytes());

    let mut all_ip = prev.clone();
    all_ip.extend_from_slice(&next);

    let (i1_yao, i2_yao, i3_yao) = run_batch_input_from_all_yao(
        setup,
        tag_offset_counter,
        relay,
        &all_ip,
        all_ip.len(),
        all_ip.len(),
        all_ip.len(),
        rng.as_mut(),
        yao_setup,
        comm,
    )
    .await?;

    let mut inputs = vec![vec![], vec![], vec![], vec![], vec![], vec![]];

    inputs[0].extend_from_slice(&i1_yao[256..]);
    inputs[1].extend_from_slice(&i2_yao[256..]);
    inputs[2].extend_from_slice(&i3_yao[256..]);

    inputs[3].extend_from_slice(&i1_yao[..256]);
    inputs[4].extend_from_slice(&i2_yao[..256]);
    inputs[5].extend_from_slice(&i3_yao[..256]);

    let circ = build_scalar_to_y_verification_circuit();

    let outp = yao_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &inputs,
        &circ,
        rng,
        hash,
        yao_setup,
    )
    .await?;

    let veradd: Vec<YaoShare> = circ
        .output_gate_ids
        .iter()
        .map(|id| outp.get(id).unwrap().clone())
        .collect();

    let verification =
        batch_output_yao_functionality(setup, tag_offset_counter, relay, &veradd[..1]).await?;

    assert!(verification[0]);

    let out = veradd[1..].to_vec();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use garbled_circuit::{
        functionality::{
            output::batch_output_yao_functionality, setup::setup_yao_functionality,
            utils_dep::TagOffsetCounter,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash, types::YaoSetup},
    };
    use k256::{ProjectivePoint, Scalar};
    use rand::{RngCore, SeedableRng, rngs};
    use rand_chacha::ChaCha8Rng;
    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::{
        rss_to_yao::run_scalar_rss_to_yao,
        types::{HardDerivationError, PrivKeyShare, ProtocolParticipant, ScalarFromBytes},
        utils::run_init,
    };

    async fn test_run_scalar_to_yao<S, R>(
        setup: S,
        share: PrivKeyShare<ProjectivePoint>,
        relay: R,
    ) -> Result<(usize, Scalar), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut cnt = TagOffsetCounter::new();

        let yao_setup = setup_yao_functionality(&setup, &mut cnt, &mut relay).await?;

        let (mut rng, hash, comm) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesHash::new(e.comm_crs);
                let comm = HashCommitment::new(hash.clone());
                (None, hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesHash::new(g.comm_crs);
                let comm = HashCommitment::new(hash);
                let r = ChaCha8Rng::from_seed(g.prf_key);
                (Some(r), hash, comm)
            }
        };

        let output = run_scalar_rss_to_yao(
            &setup,
            &mut relay,
            &mut cnt,
            &share,
            &yao_setup,
            rng.as_mut(),
            &comm,
            &hash,
        )
        .await?;

        let op = batch_output_yao_functionality(&setup, &mut cnt, &mut relay, &output).await?;

        let mut sum = Scalar::ZERO;
        let two = Scalar::ONE + Scalar::ONE;
        let mut twopow = Scalar::ONE;
        for i in op {
            if i {
                sum += twopow;
            }
            twopow *= two;
        }

        Ok((setup.participant_index(), sum))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_scalar_to_yao() {
        let mut rng = rngs::StdRng::from_entropy();

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let s1 = Scalar::from_bytes(bytes);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let s2 = Scalar::from_bytes(bytes);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let s3 = Scalar::from_bytes(bytes);

        let share1 = PrivKeyShare::<ProjectivePoint> {
            prev_share: s1,
            next_share: s2,
        };
        let share2 = PrivKeyShare::<ProjectivePoint> {
            prev_share: s2,
            next_share: s3,
        };
        let share3 = PrivKeyShare::<ProjectivePoint> {
            prev_share: s3,
            next_share: s1,
        };

        let shares = [share1, share2, share3];

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        let mut cnt = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_scalar_to_yao(setup, shares[cnt], relay));
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

        let s = s1 + s2 + s3;

        assert_eq!(s, shares[0].1);
        assert_eq!(s, shares[1].1);
        assert_eq!(s, shares[2].1);
    }
}
