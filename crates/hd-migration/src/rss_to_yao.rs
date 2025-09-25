use std::collections::HashMap;

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
    circuits::{build_scalar_to_y_circuit, build_verify_sharings_circuit},
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
    rng: &mut Option<G>,
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
        rng,
        yao_setup,
        comm,
    )
    .await?;

    let mut gin = HashMap::new();
    let verification_circuit = build_verify_sharings_circuit();
    for (cnt, val) in verification_circuit.garbler_input_ids.iter().enumerate() {
        let v = if cnt < 256 {
            i1_yao[256 + cnt].clone()
        } else if cnt < 256 * 2 {
            i2_yao[256 + cnt - 256].clone()
        } else {
            i3_yao[256 + cnt - (256 * 2)].clone()
        };
        gin.insert(*val, v);
    }
    let mut ein = HashMap::new();
    for (cnt, val) in verification_circuit.evaluator_input_ids.iter().enumerate() {
        let v = if cnt < 256 {
            i1_yao[cnt].clone()
        } else if cnt < 256 * 2 {
            i2_yao[cnt - 256].clone()
        } else {
            i3_yao[cnt - (256 * 2)].clone()
        };
        ein.insert(*val, v);
    }

    let outver = yao_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &gin,
        &ein,
        &verification_circuit,
        rng,
        hash,
        yao_setup,
    )
    .await?;

    let ver: Vec<YaoShare> = verification_circuit
        .output_gate_ids
        .iter()
        .map(|id| outver.get(id).unwrap().clone())
        .collect();

    let verification =
        batch_output_yao_functionality(setup, tag_offset_counter, relay, &ver).await?;

    assert!(verification[0]);

    let mut x_y = i1_yao[..256].to_vec();
    x_y.extend_from_slice(&i2_yao[..256]);

    let circ = build_scalar_to_y_circuit();

    let mut gin = HashMap::new();
    for (cnt, val) in circ.garbler_input_ids.iter().enumerate() {
        gin.insert(*val, x_y[cnt].clone());
    }
    let mut ein = HashMap::new();
    for (cnt, val) in circ.evaluator_input_ids.iter().enumerate() {
        ein.insert(*val, i3_yao[cnt].clone());
    }

    let out_hmap = yao_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &gin,
        &ein,
        &circ,
        rng,
        hash,
        yao_setup,
    )
    .await?;

    let out: Vec<YaoShare> = circ
        .output_gate_ids
        .iter()
        .map(|id| out_hmap.get(id).unwrap().clone())
        .collect();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use garbled_circuit::{
        functionality::{
            output::batch_output_yao_functionality, setup::setup_yao_functionality,
            utils_dep::TagOffsetCounter,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash},
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

        let (mut rng, hash, comm) = if setup.participant_index() == 2 {
            let hash = AesHash::new(yao_setup.e_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(hash.clone());
            (None, hash, comm)
        } else {
            let hash = AesHash::new(yao_setup.g_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(hash.clone());
            let r = ChaCha8Rng::from_seed(yao_setup.g_setup.clone().unwrap().prf_key);
            (Some(r), hash, comm)
        };

        let output = run_scalar_rss_to_yao(
            &setup, &mut relay, &mut cnt, &share, &yao_setup, &mut rng, &comm, &hash,
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
