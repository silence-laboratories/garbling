// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas::{Base, Scalar};
use rand::RngCore;
use rand::{SeedableRng, rngs::StdRng};

use garbled_circuit::{
    functionality::{
        circuit_eval::yao_circuit_eval_functionality,
        input::run_batch_input_from_all_yao,
        output::{batch_output_yao_functionality, output_yao_functionality},
        setup::setup_yao_functionality,
        utils::{FilteredMsgRelay, run_common_randomness},
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::{Commitment, HashCommitment},
        hash_function::{AesHash, HashFunction},
        types::{YaoSetup, YaoShare},
    },
};

use sl_compute_common::CommonRandomness;
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    shamir_to_rss::run_shamir_to_scalar_rss_pallas,
    utils::{bits_to_bytes_le, bytes_to_bits_le},
    zcash::build_zcash_import_function,
};

const SHARE_BITS: usize = 256;
const COMPONENT_BITS: usize = 512;

async fn run_orchard_key_components<S, R, H, C>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    shamir_share: &Scalar,
    randomness: &mut CommonRandomness,
    comm: &C,
    hash: &H,
    yao_setup: &mut YaoSetup,
) -> Result<(Vec<YaoShare>, Vec<YaoShare>, Vec<YaoShare>), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
    H: HashFunction,
    C: Commitment,
{
    let (rss_prev, rss_next) = run_shamir_to_scalar_rss_pallas(
        setup,
        relay,
        shamir_share,
        randomness,
    )
    .await?;

    let all_ip: Vec<bool> = bytes_to_bits_le(&rss_prev.to_repr())
        .chain(bytes_to_bits_le(&rss_next.to_repr()))
        .collect();

    let (i1_yao, i2_yao, i3_yao) =
        run_batch_input_from_all_yao(setup, relay, &all_ip, yao_setup, comm)
            .await?;

    let (i1_prev, i1_next) = i1_yao.split_at(SHARE_BITS);
    let (i2_prev, i2_next) = i2_yao.split_at(SHARE_BITS);
    let (i3_prev, i3_next) = i3_yao.split_at(SHARE_BITS);
    let inputs = [
        i1_next.to_vec(),
        i2_next.to_vec(),
        i3_next.to_vec(),
        i1_prev.to_vec(),
        i2_prev.to_vec(),
        i3_prev.to_vec(),
    ];

    let circuit = build_zcash_import_function();

    let output = yao_circuit_eval_functionality(
        setup, relay, &inputs, &circuit, hash, yao_setup,
    )
    .await?;

    let out_yao = circuit
        .output_gate_ids()
        .iter()
        .map(|v| output.get(v).unwrap().clone())
        .collect::<Vec<_>>();

    let (ver, component_bits) = out_yao
        .split_first()
        .expect("zcash import circuit should produce a verification bit");
    let verification = output_yao_functionality(setup, relay, ver).await?;
    if !verification {
        return Err(ProtocolError::VerificationError);
    }

    let (ask_i, rem) = component_bits.split_at(COMPONENT_BITS);
    let (nk_i, rivk_i) = rem.split_at(COMPONENT_BITS);

    Ok((ask_i.to_vec(), nk_i.to_vec(), rivk_i.to_vec()))
}

/// Runs derivation, sampling a fresh 32-byte seed from the OS-backed RNG.
///
/// Prefer this over [`run_derivation_with_seed`] in production.
pub async fn run_derivation<S, R>(
    setup: S,
    shamir_share: Scalar,
    relay: R,
) -> Result<(Scalar, Base, Scalar), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
{
    let mut rng = StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    run_derivation_with_seed(setup, shamir_share, relay, seed).await
}

/// Runs derivation from an explicit 32-byte seed.
///
/// # Security
///
/// The seed **must** be sampled from a CSPRNG and used for at most one
/// derivation. This function cannot detect reuse. Use [`run_derivation`]
/// unless you need a deterministic seed (tests or replay).
///
/// Reusing a **garbler** seed repeats `delta` and the Yao label stream, which
/// lets an evaluator XOR labels from two runs and recover `delta`.
/// Reusing an **evaluator** seed still repeats CRS and common-randomness keys.
/// The evaluator's input-bit pad is sampled from the OS RNG each run and is
/// not derived from this seed.
pub async fn run_derivation_with_seed<S, R>(
    setup: S,
    shamir_share: Scalar,
    relay: R,
    seed: [u8; 32],
) -> Result<(Scalar, Base, Scalar), ProtocolError>
where
    S: ProtocolParticipant,
    R: Relay,
{
    let mut relay = FilteredMsgRelay::new(relay);

    let mut yao_setup = setup_yao_functionality(&setup, &mut relay).await?;

    let hash = AesHash::new(yao_setup.garble_key());
    let comm = HashCommitment::new(AesHash::new(yao_setup.comm_crs()));

    let mut randomness =
        run_common_randomness(&setup, &seed, &mut relay).await?;

    let output = run_orchard_key_components(
        &setup,
        &mut relay,
        &shamir_share,
        &mut randomness,
        &comm,
        &hash,
        &mut yao_setup,
    )
    .await?;

    let out = batch_output_yao_functionality(
        &setup,
        &mut relay,
        &[output.0, output.1, output.2].concat(),
    )
    .await?;

    let (ask_bits, rem) = out.split_at(COMPONENT_BITS);
    let (nk_bits, rivk_bits) = rem.split_at(COMPONENT_BITS);
    let ask_i = bits_to_bytes_le(ask_bits);
    let nk_i = bits_to_bytes_le(nk_bits);
    let rivk_i = bits_to_bytes_le(rivk_bits);

    let ask = Scalar::from_uniform_bytes(&ask_i.try_into().unwrap());
    let nk = Base::from_uniform_bytes(&nk_i.try_into().unwrap());
    let rivk = Scalar::from_uniform_bytes(&rivk_i.try_into().unwrap());

    Ok((ask, nk, rivk))
}

#[cfg(test)]
mod tests {
    use blake2b_simd::Params;
    use ff::{Field, FromUniformBytes, PrimeField};
    use pasta_curves::pallas::{Base, Scalar};
    use rand::{SeedableRng, rngs::StdRng};

    use garbled_circuit::functionality::utils::run_init;
    use sl_messages::{
        relay::SimpleMessageRelay, setup::ProtocolParticipant,
    };

    use super::run_derivation;

    fn generate_shamir_shares(rng: &mut StdRng) -> [Scalar; 3] {
        let secret = Scalar::random(&mut *rng);
        let coeff = Scalar::random(&mut *rng);

        core::array::from_fn(|idx| {
            let point = Scalar::from((idx + 1) as u64);
            secret + coeff * point
        })
    }

    async fn test_orchard_key_components_util(
        shamir_shares: [Scalar; 3],
    ) -> [(Scalar, Base, Scalar); 3] {
        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            let pid = setup.participant_index();
            parties.spawn(run_derivation(setup, shamir_shares[pid], relay));
        }

        let mut shares = [None, None, None];

        while let Some(fini) = parties.join_next().await {
            if let Err(ref err) = fini {
                println!("error {err:?}");
            } else {
                match fini.unwrap() {
                    Err(err) => panic!("err {err:?}"),
                    Ok(share) => {
                        let idx = shares
                            .iter()
                            .position(Option::is_none)
                            .expect("space for all three shares");
                        shares[idx] = Some(share);
                    }
                }
            }
        }

        shares.map(|share| share.expect("all parties completed"))
    }

    fn prf_expand(sk: &[u8; 32], t: u8) -> [u8; 64] {
        let mut hasher = Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state();
        hasher.update(sk);
        hasher.update(&[t]);
        let hash = hasher.finalize();
        let mut res = [0u8; 64];
        res.copy_from_slice(hash.as_bytes());
        res
    }

    fn get_evaluation(
        party_points: &[Scalar],
        evals: &[Scalar],
        eval_point: &Scalar,
    ) -> Scalar {
        let lcoeff = party_points.iter().map(|x_i| {
            let mut coeff = Scalar::ONE;
            for x_j in party_points {
                if x_i != x_j {
                    let num = x_j.sub(eval_point);
                    let sub = x_j.sub(x_i);
                    coeff *= num * sub.invert().unwrap();
                }
            }
            coeff
        });

        evals
            .iter()
            .zip(lcoeff)
            .fold(Scalar::ZERO, |acc, (ev, lc)| acc + *ev * lc)
    }

    fn get_ideal_execution(sk: [u8; 32]) -> (Scalar, Base, Scalar) {
        let ask_bytes = prf_expand(&sk, 0x06);
        let ask = Scalar::from_uniform_bytes(&ask_bytes);

        let nk_bytes = prf_expand(&sk, 0x07);
        let nk = Base::from_uniform_bytes(&nk_bytes);

        let rivk_bytes = prf_expand(&sk, 0x08);
        let rivk = Scalar::from_uniform_bytes(&rivk_bytes);

        (ask, nk, rivk)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_orchard_key_components() {
        let mut rng = StdRng::from_entropy();
        let shamir_shares = generate_shamir_shares(&mut rng);

        let pts = [Scalar::ONE, Scalar::from(2u64)];
        let sk = get_evaluation(
            &pts,
            &[shamir_shares[0], shamir_shares[1]],
            &Scalar::ZERO,
        );
        let (ask_ideal, nk_ideal, rivk_ideal) =
            get_ideal_execution(sk.to_repr());

        let out = test_orchard_key_components_util(shamir_shares).await;
        assert_eq!(out[0], out[1]);
        assert_eq!(out[0], out[2]);
        let ask = out[0].0;
        let nk = out[0].1;
        let rivk = out[0].2;

        assert_eq!(ask, ask_ideal);
        assert_eq!(nk, nk_ideal);
        assert_eq!(rivk, rivk_ideal);

        assert!(!bool::from(ask.is_zero()));

        use orchard::{
            keys::FullViewingKey,
            primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
        };

        let mut ask_eff = ask;
        let ak_bytes = loop {
            let signing_key: SigningKey<SpendAuth> =
                ask_eff.to_repr().try_into().unwrap();
            let vk: VerificationKey<SpendAuth> = (&signing_key).into();
            let ak_bytes: [u8; 32] = (&vk).into();

            if (ak_bytes[31] >> 7) == 1 {
                ask_eff = -ask_eff;
                continue;
            }

            break ak_bytes;
        };

        let mut fvk_bytes = [0u8; 96];
        fvk_bytes[0..32].copy_from_slice(&ak_bytes);
        fvk_bytes[32..64].copy_from_slice(&nk.to_repr());
        fvk_bytes[64..96].copy_from_slice(&rivk.to_repr());

        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .expect("valid Orchard FullViewingKey");

        let internal_ivk = fvk.to_ivk(orchard::keys::Scope::Internal);
        let external_ivk = fvk.to_ivk(orchard::keys::Scope::External);

        for ivk in [internal_ivk, external_ivk] {
            let ivk_bytes = ivk.to_bytes();
            assert_ne!(ivk_bytes, [0u8; 64]);
            assert!(bool::from(
                orchard::keys::IncomingViewingKey::from_bytes(&ivk_bytes)
                    .is_some()
            ));
        }
    }
}
