// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::PrimeField;
use pasta_curves::pallas::Scalar;

use garbled_circuit::{
    arithmetic::{build_compare_eq_circuit, build_mod_add_circut},
    circuit::{BinaryCircuit, CircuitBuilder},
};

use crate::prf::build_prf_expand_circuit;

fn build_zcash_blake2b_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let sk_ids = builder.new_inputs(256);
    let ints = [6, 7, 8];

    for i in ints {
        let hash_circuit = build_prf_expand_circuit(i);
        let hash_ids = builder.add_circuit(&hash_circuit, &[&sk_ids]);

        for i in hash_ids {
            builder.output(i);
        }
    }

    builder.finish()
}

pub(crate) fn build_zcash_import_function() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let p1_next = builder.new_inputs(256);
    let p2_next = builder.new_inputs(256);
    let p3_next = builder.new_inputs(256);
    let p1_prev = builder.new_inputs(256);
    let p2_prev = builder.new_inputs(256);
    let p3_prev = builder.new_inputs(256);

    let comp_eq_circ = build_compare_eq_circuit(256);
    let op1 = builder.add_circuit(&comp_eq_circ, &[&p1_next, &p2_prev])[0];
    let op2 = builder.add_circuit(&comp_eq_circ, &[&p2_next, &p3_prev])[0];
    let op3 = builder.add_circuit(&comp_eq_circ, &[&p3_next, &p1_prev])[0];

    let temp = builder.and(op1, op2);
    let output = builder.and(temp, op3);

    let mut prime_bytes = hex::decode(&Scalar::MODULUS[2..]).unwrap();
    prime_bytes.reverse();

    let circ = build_mod_add_circut(p1_next.len(), &prime_bytes);

    let temp = builder.add_circuit(&circ, &[&p1_next, &p2_next]);
    let res3_ids = builder.add_circuit(&circ, &[&temp, &p3_next]);

    let zcash_circuit = build_zcash_blake2b_circuit();
    let op = builder.add_circuit(&zcash_circuit, &[&res3_ids]);

    builder.output(output);
    for i in &op {
        builder.output(*i);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use ff::{Field, FromUniformBytes, PrimeField};
    use garbled_circuit::functionality::{
        circuit_eval::yao_circuit_eval_functionality,
        input::batch_input_yao_functionality,
        output::batch_output_yao_functionality,
        setup::setup_aes_yao_functionality,
        utils::{FilteredMsgRelay, run_init},
        utils_dep::ProtocolError,
    };
    use pasta_curves::pallas::{Base, Scalar};
    use rand::{SeedableRng, rngs::StdRng};

    use sl_compute_common::BinaryString;
    use sl_messages::{
        relay::{Relay, SimpleMessageRelay},
        setup::ProtocolParticipant,
    };

    use super::*;
    use crate::utils::bits_to_bytes_le;

    /// Converts a vector of `u8` values to a vector of `bool` values
    fn u8_vec_to_bool_vec(vec_u8: Vec<u8>) -> Vec<bool> {
        let mut output = Vec::with_capacity(vec_u8.len() * 8);
        for byte in vec_u8 {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;
                output.push(bit != 0);
            }
        }
        output
    }

    fn generate_shamir_shares(rng: &mut StdRng) -> [Scalar; 3] {
        let secret = Scalar::random(&mut *rng);
        let coeff = Scalar::random(&mut *rng);

        core::array::from_fn(|idx| {
            let point = Scalar::from((idx + 1) as u64);
            secret + coeff * point
        })
    }

    #[test]
    fn test_zcash_blake2b_circuit() {
        let circ = build_zcash_blake2b_circuit();
        let rng = StdRng::from_entropy();

        let scalar = Scalar::random(rng);
        let scalar_bool = u8_vec_to_bool_vec(scalar.to_repr().to_vec());

        let out = circ.evaluate(&[&scalar_bool]);
        let mut ask_i = BinaryString::new();
        let mut nk_i = BinaryString::new();
        let mut rivk_i = BinaryString::new();
        for i in &out[..512] {
            ask_i.push(*i);
        }
        for i in &out[512..1024] {
            nk_i.push(*i);
        }
        for i in &out[1024..] {
            rivk_i.push(*i);
        }
        println!("ask_i: {:?}", hex::encode(ask_i.value));
        println!("nk_i: {:?}", hex::encode(nk_i.value));
        println!("rivk_i: {:?}", hex::encode(rivk_i.value));
    }

    async fn test_run_zcash_blake2b_3pc<S, R>(
        setup: S,
        scalar_bool: Vec<bool>,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);

        let (mut yao_setup, hash, _) =
            setup_aes_yao_functionality(&setup, &mut relay).await?;

        let scalar_yao = batch_input_yao_functionality(
            &setup,
            &mut relay,
            &scalar_bool,
            &mut yao_setup,
        )
        .await?;

        let circuit = build_zcash_blake2b_circuit();

        let output = yao_circuit_eval_functionality(
            &setup,
            &mut relay,
            &[scalar_yao],
            &circuit,
            &hash,
            &mut yao_setup,
        )
        .await?;

        let out_yao = circuit
            .output_gate_ids()
            .iter()
            .map(|id| output.get(id).unwrap().clone())
            .collect::<Vec<_>>();

        let out =
            batch_output_yao_functionality(&setup, &mut relay, &out_yao)
                .await?;

        Ok((setup.participant_index(), out))
    }

    async fn test_zcash_blake2b_3pc_util(
        scalar_bool: Vec<bool>,
    ) -> Vec<bool> {
        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_zcash_blake2b_3pc(
                setup,
                scalar_bool.clone(),
                relay,
            ));
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

        assert_eq!(shares[0].1, shares[2].1);
        assert_eq!(shares[0].1, shares[1].1);

        shares[0].1.clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_zcash_blake2b_3pc() {
        let rng = StdRng::from_entropy();

        let scalar = Scalar::random(rng);
        let scalar_bool = u8_vec_to_bool_vec(scalar.to_repr().to_vec());
        let out = test_zcash_blake2b_3pc_util(scalar_bool).await;
        let mut ask_i = BinaryString::new();
        let mut nk_i = BinaryString::new();
        let mut rivk_i = BinaryString::new();
        for i in &out[..512] {
            ask_i.push(*i);
        }
        for i in &out[512..1024] {
            nk_i.push(*i);
        }
        for i in &out[1024..] {
            rivk_i.push(*i);
        }
        println!("ask_i: {:?}", hex::encode(ask_i.value));
        println!("nk_i: {:?}", hex::encode(nk_i.value));
        println!("rivk_i: {:?}", hex::encode(rivk_i.value));

        println!()
    }

    async fn test_run_zcash_dkg<S, R>(
        setup: S,
        shamir_share: Scalar,
        relay: R,
    ) -> Result<(usize, Vec<bool>), ProtocolError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        use garbled_circuit::functionality::{
            input::run_batch_input_from_all_yao, utils::run_common_randomness,
        };
        use rand::RngCore;

        use crate::{
            shamir_to_rss::run_shamir_to_scalar_rss_pallas,
            utils::bytes_to_bits_le,
        };

        let mut relay = FilteredMsgRelay::new(relay);
        let mut rng = StdRng::from_entropy();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let (mut yao_setup, hash, comm) =
            setup_aes_yao_functionality(&setup, &mut relay).await?;
        // run setup for serverstate
        let mut randomness =
            run_common_randomness(&setup, &seed, &mut relay).await?;

        let (rss_prev, rss_next) = run_shamir_to_scalar_rss_pallas(
            &setup,
            &mut relay,
            &shamir_share,
            &mut randomness,
        )
        .await?;

        let all_ip: Vec<bool> = bytes_to_bits_le(&rss_prev.to_repr())
            .chain(bytes_to_bits_le(&rss_next.to_repr()))
            .collect();

        let (i1_yao, i2_yao, i3_yao) = run_batch_input_from_all_yao(
            &setup,
            &mut relay,
            &all_ip,
            &mut yao_setup,
            &comm,
        )
        .await?;

        let mut inputs = [vec![], vec![], vec![], vec![], vec![], vec![]];

        inputs[0].extend_from_slice(&i1_yao[256..]);
        inputs[1].extend_from_slice(&i2_yao[256..]);
        inputs[2].extend_from_slice(&i3_yao[256..]);

        inputs[3].extend_from_slice(&i1_yao[..256]);
        inputs[4].extend_from_slice(&i2_yao[..256]);
        inputs[5].extend_from_slice(&i3_yao[..256]);

        let circuit = build_zcash_import_function();

        let output = yao_circuit_eval_functionality(
            &setup,
            &mut relay,
            &inputs,
            &circuit,
            &hash,
            &mut yao_setup,
        )
        .await?;

        let out_yao = circuit
            .output_gate_ids()
            .iter()
            .map(|v| output.get(v).unwrap().clone())
            .collect::<Vec<_>>();

        let out =
            batch_output_yao_functionality(&setup, &mut relay, &out_yao)
                .await?;

        Ok((setup.participant_index(), out))
    }

    async fn test_zcash_dkg_util(shamir_shares: [Scalar; 3]) -> Vec<bool> {
        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            let pid = setup.participant_index();
            parties.spawn(test_run_zcash_dkg(
                setup,
                shamir_shares[pid],
                relay,
            ));
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

        assert_eq!(shares[0].1, shares[2].1);
        assert_eq!(shares[0].1, shares[1].1);

        shares[0].1.clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_zcash_dkg() {
        let mut rng = StdRng::from_entropy();
        let out = test_zcash_dkg_util(generate_shamir_shares(&mut rng)).await;
        let mut ask_i = BinaryString::new();
        let mut nk_i = BinaryString::new();
        let mut rivk_i = BinaryString::new();
        for i in &out[1..513] {
            ask_i.push(*i);
        }
        for i in &out[513..1025] {
            nk_i.push(*i);
        }
        for i in &out[1025..] {
            rivk_i.push(*i);
        }
        println!("ver: {:?}", out[0]);
        println!("ask_i: {:?}", hex::encode(ask_i.value));
        println!("nk_i: {:?}", hex::encode(nk_i.value));
        println!("rivk_i: {:?}", hex::encode(rivk_i.value));

        use orchard::{
            keys::FullViewingKey,
            primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
        };

        let ask_bytes: [u8; 64] =
            bits_to_bytes_le(&out[1..513]).try_into().unwrap();
        let nk_bytes: [u8; 64] =
            bits_to_bytes_le(&out[513..1025]).try_into().unwrap();
        let rivk_bytes: [u8; 64] =
            bits_to_bytes_le(&out[1025..1537]).try_into().unwrap();
        let mut ask_eff = Scalar::from_uniform_bytes(&ask_bytes);
        let nk = Base::from_uniform_bytes(&nk_bytes);
        let rivk = Scalar::from_uniform_bytes(&rivk_bytes);
        let ak_bytes = loop {
            let signing_key: SigningKey<SpendAuth> =
                ask_eff.to_repr().try_into().unwrap();
            let vk: VerificationKey<SpendAuth> = (&signing_key).into();
            let ak_bytes: [u8; 32] = (&vk).into();

            if (ak_bytes[31] >> 7) == 1 {
                // If the last bit of repr_P(ak) is 1, negate ask.
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

        // Derive the incoming viewing keys (ivk) from the full viewing key.
        let internal_ivk = fvk.to_ivk(orchard::keys::Scope::Internal);
        let external_ivk = fvk.to_ivk(orchard::keys::Scope::External);

        // Spec sanity checks: `ivk` must be neither 0 nor ⊥.
        for ivk in [&internal_ivk, &external_ivk] {
            let ivk_bytes = ivk.to_bytes();
            assert_ne!(ivk_bytes, [0u8; 64]);
            assert!(bool::from(
                orchard::keys::IncomingViewingKey::from_bytes(&ivk_bytes)
                    .is_some()
            ));
        }

        println!("internal_ivk: {:?}", hex::encode(internal_ivk.to_bytes()));
        println!("external_ivk: {:?}", hex::encode(external_ivk.to_bytes()));
    }
}
