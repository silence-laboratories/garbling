// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use ff::PrimeField;
use pasta_curves::pallas::Scalar;

use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};

use crate::{circuits::build_mod_add_circut, prf::build_prf_expand_circuit};

/// Converts a vector of `u8` values to a vector of `bool` values
pub fn u8_vec_to_bool_vec(vec_u8: Vec<u8>) -> Vec<bool> {
    let mut output = Vec::with_capacity(vec_u8.len() * 8);
    for byte in vec_u8 {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            output.push(bit != 0);
        }
    }
    output
}

pub fn build_zcash_blake2b_circuit() -> BinaryCircuit {
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

pub fn build_zcash_import_function() -> BinaryCircuit {
    use crate::{
        circuits::build_compare_eq_circuit,
        zcash::build_zcash_blake2b_circuit,
    };

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

    let circ =
        build_mod_add_circut(p1_next.len(), prime_bytes.try_into().unwrap());

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
    use ff::{Field, PrimeField};
    use garbled_circuit::{
        functionality::{
            circuit_eval::yao_circuit_eval_functionality,
            input::batch_input_yao_functionality,
            output::batch_output_yao_functionality,
            setup::setup_yao_functionality, utils::FilteredMsgRelay,
            utils_dep::ProtocolError,
        },
        utilities::{
            commitments::HashCommitment, hash_function::AesHash,
            types::YaoSetup,
        },
    };
    use pasta_curves::pallas::Scalar;
    use rand::{SeedableRng, rngs::StdRng};
    use sl_compute_common::BinaryString;
    use sl_messages::{
        relay::{Relay, SimpleMessageRelay},
        setup::ProtocolParticipant,
    };

    use crate::eval::evaluate;

    use super::*;

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

        let out = evaluate(&circ, &[&scalar_bool]);
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

    #[cfg(any(test, feature = "test-support"))]
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

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let (hash, _) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesHash::new(e.comm_crs);
                let comm = HashCommitment::new(hash);
                (hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesHash::new(g.comm_crs);
                let comm = HashCommitment::new(hash);
                (hash, comm)
            }
        };

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

    #[cfg(any(test, feature = "test-support"))]
    async fn test_zcash_blake2b_3pc_util(
        scalar_bool: Vec<bool>,
    ) -> Vec<bool> {
        use crate::test_support::run_init;

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

    #[cfg(any(test, feature = "test-support"))]
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
            utils::bytes_to_bits_be,
        };

        let mut relay = FilteredMsgRelay::new(relay);
        let mut rng = StdRng::from_entropy();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let (hash, comm) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesHash::new(e.comm_crs);
                let comm = HashCommitment::new(hash);
                (hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesHash::new(g.comm_crs);
                let comm = HashCommitment::new(hash);
                (hash, comm)
            }
        };
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

        // let tag = MessageTag::tag(12389);

        // let res_next = p2p_send_to_next_receive_from_prev(
        //     &setup,
        //     tag,
        //     rss_prev.to_repr(),
        //     &mut relay,
        // )
        // .await?;

        // let res = Scalar::from_repr(res_next).unwrap();

        // let s = rss_next + rss_prev + res;

        // if setup.participant_index() == 0 {
        //     println!("{rss_next:?} \n{rss_prev:?} \n{res:?}\n{s:?}");
        // }

        let prev = bytes_to_bits_be(&rss_prev.to_repr());
        let next = bytes_to_bits_be(&rss_next.to_repr());

        let mut all_ip = prev;
        all_ip.extend_from_slice(&next);

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

    #[cfg(any(test, feature = "test-support"))]
    async fn test_zcash_dkg_util(shamir_shares: [Scalar; 3]) -> Vec<bool> {
        use crate::test_support::run_init;

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
    }
}
