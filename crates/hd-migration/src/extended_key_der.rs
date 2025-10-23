// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use derivation_path::{ChildIndex, DerivationPath};
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use sl_compute_common::CommonRandomness;
use sl_messages::relay::Relay;

use garbled_circuit::{
    functionality::{
        circuit_eval::yao_circuit_eval_functionality,
        input::run_batch_input_from_all_yao,
        output::{batch_output_yao_functionality, output_yao_functionality},
        setup::setup_yao_functionality,
        utils::{FilteredMsgRelay, run_common_randomness},
        utils_dep::TagOffsetCounter,
    },
    utilities::{
        commitments::{Commitment, HashCommitment},
        hash_function::{AesHash, HashFunction},
        types::YaoSetup,
    },
};

use crate::{
    circuits::build_child_key_der_hmac_round1_circuit,
    derive_child_key::{run_batch_derive_child_key, run_derive_child_key},
    shamir_to_rss::run_shamir_to_scalar_rss,
    types::{HardDerivationError, PrivKeyShareBip, ProtocolParticipant},
    utils::{bool_vec_to_u8_vec, bytes_to_bits_le},
    yao_to_rss::run_yao_to_scalar_rss_keypair,
};

/// Implements the child key derivation protocol for BIP-32 on secret-shared inputs.
#[allow(clippy::too_many_arguments)]
async fn run_extended_key_derivation_round1<S, R, G, H, C>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    tag_offset_counter: &mut TagOffsetCounter,
    share: Scalar,
    evaluation_points: Vec<NonZeroScalar>,
    derivation_path: &DerivationPath,
    chain_code: [u8; 32],
    public_key: ProjectivePoint,
    randomness: &mut CommonRandomness,
    yao_setup: &YaoSetup,
    mut rng: Option<&mut G>,
    comm: &C,
    hash: &H,
) -> Result<(PrivKeyShareBip, PrivKeyShareBip), HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
    C: Commitment,
{
    // convert privkey in shamir to rss
    let scalar_rss_privkey = run_shamir_to_scalar_rss(
        setup,
        relay,
        tag_offset_counter,
        &share,
        &evaluation_points,
        randomness,
    )
    .await?;

    let prev = bytes_to_bits_le(&scalar_rss_privkey.prev_share.to_bytes());
    let next = bytes_to_bits_le(&scalar_rss_privkey.next_share.to_bytes());

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

    let mut inputs = [vec![], vec![], vec![], vec![], vec![], vec![]];

    inputs[0].extend_from_slice(&i1_yao[256..]);
    inputs[1].extend_from_slice(&i2_yao[256..]);
    inputs[2].extend_from_slice(&i3_yao[256..]);

    inputs[3].extend_from_slice(&i1_yao[..256]);
    inputs[4].extend_from_slice(&i2_yao[..256]);
    inputs[5].extend_from_slice(&i3_yao[..256]);

    let child = derivation_path.path()[0];

    let circ = build_child_key_der_hmac_round1_circuit(
        &public_key,
        &child,
        chain_code,
    );

    let output = yao_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &inputs,
        &circ,
        rng.as_mut(),
        hash,
        yao_setup,
    )
    .await?;

    let mut ops = Vec::new();
    for i in circ.output_gate_ids {
        ops.push(output.get(&i).unwrap().to_owned());
    }

    let ver = &ops[0];
    let par_sk_yao = ops[1..257].to_vec();
    let mut child_sk_yao = ops[257..513].to_vec();
    let child_chain_yao = ops[513..].to_vec();

    let verification =
        output_yao_functionality(setup, tag_offset_counter, relay, ver)
            .await?;
    assert!(verification);

    let scalar_rss_child = run_yao_to_scalar_rss_keypair(
        setup,
        relay,
        tag_offset_counter,
        &child_sk_yao,
        rng,
    )
    .await?;

    let child_cc_pub = batch_output_yao_functionality(
        setup,
        tag_offset_counter,
        relay,
        &child_chain_yao,
    )
    .await?;

    let child_cc = bool_vec_to_u8_vec(child_cc_pub);

    child_sk_yao.reverse();

    // set the input for child key derivation
    let parent = PrivKeyShareBip {
        yao_share: par_sk_yao.try_into().expect("Conversion failed"),
        chain_code,
        keyshare: scalar_rss_privkey,
        pubkey: public_key,
    };

    let child = PrivKeyShareBip {
        yao_share: child_sk_yao.try_into().expect("Conversion failed"),
        chain_code: child_cc.try_into().expect("Conversion failed"),
        keyshare: scalar_rss_child.keyshare,
        pubkey: scalar_rss_child.pubkey,
    };

    Ok((parent, child))
}

pub async fn run_extended_key_derivation<S, R>(
    setup: S,
    share: Scalar,
    evaluation_points: Vec<NonZeroScalar>,
    derivation_path: DerivationPath,
    chain_code: [u8; 32],
    public_key: ProjectivePoint,
    relay: R,
) -> Result<Vec<PrivKeyShareBip>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
{
    let mut tag_offset_counter = TagOffsetCounter::new();

    let mut relay = FilteredMsgRelay::new(relay);

    let mut rng = StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // run setup for serverstate
    let mut randomness =
        run_common_randomness(&setup, &seed, &mut relay).await?;

    // run setup for yao protocols
    let yao_setup =
        setup_yao_functionality(&setup, &mut tag_offset_counter, &mut relay)
            .await?;

    let (mut rng, hash, comm) = match &yao_setup {
        YaoSetup::E(e) => {
            let hash = AesHash::new(e.comm_crs);
            let comm = HashCommitment::new(hash);
            (None, hash, comm)
        }

        YaoSetup::G(g) => {
            let hash = AesHash::new(g.comm_crs);
            let comm = HashCommitment::new(hash);
            let r = ChaCha8Rng::from_seed(g.prf_key);
            (Some(r), hash, comm)
        }
    };

    let (_, ch) = run_extended_key_derivation_round1(
        &setup,
        &mut relay,
        &mut tag_offset_counter,
        share,
        evaluation_points,
        &derivation_path,
        chain_code,
        public_key,
        &mut randomness,
        &yao_setup,
        rng.as_mut(),
        &comm,
        &hash,
    )
    .await?;

    let mut output = vec![ch];

    for (cnt, i) in derivation_path.path().iter().skip(1).enumerate() {
        let child_key = run_derive_child_key(
            &setup,
            &mut relay,
            &mut tag_offset_counter,
            &output[cnt],
            i,
            &yao_setup,
            rng.as_mut(),
            &hash,
        )
        .await?;

        output.push(child_key);
    }

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_extended_key_derivation_multiple_children<S, R>(
    setup: S,
    share: Scalar,
    evaluation_points: Vec<NonZeroScalar>,
    derivation_path: DerivationPath,
    children: Vec<ChildIndex>,
    chain_code: [u8; 32],
    public_key: ProjectivePoint,
    relay: R,
) -> Result<Vec<PrivKeyShareBip>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
{
    let mut tag_offset_counter = TagOffsetCounter::new();

    let mut relay = FilteredMsgRelay::new(relay);

    let mut rng = StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // run setup for serverstate
    let mut randomness =
        run_common_randomness(&setup, &seed, &mut relay).await?;

    // run setup for yao protocols
    let yao_setup =
        setup_yao_functionality(&setup, &mut tag_offset_counter, &mut relay)
            .await?;

    let (mut rng, hash, comm) = match &yao_setup {
        YaoSetup::E(e) => {
            let hash = AesHash::new(e.comm_crs);
            let comm = HashCommitment::new(hash);
            (None, hash, comm)
        }

        YaoSetup::G(g) => {
            let hash = AesHash::new(g.comm_crs);
            let comm = HashCommitment::new(hash);
            let r = ChaCha8Rng::from_seed(g.prf_key);
            (Some(r), hash, comm)
        }
    };

    let (_, ch) = run_extended_key_derivation_round1(
        &setup,
        &mut relay,
        &mut tag_offset_counter,
        share,
        evaluation_points,
        &derivation_path,
        chain_code,
        public_key,
        &mut randomness,
        &yao_setup,
        rng.as_mut(),
        &comm,
        &hash,
    )
    .await?;

    let mut temp = vec![ch];

    for (cnt, i) in derivation_path.path()[1..].iter().enumerate() {
        let child_key = run_derive_child_key(
            &setup,
            &mut relay,
            &mut tag_offset_counter,
            &temp[cnt],
            i,
            &yao_setup,
            rng.as_mut(),
            &hash,
        )
        .await?;

        temp.push(child_key);
    }

    let par = vec![&temp[temp.len() - 1]; children.len()];

    let children = run_batch_derive_child_key(
        &setup,
        &mut relay,
        &mut tag_offset_counter,
        &par,
        &children,
        &yao_setup,
        rng.as_mut(),
        &hash,
    )
    .await?;

    Ok(children)
}
#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use derivation_path::{ChildIndex, DerivationPath};
    use garbled_circuit::functionality::utils_dep::ProtocolParticipant;
    use hmac::{Hmac, Mac};
    use k256::elliptic_curve::bigint::Encoding;
    use k256::elliptic_curve::{Curve, ops::Reduce};
    use k256::{FieldBytes, NonZeroScalar};
    use k256::{
        ProjectivePoint, Scalar, Secp256k1, U256,
        elliptic_curve::sec1::ToEncodedPoint,
    };
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::extended_key_der::{
        run_extended_key_derivation,
        run_extended_key_derivation_multiple_children,
    };
    use crate::shamir_to_rss::scalar_rss_to_shamir;
    use crate::types::{HardDerivationError, PrivKeyShareBip};
    use crate::utils::{get_evaluation, run_init};

    #[allow(clippy::too_many_arguments)]
    fn generate_random_input() -> (
        Scalar,
        Scalar,
        Scalar,
        Scalar,
        [u8; 32],
        ProjectivePoint,
        [NonZeroScalar; 3],
    ) {
        // test input evaluation points
        let x_1 = NonZeroScalar::from_repr(*FieldBytes::from_slice(&[
            100, 48, 244, 185, 61, 88, 116, 164, 93, 235, 5, 61, 37, 167, 19,
            87, 244, 186, 51, 41, 28, 223, 10, 96, 117, 115, 12, 238, 100,
            70, 71, 48,
        ]))
        .expect("Conversion Failed");
        let x_2 = NonZeroScalar::from_repr(*FieldBytes::from_slice(&[
            119, 139, 180, 247, 206, 8, 172, 176, 83, 173, 134, 148, 56, 72,
            245, 140, 242, 169, 145, 48, 227, 164, 1, 193, 59, 173, 50, 139,
            100, 219, 68, 4,
        ]))
        .expect("Conversion Failed");
        let x_3 = NonZeroScalar::from_repr(*FieldBytes::from_slice(&[
            197, 148, 247, 13, 223, 180, 119, 249, 87, 162, 0, 13, 123, 239,
            115, 202, 165, 205, 215, 176, 2, 81, 199, 180, 122, 80, 197, 187,
            176, 1, 90, 229,
        ]))
        .expect("Conversion Failed");

        let mut rng = StdRng::from_entropy();
        let mut s1_byt = [0u8; 32];
        rng.fill_bytes(&mut s1_byt);
        let mut s2_byt = [0u8; 32];
        rng.fill_bytes(&mut s2_byt);

        let s1 = Scalar::reduce(U256::from_be_bytes(s1_byt));
        let s2 = Scalar::reduce(U256::from_be_bytes(s2_byt));
        let s3 = get_evaluation(&[x_1, x_2], &[s1, s2], &x_3);

        let s = get_evaluation(&[x_1, x_2], &[s1, s2], &Scalar::ZERO);
        let pubkey = ProjectivePoint::GENERATOR * s;

        let mut chaincode = [0u8; 32];
        rng.fill_bytes(&mut chaincode);

        (s1, s2, s3, s, chaincode, pubkey, [x_1, x_2, x_3])
    }

    fn get_ideal_output(
        cc: &[u8; 32],
        pubkey: &ProjectivePoint,
        child_index: ChildIndex,
        privkey: Scalar,
    ) -> (Scalar, Vec<u8>) {
        let result = if child_index.is_normal() {
            let mut hmac_hasher =
                Hmac::<sha2::Sha512>::new_from_slice(cc).unwrap();

            hmac_hasher.update(pubkey.to_encoded_point(true).as_bytes());

            hmac_hasher.update(&child_index.to_bits().to_be_bytes());
            hmac_hasher.finalize().into_bytes()
        } else {
            let mut hmac_hasher =
                Hmac::<sha2::Sha512>::new_from_slice(cc).unwrap();

            hmac_hasher.update(&[0]);
            hmac_hasher.update(&privkey.to_bytes());

            hmac_hasher.update(&child_index.to_bits().to_be_bytes());
            hmac_hasher.finalize().into_bytes()
        };
        let (il_int, child_chain_code) = result.split_at(32);
        let il_int = U256::from_be_slice(il_int);

        // Has a chance of 1 in 2^127
        if il_int > Secp256k1::ORDER {
            println!("More than order!!");
        }

        let child_key = Scalar::reduce(il_int) + privkey;
        (child_key, child_chain_code.to_vec())
    }

    pub async fn test_hard_derivation_import_protocol<S, R>(
        setup: S,
        share: Scalar,
        evaluation_points: Vec<NonZeroScalar>,
        derivation_path: DerivationPath,
        chain_code: [u8; 32],
        public_key: ProjectivePoint,
        relay: R,
    ) -> Result<(usize, Vec<PrivKeyShareBip>), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let i = &setup.participant_index();
        let a = run_extended_key_derivation(
            setup,
            share,
            evaluation_points.to_vec(),
            derivation_path.clone(),
            chain_code,
            public_key,
            relay,
        )
        .await;
        match a {
            Ok(v) => Ok((*i, v)),
            Err(e) => Err(e),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_hard_derivation_import() {
        let (s1, s2, s3, s, chaincode, pubkey, evaluation_points) =
            generate_random_input();

        let derivation_path = DerivationPath::from_str("m/0'/1/2'").unwrap();

        let shares = [s1, s2, s3];

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        let mut i = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_hard_derivation_import_protocol(
                setup,
                shares[i],
                evaluation_points.to_vec(),
                derivation_path.clone(),
                chaincode,
                pubkey,
                relay,
            ));
            i += 1;
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

        shares.sort_by_key(|f| f.0);

        let mut t = vec![(chaincode, s, pubkey)];
        let path = derivation_path.path();

        for i in 0..path.len() {
            let (cc, sk, pk) = t[i];
            let (is, icc) = get_ideal_output(&cc, &pk, path[i], sk);
            let ip = ProjectivePoint::GENERATOR * is;

            let reals = shares[0].1[i].keyshare.next_share
                + shares[1].1[i].keyshare.next_share
                + shares[2].1[i].keyshare.next_share;

            let shamir_p1 = scalar_rss_to_shamir(
                &shares[0].1[i].keyshare,
                0,
                &evaluation_points,
            );
            let shamir_p2 = scalar_rss_to_shamir(
                &shares[1].1[i].keyshare,
                1,
                &evaluation_points,
            );
            let shamir_p3 = scalar_rss_to_shamir(
                &shares[2].1[i].keyshare,
                2,
                &evaluation_points,
            );

            let s3 = get_evaluation(
                &[evaluation_points[0], evaluation_points[1]],
                &[shamir_p1, shamir_p2],
                &evaluation_points[2],
            );

            assert_eq!(s3, shamir_p3);

            let s = get_evaluation(
                &[evaluation_points[0], evaluation_points[1]],
                &[shamir_p1, shamir_p2],
                &Scalar::ZERO,
            );

            assert_eq!(reals, s);

            let realp = ProjectivePoint::GENERATOR * reals;

            assert_eq!(realp, shares[0].1[i].pubkey);
            assert_eq!(reals, is);

            t.push((icc.try_into().expect("Conversion failed"), is, ip));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn test_hard_derivation_import_multiple_children_protocol<
        S: ProtocolParticipant,
        R: Relay,
    >(
        setup: S,
        share: Scalar,
        evaluation_points: Vec<NonZeroScalar>,
        derivation_path: DerivationPath,
        children: Vec<ChildIndex>,
        chain_code: [u8; 32],
        public_key: ProjectivePoint,
        relay: R,
    ) -> Result<(usize, Vec<PrivKeyShareBip>), HardDerivationError> {
        let i = &setup.participant_index();
        let a = run_extended_key_derivation_multiple_children(
            setup,
            share,
            evaluation_points.to_vec(),
            derivation_path.clone(),
            children.clone(),
            chain_code,
            public_key,
            relay,
        )
        .await;
        match a {
            Ok(v) => Ok((*i, v)),
            Err(e) => Err(e),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_hard_derivation_import_multiple_children() {
        let (s1, s2, s3, s, chaincode, pubkey, evaluation_points) =
            generate_random_input();

        let derivation_path =
            DerivationPath::from_str("m/44'/60'/0'/0").unwrap();

        let mut children = Vec::new();
        for i in 1..4 {
            let child_node = ChildIndex::Normal(i);
            children.push(child_node);
        }

        let shares = [s1, s2, s3];

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        let mut i = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn({
                test_hard_derivation_import_multiple_children_protocol(
                    setup,
                    shares[i],
                    evaluation_points.to_vec(),
                    derivation_path.clone(),
                    children.clone(),
                    chaincode,
                    pubkey,
                    relay,
                )
            });
            i += 1;
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

        shares.sort_by_key(|f| f.0);

        let mut t = vec![(chaincode, s, pubkey)];
        let path = derivation_path.path();

        for i in 0..path.len() {
            let (cc, sk, pk) = t[i];
            let (is, icc) = get_ideal_output(&cc, &pk, path[i], sk);
            let ip = ProjectivePoint::GENERATOR * is;
            t.push((icc.try_into().expect("Conversion failed"), is, ip));
        }

        let (cc, sk, pk) = t[t.len() - 1];

        (0..children.len()).for_each(|i| {
            let (is, _) = get_ideal_output(&cc, &pk, children[i], sk);

            let reals = shares[0].1[i].keyshare.next_share
                + shares[1].1[i].keyshare.next_share
                + shares[2].1[i].keyshare.next_share;

            let shamir_p1 = scalar_rss_to_shamir(
                &shares[0].1[i].keyshare,
                0,
                &evaluation_points,
            );
            let shamir_p2 = scalar_rss_to_shamir(
                &shares[1].1[i].keyshare,
                1,
                &evaluation_points,
            );
            let shamir_p3 = scalar_rss_to_shamir(
                &shares[2].1[i].keyshare,
                2,
                &evaluation_points,
            );

            let s3 = get_evaluation(
                &[evaluation_points[0], evaluation_points[1]],
                &[shamir_p1, shamir_p2],
                &evaluation_points[2],
            );

            assert_eq!(s3, shamir_p3);

            let s = get_evaluation(
                &[evaluation_points[0], evaluation_points[1]],
                &[shamir_p1, shamir_p2],
                &Scalar::ZERO,
            );

            assert_eq!(reals, s);

            let realp = ProjectivePoint::GENERATOR * reals;

            assert_eq!(realp, shares[0].1[i].pubkey);
            assert_eq!(reals, is);
        });
    }
}
