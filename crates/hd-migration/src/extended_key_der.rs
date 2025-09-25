use derivation_path::DerivationPath;
use garbled_circuit::{
    functionality::{
        input::batch_input_yao_functionality, setup::setup_yao_functionality,
        utils::run_common_randomness, utils_dep::TagOffsetCounter,
    },
    utilities::{commitments::HashCommitment, hash_function::AesHash},
};
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;
use sl_messages::relay::Relay;

use crate::{
    derive_child_key::run_derive_child_key,
    rss_to_yao::run_scalar_rss_to_yao,
    shamir_to_rss::run_shamir_to_scalar_rss,
    types::{HardDerivationError, PrivKeyShareBip, PrivKeyShareDkg, ProtocolParticipant},
    utils::u8_vec_to_bool_vec,
};

pub async fn run_extended_key_derivation<S, R>(
    setup: S,
    share: Scalar,
    evaluation_points: Vec<NonZeroScalar>,
    derivation_path: DerivationPath,
    chain_code: [u8; 32],
    public_key: ProjectivePoint,
    relay: R,
) -> Result<Vec<PrivKeyShareDkg<ProjectivePoint>>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
{
    let mut tag_offset_counter = TagOffsetCounter::new();

    let mut relay = relay;

    let mut rng = StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // run setup for serverstate
    let mut randomness = run_common_randomness(&setup, &seed, &mut relay).await?;

    // run setup for yao protocols
    let yao_setup = setup_yao_functionality(&setup, &mut tag_offset_counter, &mut relay).await?;

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

    // convert privkey in shamir to rss
    let scalar_rss_privkey = run_shamir_to_scalar_rss(
        &setup,
        &mut relay,
        &mut tag_offset_counter,
        &share,
        &evaluation_points,
        &mut randomness,
    )
    .await?;

    // convert rss to yao
    let mut yao_privkey = run_scalar_rss_to_yao(
        &setup,
        &mut relay,
        &mut tag_offset_counter,
        &scalar_rss_privkey,
        &yao_setup,
        &mut rng,
        &comm,
        &hash,
    )
    .await?;
    yao_privkey.reverse();

    // convert public chain code to yao
    let chain = u8_vec_to_bool_vec(chain_code.to_vec());
    let yao_chain = batch_input_yao_functionality(
        &setup,
        &mut tag_offset_counter,
        &mut relay,
        &chain,
        &mut rng,
        &yao_setup,
    )
    .await?;

    // set the input for child key derivation
    let parent = PrivKeyShareBip {
        yao_share: yao_privkey.try_into().expect("Conversion failed"),
        chain_share: yao_chain.try_into().expect("Conversion failed"),
        key_share: scalar_rss_privkey,
        pubkey: public_key,
    };

    let mut output = Vec::new();

    let mut temp = vec![parent];

    for (cnt, i) in derivation_path.path().iter().enumerate() {
        let child_key = run_derive_child_key(
            &setup,
            &mut relay,
            &mut tag_offset_counter,
            &temp[cnt],
            i,
            &yao_setup,
            &mut rng,
            &hash,
        )
        .await?;

        output.push(PrivKeyShareDkg {
            keyshare: child_key.key_share,
            pubkey: child_key.pubkey,
        });

        temp.push(child_key);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use derivation_path::{ChildIndex, DerivationPath};
    use hmac::{Hmac, Mac};
    use k256::elliptic_curve::bigint::Encoding;
    use k256::elliptic_curve::{Curve, ops::Reduce};
    use k256::{FieldBytes, NonZeroScalar};
    use k256::{ProjectivePoint, Scalar, Secp256k1, U256, elliptic_curve::sec1::ToEncodedPoint};
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use sl_messages::relay::SimpleMessageRelay;

    use crate::extended_key_der::run_extended_key_derivation;
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
            100, 48, 244, 185, 61, 88, 116, 164, 93, 235, 5, 61, 37, 167, 19, 87, 244, 186, 51, 41,
            28, 223, 10, 96, 117, 115, 12, 238, 100, 70, 71, 48,
        ]))
        .expect("Conversion Failed");
        let x_2 = NonZeroScalar::from_repr(*FieldBytes::from_slice(&[
            119, 139, 180, 247, 206, 8, 172, 176, 83, 173, 134, 148, 56, 72, 245, 140, 242, 169,
            145, 48, 227, 164, 1, 193, 59, 173, 50, 139, 100, 219, 68, 4,
        ]))
        .expect("Conversion Failed");
        let x_3 = NonZeroScalar::from_repr(*FieldBytes::from_slice(&[
            197, 148, 247, 13, 223, 180, 119, 249, 87, 162, 0, 13, 123, 239, 115, 202, 165, 205,
            215, 176, 2, 81, 199, 180, 122, 80, 197, 187, 176, 1, 90, 229,
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
            let mut hmac_hasher = Hmac::<sha2::Sha512>::new_from_slice(cc).unwrap();

            hmac_hasher.update(pubkey.to_encoded_point(true).as_bytes());

            hmac_hasher.update(&child_index.to_bits().to_be_bytes());
            hmac_hasher.finalize().into_bytes()
        } else {
            let mut hmac_hasher = Hmac::<sha2::Sha512>::new_from_slice(cc).unwrap();

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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_hard_derivation_import() {
        let (s1, s2, s3, s, chaincode, pubkey, evaluation_points) = generate_random_input();

        let derivation_path = DerivationPath::from_str("m/0'/1/2'").unwrap();

        let shares = [s1, s2, s3];

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        let mut i = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(run_extended_key_derivation(
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

        let mut t = vec![(chaincode, s, pubkey)];
        let path = derivation_path.path();

        for i in 0..path.len() {
            let (cc, sk, pk) = t[i];
            let (is, icc) = get_ideal_output(&cc, &pk, path[i], sk);
            let ip = ProjectivePoint::GENERATOR * is;

            let reals = shares[0][i].keyshare.next_share
                + shares[1][i].keyshare.next_share
                + shares[2][i].keyshare.next_share;

            let realp = ProjectivePoint::GENERATOR * reals;

            assert_eq!(reals, is);
            assert_eq!(realp, shares[0][i].pubkey);

            t.push((icc.try_into().expect("Conversion failed"), is, ip));
        }
    }
}
