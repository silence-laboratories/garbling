use std::collections::HashMap;

use derivation_path::ChildIndex;
use garbled_circuit::{
    functionality::{circuit_eval::yao_circuit_eval_functionality, utils_dep::TagOffsetCounter},
    utilities::{
        hash_function::HashFunction,
        types::{YaoSetup, YaoShare},
    },
};
use rand::{CryptoRng, RngCore};
use sl_messages::relay::Relay;

use crate::{
    circuits::build_child_key_der_hmac_circuit,
    types::{HardDerivationError, PrivKeyShareBip, ProtocolParticipant},
    yao_to_rss::run_yao_to_scalar_rss_keypair,
};

/// Implements the child key derivation protocol for BIP-32 on secret-shared inputs.
#[allow(clippy::too_many_arguments)]
pub async fn run_derive_child_key<S, R, G, H>(
    setup: &S,
    relay: &mut R,
    tag_offset_counter: &mut TagOffsetCounter,
    parent_key: &PrivKeyShareBip,
    index_child: &ChildIndex,
    yao_setup: &YaoSetup,
    rng: &mut Option<G>,
    hash: &H,
) -> Result<PrivKeyShareBip, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let circuit = build_child_key_der_hmac_circuit(&parent_key.pubkey, index_child);

    let mut gin = HashMap::new();
    for (cnt, val) in circuit.garbler_input_ids.iter().enumerate() {
        gin.insert(*val, parent_key.yao_share[cnt].clone());
    }
    let mut ein = HashMap::new();
    for (cnt, val) in circuit.evaluator_input_ids.iter().enumerate() {
        ein.insert(*val, parent_key.chain_share[cnt].clone());
    }

    let hashed_vals = yao_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &gin,
        &ein,
        &circuit,
        rng,
        hash,
        yao_setup,
    )
    .await?;

    let hash_out: Vec<YaoShare> = circuit
        .output_gate_ids
        .iter()
        .map(|val| hashed_vals.get(val).unwrap().clone())
        .collect();

    let (il_int, child_chain_code) = hash_out.split_at(32 * 8);

    let scalar_rss_out =
        run_yao_to_scalar_rss_keypair(setup, relay, tag_offset_counter, il_int, rng).await?;

    let mut child_yao_share = il_int.to_vec();
    child_yao_share.reverse();

    let out = PrivKeyShareBip {
        yao_share: child_yao_share.try_into().expect("Conversion faileds"),
        pubkey: scalar_rss_out.pubkey,
        key_share: scalar_rss_out.keyshare,
        chain_share: child_chain_code
            .to_vec()
            .try_into()
            .expect("Conversion failed"),
    };

    Ok(out)
}

#[cfg(test)]
mod tests {
    use derivation_path::ChildIndex;
    use garbled_circuit::{
        functionality::{
            input::batch_input_yao_functionality, output::batch_output_yao_functionality,
            setup::setup_yao_functionality, utils_dep::TagOffsetCounter,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash, utils::bool_vec_to_hex},
    };
    use hmac::{Hmac, Mac};
    use k256::{
        ProjectivePoint, Scalar, Secp256k1, U256,
        elliptic_curve::{Curve, ops::Reduce, sec1::ToEncodedPoint},
    };
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rand_chacha::ChaCha8Rng;
    use sha2::{Digest, Sha256};
    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::{
        derive_child_key::run_derive_child_key,
        types::{HardDerivationError, PrivKeyShare, PrivKeyShareBip, ProtocolParticipant},
        utils::{run_init, u8_vec_to_bool_vec},
    };

    async fn test_run_derive_child_key<S, R>(
        setup: S,
        rpk_bool: Vec<bool>,
        rcc_bool: Vec<bool>,
        public_key: ProjectivePoint,
        child_index: ChildIndex,
        relay: R,
    ) -> Result<(usize, (PrivKeyShareBip, Vec<bool>)), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut cnt = TagOffsetCounter::new();

        let yao_setup = setup_yao_functionality(&setup, &mut cnt, &mut relay).await?;

        let (mut rng, hash, _) = if setup.participant_index() == 2 {
            let hash = AesHash::new(yao_setup.e_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(hash.clone());
            (None, hash, comm)
        } else {
            let hash = AesHash::new(yao_setup.g_setup.clone().unwrap().comm_crs);
            let comm = HashCommitment::new(hash.clone());
            let r = ChaCha8Rng::from_seed(yao_setup.g_setup.clone().unwrap().prf_key);
            (Some(r), hash, comm)
        };

        let rpk_yao = batch_input_yao_functionality(
            &setup, &mut cnt, &mut relay, &rpk_bool, &mut rng, &yao_setup,
        )
        .await?;

        let rcc_yao = batch_input_yao_functionality(
            &setup, &mut cnt, &mut relay, &rcc_bool, &mut rng, &yao_setup,
        )
        .await?;

        let share = PrivKeyShareBip {
            yao_share: rpk_yao.try_into().expect("Conversion failed"),
            chain_share: rcc_yao.try_into().expect("Conversion failed"),
            key_share: PrivKeyShare::<ProjectivePoint>::default(),
            pubkey: public_key,
        };

        let output = run_derive_child_key(
            &setup,
            &mut relay,
            &mut cnt,
            &share,
            &child_index,
            &yao_setup,
            &mut rng,
            &hash,
        )
        .await?;

        let child_chain =
            batch_output_yao_functionality(&setup, &mut cnt, &mut relay, &output.chain_share)
                .await?;

        Ok((setup.participant_index(), (output, child_chain)))
    }

    fn setup() -> (ProjectivePoint, Scalar, [u8; 32]) {
        // let private_key = Scalar::from(Scalar::<Secp256k1>::group_order() - 5);
        let a: u32 = 5;
        let private_key = Scalar::ZERO - Scalar::from(a);

        let root_public_key = ProjectivePoint::GENERATOR * private_key;
        let root_chain_code = Sha256::digest("test".as_bytes());

        (root_public_key, private_key, root_chain_code.into())
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

    async fn test_derive_child_key_util(child_index: ChildIndex) {
        let (root_public_key, root_private_key, root_chain_code) = setup();
        let rpk_bool = u8_vec_to_bool_vec(root_private_key.to_bytes().to_vec());
        let rcc_bool = u8_vec_to_bool_vec(root_chain_code.to_vec());

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_derive_child_key(
                setup,
                rpk_bool.clone(),
                rcc_bool.clone(),
                root_public_key,
                child_index,
                relay,
            ));
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

        let child_privkey_obtained = shares[0].1.0.key_share.next_share
            + shares[1].1.0.key_share.next_share
            + shares[2].1.0.key_share.next_share;

        let child_chaincode_obtained = bool_vec_to_hex(shares[0].1.1.clone());

        let (child_privkey_ideal, child_chaincode_ideal) = get_ideal_output(
            &root_chain_code,
            &root_public_key,
            child_index,
            root_private_key,
        );

        assert_eq!(child_privkey_ideal, child_privkey_obtained);
        assert_eq!(hex::encode(child_chaincode_ideal), child_chaincode_obtained);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_derive_child_key() {
        let mut rng = StdRng::from_entropy();

        let no: u32 = rng.r#gen();
        let child_number = ChildIndex::Normal(no);
        test_derive_child_key_util(child_number).await;

        let no: u32 = rng.r#gen();
        let child_number = ChildIndex::Hardened(no);
        test_derive_child_key_util(child_number).await;
    }
}
