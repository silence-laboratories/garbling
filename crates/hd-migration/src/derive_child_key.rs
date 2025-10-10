use derivation_path::ChildIndex;
use garbled_circuit::{
    functionality::{
        circuit_eval::{yao_circuit_eval_functionality, yao_map_circuit_eval_functionality},
        output::batch_output_yao_functionality,
        utils_dep::TagOffsetCounter,
    },
    utilities::{
        hash_function::HashFunction,
        types::{MapArg, YaoSetup, YaoShare},
    },
};
use rand::{CryptoRng, RngCore};
use sl_messages::relay::Relay;

use crate::{
    circuits::build_child_key_der_hmac_circuit,
    types::{HardDerivationError, PrivKeyShareBip, ProtocolParticipant},
    utils::bool_vec_to_u8_vec,
    yao_to_rss::{run_batch_yao_to_scalar_rss_keypair, run_yao_to_scalar_rss_keypair},
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
    mut rng: Option<&mut G>,
    hash: &H,
) -> Result<PrivKeyShareBip, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    let circuit =
        build_child_key_der_hmac_circuit(&parent_key.pubkey, index_child, parent_key.chain_code);

    let inputs = [parent_key.yao_share.to_vec()];

    let hashed_vals = yao_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &inputs,
        &circuit,
        rng.as_mut(),
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

    let child_cc_pub =
        batch_output_yao_functionality(setup, tag_offset_counter, relay, child_chain_code).await?;

    let child_cc = bool_vec_to_u8_vec(child_cc_pub);

    let out = PrivKeyShareBip {
        yao_share: child_yao_share.try_into().expect("Conversion failed"),
        pubkey: scalar_rss_out.pubkey,
        keyshare: scalar_rss_out.keyshare,
        chain_code: child_cc.try_into().expect("Conversion failed"),
    };

    Ok(out)
}

/// Implements the child key derivation protocol for BIP-32 on secret-shared inputs.
#[allow(clippy::too_many_arguments)]
pub async fn run_batch_derive_child_key<S, R, G, H>(
    setup: &S,
    relay: &mut R,
    tag_offset_counter: &mut TagOffsetCounter,
    parent_key: &[&PrivKeyShareBip],
    index_child: &[ChildIndex],
    yao_setup: &YaoSetup,
    mut rng: Option<&mut G>,
    hash: &H,
) -> Result<Vec<PrivKeyShareBip>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    H: HashFunction,
{
    assert_eq!(parent_key.len(), index_child.len());

    let batch_size = parent_key.len();
    let mut circuit_store = Vec::new();
    let mut circuits = Vec::new();

    for i in 0..batch_size {
        circuit_store.push(build_child_key_der_hmac_circuit(
            &parent_key[i].pubkey,
            &index_child[i],
            parent_key[i].chain_code,
        ));
    }
    for circuit in &circuit_store {
        circuits.push(circuit);
    }

    let yao_share_vecs: Vec<Vec<Vec<YaoShare>>> = parent_key
        .iter()
        .map(|v| vec![v.yao_share.to_vec()])
        .collect();

    let inputs: Vec<&[Vec<YaoShare>]> = yao_share_vecs.iter().map(|v| v.as_slice()).collect();

    let hashed_vals = yao_map_circuit_eval_functionality(
        setup,
        tag_offset_counter,
        relay,
        &MapArg::Vector(&inputs),
        &MapArg::Vector(&circuits),
        rng.as_mut(),
        hash,
        yao_setup,
    )
    .await?;

    let mut il_ints = Vec::with_capacity(batch_size);
    let mut child_yao_shares = Vec::with_capacity(batch_size);
    let mut child_chain_codes = Vec::with_capacity(batch_size);

    circuits.iter().enumerate().for_each(|(cnt, circuit)| {
        let hash_out: Vec<YaoShare> = circuit
            .output_gate_ids
            .iter()
            .map(|val| hashed_vals[cnt].get(val).unwrap().clone())
            .collect();

        let (il_int, child_chain_code) = hash_out.split_at(32 * 8);

        let mut child_yao_share = il_int.to_vec();
        child_yao_share.reverse();

        child_yao_shares.push(child_yao_share);
        il_ints.push(il_int.to_vec());
        child_chain_codes.push(child_chain_code.to_vec());
    });

    let il_int_slices: Vec<&[YaoShare]> = il_ints.iter().map(|x| x.as_slice()).collect();

    let scalar_rss_out =
        run_batch_yao_to_scalar_rss_keypair(setup, relay, tag_offset_counter, &il_int_slices, rng)
            .await?;

    let mut ccoutinput = Vec::new();
    for i in child_chain_codes.iter() {
        ccoutinput.extend_from_slice(i);
    }

    let child_cc_pub_vals =
        batch_output_yao_functionality(setup, tag_offset_counter, relay, &ccoutinput).await?;

    let mut child_ccs = Vec::new();
    let ccsize = child_chain_codes[0].len();
    for i in 0..batch_size {
        let child_cc_pub = child_cc_pub_vals[i * ccsize..(i + 1) * ccsize].to_vec();
        let child_cc = bool_vec_to_u8_vec(child_cc_pub);

        child_ccs.push(child_cc);
    }

    let mut out: Vec<PrivKeyShareBip> = Vec::with_capacity(batch_size);

    for i in 0..batch_size {
        let val = PrivKeyShareBip {
            yao_share: child_yao_shares[i]
                .clone()
                .try_into()
                .expect("Conversion failed"),
            pubkey: scalar_rss_out[i].pubkey,
            keyshare: scalar_rss_out[i].keyshare,
            chain_code: child_ccs[i].clone().try_into().expect("Conversion failed"),
        };

        out.push(val);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use derivation_path::ChildIndex;
    use garbled_circuit::{
        functionality::{
            input::batch_input_yao_functionality, setup::setup_yao_functionality,
            utils_dep::TagOffsetCounter,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash, types::YaoSetup},
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
        derive_child_key::{run_batch_derive_child_key, run_derive_child_key},
        types::{HardDerivationError, PrivKeyShare, PrivKeyShareBip, ProtocolParticipant},
        utils::{run_init, u8_vec_to_bool_vec},
    };

    async fn test_run_derive_child_key<S, R>(
        setup: S,
        rpk_bool: Vec<bool>,
        rcc_bool: [u8; 32],
        public_key: ProjectivePoint,
        child_index: ChildIndex,
        relay: R,
    ) -> Result<(usize, PrivKeyShareBip), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut cnt = TagOffsetCounter::new();

        let yao_setup = setup_yao_functionality(&setup, &mut cnt, &mut relay).await?;

        let (mut rng, hash, _) = match &yao_setup {
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

        let rpk_yao = batch_input_yao_functionality(
            &setup,
            &mut cnt,
            &mut relay,
            &rpk_bool,
            rng.as_mut(),
            &yao_setup,
        )
        .await?;

        let share = PrivKeyShareBip {
            yao_share: rpk_yao.try_into().expect("Conversion failed"),
            keyshare: PrivKeyShare::<ProjectivePoint>::default(),
            pubkey: public_key,
            chain_code: rcc_bool,
        };

        let output = run_derive_child_key(
            &setup,
            &mut relay,
            &mut cnt,
            &share,
            &child_index,
            &yao_setup,
            rng.as_mut(),
            &hash,
        )
        .await?;

        Ok((setup.participant_index(), output))
    }

    async fn test_run_batched_derive_child_key<S, R>(
        setup: S,
        rpk_bool: Vec<bool>,
        rcc_bool: [u8; 32],
        public_key: ProjectivePoint,
        child_index: Vec<ChildIndex>,
        relay: R,
    ) -> Result<(usize, Vec<PrivKeyShareBip>), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut cnt = TagOffsetCounter::new();

        let yao_setup = setup_yao_functionality(&setup, &mut cnt, &mut relay).await?;

        let (mut rng, hash, _) = match &yao_setup {
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

        let rpk_yao = batch_input_yao_functionality(
            &setup,
            &mut cnt,
            &mut relay,
            &rpk_bool,
            rng.as_mut(),
            &yao_setup,
        )
        .await?;

        let mut inputs = Vec::new();
        for _ in 0..child_index.len() {
            let share = PrivKeyShareBip {
                yao_share: rpk_yao.clone().try_into().expect("Conversion failed"),
                keyshare: PrivKeyShare::<ProjectivePoint>::default(),
                pubkey: public_key,
                chain_code: rcc_bool,
            };
            inputs.push(share);
        }

        let input_slices: Vec<&PrivKeyShareBip> = inputs.iter().collect();

        let output = run_batch_derive_child_key(
            &setup,
            &mut relay,
            &mut cnt,
            &input_slices,
            &child_index,
            &yao_setup,
            rng.as_mut(),
            &hash,
        )
        .await?;

        Ok((setup.participant_index(), output))
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

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_derive_child_key(
                setup,
                rpk_bool.clone(),
                root_chain_code,
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

        let child_privkey_obtained = shares[0].1.keyshare.next_share
            + shares[1].1.keyshare.next_share
            + shares[2].1.keyshare.next_share;

        let (child_privkey_ideal, child_chaincode_ideal) = get_ideal_output(
            &root_chain_code,
            &root_public_key,
            child_index,
            root_private_key,
        );

        assert_eq!(child_privkey_ideal, child_privkey_obtained);
        assert_eq!(
            hex::encode(child_chaincode_ideal),
            hex::encode(shares[0].1.chain_code)
        );
    }

    async fn test_derive_child_key_batched_util(child_index: Vec<ChildIndex>) {
        let (root_public_key, root_private_key, root_chain_code) = setup();
        let rpk_bool = u8_vec_to_bool_vec(root_private_key.to_bytes().to_vec());

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_batched_derive_child_key(
                setup,
                rpk_bool.clone(),
                root_chain_code,
                root_public_key,
                child_index.clone(),
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

        (0..child_index.len()).for_each(|i| {
            let child_privkey_obtained = shares[0].1[i].keyshare.next_share
                + shares[1].1[i].keyshare.next_share
                + shares[2].1[i].keyshare.next_share;

            let (child_privkey_ideal, child_chaincode_ideal) = get_ideal_output(
                &root_chain_code,
                &root_public_key,
                child_index[i],
                root_private_key,
            );

            assert_eq!(child_privkey_ideal, child_privkey_obtained);
            assert_eq!(
                hex::encode(child_chaincode_ideal),
                hex::encode(shares[0].1[i].chain_code)
            );
        });
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

        let mut nos = Vec::new();
        for _ in 0..5 {
            let no: u32 = rng.r#gen();
            let child_number = ChildIndex::Normal(no);
            nos.push(child_number);
        }
        test_derive_child_key_batched_util(nos).await;
    }
}
