// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::prelude::*;
use rand::{RngCore, SeedableRng};
use zeroize::Zeroizing;

use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    config::constants::{
        SETUP_YAO_FUNC_MSG1, SETUP_YAO_FUNC_MSG2, SETUP_YAO_FUNC_MSG3,
    },
    functionality::{
        utils::{receive_from_one_party, send_to_party, FilteredMsgRelay},
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::HashCommitment,
        hash_function::AesHash,
        label_prf::LabelPrf,
        types::{Block, EvaluatorSetup, GarblerSetup, YaoSetup},
    },
};

/// Expands a shared PRF key into free-XOR offset, label stream, and garble key.
///
/// Delta, wire labels, and the circuit-garbling hash key must not share
/// ChaCha8 keystream. The input key is stretched into three 32-byte seeds.
pub fn garbler_delta_and_prf(prf_key: [u8; 32]) -> (Block, LabelPrf, Block) {
    let prf_key = Zeroizing::new(prf_key);
    let mut kdf = LabelPrf::from_seed(*prf_key);
    let mut delta_seed = Zeroizing::new([0u8; 32]);
    let mut label_seed = Zeroizing::new([0u8; 32]);
    let mut garble_seed = Zeroizing::new([0u8; 32]);
    kdf.fill_bytes(delta_seed.as_mut());
    kdf.fill_bytes(label_seed.as_mut());
    kdf.fill_bytes(garble_seed.as_mut());

    let mut delta = Block::default();
    LabelPrf::from_seed(*delta_seed).fill_bytes(&mut delta);
    delta[0] |= 1;

    let mut garble_key = Block::default();
    garble_key.copy_from_slice(&garble_seed[..16]);

    (delta, LabelPrf::from_seed(*label_seed), garble_key)
}

pub async fn setup_yao_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<YaoSetup, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let tag1 = relay.next_tag(SETUP_YAO_FUNC_MSG1);
    let tag2 = relay.next_tag(SETUP_YAO_FUNC_MSG2);
    let tag3 = relay.next_tag(SETUP_YAO_FUNC_MSG3);

    let party_id = setup.participant_index();
    let mut rng = rand::rngs::StdRng::from_entropy();

    if party_id == 2 {
        let crs = rng.gen();

        send_to_party(setup, tag1, &crs, 0, relay).await?;
        send_to_party(setup, tag1, &crs, 1, relay).await?;

        let garble_key: Block =
            receive_from_one_party(setup, tag3, 0, relay).await?;

        Ok(YaoSetup::E(EvaluatorSetup {
            comm_crs: crs,
            garble_key,
        }))
    } else {
        let comm_crs = receive_from_one_party(setup, tag1, 2, relay).await?;

        let prf_key = if party_id == 0 {
            let seed: [u8; 32] = rng.gen();
            send_to_party(setup, tag2, &(seed, comm_crs), 1, relay).await?;
            seed
        } else {
            let (seed, p0_comm_crs): ([u8; 32], Block) =
                receive_from_one_party(setup, tag2, 0, relay).await?;
            if p0_comm_crs != comm_crs {
                return Err(ProtocolError::InconsistentMessage);
            }
            seed
        };

        let (delta, prf, garble_key) = garbler_delta_and_prf(prf_key);

        if party_id == 0 {
            send_to_party(setup, tag3, &garble_key, 2, relay).await?;
        }

        Ok(YaoSetup::G(GarblerSetup {
            comm_crs,
            garble_key,
            prf,
            delta,
            party_id,
        }))
    }
}

pub async fn setup_aes_yao_functionality<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<(YaoSetup, AesHash, HashCommitment<AesHash>), ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let yao_setup = setup_yao_functionality(setup, relay).await?;
    let hash = AesHash::new(yao_setup.garble_key());
    let comm = HashCommitment::new(AesHash::new(yao_setup.comm_crs()));

    Ok((yao_setup, hash, comm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::types::BLOCK_SIZE;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    /// Pre-fix construction: reseeding the stored PRF from `prf_key` after
    /// drawing delta, then consuming a permute bit and a 16-byte label.
    fn buggy_first_label_and_delta(prf_key: [u8; 32]) -> (Block, Block) {
        let mut rng = ChaCha8Rng::from_seed(prf_key);
        let mut delta = Block::default();
        rng.fill_bytes(&mut delta);
        delta[0] |= 1;

        let mut prf = ChaCha8Rng::from_seed(prf_key);
        let _permute = prf.next_u32();
        let mut label = Block::default();
        prf.fill_bytes(&mut label);
        (delta, label)
    }

    fn first_input_label(prf_key: [u8; 32]) -> (Block, Block) {
        let (delta, mut prf, _) = garbler_delta_and_prf(prf_key);
        let _permute = prf.next_u32();
        let mut label = Block::default();
        prf.fill_bytes(&mut label);
        (delta, label)
    }

    #[test]
    fn buggy_construction_overlaps_delta_in_twelve_bytes() {
        let prf_key = [0x5au8; 32];
        let (delta, label) = buggy_first_label_and_delta(prf_key);
        assert_eq!(&label[..12], &delta[4..]);
    }

    #[test]
    fn first_prf_block_is_independent_of_delta() {
        let prf_key = [0x5au8; 32];
        let (delta, mut prf, garble_key) = garbler_delta_and_prf(prf_key);

        let mut first_block = Block::default();
        prf.fill_bytes(&mut first_block);
        assert_ne!(first_block, delta);
        assert_ne!(garble_key, delta);
        assert_ne!(garble_key, first_block);

        let (delta, label) = first_input_label(prf_key);
        assert_ne!(&label[..12], &delta[4..]);
        assert_ne!(label, delta);

        for offset in 0..=BLOCK_SIZE - 12 {
            assert_ne!(
                &label[..12],
                &delta[offset..offset + 12],
                "12-byte window of delta at offset {offset} leaked into the first label"
            );
        }
    }

    #[test]
    fn garble_key_is_independent_of_comm_crs_style_seed() {
        // Same PRF key always yields the same garble key; it must not equal an
        // unrelated evaluator CRS block used only for commitments.
        let prf_key = [0x5au8; 32];
        let (_, _, garble_key) = garbler_delta_and_prf(prf_key);
        let comm_crs = [0x11u8; 16];
        assert_ne!(garble_key, comm_crs);
    }
}
