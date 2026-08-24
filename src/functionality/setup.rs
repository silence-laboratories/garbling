// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use sl_messages::{relay::Relay, setup::ProtocolParticipant};

use crate::{
    config::constants::{SETUP_YAO_FUNC_MSG1, SETUP_YAO_FUNC_MSG2},
    functionality::{
        utils::{receive_from_one_party, send_to_party, FilteredMsgRelay},
        utils_dep::ProtocolError,
    },
    utilities::{
        commitments::HashCommitment,
        hash_function::AesHash,
        types::{Block, EvaluatorSetup, GarblerSetup, YaoSetup},
    },
};

/// Expands a shared PRF key into an independent free-XOR offset and label stream.
///
/// Delta and wire labels must not share ChaCha8 keystream. The input key is
/// stretched into two 32-byte seeds: one for `delta`, one for the stored PRF.
pub fn garbler_delta_and_prf(prf_key: [u8; 32]) -> (Block, ChaCha8Rng) {
    let mut kdf = ChaCha8Rng::from_seed(prf_key);
    let mut delta_seed = [0u8; 32];
    let mut label_seed = [0u8; 32];
    kdf.fill_bytes(&mut delta_seed);
    kdf.fill_bytes(&mut label_seed);

    let mut delta = Block::default();
    ChaCha8Rng::from_seed(delta_seed).fill_bytes(&mut delta);
    delta[0] |= 1;

    (delta, ChaCha8Rng::from_seed(label_seed))
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

    let party_id = setup.participant_index();
    let mut rng = rand::rngs::StdRng::from_entropy();

    if party_id == 2 {
        let crs = rng.gen();

        send_to_party(setup, tag1, &crs, 0, relay).await?;
        send_to_party(setup, tag1, &crs, 1, relay).await?;

        Ok(YaoSetup::E(EvaluatorSetup { comm_crs: crs }))
    } else {
        let comm_crs = receive_from_one_party(setup, tag1, 2, relay).await?;

        let prf_key = if party_id == 0 {
            let seed = rng.gen();
            send_to_party(setup, tag2, &seed, 1, relay).await?;
            seed
        } else {
            receive_from_one_party(setup, tag2, 0, relay).await?
        };

        let (delta, prf) = garbler_delta_and_prf(prf_key);

        Ok(YaoSetup::G(GarblerSetup {
            comm_crs,
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
    let comm_crs = match &yao_setup {
        YaoSetup::E(e) => e.comm_crs,
        YaoSetup::G(g) => g.comm_crs,
    };
    let hash = AesHash::new(comm_crs);
    let comm = HashCommitment::new(hash);

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
        let (delta, mut prf) = garbler_delta_and_prf(prf_key);
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
        let (delta, mut prf) = garbler_delta_and_prf(prf_key);

        let mut first_block = Block::default();
        prf.fill_bytes(&mut first_block);
        assert_ne!(first_block, delta);

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
}
