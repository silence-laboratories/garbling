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

        let mut rng = ChaCha8Rng::from_seed(prf_key);

        let mut delta = Block::default();
        rng.fill_bytes(&mut delta);
        delta[0] |= 1;

        Ok(YaoSetup::G(GarblerSetup {
            comm_crs,
            prf: ChaCha8Rng::from_seed(prf_key),
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
