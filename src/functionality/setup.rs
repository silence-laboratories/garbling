// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    config::constants::{SETUP_YAO_FUNC_MSG1, SETUP_YAO_FUNC_MSG2},
    functionality::{
        utils::{receive_from_parties, send_to_party, FilteredMsgRelay},
        utils_dep::{ProtocolError, ProtocolParticipant},
    },
    utilities::types::{Block, EvaluatorSetup, GarblerSetup, YaoSetup},
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

    let output =
        setup_yao_functionality_inner(setup, relay, tag1, tag2).await?;

    Ok(output)
}

async fn setup_yao_functionality_inner<T, R>(
    setup: &T,
    relay: &mut FilteredMsgRelay<R>,
    tag1: MessageTag,
    tag2: MessageTag,
) -> Result<YaoSetup, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let party_id = setup.participant_index();

    if party_id == 2 {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut crs = Block::default();
        rng.fill_bytes(&mut crs);

        send_to_party(setup, tag1, crs, 0, relay).await?;
        send_to_party(setup, tag1, crs, 1, relay).await?;

        Ok(YaoSetup::E(EvaluatorSetup { comm_crs: crs }))
    } else {
        let crss: Vec<Block> =
            receive_from_parties(setup, tag1, &[2], relay).await?;

        let mut rng = rand::rngs::StdRng::from_entropy();
        let seed = if party_id == 0 {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);

            send_to_party(setup, tag2, seed, 1, relay).await?;
            seed
        } else {
            let seed: Vec<[u8; 32]> =
                receive_from_parties(setup, tag2, &[0], relay).await?;
            seed[0]
        };

        let mut rng = ChaCha8Rng::from_seed(seed);

        let mut delta = Block::default();
        rng.fill_bytes(&mut delta);
        delta[0] |= 1;

        Ok(YaoSetup::G(GarblerSetup {
            comm_crs: crss[0],
            prf_key: seed,
            delta,
        }))
    }
}
