// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use sl_messages::relay::Relay;

use crate::{
    config::constants::{SETUP_YAO_FUNC_MSG1, SETUP_YAO_FUNC_MSG2},
    functionality::{
        utils::{receive_from_one_party, send_to_party, FilteredMsgRelay},
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
