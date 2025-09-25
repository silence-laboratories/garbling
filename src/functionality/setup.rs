use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    config::constants::{SETUP_YAO_FUNC_MSG1, SETUP_YAO_FUNC_MSG2},
    functionality::{
        utils::{receive_from_parties, send_to_party},
        utils_dep::{FilteredMsgRelay, ProtocolError, ProtocolParticipant, TagOffsetCounter},
    },
    utilities::types::{Block, EvaluatorSetup, GarblerSetup, YaoSetup, BLOCK_SIZE},
};

pub async fn setup_yao_functionality<T, R>(
    setup: &T,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<YaoSetup, ProtocolError>
where
    T: ProtocolParticipant,
    R: Relay,
{
    let party_id = setup.participant_index();

    let mut output = YaoSetup {
        g_setup: None,
        e_setup: None,
    };

    let tag_offset = tag_offset_counter.next_value();
    let tag1 = MessageTag::tag1(SETUP_YAO_FUNC_MSG1.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag1, true).await?;
    let tag_offset = tag_offset_counter.next_value();
    let tag2 = MessageTag::tag1(SETUP_YAO_FUNC_MSG2.try_into().unwrap(), tag_offset);
    relay.ask_messages(setup, tag2, true).await?;

    if party_id == 2 {
        let mut rng = rand::rngs::StdRng::from_os_rng();
        let mut crs = Block::default();
        rng.fill_bytes(&mut crs);

        send_to_party(setup, tag1, crs, 0, relay).await?;
        send_to_party(setup, tag1, crs, 1, relay).await?;

        output.e_setup = Some(EvaluatorSetup { comm_crs: crs })
    } else {
        let crss: Vec<Block> =
            receive_from_parties(setup, tag1, BLOCK_SIZE, vec![2], relay).await?;

        let mut rng = rand::rngs::StdRng::from_os_rng();
        let seed = if party_id == 0 {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);

            send_to_party(setup, tag2, seed, 1, relay).await?;
            seed
        } else {
            let seed: Vec<[u8; 32]> = receive_from_parties(setup, tag2, 32, vec![0], relay).await?;
            seed[0]
        };

        let mut rng = ChaCha8Rng::from_seed(seed);

        let mut delta = Block::default();
        rng.fill_bytes(&mut delta);
        delta[0] |= 1;

        output.g_setup = Some(GarblerSetup {
            comm_crs: crss[0],
            prf_key: seed,
            delta,
        })
    }

    Ok(output)
}
