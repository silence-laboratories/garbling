// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
};
use k256::{ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::Digest;

use garbled_circuit::utilities::{
    types::{YaoEvaluatorShare, YaoGarblerShare},
    utils::{lsb, xor_blocks},
};

use crate::types::ScalarFromBytes;

fn get_pub_vec_times_a<G>(a: &G::Scalar) -> Vec<G::Scalar>
where
    G: Group + GroupEncoding,
    G::Scalar: Field,
{
    let mut out = Vec::new();
    let mut twopow = G::Scalar::ONE;
    let two = G::Scalar::ONE + G::Scalar::ONE;

    for _ in 0..256 {
        let val = *a * twopow;

        twopow *= two;
        out.push(val);
    }

    out
}

pub fn kdf<G>(i: &[u8], label: &[u8]) -> G::Scalar
where
    G: Group + GroupEncoding,
    G::Scalar: PrimeField + ScalarFromBytes,
{
    let mut h = sha2::Sha512::new();
    h.update(i);
    h.update(label);
    G::Scalar::from_bytes(h.finalize()[..32].try_into().unwrap())
}

/// Implementation of the garble algorithm of garbling gadget from the paper (2.1)
pub fn garble_gadget<R>(
    garbled_inputs: &[&YaoGarblerShare],
    rng: &mut R,
) -> (Vec<Scalar>, (Scalar, Scalar))
where
    R: CryptoRng + RngCore,
{
    assert_eq!(garbled_inputs.len(), 256);
    let eta = garbled_inputs.len();

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let a = Scalar::from_bytes(bytes);

    let mut b = Scalar::ZERO;
    let mut cvec = Vec::with_capacity(eta);

    let pub_times_a = get_pub_vec_times_a::<ProjectivePoint>(&a);

    for i in 0..eta {
        let pi = lsb(&garbled_inputs[i].f_label) != 0;

        let hk0 = kdf::<ProjectivePoint>(
            &i.to_be_bytes(),
            &garbled_inputs[i].f_label,
        );

        let hk1 = kdf::<ProjectivePoint>(
            &i.to_be_bytes(),
            &xor_blocks(&garbled_inputs[i].f_label, &garbled_inputs[i].delta),
        );
        let a_ui = &pub_times_a[i];

        let bi_p1 = Scalar::ZERO - hk0;
        let bi_p2 = if pi { (hk0 - hk1) - a_ui } else { Scalar::ZERO };
        let bi = bi_p1 + bi_p2;

        b += bi;

        let ci_p1 = if pi { hk0 } else { hk1 + a_ui };
        let ci = ci_p1 + bi;

        cvec.push(ci);
    }

    let dec = (a, b);

    (cvec, dec)
}

/// Implementation of the evaluate algorithm of garbling gadget from the paper (2.1)
pub fn evaluate_gadget<G>(
    cvec: &[G::Scalar],
    garbled_inputs: &[YaoEvaluatorShare],
) -> G::Scalar
where
    G: Group + GroupEncoding,
    G::Scalar: PrimeField + ScalarFromBytes,
{
    // Internal precondition. `cvec` arrives from the garblers, so its length
    // is checked against the local share count at the message boundary in
    // `get_private_key_shares_dkg_create_msg2_p3` before this is reached.
    assert_eq!(cvec.len(), garbled_inputs.len());

    let eta = cvec.len();

    let mut z = G::Scalar::ZERO;

    for i in 0..eta {
        let lambda_i = lsb(&garbled_inputs[i].label) != 0;

        let hke = kdf::<G>(&i.to_be_bytes(), &garbled_inputs[i].label);
        let zi = if lambda_i {
            cvec[i] - hke
        } else {
            G::Scalar::ZERO - hke
        };

        z += zi;
    }

    z
}

/// Implementation of the decode algorithm of garbling gadget from the paper (2.1)
pub fn decode_gadget<G>(
    dec: &(G::Scalar, G::Scalar),
    z: G::Scalar,
) -> G::Scalar
where
    G: Group + GroupEncoding,
{
    let ainv = dec.0.invert().unwrap();
    let out_p1 = z - dec.1;
    ainv * out_p1
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use garbled_circuit::{
        functionality::{
            input::batch_input_yao_functionality,
            setup::setup_yao_functionality,
            utils::{
                receive_from_one_party, receive_from_parties, send_to_party,
                FilteredMsgRelay,
            },
        },
        utilities::types::{YaoEvaluatorShare, YaoGarblerShare, YaoSetup},
    };
    use k256::{ProjectivePoint, Scalar};
    use sha2::{Digest, Sha512};
    use sl_compute_common::{binary_string_to_u8_vec, BinaryString};
    use sl_messages::{
        message::MessageTag,
        relay::{Relay, SimpleMessageRelay},
    };

    use crate::{
        arith_gadget::{decode_gadget, evaluate_gadget, garble_gadget},
        types::{
            vec_scalar_2_scalarvals, vec_scalarval_2_scalars,
            HardDerivationError, ProtocolParticipant, ScalarVal,
        },
        utils::{run_init, u8_vec_to_bool_vec},
    };

    async fn test_run_arith_gadget<S, R>(
        setup: S,
        garb_input: Vec<bool>,
        relay: R,
    ) -> Result<(usize, k256::Scalar), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);
        relay.init_abort(&setup).await?;

        let mut yao_setup =
            setup_yao_functionality(&setup, &mut relay).await?;

        let outputs = batch_input_yao_functionality(
            &setup,
            &mut relay,
            &garb_input,
            &mut yao_setup,
        )
        .await?;

        let mut r = relay;

        let tag1 = MessageTag::tag(511);
        let tag2 = MessageTag::tag(512);
        let tag3 = MessageTag::tag(513);

        let out = match &mut yao_setup {
            YaoSetup::E(_) => {
                let svcvecs: Vec<Vec<ScalarVal>> =
                    receive_from_parties(&setup, tag1, &[0, 1], &mut r)
                        .await?;

                let cvecs = [
                    vec_scalarval_2_scalars(&svcvecs[0]),
                    vec_scalarval_2_scalars(&svcvecs[1]),
                ];

                assert_eq!(cvecs[0], cvecs[1]);
                let cvec = cvecs[0].clone();

                let eins: Vec<YaoEvaluatorShare> = outputs
                    .iter()
                    .map(|ins| ins.as_evaluator())
                    .cloned()
                    .collect();

                let z = evaluate_gadget::<ProjectivePoint>(&cvec, &eins);

                send_to_party(&setup, tag2, &ScalarVal(z), 0, &mut r).await?;
                send_to_party(&setup, tag2, &ScalarVal(z), 1, &mut r).await?;

                let outs: Vec<ScalarVal> =
                    receive_from_parties(&setup, tag3, &[0, 1], &mut r)
                        .await?;

                assert_eq!(outs[0].0, outs[1].0);
                outs[0].0
            }

            YaoSetup::G(g) => {
                let gins: Vec<&YaoGarblerShare> =
                    outputs.iter().map(|ins| ins.as_garbler()).collect();

                let (cvec, de) = garble_gadget(&gins, &mut g.prf);

                let svcvec = vec_scalar_2_scalarvals(&cvec);

                send_to_party(&setup, tag1, &svcvec, 2, &mut r).await?;

                let zs: ScalarVal =
                    receive_from_one_party(&setup, tag2, 2, &mut r).await?;

                let out = decode_gadget::<ProjectivePoint>(&de, zs.0);

                send_to_party(&setup, tag3, &ScalarVal(out), 2, &mut r)
                    .await?;

                out
            }
        };

        Ok((setup.participant_index(), out))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_arith_gadget() {
        let binstr = BinaryString::new_with_zeros(256);

        let mut hasher = Sha512::new();
        let ginu8 = binary_string_to_u8_vec(binstr);
        hasher.update(ginu8);
        let result: [u8; 64] = hasher.finalize().into();
        let gin = u8_vec_to_bool_vec(&result[..32]).collect::<Vec<_>>();

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_arith_gadget(setup, gin.clone(), relay));
        }

        let mut shares = vec![];

        while let Some(fini) = parties.join_next().await {
            if let Err(ref err) = fini {
                println!("error {err:?}");
            } else {
                match fini.unwrap() {
                    Err(err) => panic!("err {err:?}"),
                    Ok(share) => shares.push(Arc::new(share)),
                }
            }
        }

        let mut sum = Scalar::ZERO;
        let two = Scalar::ONE + Scalar::ONE;
        let mut twopow = Scalar::ONE;

        for i in gin {
            if i {
                sum += twopow;
            }
            twopow *= two;
        }

        assert_eq!(sum, shares[0].1);
        assert_eq!(sum, shares[1].1);
        assert_eq!(sum, shares[2].1);
    }
}
