use garbled_circuit::{
    functionality::{
        utils::{FilteredMsgRelay, Wrap, receive_from_parties, send_to_party},
        utils_dep::TagOffsetCounter,
    },
    utilities::types::{YaoEvaluatorShare, YaoGarblerShare, YaoShare},
};
use k256::elliptic_curve::PrimeField;
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sl_messages::{message::MessageTag, relay::Relay};

use crate::{
    arith_gadget::{evaluate_gadget, garble_gadget},
    constants::{YAO_TO_RSS_MSG1, YAO_TO_RSS_MSG2, YAO_TO_RSS_MSG3, YAO_TO_RSS_MSG4},
    types::{
        HardDerivationError, PrivKeyShare, PrivKeyShareDkg, ProtocolParticipant, ScalarFromBytes,
        ScalarVal,
    },
};

/// Msg1 for Yao to Scalar RSS key pair protocol
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg1 {
    cvec: Vec<Scalar>,
    cvec_star: Vec<Scalar>,
    delta_2: Scalar,
    delta_0: Scalar,
}

impl Wrap for YaoToScalarRssKeypairMsg1 {
    fn external_size(&self) -> usize {
        self.cvec.len() * 32 + self.cvec.len() * 32 + 32 + 32
    }

    fn write(&self, buffer: &mut [u8]) {
        for (b, s) in buffer.chunks_exact_mut(32).zip(
            self.cvec
                .iter()
                .chain(&self.cvec_star)
                .chain(Some(&self.delta_2))
                .chain(Some(&self.delta_0)),
        ) {
            b.copy_from_slice(&s.to_bytes());
        }
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let cveclen = buffer
            .len()
            .is_multiple_of(64)
            .then(|| buffer.len() / 32)
            .filter(|&len| len > 2)
            .map(|len| (len - 2) / 2)?;

        fn svec(b: &[u8], count: usize) -> Option<(&[u8], Vec<Scalar>)> {
            let (b, rest) = b.split_at_checked(count * 32)?;

            let v = b
                .chunks_exact(32)
                .map(FieldBytes::from_slice)
                .map(|&b| Scalar::from_repr(b).into_option())
                .collect::<Option<Vec<_>>>()?;

            Some((rest, v))
        }

        let (buffer, cvec) = svec(buffer, cveclen)?;
        let (buffer, cvec_star) = svec(buffer, cveclen)?;

        let delta_2 = ScalarVal::read(&buffer[..32])?.0;
        let delta_0 = ScalarVal::read(&buffer[32..])?.0;

        Some(YaoToScalarRssKeypairMsg1 {
            cvec,
            cvec_star,
            delta_2,
            delta_0,
        })
    }
}

/// State1 for Yao to Scalar RSS key pair protocol
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairState1 {
    cvec: Vec<Scalar>,
    cvec_star: Vec<Scalar>,
    alpha: Scalar,
    alpha_star: Scalar,
    beta: Scalar,
    beta_star: Scalar,
    delta_0: Scalar,
    delta_1: Scalar,
    delta_2: Scalar,
}

/// Msg2 for Yao to Scalar RSS key pair protocol
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg2 {
    pk_tilde: ProjectivePoint,
    pk_tilde_star: ProjectivePoint,
    ski_tilde: Scalar,
    skip2_tilde: Scalar,
}

impl Wrap for YaoToScalarRssKeypairMsg2 {
    fn external_size(&self) -> usize {
        32 * 2 + 33 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33].copy_from_slice(self.pk_tilde.to_encoded_point(true).as_bytes());
        buffer[33..66].copy_from_slice(self.pk_tilde_star.to_encoded_point(true).as_bytes());
        buffer[66..98].copy_from_slice(&self.ski_tilde.to_bytes());
        buffer[98..130].copy_from_slice(&self.skip2_tilde.to_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let encoded = EncodedPoint::from_bytes(buffer[0..33].as_ref()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pk_tilde = ProjectivePoint::from(affine);

        let encoded = EncodedPoint::from_bytes(buffer[33..66].as_ref()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pk_tilde_star = ProjectivePoint::from(affine);

        let ski_tilde = k256::Scalar::from_repr(*FieldBytes::from_slice(&buffer[66..98])).unwrap();
        let skip2_tilde =
            k256::Scalar::from_repr(*FieldBytes::from_slice(&buffer[98..130])).unwrap();
        Some(Self {
            pk_tilde,
            pk_tilde_star,
            ski_tilde,
            skip2_tilde,
        })
    }
}

/// State2 for Yao to Scalar RSS key pair protocol for evaluator
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairState2 {
    pk_tilde: ProjectivePoint,
    sk0_tilde: Scalar,
    sk2_tilde: Scalar,
    delta_0: Scalar,
    delta_2: Scalar,
}

/// Msg3 for Yao to Scalar RSS key pair protocol for evaluator
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg3p3 {
    pki_tilde: ProjectivePoint,
    pkip2_tilde: ProjectivePoint,
    alpha: Scalar,
}

impl Wrap for YaoToScalarRssKeypairMsg3p3 {
    fn external_size(&self) -> usize {
        32 + 33 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33].copy_from_slice(self.pki_tilde.to_encoded_point(true).as_bytes());
        buffer[33..66].copy_from_slice(self.pkip2_tilde.to_encoded_point(true).as_bytes());
        buffer[66..98].copy_from_slice(&self.alpha.to_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let encoded = EncodedPoint::from_bytes(buffer[0..33].as_ref()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pki_tilde = ProjectivePoint::from(affine);

        let encoded = EncodedPoint::from_bytes(buffer[33..66].as_ref()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pkip2_tilde = ProjectivePoint::from(affine);

        let alpha = k256::Scalar::from_repr(*FieldBytes::from_slice(&buffer[66..98])).unwrap();
        Some(Self {
            pki_tilde,
            pkip2_tilde,
            alpha,
        })
    }
}

/// Msg3 for Yao to Scalar RSS key pair protocol for garblers
#[derive(Clone, Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg3p12 {
    pki_tilde: ProjectivePoint,
    pkip2_tilde: ProjectivePoint,
}

impl Wrap for YaoToScalarRssKeypairMsg3p12 {
    fn external_size(&self) -> usize {
        33 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33].copy_from_slice(self.pki_tilde.to_encoded_point(true).as_bytes());
        buffer[33..66].copy_from_slice(self.pkip2_tilde.to_encoded_point(true).as_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let encoded = EncodedPoint::from_bytes(buffer[0..33].as_ref()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pki_tilde = ProjectivePoint::from(affine);

        let encoded = EncodedPoint::from_bytes(buffer[33..66].as_ref()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pkip2_tilde = ProjectivePoint::from(affine);
        Some(Self {
            pki_tilde,
            pkip2_tilde,
        })
    }
}

/// State3 for Yao to Scalar RSS key pair protocol for garblers
#[derive(Clone, Debug, PartialEq)]
pub struct YaoToScalarRssKeypairState3p12 {
    pki_tilde: ProjectivePoint,
    pkip2_tilde: ProjectivePoint,
    pk_tilde: ProjectivePoint,
    pk_tilde_star: ProjectivePoint,
    ski_tilde: Scalar,
    skip2_tilde: Scalar,
}

/// State3 for Yao to Scalar RSS key pair protocol for evaluator
pub struct YaoToScalarRssKeypairState3p3 {
    pki_tilde: ProjectivePoint,
    pkip2_tilde: ProjectivePoint,
}

/// Create msg1 in the DeriveSKSharesDKG protocol, to be executed by parties p1 and p2
pub fn get_private_key_shares_dkg_create_msg1_p12<G>(
    sha_hashed_vals: &[YaoGarblerShare],
    rng: &mut G,
) -> (YaoToScalarRssKeypairMsg1, YaoToScalarRssKeypairState1)
where
    G: RngCore + CryptoRng,
{
    // Step 2b
    let garble_res = garble_gadget(sha_hashed_vals, rng);
    let cvec = garble_res.0;
    let de = garble_res.1;
    let alpha = de.0;
    let beta = de.1;

    // Step 2c
    let garble_res_star = garble_gadget(sha_hashed_vals, rng);
    let cvec_star = garble_res_star.0;
    let de_star = garble_res_star.1;
    let alpha_star = de_star.0;
    let beta_star = de_star.1;

    // Step 2d
    let delta = beta * alpha.invert().unwrap();

    // Step 2e
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let delta_0 = Scalar::from_bytes(bytes);

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let delta_1 = Scalar::from_bytes(bytes);

    // Step 2f
    let delta_2 = delta - (delta_0 + delta_1);

    (
        YaoToScalarRssKeypairMsg1 {
            cvec: cvec.clone(),
            cvec_star: cvec_star.clone(),
            delta_2,
            delta_0,
        },
        YaoToScalarRssKeypairState1 {
            cvec,
            cvec_star,
            alpha,
            alpha_star,
            beta,
            beta_star,
            delta_0,
            delta_1,
            delta_2,
        },
    )
}

/// Create msg2 in the DeriveSKSharesDKG protocol, to be executed by parties p3
pub fn get_private_key_shares_dkg_create_msg2_p3(
    sha_hashed_vals: &[YaoEvaluatorShare],
    msg1_from_p1: &YaoToScalarRssKeypairMsg1,
    msg1_from_p2: &YaoToScalarRssKeypairMsg1,
) -> (
    YaoToScalarRssKeypairMsg2,
    YaoToScalarRssKeypairMsg2,
    YaoToScalarRssKeypairState2,
) {
    // Step 5a
    assert_eq!(msg1_from_p1, msg1_from_p2);

    // Step 5c
    let sk_tilde = evaluate_gadget::<ProjectivePoint>(&msg1_from_p1.cvec, sha_hashed_vals);
    // Step 5e
    let pk_tilde = ProjectivePoint::GENERATOR * sk_tilde;

    // Step 5d
    let sk_tilde_star =
        evaluate_gadget::<ProjectivePoint>(&msg1_from_p1.cvec_star, sha_hashed_vals);
    // Step 5f
    let pk_tilde_star = ProjectivePoint::GENERATOR * sk_tilde_star;

    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut rng = ChaCha8Rng::from_seed(seed);

    // Step 5g
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk0_tilde = Scalar::from_bytes(bytes);

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk1_tilde = Scalar::from_bytes(bytes);

    // Step 5h
    let sk2_tilde = sk_tilde - (sk0_tilde + sk1_tilde);

    let msg2_p1 = YaoToScalarRssKeypairMsg2 {
        pk_tilde,
        pk_tilde_star,
        ski_tilde: sk0_tilde,
        skip2_tilde: sk1_tilde,
    };

    let msg2_p2 = YaoToScalarRssKeypairMsg2 {
        pk_tilde,
        pk_tilde_star,
        ski_tilde: sk1_tilde,
        skip2_tilde: sk2_tilde,
    };

    (
        msg2_p1,
        msg2_p2,
        YaoToScalarRssKeypairState2 {
            pk_tilde,
            sk0_tilde,
            sk2_tilde,
            delta_0: msg1_from_p1.delta_0,
            delta_2: msg1_from_p1.delta_2,
        },
    )
}

/// Create msg3 in the DeriveSKSharesDKG protocol, to be executed by parties p1 and p2
pub fn get_private_key_shares_dkg_create_msg3_p12(
    state1: &YaoToScalarRssKeypairState1,
    msg2: &YaoToScalarRssKeypairMsg2,
) -> (
    YaoToScalarRssKeypairMsg3p12,
    YaoToScalarRssKeypairMsg3p3,
    YaoToScalarRssKeypairState3p12,
) {
    // Step 8a
    let pki_tilde = ProjectivePoint::GENERATOR * msg2.ski_tilde;
    let pkip2_tilde = ProjectivePoint::GENERATOR * msg2.skip2_tilde;

    (
        YaoToScalarRssKeypairMsg3p12 {
            pki_tilde,
            pkip2_tilde,
        },
        YaoToScalarRssKeypairMsg3p3 {
            pki_tilde,
            pkip2_tilde,
            alpha: state1.alpha,
        },
        YaoToScalarRssKeypairState3p12 {
            pki_tilde,
            pkip2_tilde,
            pk_tilde: msg2.pk_tilde,
            pk_tilde_star: msg2.pk_tilde_star,
            ski_tilde: msg2.ski_tilde,
            skip2_tilde: msg2.skip2_tilde,
        },
    )
}

/// Create msg3 in the DeriveSKSharesDKG protocol, to be executed by parties p3
pub fn get_private_key_shares_dkg_create_msg3_p3(
    state2: &YaoToScalarRssKeypairState2,
) -> (YaoToScalarRssKeypairMsg3p12, YaoToScalarRssKeypairState3p3) {
    // Step 8a
    let pki_tilde = ProjectivePoint::GENERATOR * state2.sk2_tilde;
    let pkip2_tilde = ProjectivePoint::GENERATOR * state2.sk0_tilde;

    (
        YaoToScalarRssKeypairMsg3p12 {
            pki_tilde,
            pkip2_tilde,
        },
        YaoToScalarRssKeypairState3p3 {
            pki_tilde,
            pkip2_tilde,
        },
    )
}

/// Process msg3 in the DeriveSKSharesDKG protocol, to be executed by parties p1 and p2
pub fn get_private_key_shares_dkg_process_msg3_p12(
    msg3_recv_pim1: &YaoToScalarRssKeypairMsg3p12,
    msg3_recv_pip2: &YaoToScalarRssKeypairMsg3p12,
    state3: &YaoToScalarRssKeypairState3p12,
) {
    // Step 8c
    assert_eq!(state3.pki_tilde, msg3_recv_pim1.pkip2_tilde);
    assert_eq!(state3.pkip2_tilde, msg3_recv_pip2.pki_tilde);
    assert_eq!(msg3_recv_pip2.pkip2_tilde, msg3_recv_pim1.pki_tilde);
    assert_eq!(
        state3.pki_tilde + state3.pkip2_tilde + msg3_recv_pim1.pki_tilde,
        state3.pk_tilde
    );
}

/// Process msg3 in the DeriveSKSharesDKG protocol, to be executed by parties p3
pub fn get_private_key_shares_dkg_process_msg3_p3(
    msg3_recv_pim1: &YaoToScalarRssKeypairMsg3p3,
    msg3_recv_pip2: &YaoToScalarRssKeypairMsg3p3,
    state2: &YaoToScalarRssKeypairState2,
    state3: &YaoToScalarRssKeypairState3p3,
) -> Scalar {
    // Step 8c
    assert_eq!(msg3_recv_pim1.alpha, msg3_recv_pip2.alpha);
    assert_eq!(state3.pki_tilde, msg3_recv_pim1.pkip2_tilde);
    assert_eq!(state3.pkip2_tilde, msg3_recv_pip2.pki_tilde);
    assert_eq!(msg3_recv_pip2.pkip2_tilde, msg3_recv_pim1.pki_tilde);
    assert_eq!(
        state3.pki_tilde + state3.pkip2_tilde + msg3_recv_pim1.pki_tilde,
        state2.pk_tilde
    );
    msg3_recv_pip2.alpha
}

/// Create msg4 in the DeriveSKSharesDKG protocol, to be executed by parties p1 and p2
pub fn get_private_key_shares_dkg_create_msg4_p12(
    state3: &YaoToScalarRssKeypairState3p12,
    state1: &YaoToScalarRssKeypairState1,
) -> ProjectivePoint {
    // Step 9a
    let pk = (state3.pk_tilde - (ProjectivePoint::GENERATOR * state1.beta))
        * state1.alpha.invert().unwrap();
    // Step 9b
    let pk_star = (state3.pk_tilde_star - (ProjectivePoint::GENERATOR * state1.beta_star))
        * state1.alpha_star.invert().unwrap();

    // Step 9b
    assert_eq!(pk, pk_star);
    pk
}

/// Process msg4 in the DeriveSKSharesDKG protocol, to be executed by parties p3
pub fn get_private_key_shares_dkg_process_msg4_p3(
    msg4_p1: &ProjectivePoint,
    msg4_p2: &ProjectivePoint,
) -> ProjectivePoint {
    // Step 10
    assert_eq!(msg4_p1, msg4_p2);
    *msg4_p1
}

/// Get output of the DeriveSKSharesDKG protocol to be executed by party p1
pub fn get_private_key_shares_dkg_genout_p1(
    pk: &ProjectivePoint,
    state1: &YaoToScalarRssKeypairState1,
    state3: &YaoToScalarRssKeypairState3p12,
) -> PrivKeyShareDkg<ProjectivePoint> {
    // Step 9a
    let ski = state3.ski_tilde * state1.alpha.invert().unwrap() - state1.delta_0;
    let skip2 = state3.skip2_tilde * state1.alpha.invert().unwrap() - state1.delta_1;

    // Step 9b
    PrivKeyShareDkg::<ProjectivePoint> {
        keyshare: PrivKeyShare::<ProjectivePoint> {
            prev_share: ski,
            next_share: skip2,
        },
        pubkey: *pk,
    }
}

/// Get output of the DeriveSKSharesDKG protocol to be executed by party p3
pub fn get_private_key_shares_dkg_genout_p2(
    pk: &ProjectivePoint,
    state1: &YaoToScalarRssKeypairState1,
    state3: &YaoToScalarRssKeypairState3p12,
) -> PrivKeyShareDkg<ProjectivePoint> {
    // Step 9a
    let ski = state3.ski_tilde * state1.alpha.invert().unwrap() - state1.delta_1;
    let skip2 = state3.skip2_tilde * state1.alpha.invert().unwrap() - state1.delta_2;

    // Step 9b
    PrivKeyShareDkg::<ProjectivePoint> {
        keyshare: PrivKeyShare::<ProjectivePoint> {
            prev_share: ski,
            next_share: skip2,
        },
        pubkey: *pk,
    }
}

/// Get output of the DeriveSKSharesDKG protocol to be executed by party p3
pub fn get_private_key_shares_dkg_genout_p3(
    pk: &ProjectivePoint,
    alpha: &Scalar,
    state2: &YaoToScalarRssKeypairState2,
) -> PrivKeyShareDkg<ProjectivePoint> {
    // Step 9a
    let ski = state2.sk2_tilde * alpha.invert().unwrap() - state2.delta_2;
    let skip2 = state2.sk0_tilde * alpha.invert().unwrap() - state2.delta_0;

    // Step 9b
    PrivKeyShareDkg::<ProjectivePoint> {
        keyshare: PrivKeyShare::<ProjectivePoint> {
            prev_share: ski,
            next_share: skip2,
        },
        pubkey: *pk,
    }
}

pub async fn run_yao_to_scalar_rss_keypair<S, G, R>(
    setup: &S,
    relay: &mut R,
    tag_offset_counter: &mut TagOffsetCounter,
    share: &[YaoShare],
    rng: Option<&mut G>,
) -> Result<PrivKeyShareDkg<k256::ProjectivePoint>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let mut relay = FilteredMsgRelay::new(relay);

    let tag1 = MessageTag::tag1(YAO_TO_RSS_MSG1, tag_offset_counter.next_value());
    let tag2 = MessageTag::tag1(YAO_TO_RSS_MSG2, tag_offset_counter.next_value());
    let tag3 = MessageTag::tag1(YAO_TO_RSS_MSG3, tag_offset_counter.next_value());
    let tag4 = MessageTag::tag1(YAO_TO_RSS_MSG4, tag_offset_counter.next_value());

    relay.ask_messages(setup, tag1, true).await?;
    relay.ask_messages(setup, tag2, true).await?;
    relay.ask_messages(setup, tag3, true).await?;
    relay.ask_messages(setup, tag4, true).await?;

    let output =
        run_yao_to_scalar_rss_keypair_inner(setup, &mut relay, share, rng, tag1, tag2, tag3, tag4)
            .await?;

    Ok(output)
}

/// Converts a given scalar represented as yao shares to Scalar RSS shares
/// and returns it along with the correspoding public key along
#[allow(clippy::too_many_arguments)]
async fn run_yao_to_scalar_rss_keypair_inner<S, G, R>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &[YaoShare],
    rng: Option<&mut G>,
    tag1: MessageTag,
    tag2: MessageTag,
    tag3: MessageTag,
    tag4: MessageTag,
) -> Result<PrivKeyShareDkg<k256::ProjectivePoint>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
{
    let party_id = setup.participant_index();

    if party_id == 2 {
        let msg1: Vec<YaoToScalarRssKeypairMsg1> =
            receive_from_parties(setup, tag1, &[0, 1], relay).await?;

        let msg1_p3_from_p1 = &msg1[0];
        let msg1_p3_from_p2 = &msg1[1];

        let eins: Vec<YaoEvaluatorShare> = share
            .iter()
            .map(|ins| ins.as_evaluator())
            .cloned()
            .collect();

        let (msg2_0, msg2_1, state2) =
            get_private_key_shares_dkg_create_msg2_p3(&eins, msg1_p3_from_p1, msg1_p3_from_p2);

        send_to_party(setup, tag2, msg2_0, 0, relay).await?;
        send_to_party(setup, tag2, msg2_1, 1, relay).await?;

        let (msg3, state3) = get_private_key_shares_dkg_create_msg3_p3(&state2);

        send_to_party(setup, tag3, msg3.clone(), 0, relay).await?;
        send_to_party(setup, tag3, msg3, 1, relay).await?;

        let msg3s: Vec<YaoToScalarRssKeypairMsg3p3> =
            receive_from_parties(setup, tag3, &[0, 1], relay).await?;

        let msg3_0 = &msg3s[0];
        let msg3_1 = &msg3s[1];

        let alpha_p3 = get_private_key_shares_dkg_process_msg3_p3(msg3_1, msg3_0, &state2, &state3);

        let pks: Vec<[u8; 33]> = receive_from_parties(setup, tag4, &[0, 1], relay).await?;

        let encoded = EncodedPoint::from_bytes(pks[0]).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pk_p1 = ProjectivePoint::from(affine);

        let encoded = EncodedPoint::from_bytes(pks[1]).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded).unwrap();
        let pk_p2 = ProjectivePoint::from(affine);

        let pk = get_private_key_shares_dkg_process_msg4_p3(&pk_p1, &pk_p2);

        Ok(get_private_key_shares_dkg_genout_p3(
            &pk, &alpha_p3, &state2,
        ))
    } else {
        let r = rng.unwrap();
        let gins: Vec<YaoGarblerShare> =
            share.iter().map(|ins| ins.as_garbler()).cloned().collect();
        let (msg1, state1) = get_private_key_shares_dkg_create_msg1_p12(&gins, r);

        send_to_party(setup, tag1, msg1, 2, relay).await?;

        let msg2s: Vec<YaoToScalarRssKeypairMsg2> =
            receive_from_parties(setup, tag2, &[2], relay).await?;

        let msg2 = &msg2s[0];

        let (msg3_01, msg3_2, state3) = get_private_key_shares_dkg_create_msg3_p12(&state1, msg2);

        send_to_party(setup, tag3, msg3_01, 1 - party_id, relay).await?;
        send_to_party(setup, tag3, msg3_2, 2, relay).await?;

        let msg3s: Vec<YaoToScalarRssKeypairMsg3p12> =
            receive_from_parties(setup, tag3, &[1 - party_id, 2], relay).await?;

        let msg3_01 = msg3s[0].clone();
        let msg3_2 = msg3s[1].clone();

        if party_id == 0 {
            get_private_key_shares_dkg_process_msg3_p12(&msg3_2, &msg3_01, &state3);
        } else {
            get_private_key_shares_dkg_process_msg3_p12(&msg3_01, &msg3_2, &state3);
        }

        let pk = get_private_key_shares_dkg_create_msg4_p12(&state3, &state1);
        send_to_party(
            setup,
            tag4,
            pk.to_encoded_point(true).as_bytes().to_vec(),
            2,
            relay,
        )
        .await?;

        if party_id == 0 {
            Ok(get_private_key_shares_dkg_genout_p1(&pk, &state1, &state3))
        } else {
            Ok(get_private_key_shares_dkg_genout_p2(&pk, &state1, &state3))
        }
    }
}

#[cfg(test)]
mod tests {
    use garbled_circuit::{
        functionality::{
            input::batch_input_yao_functionality, setup::setup_yao_functionality,
            utils_dep::TagOffsetCounter,
        },
        utilities::{commitments::HashCommitment, hash_function::AesHash, types::YaoSetup},
    };
    use k256::{ProjectivePoint, Scalar};
    use rand::{Rng, SeedableRng, rngs};
    use rand_chacha::ChaCha8Rng;
    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::{
        types::{HardDerivationError, PrivKeyShareDkg, ProtocolParticipant},
        utils::run_init,
        yao_to_rss::run_yao_to_scalar_rss_keypair,
    };

    async fn test_run_yao_to_scalar_rss_keypair<S, R>(
        setup: S,
        input: Vec<bool>,
        relay: R,
    ) -> Result<(usize, PrivKeyShareDkg<ProjectivePoint>), HardDerivationError>
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = relay;

        let mut tag_offset_counter = TagOffsetCounter::new();

        let yao_setup =
            setup_yao_functionality(&setup, &mut tag_offset_counter, &mut relay).await?;

        let (mut rng, _, _) = match &yao_setup {
            YaoSetup::E(e) => {
                let hash = AesHash::new(e.comm_crs);
                let comm = HashCommitment::new(hash.clone());
                (None, hash, comm)
            }
            YaoSetup::G(g) => {
                let hash = AesHash::new(g.comm_crs);
                let comm = HashCommitment::new(hash);
                let r = ChaCha8Rng::from_seed(g.prf_key);
                (Some(r), hash, comm)
            }
        };

        let in_yao = batch_input_yao_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
            &input,
            rng.as_mut(),
            &yao_setup,
        )
        .await?;

        let out = run_yao_to_scalar_rss_keypair(
            &setup,
            &mut relay,
            &mut tag_offset_counter,
            &in_yao,
            rng.as_mut(),
        )
        .await?;

        Ok((setup.participant_index(), out))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_yao_to_scalar_rss_keypair() {
        let mut rng = rngs::StdRng::from_entropy();
        let mut i1 = vec![false; 256];
        (0..i1.len()).for_each(|i| {
            i1[i] = rng.gen_bool(0.5);
        });

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_yao_to_scalar_rss_keypair(setup, i1.clone(), relay));
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

        let out = shares[0].1.keyshare.next_share
            + shares[1].1.keyshare.next_share
            + shares[2].1.keyshare.next_share;

        let mut sum = Scalar::ZERO;
        let two = Scalar::ONE + Scalar::ONE;
        let mut twopow = Scalar::ONE;
        for i in i1 {
            if i {
                sum += twopow;
            }
            twopow *= two;
        }

        assert_eq!(sum, out);
        assert_eq!(ProjectivePoint::GENERATOR * sum, shares[0].1.pubkey);
    }
}
