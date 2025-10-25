// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::edwards::CompressedEdwardsY;
use group::{Group, ff::Field};
use k256::{
    FieldBytes,
    elliptic_curve::{
        PrimeField, group::GroupEncoding, sec1::ToEncodedPoint,
    },
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use sl_messages::{message::MessageTag, relay::Relay};

use garbled_circuit::{
    functionality::{
        utils::{
            FilteredMsgRelay, FixedExternalSize, Wrap, receive_from_parties,
            send_to_party,
        },
        utils_dep::TagOffsetCounter,
    },
    utilities::types::{YaoEvaluatorShare, YaoGarblerShare, YaoShare},
};

use crate::{
    arith_gadget::{evaluate_gadget, garble_gadget},
    constants::{
        YAO_TO_RSS_MSG1, YAO_TO_RSS_MSG2, YAO_TO_RSS_MSG3, YAO_TO_RSS_MSG4,
    },
    types::{
        HardDerivationError, PrivKeyShare, PrivKeyShareDkg,
        ProtocolParticipant, ScalarFromBytes, ScalarVal,
    },
};

/// Msg1 for Yao to Scalar RSS key pair protocol
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg1<G>
where
    G: GroupEncoding + Group,
{
    cvec: Vec<G::Scalar>,
    cvec_star: Vec<G::Scalar>,
    delta_2: G::Scalar,
    delta_0: G::Scalar,
}

fn decode_secp_projective_point(
    bytes: &[u8],
) -> Option<k256::ProjectivePoint> {
    let mut repr = <k256::ProjectivePoint as GroupEncoding>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);

    k256::ProjectivePoint::from_bytes(&repr).into()
}

fn decode_25519_edwards_point(
    bytes: &[u8],
) -> Option<curve25519_dalek::EdwardsPoint> {
    CompressedEdwardsY(bytes.try_into().expect("Conversion Failed"))
        .decompress()
}

impl Wrap for YaoToScalarRssKeypairMsg1<k256::ProjectivePoint> {
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
        let cveclen = Some(buffer.len())
            .filter(|&len| len > 64 && len % 64 == 0)
            .map(|len| len / 32)
            .filter(|&len| len > 4)
            .map(|len| (len - 2) / 2)?;

        fn svec(
            b: &[u8],
            count: usize,
        ) -> Option<(&[u8], Vec<k256::Scalar>)> {
            let (b, rest) = b.split_at_checked(count * 32)?;

            let v = b
                .chunks_exact(32)
                .map(FieldBytes::from_slice)
                .map(|&b| k256::Scalar::from_repr(b).into_option())
                .collect::<Option<Vec<_>>>()?;

            Some((rest, v))
        }

        let (buffer, cvec) = svec(buffer, cveclen)?;
        let (buffer, cvec_star) = svec(buffer, cveclen)?;

        let delta_2 =
            ScalarVal::<k256::ProjectivePoint>::read(&buffer[..32])?.0;
        let delta_0 =
            ScalarVal::<k256::ProjectivePoint>::read(&buffer[32..])?.0;

        Some(YaoToScalarRssKeypairMsg1 {
            cvec,
            cvec_star,
            delta_2,
            delta_0,
        })
    }
}

impl Wrap for YaoToScalarRssKeypairMsg1<curve25519_dalek::EdwardsPoint> {
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
        let cveclen = Some(buffer.len())
            .filter(|&len| len > 64 && len % 64 == 0)
            .map(|len| len / 32)
            .filter(|&len| len > 4)
            .map(|len| (len - 2) / 2)?;

        fn svec(
            b: &[u8],
            count: usize,
        ) -> Option<(&[u8], Vec<curve25519_dalek::Scalar>)> {
            let (b, rest) = b.split_at_checked(count * 32)?;

            let v = b
                .chunks_exact(32)
                .map(FieldBytes::from_slice)
                .map(|&b| {
                    curve25519_dalek::Scalar::from_bytes_mod_order(b.into())
                })
                .collect::<Vec<_>>();

            Some((rest, v))
        }

        let (buffer, cvec) = svec(buffer, cveclen)?;
        let (buffer, cvec_star) = svec(buffer, cveclen)?;

        let delta_2 =
            ScalarVal::<curve25519_dalek::EdwardsPoint>::read(&buffer[..32])?
                .0;
        let delta_0 =
            ScalarVal::<curve25519_dalek::EdwardsPoint>::read(&buffer[32..])?
                .0;

        Some(YaoToScalarRssKeypairMsg1 {
            cvec,
            cvec_star,
            delta_2,
            delta_0,
        })
    }
}

impl FixedExternalSize for YaoToScalarRssKeypairMsg1<k256::ProjectivePoint> {
    const SIZE: usize = 16448;
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg1<curve25519_dalek::EdwardsPoint>
{
    const SIZE: usize = 16448;
}

/// State1 for Yao to Scalar RSS key pair protocol
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairState1<G: Group + GroupEncoding> {
    cvec: Vec<G::Scalar>,
    cvec_star: Vec<G::Scalar>,
    alpha: G::Scalar,
    alpha_star: G::Scalar,
    beta: G::Scalar,
    beta_star: G::Scalar,
    delta_0: G::Scalar,
    delta_1: G::Scalar,
    delta_2: G::Scalar,
}

/// Msg2 for Yao to Scalar RSS key pair protocol
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg2<G: Group + GroupEncoding> {
    pk_tilde: G,
    pk_tilde_star: G,
    ski_tilde: G::Scalar,
    skip2_tilde: G::Scalar,
}

impl FixedExternalSize for YaoToScalarRssKeypairMsg2<k256::ProjectivePoint> {
    const SIZE: usize = 32 * 2 + 33 * 2;
}

impl Wrap for YaoToScalarRssKeypairMsg2<k256::ProjectivePoint> {
    fn external_size(&self) -> usize {
        Self::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33]
            .copy_from_slice(self.pk_tilde.to_encoded_point(true).as_bytes());
        buffer[33..66].copy_from_slice(
            self.pk_tilde_star.to_encoded_point(true).as_bytes(),
        );
        buffer[66..98].copy_from_slice(&self.ski_tilde.to_bytes());
        buffer[98..130].copy_from_slice(&self.skip2_tilde.to_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pk_tilde = decode_secp_projective_point(&buffer[0..33])?;
        let pk_tilde_star = decode_secp_projective_point(&buffer[33..66])?;

        let ski_tilde =
            ScalarVal::<k256::ProjectivePoint>::read(&buffer[66..98])?.0;
        let skip2_tilde =
            ScalarVal::<k256::ProjectivePoint>::read(&buffer[98..130])?.0;

        Some(Self {
            pk_tilde,
            pk_tilde_star,
            ski_tilde,
            skip2_tilde,
        })
    }
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg2<curve25519_dalek::EdwardsPoint>
{
    const SIZE: usize = 32 * 2 + 32 * 2;
}

impl Wrap for YaoToScalarRssKeypairMsg2<curve25519_dalek::EdwardsPoint> {
    fn external_size(&self) -> usize {
        Self::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..32].copy_from_slice(&self.pk_tilde.compress().0);
        buffer[32..64].copy_from_slice(&self.pk_tilde_star.compress().0);
        buffer[64..96].copy_from_slice(&self.ski_tilde.to_bytes());
        buffer[96..128].copy_from_slice(&self.skip2_tilde.to_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pk_tilde = decode_25519_edwards_point(&buffer[0..32])?;
        let pk_tilde_star = decode_25519_edwards_point(&buffer[32..64])?;

        let ski_tilde = ScalarVal::<curve25519_dalek::EdwardsPoint>::read(
            &buffer[64..96],
        )?
        .0;
        let skip2_tilde = ScalarVal::<curve25519_dalek::EdwardsPoint>::read(
            &buffer[96..128],
        )?
        .0;

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
pub struct YaoToScalarRssKeypairState2<G: Group + GroupEncoding> {
    pk_tilde: G,
    sk0_tilde: G::Scalar,
    sk2_tilde: G::Scalar,
    delta_0: G::Scalar,
    delta_2: G::Scalar,
}

/// Msg3 for Yao to Scalar RSS key pair protocol for evaluator
#[derive(Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg3p3<G: Group + GroupEncoding> {
    pki_tilde: G,
    pkip2_tilde: G,
    alpha: G::Scalar,
}

impl Wrap for YaoToScalarRssKeypairMsg3p3<k256::ProjectivePoint> {
    fn external_size(&self) -> usize {
        32 + 33 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33].copy_from_slice(
            self.pki_tilde.to_encoded_point(true).as_bytes(),
        );
        buffer[33..66].copy_from_slice(
            self.pkip2_tilde.to_encoded_point(true).as_bytes(),
        );
        buffer[66..98].copy_from_slice(&self.alpha.to_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pki_tilde = decode_secp_projective_point(&buffer[0..33])?;

        let pkip2_tilde = decode_secp_projective_point(&buffer[33..66])?;

        let alpha =
            ScalarVal::<k256::ProjectivePoint>::read(&buffer[66..98])?.0;

        Some(Self {
            pki_tilde,
            pkip2_tilde,
            alpha,
        })
    }
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg3p3<k256::ProjectivePoint>
{
    const SIZE: usize = 98;
}

impl Wrap for YaoToScalarRssKeypairMsg3p3<curve25519_dalek::EdwardsPoint> {
    fn external_size(&self) -> usize {
        32 + 32 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..32].copy_from_slice(&self.pki_tilde.compress().0);
        buffer[32..64].copy_from_slice(&self.pkip2_tilde.compress().0);
        buffer[64..96].copy_from_slice(&self.alpha.to_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pki_tilde = decode_25519_edwards_point(&buffer[0..33])?;

        let pkip2_tilde = decode_25519_edwards_point(&buffer[33..66])?;

        let alpha = ScalarVal::<curve25519_dalek::EdwardsPoint>::read(
            &buffer[66..98],
        )?
        .0;

        Some(Self {
            pki_tilde,
            pkip2_tilde,
            alpha,
        })
    }
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg3p3<curve25519_dalek::EdwardsPoint>
{
    const SIZE: usize = 96;
}

/// Msg3 for Yao to Scalar RSS key pair protocol for garblers
#[derive(Clone, Debug, PartialEq)]
pub struct YaoToScalarRssKeypairMsg3p12<G: Group + GroupEncoding> {
    pki_tilde: G,
    pkip2_tilde: G,
}

impl Wrap for YaoToScalarRssKeypairMsg3p12<k256::ProjectivePoint> {
    fn external_size(&self) -> usize {
        33 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33].copy_from_slice(
            self.pki_tilde.to_encoded_point(true).as_bytes(),
        );
        buffer[33..66].copy_from_slice(
            self.pkip2_tilde.to_encoded_point(true).as_bytes(),
        );
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pki_tilde = decode_secp_projective_point(&buffer[..33])?;

        let pkip2_tilde = decode_secp_projective_point(&buffer[33..66])?;

        Some(Self {
            pki_tilde,
            pkip2_tilde,
        })
    }
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg3p12<k256::ProjectivePoint>
{
    const SIZE: usize = 66;
}

impl Wrap for YaoToScalarRssKeypairMsg3p12<curve25519_dalek::EdwardsPoint> {
    fn external_size(&self) -> usize {
        33 * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33].copy_from_slice(&self.pki_tilde.compress().0);
        buffer[33..66].copy_from_slice(&self.pkip2_tilde.compress().0);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pki_tilde = decode_25519_edwards_point(&buffer[..33])?;

        let pkip2_tilde = decode_25519_edwards_point(&buffer[33..66])?;

        Some(Self {
            pki_tilde,
            pkip2_tilde,
        })
    }
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg3p12<curve25519_dalek::EdwardsPoint>
{
    const SIZE: usize = 64;
}

/// State3 for Yao to Scalar RSS key pair protocol for garblers
#[derive(Clone, Debug, PartialEq)]
pub struct YaoToScalarRssKeypairState3p12<G: Group + GroupEncoding> {
    pki_tilde: G,
    pkip2_tilde: G,
    pk_tilde: G,
    pk_tilde_star: G,
    ski_tilde: G::Scalar,
    skip2_tilde: G::Scalar,
}

/// State3 for Yao to Scalar RSS key pair protocol for evaluator
pub struct YaoToScalarRssKeypairState3p3<G: Group + GroupEncoding> {
    pki_tilde: G,
    pkip2_tilde: G,
}

/// Message4 for Yao to Scalar RSS key pair protocol
pub struct YaoToScalarRssKeypairMsg4<G: Group + GroupEncoding> {
    pk: G,
}

impl Wrap for YaoToScalarRssKeypairMsg4<k256::ProjectivePoint> {
    fn external_size(&self) -> usize {
        33
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..33]
            .copy_from_slice(self.pk.to_encoded_point(true).as_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pk = decode_secp_projective_point(&buffer[..33])?;
        Some(Self { pk })
    }
}

impl FixedExternalSize for YaoToScalarRssKeypairMsg4<k256::ProjectivePoint> {
    const SIZE: usize = 33;
}

impl Wrap for YaoToScalarRssKeypairMsg4<curve25519_dalek::EdwardsPoint> {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0..32].copy_from_slice(&self.pk.compress().0);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let pk = decode_25519_edwards_point(&buffer[..32])?;
        Some(Self { pk })
    }
}

impl FixedExternalSize
    for YaoToScalarRssKeypairMsg4<curve25519_dalek::EdwardsPoint>
{
    const SIZE: usize = 32;
}

/// Create msg1 in the DeriveSKSharesDKG protocol, to be executed by parties p1 and p2
pub fn get_private_key_shares_dkg_create_msg1_p12<G, T>(
    sha_hashed_vals: &[YaoGarblerShare],
    rng: &mut G,
) -> (YaoToScalarRssKeypairMsg1<T>, YaoToScalarRssKeypairState1<T>)
where
    G: RngCore + CryptoRng,
    T: Group + GroupEncoding,
    T::Scalar: ScalarFromBytes,
{
    // Step 2b
    let garble_res = garble_gadget::<T, _>(sha_hashed_vals, rng);
    let cvec = garble_res.0;
    let de = garble_res.1;
    let alpha = de.0;
    let beta = de.1;

    // Step 2c
    let garble_res_star = garble_gadget::<T, _>(sha_hashed_vals, rng);
    let cvec_star = garble_res_star.0;
    let de_star = garble_res_star.1;
    let alpha_star = de_star.0;
    let beta_star = de_star.1;

    // Step 2d
    let delta = beta * alpha.invert().unwrap();

    // Step 2e
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let delta_0 = T::Scalar::from_bytes(bytes);

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let delta_1 = T::Scalar::from_bytes(bytes);

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
pub fn get_private_key_shares_dkg_create_msg2_p3<G: Group + GroupEncoding>(
    sha_hashed_vals: &[YaoEvaluatorShare],
    msg1_from_p1: &YaoToScalarRssKeypairMsg1<G>,
    msg1_from_p2: &YaoToScalarRssKeypairMsg1<G>,
) -> (
    YaoToScalarRssKeypairMsg2<G>,
    YaoToScalarRssKeypairMsg2<G>,
    YaoToScalarRssKeypairState2<G>,
)
where
    G::Scalar: ScalarFromBytes,
{
    // Step 5a
    assert_eq!(msg1_from_p1, msg1_from_p2);

    // Step 5c
    let sk_tilde = evaluate_gadget::<G>(&msg1_from_p1.cvec, sha_hashed_vals);
    // Step 5e
    let pk_tilde = G::generator() * sk_tilde;

    // Step 5d
    let sk_tilde_star =
        evaluate_gadget::<G>(&msg1_from_p1.cvec_star, sha_hashed_vals);
    // Step 5f
    let pk_tilde_star = G::generator() * sk_tilde_star;

    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut rng = ChaCha8Rng::from_seed(seed);

    // Step 5g
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk0_tilde = G::Scalar::from_bytes(bytes);

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk1_tilde = G::Scalar::from_bytes(bytes);

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
pub fn get_private_key_shares_dkg_create_msg3_p12<
    G: Group + GroupEncoding,
>(
    state1: &YaoToScalarRssKeypairState1<G>,
    msg2: &YaoToScalarRssKeypairMsg2<G>,
) -> (
    YaoToScalarRssKeypairMsg3p12<G>,
    YaoToScalarRssKeypairMsg3p3<G>,
    YaoToScalarRssKeypairState3p12<G>,
) {
    // Step 8a
    let pki_tilde = G::generator() * msg2.ski_tilde;
    let pkip2_tilde = G::generator() * msg2.skip2_tilde;

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
pub fn get_private_key_shares_dkg_create_msg3_p3<G: Group + GroupEncoding>(
    state2: &YaoToScalarRssKeypairState2<G>,
) -> (
    YaoToScalarRssKeypairMsg3p12<G>,
    YaoToScalarRssKeypairState3p3<G>,
) {
    // Step 8a
    let pki_tilde = G::generator() * state2.sk2_tilde;
    let pkip2_tilde = G::generator() * state2.sk0_tilde;

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
pub fn get_private_key_shares_dkg_process_msg3_p12<
    G: Group + GroupEncoding,
>(
    msg3_recv_pim1: &YaoToScalarRssKeypairMsg3p12<G>,
    msg3_recv_pip2: &YaoToScalarRssKeypairMsg3p12<G>,
    state3: &YaoToScalarRssKeypairState3p12<G>,
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
pub fn get_private_key_shares_dkg_process_msg3_p3<
    G: Group + GroupEncoding,
>(
    msg3_recv_pim1: &YaoToScalarRssKeypairMsg3p3<G>,
    msg3_recv_pip2: &YaoToScalarRssKeypairMsg3p3<G>,
    state2: &YaoToScalarRssKeypairState2<G>,
    state3: &YaoToScalarRssKeypairState3p3<G>,
) -> G::Scalar {
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
pub fn get_private_key_shares_dkg_create_msg4_p12<
    G: Group + GroupEncoding,
>(
    state3: &YaoToScalarRssKeypairState3p12<G>,
    state1: &YaoToScalarRssKeypairState1<G>,
) -> G {
    // Step 9a
    let pk = (state3.pk_tilde - (G::generator() * state1.beta))
        * state1.alpha.invert().unwrap();
    // Step 9b
    let pk_star = (state3.pk_tilde_star
        - (G::generator() * state1.beta_star))
        * state1.alpha_star.invert().unwrap();

    // Step 9b
    assert_eq!(pk, pk_star);
    pk
}

/// Process msg4 in the DeriveSKSharesDKG protocol, to be executed by parties p3
pub fn get_private_key_shares_dkg_process_msg4_p3<
    G: Group + GroupEncoding,
>(
    msg4_p1: &G,
    msg4_p2: &G,
) -> G {
    // Step 10
    assert_eq!(msg4_p1, msg4_p2);
    *msg4_p1
}

/// Get output of the DeriveSKSharesDKG protocol to be executed by party p1
pub fn get_private_key_shares_dkg_genout_p1<G: Group + GroupEncoding>(
    pk: &G,
    state1: &YaoToScalarRssKeypairState1<G>,
    state3: &YaoToScalarRssKeypairState3p12<G>,
) -> PrivKeyShareDkg<G> {
    // Step 9a
    let ski =
        state3.ski_tilde * state1.alpha.invert().unwrap() - state1.delta_0;
    let skip2 =
        state3.skip2_tilde * state1.alpha.invert().unwrap() - state1.delta_1;

    // Step 9b
    PrivKeyShareDkg::<G> {
        keyshare: PrivKeyShare::<G> {
            prev_share: ski,
            next_share: skip2,
        },
        pubkey: *pk,
    }
}

/// Get output of the DeriveSKSharesDKG protocol to be executed by party p3
pub fn get_private_key_shares_dkg_genout_p2<G: Group + GroupEncoding>(
    pk: &G,
    state1: &YaoToScalarRssKeypairState1<G>,
    state3: &YaoToScalarRssKeypairState3p12<G>,
) -> PrivKeyShareDkg<G> {
    // Step 9a
    let ski =
        state3.ski_tilde * state1.alpha.invert().unwrap() - state1.delta_1;
    let skip2 =
        state3.skip2_tilde * state1.alpha.invert().unwrap() - state1.delta_2;

    // Step 9b
    PrivKeyShareDkg::<G> {
        keyshare: PrivKeyShare::<G> {
            prev_share: ski,
            next_share: skip2,
        },
        pubkey: *pk,
    }
}

/// Get output of the DeriveSKSharesDKG protocol to be executed by party p3
pub fn get_private_key_shares_dkg_genout_p3<G: Group + GroupEncoding>(
    pk: &G,
    alpha: &G::Scalar,
    state2: &YaoToScalarRssKeypairState2<G>,
) -> PrivKeyShareDkg<G> {
    // Step 9a
    let ski = state2.sk2_tilde * alpha.invert().unwrap() - state2.delta_2;
    let skip2 = state2.sk0_tilde * alpha.invert().unwrap() - state2.delta_0;

    // Step 9b
    PrivKeyShareDkg::<G> {
        keyshare: PrivKeyShare::<G> {
            prev_share: ski,
            next_share: skip2,
        },
        pubkey: *pk,
    }
}

pub async fn run_yao_to_scalar_rss_keypair<S, G, R, T>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    tag_offset_counter: &mut TagOffsetCounter,
    share: &[YaoShare],
    rng: Option<&mut G>,
) -> Result<PrivKeyShareDkg<T>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    T: Group + GroupEncoding,
    T::Scalar: ScalarFromBytes,
    YaoToScalarRssKeypairMsg1<T>: Wrap,
    YaoToScalarRssKeypairMsg2<T>: Wrap,
    YaoToScalarRssKeypairMsg3p12<T>: Wrap,
    YaoToScalarRssKeypairMsg3p3<T>: Wrap,
    YaoToScalarRssKeypairMsg4<T>: Wrap,
{
    let tag1 =
        MessageTag::tag1(YAO_TO_RSS_MSG1, tag_offset_counter.next_value());
    let tag2 =
        MessageTag::tag1(YAO_TO_RSS_MSG2, tag_offset_counter.next_value());
    let tag3 =
        MessageTag::tag1(YAO_TO_RSS_MSG3, tag_offset_counter.next_value());
    let tag4 =
        MessageTag::tag1(YAO_TO_RSS_MSG4, tag_offset_counter.next_value());

    relay.ask_messages(setup, tag1, true).await?;
    relay.ask_messages(setup, tag2, true).await?;
    relay.ask_messages(setup, tag3, true).await?;
    relay.ask_messages(setup, tag4, true).await?;

    let output = run_yao_to_scalar_rss_keypair_inner(
        setup, relay, share, rng, tag1, tag2, tag3, tag4,
    )
    .await?;

    Ok(output)
}

/// Converts a given scalar represented as yao shares to Scalar RSS shares
/// and returns it along with the correspoding public key along
#[allow(clippy::too_many_arguments)]
async fn run_yao_to_scalar_rss_keypair_inner<S, G, R, T>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &[YaoShare],
    rng: Option<&mut G>,
    tag1: MessageTag,
    tag2: MessageTag,
    tag3: MessageTag,
    tag4: MessageTag,
) -> Result<PrivKeyShareDkg<T>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    T: Group + GroupEncoding,
    T::Scalar: ScalarFromBytes,
    YaoToScalarRssKeypairMsg1<T>: Wrap,
    YaoToScalarRssKeypairMsg2<T>: Wrap,
    YaoToScalarRssKeypairMsg3p12<T>: Wrap,
    YaoToScalarRssKeypairMsg3p3<T>: Wrap,
    YaoToScalarRssKeypairMsg4<T>: Wrap,
{
    let party_id = setup.participant_index();

    if party_id == 2 {
        let msg1: Vec<YaoToScalarRssKeypairMsg1<T>> =
            receive_from_parties(setup, tag1, &[0, 1], relay).await?;

        let msg1_p3_from_p1 = &msg1[0];
        let msg1_p3_from_p2 = &msg1[1];

        let eins: Vec<YaoEvaluatorShare> = share
            .iter()
            .map(|ins| ins.as_evaluator())
            .cloned()
            .collect();

        let (msg2_0, msg2_1, state2) =
            get_private_key_shares_dkg_create_msg2_p3(
                &eins,
                msg1_p3_from_p1,
                msg1_p3_from_p2,
            );

        send_to_party(setup, tag2, msg2_0, 0, relay).await?;
        send_to_party(setup, tag2, msg2_1, 1, relay).await?;

        let (msg3, state3) =
            get_private_key_shares_dkg_create_msg3_p3(&state2);

        send_to_party(setup, tag3, msg3.clone(), 0, relay).await?;
        send_to_party(setup, tag3, msg3, 1, relay).await?;

        let msg3s: Vec<YaoToScalarRssKeypairMsg3p3<T>> =
            receive_from_parties(setup, tag3, &[0, 1], relay).await?;

        let msg3_0 = &msg3s[0];
        let msg3_1 = &msg3s[1];

        let alpha_p3 = get_private_key_shares_dkg_process_msg3_p3(
            msg3_1, msg3_0, &state2, &state3,
        );

        let pks: Vec<YaoToScalarRssKeypairMsg4<T>> =
            receive_from_parties(setup, tag4, &[0, 1], relay).await?;

        let pk_p1 = pks[0].pk;
        let pk_p2 = pks[1].pk;

        let pk = get_private_key_shares_dkg_process_msg4_p3(&pk_p1, &pk_p2);

        let out =
            get_private_key_shares_dkg_genout_p3(&pk, &alpha_p3, &state2);
        Ok(out)
    } else {
        let r = rng.unwrap();
        let gins: Vec<YaoGarblerShare> =
            share.iter().map(|ins| ins.as_garbler()).cloned().collect();
        let (msg1, state1) =
            get_private_key_shares_dkg_create_msg1_p12(&gins, r);

        send_to_party(setup, tag1, msg1, 2, relay).await?;

        let msg2s: Vec<YaoToScalarRssKeypairMsg2<T>> =
            receive_from_parties(setup, tag2, &[2], relay).await?;

        let msg2 = &msg2s[0];

        let (msg3_01, msg3_2, state3) =
            get_private_key_shares_dkg_create_msg3_p12(&state1, msg2);

        send_to_party(setup, tag3, msg3_01, 1 - party_id, relay).await?;
        send_to_party(setup, tag3, msg3_2, 2, relay).await?;

        let msg3s: Vec<YaoToScalarRssKeypairMsg3p12<T>> =
            receive_from_parties(setup, tag3, &[1 - party_id, 2], relay)
                .await?;

        let msg3_01 = msg3s[0].clone();
        let msg3_2 = msg3s[1].clone();

        if party_id == 0 {
            get_private_key_shares_dkg_process_msg3_p12(
                &msg3_2, &msg3_01, &state3,
            );
        } else {
            get_private_key_shares_dkg_process_msg3_p12(
                &msg3_01, &msg3_2, &state3,
            );
        }

        let pk = get_private_key_shares_dkg_create_msg4_p12(&state3, &state1);
        send_to_party(
            setup,
            tag4,
            YaoToScalarRssKeypairMsg4 { pk },
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

pub async fn run_batch_yao_to_scalar_rss_keypair<S, G, R, T>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    tag_offset_counter: &mut TagOffsetCounter,
    share: &[&[YaoShare]],
    rng: Option<&mut G>,
) -> Result<Vec<PrivKeyShareDkg<T>>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    T: Group + GroupEncoding,
    T::Scalar: ScalarFromBytes,
    YaoToScalarRssKeypairMsg1<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg2<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg3p12<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg3p3<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg4<T>: Wrap + FixedExternalSize,
{
    let tag1 =
        MessageTag::tag1(YAO_TO_RSS_MSG1, tag_offset_counter.next_value());
    let tag2 =
        MessageTag::tag1(YAO_TO_RSS_MSG2, tag_offset_counter.next_value());
    let tag3 =
        MessageTag::tag1(YAO_TO_RSS_MSG3, tag_offset_counter.next_value());
    let tag4 =
        MessageTag::tag1(YAO_TO_RSS_MSG4, tag_offset_counter.next_value());

    relay.ask_messages(setup, tag1, true).await?;
    relay.ask_messages(setup, tag2, true).await?;
    relay.ask_messages(setup, tag3, true).await?;
    relay.ask_messages(setup, tag4, true).await?;

    let output = run_batch_yao_to_scalar_rss_keypair_inner(
        setup, relay, share, rng, tag1, tag2, tag3, tag4,
    )
    .await?;

    Ok(output)
}

/// Converts a given scalar represented as yao shares to Scalar RSS shares
/// and returns it along with the correspoding public key along
#[allow(clippy::too_many_arguments)]
pub async fn run_batch_yao_to_scalar_rss_keypair_inner<S, G, R, T>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[&[YaoShare]],
    rng: Option<&mut G>,
    tag1: MessageTag,
    tag2: MessageTag,
    tag3: MessageTag,
    tag4: MessageTag,
) -> Result<Vec<PrivKeyShareDkg<T>>, HardDerivationError>
where
    S: ProtocolParticipant,
    R: Relay,
    G: RngCore + CryptoRng,
    T: Group + GroupEncoding,
    T::Scalar: ScalarFromBytes,
    YaoToScalarRssKeypairMsg1<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg2<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg3p12<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg3p3<T>: Wrap + FixedExternalSize,
    YaoToScalarRssKeypairMsg4<T>: Wrap + FixedExternalSize,
{
    let party_id = setup.participant_index();

    let batch_size = shares.len();

    if party_id == 2 {
        let msg1s: Vec<Vec<YaoToScalarRssKeypairMsg1<T>>> =
            receive_from_parties(setup, tag1, &[0, 1], relay).await?;

        let msg1s_p3_from_p1 = &msg1s[0];
        let msg1s_p3_from_p2 = &msg1s[1];

        let eins: Vec<Vec<YaoEvaluatorShare>> = shares
            .iter()
            .map(|share| {
                share
                    .iter()
                    .map(|ins| ins.as_evaluator())
                    .cloned()
                    .collect()
            })
            .collect();

        let mut msg2_0s = Vec::with_capacity(batch_size);
        let mut msg2_1s = Vec::with_capacity(batch_size);
        let mut state2s = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let (msg2_0, msg2_1, state2) =
                get_private_key_shares_dkg_create_msg2_p3(
                    &eins[i],
                    &msg1s_p3_from_p1[i],
                    &msg1s_p3_from_p2[i],
                );

            msg2_0s.push(msg2_0);
            msg2_1s.push(msg2_1);
            state2s.push(state2);
        }

        send_to_party(setup, tag2, msg2_0s, 0, relay).await?;
        send_to_party(setup, tag2, msg2_1s, 1, relay).await?;

        let mut msg3s = Vec::with_capacity(batch_size);
        let mut state3s = Vec::with_capacity(batch_size);
        for i in state2s.iter() {
            let (msg3, state3) = get_private_key_shares_dkg_create_msg3_p3(i);

            msg3s.push(msg3);
            state3s.push(state3);
        }

        send_to_party(setup, tag3, msg3s.clone(), 0, relay).await?;
        send_to_party(setup, tag3, msg3s, 1, relay).await?;

        let msg3s: Vec<Vec<YaoToScalarRssKeypairMsg3p3<T>>> =
            receive_from_parties(setup, tag3, &[0, 1], relay).await?;

        let msg3s_0 = &msg3s[0];
        let msg3s_1 = &msg3s[1];

        let mut alpha_p3s = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let alpha_p3 = get_private_key_shares_dkg_process_msg3_p3(
                &msg3s_1[i],
                &msg3s_0[i],
                &state2s[i],
                &state3s[i],
            );

            alpha_p3s.push(alpha_p3);
        }

        let pks: Vec<Vec<YaoToScalarRssKeypairMsg4<T>>> =
            receive_from_parties(setup, tag4, &[0, 1], relay).await?;

        let mut output = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let pk_p1 = pks[0][i].pk;
            let pk_p2 = pks[1][i].pk;

            let pk =
                get_private_key_shares_dkg_process_msg4_p3(&pk_p1, &pk_p2);
            output.push(get_private_key_shares_dkg_genout_p3(
                &pk,
                &alpha_p3s[i],
                &state2s[i],
            ));
        }

        Ok(output)
    } else {
        let r = rng.unwrap();
        let gins: Vec<Vec<YaoGarblerShare>> = shares
            .iter()
            .map(|share| {
                share.iter().map(|ins| ins.as_garbler()).cloned().collect()
            })
            .collect();

        let mut msg1s = Vec::with_capacity(batch_size);
        let mut state1s = Vec::with_capacity(batch_size);

        for i in gins.iter() {
            let (msg1, state1) =
                get_private_key_shares_dkg_create_msg1_p12(i, r);

            msg1s.push(msg1);
            state1s.push(state1);
        }

        send_to_party(setup, tag1, msg1s, 2, relay).await?;

        let msg2s: Vec<Vec<YaoToScalarRssKeypairMsg2<T>>> =
            receive_from_parties(setup, tag2, &[2], relay).await?;

        let msg2s = &msg2s[0];

        let mut msg3_01s = Vec::with_capacity(batch_size);
        let mut msg3_2s = Vec::with_capacity(batch_size);
        let mut state3s = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let (msg3_01, msg3_2, state3) =
                get_private_key_shares_dkg_create_msg3_p12(
                    &state1s[i],
                    &msg2s[i],
                );

            msg3_01s.push(msg3_01);
            msg3_2s.push(msg3_2);
            state3s.push(state3);
        }

        send_to_party(setup, tag3, msg3_01s, 1 - party_id, relay).await?;
        send_to_party(setup, tag3, msg3_2s, 2, relay).await?;

        let msg3s: Vec<Vec<YaoToScalarRssKeypairMsg3p12<T>>> =
            receive_from_parties(setup, tag3, &[1 - party_id, 2], relay)
                .await?;

        let msg3_01s = &msg3s[0];
        let msg3_2s = &msg3s[1];

        let mut pks = Vec::with_capacity(batch_size);
        let mut pk_ors = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            if party_id == 0 {
                get_private_key_shares_dkg_process_msg3_p12(
                    &msg3_2s[i],
                    &msg3_01s[i],
                    &state3s[i],
                );
            } else {
                get_private_key_shares_dkg_process_msg3_p12(
                    &msg3_01s[i],
                    &msg3_2s[i],
                    &state3s[i],
                );
            }

            let pk = get_private_key_shares_dkg_create_msg4_p12(
                &state3s[i],
                &state1s[i],
            );
            pk_ors.push(pk);

            pks.push(YaoToScalarRssKeypairMsg4 { pk });
        }

        send_to_party(setup, tag4, pks, 2, relay).await?;

        let mut output = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let op = if party_id == 0 {
                get_private_key_shares_dkg_genout_p1(
                    &pk_ors[i],
                    &state1s[i],
                    &state3s[i],
                )
            } else {
                get_private_key_shares_dkg_genout_p2(
                    &pk_ors[i],
                    &state1s[i],
                    &state3s[i],
                )
            };
            output.push(op);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use garbled_circuit::{
        functionality::{
            input::batch_input_yao_functionality,
            setup::setup_yao_functionality, utils::FilteredMsgRelay,
            utils_dep::TagOffsetCounter,
        },
        utilities::{
            commitments::HashCommitment,
            hash_function::AesHash,
            types::{YaoSetup, YaoShare},
        },
    };
    use k256::{ProjectivePoint, Scalar};
    use rand::{Rng, SeedableRng, rngs};
    use rand_chacha::ChaCha8Rng;
    use sl_messages::relay::{Relay, SimpleMessageRelay};

    use crate::{
        types::{HardDerivationError, PrivKeyShareDkg, ProtocolParticipant},
        utils::run_init,
        yao_to_rss::{
            run_batch_yao_to_scalar_rss_keypair,
            run_yao_to_scalar_rss_keypair,
        },
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
        let mut relay = FilteredMsgRelay::new(relay);

        let mut tag_offset_counter = TagOffsetCounter::new();

        let yao_setup = setup_yao_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
        )
        .await?;

        let (mut rng, _, _) = match &yao_setup {
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

    async fn test_run_batch_yao_to_scalar_rss_keypair<S, R>(
        setup: S,
        input: Vec<Vec<bool>>,
        relay: R,
    ) -> Result<
        (usize, Vec<PrivKeyShareDkg<ProjectivePoint>>),
        HardDerivationError,
    >
    where
        S: ProtocolParticipant,
        R: Relay,
    {
        let mut relay = FilteredMsgRelay::new(relay);

        let mut tag_offset_counter = TagOffsetCounter::new();

        let yao_setup = setup_yao_functionality(
            &setup,
            &mut tag_offset_counter,
            &mut relay,
        )
        .await?;

        let (mut rng, _, _) = match &yao_setup {
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

        let mut in_yao = Vec::new();
        for i in input {
            let in_yaot = batch_input_yao_functionality(
                &setup,
                &mut tag_offset_counter,
                &mut relay,
                &i,
                rng.as_mut(),
                &yao_setup,
            )
            .await?;
            in_yao.push(in_yaot);
        }

        let inyao_slices: Vec<&[YaoShare]> =
            in_yao.iter().map(|x| x.as_slice()).collect();

        let out = run_batch_yao_to_scalar_rss_keypair(
            &setup,
            &mut relay,
            &mut tag_offset_counter,
            &inyao_slices,
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
            parties.spawn(test_run_yao_to_scalar_rss_keypair(
                setup,
                i1.clone(),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_yao_to_scalar_rss_keypair_batched() {
        let mut rng = rngs::StdRng::from_entropy();

        let mut inputs = Vec::new();

        for _ in 0..10 {
            let mut i1 = vec![false; 256];
            (0..i1.len()).for_each(|i| {
                i1[i] = rng.gen_bool(0.5);
            });
            inputs.push(i1);
        }

        let mut parties = tokio::task::JoinSet::new();
        let coord = SimpleMessageRelay::new();
        for (setup, _) in run_init(None) {
            let relay = coord.connect();
            parties.spawn(test_run_batch_yao_to_scalar_rss_keypair(
                setup,
                inputs.clone(),
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

        for (i, inp) in inputs.iter().enumerate().take(10) {
            let out = shares[0].1[i].keyshare.next_share
                + shares[1].1[i].keyshare.next_share
                + shares[2].1[i].keyshare.next_share;

            let mut sum = Scalar::ZERO;
            let two = Scalar::ONE + Scalar::ONE;
            let mut twopow = Scalar::ONE;
            for i in inp {
                if *i {
                    sum += twopow;
                }
                twopow *= two;
            }
            assert_eq!(sum, out);
            assert_eq!(
                ProjectivePoint::GENERATOR * sum,
                shares[0].1[i].pubkey
            );
        }
    }
}
