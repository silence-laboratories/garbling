#[cfg(any(test, feature = "test-support"))]
use garbled_circuit::functionality::utils::SetupMessage;
use k256::{NonZeroScalar, Scalar, elliptic_curve::subtle::ConstantTimeEq};

/// Converts a vector of `u8` values to a vector of `bool` values
pub fn u8_vec_to_bool_vec(vec_u8: Vec<u8>) -> Vec<bool> {
    let mut output = Vec::with_capacity(vec_u8.len() * 8);
    for byte in vec_u8 {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            output.push(bit != 0);
        }
    }
    output
}

/// Converts a vector of bytes to a vector of bool values in little endian
pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    // go from least significant byte to most significant
    for &byte in bytes.iter().rev() {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    bits
}

pub(crate) fn get_lagrange_coeff_list<'a, K, T>(
    party_points: &'a [T],
    eval_point: &'a Scalar,
    k: K,
) -> impl Iterator<Item = Scalar> + 'a
where
    K: Fn(&T) -> &NonZeroScalar + 'a,
{
    party_points.iter().map(move |x_i| {
        let x_i = k(x_i);
        let mut coeff = Scalar::ONE;
        for x_j in party_points {
            let x_j = k(x_j);
            if x_i.ct_ne(x_j).into() {
                let num = x_j.sub(eval_point);
                let sub = x_j.sub(x_i);
                // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
                coeff *= num.as_ref() * &sub.invert().unwrap();
            }
        }
        coeff
    })
}

pub fn get_evaluation(
    party_points: &[NonZeroScalar],
    evals: &[Scalar],
    eval_point: &Scalar,
) -> Scalar {
    let lcoeff = get_lagrange_coeff_list(party_points, eval_point, |x| x);

    evals
        .iter()
        .zip(lcoeff)
        .fold(Scalar::ZERO, |acc, (ev, lc)| acc + *ev * lc)
}

#[cfg(any(test, feature = "test-support"))]
pub fn run_init(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
    use std::time::Duration;

    use garbled_circuit::functionality::utils::{NoSigningKey, NoVerifyingKey};
    use sl_messages::message::InstanceId;

    let n = 3;

    let instance = instance.unwrap_or_else(rand::random);

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(n as usize)
        .collect();

    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(party_id, _)| NoVerifyingKey::new(party_id))
        .collect();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(party_id, sk)| {
            SetupMessage::new(InstanceId::new(instance), sk, party_id, party_vk.clone())
                .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
        })
        .map(|setup| {
            use garbled_circuit::functionality::utils_dep::ProtocolParticipant;
            use sha2::{Digest, Sha256};

            let mixin = [setup.participant_index() as u8 + 1];

            (
                setup,
                Sha256::new()
                    .chain_update(instance)
                    .chain_update(b"party-seed")
                    .chain_update(mixin)
                    .finalize()
                    .into(),
            )
        })
        .collect::<Vec<_>>()
}
