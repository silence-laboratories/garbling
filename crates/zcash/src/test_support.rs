use garbled_circuit::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};
#[cfg(any(test, feature = "test-support"))]
use garbled_circuit::functionality::{
    utils::FilteredMsgRelay,
    utils::{NoSigningKey, NoVerifyingKey, SetupMessage},
    utils_dep::ProtocolError,
};

#[cfg(any(test, feature = "test-support"))]
use group::{Group, GroupEncoding};
#[cfg(any(test, feature = "test-support"))]
use pasta_curves::{
    group::ff::{Field, PrimeField},
    {pallas, pallas::Scalar},
};

#[cfg(any(test, feature = "test-support"))]
use sl_messages::{relay::Relay, setup::ProtocolParticipant};

#[cfg(any(test, feature = "test-support"))]
use sl_compute_common::CommonRandomness;

/// Generate setup messages and seeds for parties.
#[cfg(any(test, feature = "test-support"))]
pub fn run_init(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
    use std::time::Duration;

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
            SetupMessage::new(
                InstanceId::new(instance),
                sk,
                party_id,
                party_vk.clone(),
            )
            .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
        })
        .map(|setup| {
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

/// Converts an RSS-shared Scalar value (`PrivKeyShare`) to a shamir shared value
/// for party with id `party_id` for a set of evaluation points.
#[cfg(any(test, feature = "test-support"))]
pub fn scalar_rss_to_shamir<G>(
    prev_share: G::Scalar,
    next_share: G::Scalar,
    party_id: usize,
) -> G::Scalar
where
    G: Group + GroupEncoding,
{
    // helper closure f_A(j) = (j - m)/(-m)

    use std::ops::Sub;

    use group::ff::Field;

    let eval_points =
        (0..3).map(|v| G::Scalar::from(v + 1)).collect::<Vec<_>>();

    let f = |j: G::Scalar, m: G::Scalar| -> G::Scalar {
        let num = j.sub(&m);
        let denom = -m;
        num * denom.invert().unwrap()
    };

    match party_id {
        0 => {
            // subsets containing 1: {1,2} (next_share), {1,3} (prev_share)
            let term12 = next_share * f(eval_points[0], eval_points[2]);
            let term13 = prev_share * f(eval_points[0], eval_points[1]);
            term12 + term13
        }

        1 => {
            // subsets containing 2: {1,2} (prev_share), {2,3} (next_share)
            let term12 = prev_share * f(eval_points[1], eval_points[2]);
            let term23 = next_share * f(eval_points[1], eval_points[0]);
            term12 + term23
        }

        2 => {
            // subsets containing 3: {1,3} (next_share), {2,3} (prev_share)
            let term13 = next_share * f(eval_points[2], eval_points[1]);
            let term23 = prev_share * f(eval_points[2], eval_points[0]);
            term13 + term23
        }

        _ => unreachable!(),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn get_evaluation(
    party_points: &[Scalar],
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
pub(crate) fn get_lagrange_coeff_list<'a, K, T>(
    party_points: &'a [T],
    eval_point: &'a Scalar,
    k: K,
) -> impl Iterator<Item = Scalar> + 'a
where
    K: Fn(&T) -> &Scalar + 'a,
{
    party_points.iter().map(move |x_i| {
        let x_i = k(x_i);
        let mut coeff = Scalar::ONE;
        for x_j in party_points {
            let x_j = k(x_j);
            if x_i != x_j {
                let num = x_j.sub(eval_point);
                let sub = x_j.sub(x_i);
                // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
                coeff *= num * sub.invert().unwrap();
            }
        }
        coeff
    })
}

#[cfg(any(test, feature = "test-support"))]
fn reconstruct_shamir_process_msg1(
    share: &Scalar,
    share_next: &Scalar,
    share_prev: &Scalar,
    party_points: &[Scalar],
    party_id: usize,
) -> Result<Scalar, ProtocolError> {
    let evals = [*share, *share_prev];
    let (ppts, next_eval) = match party_id {
        0 => ([party_points[0], party_points[2]], &party_points[1]),
        1 => ([party_points[1], party_points[0]], &party_points[2]),
        2 => ([party_points[2], party_points[1]], &party_points[0]),
        _ => return Err(ProtocolError::InvalidMessage),
    };

    let next_val = get_evaluation(&ppts, &evals, next_eval);

    if *share_next != next_val {
        return Err(ProtocolError::VerificationError);
    }

    Ok(get_evaluation(&ppts, &evals, &Scalar::ZERO))
}

#[cfg(any(test, feature = "test-support"))]
fn get_random_pallas_scalar_share(
    common_randomness: &mut CommonRandomness,
) -> (pasta_curves::Fq, pasta_curves::Fq) {
    use multi_party_schnorr::common::traits::ScalarReduce;

    let (prev_bytes, next_bytes) = common_randomness.random_32_bytes();
    let prev: pallas::Scalar = pallas::Scalar::reduce_from_bytes(&prev_bytes);
    let next: pallas::Scalar = pallas::Scalar::reduce_from_bytes(&next_bytes);

    (prev, next)
}

#[cfg(any(test, feature = "test-support"))]
/// Function to reconstruct a shamir shared Scalar value to all parties
pub async fn run_reconstruct_pallas_shamir<
    R: Relay,
    S: ProtocolParticipant,
>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &Scalar,
) -> Result<Scalar, ProtocolError> {
    use garbled_circuit::functionality::utils::{
        receive_from_one_party, send_to_party,
    };

    let tag1 = relay.next_tag(1);
    let tag2 = relay.next_tag(2);

    let my_party_id = setup.participant_index();
    let prev_party = (3 + my_party_id - 1) % 3;
    let next_party = (3 + my_party_id + 1) % 3;

    send_to_party(setup, tag1, &share.to_repr(), prev_party, relay).await?;
    send_to_party(setup, tag2, &share.to_repr(), next_party, relay).await?;

    let shares_recv_n: [u8; 32] =
        receive_from_one_party(setup, tag1, next_party, relay).await?;
    let shares_recv_p: [u8; 32] =
        receive_from_one_party(setup, tag2, prev_party, relay).await?;

    let share_prev = &Scalar::from_repr(shares_recv_p).unwrap();
    let share_next = &Scalar::from_repr(shares_recv_n).unwrap();

    let eval_points = (0..3).map(|v| Scalar::from(v + 1)).collect::<Vec<_>>();

    reconstruct_shamir_process_msg1(
        share,
        share_next,
        share_prev,
        &eval_points,
        my_party_id,
    )
}

#[cfg(any(test, feature = "test-support"))]
/// Converts a Shamir-shared Scalar valueto an RSS-shared Scalar value (`PrivKeyShare`)
pub async fn run_shamir_to_scalar_rss_pallas<
    R: Relay,
    S: ProtocolParticipant,
>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    share: &pallas::Scalar,
    randomness: &mut CommonRandomness,
) -> Result<(Scalar, Scalar), ProtocolError> {
    use multi_party_schnorr::common::redpallas::RedPallasPoint;

    let my_party_id = setup.participant_index();

    let (r_prev, r_next) = get_random_pallas_scalar_share(randomness);

    let r_shamir =
        scalar_rss_to_shamir::<RedPallasPoint>(r_prev, r_next, my_party_id);

    let padded_shamir = share + r_shamir;

    let padded =
        run_reconstruct_pallas_shamir(setup, relay, &padded_shamir).await?;

    let out_rss = if my_party_id == 0 {
        (padded - r_prev, -r_next)
    } else if my_party_id == 1 {
        (-r_prev, -r_next)
    } else {
        (-r_prev, padded - r_next)
    };

    Ok(out_rss)
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

/// Converts a vector of bytes to a vector of bool values in big endian
pub fn bytes_to_bits_be(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    // go from most significant byte to least significant
    for &byte in bytes.iter() {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    bits
}

#[cfg(any(test, feature = "test-support"))]
pub fn build_zcash_import_function() -> BinaryCircuit {
    use crate::zcash::build_zcash_blake2b_circuit;

    let mut builder = CircuitBuilder::new();

    let p1_next = builder.new_inputs(256);
    let p2_next = builder.new_inputs(256);
    let p3_next = builder.new_inputs(256);
    let p1_prev = builder.new_inputs(256);
    let p2_prev = builder.new_inputs(256);
    let p3_prev = builder.new_inputs(256);

    let comp_eq_circ = build_compare_eq_circuit(256);
    let op1 = builder.add_circuit(&comp_eq_circ, &[&p1_next, &p2_prev])[0];
    let op2 = builder.add_circuit(&comp_eq_circ, &[&p2_next, &p3_prev])[0];
    let op3 = builder.add_circuit(&comp_eq_circ, &[&p3_next, &p1_prev])[0];

    let temp = builder.and(op1, op2);
    let output = builder.and(temp, op3);

    let mut prime_bytes = hex::decode(&Scalar::MODULUS[2..]).unwrap();
    prime_bytes.reverse();

    let circ =
        build_mod_add_circut(p1_next.len(), prime_bytes.try_into().unwrap());

    let temp = builder.add_circuit(&circ, &[&p1_next, &p2_next]);
    let res3_ids = builder.add_circuit(&circ, &[&temp, &p3_next]);

    let zcash_circuit = build_zcash_blake2b_circuit();
    let op = builder.add_circuit(&zcash_circuit, &[&res3_ids]);

    builder.output(output);
    for i in &op {
        builder.output(*i);
    }

    builder.finish()
}

#[cfg(any(test, feature = "test-support"))]
/// Returns the `BinaryCircuit` which implements addition modulo a constant `prime` of two
///  binary values of bit length `size`
///
/// The first input is set as the gabler's input and the next input is
/// set as the evaluator's input
pub fn build_mod_add_circut(
    size: usize,
    prime_bytes: [u8; 32],
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let mut pbin = bytes_to_bits_be(&prime_bytes);

    if size + 1 > pbin.len() {
        pbin.extend_from_slice(&vec![false; (size + 1) - pbin.len()]);
    }

    let ps = pbin
        .iter()
        .map(|&v| builder.constant(v))
        .collect::<Vec<_>>();

    let x = builder.new_inputs(size as u16);
    let y = builder.new_inputs(size as u16);

    let add_circuit = build_ppa_circuit(size);

    let add = builder.add_circuit(&add_circuit, &[&x, &y]);

    let comp_circ = build_compare_ge_circuit(size + 1);
    let comp = builder.add_circuit(&comp_circ, &[&add, &ps]);

    let sub_circ = build_subtract_order_circuit(size + 1, prime_bytes);
    let sub = builder.add_circuit(&sub_circ, &[&add]);

    let comps = vec![comp[0]; size];

    let ifthenelse_circ = build_if_then_else_circuit(size);
    let out = builder
        .add_circuit(&ifthenelse_circ, &[&comps, &sub[..size], &add[..size]]);

    for i in out {
        builder.output(i);
    }

    builder.finish()
}

#[cfg(any(test, feature = "test-support"))]
fn build_compare_eq_circuit(input_len: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let input1 = builder.new_inputs(input_len as u16);
    let input2 = builder.new_inputs(input_len as u16);

    let xors: Vec<u32> = input1
        .iter()
        .zip(&input2)
        .map(|(i1, i2)| builder.xor(*i1, *i2))
        .collect();

    let mut output = xors[0];

    (1..xors.len()).for_each(|i| {
        let temp1 = builder.xor(output, xors[i]);
        let temp2 = builder.and(output, xors[i]);
        output = builder.xor(temp1, temp2);
    });

    let op = builder.negate(output);
    builder.output(op);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements subtraction of a binary value of
/// bit length `size` by a constant `prime`.
///
/// The input is set as the garbler's input
pub fn build_subtract_order_circuit(
    size: usize,
    prime_bytes: [u8; 32],
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let gin = builder.new_inputs(size as u16);

    let mut pbin = bytes_to_bits_be(&prime_bytes);

    if size > pbin.len() {
        pbin.extend_from_slice(&vec![false; size - pbin.len()]);
    }

    pbin = pbin.iter().map(|v| !*v).collect();

    let mut value = true;
    #[allow(clippy::needless_range_loop)]
    for i in 0..pbin.len() {
        let bit = pbin[i];
        let sum = bit ^ value;
        value &= bit;
        pbin[i] = sum;
        if !value {
            break;
        }
    }

    let mut pbin_ids = Vec::new();
    let mut pt = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for i in 0..pbin.len() as usize {
        let id = builder.constant(pbin[i]);
        pt.push(pbin[i]);
        pbin_ids.push(id);
    }

    let ppa_circuit = build_ppa_circuit(size);
    let ppaout = builder.add_circuit(&ppa_circuit, &[&gin, &pbin_ids]);

    (0..size).for_each(|i| {
        builder.output(ppaout[i]);
    });

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements parallel prefix adder, which
/// adds two binary values of bit length `size`.
///
/// The first input is set as the gabler's input and the next input is set as the
/// evaluator's input
pub fn build_ppa_circuit(size: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let inp1 = builder.new_inputs(size as u16);
    let inp2 = builder.new_inputs(size as u16);

    let mut g = Vec::new();
    let mut p = Vec::new();

    let mut size_log2 = size.ilog2() as usize;
    let size_diff = size - (1 << size_log2);
    if size_diff != 0 {
        size_log2 += 1;
    }

    for i in 0..size {
        p.push(builder.xor(inp1[i], inp2[i]));
        g.push(builder.and(inp1[i], inp2[i]));
    }

    let pc = p.clone();

    for step in 0..size_log2 {
        let g_to_and_1 = &g[0..size - (1usize << step)];
        let p_to_and_2 = &p[0..size - (1usize << step)];
        let p_to_and_1_2 = &p[1usize << step..size];
        let g_to_or = &g[1usize << step..size];

        let gc_to_or: Vec<u32> = g_to_and_1
            .iter()
            .zip(p_to_and_1_2)
            .map(|(x, y)| builder.and(*x, *y))
            .collect();

        let pc_after_and: Vec<u32> = p_to_and_2
            .iter()
            .zip(p_to_and_1_2)
            .map(|(x, y)| builder.and(*x, *y))
            .collect();

        let gc_after_or: Vec<u32> = g_to_or
            .iter()
            .zip(&gc_to_or)
            .map(|(x, y)| {
                let l = builder.and(*x, *y);
                let m = builder.xor(*x, *y);
                builder.xor(l, m)
            })
            .collect();

        for i in (1usize << step)..size {
            p[i] = pc_after_and[i - (1usize << step)];
            g[i] = gc_after_or[i - (1usize << step)];
        }
    }

    let g_size = g[size - 1];
    let mut g_mul_two = vec![builder.constant(false)];
    g_mul_two.extend_from_slice(&g[..size - 1]);

    let sum: Vec<u32> = pc
        .iter()
        .zip(&g_mul_two)
        .map(|(x, y)| builder.xor(*x, *y))
        .collect();

    for i in sum {
        builder.output(i);
    }

    builder.output(g_size);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements compare ge protocol, which
/// compares two binary values of `size` bit length
///
/// If the garbler's input is `x` and the evaluator's input is `y`, the
/// circuit returns `x >= y`
pub fn build_compare_ge_circuit(size: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let x = builder.new_inputs(size as u16);
    let y = builder.new_inputs(size as u16);

    let rec_circ = build_compare_ge_rec_circuit(size, 0, size - 1);

    let ops = builder.add_circuit(&rec_circ, &[&x, &y]);

    builder.output(ops[0]);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements the recursion for
/// compare ge protocol, which compares two binary values of `size`
/// bit length
pub fn build_compare_ge_rec_circuit(
    size: usize,
    lo: usize,
    hi: usize,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let xvals = builder.new_inputs(size as u16);
    let yvals = builder.new_inputs(size as u16);

    assert!(lo <= hi, "impossible {lo} {hi}");

    if lo == hi {
        let a = builder.xor(xvals[lo], yvals[lo]);
        let temp = builder.and(a, yvals[lo]);
        let t = builder.negate(temp);
        builder.output(t);
        builder.output(a);
        return builder.finish();
    }

    let m = lo + (hi - lo) / 2;
    let circ_low = build_compare_ge_rec_circuit(size, lo, m);
    let circ_high = build_compare_ge_rec_circuit(size, m + 1, hi);

    let lowout = builder.add_circuit(&circ_low, &[&xvals, &yvals]);
    let highout = builder.add_circuit(&circ_high, &[&xvals, &yvals]);

    let (subres_l, diff_l) = (lowout[0], lowout[1]);
    let (subres_h, diff_h) = (highout[0], highout[1]);

    let ifelse_circ = build_if_then_else_circuit(1);
    let subres = builder
        .add_circuit(&ifelse_circ, &[&[diff_h], &[subres_h], &[subres_l]]);

    let mut diff = builder.xor(diff_h, diff_l);
    let temp = builder.and(diff_h, diff_l);
    diff = builder.xor(temp, diff);

    builder.output(subres[0]);
    builder.output(diff);

    builder.finish()
}

/// Returns a `BinaryCircuit` which implements a batched version of `if then else`.
/// The garbler inputs contains `choice + input1`.
/// The evaluator inputs contains `input2`.
/// If choice is true, then `input1` is the output. Else, the output is `input2`.
pub fn build_if_then_else_circuit(size: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let choice = builder.new_inputs(size as u16);
    let gin = builder.new_inputs(size as u16);
    let ein = builder.new_inputs(size as u16);

    let r: Vec<u32> = gin
        .iter()
        .zip(&ein)
        .zip(&choice)
        .map(|((x, y), c)| {
            let z = builder.xor(*x, *y);
            let d = builder.and(z, *c);
            builder.xor(d, *y)
        })
        .collect();

    for i in r {
        builder.output(i);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use group::ff::{Field, PrimeField};
    use pasta_curves::pallas::Scalar;
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        eval::evaluate,
        test_support::{build_mod_add_circut, bytes_to_bits_be},
    };

    #[test]
    fn test_mod_add() {
        let mut rng = StdRng::from_entropy();

        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);

        let s1_bits = bytes_to_bits_be(&s1.to_repr());
        let s2_bits = bytes_to_bits_be(&s2.to_repr());

        // let mut outval = Scalar::ZERO;
        // let two = Scalar::ONE + Scalar::ONE;
        // let mut twomul = Scalar::ONE;

        // for &i in &s1_bits {
        //     if i {
        //         outval += twomul;
        //     }
        //     twomul *= two;
        // }

        // println!("s1: {:?}", outval);

        let mut prime_bytes = hex::decode(&Scalar::MODULUS[2..]).unwrap();
        prime_bytes.reverse();

        let circuit = build_mod_add_circut(
            s1_bits.len(),
            prime_bytes.try_into().unwrap(),
        );

        let out = evaluate(&circuit, &[&s1_bits, &s2_bits]);

        let mut outval = Scalar::ZERO;
        let two = Scalar::ONE + Scalar::ONE;
        let mut twomul = Scalar::ONE;

        for i in out {
            if i {
                outval += twomul;
            }
            twomul *= two;
        }

        println!("a : {s1:?}");
        println!("b : {s2:?}");
        println!("id: {:?}", s1 + s2);
        println!("re: {outval:?}");
    }
}
