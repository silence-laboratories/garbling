use std::path::PathBuf;

use crypto_bigint::U256;
use derivation_path::ChildIndex;
use garbled_circuit::circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder};
use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use sl_compute_common::BinaryString;

use crate::{constants::SECP256_K1_Q, utils::u8_vec_to_bool_vec};

/// Returns a `BinaryCircuit`, which takes the `key` as the garbler's inputs and the `chain code` as
/// the evaluator's input, along with the `public key` and the child's `index`, and does the following.
///
/// `I = if hardened child then HMAC-512(0x00 || key || index) else HMAC-512(public key || index)`
///
/// `IL || IR = I.split_at(256)`
///
/// `Child_key = IL + key`
///
/// `Child_Chaincode = IR`
///
/// `Return Child_key || Child_Chaincode`
pub fn build_child_key_der_hmac_circuit(
    public_key_par: &ProjectivePoint,
    index_child: &ChildIndex,
) -> garbled_circuit::circuitop::circuit::BinaryCircuit {
    let mut builder = CircuitBuilder::new();
    let key_par_ids = builder.garbler_inputs(256);
    let chain_par_ids = builder.evaluator_inputs(256);

    let mut data_ids = Vec::new();
    // key = chain_par

    if index_child.is_hardened() {
        // Hardened child
        // data = 0x00 || privkey_par || index (all in big endian)
        for _ in 0..8 {
            data_ids.push(builder.constant(0));
        }
        data_ids.extend_from_slice(&key_par_ids);
    } else {
        // Normal child
        // data = pubkey_par || index (all in big endian)
        let pubkey_bytes = public_key_par.to_encoded_point(true).as_bytes().to_vec();
        let pubkey_bool = u8_vec_to_bool_vec(pubkey_bytes);
        for i in pubkey_bool {
            data_ids.push(builder.constant(if i { 1 } else { 0 }));
        }
    }
    let index_be = index_child.to_bits().to_be_bytes();
    let index_bool = u8_vec_to_bool_vec(index_be.to_vec());
    let mut index_ids = Vec::new();
    for i in index_bool {
        index_ids.push(builder.constant(if i { 1 } else { 0 }));
    }
    data_ids.extend_from_slice(&index_ids);

    let hmac_circuit = build_hmac_512_circuit(chain_par_ids.len(), data_ids.len());
    let mut hmac_outputs = builder.add_circuit(&hmac_circuit, &chain_par_ids, &data_ids);

    let mut left = hmac_outputs[..256].to_vec();
    left.reverse();

    let mut parent_key = key_par_ids.clone();
    parent_key.reverse();

    let add_circ = build_mod_add_circut(256, SECP256_K1_Q);
    let out = builder.add_circuit(&add_circ, &parent_key, &left);

    hmac_outputs[..256].copy_from_slice(&out);

    for i in hmac_outputs {
        builder.output(i);
    }

    builder.finish()
}

/// Returns a hmac circuit which takes `key_length` bits of key and `message_length` bits of messages
/// The key bits are the garbler's inputs and the message bits are the evaluator's inputs
pub fn build_hmac_512_circuit(key_length: usize, message_length: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let key_ids = builder.garbler_inputs(key_length as u16);
    let msg_ids = builder.evaluator_inputs(message_length as u16);

    let mut resized_key_ids;
    if key_length > 1024 {
        let sha_circuit = build_sha512_circuit(key_length as u128);
        resized_key_ids = builder.add_circuit(&sha_circuit, &key_ids, &[]);
    } else {
        resized_key_ids = key_ids;
    }
    for _ in resized_key_ids.len()..1024 {
        resized_key_ids.push(builder.constant(0));
    }

    let mut i_key_pad_ids = resized_key_ids.clone();
    let mut o_key_pad_ids = resized_key_ids.clone();

    for i in 0..128 {
        o_key_pad_ids[8 * i + 1] = builder.negate(o_key_pad_ids[8 * i + 1]);
        o_key_pad_ids[8 * i + 3] = builder.negate(o_key_pad_ids[8 * i + 3]);
        o_key_pad_ids[8 * i + 4] = builder.negate(o_key_pad_ids[8 * i + 4]);
        o_key_pad_ids[8 * i + 5] = builder.negate(o_key_pad_ids[8 * i + 5]);

        i_key_pad_ids[8 * i + 2] = builder.negate(i_key_pad_ids[8 * i + 2]);
        i_key_pad_ids[8 * i + 3] = builder.negate(i_key_pad_ids[8 * i + 3]);
        i_key_pad_ids[8 * i + 5] = builder.negate(i_key_pad_ids[8 * i + 5]);
        i_key_pad_ids[8 * i + 6] = builder.negate(i_key_pad_ids[8 * i + 6]);
    }

    let mut inner_msg = i_key_pad_ids.clone();
    inner_msg.extend_from_slice(&msg_ids);

    let innersha = build_sha512_circuit(inner_msg.len() as u128);
    let inner_hash_ids = builder.add_circuit(&innersha, &inner_msg, &[]);

    let mut outer_msg = o_key_pad_ids.clone();
    outer_msg.extend_from_slice(&inner_hash_ids);

    let outersha = build_sha512_circuit(outer_msg.len() as u128);
    let output_ids = builder.add_circuit(&outersha, &outer_msg, &[]);

    for i in output_ids {
        builder.output(i);
    }

    builder.finish()
}

/// Get the pad as a `BinaryString` structure for sha512
fn get_512_chain_state() -> BinaryString {
    let chaining_state_hex: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let mut chaining_state: BinaryString = BinaryString::with_capacity(512);
    for id in 0..chaining_state_hex.len() {
        let value = chaining_state_hex[7 - id];
        let mut temp2 = Vec::new();
        for i in 0..64 {
            chaining_state.push((value >> i) & 1 == 1);
            temp2.push((value >> i) & 1 == 1);
        }
    }

    chaining_state
}

/// Get a circuit for sha512 for a generic length input.
/// The input is set as the garbler's inputs.
pub fn build_sha512_circuit(len: u128) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let k = (1024 - 128 - (len % 1024) + 1024) % 1024;

    let mut pad = vec![true];
    pad.extend(std::iter::repeat_n(false, (k - 1) as usize));

    let length_bits = len.to_be_bytes();
    for byte in length_bits.iter() {
        for i in (0..8).rev() {
            let value = (byte >> i) & 1u8 == 1u8;
            pad.push(value);
        }
    }

    let inputs = builder.garbler_inputs(len as u16);

    let mut padded = inputs.clone();

    for i in pad {
        let inp = if i {
            builder.constant(1)
        } else {
            builder.constant(0)
        };

        padded.push(inp);
    }

    let chaining_state = get_512_chain_state();

    let mut chain_input = vec![];

    for i in 0..chaining_state.length as usize {
        let inp = if chaining_state.get(i) {
            builder.constant(1)
        } else {
            builder.constant(0)
        };
        chain_input.push(inp);
    }

    let count = padded.len() / 1024;

    for i in 0..count {
        let mut block_inp = padded[1024 * i..1024 * (i + 1)].to_vec();
        block_inp.reverse();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/sha512.txt");

        println!("{}", path.to_str().unwrap());

        let block_out = builder
            .parse(path.to_str().unwrap(), &block_inp, &chain_input)
            .unwrap();

        chain_input = block_out;
    }

    chain_input.reverse();

    for i in chain_input {
        builder.output(i);
    }

    builder.finish()
}

pub fn build_scalar_to_y_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let x1_ids = builder.garbler_inputs(256);
    let x2_ids = builder.garbler_inputs(256);
    let x3_ids = builder.evaluator_inputs(256);

    let circ = build_mod_add_circut(x1_ids.len(), SECP256_K1_Q);

    let temp = builder.add_circuit(&circ, &x1_ids, &x2_ids);
    let res3_ids = builder.add_circuit(&circ, &temp, &x3_ids);

    (0..256).for_each(|i| {
        builder.output(res3_ids[i]);
    });

    builder.finish()
}

fn build_compare_eq_circuit(input_len: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let input1 = builder.garbler_inputs(input_len as u16);
    let input2 = builder.evaluator_inputs(input_len as u16);

    let xors: Vec<usize> = input1
        .iter()
        .zip(input2.iter())
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

pub fn build_verify_sharings_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let p1_next = builder.garbler_inputs(256);
    let p2_next = builder.garbler_inputs(256);
    let p3_next = builder.garbler_inputs(256);
    let p1_prev = builder.evaluator_inputs(256);
    let p2_prev = builder.evaluator_inputs(256);
    let p3_prev = builder.evaluator_inputs(256);

    let comp_eq_circ = build_compare_eq_circuit(256);
    let op1 = builder.add_circuit(&comp_eq_circ, &p1_next, &p2_prev)[0];
    let op2 = builder.add_circuit(&comp_eq_circ, &p2_next, &p3_prev)[0];
    let op3 = builder.add_circuit(&comp_eq_circ, &p3_next, &p1_prev)[0];

    let temp = builder.and(op1, op2);
    let output = builder.and(temp, op3);

    builder.output(output);
    builder.finish()
}

/// Returns the `BinaryCircuit` which implements addition modulo a constant `prime` of two
///  binary values of bit length `size`
///
/// The first input is set as the gabler's input and the next input is set as the
/// evaluator's input
pub fn build_mod_add_circut(size: usize, prime: U256) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let mut pbin = BinaryString {
        length: size as u64,
        value: prime.to_le_bytes().to_vec(),
    };

    if size + 1 > pbin.length as usize {
        for _ in pbin.length as usize..(size + 1) {
            pbin.push(false);
        }
    }

    let mut ps = Vec::new();
    for i in 0..pbin.length as usize {
        ps.push(builder.constant(if pbin.get(i) { 1 } else { 0 }));
    }

    let x = builder.garbler_inputs(size as u16);
    let y = builder.evaluator_inputs(size as u16);

    let add_circuit = build_ppa_circuit(size);

    let add = builder.add_circuit(&add_circuit, &x, &y);

    let comp_circ = build_compare_ge_circuit(size + 1);
    let comp = builder.add_circuit(&comp_circ, &add, &ps);

    let sub_circ = build_subtract_order_circuit(size + 1, prime);
    let sub = builder.add_circuit(&sub_circ, &add, &[]);

    let mut gin = vec![comp[0]; size];
    for i in &sub[..size] {
        gin.push(*i);
    }

    let ifthenelse_circ = build_if_then_else_circuit(size);
    let out = builder.add_circuit(&ifthenelse_circ, &gin, &add[..size]);

    for i in out {
        builder.output(i);
    }

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements subtraction of a binary value of
/// bit length `size` by a constant `prime`.
///
/// The input is set as the garbler's input
pub fn build_subtract_order_circuit(size: usize, prime: U256) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let gin = builder.garbler_inputs(size as u16);

    let mut pbin = BinaryString {
        length: prime.to_le_bytes().len() as u64,
        value: prime.to_le_bytes().to_vec(),
    };

    if size > pbin.length as usize {
        for _ in pbin.length as usize..size {
            pbin.push(false);
        }
    }

    // pbin.not();
    let mut negate = BinaryString::with_capacity(size);
    for i in 0..size {
        negate.push(!pbin.get(i));
    }
    pbin = negate;
    // pbin.add_one();
    let mut value = true;
    for i in 0..pbin.length as usize {
        let bit = pbin.get(i);
        let sum = bit ^ value;
        value &= bit;
        pbin.set(i, sum);
        if !value {
            break;
        }
    }

    let mut pbin_ids = Vec::new();
    let mut pt = Vec::new();
    for i in 0..pbin.length as usize {
        let id = builder.constant(if pbin.get(i) { 1 } else { 0 });
        pt.push(pbin.get(i));
        pbin_ids.push(id);
    }

    let ppa_circuit = build_ppa_circuit(size);
    let ppaout = builder.add_circuit(&ppa_circuit, &gin, &pbin_ids);

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

    let inp1 = builder.garbler_inputs(size as u16);
    let inp2 = builder.evaluator_inputs(size as u16);

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
        let g_to_and_1 = g[0..size - (1usize << step)].to_vec();
        let p_to_and_2 = p[0..size - (1usize << step)].to_vec();
        let p_to_and_1_2 = p[1usize << step..size].to_vec();
        let g_to_or = g[1usize << step..size].to_vec();

        let gc_to_or: Vec<usize> = g_to_and_1
            .iter()
            .zip(&p_to_and_1_2)
            .map(|(x, y)| builder.and(*x, *y))
            .collect();

        let pc_after_and: Vec<usize> = p_to_and_2
            .iter()
            .zip(&p_to_and_1_2)
            .map(|(x, y)| builder.and(*x, *y))
            .collect();

        let gc_after_or: Vec<usize> = g_to_or
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
    let mut g_mul_two = vec![builder.constant(0)];
    g_mul_two.extend_from_slice(&g[..size - 1]);

    let sum: Vec<usize> = pc
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

    let x = builder.garbler_inputs(size as u16);
    let y = builder.evaluator_inputs(size as u16);

    let rec_circ = build_compare_ge_rec_circuit(size, 0, size - 1);

    let ops = builder.add_circuit(&rec_circ, &x, &y);

    builder.output(ops[0]);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements the recursion for compare ge protocol, which
/// compares two binary values of `size` bit length
pub fn build_compare_ge_rec_circuit(size: usize, lo: usize, hi: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let xvals = builder.garbler_inputs(size as u16);
    let yvals = builder.evaluator_inputs(size as u16);

    if lo == hi {
        let a = builder.xor(xvals[lo], yvals[lo]);
        let temp = builder.and(a, yvals[lo]);
        let t = builder.negate(temp);
        builder.output(t);
        builder.output(a);
        return builder.finish();
    } else if lo > hi {
        println!("impossible {} {}", lo, hi);
    }

    let m = lo + (hi - lo) / 2;
    let circ_low = build_compare_ge_rec_circuit(size, lo, m);
    let circ_high = build_compare_ge_rec_circuit(size, m + 1, hi);

    let lowout = builder.add_circuit(&circ_low, &xvals, &yvals);
    let highout = builder.add_circuit(&circ_high, &xvals, &yvals);

    let (subres_l, diff_l) = (lowout[0], lowout[1]);
    let (subres_h, diff_h) = (highout[0], highout[1]);

    let ifelse_circ = build_if_then_else_circuit(1);
    let subres = builder.add_circuit(&ifelse_circ, &[diff_h, subres_h], &[subres_l]);

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

    let choice = builder.garbler_inputs(size as u16);
    let gin = builder.garbler_inputs(size as u16);
    let ein = builder.evaluator_inputs(size as u16);

    let r: Vec<usize> = gin
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
