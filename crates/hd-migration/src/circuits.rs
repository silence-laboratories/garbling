// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use derivation_path::ChildIndex;
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{bigint::Encoding, sec1::ToEncodedPoint},
    ProjectivePoint, U256,
};

use sl_compute_common::BinaryString;

use garbled_circuit::{
    arithmetic,
    circuit::{prebuilt, BinaryCircuit, CircuitBuilder},
};

use crate::{constants::SECP256_K1_Q, utils::u8_vec_to_bool_vec};

pub fn build_child_key_der_hmac_round1_circuit(
    public_key_par: &ProjectivePoint,
    index_child: &ChildIndex,
    chain_code: [u8; 32],
) -> BinaryCircuit {
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

    let circ = build_mod_add_circut(p1_next.len(), SECP256_K1_Q);

    let temp = builder.add_circuit(&circ, &[&p1_next, &p2_next]);
    let mut res3_ids = builder.add_circuit(&circ, &[&temp, &p3_next]);
    res3_ids.reverse();

    builder.output(output);
    (0..256).for_each(|i| {
        builder.output(res3_ids[i]);
    });

    let key_par_ids = res3_ids;

    let mut data_ids = Vec::new();
    // key = chain_par

    let mut hmac_outputs = if index_child.is_hardened() {
        // Hardened child
        // data = 0x00 || privkey_par || index (all in big endian)

        let mut chain_par_ids = Vec::new();
        for i in u8_vec_to_bool_vec(chain_code) {
            chain_par_ids.push(builder.constant(i));
        }

        for _ in 0..8 {
            data_ids.push(builder.constant(false));
        }
        data_ids.extend_from_slice(&key_par_ids);

        let mut index_ids = Vec::new();
        for i in u8_vec_to_bool_vec(index_child.to_bits().to_be_bytes()) {
            index_ids.push(builder.constant(i));
        }
        data_ids.extend_from_slice(&index_ids);

        let hmac_circuit =
            build_hmac_512_circuit(chain_par_ids.len(), data_ids.len());
        builder.add_circuit(&hmac_circuit, &[&chain_par_ids, &data_ids])
    } else {
        // Normal child
        // data = pubkey_par || index (all in big endian)
        let mut hmac_hasher =
            Hmac::<sha2::Sha512>::new_from_slice(&chain_code).unwrap();

        hmac_hasher.update(public_key_par.to_encoded_point(true).as_bytes());

        hmac_hasher.update(&index_child.to_bits().to_be_bytes());
        let hashout = hmac_hasher.finalize().into_bytes();
        u8_vec_to_bool_vec(&hashout)
            .map(|bit| builder.constant(bit))
            .collect()
    };

    let mut left = hmac_outputs[..256].to_vec();
    left.reverse();

    let mut parent_key = key_par_ids.clone();
    parent_key.reverse();

    let add_circ = build_mod_add_circut(256, SECP256_K1_Q);
    let out = builder.add_circuit(&add_circ, &[&parent_key, &left]);

    hmac_outputs[..256].copy_from_slice(&out);

    for i in hmac_outputs {
        builder.output(i);
    }

    builder.finish()
}

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
    chain_code: [u8; 32],
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();
    let key_par_ids = builder.new_inputs(256);

    let mut data_ids = Vec::new();
    // key = chain_par

    let mut hmac_outputs = if index_child.is_hardened() {
        // Hardened child
        // data = 0x00 || privkey_par || index (all in big endian)

        let mut chain_par_ids = Vec::new();
        for i in u8_vec_to_bool_vec(chain_code) {
            chain_par_ids.push(builder.constant(i));
        }

        for _ in 0..8 {
            data_ids.push(builder.constant(false));
        }
        data_ids.extend_from_slice(&key_par_ids);

        let mut index_ids = Vec::new();
        for i in u8_vec_to_bool_vec(index_child.to_bits().to_be_bytes()) {
            index_ids.push(builder.constant(i));
        }
        data_ids.extend_from_slice(&index_ids);

        let hmac_circuit =
            build_hmac_512_circuit(chain_par_ids.len(), data_ids.len());
        builder.add_circuit(&hmac_circuit, &[&chain_par_ids, &data_ids])
    } else {
        // Normal child
        // data = pubkey_par || index (all in big endian)
        let mut hmac_hasher =
            Hmac::<sha2::Sha512>::new_from_slice(&chain_code).unwrap();

        hmac_hasher.update(public_key_par.to_encoded_point(true).as_bytes());

        hmac_hasher.update(&index_child.to_bits().to_be_bytes());
        let hashout = hmac_hasher.finalize().into_bytes();
        u8_vec_to_bool_vec(&hashout)
            .map(|bit| builder.constant(bit))
            .collect()
    };

    let mut left = hmac_outputs[..256].to_vec();
    left.reverse();

    let mut parent_key = key_par_ids.clone();
    parent_key.reverse();

    let add_circ = build_mod_add_circut(256, SECP256_K1_Q);
    let out = builder.add_circuit(&add_circ, &[&parent_key, &left]);

    hmac_outputs[..256].copy_from_slice(&out);

    for i in hmac_outputs {
        builder.output(i);
    }

    builder.finish()
}

/// Returns a hmac circuit which takes `key_length` bits of key and `message_length` bits of messages
/// The key bits are the garbler's inputs and the message bits are the evaluator's inputs
pub fn build_hmac_512_circuit(
    key_length: usize,
    message_length: usize,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let key_ids = builder.new_inputs(key_length as u16);
    let msg_ids = builder.new_inputs(message_length as u16);

    let mut resized_key_ids;
    if key_length > 1024 {
        let sha_circuit = build_sha512_circuit(key_length as u128);
        resized_key_ids = builder.add_circuit(&sha_circuit, &[&key_ids]);
    } else {
        resized_key_ids = key_ids;
    }
    for _ in resized_key_ids.len()..1024 {
        resized_key_ids.push(builder.constant(false));
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
    let inner_hash_ids = builder.add_circuit(&innersha, &[&inner_msg]);

    let mut outer_msg = o_key_pad_ids.clone();
    outer_msg.extend_from_slice(&inner_hash_ids);

    let outersha = build_sha512_circuit(outer_msg.len() as u128);
    let output_ids = builder.add_circuit(&outersha, &[&outer_msg]);

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

    let inputs = builder.new_inputs(len as u16);

    let mut padded = inputs.clone();

    for i in pad {
        let inp = if i {
            builder.constant(true)
        } else {
            builder.constant(false)
        };

        padded.push(inp);
    }

    let chaining_state = get_512_chain_state();

    let mut chain_input = vec![];

    for i in 0..chaining_state.length as usize {
        let inp = if chaining_state.get(i) {
            builder.constant(true)
        } else {
            builder.constant(false)
        };
        chain_input.push(inp);
    }

    let count = padded.len() / 1024;

    let sha512_circuit = prebuilt::sha512();

    for i in 0..count {
        let mut block_inp = padded[1024 * i..1024 * (i + 1)].to_vec();
        block_inp.reverse();

        chain_input =
            builder.add_circuit(sha512_circuit, &[&block_inp, &chain_input]);
    }

    chain_input.reverse();

    for i in chain_input {
        builder.output(i);
    }

    builder.finish()
}

pub fn build_scalar_rss_to_y_verification_circuit() -> BinaryCircuit {
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

    let circ = build_mod_add_circut(p1_next.len(), SECP256_K1_Q);

    let temp = builder.add_circuit(&circ, &[&p1_next, &p2_next]);
    let res3_ids = builder.add_circuit(&circ, &[&temp, &p3_next]);

    builder.output(output);
    (0..256).for_each(|i| {
        builder.output(res3_ids[i]);
    });

    builder.finish()
}

pub fn build_scalar_rss_to_y_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let x1_ids = builder.new_inputs(256);
    let x2_ids = builder.new_inputs(256);
    let x3_ids = builder.new_inputs(256);

    let circ = build_mod_add_circut(x1_ids.len(), SECP256_K1_Q);

    let temp = builder.add_circuit(&circ, &[&x1_ids, &x2_ids]);
    let res3_ids = builder.add_circuit(&circ, &[&temp, &x3_ids]);

    (0..256).for_each(|i| {
        builder.output(res3_ids[i]);
    });

    builder.finish()
}

pub use garbled_circuit::arithmetic::build_compare_eq_circuit;
pub use garbled_circuit::arithmetic::build_compare_ge_circuit;
pub use garbled_circuit::arithmetic::build_compare_ge_rec_circuit;
pub use garbled_circuit::arithmetic::build_if_then_else_circuit;
pub use garbled_circuit::arithmetic::build_ppa_circuit;

pub fn build_verify_sharings_circuit() -> BinaryCircuit {
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

    builder.output(output);
    builder.finish()
}

/// Returns the `BinaryCircuit` which implements addition modulo a constant `prime` of two
///  binary values of bit length `size`
///
/// The first input is set as the gabler's input and the next input is
/// set as the evaluator's input
pub fn build_mod_add_circut(size: usize, prime: U256) -> BinaryCircuit {
    arithmetic::build_mod_add_circut(size, &prime.to_le_bytes())
}

/// Returns the `BinaryCircuit` which implements subtraction of a binary value of
/// bit length `size` by a constant `prime`.
///
/// The input is set as the garbler's input
pub fn build_subtract_order_circuit(
    size: usize,
    prime: U256,
) -> BinaryCircuit {
    arithmetic::build_subtract_order_circuit(size, &prime.to_le_bytes())
}
