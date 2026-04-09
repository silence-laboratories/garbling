// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use garbled_circuit::{
    circuitop::{circuit::BinaryCircuit, prebuilt},
    functionality::{
        evaluate::evaluate_functionality, garble::garble_functionality,
    },
    utilities::{
        garble_hash::AesGarbleHash,
        types::{
            Block, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare,
            YaoShare, BLOCK_SIZE,
        },
    },
};
use rand::{prelude::*, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub const AES_KEY: Block = [1u8; BLOCK_SIZE];

fn aes128_circuit() -> BinaryCircuit {
    prebuilt::decode(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/circuits/aes128.bin"
    )))
}

fn aes256_circuit() -> BinaryCircuit {
    prebuilt::decode(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/circuits/aes256.bin"
    )))
}

fn sha256_circuit() -> BinaryCircuit {
    prebuilt::decode(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/circuits/sha256.bin"
    )))
}

pub fn eval_aes256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");

    // 8832 AND Gates
    let circuit = aes256_circuit();

    let delta = random();

    let hash = AesGarbleHash::new(AES_KEY);

    let zero = Block::default();
    let gin: Vec<Vec<_>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoGarblerShare {
                    delta,
                    f_label: zero,
                })
                .map(From::from)
                .collect()
        })
        .collect();

    let ein: Vec<Vec<YaoShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoEvaluatorShare { label: zero })
                .map(|s| s.into())
                .collect()
        })
        .collect();

    let (gc, _): (_, HashMap<u32, YaoShare>) = garble_functionality(
        &circuit,
        &gin,
        &mut GarblerSetup {
            delta,
            comm_crs: Block::default(),
            prf: ChaCha8Rng::from_seed([0; 32]),
            party_id: 0,
        },
        &hash,
    );

    group.bench_function("aes256_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality::<YaoEvaluatorShare, _>(
                &circuit, &ein, &gc, &hash,
            );
        })
    });

    group.finish();
}

pub fn eval_aes128_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 6400 AND Gates
    let circuit = aes128_circuit();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let zero = Block::default();
    let gin: Vec<Vec<_>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoGarblerShare {
                    delta,
                    f_label: zero,
                })
                .map(From::from)
                .collect()
        })
        .collect();

    let ein: Vec<Vec<_>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoEvaluatorShare { label: zero })
                .map(From::from)
                .collect()
        })
        .collect();

    let (gc, _): (_, HashMap<u32, YaoShare>) = garble_functionality(
        &circuit,
        &gin,
        &mut GarblerSetup {
            delta,
            prf: ChaCha8Rng::from_seed([0; 32]),
            comm_crs: Block::default(),
            party_id: 0,
        },
        &hash,
    );
    group.bench_function("aes128_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality::<YaoEvaluatorShare, _>(
                &circuit, &ein, &gc, &hash,
            );
        })
    });
    group.finish();
}

pub fn eval_sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 22573 AND Gates
    let circuit = sha256_circuit();
    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let zero = Block::default();
    let gin: Vec<Vec<_>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoGarblerShare {
                    delta,
                    f_label: zero,
                })
                .map(From::from)
                .collect()
        })
        .collect();

    let ein: Vec<Vec<_>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoEvaluatorShare { label: zero })
                .map(From::from)
                .collect()
        })
        .collect();

    let (gc, _): (_, HashMap<u32, YaoShare>) = garble_functionality(
        &circuit,
        &gin,
        &mut GarblerSetup {
            delta,
            comm_crs: Block::default(),
            prf: ChaCha8Rng::from_seed([0; 32]),
            party_id: 0,
        },
        &hash,
    );
    group.bench_function("sha256_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality::<YaoEvaluatorShare, _>(
                &circuit, &ein, &gc, &hash,
            );
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    eval_aes256_benchmark,
    eval_aes128_benchmark,
    eval_sha256_benchmark
);
criterion_main!(benches);
