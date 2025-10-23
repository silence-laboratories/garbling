// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use garbled_circuit::{
    circuitop::circuit::BinaryCircuit,
    config::constants::{
        AES128_CIRCUIT, AES256_CIRCUIT, AES_KEY, SHA256_CIRCUIT,
    },
    functionality::garble::garble_functionality,
    utilities::{
        garble_hash::AesGarbleHash,
        types::{Block, GarblerSetup, YaoGarblerShare, YaoShare},
    },
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub fn garble_aes256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Garble");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 8832 AND Gates
    let circuit = BinaryCircuit::parse(AES256_CIRCUIT).unwrap();

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
    group.bench_function("aes256_garble", |b| {
        b.iter(|| {
            let _: (_, HashMap<u32, YaoShare>) = garble_functionality(
                &circuit,
                &gin,
                &GarblerSetup {
                    delta,
                    comm_crs: Block::default(),
                    prf_key: [0u8; 32],
                },
                &mut rng,
                &hash,
            );
        })
    });

    group.finish();
}

pub fn garble_aes128_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Garble");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 6400 AND Gates
    let circuit = BinaryCircuit::parse(AES128_CIRCUIT).unwrap();

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
    group.bench_function("aes128_garble", |b| {
        b.iter(|| {
            let _: (_, HashMap<u32, YaoShare>) = garble_functionality(
                &circuit,
                &gin,
                &GarblerSetup {
                    delta,
                    comm_crs: Block::default(),
                    prf_key: [0u8; 32],
                },
                &mut rng,
                &hash,
            );
        })
    });
    group.finish();
}

pub fn garble_sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Garble");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 22573 AND Gates
    let circuit = BinaryCircuit::parse(SHA256_CIRCUIT).unwrap();

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
    group.bench_function("sha256_garble", |b| {
        b.iter(|| {
            let _: (_, HashMap<u32, YaoShare>) = garble_functionality(
                &circuit,
                &gin,
                &GarblerSetup {
                    delta,
                    comm_crs: Block::default(),
                    prf_key: [0u8; 32],
                },
                &mut rng,
                &hash,
            );
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    garble_aes256_benchmark,
    garble_aes128_benchmark,
    garble_sha256_benchmark
);
criterion_main!(benches);
