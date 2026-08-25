// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use criterion::{Criterion, criterion_group, criterion_main};
use garbled_circuit::{
    functionality::{
        evaluate::evaluate_functionality, garble::garble_functionality,
    },
    utilities::{
        garble_hash::AesGarbleHash,
        types::{
            BLOCK_SIZE, Block, GarblerSetup, YaoEvaluatorShare,
            YaoGarblerShare, YaoShare,
        },
    },
};
use rand::{RngCore, SeedableRng, prelude::*};
use rand_chacha::ChaCha8Rng;
use zcash::blake2b::create_blake2b_circuit;
pub const AES_KEY: Block = [1u8; BLOCK_SIZE];

pub fn garb_blake2b_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");

    let circuit = create_blake2b_circuit(1024);

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

    group.bench_function("blake2b_garble", |b| {
        b.iter(|| {
            let _: (_, HashMap<u32, YaoShare>) = garble_functionality(
                &circuit,
                &gin,
                &mut GarblerSetup {
                    delta,
                    comm_crs: Block::default(),
                    garble_key: Block::default(),
                    prf: ChaCha8Rng::from_seed([0; 32]),
                    party_id: 0,
                },
                &hash,
            );
        })
    });

    group.finish();
}

pub fn eval_blake2b_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 6400 AND Gates
    let circuit = create_blake2b_circuit(1024);

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
            garble_key: Block::default(),
            party_id: 0,
        },
        &hash,
    );
    println!("{}", gc.len());
    group.bench_function("blake2b_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality::<YaoEvaluatorShare, _>(
                &circuit, &ein, &gc, &hash,
            )
            .unwrap();
        })
    });
    group.finish();
}

criterion_group!(benches, garb_blake2b_benchmark, eval_blake2b_benchmark,);
criterion_main!(benches);
