use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use garbled_circuit::{
    circuitop::circuit::BinaryCircuit,
    config::constants::AES_KEY,
    functionality::garble::garble_functionality,
    utilities::{
        garble_hash::AesGarbleHash,
        types::{Block, GarblerSetup, YaoGarblerShare},
    },
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub fn garble_aes256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Garble");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 8832 AND Gates
    let circuit = BinaryCircuit::parse("circuits/aes256.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let mut ggarin = HashMap::new();
    let mut gevain = HashMap::new();

    for ind in &circuit.garbler_input_ids {
        let mut zero = Block::default();
        rng.fill_bytes(&mut zero);
        ggarin.insert(
            *ind,
            YaoGarblerShare {
                delta,
                f_label: zero,
            },
        );
    }

    for ind in &circuit.garbler_input_ids {
        let mut zero = Block::default();
        rng.fill_bytes(&mut zero);
        gevain.insert(
            *ind,
            YaoGarblerShare {
                delta,
                f_label: zero,
            },
        );
    }
    group.bench_function("aes256_garble", |b| {
        b.iter(|| {
            let _ = garble_functionality(
                &circuit,
                &ggarin,
                &gevain,
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
    let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let mut ggarin = HashMap::new();
    let mut gevain = HashMap::new();

    for ind in &circuit.garbler_input_ids {
        let mut zero = Block::default();
        rng.fill_bytes(&mut zero);
        ggarin.insert(
            *ind,
            YaoGarblerShare {
                delta,
                f_label: zero,
            },
        );
    }

    for ind in &circuit.garbler_input_ids {
        let mut zero = Block::default();
        rng.fill_bytes(&mut zero);
        gevain.insert(
            *ind,
            YaoGarblerShare {
                delta,
                f_label: zero,
            },
        );
    }
    group.bench_function("aes128_garble", |b| {
        b.iter(|| {
            let _ = garble_functionality(
                &circuit,
                &ggarin,
                &gevain,
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
    let circuit = BinaryCircuit::parse("circuits/sha256.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let mut ggarin = HashMap::new();
    let mut gevain = HashMap::new();

    for ind in &circuit.garbler_input_ids {
        let mut zero = Block::default();
        rng.fill_bytes(&mut zero);
        ggarin.insert(
            *ind,
            YaoGarblerShare {
                delta,
                f_label: zero,
            },
        );
    }

    for ind in &circuit.garbler_input_ids {
        let mut zero = Block::default();
        rng.fill_bytes(&mut zero);
        gevain.insert(
            *ind,
            YaoGarblerShare {
                delta,
                f_label: zero,
            },
        );
    }
    group.bench_function("sha256_garble", |b| {
        b.iter(|| {
            let _ = garble_functionality(
                &circuit,
                &ggarin,
                &gevain,
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
