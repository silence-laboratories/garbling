use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use garbled_circuit::{
    circuitop::circuit::BinaryCircuit,
    config::constants::AES_KEY,
    functionality::{evaluate::evaluate_functionality, garble::garble_functionality},
    utilities::{
        garble_hash::AesGarbleHash,
        types::{Block, GarblerSetup, YaoEvaluatorShare, YaoGarblerShare},
    },
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub fn eval_aes256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed(Block::default());

    // 8832 AND Gates
    let circuit = BinaryCircuit::parse("circuits/aes256.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let mut ggarin = HashMap::new();
    let mut gevain = HashMap::new();
    let mut egarin = HashMap::new();
    let mut eevain = HashMap::new();

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
        egarin.insert(*ind, YaoEvaluatorShare { label: zero });
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
        eevain.insert(*ind, YaoEvaluatorShare { label: zero });
    }

    let (gc, _) = garble_functionality(
        &circuit,
        &ggarin,
        &gevain,
        &GarblerSetup {
            delta,
            comm_crs: Block::default(),
            prf_key: Block::default(),
        },
        &mut rng,
        &hash,
    );
    group.bench_function("aes256_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality(&circuit, &egarin, &eevain, &gc, &hash);
        })
    });
    group.finish();
}

pub fn eval_aes128_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed(Block::default());

    // 6400 AND Gates
    let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let mut ggarin = HashMap::new();
    let mut gevain = HashMap::new();
    let mut egarin = HashMap::new();
    let mut eevain = HashMap::new();

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
        egarin.insert(*ind, YaoEvaluatorShare { label: zero });
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
        eevain.insert(*ind, YaoEvaluatorShare { label: zero });
    }

    let (gc, _) = garble_functionality(
        &circuit,
        &ggarin,
        &gevain,
        &GarblerSetup {
            delta,
            comm_crs: Block::default(),
            prf_key: Block::default(),
        },
        &mut rng,
        &hash,
    );
    group.bench_function("aes128_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality(&circuit, &egarin, &eevain, &gc, &hash);
        })
    });
    group.finish();
}

pub fn eval_sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed(Block::default());

    // 22573 AND Gates
    let circuit = BinaryCircuit::parse("circuits/sha256.txt").unwrap();
    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let mut ggarin = HashMap::new();
    let mut gevain = HashMap::new();
    let mut egarin = HashMap::new();
    let mut eevain = HashMap::new();

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
        egarin.insert(*ind, YaoEvaluatorShare { label: zero });
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
        eevain.insert(*ind, YaoEvaluatorShare { label: zero });
    }

    let (gc, _) = garble_functionality(
        &circuit,
        &ggarin,
        &gevain,
        &GarblerSetup {
            delta,
            comm_crs: Block::default(),
            prf_key: Block::default(),
        },
        &mut rng,
        &hash,
    );
    group.bench_function("sha256_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality(&circuit, &egarin, &eevain, &gc, &hash);
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
