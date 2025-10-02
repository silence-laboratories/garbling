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
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 8832 AND Gates
    let circuit = BinaryCircuit::parse("circuits/aes256.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let zero = Block::default();
    let gin: Vec<Vec<YaoGarblerShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoGarblerShare {
                    delta,
                    f_label: zero,
                })
                .collect()
        })
        .collect();

    let ein: Vec<Vec<YaoEvaluatorShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoEvaluatorShare { label: zero })
                .collect()
        })
        .collect();

    let (gc, _) = garble_functionality(
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
    group.bench_function("aes256_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality(&circuit, &ein, &gc, &hash);
        })
    });
    group.finish();
}

pub fn eval_aes128_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 6400 AND Gates
    let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();

    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let zero = Block::default();
    let gin: Vec<Vec<YaoGarblerShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoGarblerShare {
                    delta,
                    f_label: zero,
                })
                .collect()
        })
        .collect();

    let ein: Vec<Vec<YaoEvaluatorShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoEvaluatorShare { label: zero })
                .collect()
        })
        .collect();

    let (gc, _) = garble_functionality(
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
    group.bench_function("aes128_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality(&circuit, &ein, &gc, &hash);
        })
    });
    group.finish();
}

pub fn eval_sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evaluate");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    // 22573 AND Gates
    let circuit = BinaryCircuit::parse("circuits/sha256.txt").unwrap();
    let mut delta = Block::default();
    rng.fill_bytes(&mut delta);

    let hash = AesGarbleHash::new(AES_KEY);

    let zero = Block::default();
    let gin: Vec<Vec<YaoGarblerShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoGarblerShare {
                    delta,
                    f_label: zero,
                })
                .collect()
        })
        .collect();

    let ein: Vec<Vec<YaoEvaluatorShare>> = circuit
        .get_input_ids()
        .iter()
        .map(|v| {
            v.iter()
                .map(|_| YaoEvaluatorShare { label: zero })
                .collect()
        })
        .collect();

    let (gc, _) = garble_functionality(
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
    group.bench_function("sha256_eval", |b| {
        b.iter(|| {
            let _ = evaluate_functionality(&circuit, &ein, &gc, &hash);
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
