use criterion::{criterion_group, criterion_main, Criterion};
use garbled_circuit::{
    circuitop::circuit::BinaryCircuit, config::constants::AES_KEY,
    garbling2pc::garbler_operations::BinaryGarbler, utilities::hash_function::AesHash,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub fn garble_aes256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Preprocess");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    let circuit = BinaryCircuit::parse("circuits/aes256.txt").unwrap();
    group.bench_function("aes256_garble", |b| {
        b.iter(|| {
            let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
            garbler.garble(&circuit).unwrap();
        })
    });
    group.finish();
}

pub fn garble_aes128_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Preprocess");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();
    group.bench_function("aes128_garble", |b| {
        b.iter(|| {
            let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
            garbler.garble(&circuit).unwrap();
        })
    });
    group.finish();
}

pub fn garble_sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Preprocess");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    let circuit = BinaryCircuit::parse("circuits/sha256.txt").unwrap();
    group.bench_function("sha256_garble", |b| {
        b.iter(|| {
            let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
            garbler.garble(&circuit).unwrap();
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
