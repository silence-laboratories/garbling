use criterion::{criterion_group, criterion_main, Criterion};
use garbled_circuit::{
    circuitop::circuit::BinaryCircuit,
    config::constants::AES_KEY,
    garbling2pc::{evaluator_operations::BinaryEvaluator, garbler_operations::BinaryGarbler},
    utilities::hash_function::AesHash,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub fn eval_aes256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Preprocess");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    let circuit = BinaryCircuit::parse("circuits/aes256.txt").unwrap();
    let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
    let garble_out = garbler.garble(&circuit).unwrap();
    let garbler_inputs = garbler.get_garbled_inputs(
        circuit.clone(),
        [false; 256].as_slice(),
        garble_out.garbler_input_encodings.clone(),
    );
    group.bench_function("aes256_eval", |b| {
        b.iter(|| {
            let mut evaluator = BinaryEvaluator::new(
                garble_out.evaluator_input_encodings.clone(),
                garble_out.decoding_infos.clone(),
                garbler.delta,
                AesHash::new(AES_KEY),
                garble_out.garbled_circuit.clone(),
            );
            evaluator
                .evaluate(&circuit, &garbler_inputs, [false; 128].as_slice())
                .unwrap();
        })
    });
    group.finish();
}

pub fn eval_aes128_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Preprocess");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    let circuit = BinaryCircuit::parse("circuits/aes128.txt").unwrap();
    let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
    let garble_out = garbler.garble(&circuit).unwrap();
    let garbler_inputs = garbler.get_garbled_inputs(
        circuit.clone(),
        [false; 128].as_slice(),
        garble_out.garbler_input_encodings.clone(),
    );
    group.bench_function("aes128_eval", |b| {
        b.iter(|| {
            let mut evaluator = BinaryEvaluator::new(
                garble_out.evaluator_input_encodings.clone(),
                garble_out.decoding_infos.clone(),
                garbler.delta,
                AesHash::new(AES_KEY),
                garble_out.garbled_circuit.clone(),
            );
            evaluator
                .evaluate(&circuit, &garbler_inputs, [false; 128].as_slice())
                .unwrap();
        })
    });
    group.finish();
}

pub fn eval_sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Preprocess");
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

    let circuit = BinaryCircuit::parse("circuits/sha256.txt").unwrap();
    let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY), &mut rng);
    let garble_out = garbler.garble(&circuit).unwrap();
    let garbler_inputs = garbler.get_garbled_inputs(
        circuit.clone(),
        [false; 512].as_slice(),
        garble_out.garbler_input_encodings.clone(),
    );
    group.bench_function("sha256_eval", |b| {
        b.iter(|| {
            let mut evaluator = BinaryEvaluator::new(
                garble_out.evaluator_input_encodings.clone(),
                garble_out.decoding_infos.clone(),
                garbler.delta,
                AesHash::new(AES_KEY),
                garble_out.garbled_circuit.clone(),
            );
            evaluator
                .evaluate(&circuit, &garbler_inputs, [false; 256].as_slice())
                .unwrap();
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
