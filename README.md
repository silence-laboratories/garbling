# Garbling Library

This library implements the garbler and evaluator for two-party
semi-honest and three-party malicious garbled-circuit protocols, based
on [[ZRE15]](https://eprint.iacr.org/2014/756.pdf) and
[[MRZ15]](https://eprint.iacr.org/2015/931.pdf). It does **not**
include the oblivious transfer protocols required for input label
sharing in the two-party semi-honest case.

### Crate Layout

The public modules exposed by `src/lib.rs` are:

- **`circuit`**: Core Boolean-circuit representation.
  - Defines `BinaryCircuit`, `BinaryGate`, and `CircuitBuilder`.
  - Supports parsing Bristol Fashion circuits from text.
  - Includes `circuit::prebuilt` for build-time embedded circuit artifacts.
- **`arithmetic`**: Programmatically built arithmetic circuits.
  - Provides reusable circuit builders such as modular addition, subtraction,
    comparisons, and batched conditional selection.
- **`comparison`**: Comparison-related circuit helpers exposed at the crate
  root.
- **`circuitop`**: Compatibility shim for the older module layout.
  - Re-exports the circuit types under the previous paths
    (`circuitop::circuit`, `circuitop::circuit_builder`,
    `circuitop::gate`, `circuitop::prebuilt`).
- **`customcircuits`**: Compatibility shim for the previous custom-circuit
  layout.
  - Re-exports `arithmetic` and `comparison` under their legacy paths.
- **`config`**: Protocol constants and error types.
  - `constants`: message tags and test circuit constants.
  - `errors`: circuit parsing errors.
  - `util_errors`: utility/hash-related errors.
- **`utilities`**: Shared cryptographic helpers and types.
  - `hash_function`: AES-based hash trait and implementation.
  - `shahash`: SHA-512-based `HashFunction` implementation.
  - `garble_hash`: AES garbling hash utilities.
  - `commitments`: commitment trait and hash-based commitment scheme.
  - `types`: core Yao share/setup/block types.
  - `utils`: low-level block helpers.
- **`functionality`**: Protocol building blocks and higher-level Yao/garbling flows.
  - `setup`: setup for garbler/evaluator roles.
  - `input` / `output`: encode inputs and decode outputs.
  - `garble` / `evaluate`: plaintext garbling and evaluation over a `BinaryCircuit`.
  - `circuit_eval`: end-to-end circuit evaluation flow over a relay.
  - `b_to_y` / `y_to_b`: conversion between binary shares and Yao shares.
  - `utils` / `utils_dep`: relay helpers and protocol errors.

### Repository Layout

- **`circuits/`**: Checked-in Bristol Fashion circuit files (`aes128`,
  `aes256`, `binmult`, `blake2b`, `sha256`, `sha512`).
- **`build.rs`**: Converts `circuits/*.txt` into a compact private
  binary format embedded at build time and decoded by
  `BinaryCircuit::from_compact_bytes`.
- **`benches/`**: Criterion benchmarks for garbling and evaluation.

### Notes

- The old `circuitop` and `customcircuits` layouts are still available only as
  **compatibility re-exports**; the main implementations now live in
  **`circuit`**, **`arithmetic`**, and **`comparison`**.
- Hashing utilities follow the design used by
  [`fancy-garbling`](https://github.com/GaloisInc/swanky/tree/dev/edge/fancy-garbling)
  and the commitment implementation is a simple hash-based commitment.

### References

- [[ZRE15]](https://eprint.iacr.org/2014/756.pdf) — Zahur, S., Rosulek, M., Evans, D. (2015). Two Halves Make a Whole. In: Oswald, E., Fischlin, M. (eds) Advances in Cryptology - EUROCRYPT 2015. EUROCRYPT 2015. Lecture Notes in Computer Science(), vol 9057. Springer, Berlin, Heidelberg. https://doi.org/10.1007/978-3-662-46803-6_8.
- [[MRZ15]](https://eprint.iacr.org/2015/931.pdf) — Payman Mohassel, Mike Rosulek, and Ye Zhang. 2015. Fast and Secure Three-party Computation: The Garbled Circuit Approach. In Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security (CCS '15). Association for Computing Machinery, New York, NY, USA, 591–602. https://doi.org/10.1145/2810103.2813705.
- [[GKW+19]](https://eprint.iacr.org/2019/074.pdf) — C. Guo, J. Katz, X. Wang and Y. Yu, "Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers," 2020 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2020, pp. 825-841, doi: 10.1109/SP40000.2020.00016.
- [fancy-garbling](https://github.com/GaloisInc/swanky/tree/dev/edge/fancy-garbling) - https://github.com/GaloisInc/swanky/tree/dev/edge/fancy-garbling .
