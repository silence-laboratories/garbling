# Changelog

All notable changes to the `garbled-circuit` crate will be documented in this
file.

## [Unreleased]

## [1.3.1-pre.1] - 2026-05-04

### Added

- Added the new public `garbled_circuit::arithmetic` module for shared
  arithmetic circuit builders.
- Added the new public `garbled_circuit::comparison` module at the crate root.
- Added a test-only `BinaryCircuit::evaluate()` helper behind the `test` and
  `test-support` cfgs for plain Boolean circuit evaluation.

### Changed

- Moved shared arithmetic circuit builders from downstream crates into
  `garbled-circuit`, with `customcircuits` retained as a compatibility shim.
- Moved the generic modular-addition test into `garbled-circuit` so the shared
  arithmetic builders are tested at their implementation point.
- Stopped re-exporting `NoSignature`, `NoSigningKey`, and `NoVerifyingKey`
  from `functionality::utils`; callers now import those no-op key types from
  `sl-messages` directly.

## [1.3.0] - 2026-04-13

### Changed

- Released `garbled-circuit` as `1.3.0`.

## [1.3.0-pre.2] - 2026-04-10

### Added

- Added compatibility re-exports for the previous `circuitop` public module
  layout, including `circuitop::circuit_builder::CircuitBuilder`.

### Changed

- Merged the `circuitop` implementation into the new top-level `circuit`
  module, with prebuilt circuit helpers living in `circuit::prebuilt`.
- Made `BinaryCircuit` opaque by hiding its fields and removing its public
  mutation-oriented construction path.
- Consolidated circuit construction around `BinaryCircuit::parse()`,
  embedded prebuilt assets, and `CircuitBuilder::finish()`.
- Simplified `BinaryCircuit` constant tracking to dedicated `true` and `false`
  wire slots instead of a map.
- Updated internal callers, tests, and benchmarks to use the new `circuit`
  module paths and `BinaryCircuit` accessor methods.

## [1.3.0-pre.1] - 2026-04-10

### Added

- Added `build.rs` to compile checked-in Bristol circuit files in `circuits/`
  into compact binary artifacts during the Cargo build.
- Added compact circuit decoding support in `BinaryCircuit`.
- Added `circuitop::prebuilt` helpers for embedded prebuilt circuit assets.
- Added documentation for the trust boundary between `build.rs` and
  `BinaryCircuit::from_compact_bytes()`.

### Changed

- Switched large circuit consumers in tests and benchmarks from reparsing text
  circuits at runtime to loading generated compact assets with `include_bytes!`.
- Simplified circuit constant handling from integer sentinels to `bool` in
  `BinaryGate`, `BinaryCircuit`, and `CircuitBuilder`.

[Unreleased]: https://github.com/silence-laboratories/garbling/compare/garbled-circuit/v1.3.1-pre.1...HEAD
[1.3.1-pre.1]: https://github.com/silence-laboratories/garbling/compare/garbled-circuit/v1.3.0...garbled-circuit/v1.3.1-pre.1
[1.3.0]: https://github.com/silence-laboratories/garbling/compare/garbled-circuit/v1.3.0-pre.2...garbled-circuit/v1.3.0
[1.3.0-pre.2]: https://github.com/silence-laboratories/garbling/compare/garbled-circuit/v1.3.0-pre.1...garbled-circuit/v1.3.0-pre.2
[1.3.0-pre.1]: https://github.com/silence-laboratories/garbling/compare/garbled-circuit/v1.2.0...garbled-circuit/v1.3.0-pre.1
