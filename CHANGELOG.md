# Changelog

All notable changes to this repository will be documented in this file.

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
- Switched `hd-migration` SHA-512 circuit loading to use prebuilt compact
  assets.
- Simplified circuit constant handling from integer sentinels to `bool` in
  `BinaryGate`, `BinaryCircuit`, and `CircuitBuilder`.
- Generalized `hd-migration` bit and byte conversion helpers to accept
  borrowed and iterator-based inputs.
- Made `hd-migration::utils` internal to the crate.
