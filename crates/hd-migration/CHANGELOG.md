# Changelog

All notable changes to the `hd-migration` crate will be documented in this
file.

## [Unreleased]

## [1.3.1-pre.1] - 2026-05-04

### Changed

- Switched local arithmetic circuit construction to the shared
  `garbled_circuit::arithmetic` builders instead of maintaining crate-local
  copies.
- Updated test helpers to import `NoSigningKey` and `NoVerifyingKey` directly
  from `sl-messages`.
