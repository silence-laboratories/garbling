// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Circuit representation and construction utilities.
//!
//! This module contains the core Boolean-circuit data structures used by the
//! garbling code:
//! - [`circuit`] defines the owned circuit representation.
//! - [`circuit_builder`] provides a builder for constructing and composing
//!   circuits.
//! - [`gate`] defines the individual gate variants stored inside a circuit.

pub mod circuit;

pub mod circuit_builder;

pub mod gate;
