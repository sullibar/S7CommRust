// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Ported from `bonk-dev/HarpoS7` (MIT) — the `HarpoS7.Family0` project, which
// implements the legacy (non-TLS) S7CommPlus auth for REAL S7-1200/1500 hardware
// (public-key families `00:` = S7-1500 and `01:` = S7-1200). See `LICENSE-HarpoS7`.
// Each ported file cites its specific HarpoS7 source.

//! Family-0 legacy auth: the real-hardware (S7-1200/1500) key-agreement.
//!
//! Where the shipped [`crate::legacy`] PLCSIM path uses the family-`03:` (VPLC)
//! key over NIST P-256, real S7-1200/1500 units below the TLS firmware floor use
//! the `00:`/`01:` key families over a **custom ~160-bit elliptic curve** on the
//! field `GF(p)`, `p = 2^160 - 47`. HarpoS7 ships this as decompiled "Monolith"
//! point-ops; this module ports those directly (the [`monolith`] submodule) rather
//! than reimplementing the curve, validating every layer against HarpoS7's golden
//! byte vectors.
//!
//! Layers (each offline-validated against `HarpoS7.Family0.Tests`):
//! - [`field`] — the packed radix-2^30 codec (`BigIntOperations`) + `GF(2^160-47)`
//!   arithmetic.
//! - [`monolith`] — the decompiled point-ops driving the scalar multiplications.
//! - [`transforms`]/[`transform7`]/[`seed`] — `PreSeedTransform`, `SeedTransform`
//!   (the ECIES-ish encrypted seed).
//! - [`blob`]/[`auth`] — `RealPlcAuthenticator` blob assembly + `DeriveSessionKey`,
//!   validated against the byte-exact `AuthenticateRealPlc` (S71500) / FamilyOne
//!   (S71200) vectors. This is the live path behind `Connection::connect_real_plc`.

pub mod auth;
pub mod blob;
pub mod checksum;
pub mod cipher;
pub mod curve;
#[cfg(test)] // the original monolith chain, kept as the differential-test reference
pub mod data;
#[cfg(test)]
pub mod field;
#[cfg(test)]
pub mod monolith;
pub mod present;
pub mod seed;
#[cfg(test)]
pub mod transform7;
#[cfg(test)]
pub mod transforms;
