// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Derived from `bonk-dev/HarpoS7` (MIT) — the `HarpoS7.Family0` project, which
// implements the legacy (non-TLS) S7CommPlus auth for REAL S7-1200/1500 hardware
// (public-key families `00:` = S7-1500 and `01:` = S7-1200). See `LICENSE-HarpoS7`.
// What HarpoS7's decompiled "monolith" transforms compute was identified in
// `gijzelaerr/s7commplus` (MIT; see `curve`, `present` and `seed`).

//! Family-0 legacy auth: the real-hardware (S7-1200/1500) key agreement.
//!
//! Where the shipped [`crate::legacy`] PLCSIM path uses the family-`03:` (VPLC) key over
//! NIST P-256, real S7-1200/1500 units below the TLS firmware floor use the `00:`/`01:` key
//! families: an x-only ECDH on a 160-bit curve over `GF(2^160 - 47)`, and a PRESENT-80
//! variant for the pre-seed and key derivation.
//!
//! - [`curve`] — the curve and its x-only Montgomery ladder.
//! - [`present`] — the PRESENT-80 variant.
//! - [`seed`] — `PreSeedTransform`, `SeedTransform` (the ECDH-masked seed) and
//!   `KeyDerivationTransform`.
//! - [`checksum`]/[`cipher`] — the blob body's AES keystream and GF(2^128) checksum.
//! - [`blob`]/[`auth`] — `RealPlcAuthenticator` blob assembly + `DeriveSessionKey`,
//!   validated against the byte-exact `AuthenticateRealPlc` (S71500) / FamilyOne (S71200)
//!   vectors. This is the live path behind `Connection::connect_real_plc`.

pub mod auth;
pub mod blob;
pub mod checksum;
pub mod cipher;
pub mod curve;
pub mod present;
pub mod seed;
