// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// The cryptographic pieces in this module are ported from `bonk-dev/HarpoS7`
// (https://github.com/bonk-dev/HarpoS7), which is MIT-licensed:
//
//   Copyright (c) 2024 bonk
//   Permission is hereby granted, free of charge, ... (MIT). The full notice is preserved
//   in `LICENSE-HarpoS7`. Each ported file cites its specific HarpoS7 source.

//! Legacy, non-TLS ("integrity-protected") S7CommPlus dialect — S7-1500 firmware below V2.9
//! (and S7-1200 below V4.3), engineered with TIA Portal V16 or older.
//!
//! Unlike the TLS path, the transport is plaintext. The sequence is: a normal `CreateObject`
//! (which the PLC answers with a per-session 20-byte challenge), then a key-agreement step
//! that delivers a random key to the PLC encrypted under the PLC's public key, from which
//! both sides derive a **session key**. Every PDU after `CreateObject` then carries an
//! HMAC-SHA256 **integrity digest** keyed by that session key.
//!
//! The key agreement is public-key-**family** specific: the **PLCSIM** family (`03:`, what
//! PLCSIM Advanced reports; [`session`]) and the real S7-1200/1500 hardware families
//! (`00:`/`01:`; `realplc` with the x-only ECDH + PRESENT-80 seed in `family0`).
//!
//! The pieces (the `digest` seam is public; the rest are internal):
//! - [`digest`] — the per-PDU integrity digest (HMAC-SHA256), validated against HarpoS7's
//!   golden vectors.
//! - `fingerprint` — the `f()` challenge fingerprint feeding the session-key derivation.
//! - `keys` — the session-key and related key-derivation functions.
//! - `aes` — the authenticated AES-CTR mode (CTR keystream + tabulation-hash tag) used to
//!   encrypt the key material into the blob.

// Public seam: only the pieces an out-of-crate caller legitimately reaches for. Everything
// else is implementation detail behind `Connection::connect_legacy`/`connect_real_plc`.
pub mod auth;
pub mod blob;
pub mod digest;

// Internal crypto/transport machinery — reachable across the crate, not part of the API.
pub(crate) mod aes;
pub(crate) mod family0;
pub(crate) mod fingerprint;
pub(crate) mod keys;
pub(crate) mod pubkey_store;
pub(crate) mod realplc;
pub(crate) mod seed;
pub(crate) mod session;

mod aes_consts;
mod seed_consts;
