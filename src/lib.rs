// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver (C#), LGPL-3.0-or-later.

// Every public item must be documented (lib-scoped; `unsafe_code` is forbidden crate-wide via
// Cargo.toml's [lints] table).
#![deny(missing_docs)]

//! A Rust port of the [S7CommPlusDriver] for the proprietary Siemens S7CommPlus
//! protocol used by S7-1200 / S7-1500 PLCs. It speaks the modern, TLS-wrapped
//! dialect and — via [`Connection::connect_legacy`] — the older, non-TLS
//! integrity-protected scheme, so a single API reaches both current and legacy
//! firmware.
//!
//! [S7CommPlusDriver]: https://github.com/thomas-v2/S7CommPlusDriver
//!
//! # Quick start
//!
//! ```no_run
//! use std::time::Duration;
//! use s7commplus::{Connection, value::PValue};
//!
//! # fn main() -> s7commplus::Result<()> {
//! // TLS 1.3 handshake and session setup all happen inside `connect`.
//! let mut plc = Connection::connect("192.168.0.1:102", Duration::from_secs(10))?;
//!
//! // Read and write symbolic ("optimized") tags by name.
//! let value = plc.read_tag("Data_block_1.titi")?;
//! plc.write_tag("Data_block_1.titi", PValue::Int(456))?;
//! # let _ = value;
//! # Ok(())
//! # }
//! ```
//!
//! # What it does
//!
//! Everything hangs off [`Connection`]:
//!
//! - **Connect** — [`Connection::connect`] (TLS) or [`Connection::connect_legacy`]
//!   (older firmware); the TLS handshake, session, and setup are handled internally.
//!   [`Connection::close`] ends the session; after a failure, [`Connection::reconnect`].
//! - **Browse** — [`Connection::datablock_list`], [`Connection::explore`], and
//!   [`Connection::type_info`] walk the symbolic address space.
//! - **Read / write tags by name** — [`Connection::read_tag`] /
//!   [`Connection::write_tag`] (and the batched [`Connection::read_tags`] /
//!   [`Connection::write_tags`]) resolve a symbol to its address for you.
//! - **Subscriptions & alarms** — [`Connection::subscribe`] and
//!   [`Connection::subscribe_alarms`] register for the PLC's `0x33` push
//!   [`Notification`]s; [`Alarm`] parses and formats alarm events.
//! - **Legitimation** — [`Connection::legitimate`] authenticates against a
//!   password-protected program.
//!
//! Values move through the [`value::PValue`] type system (~90 PLC datatypes).
//!
//! # Module layout
//!
//! - [`transport`] — TCP + TPKT/COTP framing and the rustls TLS pump.
//! - [`wire`] — VLQ codec and S7CommPlus PDU framing.
//! - [`proto`] — request/response objects, subscriptions, notifications, alarms.
//! - [`value`] — the `PValue` datatype system and (de)serialization.
//! - [`legitimation`] — the crypto and flow for authenticating to the PLC.
//! - [`optimized`] — zlib preset-dictionary inflate of type-metadata blobs.
//!
//! The non-TLS integrity-protected path for older firmware is internal; reach it through
//! [`Connection::connect_legacy`] / [`Connection::connect_real_plc`].

pub mod connection;
pub mod error;
pub mod legitimation;
pub mod optimized;
pub mod proto;
pub mod transport;
pub mod value;
pub mod wire;

// Non-TLS legacy dialect — internal implementation behind `Connection::connect_legacy`.
pub(crate) mod legacy;
mod logging;

// Test-only: a mock legacy PLC on loopback, scripted per test or driven by firmware profiles.
#[cfg(test)]
mod mock_plc;

pub use connection::{Connection, CpuState, DataBlock, Subscription, VarInfo};
pub use error::{Error, Result};
pub use logging::set_log_redaction;
pub use optimized::decompress_blob;
pub use proto::{
    Alarm, AlarmState, AlarmText, Area, AssociatedValue, Notification, SubscriptionItem,
    SystemEvent,
};

/// This crate's version, for logs and bug reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
