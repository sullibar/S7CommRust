// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver (C#), LGPL-3.0-or-later.

//! Crate-wide error type.

use std::io;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the driver.
///
/// Marked `#[non_exhaustive]`: match with a wildcard arm, as new variants may be added in
/// future releases without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying socket / I/O failure.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// TLS-layer failure (handshake, record processing, keying-material export).
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    /// A received TPKT/COTP frame was malformed or unexpected.
    #[error("framing error: {0}")]
    Framing(String),

    /// A received S7CommPlus PDU was malformed or unexpected.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A VLQ value in a received telegram was malformed or cut off.
    #[error("malformed VLQ: {0}")]
    Vlq(String),

    /// A cryptographic operation failed (key/IV length, padding, etc.).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// A received telegram failed its integrity check: on the legacy (non-TLS) transport, a
    /// response chunk's digest didn't match or was missing. The telegram can't be trusted, so
    /// the connection is poisoned; reconnect.
    #[error("integrity check failed: {0}")]
    Integrity(String),

    /// The connection is no longer usable: a prior request/response failed partway through
    /// (e.g. the socket dropped mid-telegram), so the sequence-number / integrity-id state is
    /// out of sync with the PLC. The connection is "poisoned" and every subsequent request
    /// returns this error — the caller must drop it and reconnect.
    #[error("connection closed: {0}")]
    Closed(String),
}

impl Error {
    pub(crate) fn framing(msg: impl Into<String>) -> Self {
        Error::Framing(msg.into())
    }

    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }

    pub(crate) fn closed(msg: impl Into<String>) -> Self {
        Error::Closed(msg.into())
    }

    pub(crate) fn integrity(msg: impl Into<String>) -> Self {
        Error::Integrity(msg.into())
    }

    /// Map an I/O error raised while decoding an in-memory telegram. Running out of input there
    /// means the telegram is malformed or truncated — not that the connection was lost.
    pub(crate) fn decode(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::protocol("telegram truncated: unexpected end of data")
        } else {
            Error::Io(e)
        }
    }

    /// Whether this error is a plain socket read timeout: nothing (more) arrived in time, and the
    /// connection stays usable — retry the operation. Only waiting for a notification
    /// (`Connection::next_notification`) returns this; a request whose response does not arrive
    /// in time poisons the connection and fails with [`Error::Closed`] instead.
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            Error::Io(io) if matches!(
                io.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
        )
    }

    /// Whether this error means the connection is no longer usable and must be reconnected:
    /// a socket or TLS failure, a malformed TPKT/COTP/chunk frame (the byte stream is out of
    /// step), a telegram that failed its integrity check, or a poisoned connection. A bare
    /// timeout is *not* a lost connection (see [`Error::is_timeout`]), and neither is a PLC
    /// refusing a request or a response that fails to decode.
    pub fn is_connection_lost(&self) -> bool {
        match self {
            Error::Closed(_) | Error::Tls(_) | Error::Framing(_) | Error::Integrity(_) => true,
            Error::Io(_) => !self.is_timeout(),
            _ => false,
        }
    }
}
