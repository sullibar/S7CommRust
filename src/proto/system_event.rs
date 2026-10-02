// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/SystemEvent.cs, LGPL-3.0-or-later.

//! SystemEvent (protocol version `0xfe`) — the extended keep-alive telegrams the PLC/HMI send
//! (TIA V14+). They can arrive unsolicited between normal request/response exchanges, so the
//! receive path must recognize and skip them rather than mis-parse them as a response.
//!
//! Unlike every other function, SystemEvent fields are **fixed-width** (not VLQ). The body is
//! four `u32`s, optionally followed by a data value struct (only on errors / after DeleteObject)
//! or a raw message string (e.g. `"LOGOUT"`).

use std::io::Cursor;

use crate::error::Result;
use crate::value::datatype::tag as dt;
use crate::wire::pdu::{self, protocol_version};
use crate::wire::primitives as p;

/// A parsed SystemEvent keep-alive telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemEvent {
    /// Reserved header field.
    pub reserved1: u32,
    /// Bytes the peer confirms having received (flow-control hint).
    pub confirmed_bytes: u32,
    /// Reserved header field.
    pub reserved2: u32,
    /// Reserved header field.
    pub reserved3: u32,
    /// A data value struct is present (the PLC only sends this on error conditions).
    pub has_data: bool,
    /// An optional trailing message string (e.g. `"LOGOUT"` after a DeleteObject).
    pub message: Option<String>,
}

impl SystemEvent {
    /// Best-effort: a SystemEvent that carries a data struct signals an error condition (the PLC
    /// may be about to disconnect). Pure keep-alives and message-only events are not fatal.
    pub fn is_fatal(&self) -> bool {
        self.has_data
    }
}

/// True if `buf` is a SystemEvent telegram (protocol version `0xfe`).
pub fn is_system_event(buf: &[u8]) -> bool {
    pdu::parse_header(buf)
        .map(|h| h.protocol_version == protocol_version::SYSTEM_EVENT)
        .unwrap_or(false)
}

/// Parse a SystemEvent telegram (a framed PDU whose protocol version is `0xfe`).
pub fn parse_system_event(buf: &[u8]) -> Result<SystemEvent> {
    let h = pdu::parse_header(buf)?;
    let body = &buf[h.body_offset..h.body_end(buf)];
    let mut cur = Cursor::new(body);
    let reserved1 = p::decode_u32(&mut cur)?;
    let confirmed_bytes = p::decode_u32(&mut cur)?;
    let reserved2 = p::decode_u32(&mut cur)?;
    let reserved3 = p::decode_u32(&mut cur)?;

    let rest = &body[cur.position() as usize..];
    let mut has_data = false;
    let mut message = None;
    if rest.len() >= 2 && rest[0] == 0x00 && rest[1] == dt::STRUCT {
        // A fixed-width (non-VLQ) data value struct — carried only on errors; not decoded here.
        has_data = true;
    } else if !rest.is_empty() {
        message = Some(String::from_utf8_lossy(rest).into_owned());
    }
    Ok(SystemEvent {
        reserved1,
        confirmed_bytes,
        reserved2,
        reserved3,
        has_data,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::pdu::protocol_version;

    fn framed(body: &[u8]) -> Vec<u8> {
        pdu::frame_single_pdu(protocol_version::SYSTEM_EVENT, body)
    }

    #[test]
    fn detects_and_parses_keepalive() {
        // 16-byte keep-alive: four u32s, no data/message.
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&123u32.to_be_bytes()); // confirmed bytes
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        let f = framed(&body);
        assert!(is_system_event(&f));
        let ev = parse_system_event(&f).unwrap();
        assert_eq!(ev.confirmed_bytes, 123);
        assert!(!ev.has_data && ev.message.is_none());
        assert!(!ev.is_fatal());
    }

    #[test]
    fn parses_message_event() {
        let mut body = vec![0u8; 16];
        body.extend_from_slice(b"LOGOUT");
        let ev = parse_system_event(&framed(&body)).unwrap();
        assert_eq!(ev.message.as_deref(), Some("LOGOUT"));
        assert!(!ev.is_fatal());
    }

    #[test]
    fn data_event_is_fatal() {
        let mut body = vec![0u8; 16];
        body.extend_from_slice(&[0x00, dt::STRUCT, 0x00, 0x00, 0x00, 0x01]);
        let ev = parse_system_event(&framed(&body)).unwrap();
        assert!(ev.has_data && ev.is_fatal());
    }

    #[test]
    fn a_response_is_not_a_system_event() {
        let f = pdu::frame_single_pdu(protocol_version::V2, &[0x32, 0, 0]);
        assert!(!is_system_event(&f));
    }
}
