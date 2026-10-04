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
//!
//! The data value's header is fixed-width too: four bytes `[reserved, flags, datatype as u16]`,
//! so a Struct starts `00 00 00 17`, then a `u32` struct id and `u32`-id members ending in a 0 id.
//! Same layout in the reference driver (`SystemEvent.Deserialize` peeks a `UInt32` and compares
//! it with `Datatype.Struct`) and the Wireshark dissector (`s7commp_decode_sys_event`: `ntohl ==
//! STRUCT`, then `s7commp_decode_value` with `disable_vlq`).
//! An S7-1215C (FW V4.2) sends one with struct id 40300 and
//! no members right before it drops the connection over a rejected request (field run).

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

/// The fixed-width value header of a Struct: reserved 0, flags 0, datatype [`dt::STRUCT`] as `u16`.
const STRUCT_HEADER: u32 = dt::STRUCT as u32;

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
    if rest.len() >= 4 && u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) == STRUCT_HEADER
    {
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

    /// The notice an S7-1215C (6ES7 215-1AG40-0XB0, FW V4.2) sent right before closing the
    /// connection over a rejected request (field run): the 16-byte header, then a
    /// fixed-width Struct value header `00 00 00 17`, struct id 40300 (`9d 6c`) and the 0 id that
    /// ends its (empty) member list.
    const FW42_REJECT_NOTICE: [u8; 32] = [
        0x72, 0xfe, 0x00, 0x1c, // header, 28-byte body
        0x00, 0x00, 0x00, 0x00, // reserved1
        0x00, 0x00, 0x04, 0x85, // confirmed_bytes
        0x00, 0x00, 0x00, 0x00, // reserved2
        0x00, 0x00, 0x00, 0x00, // reserved3
        0x00, 0x00, 0x00, 0x17, // value header: Struct
        0x00, 0x00, 0x9d, 0x6c, // struct id 40300 (SystemEvent)
        0x00, 0x00, 0x00, 0x00, // end of members
    ];

    /// A plain 16-byte keep-alive, as the same FW V4.2 CPU sends between the chunks of a large
    /// Explore (field run).
    const FW42_KEEPALIVE: [u8; 20] = [
        0x72, 0xfe, 0x00, 0x10, // header, 16-byte body
        0x00, 0x00, 0x00, 0x00, // reserved1
        0x00, 0x00, 0x02, 0xee, // confirmed_bytes
        0x00, 0x00, 0x00, 0x00, // reserved2
        0x00, 0x00, 0x00, 0x00, // reserved3
    ];

    #[test]
    fn fw42_reject_notice_is_fatal() {
        assert!(is_system_event(&FW42_REJECT_NOTICE));
        let ev = parse_system_event(&FW42_REJECT_NOTICE).unwrap();
        assert_eq!(ev.confirmed_bytes, 0x485);
        assert!(ev.has_data, "{ev:?}");
        assert_eq!(ev.message, None);
        assert!(ev.is_fatal());
    }

    #[test]
    fn fw42_reject_notice_is_fatal_with_trailer_too() {
        // Same body, framed the way the crate frames PDUs (with a `72 fe 00 00` trailer).
        let f = framed(&FW42_REJECT_NOTICE[4..]);
        assert!(parse_system_event(&f).unwrap().is_fatal());
    }

    #[test]
    fn fw42_keepalive_is_not_fatal() {
        assert!(is_system_event(&FW42_KEEPALIVE));
        let ev = parse_system_event(&FW42_KEEPALIVE).unwrap();
        assert_eq!(ev.confirmed_bytes, 0x2ee);
        assert!(!ev.has_data && ev.message.is_none());
        assert!(!ev.is_fatal());
    }

    #[test]
    fn two_byte_struct_header_is_not_a_struct() {
        // `00 17` followed by anything but `00 00` is not the fixed-width Struct header (the
        // check this parser used to make); the bytes are kept as a message instead.
        let mut body = vec![0u8; 16];
        body.extend_from_slice(&[0x00, dt::STRUCT, 0x00, 0x00, 0x00, 0x01]);
        let ev = parse_system_event(&framed(&body)).unwrap();
        assert!(!ev.has_data && ev.message.is_some());
        assert!(!ev.is_fatal());
    }

    #[test]
    fn a_response_is_not_a_system_event() {
        let f = pdu::frame_single_pdu(protocol_version::V2, &[0x32, 0, 0]);
        assert!(!is_system_event(&f));
    }
}
