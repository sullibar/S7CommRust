// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/InitSslRequest.cs +
// Core/InitSslResponse.cs, LGPL-3.0-or-later.

//! The `InitSsl` bootstrap exchange.
//!
//! Sent **unencrypted** as the very first S7CommPlus telegram, this tells the PLC to
//! switch the connection to TLS. After a successful `InitSslResponse` the client performs
//! the TLS handshake; everything afterwards is encrypted.

use std::io::Cursor;

use crate::error::{Error, Result};
use crate::proto::header::{return_value_is_ok, RequestHeader, ResponseHeader};
use crate::wire::pdu::{self, functioncode, ids, protocol_version};

/// Transport flags value used by the reference `InitSslRequest`.
const TRANSPORT_FLAGS: u8 = 0x30;

/// Build a complete, framed (header + trailer) `InitSslRequest` telegram.
///
/// The body is the shared request header (with InitSsl's `0x30` transport flags) followed
/// by a 4-byte fill field, mirroring the reference `InitSslRequest.Serialize`.
pub fn build_init_ssl_request(sequence_number: u16, session_id: u32) -> Vec<u8> {
    let header = RequestHeader {
        function_code: functioncode::INIT_SSL,
        sequence_number,
        session_id,
        transport_flags: TRANSPORT_FLAGS,
    };
    let mut body = Vec::with_capacity(18);
    header
        .serialize(&mut body)
        .expect("Vec write is infallible");
    body.extend_from_slice(&0u32.to_be_bytes()); // fill
    pdu::frame_single_pdu(protocol_version::V1, &body)
}

/// Build the first `InitSslRequest`: sequence number 1, the null server session id.
pub fn init_ssl_request_default() -> Vec<u8> {
    build_init_ssl_request(1, ids::OBJECT_NULL_SERVER_SESSION)
}

/// A parsed `InitSslResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitSslResponse {
    /// Protocol version from the PDU header.
    pub protocol_version: u8,
    /// Sequence number echoed from the request.
    pub sequence_number: u16,
    /// Transport flags byte.
    pub transport_flags: u8,
    /// The S7CommPlus return value (VLQ). Bit `0x40_00_00_00_00_00_00_00` flags an error
    /// object follows; success values clear it.
    pub return_value: u64,
}

impl InitSslResponse {
    /// True when the return value signals success (see [`return_value_is_ok`]).
    pub fn is_ok(&self) -> bool {
        return_value_is_ok(self.return_value)
    }
}

/// Parse an `InitSslResponse` from a received S7CommPlus telegram.
///
/// Tolerant of whether the `0x72` header is still present (see
/// [`pdu::parse_header`]). Validates the opcode is a response and the function code is
/// `InitSsl` before reading the response fields.
pub fn parse_init_ssl_response(buf: &[u8]) -> Result<InitSslResponse> {
    let pdu_header = pdu::parse_header(buf)?;
    let mut cur = Cursor::new(&buf[pdu_header.body_offset..]);

    let header = ResponseHeader::read(&mut cur)?;
    if header.function_code != functioncode::INIT_SSL {
        // Firmware without TLS S7CommPlus answers InitSsl with an error/abort function code
        // (e.g. Error2 0x05a9 on S7-1200 FW 2.2 / 4.2) rather than a real InitSsl response.
        // Phrase this as a rejection so the `--auto` path treats it as "no TLS" and falls
        // through to the legacy transport (see `s7tool`'s `connect_auto`).
        return Err(Error::protocol(format!(
            "InitSsl rejected: PLC answered function {} (0x{:04x}), not InitSsl (0x{:04x}) — \
             no TLS S7CommPlus (firmware too old)",
            pdu::function_name(header.function_code),
            header.function_code,
            functioncode::INIT_SSL,
        )));
    }
    Ok(InitSslResponse {
        protocol_version: pdu_header.protocol_version,
        sequence_number: header.sequence_number,
        transport_flags: header.transport_flags,
        return_value: header.return_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::pdu::opcode;
    use crate::wire::vlq;

    #[test]
    fn default_request_is_byte_exact() {
        let framed = init_ssl_request_default();
        assert_eq!(
            framed,
            vec![
                // header: id, V1, len = 0x0012 (18)
                0x72, 0x01, 0x00, 0x12, //
                // body
                0x31, // opcode REQUEST
                0x00, 0x00, // reserved
                0x05, 0xb3, // function InitSsl
                0x00, 0x00, // reserved
                0x00, 0x01, // sequence number = 1
                0x00, 0x00, 0x01, 0x20, // session id = 288
                0x30, // transport flags
                0x00, 0x00, 0x00, 0x00, // fill
                // trailer
                0x72, 0x01, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn roundtrip_response() {
        // Craft a success InitSslResponse telegram and parse it back.
        let mut body = Vec::new();
        body.push(opcode::RESPONSE);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&functioncode::INIT_SSL.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes()); // sequence
        body.push(0x30); // transport flags
        vlq::encode_u64(&mut body, 0).unwrap(); // return value = 0 (ok)
        let framed = pdu::frame_single_pdu(protocol_version::V1, &body);

        let resp = parse_init_ssl_response(&framed).unwrap();
        assert_eq!(resp.protocol_version, protocol_version::V1);
        assert_eq!(resp.sequence_number, 1);
        assert_eq!(resp.transport_flags, 0x30);
        assert_eq!(resp.return_value, 0);
        assert!(resp.is_ok());
    }

    #[test]
    fn rejects_wrong_opcode() {
        let mut body = Vec::new();
        body.push(opcode::REQUEST); // wrong: not a response
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&functioncode::INIT_SSL.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let framed = pdu::frame_single_pdu(protocol_version::V1, &body);
        assert!(parse_init_ssl_response(&framed).is_err());
    }

    /// Firmware too old for TLS answers InitSsl with Error2 (0x05a9). Parsing must fail with a
    /// "rejected" message so `--auto` falls through to the legacy transport instead of aborting.
    #[test]
    fn error2_response_is_reported_as_rejected() {
        let mut body = Vec::new();
        body.push(opcode::RESPONSE);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&functioncode::ERROR_2.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes()); // sequence
        body.push(0x34); // transport flags
        vlq::encode_u64(&mut body, 0xa201_d600_01f2_fdf9).unwrap(); // an error return value
        let framed = pdu::frame_single_pdu(protocol_version::V1, &body);

        let err = parse_init_ssl_response(&framed).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("InitSsl rejected"), "message was: {msg}");
        assert!(msg.contains("0x05a9"), "message was: {msg}");
    }
}
