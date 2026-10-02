// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/*Request.cs + *Response.cs,
// LGPL-3.0-or-later.

//! The request/response header shared by every S7CommPlus function object.
//!
//! Every request body (inside the `0x72` PDU framing handled by [`crate::wire::pdu`])
//! begins with:
//!
//! ```text
//! <opcode:1> <reserved:u16=0> <function:u16> <reserved:u16=0>
//! <sequence:u16> <session_id:u32> <transport_flags:1>
//! ```
//!
//! followed by function-specific data. Note `IntegrityId` (when present) is written by
//! the individual request *inside* its body, not in this header.
//!
//! Every response body begins with:
//!
//! ```text
//! <opcode:1> <reserved:u16> <function:u16> <reserved:u16>
//! <sequence:u16> <transport_flags:1> <return_value:VLQ-u64>
//! ```
//!
//! followed by function-specific data.

use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::wire::pdu::opcode;
use crate::wire::{primitives as p, vlq};

/// The error bit in a response `return_value`: when set, an error object follows.
pub const RETURN_VALUE_ERROR_BIT: u64 = 0x4000_0000_0000_0000;

/// The leading header of a request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHeader {
    /// The function code (see [`crate::wire::pdu::functioncode`]).
    pub function_code: u16,
    /// Per-request sequence number (echoed in the response).
    pub sequence_number: u16,
    /// The session id this request belongs to.
    pub session_id: u32,
    /// Transport flags byte.
    pub transport_flags: u8,
}

impl RequestHeader {
    /// Serialize the request header. Returns bytes written.
    pub fn serialize<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = 0;
        n += p::encode_u8(w, opcode::REQUEST)?;
        n += p::encode_u16(w, 0)?; // reserved
        n += p::encode_u16(w, self.function_code)?;
        n += p::encode_u16(w, 0)?; // reserved
        n += p::encode_u16(w, self.sequence_number)?;
        n += p::encode_u32(w, self.session_id)?;
        n += p::encode_u8(w, self.transport_flags)?;
        Ok(n)
    }
}

/// Whether a response return value signals success: the error bit is clear **and** the low 16
/// bits, read as a signed error code, are not negative. The error bit alone is not enough: a PLC
/// refuses a GetMultiVariables with more items than it allows with `0xa027a600007bfffc` (error
/// bit clear, error code -4), and the reference treats any non-zero value there as a failure.
pub fn return_value_is_ok(return_value: u64) -> bool {
    return_value & RETURN_VALUE_ERROR_BIT == 0 && (return_value as i16) >= 0
}

/// The leading header of a response body (header fields + the common body prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    /// The function code being responded to (see [`crate::wire::pdu::functioncode`]).
    pub function_code: u16,
    /// The sequence number echoed from the request.
    pub sequence_number: u16,
    /// Transport flags byte.
    pub transport_flags: u8,
    /// Return value (VLQ); the top error bit (`0x4000_0000_0000_0000`) signals an error
    /// object follows. Use [`ResponseHeader::is_ok`] to test it.
    pub return_value: u64,
}

impl ResponseHeader {
    /// Read and validate a response header from `r`, leaving the reader positioned at the
    /// function-specific data. Validates the opcode is `Response`.
    pub fn read<R: Read>(r: &mut R) -> Result<Self> {
        let op = p::decode_u8(r)?;
        if op != opcode::RESPONSE {
            return Err(Error::protocol(format!(
                "expected opcode RESPONSE (0x{:02x}), got 0x{op:02x}",
                opcode::RESPONSE
            )));
        }
        let _reserved = p::decode_u16(r)?;
        let function_code = p::decode_u16(r)?;
        let _reserved2 = p::decode_u16(r)?;
        let sequence_number = p::decode_u16(r)?;
        let transport_flags = p::decode_u8(r)?;
        let return_value = vlq::decode_u64(r)?;
        Ok(ResponseHeader {
            function_code,
            sequence_number,
            transport_flags,
            return_value,
        })
    }

    /// True when the return value signals success; see [`return_value_is_ok`].
    pub fn is_ok(&self) -> bool {
        return_value_is_ok(self.return_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::pdu::functioncode;
    use std::io::Cursor;

    #[test]
    fn request_header_layout() {
        let h = RequestHeader {
            function_code: functioncode::CREATE_OBJECT,
            sequence_number: 2,
            session_id: 0x0000_0120,
            transport_flags: 0x34,
        };
        let mut out = Vec::new();
        h.serialize(&mut out).unwrap();
        assert_eq!(
            out,
            vec![
                0x31, // opcode REQUEST
                0x00, 0x00, // reserved
                0x04, 0xca, // function CreateObject
                0x00, 0x00, // reserved
                0x00, 0x02, // sequence
                0x00, 0x00, 0x01, 0x20, // session id
                0x34, // transport flags
            ]
        );
    }

    #[test]
    fn response_header_read() {
        let mut body = Vec::new();
        body.push(opcode::RESPONSE);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&functioncode::CREATE_OBJECT.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&7u16.to_be_bytes()); // sequence
        body.push(0x00); // transport flags
        vlq::encode_u64(&mut body, 0).unwrap(); // return value

        let mut cur = Cursor::new(&body);
        let h = ResponseHeader::read(&mut cur).unwrap();
        assert_eq!(h.function_code, functioncode::CREATE_OBJECT);
        assert_eq!(h.sequence_number, 7);
        assert!(h.is_ok());
    }

    #[test]
    fn return_value_success_needs_error_bit_clear_and_code_non_negative() {
        assert!(return_value_is_ok(0));
        assert!(return_value_is_ok(0x0000_0000_0000_0001));
        assert!(!return_value_is_ok(RETURN_VALUE_ERROR_BIT));
        // The PLC's answer to a GetMultiVariables over its item limit: error bit clear, code -4.
        assert!(!return_value_is_ok(0xa027_a600_007b_fffc));
    }
}
