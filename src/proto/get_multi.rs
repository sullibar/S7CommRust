// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/GetMultiVariablesRequest.cs +
// Core/GetMultiVariablesResponse.cs, LGPL-3.0-or-later.

//! `GetMultiVariables` — read one or more symbolic variables in a single request.
//!
//! Request body: shared [`RequestHeader`] (transport flags `0x34`), a link id (`0` for
//! reads), the item count and total field count (both VLQ), each [`ItemAddress`], the
//! object qualifier, an optional VLQ integrity id, and a fill `u32`.
//!
//! Response body (after the shared response header): a value list of `(item_no, value)`
//! pairs terminated by `item_no == 0`, an error list of `(item_no, return_value)` pairs
//! terminated by `item_no == 0`, and a trailing integrity id.

use std::io::Cursor;

use crate::error::{Error, Result};
use crate::proto::header::{RequestHeader, ResponseHeader};
use crate::proto::item_address::ItemAddress;
use crate::proto::object::encode_object_qualifier;
use crate::value::PValue;
use crate::wire::pdu::{self, functioncode, protocol_version};
use crate::wire::{primitives as p, vlq};

/// Transport flags used by the reference `GetMultiVariablesRequest`.
const TRANSPORT_FLAGS: u8 = 0x34;

/// Build a framed `GetMultiVariablesRequest` for the given addresses.
pub fn build_get_multi_request(
    sequence_number: u16,
    session_id: u32,
    addresses: &[ItemAddress],
    with_integrity: bool,
    integrity_id: u32,
) -> Result<Vec<u8>> {
    let header = RequestHeader {
        function_code: functioncode::GET_MULTI_VARIABLES,
        sequence_number,
        session_id,
        transport_flags: TRANSPORT_FLAGS,
    };

    let field_count: u32 = addresses.iter().map(ItemAddress::field_count).sum();

    let mut body = Vec::new();
    header.serialize(&mut body)?;
    p::encode_u32(&mut body, 0)?; // LinkId (0 for reading)
    vlq::encode_u32(&mut body, addresses.len() as u32)?;
    vlq::encode_u32(&mut body, field_count)?;
    for addr in addresses {
        addr.serialize(&mut body)?;
    }
    encode_object_qualifier(&mut body)?;
    if with_integrity {
        vlq::encode_u32(&mut body, integrity_id)?;
    }
    p::encode_u32(&mut body, 0)?; // fill

    Ok(pdu::frame_single_pdu(protocol_version::V2, &body))
}

/// A parsed `GetMultiVariablesResponse`.
#[derive(Debug, Clone, PartialEq)]
pub struct GetMultiVariablesResponse {
    /// The response header.
    pub header: ResponseHeader,
    /// Successfully read `(item_no, value)` pairs (1-based item numbers).
    pub values: Vec<(u32, PValue)>,
    /// Per-item error `(item_no, return_value)` pairs.
    pub errors: Vec<(u32, u64)>,
    /// Trailing integrity id (0 if absent).
    pub integrity_id: u32,
}

impl GetMultiVariablesResponse {
    /// The value for a 1-based item number, if it was read successfully.
    pub fn value(&self, item_no: u32) -> Option<&PValue> {
        self.values
            .iter()
            .find(|(n, _)| *n == item_no)
            .map(|(_, v)| v)
    }

    /// One entry per requested item, in request order (`count` of them): the value, or the item's
    /// return value when the PLC reported an error for it (`0` if it reported neither). Linear in
    /// the response, where calling [`value`](Self::value) for every item is quadratic.
    pub fn into_items(self, count: usize) -> Vec<std::result::Result<PValue, u64>> {
        let mut out = vec![Err(0); count];
        for (item_no, e) in self.errors {
            if let Some(s) = item_slot(&mut out, item_no) {
                *s = Err(e);
            }
        }
        for (item_no, v) in self.values {
            if let Some(s) = item_slot(&mut out, item_no) {
                *s = Ok(v);
            }
        }
        out
    }
}

/// The entry for 1-based `item_no`, if it is in range.
fn item_slot<T>(items: &mut [T], item_no: u32) -> Option<&mut T> {
    (item_no as usize)
        .checked_sub(1)
        .and_then(|i| items.get_mut(i))
}

/// Parse a `GetMultiVariablesResponse` telegram.
pub fn parse_get_multi_response(buf: &[u8]) -> Result<GetMultiVariablesResponse> {
    let pdu_header = pdu::parse_header(buf)?;
    let mut cur = Cursor::new(&buf[pdu_header.body_offset..]);

    let header = ResponseHeader::read(&mut cur)?;
    if header.function_code != functioncode::GET_MULTI_VARIABLES {
        return Err(Error::protocol(format!(
            "GetMultiVariablesResponse: expected function 0x{:04x}, got 0x{:04x}",
            functioncode::GET_MULTI_VARIABLES,
            header.function_code
        )));
    }

    // Value list: (item_no, value) until item_no == 0.
    let mut values = Vec::new();
    let mut item_no = vlq::decode_u32(&mut cur)?;
    while item_no > 0 {
        let value = PValue::deserialize(&mut cur)?;
        values.push((item_no, value));
        item_no = vlq::decode_u32(&mut cur)?;
    }

    // Error list: (item_no, return_value) until item_no == 0.
    let mut errors = Vec::new();
    let mut err_no = vlq::decode_u32(&mut cur)?;
    while err_no > 0 {
        let retval = vlq::decode_u64(&mut cur)?;
        errors.push((err_no, retval));
        err_no = vlq::decode_u32(&mut cur)?;
    }

    // Trailing integrity id (tolerate absence on short frames).
    let integrity_id = vlq::decode_u32(&mut cur).unwrap_or(0);

    Ok(GetMultiVariablesResponse {
        header,
        values,
        errors,
        integrity_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::pdu::opcode;

    #[test]
    fn request_is_byte_exact() {
        let addr = ItemAddress {
            symbol_crc: 0,
            access_area: 3,
            access_sub_area: 0,
            lid: vec![],
        };
        let framed = build_get_multi_request(3, 0x0000_0120, &[addr], true, 1).unwrap();
        let expected = vec![
            // PDU header: id, V2, len = 0x0034 (52)
            0x72, 0x02, 0x00, 0x34, //
            // request header (function 0x054c, seq 3, session 0x120, flags 0x34)
            0x31, 0x00, 0x00, 0x05, 0x4c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01, 0x20, 0x34,
            // LinkId
            0x00, 0x00, 0x00, 0x00, //
            0x01, // address count
            0x04, // total field count (4 + 0 LIDs)
            // ItemAddress: crc 0, area 3, count 1, sub 0
            0x00, 0x03, 0x01, 0x00, //
            // object qualifier
            0x00, 0x00, 0x04, 0xe8, 0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x89, 0x6a,
            0x00, 0x13, 0x00, 0x89, 0x6b, 0x00, 0x04, 0x00, 0x00, //
            0x01, // integrity id
            0x00, 0x00, 0x00, 0x00, // fill
            // PDU trailer
            0x72, 0x02, 0x00, 0x00,
        ];
        assert_eq!(framed, expected);
    }

    #[test]
    fn parse_response_with_values_and_errors() {
        let mut body = Vec::new();
        body.push(opcode::RESPONSE);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&functioncode::GET_MULTI_VARIABLES.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&3u16.to_be_bytes()); // sequence
        body.push(0x00); // transport flags
        vlq::encode_u64(&mut body, 0).unwrap(); // return value ok
                                                // value list: item 1 -> UInt(0x1234), then terminator 0
        vlq::encode_u32(&mut body, 1).unwrap();
        PValue::UInt(0x1234).serialize(&mut body).unwrap();
        vlq::encode_u32(&mut body, 0).unwrap();
        // error list: item 2 -> 0x8000_0000_0000_0000, terminator 0
        vlq::encode_u32(&mut body, 2).unwrap();
        vlq::encode_u64(&mut body, 0x8000_0000_0000_0000).unwrap();
        vlq::encode_u32(&mut body, 0).unwrap();
        // integrity id
        vlq::encode_u32(&mut body, 1).unwrap();

        let framed = pdu::frame_single_pdu(protocol_version::V1, &body);
        let resp = parse_get_multi_response(&framed).unwrap();
        assert!(resp.header.is_ok());
        assert_eq!(resp.value(1), Some(&PValue::UInt(0x1234)));
        assert_eq!(resp.errors, vec![(2, 0x8000_0000_0000_0000)]);
        assert_eq!(resp.integrity_id, 1);
    }
}
