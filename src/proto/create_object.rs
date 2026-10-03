// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/CreateObjectRequest.cs +
// Core/CreateObjectResponse.cs + S7CommPlusConnection.cs, LGPL-3.0-or-later.

//! `CreateObject` — creates the server session (step 3 of the connect sequence).
//!
//! The request body is the shared [`RequestHeader`] (with CreateObject's `0x36` transport
//! flags) followed by the request set: a `RequestId`, a `RequestValue` ([`PValue`]), a
//! fill `u32`, an optional VLQ integrity id, the `RequestObject` ([`PObject`]), and a
//! final fill `u32`.
//!
//! The response carries a list of newly allocated object ids; for session creation the
//! first is the `SessionId` and the second is `SessionId2`.

use std::io::Cursor;

use crate::error::{Error, Result};
use crate::proto::header::{RequestHeader, ResponseHeader};
use crate::proto::object::{decode_object, PObject};
use crate::value::PValue;
use crate::wire::pdu::{self, functioncode, ids, protocol_version};
use crate::wire::{primitives as p, vlq};

/// Transport flags used by the reference `CreateObjectRequest` for the session.
const TRANSPORT_FLAGS: u8 = 0x36;

/// Magic client relation id sent in the session-creation request (`ServerSessionClientRID`).
const SERVER_SESSION_CLIENT_RID_VALUE: u32 = 0x80c3_c901;

/// Build the `RequestObject` for creating the null server session (`SetNullServerSessionData`).
pub fn null_server_session_object() -> PObject {
    let mut obj = PObject::new(
        ids::GET_NEW_RID_ON_SERVER,
        ids::CLASS_SERVER_SESSION,
        ids::NONE,
    );
    obj.add_attribute(
        ids::SERVER_SESSION_CLIENT_RID,
        PValue::RID(SERVER_SESSION_CLIENT_RID_VALUE),
    );
    obj.add_object(PObject::new(
        ids::GET_NEW_RID_ON_SERVER,
        ids::CLASS_SUBSCRIPTIONS,
        ids::NONE,
    ));
    obj
}

/// Build a complete, framed `CreateObjectRequest` for creating the server session.
///
/// `integrity_id` is written (as a VLQ) only when `with_integrity` is true.
pub fn build_create_session_request(
    sequence_number: u16,
    session_id: u32,
    with_integrity: bool,
    integrity_id: u32,
) -> Result<Vec<u8>> {
    let header = RequestHeader {
        function_code: functioncode::CREATE_OBJECT,
        sequence_number,
        session_id,
        transport_flags: TRANSPORT_FLAGS,
    };

    let mut body = Vec::new();
    header.serialize(&mut body)?;
    p::encode_u32(&mut body, ids::OBJECT_SERVER_SESSION_CONTAINER)?; // RequestId
    PValue::UDInt(0).serialize(&mut body)?; // RequestValue
    p::encode_u32(&mut body, 0)?; // unknown / fill
    if with_integrity {
        vlq::encode_u32(&mut body, integrity_id)?;
    }
    null_server_session_object().serialize(&mut body)?; // RequestObject
    p::encode_u32(&mut body, 0)?; // final fill

    Ok(pdu::frame_single_pdu(protocol_version::V1, &body))
}

/// Build the first `CreateObjectRequest` (null server session, no integrity).
pub fn create_session_request_default(sequence_number: u16) -> Result<Vec<u8>> {
    build_create_session_request(sequence_number, ids::OBJECT_NULL_SERVER_SESSION, false, 0)
}

/// A parsed `CreateObjectResponse`.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateObjectResponse {
    /// The response header.
    pub header: ResponseHeader,
    /// Newly allocated object ids, in order.
    pub object_ids: Vec<u32>,
    /// The trailing response object (carries session attributes, e.g. ServerSessionVersion).
    pub response_object: Option<PObject>,
}

impl CreateObjectResponse {
    /// The session id (first allocated object id), if present.
    pub fn session_id(&self) -> Option<u32> {
        self.object_ids.first().copied()
    }

    /// The secondary session id (second allocated object id), if present.
    pub fn session_id2(&self) -> Option<u32> {
        self.object_ids.get(1).copied()
    }

    /// The `ServerSessionVersion` (attribute 306) value from the response object, which the
    /// session-setup step must echo back to the PLC.
    pub fn server_session_version(&self) -> Option<&PValue> {
        let obj = self.response_object.as_ref()?;
        obj.attributes
            .iter()
            .find(|(id, _)| *id == ids::SERVER_SESSION_VERSION)
            .map(|(_, value)| value)
    }

    /// The PLC's description of itself: member 319 of its `ServerSessionVersion`, such as
    /// `1;6ES7 SIM-01500-APLC;S4.1` from PLCSIM Advanced (a counter, the order number and the
    /// firmware version, it seems).
    pub fn plc_description(&self) -> Option<String> {
        match self.server_session_version()? {
            PValue::Struct { elements, .. } => elements.iter().find_map(|(id, v)| match v {
                PValue::WString(s) if *id == SERVER_SESSION_DESCRIPTION => Some(s.clone()),
                _ => None,
            }),
            _ => None,
        }
    }
}

/// The member of `ServerSessionVersion` with the PLC's description of itself.
const SERVER_SESSION_DESCRIPTION: u32 = 319;

/// Parse a `CreateObjectResponse` telegram.
///
/// Reads the shared response header and the object-id list. The trailing response object
/// body is not yet parsed (the ids we need precede it).
pub fn parse_create_object_response(buf: &[u8]) -> Result<CreateObjectResponse> {
    let pdu_header = pdu::parse_header(buf)?;
    let mut cur = Cursor::new(&buf[pdu_header.body_offset..]);

    let header = ResponseHeader::read(&mut cur)?;
    if header.function_code != functioncode::CREATE_OBJECT {
        return Err(Error::protocol(format!(
            "CreateObjectResponse: expected function CreateObject (0x{:04x}), got 0x{:04x}",
            functioncode::CREATE_OBJECT,
            header.function_code
        )));
    }

    let count = p::decode_u8(&mut cur)?;
    let mut object_ids = Vec::with_capacity(count as usize);
    for _ in 0..count {
        object_ids.push(vlq::decode_u32(&mut cur)?);
    }

    // The response object follows the id list (carries ServerSessionVersion etc.).
    let pos = cur.position() as usize;
    let response_object =
        if cur.get_ref().get(pos) == Some(&crate::proto::object::element_id::START_OF_OBJECT) {
            Some(decode_object(&mut cur)?)
        } else {
            None
        };

    Ok(CreateObjectResponse {
        header,
        object_ids,
        response_object,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::pdu::opcode;

    #[test]
    fn session_request_is_byte_exact() {
        let framed =
            build_create_session_request(2, ids::OBJECT_NULL_SERVER_SESSION, false, 0).unwrap();
        let expected = vec![
            // PDU header: id, V1, len = 0x003a (58)
            0x72, 0x01, 0x00, 0x3a, //
            // request header
            0x31, 0x00, 0x00, 0x04, 0xca, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x20, 0x36,
            // RequestId = ObjectServerSessionContainer (285, fixed u32)
            0x00, 0x00, 0x01, 0x1d, //
            // RequestValue = ValueUDInt(0)
            0x00, 0x04, 0x00, //
            // unknown / fill u32
            0x00, 0x00, 0x00, 0x00, //
            // RequestObject
            0xa1, 0x00, 0x00, 0x00, 0xd3, 0x82, 0x1f, 0x00, 0x00, // header
            0xa3, 0x82, 0x2c, 0x00, 0x12, 0x80, 0xc3, 0xc9, 0x01, // attribute RID
            0xa1, 0x00, 0x00, 0x00, 0xd3, 0x81, 0x7f, 0x00, 0x00,
            0xa2, // nested subscriptions
            0xa2, // terminating object
            // final fill u32
            0x00, 0x00, 0x00, 0x00, //
            // PDU trailer
            0x72, 0x01, 0x00, 0x00,
        ];
        assert_eq!(framed, expected);
    }

    #[test]
    fn parse_response_extracts_session_ids() {
        // Build a synthetic CreateObject response with two object ids.
        let mut body = Vec::new();
        body.push(opcode::RESPONSE);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&functioncode::CREATE_OBJECT.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes()); // sequence
        body.push(0x00); // transport flags
        vlq::encode_u64(&mut body, 0).unwrap(); // return value (ok)
        body.push(2); // object id count
        vlq::encode_u32(&mut body, 0x0000_0123).unwrap();
        vlq::encode_u32(&mut body, 0x0000_0456).unwrap();
        let framed = pdu::frame_single_pdu(protocol_version::V1, &body);

        let resp = parse_create_object_response(&framed).unwrap();
        assert!(resp.header.is_ok());
        assert_eq!(resp.session_id(), Some(0x0000_0123));
        assert_eq!(resp.session_id2(), Some(0x0000_0456));
    }
}
