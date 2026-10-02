// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/*.cs, LGPL-3.0-or-later.

//! S7CommPlus PDU framing and protocol constants.
//!
//! A S7CommPlus telegram (the payload carried inside a TPKT/COTP DT frame, or inside a
//! TLS record once the connection is encrypted) is framed as:
//!
//! ```text
//! 72 <protoVersion> <len_hi> <len_lo>   header (len = payload length of this chunk)
//! .. payload ..
//! 72 <protoVersion> 00 00               trailer (only on the final chunk)
//! ```
//!
//! Large PDUs are split into multiple chunks (each its own TPKT/COTP frame); the trailer
//! is appended only to the last chunk. Bootstrap PDUs such as `InitSsl` are small and fit
//! in a single chunk — [`frame_single_pdu`] handles that case.

/// The S7CommPlus protocol identifier that starts every PDU header and trailer.
pub const PROTOCOL_ID: u8 = 0x72;

/// S7CommPlus protocol versions (the second byte of the PDU header).
pub mod protocol_version {
    /// Version 1 — used for bootstrap PDUs such as `InitSsl`.
    pub const V1: u8 = 0x01;
    /// Version 2 — used for most request/response PDUs.
    pub const V2: u8 = 0x02;
    /// Version 3.
    pub const V3: u8 = 0x03;
    /// System-event telegrams (keep-alives / error pushes).
    pub const SYSTEM_EVENT: u8 = 0xfe;
}

/// Opcodes (first byte of a PDU body).
pub mod opcode {
    /// Request (client → PLC).
    pub const REQUEST: u8 = 0x31;
    /// Response (PLC → client).
    pub const RESPONSE: u8 = 0x32;
    /// Notification (unsolicited push, PLC → client).
    pub const NOTIFICATION: u8 = 0x33;
}

/// Function codes (u16, big-endian, in the PDU body).
pub mod functioncode {
    /// Explore — browse the object/type tree.
    pub const EXPLORE: u16 = 0x04bb;
    /// CreateObject — allocate a server-side object (session, subscription, …).
    pub const CREATE_OBJECT: u16 = 0x04ca;
    /// DeleteObject — tear down a server-side object.
    pub const DELETE_OBJECT: u16 = 0x04d4;
    /// SetVariable — write a single variable.
    pub const SET_VARIABLE: u16 = 0x04f2;
    /// GetVariable — read a single variable.
    pub const GET_VARIABLE: u16 = 0x04fc;
    /// SetMultiVariables — write several variables in one request.
    pub const SET_MULTI_VARIABLES: u16 = 0x0542;
    /// GetMultiVariables — read several variables in one request.
    pub const GET_MULTI_VARIABLES: u16 = 0x054c;
    /// GetVarSubstreamed — read a value delivered as a byte substream (e.g. the auth challenge).
    pub const GET_VAR_SUBSTREAMED: u16 = 0x0586;
    /// SetVarSubstreamed — write a value as a byte substream.
    pub const SET_VAR_SUBSTREAMED: u16 = 0x057c;
    /// InitSsl — the plaintext bootstrap that switches the connection to TLS.
    pub const INIT_SSL: u16 = 0x05b3;
}

/// Well-known object IDs.
pub mod ids {
    /// Sentinel "no id".
    pub const NONE: u32 = 0;
    /// Ask the server to allocate a new relation id.
    pub const GET_NEW_RID_ON_SERVER: u32 = 211;
    /// Class id of the subscriptions object.
    pub const CLASS_SUBSCRIPTIONS: u32 = 255;
    /// Container object id used as the RequestId when creating a session.
    pub const OBJECT_SERVER_SESSION_CONTAINER: u32 = 285;
    /// Class id of the server-session object.
    pub const CLASS_SERVER_SESSION: u32 = 287;
    /// SessionId used before a session has been created.
    pub const OBJECT_NULL_SERVER_SESSION: u32 = 288;
    /// Attribute id: the client's relation id within the server session.
    pub const SERVER_SESSION_CLIENT_RID: u32 = 300;
    /// Attribute id: the server-session version Struct (echoed back during session setup).
    pub const SERVER_SESSION_VERSION: u32 = 306;

    // Communication resources (`CommRessources.ReadMax` in the reference).
    /// The root object: the access area of the PLC's system limits.
    pub const OBJECT_ROOT: u32 = 201;
    /// Access sub-area of the PLC's system limits (read with LID [`TAGS_PER_READ_REQUEST_MAX`]
    /// and [`TAGS_PER_WRITE_REQUEST_MAX`]).
    pub const SYSTEM_LIMITS: u32 = 1037;
    /// System-limits LID: most items one GetMultiVariables may carry.
    pub const TAGS_PER_READ_REQUEST_MAX: u32 = 1000;
    /// System-limits LID: most items one SetMultiVariables may carry.
    pub const TAGS_PER_WRITE_REQUEST_MAX: u32 = 1001;

    // Object-qualifier ids (appended to Get/SetMultiVariables requests).
    /// Object-qualifier attribute id.
    pub const OBJECT_QUALIFIER: u32 = 1256;
    /// Object-qualifier: parent relation id.
    pub const PARENT_RID: u32 = 1257;
    /// Object-qualifier: composition attribute id.
    pub const COMPOSITION_AID: u32 = 1258;
    /// Object-qualifier: key attribute id.
    pub const KEY_QUALIFIER: u32 = 1259;

    // Legitimation (auth) ids.
    /// Attribute id: the legitimation challenge request (server-session request).
    pub const SERVER_SESSION_REQUEST: u32 = 303;
    /// Attribute id: the legitimation challenge response (server-session response).
    pub const SERVER_SESSION_RESPONSE: u32 = 304;
    /// Attribute id: the effective protection level of the running program.
    pub const EFFECTIVE_PROTECTION_LEVEL: u32 = 1842;
    /// Attribute id: the `Legitimate` action (submit credentials).
    pub const LEGITIMATE: u32 = 1846;
    /// LID: the legitimation credentials struct.
    pub const LID_LEGITIMATION_PAYLOAD_STRUCT: u32 = 40400;
    /// LID: the legitimation type field.
    pub const LID_LEGITIMATION_PAYLOAD_TYPE: u32 = 40401;
    /// LID: the legitimation username field.
    pub const LID_LEGITIMATION_PAYLOAD_USERNAME: u32 = 40402;
    /// LID: the legitimation password field.
    pub const LID_LEGITIMATION_PAYLOAD_PASSWORD: u32 = 40403;
}

/// Wrap a PDU body in the S7CommPlus header + trailer, as one chunk.
///
/// Requests that are too large for one chunk are split afterwards with [`split_framed_pdu`].
/// Received telegrams reassembled from several chunks are re-wrapped here too and can exceed the
/// `u16` length field; it then saturates at `u16::MAX`, and readers find the end of the body from
/// the trailer instead (see [`PduHeader::body_end`]).
pub fn frame_single_pdu(proto_version: u8, body: &[u8]) -> Vec<u8> {
    let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(body.len() + 8);
    // header
    out.push(PROTOCOL_ID);
    out.push(proto_version);
    out.extend_from_slice(&len.to_be_bytes());
    // payload
    out.extend_from_slice(body);
    // trailer
    out.push(PROTOCOL_ID);
    out.push(proto_version);
    out.push(0x00);
    out.push(0x00);
    out
}

/// Largest payload per chunk when sending over TLS. It matches the chunks the PLC itself sends,
/// which keeps every TLS record inside one COTP frame of the 1024-byte TPDU size negotiated in
/// the connection request. A larger frame makes the PLC drop the connection.
pub const MAX_CHUNK_PAYLOAD: usize = 979;

/// Largest telegram the receive paths reassemble. Real responses (even an Explore of a large
/// program's type info) are far smaller; the cap keeps a misbehaving peer from growing the
/// reassembly buffer without bound.
pub const MAX_TELEGRAM_LEN: usize = 64 * 1024 * 1024;

/// Split a [`frame_single_pdu`]-framed telegram into chunks of at most `max_payload` bytes,
/// each with its own header and the trailer only on the last. Each chunk is meant to be sent
/// as a separate TLS record. A telegram that already fits is returned unchanged.
pub fn split_framed_pdu(framed: &[u8], max_payload: usize) -> Vec<Vec<u8>> {
    let max_payload = max_payload.max(1);
    if framed.len() < 8 || framed.len() - 8 <= max_payload {
        return vec![framed.to_vec()];
    }
    let version = framed[1];
    let body = &framed[4..framed.len() - 4];
    let mut chunks: Vec<Vec<u8>> = body
        .chunks(max_payload)
        .map(|part| {
            let mut chunk = Vec::with_capacity(part.len() + 8);
            chunk.extend_from_slice(&[PROTOCOL_ID, version]);
            chunk.extend_from_slice(&(part.len() as u16).to_be_bytes());
            chunk.extend_from_slice(part);
            chunk
        })
        .collect();
    if let Some(last) = chunks.last_mut() {
        last.extend_from_slice(&framed[framed.len() - 4..]);
    }
    chunks
}

/// A parsed S7CommPlus PDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduHeader {
    /// Protocol version byte from the header (see [`protocol_version`]).
    pub protocol_version: u8,
    /// Declared payload length from the header (bytes between header and trailer).
    pub data_len: u16,
    /// Offset into the original buffer where the PDU body begins.
    pub body_offset: usize,
}

impl PduHeader {
    /// End (exclusive) of the PDU body within `buf`, excluding the `72 ver 00 00` trailer. The
    /// trailer is authoritative when present, since a telegram reassembled from several chunks
    /// can be longer than the `u16` [`data_len`](Self::data_len) field can say.
    pub fn body_end(&self, buf: &[u8]) -> usize {
        let n = buf.len();
        if n >= self.body_offset + 4 && buf[n - 4..] == [PROTOCOL_ID, self.protocol_version, 0, 0] {
            n - 4
        } else if self.data_len > 0 {
            (self.body_offset + self.data_len as usize).min(n)
        } else {
            n
        }
    }
}

/// Parse the leading S7CommPlus header from a received telegram.
///
/// Tolerant of whether the caller stripped the `0x72` header already: if the buffer
/// begins with [`PROTOCOL_ID`] the full 4-byte header is consumed; otherwise the first
/// byte is treated as the protocol version (mirroring the reference driver's
/// `DeserializeFromPdu`, which reads the protocol version first).
pub fn parse_header(buf: &[u8]) -> crate::Result<PduHeader> {
    if buf.is_empty() {
        return Err(crate::Error::protocol("empty S7CommPlus PDU"));
    }
    if buf[0] == PROTOCOL_ID {
        if buf.len() < 4 {
            return Err(crate::Error::protocol("truncated S7CommPlus header"));
        }
        Ok(PduHeader {
            protocol_version: buf[1],
            data_len: u16::from_be_bytes([buf[2], buf[3]]),
            body_offset: 4,
        })
    } else {
        Ok(PduHeader {
            protocol_version: buf[0],
            data_len: 0,
            body_offset: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_framed_pdu_keeps_small_telegrams_whole() {
        let framed = frame_single_pdu(protocol_version::V2, &[1, 2, 3]);
        assert_eq!(split_framed_pdu(&framed, 3), vec![framed.clone()]);
    }

    #[test]
    fn split_framed_pdu_chunks_with_trailer_on_last() {
        let body: Vec<u8> = (0..10).collect();
        let framed = frame_single_pdu(protocol_version::V2, &body);
        let chunks = split_framed_pdu(&framed, 4);
        assert_eq!(
            chunks,
            vec![
                vec![0x72, 0x02, 0x00, 0x04, 0, 1, 2, 3],
                vec![0x72, 0x02, 0x00, 0x04, 4, 5, 6, 7],
                vec![0x72, 0x02, 0x00, 0x02, 8, 9, 0x72, 0x02, 0x00, 0x00],
            ]
        );
        // Reassembled the way the receive path does, the body is unchanged.
        let rejoined: Vec<u8> = chunks
            .iter()
            .flat_map(|c| {
                let len = u16::from_be_bytes([c[2], c[3]]) as usize;
                c[4..4 + len].to_vec()
            })
            .collect();
        assert_eq!(rejoined, body);
    }

    #[test]
    fn frame_single_pdu_layout() {
        let body = [0x31, 0x00, 0x00];
        let framed = frame_single_pdu(protocol_version::V1, &body);
        assert_eq!(
            framed,
            vec![
                0x72, 0x01, 0x00, 0x03, // header: id, V1, len=3
                0x31, 0x00, 0x00, // body
                0x72, 0x01, 0x00, 0x00, // trailer
            ]
        );
    }

    #[test]
    fn parse_header_with_id() {
        let buf = [0x72, 0x01, 0x00, 0x12, 0x32];
        let h = parse_header(&buf).unwrap();
        assert_eq!(h.protocol_version, protocol_version::V1);
        assert_eq!(h.data_len, 0x12);
        assert_eq!(h.body_offset, 4);
    }

    #[test]
    fn parse_header_stripped() {
        // Buffer that already had the 0x72 stripped: first byte is the version.
        let buf = [0x01, 0x32, 0x00, 0x00];
        let h = parse_header(&buf).unwrap();
        assert_eq!(h.protocol_version, protocol_version::V1);
        assert_eq!(h.body_offset, 1);
    }
}
