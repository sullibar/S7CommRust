// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Golden-vector tests over the public API. Byte vectors here are derived from the
// reference protocol layout; expand this corpus with captures from the C# driver or a PLC
// (byte-exact protocol reproduction is the key risk). Malformed input is in malformed.rs.

use hex_literal::hex;

use s7commplus::proto;
use s7commplus::wire::pdu::{self, protocol_version};
use s7commplus::wire::vlq;
use std::io::Cursor;

#[test]
fn init_ssl_request_golden() {
    // The first InitSslRequest, framed: header + 18-byte body + trailer.
    let expected = hex!(
        "72 01 00 12"
        "31 00 00 05 b3 00 00 00 01 00 00 01 20 30 00 00 00 00"
        "72 01 00 00"
    );
    assert_eq!(proto::init_ssl_request_default(), expected);
}

#[test]
fn vlq_u32_golden() {
    // 0x4000 -> 81 80 00 (big-endian base-128, continuation bits on all but last).
    let mut out = Vec::new();
    vlq::encode_u32(&mut out, 0x4000).unwrap();
    assert_eq!(out, hex!("81 80 00"));
    assert_eq!(vlq::decode_u32(&mut Cursor::new(&out)).unwrap(), 0x4000);
}

#[test]
fn pdu_single_frame_golden() {
    let framed = pdu::frame_single_pdu(protocol_version::V1, &hex!("31 00 00"));
    assert_eq!(framed, hex!("72 01 00 03 31 00 00 72 01 00 00"));
}
