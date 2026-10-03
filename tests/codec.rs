// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Golden-vector tests over the public API. Byte vectors here are derived from the
// reference protocol layout; expand this corpus with captures from the C# driver or a PLC
// (byte-exact protocol reproduction is the key risk). Malformed input is in malformed.rs.

use hex_literal::hex;

use s7commplus::proto::{self, PObject};
use s7commplus::value::datatype::{flags, tag as dt};
use s7commplus::value::PValue;
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

// Explore responses captured from PLCSIM Advanced (legacy FW 2.8; FW 2.9 over TLS encodes them
// the same way) that the object decoder used to reject. In the BlobStructs, the bytes of each
// member blob (password-hash records) are zeroed; everything else is as captured.

/// Explore of the device tree root (rid 0x22), not recursive: an object with a non-zero
/// attribute id, followed by its attribute id flags.
const DEVICE_TREE_ROOT: &[u8] = include_bytes!("vectors/proto/explore_device_tree_root.bin");
/// Recursive explore of the device tree (rid 0x22).
const DEVICE_TREE: &[u8] = include_bytes!("vectors/proto/explore_device_tree.bin");
/// A user-management object (rid 0x89420000) carrying a BlobStruct.
const BLOB_STRUCT: &[u8] = include_bytes!("vectors/proto/explore_blob_struct.bin");
/// An object (rid 0x72007010) carrying an empty address array of non-packed structs.
const STRUCT_ADDRESS_ARRAY: &[u8] =
    include_bytes!("vectors/proto/explore_struct_address_array.bin");
/// The release-management root (rid 0x894a0000), carrying an address array of WStrings.
const WSTRING_ADDRESS_ARRAY: &[u8] =
    include_bytes!("vectors/proto/explore_wstring_address_array.bin");

/// The object list of one of the captures above: after the PDU header (4 bytes), the response
/// header (10), the return value (1), the explore id (4) and the integrity id (1); before the
/// 4-byte fill and the trailer.
fn object_bytes(capture: &[u8]) -> &[u8] {
    assert_eq!(capture[20], 0xa1, "object list starts at byte 20");
    &capture[20..capture.len() - 8]
}

/// Parse `capture`, check that serializing its objects gives back their bytes exactly, and
/// return its one object.
fn round_trip_single_object(capture: &[u8]) -> PObject {
    let resp = proto::parse_explore_response(capture, true).unwrap();
    assert!(resp.header.is_ok());
    let mut out = Vec::new();
    for obj in &resp.objects {
        obj.serialize(&mut out).unwrap();
    }
    assert_eq!(out, object_bytes(capture));
    let [obj] = <[PObject; 1]>::try_from(resp.objects).unwrap();
    obj
}

#[test]
fn explore_device_tree_root_golden() {
    // Used to fail with "unexpected element tag 0x00 (rid=34, clsid=2137)": the 0x00 is the
    // attribute id flags that follow the non-zero attribute id 3410 (`a1 00000022 9059 30 9a52 00`).
    let obj = round_trip_single_object(DEVICE_TREE_ROOT);
    assert_eq!(obj.relation_id, 0x22);
    assert_eq!(obj.class_id, 2137);
    assert_eq!(obj.class_flags, 0x30);
    assert_eq!(obj.attribute_id, 3410);
    assert_eq!(obj.attribute_id_flags, 0);
    assert_eq!(obj.attribute(233), Some(&PValue::WString("PLC_1".into())));
    assert_eq!(obj.attributes.len(), 32);
}

#[test]
fn explore_device_tree_golden() {
    let resp = proto::parse_explore_response(DEVICE_TREE, true).unwrap();
    fn walk<'a>(obj: &'a PObject, all: &mut Vec<&'a PObject>) {
        all.push(obj);
        for child in &obj.objects {
            walk(child, all);
        }
    }
    let mut all = Vec::new();
    for obj in &resp.objects {
        walk(obj, &mut all);
    }
    assert_eq!(all.len(), 21);

    // Attribute id flags above 127 take more than one VLQ byte (0x8000 is `82 80 00`).
    let mut flags: Vec<u32> = all
        .iter()
        .filter(|o| o.attribute_id == 2393)
        .map(|o| o.attribute_id_flags)
        .collect();
    flags.sort_unstable();
    assert_eq!(
        flags,
        [0, 3, 4, 5, 6, 254, 256, 0x8000, 0x8001, 0x8002, 0x8800, 0x8801]
    );

    let blob_structs = all
        .iter()
        .flat_map(|o| &o.attributes)
        .filter(|(_, v)| matches!(v, PValue::BlobStruct { root_id: 1848, .. }))
        .count();
    assert_eq!(blob_structs, 5);

    // Serializing gives back as many bytes. Not the same bytes: the PLC sends some relations
    // ahead of child objects, and a `PObject` writes its relations last.
    let mut out = Vec::new();
    for obj in &resp.objects {
        obj.serialize(&mut out).unwrap();
    }
    assert_eq!(out.len(), object_bytes(DEVICE_TREE).len());
}

#[test]
fn explore_blob_struct_golden() {
    // `00 14 8e38 0000000000000000 00 8e39 <Blob> 8e3a <Blob> 00`: a Blob with root id 1848, 8
    // reserved bytes and blob type 0, holding an ID/value list instead of bytes.
    let obj = round_trip_single_object(BLOB_STRUCT);
    assert_eq!(
        obj.attribute(8081),
        Some(&PValue::BlobStruct {
            root_id: 1848,
            elements: vec![
                (
                    1849,
                    PValue::Blob {
                        root_id: 0,
                        data: vec![]
                    }
                ),
                (
                    1850,
                    PValue::Blob {
                        root_id: 0,
                        data: vec![0; 84]
                    }
                ),
            ],
        })
    );
}

#[test]
fn explore_struct_address_array_golden() {
    // `20 17 00001e2e 00`: an address array of struct 0x1e2e with no elements.
    let obj = round_trip_single_object(STRUCT_ADDRESS_ARRAY);
    assert_eq!(
        obj.attribute(233),
        Some(&PValue::WString("UpdReqJob_01".into()))
    );
    assert_eq!(
        obj.attribute(4568),
        Some(&PValue::StructArray {
            id: 0x1e2e,
            items: vec![]
        })
    );
}

#[test]
fn explore_wstring_address_array_golden() {
    let obj = round_trip_single_object(WSTRING_ADDRESS_ARRAY);
    assert_eq!(
        obj.attribute(8342),
        Some(&PValue::Array {
            element_type: dt::WSTRING,
            flags: flags::ADDRESS_ARRAY,
            items: ["V21.0.0.0", "21.0.0.0", "S7Legacy"]
                .map(|s| PValue::WString(s.into()))
                .to_vec(),
        })
    );
}
