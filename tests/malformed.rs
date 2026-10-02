// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Malformed-input tests over the public parsers. Everything a parser reads comes from the PLC (or,
// on the unauthenticated legacy path, from anyone on the network), so no input may panic, overflow
// the stack or trigger a huge allocation: each of those aborts the whole process. The regression
// cases below each used to do one of those; the mutation loop at the end shakes out the rest.

use std::io::Cursor;

use s7commplus::proto::{self, decode_object_list, PObject};
use s7commplus::value::datatype::tag as dt;
use s7commplus::value::{datetime, strings, PValue};
use s7commplus::wire::pdu::{self, functioncode, opcode, protocol_version};
use s7commplus::wire::vlq;

/// Real Explore responses captured from PLCSIM Advanced (legacy FW 2.8): a DB's type info with
/// arrays and nested structs, a plain DB's type info, and the program browse for data blocks.
const EXPLORE_CAPTURES: [&[u8]; 3] = [
    include_bytes!("vectors/proto/explore_ti_92000001.bin"),
    include_bytes!("vectors/proto/explore_ti_92000002.bin"),
    include_bytes!("vectors/proto/explore_program.bin"),
];

/// Run `f` on a thread with a 1 MiB stack — the size of the Windows main thread, the smallest a
/// caller is likely to use — so a recursion the depth limits miss shows up as a failure here.
fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// A framed response telegram: header for `function_code` with return value 0, then `body`.
fn response(function_code: u16, body: &[u8]) -> Vec<u8> {
    let mut b = vec![opcode::RESPONSE, 0, 0];
    b.extend_from_slice(&function_code.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 7, 0]); // reserved, sequence 7, transport flags
    vlq::encode_u64(&mut b, 0).unwrap();
    b.extend_from_slice(body);
    pdu::frame_single_pdu(protocol_version::V2, &b)
}

/// One value of (nearly) every datatype, for the GetMultiVariables and notification seeds.
fn sample_values() -> Vec<PValue> {
    vec![
        PValue::Bool(true),
        PValue::USInt(200),
        PValue::UInt(0xbeef),
        PValue::UDInt(70_000),
        PValue::ULInt(u64::MAX),
        PValue::SInt(-5),
        PValue::Int(-300),
        PValue::DInt(i32::MIN),
        PValue::LInt(i64::MIN),
        PValue::Real(1.5),
        PValue::LReal(-2.25),
        PValue::Timestamp(0x0011_2233_4455_6677),
        PValue::Timespan(-1),
        PValue::Blob {
            root_id: 3,
            data: vec![1, 2, 3],
        },
        PValue::WString("Grüße".into()),
        PValue::USIntArray(vec![10, 3, b'a', b'b', b'c']),
        PValue::Array {
            element_type: dt::UINT,
            flags: s7commplus::value::datatype::flags::ARRAY,
            items: vec![PValue::UInt(4), PValue::UInt(2), PValue::UInt(0x41)],
        },
        PValue::Struct {
            id: 1,
            elements: vec![
                (1, PValue::DInt(9)),
                (
                    2,
                    PValue::Struct {
                        id: 2,
                        elements: vec![(1, PValue::Bool(false))],
                    },
                ),
            ],
        },
    ]
}

fn get_multi_seed() -> Vec<u8> {
    let mut body = Vec::new();
    let values = sample_values();
    for (i, v) in values.iter().enumerate() {
        vlq::encode_u32(&mut body, i as u32 + 1).unwrap();
        v.serialize(&mut body).unwrap();
    }
    body.push(0); // end of values
    vlq::encode_u32(&mut body, values.len() as u32 + 1).unwrap();
    vlq::encode_u64(&mut body, 0x8000_0000_0000_0013).unwrap(); // one item error
    body.push(0); // end of errors
    vlq::encode_u32(&mut body, 42).unwrap(); // integrity id
    response(functioncode::GET_MULTI_VARIABLES, &body)
}

fn notification_seed() -> Vec<u8> {
    let mut body = vec![opcode::NOTIFICATION];
    body.extend_from_slice(&0x0000_00a1u32.to_be_bytes());
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    body.push(3); // credit tick
    body.push(5); // sequence number
    body.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]); // timestamp
    body.push(1); // change counter
    for (i, v) in sample_values().iter().enumerate() {
        body.push(0x9b);
        vlq::encode_u32(&mut body, i as u32 + 1).unwrap();
        v.serialize(&mut body).unwrap();
    }
    body.push(0x13); // an item error
    body.extend_from_slice(&99u32.to_be_bytes());
    body.push(0); // end of items
    pdu::frame_single_pdu(protocol_version::V3, &body)
}

/// Feed `buf` to every parser that accepts a whole telegram, plus the helpers callers run on
/// what comes out. The only requirement is not panicking.
fn parse_everything(buf: &[u8]) {
    let _ = proto::parse_get_multi_response(buf);
    let _ = proto::parse_set_multi_response(buf);
    let _ = proto::parse_create_object_response(buf);
    let _ = proto::parse_delete_object_response(buf);
    let _ = proto::parse_get_var_substreamed_response(buf);
    let _ = proto::parse_set_variable_response(buf);
    let _ = proto::parse_init_ssl_response(buf);
    let _ = proto::parse_system_event(buf);
    let _ = s7commplus::decompress_blob(buf, 0);
    for with_integrity in [false, true] {
        if let Ok(resp) = proto::parse_explore_response(buf, with_integrity) {
            for obj in &resp.objects {
                inspect_object(obj);
            }
        }
    }
    if let Ok(n) = proto::parse_notification(buf) {
        for alarm in n.alarms() {
            let _ = alarm.message(1033);
        }
        for (_, v) in &n.values {
            inspect_value(v);
        }
    }
    if let Ok(r) = proto::parse_get_multi_response(buf) {
        for (_, v) in &r.values {
            inspect_value(v);
        }
    }
    let _ = PValue::deserialize(&mut Cursor::new(buf));
    let _ = decode_object_list(&mut Cursor::new(buf));
}

fn inspect_object(obj: &PObject) {
    if let Ok(alarm) = proto::Alarm::from_object(obj) {
        let _ = alarm.message(1033);
    }
    for (_, v) in &obj.attributes {
        inspect_value(v);
    }
    for child in &obj.objects {
        inspect_object(child);
    }
}

fn inspect_value(v: &PValue) {
    use s7commplus::value::datatype::softdatatype as sdt;
    for t in [
        sdt::DATE,
        sdt::TIME_OF_DAY,
        sdt::TIME,
        sdt::S5TIME,
        sdt::DATE_AND_TIME,
        sdt::LTIME,
        sdt::LTOD,
        sdt::LDT,
        sdt::DTL,
    ] {
        let _ = datetime::format(t, v);
    }
    let _ = strings::decode_wstring(v);
    if let Some(bytes) = v.as_bytes() {
        let _ = strings::decode_s7_string(bytes);
    }
    // Whatever decodes must serialize without panicking too (it may legitimately error).
    let _ = v.serialize(&mut Vec::new());
}

/// Values a mutation writes over a byte: tags, flags and VLQ continuation patterns that steer the
/// parsers into their deeper branches.
const INTERESTING: [u8; 16] = [
    0x00, 0x01, 0x10, 0x17, 0x20, 0x40, 0x72, 0x7f, 0x80, 0x8f, 0x9b, 0xa1, 0xa2, 0xa3, 0xab, 0xff,
];

/// xorshift64* — deterministic, so a failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        let len = v.len();
        match rng.below(6) {
            0 if len > 0 => {
                let i = rng.below(len);
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                v[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => v.truncate(rng.below(len + 1)),
            3 => {
                let at = rng.below(len + 1);
                let junk: Vec<u8> = (0..1 + rng.below(8)).map(|_| rng.next() as u8).collect();
                v.splice(at..at, junk);
            }
            4 if len > 1 => {
                // Copy a range elsewhere — repeats structure, which builds nesting.
                let start = rng.below(len);
                let end = start + 1 + rng.below((len - start).min(64));
                let at = rng.below(len + 1);
                let piece = v[start..end].to_vec();
                v.splice(at..at, piece);
            }
            5 if len > 1 => {
                let start = rng.below(len);
                let end = (start + 1 + rng.below(16)).min(len);
                v.drain(start..end);
            }
            _ => {}
        }
    }
    v
}

#[test]
fn mutated_telegrams_never_panic() {
    on_small_stack(|| {
        let mut seeds: Vec<Vec<u8>> = EXPLORE_CAPTURES.iter().map(|c| c.to_vec()).collect();
        seeds.push(get_multi_seed());
        seeds.push(notification_seed());
        // The seeds themselves must parse, or the mutations explore nothing useful.
        for capture in EXPLORE_CAPTURES {
            proto::parse_explore_response(capture, true).unwrap();
        }
        assert_eq!(
            proto::parse_get_multi_response(&get_multi_seed())
                .unwrap()
                .values
                .len(),
            sample_values().len()
        );
        assert_eq!(
            proto::parse_notification(&notification_seed())
                .unwrap()
                .values
                .len(),
            sample_values().len()
        );

        let mut rng = Rng(0x5eed_cafe_f00d_d00d);
        for seed in &seeds {
            for _ in 0..4000 {
                parse_everything(&mutate(&mut rng, seed));
            }
        }
    });
}

/// `depth` nested non-packed structs, each holding the next as member 1, around a `DInt`.
fn nested_struct(depth: usize) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..depth {
        b.extend_from_slice(&[0x00, dt::STRUCT, 0, 0, 0, 1, 0x01]); // struct id 1, member key 1
    }
    PValue::DInt(1).serialize(&mut b).unwrap();
    b.extend(std::iter::repeat_n(0x00, depth)); // member-list terminators
    b
}

/// `depth` nested objects; the innermost carries `attribute` (a serialized value), if any.
fn nested_objects(depth: usize, attribute: Option<&[u8]>) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..depth {
        b.extend_from_slice(&[0xa1, 0, 0, 0, 1, 0x01, 0x00, 0x00]); // rid 1, class 1, flags, aid
    }
    if let Some(value) = attribute {
        b.extend_from_slice(&[0xa3, 0x01]);
        b.extend_from_slice(value);
    }
    b.extend(std::iter::repeat_n(0xa2, depth));
    b
}

#[test]
fn deep_struct_nesting_is_an_error_not_a_stack_overflow() {
    on_small_stack(|| {
        // 2000 levels (14 KB) used to overflow the stack and abort the process.
        assert!(PValue::deserialize(&mut Cursor::new(nested_struct(2000))).is_err());
        // Real values nest a few levels and still decode.
        assert!(PValue::deserialize(&mut Cursor::new(nested_struct(8))).is_ok());
    });
}

#[test]
fn deep_object_nesting_is_an_error_not_a_stack_overflow() {
    on_small_stack(|| {
        let deep = nested_objects(2000, None);
        assert!(decode_object_list(&mut Cursor::new(&deep[..])).is_err());
        let explore = response(functioncode::EXPLORE, &[&[0, 0, 0, 3][..], &deep].concat());
        assert!(proto::parse_explore_response(&explore, false).is_err());
    });
}

#[test]
fn deepest_accepted_nesting_fits_a_small_stack() {
    // The worst case the limits allow — maximally nested objects whose innermost attribute is a
    // maximally nested value — must still fit, even in a debug build.
    on_small_stack(|| {
        let value = nested_struct(s7commplus::value::pvalue::MAX_VALUE_NESTING);
        let objects = nested_objects(33, Some(&value));
        let list = decode_object_list(&mut Cursor::new(&objects[..])).unwrap();
        assert_eq!(list.len(), 1);
    });
}

#[test]
fn huge_element_counts_do_not_allocate_up_front() {
    // A UInt array claiming 0xFFFFFFFF elements: used to abort trying to allocate 171 GB.
    assert!(PValue::deserialize(&mut Cursor::new(&[
        0x10,
        dt::UINT,
        0x8f,
        0xff,
        0xff,
        0xff,
        0x7f
    ]))
    .is_err());
    // Null elements take no bytes, so only the count bounded the loop (33M values in 0.7 s).
    assert!(
        PValue::deserialize(&mut Cursor::new(&[0x10, dt::NULL, 0x8f, 0xff, 0xff, 0x7f])).is_err()
    );
    // A 4 GiB Blob / WString / byte array length with nothing behind it.
    for datatype in [dt::BLOB, dt::WSTRING] {
        let mut b = vec![0x00, datatype];
        if datatype == dt::BLOB {
            b.push(0x00); // root id
        }
        b.extend_from_slice(&[0x8f, 0xff, 0xff, 0xff, 0x7f]);
        assert!(PValue::deserialize(&mut Cursor::new(b)).is_err());
    }
    assert!(PValue::deserialize(&mut Cursor::new(&[
        0x10,
        dt::USINT,
        0x8f,
        0xff,
        0xff,
        0xff,
        0x7f
    ]))
    .is_err());
}

#[test]
fn truncated_input_is_a_protocol_error_not_a_lost_connection() {
    // Parsers read from memory: running out of bytes means a malformed telegram. Reporting it as
    // an I/O EOF made callers treat a decode problem as a dropped connection.
    let seed = get_multi_seed();
    for cut in 1..seed.len() - 4 {
        if let Err(e) = proto::parse_get_multi_response(&seed[..cut]) {
            assert!(!e.is_connection_lost(), "cut at {cut}: {e}");
        }
    }
}

#[test]
fn telegrams_over_64k_keep_their_body() {
    // A reassembled notification larger than the u16 length field: the field used to wrap, which
    // cut the body short (or to nothing at exact multiples of 64 KiB).
    for blob_len in [70_000usize, 65_536 * 2 - 40] {
        let mut body = vec![opcode::NOTIFICATION];
        body.extend_from_slice(&7u32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1, 1]); // unknowns, tick, seq, counter
        body.push(0x9b);
        body.push(0x01);
        PValue::Blob {
            root_id: 0,
            data: vec![0x5a; blob_len],
        }
        .serialize(&mut body)
        .unwrap();
        body.push(0x00);
        let n = proto::parse_notification(&pdu::frame_single_pdu(protocol_version::V3, &body))
            .unwrap_or_else(|e| panic!("blob of {blob_len}: {e}"));
        match &n.values[0].1 {
            PValue::Blob { data, .. } => assert_eq!(data.len(), blob_len),
            other => panic!("unexpected value {other:?}"),
        }
    }
}

#[test]
fn split_with_zero_chunk_size_does_not_panic() {
    let framed = pdu::frame_single_pdu(protocol_version::V2, &[1, 2, 3]);
    let chunks = pdu::split_framed_pdu(&framed, 0);
    assert_eq!(chunks.len(), 3);
}
