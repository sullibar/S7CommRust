// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! Frames TIA Portal exchanged with a PLCSIM S7-1500 (FW V2.9), decoded with this crate's
//! parsers and request builders.
//!
//! The frames come from an independent capture between TIA Portal and the PLC (TLS terminated by
//! a pinned proxy) that bmappi shared in gijzelaerr/s7commplus#45; that project keeps them in
//! `tests/fixtures/golden_tia_online_session_20260915.py` (MIT, see
//! `LICENSE-gijzelaerr-s7commplus`). They are TIA's own traffic, so they pin this crate against a
//! second implementation rather than against itself.

use hex_literal::hex;
use s7commplus::proto;
use s7commplus::value::PValue;
use s7commplus::wire::pdu::{ids, protocol_version};

/// TIA's Explore of the device tree (rid 0x22): children, no attributes, integrity id 4.
const EXPLORE_DEVICE_TREE: [u8; 34] =
    hex!("7202001e31000004bb000000097000103d3400000022000101000000040000000000");

#[test]
fn the_explore_request_matches_tia_byte_for_byte() {
    let ours = proto::build_explore_request(
        protocol_version::V2,
        0x0009,      // sequence number
        0x7000_103d, // session id
        0x22,        // the device tree
        ids::NONE,   // no explore request id
        1,           // with children
        0,           // without parents
        &[],         // all attributes
        true,
        4, // integrity id
    )
    .unwrap();
    // The capture holds the PDU without its `72 02 00 00` trailer.
    let (pdu, trailer) = ours.split_at(ours.len() - 4);
    assert_eq!(pdu, EXPLORE_DEVICE_TREE);
    assert_eq!(trailer, [0x72, 0x02, 0x00, 0x00]);
}

/// A notification from TIA's CPU-state subscription: subscription 0x7000103f, credit tick 0,
/// sequence number 2, a timestamp block (change counter 0), then one struct value.
const NOTIFICATION_CPU_STATE: [u8; 63] = hex!(
    "7202003b337000103f040000000000000200065b8ba19931a9029200000001001700000e799c74000803"
    "9c700008019c710008029c72000800000000000000"
);

#[test]
fn tias_cpu_state_notification() {
    let n = proto::parse_notification(&NOTIFICATION_CPU_STATE).unwrap();
    assert_eq!(n.subscription_object_id, 0x7000_103f);
    assert_eq!(n.credit_tick, 0);
    assert_eq!(n.sequence_number, 2);
    assert!(n.errors.is_empty() && n.alarm_objects.is_empty());
    // Reference 1: struct 3705, members 3700, 3696, 3697, 3698 (VLQ `9c 74`, `9c 70`, …; the
    // fixture's comment says 3760–3764), DInt values (type 0x08) 3, 1, 2, 0.
    assert_eq!(
        n.values,
        vec![(
            1,
            PValue::Struct {
                id: 3705,
                elements: vec![
                    (3700, PValue::DInt(3)),
                    (3696, PValue::DInt(1)),
                    (3697, PValue::DInt(2)),
                    (3698, PValue::DInt(0)),
                ],
            }
        )]
    );
}

/// A notification from TIA's diagnostic-event subscription: sequence number 531 (VLQ `84 13`),
/// one value per registered event object.
const NOTIFICATION_SUB_EVENTS: [u8; 187] = hex!(
    "720200b7337000104004000000000000841300065b8bbdd2a0ce02920000000d000400920000000e0004"
    "00920000000f0008049200000002001700000e799c740008039c700008019c710008029c720008000092"
    "000000030004a2c0800092000000040004009200000005000500920000000600050092000000070004ab"
    "e52092000000080004009200000009000484c08000920000000a00049e808000920000000b0004009200"
    "00000c00040092000000100008020000000000"
);

#[test]
fn tias_event_notification() {
    let n = proto::parse_notification(&NOTIFICATION_SUB_EVENTS).unwrap();
    assert_eq!(n.subscription_object_id, 0x7000_1040);
    assert_eq!(n.sequence_number, 531);
    assert!(n.errors.is_empty() && n.alarm_objects.is_empty());
    let refs: Vec<u32> = n.values.iter().map(|(r, _)| *r).collect();
    assert_eq!(refs, [13, 14, 15, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16]);
    // Reference 2 carries the same CPU-state struct as the notification above.
    let state = NOTIFICATION_CPU_STATE;
    let cpu = proto::parse_notification(&state).unwrap().values[0]
        .1
        .clone();
    assert_eq!(n.values[3], (2, cpu));
    assert_eq!(n.values[0], (13, PValue::UDInt(0)));
    assert_eq!(n.values[2], (15, PValue::DInt(4)));
}

#[test]
fn tias_event_notifications_carry_no_alarms() {
    // The data and alarm notification grammars differ; neither frame has an alarm block.
    for frame in [&NOTIFICATION_CPU_STATE[..], &NOTIFICATION_SUB_EVENTS[..]] {
        assert!(proto::parse_notification(frame)
            .unwrap()
            .alarms()
            .is_empty());
    }
}
