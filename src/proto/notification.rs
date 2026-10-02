// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/Notification.cs, LGPL-3.0-or-later.

//! Notification (opcode `0x33`) parsing — the unsolicited subscription updates the PLC pushes
//! after a subscription is created.

use std::io::{Cursor, Seek, SeekFrom};

use crate::error::{Error, Result};
use crate::proto::object::{decode_object_list, PObject};
use crate::value::PValue;
use crate::wire::pdu::{self, opcode};
use crate::wire::{primitives as p, vlq};

/// A parsed subscription notification.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The subscription object id this notification belongs to.
    pub subscription_object_id: u32,
    /// Credit tick — increments each cycle; the client tops up the credit limit before it
    /// reaches the limit (only needed for a finite credit limit).
    pub credit_tick: u8,
    /// The notification sequence number.
    pub sequence_number: u32,
    /// `(reference_id, value)` for each item whose value is present in this notification. On a
    /// no-change cycle this may be empty (a heartbeat).
    pub values: Vec<(u32, PValue)>,
    /// `(reference_id, return_code)` for items the PLC reported an access error for.
    pub errors: Vec<(u32, u8)>,
    /// Trailing alarm objects (the "P2" block) present in alarm-subscription notifications;
    /// empty for variable subscriptions. Parse with [`crate::proto::Alarm::from_object`].
    pub alarm_objects: Vec<PObject>,
}

impl Notification {
    /// Decode the trailing alarm objects into [`Alarm`](crate::proto::Alarm)s, skipping any that
    /// fail to parse. Empty for variable subscriptions.
    pub fn alarms(&self) -> Vec<crate::proto::Alarm> {
        self.alarm_objects
            .iter()
            .filter_map(|o| crate::proto::Alarm::from_object(o).ok())
            .collect()
    }
}

/// Parse a Notification telegram (a framed PDU whose opcode is `0x33`).
pub fn parse_notification(buf: &[u8]) -> Result<Notification> {
    let h = pdu::parse_header(buf)?;
    // Exclude the trailing `72 ver 00 00` frame trailer — otherwise the optional-alarm-block peek
    // below would mistake it for data.
    let end = h.body_end(buf);
    let mut cur = Cursor::new(&buf[h.body_offset..end]);

    let op = p::decode_u8(&mut cur)?;
    if op != opcode::NOTIFICATION {
        return Err(Error::protocol(format!(
            "expected opcode NOTIFICATION (0x{:02x}), got 0x{op:02x}",
            opcode::NOTIFICATION
        )));
    }

    let subscription_object_id = p::decode_u32(&mut cur)?;
    let _unknown2 = p::decode_u16(&mut cur)?;
    let _unknown3 = p::decode_u16(&mut cur)?;
    let _unknown4 = p::decode_u16(&mut cur)?;
    let credit_tick = p::decode_u8(&mut cur)?;
    let sequence_number = vlq::decode_u32(&mut cur)?;

    // Subscription change counter, OR (newer firmware, when the byte is 0) an 8-byte UTC
    // timestamp whose first byte is that 0, followed by a change-counter byte.
    let ccnt = p::decode_u8(&mut cur)?;
    if ccnt == 0 {
        cur.seek(SeekFrom::Current(-1))?; // that 0 is the first byte of the timestamp
        let _timestamp = p::decode_u64(&mut cur)?;
        let _add1_change_counter = p::decode_u8(&mut cur)?;
    }

    // Value list: (return-code, ref-id, value?) triples terminated by a 0x00 return code.
    let mut values = Vec::new();
    let mut errors = Vec::new();
    loop {
        let item_return = p::decode_u8(&mut cur)?;
        match item_return {
            0x00 => break,
            0x92 => {
                // Success, fixed-width reference id.
                let itemref = p::decode_u32(&mut cur)?;
                values.push((itemref, PValue::deserialize(&mut cur)?));
            }
            0x9b => {
                // Success, VLQ reference id (S7-1200 / 1500).
                let itemref = vlq::decode_u32(&mut cur)?;
                values.push((itemref, PValue::deserialize(&mut cur)?));
            }
            0x9c => {
                // Variable-status-table form — ignored (id only, no value we model).
                let _ = p::decode_u32(&mut cur)?;
            }
            0x03 | 0x13 => {
                // Addressing error for this item.
                let itemref = p::decode_u32(&mut cur)?;
                errors.push((itemref, item_return));
            }
            other => {
                // 0x83 (v1) and any unknown code are not modelled (upstream throws here too).
                return Err(Error::protocol(format!(
                    "notification: unsupported item return code 0x{other:02x}"
                )));
            }
        }
    }
    // Optional trailing alarm-object block ("P2"): present for alarm subscriptions. If the next
    // byte is non-zero, a P2 header (subscription id, unknown u16, return code) precedes an
    // object list (return code 0x81).
    let mut alarm_objects = Vec::new();
    let pos = cur.position() as usize;
    let has_p2 = cur.get_ref().get(pos).is_some_and(|&b| b != 0);
    if has_p2 {
        let _p2_subscription_object_id = p::decode_u32(&mut cur)?;
        let _p2_unknown1 = p::decode_u16(&mut cur)?;
        let p2_return_value = p::decode_u8(&mut cur)?;
        if p2_return_value == 0x81 {
            alarm_objects = decode_object_list(&mut cur)?;
        }
    }

    Ok(Notification {
        subscription_object_id,
        credit_tick,
        sequence_number,
        values,
        errors,
        alarm_objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a framed notification telegram body for testing.
    fn framed(body: &[u8]) -> Vec<u8> {
        pdu::frame_single_pdu(pdu::protocol_version::V3, body)
    }

    #[test]
    fn parse_with_timestamp_and_two_values() {
        let mut body = vec![opcode::NOTIFICATION];
        body.extend_from_slice(&0x0000_00a1u32.to_be_bytes()); // subscription object id
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // unknown2/3/4
        body.push(0x00); // credit tick
        body.push(0x05); // sequence number (VLQ, small)
                         // change counter byte == 0 IS the first byte of the 8-byte UTC timestamp that follows.
        body.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]); // 8-byte ts
        body.push(0x01); // add1 change counter
                         // value 1: 0x92, ref 1 (fixed u32), DInt(7)
        body.push(0x92);
        body.extend_from_slice(&1u32.to_be_bytes());
        PValue::DInt(7).serialize(&mut body).unwrap();
        // value 2: 0x9b, ref 2 (VLQ), Bool(true)
        body.push(0x9b);
        body.push(0x02);
        PValue::Bool(true).serialize(&mut body).unwrap();
        body.push(0x00); // terminator

        let n = parse_notification(&framed(&body)).unwrap();
        assert_eq!(n.subscription_object_id, 0xa1);
        assert_eq!(n.sequence_number, 5);
        assert_eq!(n.values.len(), 2);
        assert_eq!(n.values[0], (1, PValue::DInt(7)));
        assert_eq!(n.values[1], (2, PValue::Bool(true)));
        assert!(n.errors.is_empty());
    }

    #[test]
    fn parse_change_counter_and_error_item() {
        let mut body = vec![opcode::NOTIFICATION];
        body.extend_from_slice(&7u32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        body.push(0x02); // credit tick
        body.push(0x09); // sequence
        body.push(0x03); // change counter != 0 -> no timestamp
                         // error item: 0x13, ref 4
        body.push(0x13);
        body.extend_from_slice(&4u32.to_be_bytes());
        body.push(0x00);

        let n = parse_notification(&framed(&body)).unwrap();
        assert_eq!(n.credit_tick, 2);
        assert!(n.values.is_empty());
        assert_eq!(n.errors, vec![(4, 0x13)]);
    }

    #[test]
    fn empty_heartbeat_notification() {
        let mut body = vec![opcode::NOTIFICATION];
        body.extend_from_slice(&7u32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        body.push(0x01);
        body.push(0x01);
        body.push(0x02); // change counter
        body.push(0x00); // immediate terminator (no values)
        let n = parse_notification(&framed(&body)).unwrap();
        assert!(n.values.is_empty() && n.errors.is_empty());
    }

    #[test]
    fn wrong_opcode_errors() {
        let body = vec![opcode::RESPONSE, 0, 0, 0, 0];
        assert!(parse_notification(&framed(&body)).is_err());
    }
}
