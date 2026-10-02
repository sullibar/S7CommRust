// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver ClientApi/ItemAddress.cs, LGPL-3.0-or-later. The
// byte-offset addressing (`Area`, `ItemAddress::raw`) follows gijzelaerr/s7commplus `client.py`.

//! `ItemAddress` — the symbolic address of a variable for Get/SetMultiVariables.
//!
//! An address is the symbol CRC, the access area (base relation id), the access sub-area,
//! and a list of LIDs (link/location ids) that walk into the symbol's structure. All
//! fields are VLQ-encoded; the serialized LID count is `LID.len() + 1` (the reference adds
//! one for the leading sub-area entry).

use std::io::Write;

use crate::error::Result;
use crate::wire::vlq;

/// A symbolic item address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ItemAddress {
    /// CRC of the symbol name (or 0 when addressing purely by area + LID path).
    pub symbol_crc: u32,
    /// Access area — the DB relation id, or the M/Q/I area RID.
    pub access_area: u32,
    /// Access sub-area (e.g. `DB_ValueActual`).
    pub access_sub_area: u32,
    /// Link/location ids walking into the symbol's structure.
    pub lid: Vec<u32>,
}

/// A memory area read and written by byte offset ([`ItemAddress::raw`]), as with the classic
/// S7 protocol: a data block, or the process image or bit memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Area {
    /// A data block, by number. Only a *standard* (not optimized) block has a byte layout; the
    /// PLC refuses byte-offset access to an optimized one.
    Db(u16),
    /// The process image of the inputs (`%I`).
    Inputs,
    /// The process image of the outputs (`%Q`).
    Outputs,
    /// Bit memory (`%M`).
    Memory,
}

/// Base of a data block's access area (`Ids.DB_AccessArea_Base`); the DB number is added.
const DB_ACCESS_AREA_BASE: u32 = 0x8a0e_0000;
/// `AccessSubArea` of a data block's values (`Ids.DB_ValueActual`).
pub(crate) const DB_VALUE_ACTUAL: u32 = 2550;
/// `AccessSubArea` of an I/Q/M area's values (`Ids.ControllerArea_ValueActual`).
pub(crate) const CONTROLLER_AREA_VALUE_ACTUAL: u32 = 3736;
/// The LID that addresses a byte range (`LID_OMS_STB_ClassicBlob`), followed by start and length.
const LID_CLASSIC_BLOB: u32 = 3;

impl ItemAddress {
    /// The address of `len` bytes at byte offset `start` of `area`. Read, its value is a
    /// [`PValue::Blob`](crate::value::PValue::Blob) of those bytes; write one to set them.
    pub fn raw(area: Area, start: u32, len: u32) -> ItemAddress {
        let (access_area, access_sub_area) = match area {
            Area::Db(number) => (DB_ACCESS_AREA_BASE + u32::from(number), DB_VALUE_ACTUAL),
            Area::Inputs => (80, CONTROLLER_AREA_VALUE_ACTUAL),
            Area::Outputs => (81, CONTROLLER_AREA_VALUE_ACTUAL),
            Area::Memory => (82, CONTROLLER_AREA_VALUE_ACTUAL),
        };
        ItemAddress {
            symbol_crc: 0,
            access_area,
            access_sub_area,
            lid: vec![LID_CLASSIC_BLOB, start, len],
        }
    }

    /// Serialize the address. Returns bytes written.
    pub fn serialize<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = 0;
        n += vlq::encode_u32(w, self.symbol_crc)?;
        n += vlq::encode_u32(w, self.access_area)?;
        n += vlq::encode_u32(w, self.lid.len() as u32 + 1)?;
        n += vlq::encode_u32(w, self.access_sub_area)?;
        for id in &self.lid {
            n += vlq::encode_u32(w, *id)?;
        }
        Ok(n)
    }

    /// Number of serialized VLQ fields this address contributes to the request's total
    /// field-count tally: the 4 leading fields (symbol_crc, access_area, id-count,
    /// access_sub_area) plus one per LID. Matches the reference `GetNumberOfFields`.
    pub fn field_count(&self) -> u32 {
        4 + self.lid.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_layout() {
        let addr = ItemAddress {
            symbol_crc: 0,
            access_area: 3,
            access_sub_area: 0,
            lid: vec![1, 2],
        };
        let mut out = Vec::new();
        addr.serialize(&mut out).unwrap();
        // symbol_crc=0, access_area=3, count=lid+1=3, sub_area=0, lids 1,2
        assert_eq!(out, vec![0x00, 0x03, 0x03, 0x00, 0x01, 0x02]);
        assert_eq!(addr.field_count(), 6); // 4 leading fields + 2 LIDs
    }

    #[test]
    fn raw_addresses() {
        let mut out = Vec::new();
        ItemAddress::raw(Area::Db(1), 2, 4)
            .serialize(&mut out)
            .unwrap();
        // crc 0, area 0x8a0e0001, 4 ids, sub-area 2550 (DB.ValueActual), classic blob 3, start, len
        assert_eq!(
            out,
            [0x00, 0x88, 0xd0, 0xb8, 0x80, 0x01, 0x04, 0x93, 0x76, 0x03, 0x02, 0x04]
        );
        let m = ItemAddress::raw(Area::Memory, 300, 1);
        assert_eq!((m.access_area, m.access_sub_area), (82, 3736));
        assert_eq!(m.lid, [3, 300, 1]);
        assert_eq!(ItemAddress::raw(Area::Inputs, 0, 1).access_area, 80);
        assert_eq!(ItemAddress::raw(Area::Outputs, 0, 1).access_area, 81);
        assert_eq!(
            ItemAddress::raw(Area::Db(60999), 0, 1).access_area,
            0x8a0e_ee47
        );
    }

    #[test]
    fn vlq_widths_for_large_ids() {
        let addr = ItemAddress {
            symbol_crc: 0x4000,
            access_area: 0,
            access_sub_area: 0,
            lid: vec![],
        };
        let mut out = Vec::new();
        addr.serialize(&mut out).unwrap();
        // symbol_crc 0x4000 -> 81 80 00; access_area 0 -> 00; count 1 -> 01; sub_area 0 -> 00
        assert_eq!(out, vec![0x81, 0x80, 0x00, 0x00, 0x01, 0x00]);
    }
}
