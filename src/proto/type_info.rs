// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/PVartypeList.cs, Core/PVarnameList.cs,
// and Core/POffsetInfoType.cs, LGPL-3.0-or-later.

//! Type-info structures returned by Explore of a block's type info: the `VartypeList`
//! (one element per member: LID, symbol CRC, datatype, offset info) and the parallel
//! `VarnameList` (member names). Together they map a symbol name to its access LID(s).

use std::io::Cursor;

use crate::error::{Error, Result};
use crate::wire::primitives as p;

/// Per-member offset info. Only the fields needed for symbol→access resolution are kept;
/// the rest are consumed to keep the stream aligned. `kind` is the offset-info-type nibble.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OffsetInfo {
    /// The offset-info-type nibble (0..15) that selected this variant's layout.
    pub kind: u8,
    /// Relation id of the referenced type (structs, FBs) — `Some` iff this has a relation.
    pub relation_id: Option<u32>,
    /// True for a one-dimensional array member.
    pub is_1dim: bool,
    /// True for a multi-dimensional array member.
    pub is_mdim: bool,
    /// Lower bound of a 1-D array.
    pub array_lower_bounds: i32,
    /// Element count of a 1-D array.
    pub array_element_count: u32,
    /// Per-dimension lower bounds of a multi-dimensional array (up to 6 dims).
    pub mdim_lower_bounds: [i32; 6],
    /// Per-dimension element counts of a multi-dimensional array (up to 6 dims).
    pub mdim_element_count: [u32; 6],
    /// For `String`/`StructElemString` members: the declared max length.
    pub string_max_len: u16,
}

impl OffsetInfo {
    /// Whether this member references another type by relation id (a struct or FB).
    pub fn has_relation(&self) -> bool {
        self.relation_id.is_some()
    }

    /// Deserialize the offset info for `kind` (the offsetinfotype nibble 0..15), consuming
    /// exactly the bytes the reference reads for that variant.
    fn deserialize(cur: &mut Cursor<&[u8]>, kind: u8) -> Result<OffsetInfo> {
        let mut oi = OffsetInfo {
            kind,
            ..Default::default()
        };
        // Helper: read & discard `n` little-endian u32s.
        fn skip_u32s(cur: &mut Cursor<&[u8]>, n: usize) -> Result<()> {
            for _ in 0..n {
                p::decode_u32_le(cur)?;
            }
            Ok(())
        }
        fn read_mdim(cur: &mut Cursor<&[u8]>, oi: &mut OffsetInfo) -> Result<()> {
            for bound in &mut oi.mdim_lower_bounds {
                *bound = p::decode_i32_le(cur)?;
            }
            for count in &mut oi.mdim_element_count {
                *count = p::decode_u32_le(cur)?;
            }
            Ok(())
        }

        match kind {
            // Std (8) / StructElemStd (1): two u16 LE (optimized + nonoptimized address).
            1 | 8 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
            }
            // String (9) / StructElemString (2): u16 x2 + u32 x2. The first u16 is the
            // declared max length.
            2 | 9 => {
                oi.string_max_len = p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
            }
            // Array1Dim (10) / StructElemArray1Dim (3): u16 x2 + u32 x2 + i32 + u32.
            3 | 10 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.array_lower_bounds = p::decode_i32_le(cur)?;
                oi.array_element_count = p::decode_u32_le(cur)?;
                oi.is_1dim = true;
            }
            // ArrayMDim (11) / StructElemArrayMDim (4): u16 x2 + u32 x2 + i32 + u32 + mdim.
            4 | 11 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.array_lower_bounds = p::decode_i32_le(cur)?;
                oi.array_element_count = p::decode_u32_le(cur)?;
                read_mdim(cur, &mut oi)?;
                oi.is_mdim = true;
            }
            // Struct (12) / StructElemStruct (5): u16 x2 + u32 x2 + relid + 4 u32.
            5 | 12 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.relation_id = Some(p::decode_u32_le(cur)?);
                skip_u32s(cur, 4)?;
            }
            // Struct1Dim (13) / StructElemStruct1Dim (6): + array bounds + struct sizes.
            6 | 13 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.array_lower_bounds = p::decode_i32_le(cur)?;
                oi.array_element_count = p::decode_u32_le(cur)?;
                skip_u32s(cur, 2)?; // nonoptimized + optimized struct size
                oi.relation_id = Some(p::decode_u32_le(cur)?);
                skip_u32s(cur, 4)?;
                oi.is_1dim = true;
            }
            // StructMDim (14) / StructElemStructMDim (7).
            7 | 14 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.array_lower_bounds = p::decode_i32_le(cur)?;
                oi.array_element_count = p::decode_u32_le(cur)?;
                read_mdim(cur, &mut oi)?;
                skip_u32s(cur, 2)?; // struct sizes
                oi.relation_id = Some(p::decode_u32_le(cur)?);
                skip_u32s(cur, 4)?;
                oi.is_mdim = true;
            }
            // FbArray (0): u16 x2 + u32 x2 + relid + 10 u32 + mdim.
            0 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.relation_id = Some(p::decode_u32_le(cur)?);
                skip_u32s(cur, 10)?;
                read_mdim(cur, &mut oi)?;
            }
            // FbSfb (15): u16 x2 + u32 x2 + relid + 6 u32.
            15 => {
                p::decode_u16_le(cur)?;
                p::decode_u16_le(cur)?;
                skip_u32s(cur, 2)?;
                oi.relation_id = Some(p::decode_u32_le(cur)?);
                skip_u32s(cur, 6)?;
            }
            other => {
                return Err(Error::protocol(format!("unknown offsetinfotype {other}")));
            }
        }
        Ok(oi)
    }
}

/// One `VartypeList` element (a member of a block/struct type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VartypeElement {
    /// The member's local id (LID) — its access index within the block/struct.
    pub lid: u32,
    /// CRC of the member's symbol name (used to match names to elements).
    pub symbol_crc: u32,
    /// The member's semantic type (see [`crate::value::datatype::softdatatype`]).
    pub softdatatype: u8,
    /// Attribute flags (big-endian); the high nibble encodes the offset-info type.
    pub attribute_flags: u16,
    /// Bit-offset-info flags.
    pub bitoffsetinfo_flags: u8,
    /// The member's offset/layout info.
    pub offset_info: OffsetInfo,
}

impl VartypeElement {
    fn deserialize(cur: &mut Cursor<&[u8]>) -> Result<VartypeElement> {
        let lid = p::decode_u32_le(cur)?;
        let symbol_crc = p::decode_u32_le(cur)?;
        let softdatatype = p::decode_u8(cur)?;
        let attribute_flags = p::decode_u16(cur)?; // big-endian
        let bitoffsetinfo_flags = p::decode_u8(cur)?;
        let offsetinfotype = ((attribute_flags & 0xf000) >> 12) as u8;
        let offset_info = OffsetInfo::deserialize(cur, offsetinfotype)?;
        Ok(VartypeElement {
            lid,
            symbol_crc,
            softdatatype,
            attribute_flags,
            bitoffsetinfo_flags,
            offset_info,
        })
    }
}

/// The `VartypeList` element 0xab: a `first_id` plus one element per member, in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VartypeList {
    /// The list's first LID (subsequent elements follow in order).
    pub first_id: u32,
    /// One element per member, in declaration order.
    pub elements: Vec<VartypeElement>,
}

impl VartypeList {
    /// Decode the list body (the `0xab` tag has already been consumed).
    pub fn deserialize(cur: &mut Cursor<&[u8]>) -> Result<VartypeList> {
        let mut blocklen = p::decode_u16(cur)?; // big-endian
        let mut max_pos = cur.position() + blocklen as u64;
        let first_id = p::decode_u32_le(cur)?;
        let mut elements = Vec::new();
        while blocklen > 0 {
            loop {
                elements.push(VartypeElement::deserialize(cur)?);
                if cur.position() >= max_pos {
                    break;
                }
            }
            blocklen = p::decode_u16(cur)?;
            max_pos = cur.position() + blocklen as u64;
        }
        Ok(VartypeList { first_id, elements })
    }
}

/// The `VarnameList` element 0xac: member names, parallel (by index) to the `VartypeList`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VarnameList {
    /// Member names, parallel by index to the [`VartypeList`] elements.
    pub names: Vec<String>,
}

impl VarnameList {
    /// Decode the list body (the `0xac` tag has already been consumed).
    pub fn deserialize(cur: &mut Cursor<&[u8]>) -> Result<VarnameList> {
        let mut blocklen = p::decode_u16(cur)?; // big-endian
        let mut max_pos = cur.position() + blocklen as u64;
        let mut names = Vec::new();
        while blocklen > 0 {
            loop {
                let namelen = p::decode_u8(cur)? as usize;
                let bytes = p::decode_octets(cur, namelen)?;
                names.push(String::from_utf8_lossy(&bytes).into_owned());
                let _null_terminator = p::decode_u8(cur)?;
                if cur.position() >= max_pos {
                    break;
                }
            }
            blocklen = p::decode_u16(cur)?;
            max_pos = cur.position() + blocklen as u64;
        }
        Ok(VarnameList { names })
    }
}
