// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/PValue.cs, LGPL-3.0-or-later.

//! The S7CommPlus value type, modelled as a Rust enum (cleaner than the C# class tree).
//!
//! A serialized value is framed as:
//!
//! ```text
//! <flags:1> <datatype:1> <payload...>
//! ```
//!
//! where `flags` carries the array-shape bits (see [`super::datatype::flags`]) and
//! `datatype` is one of [`super::datatype::tag`]. The payload encoding per type
//! is a faithful port of the concrete `Value*` classes — note the deliberate mix of
//! fixed-width and VLQ encodings (e.g. `UInt`/`Word` are fixed `u16`, but `UDInt` is a
//! VLQ, while `DWord` is fixed `u32`).
//!
//! Scalar types, `Timestamp`/`Timespan`, `Blob`, `WString`, non-packed `Struct`, packed
//! `Struct` (raw payload), and the array shapes (regular/address/sparse of scalar elements)
//! are implemented and byte-tested. The remaining types — `Variant`, `S7String`, and arrays
//! of variable-length element types — surface a clear error rather than silently mis-encoding.
//! (`Variant` and `S7String` are `NotImplementedException` in the upstream C# reference too,
//! so there is no wire format to port faithfully; they stay explicit errors by design.)
//!
//! Note on `WString`: despite the "W" (wide) name, the S7CommPlus *value* codec transmits it
//! as UTF-8 with a VLQ **byte-length** prefix (matching `S7p.DecodeWString`, which reads that
//! many bytes). It is not UTF-16 on the wire.

use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::value::datatype::{flags, tag as dt};
use crate::wire::{primitives as p, vlq};

/// Deepest `Struct` nesting [`PValue::deserialize`] accepts. Real values nest a few levels; the
/// limit keeps a corrupt or hostile telegram from overflowing the stack (which would abort the
/// process rather than return an error).
pub const MAX_VALUE_NESTING: usize = 32;

/// A single S7CommPlus value.
#[derive(Debug, Clone, PartialEq)]
pub enum PValue {
    /// Null / absent value.
    Null,
    /// Boolean.
    Bool(bool),
    /// Unsigned 8-bit (`USInt`).
    USInt(u8),
    /// Unsigned 16-bit (`UInt`).
    UInt(u16),
    /// Unsigned 32-bit (`UDInt`).
    UDInt(u32),
    /// Unsigned 64-bit (`ULInt`).
    ULInt(u64),
    /// Signed 8-bit (`SInt`).
    SInt(i8),
    /// Signed 16-bit (`Int`).
    Int(i16),
    /// Signed 32-bit (`DInt`).
    DInt(i32),
    /// Signed 64-bit (`LInt`).
    LInt(i64),
    /// 8-bit bit-string (`Byte`).
    Byte(u8),
    /// 16-bit bit-string (`Word`).
    Word(u16),
    /// 32-bit bit-string (`DWord`).
    DWord(u32),
    /// 64-bit bit-string (`LWord`).
    LWord(u64),
    /// 32-bit IEEE float (`Real`).
    Real(f32),
    /// 64-bit IEEE float (`LReal`).
    LReal(f64),
    /// Relation ID — fixed-width `u32`.
    RID(u32),
    /// Attribute ID — VLQ `u32`.
    AID(u32),
    /// Timestamp — fixed-width `u64` (nanoseconds since 1970, per the PLC).
    Timestamp(u64),
    /// Timespan — signed VLQ `i64` (a duration in nanoseconds).
    Timespan(i64),
    /// Blob — a root id plus raw bytes.
    Blob {
        /// Type root id identifying the blob's schema.
        root_id: u32,
        /// Raw blob bytes.
        data: Vec<u8>,
    },
    /// Struct — a struct id and ordered `(element_id, value)` members (non-packed form).
    Struct {
        /// Struct type id.
        id: u32,
        /// Ordered `(element_id, value)` members.
        elements: Vec<(u32, PValue)>,
    },
    /// Packed (optimized) struct. The struct id falls in the packed ranges (see the
    /// `struct_is_packed` predicate); the member area is a raw byte block whose field offsets are
    /// described out-of-band by the type's offset-info. The bytes are stored verbatim
    /// so decode→encode is byte-exact; interpreting them into typed fields needs the
    /// offset-info walk (the [`crate::optimized`] layer).
    PackedStruct {
        /// Packed-struct type id.
        id: u32,
        /// Interface (schema) timestamp the packed layout was generated against.
        interface_timestamp: u64,
        /// Packed-struct transport flags.
        transport_flags: u32,
        /// Raw packed member block (offsets resolved via the type's offset-info).
        data: Vec<u8>,
    },
    /// WString — UTF-8 text with a VLQ length prefix (the protocol's "WString" value type;
    /// the C# codec encodes/decodes it as UTF-8 despite the name).
    WString(String),
    /// Array of USInt (carries the array flag in the flags byte). Used e.g. for the
    /// legitimation challenge.
    USIntArray(Vec<u8>),
    /// A regular/address array of scalar elements (`element_type` is the datatype tag,
    /// `flags` the array-shape byte). Elements are stored as their scalar `PValue`s.
    Array {
        /// Datatype tag of each element (see [`super::datatype::tag`]).
        element_type: u8,
        /// Array-shape flags byte (see [`super::datatype::flags`]).
        flags: u8,
        /// The element values, in order.
        items: Vec<PValue>,
    },
    /// A sparse array: ordered `(key, value)` entries (terminated on the wire by a zero
    /// key). `element_type` is the value's datatype tag.
    SparseArray {
        /// Datatype tag of each value (see [`super::datatype::tag`]).
        element_type: u8,
        /// Ordered `(key, value)` entries.
        entries: Vec<(u32, PValue)>,
    },
}

/// Struct ids in these ranges use the packed (optimized) serialization, which is not yet
/// supported. Legitimation and other hand-built structs use ids outside these ranges.
fn struct_is_packed(id: u32) -> bool {
    // Matches the reference's strict (exclusive) bounds.
    (id > 0x9000_0000 && id < 0x9fff_ffff) || (id > 0x0200_0000 && id < 0x02ff_ffff)
}

/// `PackedStructTransportFlagBits.Count2Present` — when set, a second length follows the first
/// before the raw member bytes. For a single struct both are equal; for an array of packed
/// structs they are the element stride and the total byte length.
const PACKED_STRUCT_COUNT2_PRESENT: u32 = 1 << 10;

/// An array element is written as a bare payload, so it must be a scalar of the array's declared
/// element type: an `Int` in a `DInt` array would encode bytes that decode as something else.
fn check_element(element_type: u8, item: &PValue) -> Result<()> {
    let nested = matches!(
        item,
        PValue::Array { .. } | PValue::SparseArray { .. } | PValue::USIntArray(_)
    );
    if nested || item.datatype() != element_type {
        return Err(Error::protocol(format!(
            "array element {item:?} does not match element type 0x{element_type:02x}"
        )));
    }
    Ok(())
}

/// Payload of an array of packed structs — the inverse of
/// `PValue::deserialize_packed_struct_array`: one header taken from the first element, the
/// stride and total length, then every element's member block. All elements must be
/// [`PValue::PackedStruct`]s of the same type and size.
fn serialize_packed_struct_array<W: Write>(w: &mut W, items: &[PValue]) -> Result<usize> {
    let mut blocks = Vec::with_capacity(items.len());
    let mut header = None;
    for item in items {
        let PValue::PackedStruct {
            id,
            interface_timestamp,
            transport_flags,
            data,
        } = item
        else {
            return Err(Error::protocol(
                "struct array elements must all be packed structs",
            ));
        };
        let h = (*id, *interface_timestamp, *transport_flags, data.len());
        if *header.get_or_insert(h) != h {
            return Err(Error::protocol(
                "struct array elements must share type and size",
            ));
        }
        blocks.push(data);
    }
    let Some((id, interface_timestamp, transport_flags, stride)) = header else {
        return Err(Error::protocol("cannot serialize an empty struct array"));
    };
    let mut n = 0;
    n += p::encode_u32(w, id)?;
    n += p::encode_u64(w, interface_timestamp)?;
    n += vlq::encode_u32(w, transport_flags | PACKED_STRUCT_COUNT2_PRESENT)?;
    n += vlq::encode_u32(w, stride as u32)?;
    n += vlq::encode_u32(w, (stride * blocks.len()) as u32)?;
    for data in blocks {
        n += p::encode_octets(w, data)?;
    }
    Ok(n)
}

impl PValue {
    /// Best-effort `bool` view: `true`/`false` for `Bool`, or non-zero for any integer type.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PValue::Bool(b) => Some(*b),
            _ => self.as_i64().map(|v| v != 0),
        }
    }

    /// View as a signed 64-bit integer, if this is an integer-like scalar that fits in `i64`.
    /// Covers the signed/unsigned integers, `Byte`/`Word`/`DWord`/`LWord`, `Bool`, and the id
    /// types. `ULInt`/`LWord` values above `i64::MAX` return `None` (use [`PValue::as_u64`]).
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PValue::Bool(b) => Some(i64::from(*b)),
            PValue::USInt(v) | PValue::Byte(v) => Some(i64::from(*v)),
            PValue::SInt(v) => Some(i64::from(*v)),
            PValue::UInt(v) | PValue::Word(v) => Some(i64::from(*v)),
            PValue::Int(v) => Some(i64::from(*v)),
            PValue::UDInt(v) | PValue::DWord(v) | PValue::RID(v) | PValue::AID(v) => {
                Some(i64::from(*v))
            }
            PValue::DInt(v) => Some(i64::from(*v)),
            PValue::LInt(v) | PValue::Timespan(v) => Some(*v),
            PValue::ULInt(v) | PValue::LWord(v) | PValue::Timestamp(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// View as an unsigned 64-bit integer, if this is a non-negative integer-like scalar.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            PValue::Bool(b) => Some(u64::from(*b)),
            PValue::USInt(v) | PValue::Byte(v) => Some(u64::from(*v)),
            PValue::UInt(v) | PValue::Word(v) => Some(u64::from(*v)),
            PValue::UDInt(v) | PValue::DWord(v) | PValue::RID(v) | PValue::AID(v) => {
                Some(u64::from(*v))
            }
            PValue::ULInt(v) | PValue::LWord(v) | PValue::Timestamp(v) => Some(*v),
            PValue::SInt(v) => u64::try_from(*v).ok(),
            PValue::Int(v) => u64::try_from(*v).ok(),
            PValue::DInt(v) => u64::try_from(*v).ok(),
            PValue::LInt(v) | PValue::Timespan(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// View as `f64`: the floats directly, or an integer widened to `f64` (may lose precision
    /// for 64-bit integers beyond 2^53, as with any numeric widening).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            PValue::Real(v) => Some(f64::from(*v)),
            PValue::LReal(v) => Some(*v),
            PValue::ULInt(v) | PValue::LWord(v) | PValue::Timestamp(v) => Some(*v as f64),
            _ => self.as_i64().map(|v| v as f64),
        }
    }

    /// Borrow the text of a `WString`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PValue::WString(s) => Some(s),
            _ => None,
        }
    }

    /// Borrow the raw bytes of a `Blob`, `USIntArray`, or `PackedStruct`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            PValue::Blob { data, .. }
            | PValue::USIntArray(data)
            | PValue::PackedStruct { data, .. } => Some(data),
            _ => None,
        }
    }

    /// The datatype tag byte for this value.
    pub fn datatype(&self) -> u8 {
        match self {
            PValue::Null => dt::NULL,
            PValue::Bool(_) => dt::BOOL,
            PValue::USInt(_) => dt::USINT,
            PValue::UInt(_) => dt::UINT,
            PValue::UDInt(_) => dt::UDINT,
            PValue::ULInt(_) => dt::ULINT,
            PValue::SInt(_) => dt::SINT,
            PValue::Int(_) => dt::INT,
            PValue::DInt(_) => dt::DINT,
            PValue::LInt(_) => dt::LINT,
            PValue::Byte(_) => dt::BYTE,
            PValue::Word(_) => dt::WORD,
            PValue::DWord(_) => dt::DWORD,
            PValue::LWord(_) => dt::LWORD,
            PValue::Real(_) => dt::REAL,
            PValue::LReal(_) => dt::LREAL,
            PValue::RID(_) => dt::RID,
            PValue::AID(_) => dt::AID,
            PValue::Timestamp(_) => dt::TIMESTAMP,
            PValue::Timespan(_) => dt::TIMESPAN,
            PValue::Blob { .. } => dt::BLOB,
            PValue::Struct { .. } => dt::STRUCT,
            PValue::PackedStruct { .. } => dt::STRUCT,
            PValue::WString(_) => dt::WSTRING,
            PValue::USIntArray(_) => dt::USINT,
            PValue::Array { element_type, .. } => *element_type,
            PValue::SparseArray { element_type, .. } => *element_type,
        }
    }

    /// The datatype-flags byte for this value (array shapes set a bit here).
    fn flags_byte(&self) -> u8 {
        match self {
            PValue::USIntArray(_) => flags::ARRAY,
            PValue::Array { flags, .. } => *flags,
            PValue::SparseArray { .. } => flags::SPARSE_ARRAY,
            _ => 0x00,
        }
    }

    /// Serialize the full value (flags + datatype + payload). Returns bytes written.
    ///
    /// Scalars are written with a zero flags byte (no array shape).
    pub fn serialize<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = 0;
        n += p::encode_u8(w, self.flags_byte())?;
        n += p::encode_u8(w, self.datatype())?;
        n += self.serialize_payload(w)?;
        Ok(n)
    }

    fn serialize_payload<W: Write>(&self, w: &mut W) -> Result<usize> {
        match self {
            PValue::Null => Ok(0),
            PValue::Bool(v) => p::encode_u8(w, u8::from(*v)),
            PValue::USInt(v) => p::encode_u8(w, *v),
            PValue::UInt(v) => p::encode_u16(w, *v),
            PValue::UDInt(v) => vlq::encode_u32(w, *v),
            PValue::ULInt(v) => vlq::encode_u64(w, *v),
            PValue::SInt(v) => p::encode_u8(w, *v as u8),
            PValue::Int(v) => p::encode_i16(w, *v),
            PValue::DInt(v) => vlq::encode_i32(w, *v),
            PValue::LInt(v) => vlq::encode_i64(w, *v),
            PValue::Byte(v) => p::encode_u8(w, *v),
            PValue::Word(v) => p::encode_u16(w, *v),
            PValue::DWord(v) => p::encode_u32(w, *v),
            PValue::LWord(v) => p::encode_u64(w, *v),
            PValue::Real(v) => p::encode_f32(w, *v),
            PValue::LReal(v) => p::encode_f64(w, *v),
            PValue::RID(v) => p::encode_u32(w, *v),
            PValue::AID(v) => vlq::encode_u32(w, *v),
            PValue::Timestamp(v) => p::encode_u64(w, *v),
            PValue::Timespan(v) => vlq::encode_i64(w, *v),
            PValue::Blob { root_id, data } => {
                let mut n = 0;
                n += vlq::encode_u32(w, *root_id)?;
                n += vlq::encode_u32(w, data.len() as u32)?;
                n += p::encode_octets(w, data)?;
                Ok(n)
            }
            PValue::Struct { id, elements } => {
                if struct_is_packed(*id) {
                    return Err(Error::protocol(format!(
                        "packed struct serialization not supported (id 0x{id:08x})"
                    )));
                }
                let mut n = 0;
                n += p::encode_u32(w, *id)?; // struct id (fixed-width)
                for (key, value) in elements {
                    n += vlq::encode_u32(w, *key)?;
                    n += value.serialize(w)?;
                }
                n += p::encode_u8(w, 0x00)?; // terminator
                Ok(n)
            }
            PValue::PackedStruct {
                id,
                interface_timestamp,
                transport_flags,
                data,
            } => {
                let mut n = 0;
                n += p::encode_u32(w, *id)?; // struct id (fixed-width)
                n += p::encode_u64(w, *interface_timestamp)?;
                n += vlq::encode_u32(w, *transport_flags)?;
                n += vlq::encode_u32(w, data.len() as u32)?;
                if transport_flags & PACKED_STRUCT_COUNT2_PRESENT != 0 {
                    n += vlq::encode_u32(w, data.len() as u32)?;
                }
                n += p::encode_octets(w, data)?;
                Ok(n)
            }
            PValue::WString(s) => {
                let bytes = s.as_bytes();
                let mut n = 0;
                n += vlq::encode_u32(w, bytes.len() as u32)?;
                n += p::encode_octets(w, bytes)?;
                Ok(n)
            }
            PValue::USIntArray(data) => {
                let mut n = 0;
                n += vlq::encode_u32(w, data.len() as u32)?;
                n += p::encode_octets(w, data)?;
                Ok(n)
            }
            PValue::Array {
                element_type: dt::STRUCT,
                items,
                ..
            } => serialize_packed_struct_array(w, items),
            PValue::Array {
                element_type,
                flags: array_flags,
                items,
            } => {
                if array_flags & flags::ANY_ARRAY == 0 || array_flags & flags::SPARSE_ARRAY != 0 {
                    return Err(Error::protocol(format!(
                        "PValue::Array needs the ARRAY or ADDRESS_ARRAY flag (got 0x{array_flags:02x})"
                    )));
                }
                let mut n = 0;
                n += vlq::encode_u32(w, items.len() as u32)?;
                for item in items {
                    check_element(*element_type, item)?;
                    n += item.serialize_payload(w)?;
                }
                Ok(n)
            }
            PValue::SparseArray {
                element_type,
                entries,
            } => {
                let mut n = 0;
                for (key, value) in entries {
                    if *key == 0 {
                        return Err(Error::protocol(
                            "sparse array key 0 is reserved for the terminator",
                        ));
                    }
                    check_element(*element_type, value)?;
                    n += vlq::encode_u32(w, *key)?;
                    n += value.serialize_payload(w)?;
                }
                n += p::encode_u8(w, 0x00)?; // key-0 terminator
                Ok(n)
            }
        }
    }

    /// Deserialize a full value (flags + datatype + payload).
    ///
    /// Nested `Struct`s deeper than [`MAX_VALUE_NESTING`] are rejected, so a corrupt or hostile
    /// telegram cannot overflow the stack.
    pub fn deserialize<R: Read>(r: &mut R) -> Result<PValue> {
        Self::deserialize_at(r, 0)
    }

    fn deserialize_at<R: Read>(r: &mut R, depth: usize) -> Result<PValue> {
        if depth > MAX_VALUE_NESTING {
            return Err(Error::protocol(format!(
                "value nesting deeper than {MAX_VALUE_NESTING} levels"
            )));
        }
        let flags = p::decode_u8(r)?;
        let datatype = p::decode_u8(r)?;
        if flags & flags::ANY_ARRAY != 0 {
            return Self::deserialize_array(r, flags, datatype, depth);
        }
        Self::deserialize_payload(r, datatype, depth)
    }

    /// Deserialize an array value. Regular and address arrays are a VLQ element count
    /// followed by that many bare element payloads (supported for scalars and `Blob` — the
    /// latter used by alarm associated-values). Sparse arrays are `(key, value)` pairs. Packed
    /// `Struct` arrays have their own layout (see `deserialize_packed_struct_array`). The
    /// remaining variable-length element types (`WString`/`Variant`/`S7String`) use an
    /// address-array layout we don't decode yet and error clearly rather than desync.
    fn deserialize_array<R: Read>(
        r: &mut R,
        flags: u8,
        datatype: u8,
        depth: usize,
    ) -> Result<PValue> {
        if flags & flags::SPARSE_ARRAY != 0 {
            // Sparse array: (VLQ key, value) entries terminated by a zero key. The value
            // payload is the same as a scalar of `datatype` (Blob/UDInt/DInt/WString).
            let mut entries = Vec::new();
            let mut key = vlq::decode_u32(r)?;
            while key != 0 {
                let value = Self::deserialize_payload(r, datatype, depth)?;
                entries.push((key, value));
                key = vlq::decode_u32(r)?;
            }
            return Ok(PValue::SparseArray {
                element_type: datatype,
                entries,
            });
        }
        match datatype {
            dt::STRUCT => return Self::deserialize_packed_struct_array(r, flags),
            dt::WSTRING | dt::VARIANT | dt::S7STRING => {
                return Err(Error::protocol(format!(
                    "array of variable-length datatype 0x{datatype:02x} not yet supported (flags 0x{flags:02x})"
                )));
            }
            _ => {}
        }
        let count = vlq::decode_u32(r)? as usize;
        if datatype == dt::USINT {
            // Preserve the raw-byte representation (used by legitimation).
            let data = crate::wire::primitives::decode_octets(r, count)?;
            return Ok(PValue::USIntArray(data));
        }
        if datatype == dt::NULL && count > 0 {
            // Null elements occupy no bytes, so the count would be the only bound on the loop.
            return Err(Error::protocol("array of Null elements not supported"));
        }
        // Every other element consumes input, so a bogus count fails at the end of the telegram;
        // only the pre-allocation needs a cap.
        let mut items = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            items.push(Self::deserialize_payload(r, datatype, depth)?);
        }
        Ok(PValue::Array {
            element_type: datatype,
            flags,
            items,
        })
    }

    /// Deserialize an array of packed structs (an element, or the whole, of an `Array of UDT` /
    /// `Array of Struct`). Unlike other arrays it carries no element count: it is a single
    /// packed-struct header whose two lengths are the element stride and the total byte length,
    /// followed by the elements' member blocks back to back. Each element becomes a
    /// [`PValue::PackedStruct`] carrying the shared header.
    fn deserialize_packed_struct_array<R: Read>(r: &mut R, flags: u8) -> Result<PValue> {
        let id = p::decode_u32(r)?;
        if !struct_is_packed(id) {
            return Err(Error::protocol(format!(
                "array of non-packed structs not yet supported (id 0x{id:08x}, flags 0x{flags:02x})"
            )));
        }
        let interface_timestamp = p::decode_u64(r)?;
        let transport_flags = vlq::decode_u32(r)?;
        let stride = vlq::decode_u32(r)? as usize;
        let total = if transport_flags & PACKED_STRUCT_COUNT2_PRESENT != 0 {
            vlq::decode_u32(r)? as usize
        } else {
            stride
        };
        if (stride == 0 && total != 0) || (stride != 0 && total % stride != 0) {
            return Err(Error::protocol(format!(
                "packed struct array: total length {total} is not a multiple of stride {stride}"
            )));
        }
        let data = crate::wire::primitives::decode_octets(r, total)?;
        let items = data
            .chunks(stride.max(1))
            .map(|chunk| PValue::PackedStruct {
                id,
                interface_timestamp,
                transport_flags,
                data: chunk.to_vec(),
            })
            .collect();
        Ok(PValue::Array {
            element_type: dt::STRUCT,
            flags,
            items,
        })
    }

    fn deserialize_payload<R: Read>(r: &mut R, datatype: u8, depth: usize) -> Result<PValue> {
        Ok(match datatype {
            dt::NULL => PValue::Null,
            dt::BOOL => PValue::Bool(p::decode_u8(r)? != 0),
            dt::USINT => PValue::USInt(p::decode_u8(r)?),
            dt::UINT => PValue::UInt(p::decode_u16(r)?),
            dt::UDINT => PValue::UDInt(vlq::decode_u32(r)?),
            dt::ULINT => PValue::ULInt(vlq::decode_u64(r)?),
            dt::SINT => PValue::SInt(p::decode_u8(r)? as i8),
            dt::INT => PValue::Int(p::decode_i16(r)?),
            dt::DINT => PValue::DInt(vlq::decode_i32(r)?),
            dt::LINT => PValue::LInt(vlq::decode_i64(r)?),
            dt::BYTE => PValue::Byte(p::decode_u8(r)?),
            dt::WORD => PValue::Word(p::decode_u16(r)?),
            dt::DWORD => PValue::DWord(p::decode_u32(r)?),
            dt::LWORD => PValue::LWord(p::decode_u64(r)?),
            dt::REAL => PValue::Real(p::decode_f32(r)?),
            dt::LREAL => PValue::LReal(p::decode_f64(r)?),
            dt::RID => PValue::RID(p::decode_u32(r)?),
            dt::AID => PValue::AID(vlq::decode_u32(r)?),
            dt::TIMESTAMP => PValue::Timestamp(p::decode_u64(r)?),
            dt::TIMESPAN => PValue::Timespan(vlq::decode_i64(r)?),
            dt::BLOB => {
                let root_id = vlq::decode_u32(r)?;
                let len = vlq::decode_u32(r)? as usize;
                let data = crate::wire::primitives::decode_octets(r, len)?;
                PValue::Blob { root_id, data }
            }
            dt::WSTRING => {
                let len = vlq::decode_u32(r)? as usize;
                let bytes = crate::wire::primitives::decode_octets(r, len)?;
                // Lossy, like the reference (`Encoding.UTF8.GetString`): one bad byte in a name
                // must not fail a whole Explore or read.
                PValue::WString(String::from_utf8_lossy(&bytes).into_owned())
            }
            dt::STRUCT => Self::deserialize_struct(r, depth)?,
            other => {
                return Err(Error::protocol(format!(
                    "unsupported or not-yet-implemented PValue datatype 0x{other:02x}"
                )))
            }
        })
    }

    /// Deserialize a `Struct` payload (the struct id has datatype `0x17`). Mirrors
    /// `ValueStruct.Deserialize`: a fixed-width id, then — for the non-packed form —
    /// `(VLQ key, value)` members terminated by a zero key.
    fn deserialize_struct<R: Read>(r: &mut R, depth: usize) -> Result<PValue> {
        let id = p::decode_u32(r)?;
        if struct_is_packed(id) {
            // Packed (optimized) struct: fixed u64 interface timestamp, VLQ transport flags,
            // VLQ element count (repeated once more when Count2Present is set), then that many
            // raw member bytes. Mirrors `ValueStruct.Deserialize`.
            let interface_timestamp = p::decode_u64(r)?;
            let transport_flags = vlq::decode_u32(r)?;
            let mut count = vlq::decode_u32(r)? as usize;
            if transport_flags & PACKED_STRUCT_COUNT2_PRESENT != 0 {
                count = vlq::decode_u32(r)? as usize;
            }
            let data = crate::wire::primitives::decode_octets(r, count)?;
            return Ok(PValue::PackedStruct {
                id,
                interface_timestamp,
                transport_flags,
                data,
            });
        }
        let mut elements = Vec::new();
        let mut key = vlq::decode_u32(r)?;
        while key != 0 {
            let value = PValue::deserialize_at(r, depth + 1)?;
            elements.push((key, value));
            key = vlq::decode_u32(r)?;
        }
        Ok(PValue::Struct { id, elements })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip(v: PValue) {
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        let got = PValue::deserialize(&mut Cursor::new(&out)).unwrap();
        assert_eq!(got, v, "roundtrip mismatch via {out:02x?}");
    }

    #[test]
    fn scalar_roundtrips() {
        roundtrip(PValue::Null);
        roundtrip(PValue::Bool(true));
        roundtrip(PValue::Bool(false));
        roundtrip(PValue::USInt(0xab));
        roundtrip(PValue::UInt(0x1234));
        roundtrip(PValue::UDInt(0x0102_0304));
        roundtrip(PValue::ULInt(u64::MAX));
        roundtrip(PValue::SInt(-5));
        roundtrip(PValue::Int(-12345));
        roundtrip(PValue::DInt(-70000));
        roundtrip(PValue::LInt(i64::MIN));
        roundtrip(PValue::Byte(0xfe));
        roundtrip(PValue::Word(0xbeef));
        roundtrip(PValue::DWord(0xdead_beef));
        roundtrip(PValue::LWord(0x0123_4567_89ab_cdef));
        roundtrip(PValue::Real(3.5));
        roundtrip(PValue::LReal(-2.25));
        roundtrip(PValue::RID(0x80c3_c901));
        roundtrip(PValue::AID(0x4000));
        roundtrip(PValue::Timestamp(0x0102_0304_0506_0708));
    }

    #[test]
    fn rid_is_fixed_aid_is_vlq() {
        // RID 0x80c3c901 -> 00 12 80 c3 c9 01 (fixed u32 payload).
        let mut out = Vec::new();
        PValue::RID(0x80c3_c901).serialize(&mut out).unwrap();
        assert_eq!(out, vec![0x00, dt::RID, 0x80, 0xc3, 0xc9, 0x01]);
        // AID 0x4000 -> 00 13 81 80 00 (VLQ payload).
        let mut out = Vec::new();
        PValue::AID(0x4000).serialize(&mut out).unwrap();
        assert_eq!(out, vec![0x00, dt::AID, 0x81, 0x80, 0x00]);
    }

    #[test]
    fn golden_uint_is_fixed_u16() {
        // UInt 0x1234 -> flags 00, datatype 03 (UInt), then fixed-width 12 34.
        let mut out = Vec::new();
        PValue::UInt(0x1234).serialize(&mut out).unwrap();
        assert_eq!(out, vec![0x00, dt::UINT, 0x12, 0x34]);
    }

    #[test]
    fn golden_dint_is_signed_vlq() {
        // DInt 345 -> flags 00, datatype 08 (DInt), then signed VLQ 82 59. This is the
        // shape a GetMultiVariables response carries for a DInt (Int32) PLC tag.
        let mut out = Vec::new();
        PValue::DInt(345).serialize(&mut out).unwrap();
        assert_eq!(out, vec![0x00, dt::DINT, 0x82, 0x59]);
        assert_eq!(
            PValue::deserialize(&mut Cursor::new(&out)).unwrap(),
            PValue::DInt(345)
        );
        // Negative DInt: -70000 -> fb dd 10.
        let buf = vec![0x00, dt::DINT, 0xfb, 0xdd, 0x10];
        assert_eq!(
            PValue::deserialize(&mut Cursor::new(&buf)).unwrap(),
            PValue::DInt(-70000)
        );
    }

    #[test]
    fn golden_udint_is_vlq() {
        // UDInt 0x4000 -> flags 00, datatype 04 (UDInt), then VLQ 81 80 00.
        let mut out = Vec::new();
        PValue::UDInt(0x4000).serialize(&mut out).unwrap();
        assert_eq!(out, vec![0x00, dt::UDINT, 0x81, 0x80, 0x00]);
    }

    #[test]
    fn golden_dword_is_fixed_u32() {
        // DWord is fixed-width (contrast with UDInt's VLQ).
        let mut out = Vec::new();
        PValue::DWord(0x0000_4000).serialize(&mut out).unwrap();
        assert_eq!(out, vec![0x00, dt::DWORD, 0x00, 0x00, 0x40, 0x00]);
    }

    #[test]
    fn uint_array_roundtrips() {
        // flags 0x10 (array), datatype UInt, count VLQ 02, then two fixed u16 — the shape
        // seen in the live Explore response (attribute 4543).
        let buf = vec![flags::ARRAY, dt::UINT, 0x02, 0xea, 0x60, 0xee, 0x47];
        let v = PValue::deserialize(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(
            v,
            PValue::Array {
                element_type: dt::UINT,
                flags: flags::ARRAY,
                items: vec![PValue::UInt(0xea60), PValue::UInt(0xee47)],
            }
        );
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(out, buf);
    }

    #[test]
    fn variable_length_arrays_rejected_for_now() {
        // WString arrays use an address-array layout we don't decode yet — must error,
        // not silently desync.
        let buf = [flags::ADDRESS_ARRAY, dt::WSTRING, 0x01];
        assert!(PValue::deserialize(&mut Cursor::new(buf)).is_err());
    }

    #[test]
    fn blob_roundtrip_and_layout() {
        let v = PValue::Blob {
            root_id: 0,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        // flags 00, datatype 14, root_id VLQ 00, len VLQ 04, bytes
        assert_eq!(
            out,
            vec![0x00, dt::BLOB, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(PValue::deserialize(&mut Cursor::new(&out)).unwrap(), v);
    }

    #[test]
    fn usint_array_roundtrip_and_layout() {
        let v = PValue::USIntArray(vec![0x01, 0x02, 0x03]);
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        // flags 10 (array), datatype 02 (USInt), count VLQ 03, bytes
        assert_eq!(out, vec![flags::ARRAY, dt::USINT, 0x03, 0x01, 0x02, 0x03]);
        assert_eq!(PValue::deserialize(&mut Cursor::new(&out)).unwrap(), v);
    }

    #[test]
    fn server_session_version_struct_roundtrips_golden() {
        // Captured live from a PLCSIM Advanced 8 (TIA V21) CreateObject response: the
        // ServerSessionVersion (attribute 306) value — a non-packed Struct (id 314) with
        // UDInt/WString/UInt members. Decode then re-encode must be byte-identical, since
        // the session-setup step echoes this value back to the PLC.
        let bytes: Vec<u8> = vec![
            0x00, 0x17, // flags, datatype Struct
            0x00, 0x00, 0x01, 0x3a, // struct id 314
            0x82, 0x3b, 0x00, 0x04, 0x88, 0x00, // 315: UDInt(1024)
            0x82, 0x3c, 0x00, 0x04, 0x85, 0x40, // 316: UDInt(704)
            0x82, 0x3d, 0x00, 0x04, 0x84, 0x81, 0x86, 0x40, // 317: UDInt
            0x82, 0x3e, 0x00, 0x04, 0x84, 0x81, 0x84, 0x40, // 318: UDInt
            0x82, 0x3f, 0x00, 0x15, 0x1a, // 319: WString len 26
            0x31, 0x3b, 0x36, 0x45, 0x53, 0x37, 0x20, 0x53, 0x49, 0x4d, 0x2d, 0x30, 0x31, 0x35,
            0x30, 0x30, 0x2d, 0x41, 0x50, 0x4c, 0x43, 0x3b, 0x53, 0x34, 0x2e,
            0x31, // "1;6ES7 SIM-01500-APLC;S4.1"
            0x82, 0x40, 0x00, 0x15, 0x08, // 320: WString len 8
            0x32, 0x3b, 0x38, 0x31, 0x31, 0x38, 0x31, 0x30, // "2;811810"
            0x82, 0x41, 0x00, 0x03, 0x00, 0x03, // 321: UInt(3)
            0x00, // struct terminator
        ];
        let v = PValue::deserialize(&mut Cursor::new(&bytes)).unwrap();
        match &v {
            PValue::Struct { id, elements } => {
                assert_eq!(*id, 314);
                assert_eq!(elements.len(), 7);
                assert_eq!(elements[0], (315, PValue::UDInt(1024)));
                assert_eq!(elements[1], (316, PValue::UDInt(704)));
                assert_eq!(
                    elements[4],
                    (
                        319,
                        PValue::WString("1;6ES7 SIM-01500-APLC;S4.1".to_string())
                    )
                );
                assert_eq!(elements[6], (321, PValue::UInt(3)));
            }
            other => panic!("expected Struct, got {other:?}"),
        }
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(out, bytes, "struct re-serialization not byte-exact");
    }

    #[test]
    fn struct_serialize_layout() {
        let v = PValue::Struct {
            id: 0x0000_1000,
            elements: vec![
                (1, PValue::UDInt(2)),
                (
                    2,
                    PValue::Blob {
                        root_id: 0,
                        data: vec![0xaa],
                    },
                ),
            ],
        };
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(
            out,
            vec![
                0x00,
                dt::STRUCT, // flags, datatype
                0x00,
                0x00,
                0x10,
                0x00, // struct id (fixed u32)
                0x01,
                0x00,
                0x04,
                0x02, // elem 1: key 1, UDInt(2)
                0x02,
                0x00,
                0x14,
                0x00,
                0x01,
                0xaa, // elem 2: key 2, Blob{0,[aa]}
                0x00, // terminator
            ]
        );
    }

    #[test]
    fn wstring_byte_length_prefix_and_utf8() {
        // The value codec transmits WString as UTF-8 with a VLQ *byte-length* prefix (not a
        // char count, not UTF-16). A multi-byte character must widen the length prefix.
        let v = PValue::WString("é".to_string()); // U+00E9 → 0xC3 0xA9 in UTF-8 (2 bytes)
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        // flags 00, datatype 15 (WString), VLQ len 02, then the two UTF-8 bytes.
        assert_eq!(out, vec![0x00, dt::WSTRING, 0x02, 0xc3, 0xa9]);
        assert_eq!(PValue::deserialize(&mut Cursor::new(&out)).unwrap(), v);
        roundtrip(PValue::WString("ascii-and-Ω-mix".to_string()));
    }

    #[test]
    fn blob_array_roundtrips() {
        // A regular array of Blobs (used by alarm associated-values): count + per-element blob.
        let v = PValue::Array {
            element_type: dt::BLOB,
            flags: flags::ARRAY,
            items: vec![
                PValue::Blob {
                    root_id: 0,
                    data: vec![0xaa, 0xbb],
                },
                PValue::Blob {
                    root_id: 0,
                    data: vec![],
                },
            ],
        };
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(PValue::deserialize(&mut Cursor::new(&out)).unwrap(), v);
    }

    #[test]
    fn packed_struct_roundtrip_and_layout() {
        // No Count2Present: id(4) + timestamp(8) + flags VLQ + count VLQ + raw bytes.
        let v = PValue::PackedStruct {
            id: 0x9000_0001,
            interface_timestamp: 0x1122_3344_5566_7788,
            transport_flags: 0x02, // AlwaysSet only
            data: vec![0xaa, 0xbb, 0xcc],
        };
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(
            out,
            vec![
                0x00,
                dt::STRUCT, // flags, datatype
                0x90,
                0x00,
                0x00,
                0x01, // struct id (fixed u32, packed range)
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77,
                0x88, // interface timestamp (u64)
                0x02, // transport flags VLQ (AlwaysSet)
                0x03, // element count VLQ
                0xaa,
                0xbb,
                0xcc, // raw member bytes
            ]
        );
        assert_eq!(PValue::deserialize(&mut Cursor::new(&out)).unwrap(), v);
    }

    #[test]
    fn packed_struct_count2_present_roundtrip() {
        // Count2Present (bit 10) ⇒ the element count is written twice. Roundtrip must be exact.
        let v = PValue::PackedStruct {
            id: 0x0200_0005,
            interface_timestamp: 0,
            transport_flags: 0x02 | PACKED_STRUCT_COUNT2_PRESENT,
            data: vec![0x01, 0x02, 0x03, 0x04],
        };
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(PValue::deserialize(&mut Cursor::new(&out)).unwrap(), v);
        // Two identical VLQ count bytes (0x04, 0x04) must appear before the 4 data bytes.
        let tail = &out[out.len() - 6..];
        assert_eq!(tail, &[0x04, 0x04, 0x01, 0x02, 0x03, 0x04]);
    }

    /// The value PLCSIM returned for a whole `Array[0..1] of "UDT.1"` (16-byte elements).
    fn udt_array_wire() -> Vec<u8> {
        let mut v = vec![
            0x10,
            dt::STRUCT, // flags (array), datatype
            0x91,
            0x00,
            0x00,
            0x01, // struct id (UDT type, packed range)
            0x62,
            0xd7,
            0x2f,
            0x46,
            0x41,
            0x36,
            0x6d,
            0x72, // interface timestamp
            0x88,
            0x02, // transport flags 0x402 (Count2Present)
            0x10,
            0x20, // stride 16, total 32
        ];
        v.extend([0u8; 16]); // element 0
        v.extend([0, 0, 0, 0, 0, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // element 1: a = 11
        v
    }

    #[test]
    fn packed_struct_array_splits_by_stride_and_roundtrips() {
        let wire = udt_array_wire();
        let v = PValue::deserialize(&mut Cursor::new(&wire)).unwrap();
        let PValue::Array {
            element_type,
            items,
            ..
        } = &v
        else {
            panic!("not an array: {v:?}");
        };
        assert_eq!(*element_type, dt::STRUCT);
        assert_eq!(items.len(), 2);
        match &items[1] {
            PValue::PackedStruct { id, data, .. } => {
                assert_eq!(*id, 0x9100_0001);
                assert_eq!(data.len(), 16);
                assert_eq!(&data[4..6], &[0x00, 0x0b]);
            }
            other => panic!("not a packed struct: {other:?}"),
        }
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn packed_struct_array_single_element() {
        // An indexed element (`arrStruct[1]`): stride == total, one 8-byte element.
        let mut wire = vec![0x10, dt::STRUCT, 0x92, 0x01, 0x00, 0x04];
        wire.extend([
            0x8a, 0x9a, 0x2a, 0x44, 0xa3, 0x9c, 0x79, 0xd9, 0x88, 0x02, 0x08, 0x08,
        ]);
        wire.extend([0x3f, 0xa0, 0, 0, 0, 0, 0, 0]);
        let v = PValue::deserialize(&mut Cursor::new(&wire)).unwrap();
        match &v {
            PValue::Array { items, .. } => assert_eq!(items.len(), 1),
            other => panic!("not an array: {other:?}"),
        }
        let mut out = Vec::new();
        v.serialize(&mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn packed_struct_array_rejects_bad_lengths() {
        let mut wire = udt_array_wire();
        wire[17] = 0x1f; // total 31: not a multiple of the 16-byte stride
        assert!(PValue::deserialize(&mut Cursor::new(&wire)).is_err());
    }

    #[test]
    fn array_elements_must_match_the_element_type() {
        // An Int in a DInt array used to serialize as `10 08 01 00 05`, which decodes as DInt(0)
        // plus a stray byte — a malformed (or wrong-valued) write.
        let bad = PValue::Array {
            element_type: dt::DINT,
            flags: flags::ARRAY,
            items: vec![PValue::Int(5)],
        };
        assert!(bad.serialize(&mut Vec::new()).is_err());
        let no_shape = PValue::Array {
            element_type: dt::DINT,
            flags: 0,
            items: vec![PValue::DInt(5)],
        };
        assert!(no_shape.serialize(&mut Vec::new()).is_err());
        let sparse_zero_key = PValue::SparseArray {
            element_type: dt::UDINT,
            entries: vec![(0, PValue::UDInt(1))],
        };
        assert!(sparse_zero_key.serialize(&mut Vec::new()).is_err());
        roundtrip(PValue::Array {
            element_type: dt::DINT,
            flags: flags::ARRAY,
            items: vec![PValue::DInt(5), PValue::DInt(-70_000)],
        });
    }

    #[test]
    fn wstring_with_invalid_utf8_decodes_lossily() {
        // Like the reference: one bad byte in a name must not fail a whole Explore.
        let wire = [0x00, dt::WSTRING, 0x03, b'a', 0xff, b'b'];
        assert_eq!(
            PValue::deserialize(&mut Cursor::new(&wire)).unwrap(),
            PValue::WString("a\u{fffd}b".into())
        );
    }
}
