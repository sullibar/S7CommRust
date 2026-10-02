// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/PObject.cs + Core/ElementID.cs,
// LGPL-3.0-or-later.

//! The S7CommPlus object model (`PObject`).
//!
//! Objects are a tag-delimited (TLV-ish) structure: an object opens with
//! [`element_id::START_OF_OBJECT`], carries a fixed header (relation id, class id, class
//! flags, attribute id), then a sequence of attributes (each a [`PValue`]), nested
//! objects, and relations, and closes with [`element_id::TERMINATING_OBJECT`].
//!
//! Serialization is a faithful port of `PObject.Serialize`. Deserialization of arbitrary
//! response objects is not yet implemented (responses we currently need — e.g.
//! CreateObject — expose what we want via their object-id list before the object body).

use std::io::{Cursor, Write};

use crate::error::{Error, Result};
use crate::proto::type_info::{VarnameList, VartypeList};
use crate::value::PValue;
use crate::wire::pdu::ids;
use crate::wire::{primitives as p, vlq};

/// Element-ID tag bytes that delimit the parts of a serialized object.
pub mod element_id {
    pub const START_OF_OBJECT: u8 = 0xa1;
    pub const TERMINATING_OBJECT: u8 = 0xa2;
    pub const ATTRIBUTE: u8 = 0xa3;
    pub const RELATION: u8 = 0xa4;
    pub const VARTYPE_LIST: u8 = 0xab;
    pub const VARNAME_LIST: u8 = 0xac;
}

/// A S7CommPlus object: a header plus ordered attributes, nested objects, and relations.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PObject {
    /// Relation id (RID) identifying this object instance.
    pub relation_id: u32,
    /// Class id (CLSID) — the object's type.
    pub class_id: u32,
    /// Class flags.
    pub class_flags: u32,
    /// Attribute id (AID) the object was addressed by.
    pub attribute_id: u32,
    /// Attributes in insertion order (`(attribute_id, value)`).
    pub attributes: Vec<(u32, PValue)>,
    /// Nested objects in insertion order.
    pub objects: Vec<PObject>,
    /// Relations in insertion order (`(relation_id, value)`).
    pub relations: Vec<(u32, u32)>,
    /// Type-info member list (element `0xab`), present on type-info objects.
    pub vartype_list: Option<VartypeList>,
    /// Type-info member names (element `0xac`), parallel to `vartype_list`.
    pub varname_list: Option<VarnameList>,
}

impl PObject {
    /// Create an object with the given relation id (RID), class id (CLSID), and attribute
    /// id (AID). `class_flags` defaults to 0, matching the reference constructor.
    pub fn new(relation_id: u32, class_id: u32, attribute_id: u32) -> Self {
        PObject {
            relation_id,
            class_id,
            class_flags: 0,
            attribute_id,
            ..Default::default()
        }
    }

    /// Add an attribute (preserves insertion order).
    pub fn add_attribute(&mut self, attribute_id: u32, value: PValue) -> &mut Self {
        self.attributes.push((attribute_id, value));
        self
    }

    /// Add a nested object (preserves insertion order).
    pub fn add_object(&mut self, obj: PObject) -> &mut Self {
        self.objects.push(obj);
        self
    }

    /// Add a relation (preserves insertion order).
    pub fn add_relation(&mut self, relation_id: u32, value: u32) -> &mut Self {
        self.relations.push((relation_id, value));
        self
    }

    /// The value of the attribute with id `attribute_id`, if present (first match).
    pub fn attribute(&self, attribute_id: u32) -> Option<&PValue> {
        self.attributes
            .iter()
            .find(|(id, _)| *id == attribute_id)
            .map(|(_, v)| v)
    }

    /// Serialize the object. Returns bytes written.
    pub fn serialize<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = 0;
        n += p::encode_u8(w, element_id::START_OF_OBJECT)?;
        n += p::encode_u32(w, self.relation_id)?; // fixed-width
        n += vlq::encode_u32(w, self.class_id)?;
        n += vlq::encode_u32(w, self.class_flags)?;
        n += vlq::encode_u32(w, self.attribute_id)?;

        for (key, value) in &self.attributes {
            n += p::encode_u8(w, element_id::ATTRIBUTE)?;
            n += vlq::encode_u32(w, *key)?;
            n += value.serialize(w)?;
        }

        for obj in &self.objects {
            n += obj.serialize(w)?;
        }

        for (key, value) in &self.relations {
            n += p::encode_u8(w, element_id::RELATION)?;
            n += vlq::encode_u32(w, *key)?;
            n += p::encode_u32(w, *value)?; // fixed-width
        }

        n += p::encode_u8(w, element_id::TERMINATING_OBJECT)?;
        Ok(n)
    }
}

/// Encode the object qualifier appended to Get/SetMultiVariables requests
/// (`S7p.EncodeObjectQualifier`): a fixed-u32 qualifier id, then three (id, value) pairs
/// with zero values (parent RID, composition AID, key qualifier), then a `0x00` terminator.
pub fn encode_object_qualifier<W: Write>(w: &mut W) -> Result<usize> {
    let mut n = 0;
    n += p::encode_u32(w, ids::OBJECT_QUALIFIER)?; // fixed-width id
    n += vlq::encode_u32(w, ids::PARENT_RID)?;
    n += PValue::RID(0).serialize(w)?;
    n += vlq::encode_u32(w, ids::COMPOSITION_AID)?;
    n += PValue::AID(0).serialize(w)?;
    n += vlq::encode_u32(w, ids::KEY_QUALIFIER)?;
    n += PValue::UDInt(0).serialize(w)?;
    n += p::encode_u8(w, 0x00)?;
    Ok(n)
}

/// Deepest object nesting the decoder accepts. Explore trees nest a handful of levels; the limit
/// keeps a corrupt or hostile telegram from overflowing the stack.
pub const MAX_OBJECT_NESTING: usize = 32;

/// Decode a list of objects (`S7p.DecodeObjectList`): consume consecutive objects while
/// the next tag is `element_id::START_OF_OBJECT`; stop at anything else (or end of buf).
pub fn decode_object_list(cur: &mut Cursor<&[u8]>) -> Result<Vec<PObject>> {
    let mut list = Vec::new();
    loop {
        let pos = cur.position() as usize;
        let buf = cur.get_ref();
        if pos >= buf.len() || buf[pos] != element_id::START_OF_OBJECT {
            break;
        }
        list.push(decode_object(cur)?);
    }
    Ok(list)
}

/// Decode a single object including its leading [`element_id::START_OF_OBJECT`] tag.
pub fn decode_object(cur: &mut Cursor<&[u8]>) -> Result<PObject> {
    let tag = p::decode_u8(cur)?;
    if tag != element_id::START_OF_OBJECT {
        return Err(Error::protocol(format!(
            "decode_object: expected StartOfObject (0xa1), got 0x{tag:02x}"
        )));
    }
    decode_object_after_tag(cur, 0)
}

/// Decode an object's header and body, assuming the `StartOfObject` tag was already read
/// (mirrors the body of `S7p.DecodeObject`). Nested child objects recurse; the object ends
/// at [`element_id::TERMINATING_OBJECT`]. Nesting deeper than [`MAX_OBJECT_NESTING`] is rejected.
fn decode_object_after_tag(cur: &mut Cursor<&[u8]>, depth: usize) -> Result<PObject> {
    if depth > MAX_OBJECT_NESTING {
        return Err(Error::protocol(format!(
            "object nesting deeper than {MAX_OBJECT_NESTING} levels"
        )));
    }
    let relation_id = p::decode_u32(cur)?; // fixed-width
    let class_id = vlq::decode_u32(cur)?;
    let class_flags = vlq::decode_u32(cur)?;
    let attribute_id = vlq::decode_u32(cur)?;
    let mut obj = PObject {
        relation_id,
        class_id,
        class_flags,
        attribute_id,
        ..Default::default()
    };

    loop {
        let tag = p::decode_u8(cur)?;
        match tag {
            element_id::START_OF_OBJECT => {
                let child = decode_object_after_tag(cur, depth + 1)?;
                obj.objects.push(child);
            }
            element_id::TERMINATING_OBJECT => break,
            element_id::ATTRIBUTE => {
                let id = vlq::decode_u32(cur)?;
                let value = PValue::deserialize(cur)?;
                obj.attributes.push((id, value));
            }
            element_id::RELATION => {
                let id = vlq::decode_u32(cur)?;
                let value = p::decode_u32(cur)?; // fixed-width
                obj.relations.push((id, value));
            }
            element_id::VARTYPE_LIST => {
                obj.vartype_list = Some(VartypeList::deserialize(cur)?);
            }
            element_id::VARNAME_LIST => {
                obj.varname_list = Some(VarnameList::deserialize(cur)?);
            }
            other => {
                return Err(Error::protocol(format!(
                    "decode_object: unexpected element tag 0x{other:02x} (rid={relation_id}, clsid={class_id})"
                )));
            }
        }
    }
    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_qualifier_layout() {
        let mut out = Vec::new();
        encode_object_qualifier(&mut out).unwrap();
        assert_eq!(
            out,
            vec![
                0x00, 0x00, 0x04, 0xe8, // ObjectQualifier 1256 (fixed u32)
                0x89, 0x69, // ParentRID 1257 (VLQ)
                0x00, 0x12, 0x00, 0x00, 0x00, 0x00, // RID(0)
                0x89, 0x6a, // CompositionAID 1258 (VLQ)
                0x00, 0x13, 0x00, // AID(0)
                0x89, 0x6b, // KeyQualifier 1259 (VLQ)
                0x00, 0x04, 0x00, // UDInt(0)
                0x00, // terminator
            ]
        );
    }

    #[test]
    fn empty_object_layout() {
        let obj = PObject::new(211, 255, 0);
        let mut out = Vec::new();
        obj.serialize(&mut out).unwrap();
        assert_eq!(
            out,
            vec![
                0xa1, // StartOfObject
                0x00, 0x00, 0x00, 0xd3, // relation id 211 (fixed)
                0x81, 0x7f, // class id 255 (VLQ)
                0x00, // class flags 0 (VLQ)
                0x00, // attribute id 0 (VLQ)
                0xa2, // TerminatingObject
            ]
        );
    }

    #[test]
    fn attribute_and_nested_object() {
        let mut obj = PObject::new(211, 287, 0);
        obj.add_attribute(300, PValue::RID(0x80c3_c901));
        obj.add_object(PObject::new(211, 255, 0));
        let mut out = Vec::new();
        obj.serialize(&mut out).unwrap();
        assert_eq!(
            out,
            vec![
                0xa1, 0x00, 0x00, 0x00, 0xd3, // header: SOO, rid 211
                0x82, 0x1f, // class id 287 (VLQ)
                0x00, 0x00, // class flags, attribute id
                0xa3, 0x82, 0x2c, // attribute, key 300
                0x00, 0x12, 0x80, 0xc3, 0xc9, 0x01, // RID value
                0xa1, 0x00, 0x00, 0x00, 0xd3, 0x81, 0x7f, 0x00, 0x00, 0xa2, // nested obj
                0xa2, // TerminatingObject (outer)
            ]
        );
    }
}
