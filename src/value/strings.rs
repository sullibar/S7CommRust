// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver ClientApi/PlcTag.cs (PlcTagString, PlcTagWString),
// LGPL-3.0-or-later.

//! Codecs for the S7 `STRING` / `WSTRING` *variable* types.
//!
//! These are distinct from the protocol's [`PValue::WString`] value type (UTF-8 text used for
//! attribute names and the like). A PLC variable declared `STRING` or `WSTRING` is transferred as
//! a plain array carrying a two-element header:
//!
//! - `STRING` → `USInt` array `[max_len, actual_len, chars…]`, one ISO-8859-1 byte per char
//!   (read back as [`PValue::USIntArray`]);
//! - `WSTRING` → `UInt` array `[max_len, actual_len, code units…]`, UTF-16
//!   (read back as [`PValue::Array`] of [`PValue::UInt`]).
//!
//! [`Connection::read_string`](crate::Connection::read_string) /
//! [`read_wstring`](crate::Connection::read_wstring) and their `write_*` counterparts wrap these
//! for tags addressed by name; use the functions here when the value came from elsewhere (a batched
//! read, a subscription notification, …).

use crate::value::datatype::{flags, tag};
use crate::value::PValue;

/// Decode an S7 `STRING` from its USInt-array form `[max_len, actual_len, chars…]` (ISO-8859-1).
/// A truncated buffer yields the characters that are present; an `actual_len` past `max_len` is
/// clamped to `max_len`, so the unused tail of the buffer never shows up as text.
pub fn decode_s7_string(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }
    let act_len = bytes[1].min(bytes[0]) as usize;
    let end = (2 + act_len).min(bytes.len());
    bytes[2..end].iter().map(|&b| b as char).collect()
}

/// Encode an S7 `STRING` to its USInt-array write form `[max_len, actual_len, chars…]`, padded to
/// `max_len + 2` bytes as the PLC expects the complete buffer. Text longer than `max_len` is
/// truncated; characters outside ISO-8859-1 become `?`.
pub fn encode_s7_string(value: &str, max_len: u8) -> Vec<u8> {
    let chars: Vec<u8> = value
        .chars()
        .map(|c| if (c as u32) <= 0xff { c as u8 } else { b'?' })
        .collect();
    let act = chars.len().min(max_len as usize);
    let mut out = vec![0u8; max_len as usize + 2];
    out[0] = max_len;
    out[1] = act as u8;
    out[2..2 + act].copy_from_slice(&chars[..act]);
    out
}

/// Decode an S7 `WSTRING` from its UInt-array form `[max_len, actual_len, code units…]` (UTF-16).
/// Returns `None` if `v` is not an array of `UInt`; unpaired surrogates become U+FFFD.
pub fn decode_wstring(v: &PValue) -> Option<String> {
    let PValue::Array { items, .. } = v else {
        return None;
    };
    let units = items
        .iter()
        .map(|item| match item {
            PValue::UInt(u) => Some(*u),
            _ => None,
        })
        .collect::<Option<Vec<u16>>>()?;
    if units.len() < 2 {
        return Some(String::new());
    }
    let end = (2 + units[1].min(units[0]) as usize).min(units.len());
    Some(String::from_utf16_lossy(&units[2..end]))
}

/// Encode an S7 `WSTRING` to its UInt-array write form `[max_len, actual_len, code units…]`,
/// padded to `max_len + 2` elements like the `STRING` form. Text longer than `max_len` UTF-16
/// code units is truncated at a character boundary (a surrogate pair is never split).
pub fn encode_wstring(value: &str, max_len: u16) -> PValue {
    let mut units: Vec<u16> = Vec::with_capacity(value.len().min(max_len as usize));
    let mut buf = [0u16; 2];
    for c in value.chars() {
        let enc = c.encode_utf16(&mut buf);
        if units.len() + enc.len() > max_len as usize {
            break;
        }
        units.extend_from_slice(enc);
    }
    let mut items = Vec::with_capacity(max_len as usize + 2);
    items.push(PValue::UInt(max_len));
    items.push(PValue::UInt(units.len() as u16));
    items.extend(units.into_iter().map(PValue::UInt));
    items.resize(max_len as usize + 2, PValue::UInt(0));
    PValue::Array {
        element_type: tag::UINT,
        flags: flags::ARRAY,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s7_string_roundtrip() {
        let encoded = encode_s7_string("Hello", 254);
        assert_eq!(encoded.len(), 256);
        assert_eq!(encoded[0], 254); // max len
        assert_eq!(encoded[1], 5); // actual len
        assert_eq!(&encoded[2..7], b"Hello");
        assert_eq!(decode_s7_string(&encoded), "Hello");
        // Truncation to max length.
        let short = encode_s7_string("abcdef", 3);
        assert_eq!(short, vec![3, 3, b'a', b'b', b'c']);
        assert_eq!(decode_s7_string(&short), "abc");
    }

    fn uints(v: &PValue) -> Vec<u16> {
        match v {
            PValue::Array { items, .. } => items
                .iter()
                .map(|i| match i {
                    PValue::UInt(u) => *u,
                    other => panic!("not a UInt: {other:?}"),
                })
                .collect(),
            other => panic!("not an array: {other:?}"),
        }
    }

    #[test]
    fn wstring_decodes_plc_form() {
        // As read from a PLC: WString[254] holding "Hé温" — header, units, zero padding.
        let mut items = vec![PValue::UInt(254), PValue::UInt(3)];
        items.extend([0x48, 0xe9, 0x6e29].map(PValue::UInt));
        items.resize(256, PValue::UInt(0));
        let v = PValue::Array {
            element_type: tag::UINT,
            flags: flags::ARRAY,
            items,
        };
        assert_eq!(decode_wstring(&v).as_deref(), Some("Hé温"));
        // Not a UInt array → None; a bare header → empty.
        assert_eq!(decode_wstring(&PValue::USIntArray(vec![2, 0])), None);
        let empty = PValue::Array {
            element_type: tag::UINT,
            flags: flags::ARRAY,
            items: vec![PValue::UInt(10), PValue::UInt(0)],
        };
        assert_eq!(decode_wstring(&empty).as_deref(), Some(""));
    }

    #[test]
    fn wstring_roundtrip_and_truncation() {
        let v = encode_wstring("Hé温", 10);
        assert_eq!(v.datatype(), tag::UINT);
        assert_eq!(
            uints(&v),
            vec![10, 3, 0x48, 0xe9, 0x6e29, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(decode_wstring(&v).as_deref(), Some("Hé温"));

        // Truncated to max_len code units.
        assert_eq!(
            uints(&encode_wstring("abcdef", 3)),
            vec![3, 3, 0x61, 0x62, 0x63]
        );
        // A non-BMP char (surrogate pair) that would straddle the limit is dropped whole.
        let v = encode_wstring("a😀", 2);
        assert_eq!(uints(&v), vec![2, 1, 0x61, 0]);
        let v = encode_wstring("a😀", 3);
        assert_eq!(decode_wstring(&v).as_deref(), Some("a😀"));
    }

    #[test]
    fn actual_length_is_clamped_to_max_length() {
        // [max 2, actual 5, ...]: bytes past max_len are padding, not text.
        assert_eq!(
            decode_s7_string(&[2, 5, b'a', b'b', b'x', b'y', b'z']),
            "ab"
        );
        let v = PValue::Array {
            element_type: tag::UINT,
            flags: flags::ARRAY,
            items: [1u16, 3, 0x61, 0x62, 0x63]
                .into_iter()
                .map(PValue::UInt)
                .collect(),
        };
        assert_eq!(decode_wstring(&v).as_deref(), Some("a"));
    }
}
