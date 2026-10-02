// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/S7p.cs, LGPL-3.0-or-later.

//! Fixed-width wire primitives.
//!
//! Faithful ports of the non-VLQ `Encode*`/`Decode*` helpers in the reference `S7p`
//! class. All multi-byte integers and floats are **big-endian** (network order); a few
//! little-endian decoders exist upstream for embedded structures and are provided too.
//!
//! Note: [`encode_wstring`]/[`decode_wstring`] use **UTF-8**, matching the reference
//! `S7p.EncodeWString`. This is the transport-level string helper (used for object names
//! and similar). It is *not* the PLC `WString` datatype, which is UTF-16 and handled in
//! the value layer.

use std::io::{Read, Write};

use crate::error::{Error, Result};

#[inline]
fn read_n<const N: usize, R: Read>(r: &mut R) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf).map_err(Error::decode)?;
    Ok(buf)
}

// --- byte ------------------------------------------------------------------

/// Write a single byte.
pub fn encode_u8<W: Write>(w: &mut W, value: u8) -> Result<usize> {
    w.write_all(&[value])?;
    Ok(1)
}

/// Read a single byte.
pub fn decode_u8<R: Read>(r: &mut R) -> Result<u8> {
    Ok(read_n::<1, _>(r)?[0])
}

// --- 16-bit ----------------------------------------------------------------

/// Write a big-endian `u16`.
pub fn encode_u16<W: Write>(w: &mut W, value: u16) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(2)
}

/// Read a big-endian `u16`.
pub fn decode_u16<R: Read>(r: &mut R) -> Result<u16> {
    Ok(u16::from_be_bytes(read_n::<2, _>(r)?))
}

/// Read a little-endian `u16` (`DecodeUInt16LE`).
pub fn decode_u16_le<R: Read>(r: &mut R) -> Result<u16> {
    Ok(u16::from_le_bytes(read_n::<2, _>(r)?))
}

/// Write a big-endian `i16`.
pub fn encode_i16<W: Write>(w: &mut W, value: i16) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(2)
}

/// Read a big-endian `i16`.
pub fn decode_i16<R: Read>(r: &mut R) -> Result<i16> {
    Ok(i16::from_be_bytes(read_n::<2, _>(r)?))
}

// --- 32-bit ----------------------------------------------------------------

/// Write a big-endian `u32`.
pub fn encode_u32<W: Write>(w: &mut W, value: u32) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(4)
}

/// Read a big-endian `u32`.
pub fn decode_u32<R: Read>(r: &mut R) -> Result<u32> {
    Ok(u32::from_be_bytes(read_n::<4, _>(r)?))
}

/// Read a little-endian `u32` (`DecodeUInt32LE`).
pub fn decode_u32_le<R: Read>(r: &mut R) -> Result<u32> {
    Ok(u32::from_le_bytes(read_n::<4, _>(r)?))
}

/// Write a big-endian `i32`.
pub fn encode_i32<W: Write>(w: &mut W, value: i32) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(4)
}

/// Read a big-endian `i32`.
pub fn decode_i32<R: Read>(r: &mut R) -> Result<i32> {
    Ok(i32::from_be_bytes(read_n::<4, _>(r)?))
}

/// Read a little-endian `i32` (`DecodeInt32LE`).
pub fn decode_i32_le<R: Read>(r: &mut R) -> Result<i32> {
    Ok(i32::from_le_bytes(read_n::<4, _>(r)?))
}

// --- 64-bit ----------------------------------------------------------------

/// Write a big-endian `u64`.
pub fn encode_u64<W: Write>(w: &mut W, value: u64) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(8)
}

/// Read a big-endian `u64`.
pub fn decode_u64<R: Read>(r: &mut R) -> Result<u64> {
    Ok(u64::from_be_bytes(read_n::<8, _>(r)?))
}

/// Write a big-endian `i64`.
pub fn encode_i64<W: Write>(w: &mut W, value: i64) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(8)
}

/// Read a big-endian `i64`.
pub fn decode_i64<R: Read>(r: &mut R) -> Result<i64> {
    Ok(i64::from_be_bytes(read_n::<8, _>(r)?))
}

// --- floats ----------------------------------------------------------------

/// Write a big-endian IEEE-754 `f32`.
pub fn encode_f32<W: Write>(w: &mut W, value: f32) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(4)
}

/// Read a big-endian IEEE-754 `f32`.
pub fn decode_f32<R: Read>(r: &mut R) -> Result<f32> {
    Ok(f32::from_be_bytes(read_n::<4, _>(r)?))
}

/// Write a big-endian IEEE-754 `f64`.
pub fn encode_f64<W: Write>(w: &mut W, value: f64) -> Result<usize> {
    w.write_all(&value.to_be_bytes())?;
    Ok(8)
}

/// Read a big-endian IEEE-754 `f64`.
pub fn decode_f64<R: Read>(r: &mut R) -> Result<f64> {
    Ok(f64::from_be_bytes(read_n::<8, _>(r)?))
}

// --- octets / strings ------------------------------------------------------

/// Write raw bytes verbatim (`EncodeOctets`). A null/empty slice writes nothing.
pub fn encode_octets<W: Write>(w: &mut W, value: &[u8]) -> Result<usize> {
    if value.is_empty() {
        return Ok(0);
    }
    w.write_all(value)?;
    Ok(value.len())
}

/// Read `length` raw bytes (`DecodeOctets`).
///
/// The buffer grows as bytes actually arrive, so a bogus length from the wire fails at the end
/// of the input instead of allocating it up front.
pub fn decode_octets<R: Read>(r: &mut R, length: usize) -> Result<Vec<u8>> {
    let mut value = Vec::with_capacity(length.min(4096));
    r.by_ref()
        .take(length as u64)
        .read_to_end(&mut value)
        .map_err(Error::decode)?;
    if value.len() != length {
        return Err(Error::protocol(format!(
            "telegram truncated: wanted {length} bytes, got {}",
            value.len()
        )));
    }
    Ok(value)
}

/// Write a string as UTF-8 bytes (`EncodeWString`). See the module note: this is the
/// transport-level helper, not the PLC UTF-16 `WString` datatype.
pub fn encode_wstring<W: Write>(w: &mut W, value: &str) -> Result<usize> {
    let bytes = value.as_bytes();
    w.write_all(bytes)?;
    Ok(bytes.len())
}

/// Read `length` bytes and decode them as UTF-8 (`DecodeWString`). Invalid sequences are
/// replaced with U+FFFD, mirroring C#'s `Encoding.UTF8.GetString`.
pub fn decode_wstring<R: Read>(r: &mut R, length: usize) -> Result<String> {
    let bytes = decode_octets(r, length)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn big_endian_integers() {
        let mut out = Vec::new();
        encode_u16(&mut out, 0x0102).unwrap();
        encode_u32(&mut out, 0x0304_0506).unwrap();
        encode_u64(&mut out, 0x0708_090a_0b0c_0d0e).unwrap();
        assert_eq!(
            out,
            vec![
                0x01, 0x02, // u16
                0x03, 0x04, 0x05, 0x06, // u32
                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // u64
            ]
        );
        let mut cur = Cursor::new(&out);
        assert_eq!(decode_u16(&mut cur).unwrap(), 0x0102);
        assert_eq!(decode_u32(&mut cur).unwrap(), 0x0304_0506);
        assert_eq!(decode_u64(&mut cur).unwrap(), 0x0708_090a_0b0c_0d0e);
    }

    #[test]
    fn little_endian_decoders() {
        assert_eq!(
            decode_u16_le(&mut Cursor::new([0x01, 0x02])).unwrap(),
            0x0201
        );
        assert_eq!(
            decode_u32_le(&mut Cursor::new([0x01, 0x02, 0x03, 0x04])).unwrap(),
            0x0403_0201
        );
    }

    #[test]
    fn floats_roundtrip_big_endian() {
        let mut out = Vec::new();
        encode_f32(&mut out, 1.5).unwrap();
        // 1.5f32 = 0x3FC00000 big-endian.
        assert_eq!(out, vec![0x3f, 0xc0, 0x00, 0x00]);
        assert_eq!(decode_f32(&mut Cursor::new(&out)).unwrap(), 1.5);

        let mut out = Vec::new();
        encode_f64(&mut out, -2.0).unwrap();
        assert_eq!(decode_f64(&mut Cursor::new(&out)).unwrap(), -2.0);
    }

    #[test]
    fn signed_roundtrips() {
        for v in [i16::MIN, -1, 0, 1, i16::MAX] {
            let mut out = Vec::new();
            encode_i16(&mut out, v).unwrap();
            assert_eq!(decode_i16(&mut Cursor::new(&out)).unwrap(), v);
        }
        for v in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut out = Vec::new();
            encode_i32(&mut out, v).unwrap();
            assert_eq!(decode_i32(&mut Cursor::new(&out)).unwrap(), v);
        }
        for v in [i64::MIN, -1, 0, 1, i64::MAX] {
            let mut out = Vec::new();
            encode_i64(&mut out, v).unwrap();
            assert_eq!(decode_i64(&mut Cursor::new(&out)).unwrap(), v);
        }
    }

    #[test]
    fn octets_and_string() {
        let mut out = Vec::new();
        encode_octets(&mut out, &[]).unwrap();
        assert!(out.is_empty());
        encode_wstring(&mut out, "Tag_1").unwrap();
        assert_eq!(out, b"Tag_1");
        let s = decode_wstring(&mut Cursor::new(&out), out.len()).unwrap();
        assert_eq!(s, "Tag_1");
    }
}
