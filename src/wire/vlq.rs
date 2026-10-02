// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/S7p.cs, LGPL-3.0-or-later.

//! Variable-Length Quantity (VLQ) codec.
//!
//! S7CommPlus encodes integers as a big-endian, base-128 variable-length quantity:
//! each octet carries 7 payload bits, and the high bit (`0x80`) marks "more octets
//! follow". The 64-bit forms have a quirk — after 8 continuation octets the 9th octet
//! carries a full 8 payload bits. The signed forms sign-extend from the first octet's
//! bit 6 (`0x40`).
//!
//! These functions are a faithful, byte-for-byte port of the `*Vlq` methods in the
//! reference C# `S7p` class. Wrapping arithmetic mirrors C#'s unchecked integer
//! semantics and keeps malformed input from panicking in debug builds.

use std::io::{Read, Write};

use crate::error::{Error, Result};

#[inline]
fn read_u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => Error::Vlq("truncated VLQ".into()),
        _ => Error::Io(e),
    })?;
    Ok(b[0])
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode an unsigned 32-bit VLQ (max 5 octets).
pub fn decode_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut val: u32 = 0;
    for _ in 0..5 {
        let octet = read_u8(r)?;
        val = val.wrapping_shl(7);
        let cont = octet & 0x80;
        val = val.wrapping_add((octet & 0x7f) as u32);
        if cont == 0 {
            break;
        }
    }
    Ok(val)
}

/// Decode an unsigned 64-bit VLQ (max 8 continuation octets + 1 full-byte tail).
pub fn decode_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut val: u64 = 0;
    let mut cont = 0u8;
    for _ in 0..8 {
        let octet = read_u8(r)?;
        val = val.wrapping_shl(7);
        cont = octet & 0x80;
        val = val.wrapping_add((octet & 0x7f) as u64);
        if cont == 0 {
            break;
        }
    }
    if cont != 0 {
        let octet = read_u8(r)?;
        val = val.wrapping_shl(8);
        val = val.wrapping_add(octet as u64);
    }
    Ok(val)
}

/// Decode a signed 32-bit VLQ (sign carried in bit 6 of the first octet).
pub fn decode_i32<R: Read>(r: &mut R) -> Result<i32> {
    let mut val: i32 = 0;
    for counter in 1..=5 {
        let mut octet = read_u8(r)?;
        if counter == 1 && (octet & 0x40) != 0 {
            // sign bit set: pre-load with the one's complement of the top 6 bits
            octet &= 0xbf;
            val = -64;
        } else {
            val = val.wrapping_shl(7);
        }
        let cont = octet & 0x80;
        octet &= 0x7f;
        val = val.wrapping_add(octet as i32);
        if cont == 0 {
            break;
        }
    }
    Ok(val)
}

/// Decode a signed 64-bit VLQ (sign carried in bit 6 of the first octet).
pub fn decode_i64<R: Read>(r: &mut R) -> Result<i64> {
    let mut val: i64 = 0;
    let mut cont = 0u8;
    for counter in 1..=8 {
        let mut octet = read_u8(r)?;
        if counter == 1 && (octet & 0x40) != 0 {
            octet &= 0xbf;
            val = -64;
        } else {
            val = val.wrapping_shl(7);
        }
        cont = octet & 0x80;
        octet &= 0x7f;
        val = val.wrapping_add(octet as i64);
        if cont == 0 {
            break;
        }
    }
    if cont != 0 {
        let octet = read_u8(r)?;
        val = val.wrapping_shl(8);
        val = val.wrapping_add(octet as i64);
    }
    Ok(val)
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode an unsigned 32-bit VLQ. Returns the number of octets written.
pub fn encode_u32<W: Write>(w: &mut W, value: u32) -> Result<usize> {
    let mut bytes = [0u8; 5];
    // Find the index `i` of the highest 7-bit group that carries a set bit.
    let mut i: i32 = 4;
    while i > 0 {
        if value & 0x7fu32.wrapping_shl(i as u32 * 7) != 0 {
            break;
        }
        i -= 1;
    }
    let i = i as usize;
    for (j, slot) in bytes.iter_mut().enumerate().take(i + 1) {
        *slot = (((value >> ((i - j) as u32 * 7)) & 0x7f) as u8) | 0x80;
    }
    bytes[i] ^= 0x80; // clear continuation bit on the final octet
    w.write_all(&bytes[..i + 1])?;
    Ok(i + 1)
}

/// Encode an unsigned 64-bit VLQ. Returns the number of octets written.
pub fn encode_u64<W: Write>(w: &mut W, value: u64) -> Result<usize> {
    let mut b = [0u8; 9];
    let mut value = value;

    let special = value > 0x00ff_ffff_ffff_ffff;
    if special {
        b[0] = (value & 0xff) as u8;
    } else {
        b[0] = (value & 0x7f) as u8;
    }

    let mut length = 1usize;
    for (i, slot) in b.iter_mut().enumerate().take(9).skip(1) {
        if value >= 0x80 {
            length += 1;
            if i == 1 && special {
                value >>= 8;
            } else {
                value >>= 7;
            }
            *slot = ((value & 0x7f) as u8).wrapping_add(0x80);
        } else {
            break;
        }
    }

    if special && length == 8 {
        length += 1;
        b[8] = 0x80;
    }

    b[..length].reverse();
    w.write_all(&b[..length])?;
    Ok(length)
}

/// Encode a signed 32-bit VLQ. Returns the number of octets written.
pub fn encode_i32<W: Write>(w: &mut W, value: i32) -> Result<usize> {
    let mut b = [0u8; 5];
    let mut value = value;
    let mut abs_v: u32 = if value == i32::MIN {
        2_147_483_648
    } else {
        value.unsigned_abs()
    };

    b[0] = (value & 0x7f) as u8;
    let mut length = 1usize;
    for slot in b.iter_mut().take(5).skip(1) {
        if abs_v >= 0x40 {
            length += 1;
            abs_v >>= 7;
            value >>= 7;
            *slot = ((value & 0x7f) as u8).wrapping_add(0x80);
        } else {
            break;
        }
    }

    b[..length].reverse();
    w.write_all(&b[..length])?;
    Ok(length)
}

/// Encode a signed 64-bit VLQ. Returns the number of octets written.
pub fn encode_i64<W: Write>(w: &mut W, value: i64) -> Result<usize> {
    let mut b = [0u8; 9];
    let mut value = value;
    let mut abs_v: u64 = if value == i64::MIN {
        9_223_372_036_854_775_808
    } else {
        value.unsigned_abs()
    };

    let special = abs_v > 0x007f_ffff_ffff_ffff;
    if special {
        b[0] = (value & 0xff) as u8;
    } else {
        b[0] = (value & 0x7f) as u8;
    }

    let mut length = 1usize;
    for (i, slot) in b.iter_mut().enumerate().take(9).skip(1) {
        if abs_v >= 0x40 {
            length += 1;
            if i == 1 && special {
                abs_v >>= 8;
                value >>= 8;
            } else {
                abs_v >>= 7;
                value >>= 7;
            }
            *slot = ((value & 0x7f) as u8).wrapping_add(0x80);
        } else {
            break;
        }
    }

    if special && length == 8 {
        length += 1;
        b[8] = if value >= 0 { 0x80 } else { 0xff };
    }

    b[..length].reverse();
    w.write_all(&b[..length])?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn enc_u32(v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32(&mut out, v).unwrap();
        out
    }

    fn roundtrip_u32(v: u32) {
        let bytes = enc_u32(v);
        let got = decode_u32(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(got, v, "u32 roundtrip failed for {v:#x} via {bytes:02x?}");
    }

    #[test]
    fn u32_known_vectors() {
        assert_eq!(enc_u32(0), vec![0x00]);
        assert_eq!(enc_u32(0x7f), vec![0x7f]);
        assert_eq!(enc_u32(0x80), vec![0x81, 0x00]);
        assert_eq!(enc_u32(0x3fff), vec![0xff, 0x7f]);
        assert_eq!(enc_u32(0x4000), vec![0x81, 0x80, 0x00]);
        assert_eq!(enc_u32(u32::MAX), vec![0x8f, 0xff, 0xff, 0xff, 0x7f]);
    }

    #[test]
    fn u32_roundtrips() {
        for v in [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1234_5678, u32::MAX] {
            roundtrip_u32(v);
        }
    }

    #[test]
    fn u64_roundtrips() {
        for v in [
            0u64,
            0x7f,
            0x80,
            0x00ff_ffff_ffff_ffff,
            0x0100_0000_0000_0000,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            encode_u64(&mut out, v).unwrap();
            let got = decode_u64(&mut Cursor::new(&out)).unwrap();
            assert_eq!(got, v, "u64 roundtrip failed for {v:#x} via {out:02x?}");
        }
    }

    #[test]
    fn i32_roundtrips() {
        for v in [
            0,
            1,
            -1,
            63,
            64,
            -64,
            -65,
            0x1234,
            -0x1234,
            i32::MIN,
            i32::MAX,
        ] {
            let mut out = Vec::new();
            encode_i32(&mut out, v).unwrap();
            let got = decode_i32(&mut Cursor::new(&out)).unwrap();
            assert_eq!(got, v, "i32 roundtrip failed for {v} via {out:02x?}");
        }
    }

    #[test]
    fn i64_roundtrips() {
        for v in [
            0i64,
            1,
            -1,
            63,
            64,
            -64,
            -65,
            0x1234_5678,
            -0x1234_5678,
            i64::MIN,
            i64::MAX,
        ] {
            let mut out = Vec::new();
            encode_i64(&mut out, v).unwrap();
            let got = decode_i64(&mut Cursor::new(&out)).unwrap();
            assert_eq!(got, v, "i64 roundtrip failed for {v} via {out:02x?}");
        }
    }

    #[test]
    fn i32_sign_vector() {
        // -1 encodes as a single octet 0x7f (sign bit 0x40 set, value bits 0x3f).
        let mut out = Vec::new();
        encode_i32(&mut out, -1).unwrap();
        assert_eq!(out, vec![0x7f]);
        assert_eq!(decode_i32(&mut Cursor::new(&out)).unwrap(), -1);
    }

    /// Golden wire vectors for the signed 32-bit VLQ (the `DInt` payload), hand-derived
    /// from the reference `S7p.EncodeInt32Vlq`/`DecodeInt32Vlq`. These pin the format
    /// independently of our own encoder, so a matched encode/decode bug can't hide
    /// behind the roundtrip tests.
    #[test]
    fn i32_golden_vectors() {
        let vectors: &[(i32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (63, &[0x3f]),
            // 64 has bit 6 set, which would read as a sign — needs a lead octet.
            (64, &[0x80, 0x40]),
            (100, &[0x80, 0x64]),
            (345, &[0x82, 0x59]),
            // The reference encodes -64 non-minimally (|v| >= 0x40 forces a lead octet).
            (-64, &[0xff, 0x40]),
            (-65, &[0xff, 0x3f]),
            (-70000, &[0xfb, 0xdd, 0x10]),
            (i32::MAX, &[0x87, 0xff, 0xff, 0xff, 0x7f]),
            (i32::MIN, &[0xf8, 0x80, 0x80, 0x80, 0x00]),
        ];
        for (value, bytes) in vectors {
            let mut out = Vec::new();
            encode_i32(&mut out, *value).unwrap();
            assert_eq!(out, *bytes, "encode mismatch for {value}");
            assert_eq!(
                decode_i32(&mut Cursor::new(bytes)).unwrap(),
                *value,
                "decode mismatch for {bytes:02x?}"
            );
        }
        // Decode-only: the minimal single-octet form of -64 (sign bit, zero payload)
        // is valid on the wire even though the reference encoder never emits it.
        assert_eq!(decode_i32(&mut Cursor::new(&[0x40u8])).unwrap(), -64);
    }
}
