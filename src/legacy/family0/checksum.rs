// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Ported from `bonk-dev/HarpoS7` (MIT):
//   HarpoS7.Family0/Transforms/LutGenerator.cs
//   HarpoS7.Family0/Transforms/ChecksumTransform.cs
// See `LICENSE-HarpoS7`.

//! The Family-0 authenticated-checksum primitive used to seal the RealPlc blob.
//!
//! [`generate_lut`] builds a 4 KiB lookup table: a full 256-entry `GF(2^128)`
//! multiplication table of the 16-byte seed (the GHASH-style construction with
//! reduction polynomial `0x01_0000_8005`). [`checksum`] then folds a 16-byte key
//! through that table (byte-wise, with a rotate between rounds) into a 16-byte tag.
//!
//! Both are pure bit/table arithmetic (no elliptic-curve arithmetic), validated
//! byte-for-byte against HarpoS7's `transform3` (LUT) and `transform4` (checksum)
//! golden vectors. In the blob these are `RealPlcAuthenticator.DeriveKeysAndLookupTable`
//! (`LutGenerator`) and the running-checksum / `UpdateChecksum` step (`ChecksumTransform`).

/// `LutGenerator.SourceSize` — the 16-byte GF(2^128) seed.
pub const LUT_SRC_LEN: usize = 0x10;
/// `LutGenerator.DestinationSize` — the 4 KiB (256 × 16-byte) table.
pub const LUT_LEN: usize = 0x1000;
/// `ChecksumTransform.KeySize` / `DestinationSize` — 16 bytes.
pub const CHECKSUM_LEN: usize = 0x10;

/// The GF(2^128) reduction polynomial folded in on a carry-out of the top bit.
const GF_POLY: u128 = 0x01_0000_8005;

#[inline]
fn rd_u32(buf: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]])
}

/// `LutGenerator.Execute`: expand a 16-byte seed into the 4 KiB GF(2^128) table.
///
/// `dst` must be at least [`LUT_LEN`] bytes, `src` at least [`LUT_SRC_LEN`].
pub fn generate_lut(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() >= LUT_LEN, "lut dst too small");
    assert!(src.len() >= LUT_SRC_LEN, "lut src too small");

    // 256 GF(2^128) entries (little-endian). q[0] = 0, q[1] = seed.
    let mut q = [0u128; 256];
    q[1] = u128::from_le_bytes(src[..16].try_into().unwrap());

    let mut i = 1usize;
    while i < 128 {
        let multiplicand = q[i];
        let mut product = multiplicand << 1; // GF doubling (xtime), wraps mod 2^128
        if multiplicand >> 0x7F != 0 {
            product ^= GF_POLY;
        }

        let product_index = i * 2;
        q[product_index] = product;
        for j in 1..product_index {
            q[product_index + j] = q[j] ^ product;
        }

        i *= 2;
    }

    for (k, &v) in q.iter().enumerate() {
        dst[k * 16..k * 16 + 16].copy_from_slice(&v.to_le_bytes());
    }
}

/// `ChecksumTransform.Execute`: fold `key` (16 bytes) through the `lut` (4 KiB,
/// from [`generate_lut`]) into a 16-byte `dst` tag.
pub fn checksum(dst: &mut [u8], key: &[u8], lut: &[u8]) {
    assert!(dst.len() >= CHECKSUM_LEN, "checksum dst too small");
    assert!(key.len() >= CHECKSUM_LEN, "checksum key too small");
    assert!(lut.len() >= LUT_LEN, "checksum lut too small");

    let kd = |j: usize| rd_u32(key, j);
    let lut_word = |idx: usize| rd_u32(lut, idx);

    let mut wb = [0u32; 8];

    // XOR four table rows selected by successive key bytes (MSB..down), rotating
    // the 256-bit accumulator left by one byte between rounds.
    let mut i = 0x18i32;
    while i > 0 {
        for j in 0..4 {
            let lut_index = (((kd(j) >> i) & 0xFF) << 2) as usize;
            for k in 0..4 {
                wb[j + k] ^= lut_word(lut_index + k);
            }
        }
        for j in (1..=7).rev() {
            wb[j] = wb[j - 1] >> 0x18 | wb[j] << 0x08;
        }
        wb[0] <<= 0x08;
        i -= 0x08;
    }
    for i in 0..4 {
        let lut_index = ((kd(i) & 0xFF) << 2) as usize;
        for k in 0..4 {
            wb[i + k] ^= lut_word(lut_index + k);
        }
    }

    // Final avalanche mixing → 128-bit tag.
    let temp = (wb[7] >> 0x0D ^ wb[7]) >> 0x11 ^ wb[4] ^ wb[7];
    let out = [
        (temp << 0x0D ^ temp) << 0x02 ^ wb[0] ^ temp,
        (temp >> 0x0D ^ temp) >> 0x11 ^ (wb[5] << 0x0D ^ wb[5]) << 2 ^ wb[1] ^ temp ^ wb[5],
        (wb[5] >> 0x0D ^ wb[5]) >> 0x11 ^ (wb[6] << 0x0D ^ wb[6]) << 2 ^ wb[2] ^ wb[5] ^ wb[6],
        (wb[6] >> 0x0D ^ wb[6]) >> 0x11 ^ (wb[7] << 0x0D ^ wb[7]) << 2 ^ wb[3] ^ wb[6] ^ wb[7],
    ];
    for (i, &v) in out.iter().enumerate() {
        dst[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_lut_golden() {
        let src = include_bytes!("../../../tests/vectors/family0/transforms/transform3-src.bin");
        let expected =
            include_bytes!("../../../tests/vectors/family0/transforms/transform3-dst.bin");
        let mut dst = [0u8; LUT_LEN];
        generate_lut(&mut dst, src);
        assert_eq!(&dst[..], &expected[..]);
    }

    #[test]
    fn checksum_golden() {
        let key = include_bytes!("../../../tests/vectors/family0/transforms/transform4-key.bin");
        let lut = include_bytes!("../../../tests/vectors/family0/transforms/transform4-lut.bin");
        let expected =
            include_bytes!("../../../tests/vectors/family0/transforms/transform4-dst.bin");
        let mut dst = [0u8; CHECKSUM_LEN];
        checksum(&mut dst, key, lut);
        assert_eq!(&dst[..], &expected[..]);
    }
}
