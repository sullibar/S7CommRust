// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Ported from `bonk-dev/HarpoS7` (MIT):
//   HarpoS7.Family0/Transforms/SeedTransform.cs
// See `LICENSE-HarpoS7`.

//! `SeedTransform`: the 60-byte EC-encrypted seed (the RealPlc blob's ECIES core).
//!
//! Output layout: `dst[0x14..0x28]` = affine x of the ephemeral point `k·G`; `dst[0x28..0x3C]`
//! = the ephemeral scalar seed `prng1`; `dst[0x00..0x14]` = the ECDH combine
//! `Monolith11( t1 ‖ Transform13( Monolith8( k·publicKey ) ) )`. The same `(prng1, prng2)`
//! drives both `k·G` and `k·publicKey`.
//!
//! The two ephemeral 20-byte buffers are supplied by the injected `fill_random` closure (a
//! CSPRNG in production; a fixed fill in the golden tests, mirroring HarpoS7's
//! `SpanExtensions.StaticFillSequence`).

use super::{curve, present};
// The original monolith chain, kept as the differential-test reference.
#[cfg(test)]
use super::{data::TRANSFORM7_DATA, monolith, transform7::transform7, transforms::transform13};

/// `SeedTransform.DestinationSize` (used by the seed round-trip test).
#[cfg(test)]
const SEED_LEN: usize = 0x3C;

#[cfg(test)]
/// `Monolith1.Loop(buf, buf)` — the aliased (destination == source) normalization used by
/// `SeedTransform`: run `execute` (reading a snapshot, writing `buf`) until it returns nonzero.
fn loop_normalize_in_place(buf: &mut [u8]) {
    loop {
        let src = buf.to_vec();
        if monolith::m1::execute(buf, &src) != 0 {
            break;
        }
    }
}

#[cfg(test)]
/// `SeedTransform.Execute(destination[0x3C], publicKey[0x28], t1[0x3C])`.
pub fn seed_transform(
    destination: &mut [u8],
    public_key: &[u8],
    t1: &[u8],
    fill_random: &mut dyn FnMut(&mut [u8]),
) {
    let mut prng1 = [0u8; 20];
    fill_random(&mut prng1);

    let mut prng2 = [0u8; 20];
    let mut t7 = [0u8; 72];
    let base = &TRANSFORM7_DATA[0xD8..0x100]; // base point G (40 bytes)

    // Ephemeral point R = k·G; retry until its affine x is nonzero.
    loop {
        fill_random(&mut prng2);
        transform7(&mut t7, &prng1, &prng2, base);
        loop_normalize_in_place(&mut t7);
        let mut x = [0u8; 20];
        monolith::m2::execute(&mut x, &t7);
        if x.iter().any(|&b| b != 0) {
            destination[0x14..0x28].copy_from_slice(&x);
            break;
        }
    }
    destination[0x28..0x3C].copy_from_slice(&prng1);

    // ECDH point k·publicKey, combined with t1.
    transform7(&mut t7, &prng1, &prng2, public_key);
    loop_normalize_in_place(&mut t7);

    let mut m8 = [0u8; 60];
    monolith::m8::execute(&mut m8, &t7);

    let mut m11src = [0u8; 120];
    m11src[..60].copy_from_slice(&t1[..60]);
    transform13(&mut m11src[60..120], &m8);

    let mut m11 = [0u8; 20];
    monolith::m11::execute(&mut m11, &m11src);
    destination[0..20].copy_from_slice(&m11);
}

/// The key register whose Monolith10 round-key layout is HarpoS7's `Transform1Data`; the
/// PreSeed encrypts `key1` under it.
const PRE_SEED_KEY: u128 = 0xA98D_E7C5_164A_D032_538F;

/// Fixed plaintexts: HarpoS7's `SharedData` words `0..12` (KeyDerivation) and `12..18`
/// (Transform13), as little-endian 64-bit blocks.
const KEY_PLAINTEXTS: [u64; 6] = [
    0xEFFC_B975_BC88_64FD,
    0x20B6_407A_F043_3F14,
    0x6108_06EF_E035_8644,
    0xFF78_C6D5_C660_CEDC,
    0xC5E8_8FDB_01AF_4AE1,
    0x2AE2_BA51_7C0D_93F6,
];
const SEED_MASK_PLAINTEXTS: [u64; 3] = [
    0xF5EA_1E69_CBDF_8EF1,
    0xF4C5_2FEB_C1C0_1D1A,
    0xADF3_6021_56A7_24DE,
];

/// `PreSeedTransform`: `key1`'s three 64-bit blocks encrypted under [`PRE_SEED_KEY`], as one
/// 160-bit little-endian value.
pub fn pre_seed(key1: &[u8; 24]) -> [u8; 20] {
    let block = |i: usize| u64::from_le_bytes(key1[8 * i..8 * i + 8].try_into().unwrap());
    present::encrypt_blocks([block(0), block(1), block(2)], [PRE_SEED_KEY; 3])
}

/// `Transform13`: the fixed blocks under the low, low and high 80 bits of the shared secret.
fn seed_mask(shared_x: &[u8; 20]) -> [u8; 20] {
    let (low, high) = present::key_halves(shared_x);
    present::encrypt_blocks(SEED_MASK_PLAINTEXTS, [low, low, high])
}

/// `SeedTransform`: write the 60-byte seed field — the pre-seed masked by the ECDH shared
/// secret, the ephemeral public x-coordinate, and `prng1`.
///
/// `fill_random` is called for `prng1` then `prng2` (again for a fresh `prng2` in the
/// vanishingly rare case that `k·G` is the point at infinity), like the original. `prng1` only
/// blinded HarpoS7's internal encoding of the scalar, but is still sent.
pub fn write_seed(
    destination: &mut [u8],
    public_key: &[u8],
    pre_seed: &[u8; 20],
    fill_random: &mut dyn FnMut(&mut [u8]),
) {
    let mut prng1 = [0u8; 20];
    fill_random(&mut prng1);

    let mut prng2 = [0u8; 20];
    let (scalar, ephemeral) = loop {
        fill_random(&mut prng2);
        let scalar = curve::ladder_scalar(&prng2);
        let x = curve::x_multiply(&scalar, &curve::GENERATOR_X);
        if x != [0u8; 20] {
            break (scalar, x);
        }
    };
    // Only the public key's x-coordinate (its first 20 bytes) takes part.
    let public_x: [u8; 20] = public_key[..20].try_into().unwrap();
    let shared = curve::x_multiply(&scalar, &public_x);

    let mask = seed_mask(&shared);
    for (i, slot) in destination[..20].iter_mut().enumerate() {
        *slot = pre_seed[i] ^ mask[i];
    }
    destination[0x14..0x28].copy_from_slice(&ephemeral);
    destination[0x28..0x3C].copy_from_slice(&prng1);
}

/// `KeyDerivationTransform`: three fixed blocks under the pre-seed's low 80 bits and three
/// under its high 80 bits, giving `challengeKey(16) ‖ checksumKey(16) ‖ lutSeed(16)`.
pub fn derive_keys(pre_seed: &[u8; 20]) -> [u8; 48] {
    let (low, high) = present::key_halves(pre_seed);
    let mut out = [0u8; 48];
    for (i, &block) in KEY_PLAINTEXTS.iter().enumerate() {
        let key = if i < 3 { low } else { high };
        out[8 * i..8 * i + 8].copy_from_slice(&present::encrypt(block, key).to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::family0::data::SHARED_DATA;

    #[test]
    fn plaintexts_are_harpos7_shared_data() {
        let word =
            |i: usize| u64::from(SHARED_DATA[2 * i + 1]) << 32 | u64::from(SHARED_DATA[2 * i]);
        for (i, &p) in KEY_PLAINTEXTS.iter().enumerate() {
            assert_eq!(p, word(i));
        }
        for (i, &p) in SEED_MASK_PLAINTEXTS.iter().enumerate() {
            assert_eq!(p, word(6 + i));
        }
    }

    #[test]
    fn generator_is_harpos7_transform7_base() {
        assert_eq!(curve::GENERATOR_X, TRANSFORM7_DATA[0xD8..0xEC]);
    }

    #[test]
    fn seed_transform_matches_transform6() {
        // transform6: StaticFillSequence = [0x2D] -> every fill is 0x2D.
        let public_key =
            include_bytes!("../../../tests/vectors/family0/transforms/transform6-publicKey.bin");
        let t1 = include_bytes!("../../../tests/vectors/family0/transforms/transform6-t1.bin");
        let expected =
            include_bytes!("../../../tests/vectors/family0/transforms/transform6-dst.bin");

        let mut dst = [0u8; SEED_LEN];
        let mut fill = |b: &mut [u8]| b.fill(0x2D);
        seed_transform(&mut dst, public_key, t1, &mut fill);
        assert_eq!(&dst[..], &expected[..]);
    }
}
