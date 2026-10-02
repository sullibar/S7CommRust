// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Replaces the ports of `bonk-dev/HarpoS7` (MIT) `HarpoS7.Family0/Transforms/{PreSeed,Seed,
// KeyDerivation}Transform.cs` and `Transform13.cs`. What those transforms compute, and the
// constants below, were identified in `gijzelaerr/s7commplus`
// (`s7commplus/v1_session_key/real_plc/seed.py`, MIT).
// See `LICENSE-HarpoS7` and `LICENSE-gijzelaerr-s7commplus`.

//! The real-PLC seed and blob keys, from `key1` and the PLC public key.
//!
//! - [`pre_seed`] (`PreSeedTransform`): `key1`'s three 64-bit blocks encrypted with
//!   [PRESENT-80](super::present) under a fixed key, as one 160-bit value.
//! - [`write_seed`] (`SeedTransform`): an ephemeral x-only [ECDH](super::curve) with the PLC
//!   public key. The blob gets the ephemeral x-coordinate, and a mask derived from the shared
//!   x-coordinate (`Transform13`) hides the pre-seed.
//! - [`derive_keys`] (`KeyDerivationTransform`): six fixed blocks encrypted under halves of
//!   the pre-seed, giving the challenge key, the checksum key and the checksum LUT seed.
//!
//! HarpoS7 passes these values between its transforms in an encoded form (three words per
//! bit); here they are plain 160-bit little-endian values.

use super::{curve, present};

/// The key register under which the PreSeed encrypts `key1` (HarpoS7 stores its round keys,
/// as `Transform1Data`).
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
    use hex_literal::hex;

    /// HarpoS7's `transform1` PreSeed vector output (`transform1-dst.bin`), decoded from its
    /// three-words-per-bit form with the original monolith chain before that was removed.
    /// `transform6` (SeedTransform) uses the same value as its pre-seed input.
    const HARPOS7_PRE_SEED: [u8; 20] = hex!("9267ec3b962cbb459267ec3b962cbb459267ec3b");

    #[test]
    fn pre_seed_matches_harpos7_transform1() {
        let key1 = include_bytes!("../../../tests/vectors/family0/transforms/transform1-src.bin");
        assert_eq!(pre_seed(key1), HARPOS7_PRE_SEED);
    }

    #[test]
    fn write_seed_matches_harpos7_transform6() {
        // transform6: StaticFillSequence = [0x2D] -> every fill is 0x2D.
        let public_key =
            include_bytes!("../../../tests/vectors/family0/transforms/transform6-publicKey.bin");
        let expected =
            include_bytes!("../../../tests/vectors/family0/transforms/transform6-dst.bin");

        let mut dst = [0u8; 0x3C];
        write_seed(&mut dst, public_key, &HARPOS7_PRE_SEED, &mut |b| {
            b.fill(0x2D)
        });
        assert_eq!(&dst[..], &expected[..]);
    }
}
