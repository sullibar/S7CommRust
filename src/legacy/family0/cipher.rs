// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Ported from `bonk-dev/HarpoS7` (MIT):
//   HarpoS7.Family0/Auth/RealPlcAuthenticator.cs  (EncryptFullBlocks / EncryptFinalBlock)
// See `LICENSE-HarpoS7`.

//! The RealPlc blob-body cipher: the custom AES-128-ECB keystream + `RotateLeft31` IV chain
//! that encrypts `challenge[2..18]` and `key2`, sealed with a LUT/`ChecksumTransform` MAC.
//!
//! This is **not** standard CTR (and differs from the PLCSIM `HarpoAesCtr`): each block is
//! `AES-ECB(iv) ⊕ plaintext` with the IV advanced by [`advance_counter`] (HarpoS7's `RotateLeft31`) between
//! blocks, and a running checksum folded through [`super::checksum::checksum`] and finally
//! length-bound and AES-encrypted under a separate key.
//!
//! The three derived keys (`challenge_key`, `checksum_key`, `lut`) come from
//! [`super::seed::derive_keys`]`(pre_seed(key1))`; this module takes them as inputs so it can be
//! validated independently against the blob tail of the `AuthenticateRealPlc` golden vector.

use super::checksum;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

/// Length of the encrypted body this module writes for a 24-byte key2:
/// IV(16) + enc-challenge(16) + enc-key2-block(16) + enc-key2-tail(8) + checksum(16).
pub const BODY_LEN: usize = 72;

fn aes_ecb_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut b = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

/// `_checksum ^= ct; _checksum = ChecksumTransform(_checksum, lut)` — one running-MAC fold.
fn update_checksum(cs: &mut [u8; 16], ct: &[u8; 16], lut: &[u8]) {
    for (c, &t) in cs.iter_mut().zip(ct.iter()) {
        *c ^= t;
    }
    let key = *cs;
    checksum::checksum(cs, &key, lut);
}

/// Encrypt the blob body into `dst` (must be ≥ [`BODY_LEN`]). Mirrors `EncryptFullBlocks`
/// followed by `EncryptFinalBlock` for a 24-byte `key2`. Returns the number of bytes written.
///
/// - `iv`: the 16-byte starting IV (copied out verbatim, then rotated for the keystream).
/// - `key2`: 24 bytes (the key the blob transports; the PLC recovers it).
/// - `challenge`: the PLC's challenge; bytes `[2..18]` are encrypted.
/// - `challenge_key` / `checksum_key`: the two AES-128 keys from `KeyDerivationTransform`.
/// - `lut`: the 4 KiB checksum table from [`super::checksum::generate_lut`].
pub fn encrypt_body(
    dst: &mut [u8],
    iv: &[u8; 16],
    key2: &[u8],
    challenge: &[u8],
    challenge_key: &[u8; 16],
    checksum_key: &[u8; 16],
    lut: &[u8],
) -> usize {
    assert!(dst.len() >= BODY_LEN, "cipher dst too small");
    assert!(key2.len() == 24, "this cipher path assumes a 24-byte key2");
    assert!(challenge.len() >= 18, "challenge too short");

    // Running checksum seeded from the ORIGINAL IV (WriteSeed: ChecksumTransform(_checksum, _iv, lut)).
    let mut cs = [0u8; 16];
    checksum::checksum(&mut cs, iv, lut);

    let mut iv_state = *iv;
    let mut off = 0;

    // Region C: copy the starting IV verbatim.
    dst[off..off + 16].copy_from_slice(&iv_state);
    off += 16;

    let mut encrypted_bytes: u32 = 0;

    // Region D: encrypt challenge[2..18].
    let mut ct = aes_ecb_block(challenge_key, &iv_state);
    for (c, &m) in ct.iter_mut().zip(challenge[2..18].iter()) {
        *c ^= m;
    }
    dst[off..off + 16].copy_from_slice(&ct);
    off += 16;
    encrypted_bytes += 16;
    advance_counter(&mut iv_state);
    update_checksum(&mut cs, &ct, lut);

    // Region E: encrypt full 16-byte blocks of key2 (one block for 24-byte key2).
    for chunk in key2.chunks_exact(16) {
        let mut ct = aes_ecb_block(challenge_key, &iv_state);
        for (c, &m) in ct.iter_mut().zip(chunk.iter()) {
            *c ^= m;
        }
        dst[off..off + 16].copy_from_slice(&ct);
        off += 16;
        encrypted_bytes += 16;
        advance_counter(&mut iv_state);
        update_checksum(&mut cs, &ct, lut);
    }

    // Region F: the partial final key2 block + the sealed checksum.
    let leftover = key2.len() % 16; // 8
    let start = key2.len() - leftover; // 16
    let mut ct = aes_ecb_block(challenge_key, &iv_state);
    for (c, &m) in ct[..leftover].iter_mut().zip(key2[start..].iter()) {
        *c ^= m;
    }
    dst[off..off + leftover].copy_from_slice(&ct[..leftover]);
    off += leftover;
    encrypted_bytes += leftover as u32; // now 40

    // Fold the zero-padded final block, then length-bind and seal.
    ct[leftover..].fill(0);
    update_checksum(&mut cs, &ct, lut);

    let cs3 = u32::from_le_bytes(cs[12..16].try_into().unwrap()) ^ encrypted_bytes;
    cs[12..16].copy_from_slice(&cs3.to_le_bytes());

    let key = cs;
    checksum::checksum(&mut cs, &key, lut);

    let mac = aes_ecb_block(checksum_key, &cs);
    dst[off..off + 16].copy_from_slice(&mac);
    off += 16;
    off
}

/// Advance the counter block: multiply the little-endian 128-bit value by `x` in GCM's
/// bit-reflected field (HarpoS7 calls this `BigIntOperations.RotateLeft31`).
fn advance_counter(iv: &mut [u8; 16]) {
    let v = u128::from_le_bytes(*iv);
    *iv = ((v >> 1) ^ if v & 1 == 1 { 0xE1 << 120 } else { 0 }).to_le_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_counter_multiplies_by_x_in_gcm_field() {
        // Bit-reflected: a set low bit shifts out and folds back as 0xE1 in the top byte.
        let mut iv = 1u128.to_le_bytes();
        advance_counter(&mut iv);
        assert_eq!(u128::from_le_bytes(iv), 0xE1 << 120);
        let mut iv = 0x8000_0000_0000_0000_0000_0000_0000_0002u128.to_le_bytes();
        advance_counter(&mut iv);
        assert_eq!(
            u128::from_le_bytes(iv),
            0x4000_0000_0000_0000_0000_0000_0000_0001
        );
    }
    use crate::legacy::family0::checksum::{generate_lut, LUT_LEN};
    use hex_literal::hex;

    // The S71500 AuthenticateRealPlc golden blob (LegacyAuthenticationSchemeTests.cs) with the
    // deterministic fill: key2 = 0x35×24, iv = 0x25×16, challenge = 0xDD×20. The three derived
    // keys are dumped from KeyDerivationTransform(PreSeed(key1=0x35×24)) via the .NET oracle.
    // Expected = blob bytes [0x6C..0xB4].
    #[test]
    fn encrypt_body_matches_s71500_blob_tail() {
        let iv = [0x25u8; 16];
        let key2 = [0x35u8; 24];
        let challenge = [0xDDu8; 20];
        let challenge_key = hex!("df85fc2e31ed70c4672f07350a02b768");
        let checksum_key = hex!("410755938896af2583a90fdf0f9e1bee");
        let lut_seed = hex!("0ddf4f10a200874232887bf3225736ce");

        let mut lut = [0u8; LUT_LEN];
        generate_lut(&mut lut, &lut_seed);

        let expected = hex!(
            "25252525252525252525252525252525" // IV
            "05c6087cf782dba39e21bafa8f31b324" // enc challenge[2..18]
            "bf5800164bbc3dde0d15d69db76546f4" // enc key2[0..16]
            "491ca34fef12f959"                 // enc key2[16..24]
            "ec900f005f36dd389040761ef2b856d6" // sealed checksum
        );

        let mut dst = [0u8; BODY_LEN];
        let n = encrypt_body(
            &mut dst,
            &iv,
            &key2,
            &challenge,
            &challenge_key,
            &checksum_key,
            &lut,
        );
        assert_eq!(n, BODY_LEN);
        assert_eq!(&dst[..], &expected[..]);
    }
}
