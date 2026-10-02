// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from bonk-dev/HarpoS7 `HarpoS7/Auth/LegacyAuthenticationScheme.cs`
// (`AuthenticatePlcSim`), MIT, (c) 2024 bonk.

//! The PLCSIM-family legacy authentication: assemble the `SecurityKeyEncryptedKey` blob and
//! derive the session key that subsequently keys the per-PDU integrity digest.

use super::aes::HarpoAesCtr;
use super::digest::SESSION_KEY_LEN;
use super::{blob, keys, seed};

/// Build the 216-byte encrypted-key blob and derive the session key, given the PLC's public
/// key and the per-session `challenge` (attribute 303 from the `CreateObject` response).
///
/// `fill_random` supplies the ephemeral key material (a CSPRNG in production; a fixed pattern
/// in tests). It is invoked, in order, for `key1`, `key2`, the IV, and the seed scalar.
pub fn authenticate_plcsim(
    public_key: &[u8],
    challenge: &[u8],
    fill_random: &mut dyn FnMut(&mut [u8]),
) -> ([u8; blob::PLCSIM_BLOB_LEN], [u8; SESSION_KEY_LEN]) {
    let mut key1 = [0u8; SESSION_KEY_LEN];
    let mut key2 = [0u8; SESSION_KEY_LEN];
    fill_random(&mut key1);
    fill_random(&mut key2);

    let challenge_key = keys::derive_challenge_encryption_key(&key2);

    let mut iv = [0u8; 16];
    fill_random(&mut iv);

    let mut data = [0u8; blob::PLCSIM_BLOB_LEN];
    let mut idx = blob::write_metadata(&mut data, public_key, &key1); // 48

    let encrypted_seed = seed::generate_encrypted_seed(public_key, &challenge_key, fill_random)
        .expect("public key must be non-zero");
    data[idx..idx + 96].copy_from_slice(&encrypted_seed);
    idx += 96; // 144

    data[idx..idx + 16].copy_from_slice(&iv);
    idx += 16; // 160

    let mut aes = HarpoAesCtr::new(&challenge_key);
    aes.init(&iv);
    aes.encrypt_ctr(&challenge[2..18], &mut data[idx..idx + 16]);
    idx += 16; // 176
    aes.encrypt_ctr(&key1, &mut data[idx..idx + 24]);
    idx += 24; // 200
    aes.calculate_checksum(&mut data[idx..idx + 16]); // 200..216

    let session_key = keys::derive_session_key(&key1, challenge);
    (data, session_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // No PLCSIM auth vector exists in HarpoS7 (only the RealPlc path is unit-tested there),
    // so validate structure + self-consistency against the already-validated pieces.
    // The full blob's end-to-end check is the live PLC accepting it.
    #[test]
    fn authenticate_plcsim_structure() {
        let public_key = hex!(
            "eca6d799ddf03eaadd16b5d7245331e4"
            "26c9e6ba8997877a7394f3286532a6b0"
            "53e4229818085223432483fba4d5c43b"
            "d6c354c10febc903908ed271697f39e9"
        );
        let challenge = [0x5Au8; 20];
        let mut fill = |b: &mut [u8]| b.fill(0x33);

        let (data, session_key) = authenticate_plcsim(&public_key, &challenge, &mut fill);

        // Header.
        assert_eq!(
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            0xFEE1_DEAD
        );
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 216);
        assert_eq!(&data[16..24], &blob::derive_key_id(&[0x33; 24]));
        assert_eq!(&data[32..40], &blob::derive_key_id(&public_key));

        // Session key derives from key1 (all 0x33 under this fill) + the challenge.
        assert_eq!(
            session_key,
            keys::derive_session_key(&[0x33; 24], &challenge)
        );

        // Seed fragment matches a standalone generate_encrypted_seed with the same inputs.
        let challenge_key = keys::derive_challenge_encryption_key(&[0x33; 24]);
        let mut fill2 = |b: &mut [u8]| b.fill(0x33);
        let seed = seed::generate_encrypted_seed(&public_key, &challenge_key, &mut fill2).unwrap();
        assert_eq!(&data[48..144], &seed);
    }

    // Byte-exact oracle from HarpoS7 `AuthenticatePlcSim` (net8 harness, StaticFillSequence
    // [11 22 33 44] = key1/key2/iv/seed-l1, challenge 01..14, key B07654AC9CAA4ACA).
    #[test]
    fn plcsim_oracle_diff() {
        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{:02x}", x)).collect()
        }
        let public_key = hex!(
            "4700db8fa25d791c2a77eec9795d66e3"
            "b5f2ba9a59508add510ca9fe8762aa08"
            "1dff80ea8f730ad4caa0bca7ba92892c"
            "691984338eec2047681d958dc5c5086a"
        );
        let mut challenge = [0u8; 20];
        for (i, c) in challenge.iter_mut().enumerate() {
            *c = (i + 1) as u8;
        }
        let seq = [0x11u8, 0x22, 0x33, 0x44];
        let mut idx = 0usize;
        let mut fill = |b: &mut [u8]| {
            let v = seq[idx % seq.len()];
            idx += 1;
            b.fill(v);
        };
        let (data, sk) = authenticate_plcsim(&public_key, &challenge, &mut fill);

        let ref_blob = "addee1fed8000000010000000100000006ddcee4adaec77a0103000000000000ca4aaa9cac5476b010030000000000005b36890dacbd7c9a96bb74a1ee28b3d2d75b72e09a20ef25cf8e6fd8a9f0350d0e14bed8d4682a34d83538bdff5b96e89a6666ec0db5745d02fa1210072df75ac90ed3286983fa42ae5ab6c58e2d0ea02edc036bddea720a732d68721609c9133333333333333333333333333333333341dcc04b82d37983973e1c38b05cfbbc4afcb7e666edfc9a8655d781a799285652a6e4b933fe7d844b455a3cbb68eafe943146c941ed87e2";
        let ref_sk = "d4eb8a6cbcf1bbb1e39409dae3d24e61b8dd5afdf0663431";
        let refb: Vec<u8> = (0..ref_blob.len() / 2)
            .map(|i| u8::from_str_radix(&ref_blob[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        // Byte-exact against the HarpoS7 oracle: any drift fails the test. On mismatch,
        // report the first differing byte and which region of the blob it lands in.
        let first = (0..data.len().min(refb.len())).find(|&i| data[i] != refb[i]);
        let region = |i: usize| match i {
            0..=47 => "METADATA",
            48..=143 => "ENCRYPTED_SEED",
            144..=159 => "IV",
            160..=175 => "ENC(challenge[2..18])",
            176..=199 => "ENC(key1)",
            _ => "CHECKSUM",
        };
        assert_eq!(
            hx(&data),
            ref_blob,
            "auth blob mismatch: first diff at byte {:?} ({})",
            first,
            first.map(region).unwrap_or("length"),
        );
        assert_eq!(hx(&sk), ref_sk, "session-key mismatch");
    }
}
