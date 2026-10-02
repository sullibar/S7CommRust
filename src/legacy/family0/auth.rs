// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Ported from `bonk-dev/HarpoS7` (MIT):
//   HarpoS7/Auth/LegacyAuthenticationScheme.cs  (AuthenticateRealPlc)
// See `LICENSE-HarpoS7`.

//! RealPlc (S7-1200/1500) auth orchestration.
//!
//! The full `AuthenticateRealPlc` assembles the 180-byte blob (`metadata + seed + IV +
//! enc-challenge + enc-key2 + checksum`) and derives the 24-byte session key, validated
//! byte-for-byte against HarpoS7's three `AuthenticateRealPlc` golden vectors and against 48
//! handshakes recorded from HarpoS7's original monolith implementation.
//!
//! The one RealPlc-vs-PLCSIM inversion to remember: the session key is derived from **key2**
//! (PLCSIM used key1). The KDF itself is identical — [`crate::legacy::keys::derive_session_key`].

use super::blob::{self, PublicKeyFamily, REALPLC_BLOB_LEN};
use super::{checksum, cipher, seed};
use crate::legacy::digest::SESSION_KEY_LEN;
use crate::legacy::keys::derive_session_key;

/// The RealPlc session key: `DeriveSessionKey(key2, challenge)`.
///
/// Keys the per-PDU integrity digest for the post-auth V3 PDUs, exactly as in the PLCSIM
/// path but with **key2** as the HMAC key.
pub fn real_plc_session_key(key2: &[u8], challenge: &[u8]) -> [u8; SESSION_KEY_LEN] {
    derive_session_key(key2, challenge)
}

/// `LegacyAuthenticationScheme.AuthenticateRealPlc`: build the 180-byte auth blob and derive
/// the 24-byte session key for a real S7-1200/1500.
///
/// `fill_random` supplies the ephemeral key material; it is invoked in exactly this order:
/// **key2(24), key1(24), IV(16), then (inside `SeedTransform`) prng1(20), prng2(20)** — a
/// CSPRNG in production, or a fixed cyclic sequence to reproduce the golden vectors.
pub fn authenticate_real_plc(
    blob_out: &mut [u8],
    session_key_out: &mut [u8],
    challenge: &[u8],
    public_key: &[u8],
    family: PublicKeyFamily,
    fill_random: &mut dyn FnMut(&mut [u8]),
) {
    assert!(blob_out.len() >= REALPLC_BLOB_LEN, "blob buffer too small");
    assert!(
        session_key_out.len() >= SESSION_KEY_LEN,
        "session key buffer too small"
    );

    let mut key2 = [0u8; 24];
    fill_random(&mut key2);
    let mut key1 = [0u8; 24];
    fill_random(&mut key1);
    let mut iv = [0u8; 16];
    fill_random(&mut iv);

    // Metadata (key-id from key2).
    blob::write_metadata(&mut blob_out[0..48], public_key, &key2, family);

    // ECDH-masked seed. PreSeed(key1) feeds both the seed and the AES-key derivation.
    let pre_seed = seed::pre_seed(&key1);
    seed::write_seed(&mut blob_out[48..108], public_key, &pre_seed, fill_random);
    let t2 = seed::derive_keys(&pre_seed);

    seal_body(blob_out, session_key_out, challenge, &key2, &iv, &t2);
}

/// Encrypt the blob body (IV, challenge, key2, checksum) under the derived keys `t2` and
/// write the session key.
fn seal_body(
    blob_out: &mut [u8],
    session_key_out: &mut [u8],
    challenge: &[u8],
    key2: &[u8; 24],
    iv: &[u8; 16],
    t2: &[u8; 48],
) {
    let challenge_key: [u8; 16] = t2[0..16].try_into().unwrap();
    let checksum_key: [u8; 16] = t2[16..32].try_into().unwrap();
    let mut lut = [0u8; checksum::LUT_LEN];
    checksum::generate_lut(&mut lut, &t2[32..48]);

    // IV + encrypted challenge + encrypted key2 + sealed checksum.
    cipher::encrypt_body(
        &mut blob_out[108..180],
        iv,
        key2,
        challenge,
        &challenge_key,
        &checksum_key,
        &lut,
    );

    session_key_out[..SESSION_KEY_LEN].copy_from_slice(&real_plc_session_key(key2, challenge));
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Session-key half of the AuthenticateRealPlc / FamilyOne golden vectors
    // (HarpoS7.Tests/Auth/LegacyAuthenticationSchemeTests.cs). In all three cases the
    // deterministic fill makes key2 = 0x35×24; only the challenge differs.
    const KEY2: [u8; 24] = [0x35; 24];

    #[test]
    fn session_key_s71500() {
        let challenge = [0xDDu8; 20];
        assert_eq!(
            real_plc_session_key(&KEY2, &challenge),
            hex!("65c4f179980a43cb60e1194ba500f5b9d04f374b56374866"),
        );
    }

    #[test]
    fn session_key_s71200_case1() {
        let challenge = hex!("5a5d5ab443551d9f2e680adfc44b163468e42736");
        assert_eq!(
            real_plc_session_key(&KEY2, &challenge),
            hex!("f18ce220f7ba175442cf1c4dddb59e82eafa62d5dd096e1a"),
        );
    }

    #[test]
    fn session_key_s71200_case2() {
        let challenge = hex!("45efcdabffeeddccbbaa998877665544332200 11");
        assert_eq!(
            real_plc_session_key(&KEY2, &challenge),
            hex!("27136b0919008c5cbec13529b77fdd2b905431a024167e54"),
        );
    }

    /// Cyclic fill closure mirroring HarpoS7's `SpanExtensions.StaticFillSequence`.
    fn cyclic(seq: &'static [u8]) -> impl FnMut(&mut [u8]) {
        let mut idx = 0usize;
        move |b: &mut [u8]| {
            b.fill(seq[idx % seq.len()]);
            idx += 1;
        }
    }

    fn check_auth(
        fill: &'static [u8],
        challenge: &[u8],
        public_key: &[u8],
        family: PublicKeyFamily,
        expected_blob: &[u8],
        expected_sk: &[u8],
    ) {
        let mut blob = [0u8; REALPLC_BLOB_LEN];
        let mut sk = [0u8; SESSION_KEY_LEN];
        let mut f = cyclic(fill);
        authenticate_real_plc(&mut blob, &mut sk, challenge, public_key, family, &mut f);
        assert_eq!(&blob[..], expected_blob, "blob mismatch");
        assert_eq!(&sk[..], expected_sk, "session key mismatch");
    }

    const PUB_1500: [u8; 40] =
        hex!("8456A26996122216C921C571FF11E0BEFAFDB1D70B5D4BC8390F5B0CC273EC142A03F2A04E6F1593");
    const PUB_1200: [u8; 40] =
        hex!("e0e1f04a5ca3f90148178689bd0c930ab9db867b4f0ab109623959aa32316b7880ed1b4f9a9b189f");

    #[test]
    fn authenticate_real_plc_s71500() {
        check_auth(
            &[0x35, 0x35, 0x25, 0x2D, 0x2D],
            &[0xDD; 20],
            &PUB_1500,
            PublicKeyFamily::S71500,
            include_bytes!("../../../tests/vectors/family0/auth/s71500-blob.bin"),
            include_bytes!("../../../tests/vectors/family0/auth/s71500-sk.bin"),
        );
    }

    #[test]
    fn authenticate_real_plc_s71200_a() {
        check_auth(
            &[0x35, 0x35, 0x25, 0x2D, 0x2D],
            &hex!("5a5d5ab443551d9f2e680adfc44b163468e42736"),
            &PUB_1200,
            PublicKeyFamily::S71200,
            include_bytes!("../../../tests/vectors/family0/auth/s71200a-blob.bin"),
            include_bytes!("../../../tests/vectors/family0/auth/s71200a-sk.bin"),
        );
    }

    #[test]
    fn authenticate_real_plc_s71200_b() {
        check_auth(
            &[0x35, 0x99, 0x25, 0x2D, 0x2D],
            &hex!("45efcdabffeeddccbbaa99887766554433220011"),
            &PUB_1200,
            PublicKeyFamily::S71200,
            include_bytes!("../../../tests/vectors/family0/auth/s71200b-blob.bin"),
            include_bytes!("../../../tests/vectors/family0/auth/s71200b-sk.bin"),
        );
    }

    /// SplitMix64: the deterministic fill used to generate `differential.txt`.
    struct SplitMix(u64);

    impl SplitMix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.next() as u8;
            }
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// 48 handshakes computed by HarpoS7's original monolith chain (Transform7, Monolith1..11,
    /// Transform12/13) before it was replaced: all 16 catalogue public keys plus random curve
    /// and twist x-coordinates, random challenges, and SplitMix64-seeded key material. Each line
    /// is `family fill_seed public_key challenge blob session_key`.
    #[test]
    fn matches_the_original_monolith_chain() {
        let fixture = include_str!("../../../tests/vectors/family0/differential.txt");
        let mut cases = 0;
        for line in fixture.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            let family = match f[0] {
                "1500" => PublicKeyFamily::S71500,
                _ => PublicKeyFamily::S71200,
            };
            let mut fill = SplitMix(u64::from_str_radix(f[1], 16).unwrap());
            let (mut blob, mut sk) = ([0u8; REALPLC_BLOB_LEN], [0u8; SESSION_KEY_LEN]);
            authenticate_real_plc(
                &mut blob,
                &mut sk,
                &unhex(f[3]),
                &unhex(f[2]),
                family,
                &mut |b| fill.fill(b),
            );
            assert_eq!(blob.to_vec(), unhex(f[4]), "blob, line {}", cases + 1);
            assert_eq!(sk.to_vec(), unhex(f[5]), "session key, line {}", cases + 1);
            cases += 1;
        }
        assert_eq!(cases, 48);
    }
}
