// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Replaces the port of `bonk-dev/HarpoS7` (MIT) `HarpoS7/Fingerprint/HarpoFingerprint.cs`.
// The network and every constant below were recovered from HarpoS7's white-box gate network in
// `gijzelaerr/s7commplus` (`s7commplus/v1_session_key/real_plc/fingerprint.py`, MIT).
// See `LICENSE-HarpoS7` and `LICENSE-gijzelaerr-s7commplus`.

//! The `f()` challenge fingerprint: 8 bytes derived from `challenge[2..18]`, one input to the
//! legacy session-key derivation ([`super::keys`]).
//!
//! HarpoS7 computes it with a white-boxed network of 496 nibble lookup gates. Underneath the
//! encodings it is a fixed-key substitution-permutation network on AES's inverse S-box. Write
//! `crumb(v, j)` for bits `j` and `j + 4` of byte `v` as a 2-bit value; then
//!
//! 1. `y = InvSubBytes(challenge[2..18] ^ INPUT_KEY)` (16 bytes);
//! 2. the 8-byte state is `y[0..8] ^ y[8..16]`;
//! 3. each of 13 rounds replaces every state byte with `InvSbox(w ^ key)`, where `w` holds
//!    crumb `j` of four source bytes (the first in bits 0–1);
//! 4. each output nibble is a fixed 4-bit encoding of crumb `j` of two state bytes.

pub const FINGERPRINT_LEN: usize = 8;

/// AES's inverse S-box.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const INPUT_KEY: [u8; 16] = [
    0x84, 0xbf, 0x37, 0xe0, 0x56, 0xaf, 0x42, 0x11, 0x91, 0x57, 0x9e, 0xbc, 0x64, 0x1c, 0x9f, 0xb3,
];

/// Per round, the key byte of each of the 8 S-boxes.
const ROUND_KEYS: [[u8; 8]; 13] = [
    [0x3b, 0xe4, 0xb2, 0x5d, 0x87, 0xbc, 0xc3, 0xdb],
    [0xad, 0x4c, 0x46, 0x0f, 0x73, 0x24, 0xd5, 0xcf],
    [0x64, 0x3e, 0xe2, 0x5f, 0x38, 0x92, 0xb8, 0x0e],
    [0xd3, 0x52, 0xfe, 0x09, 0xba, 0x33, 0x0d, 0xea],
    [0x25, 0x25, 0xc6, 0xa8, 0x27, 0xce, 0xe5, 0x5b],
    [0x71, 0xf7, 0xc2, 0x62, 0xb6, 0x0c, 0x09, 0x00],
    [0x54, 0xf7, 0x22, 0x9e, 0xba, 0x99, 0xcb, 0xc6],
    [0x40, 0xa2, 0xf2, 0xca, 0xd7, 0xbf, 0xe2, 0x9d],
    [0xbd, 0xa9, 0x45, 0xcd, 0x3d, 0x9b, 0xee, 0xf6],
    [0xd2, 0xa3, 0x71, 0x7b, 0x0e, 0xe1, 0xb5, 0xa4],
    [0xda, 0xa4, 0x65, 0xfa, 0x78, 0xe7, 0x49, 0xe0],
    [0x76, 0x00, 0x32, 0x97, 0x83, 0xca, 0x7c, 0xfe],
    [0xfe, 0x52, 0x40, 0x52, 0x9c, 0x64, 0xdf, 0xd6],
];

/// Per round, for each new state byte: `(crumb j, [four source bytes, low crumb first])`.
#[rustfmt::skip]
const ROUND_WIRING: [[(u8, [u8; 4]); 8]; 13] = [
    [(1, [7, 6, 5, 4]), (0, [3, 2, 1, 0]), (0, [7, 6, 5, 4]), (1, [3, 2, 1, 0]), (2, [7, 6, 5, 4]), (2, [3, 2, 1, 0]), (3, [7, 6, 5, 4]), (3, [3, 2, 1, 0])],
    [(2, [2, 1, 0, 3]), (3, [2, 1, 0, 3]), (1, [2, 1, 0, 3]), (0, [2, 1, 0, 3]), (2, [4, 5, 6, 7]), (3, [4, 5, 6, 7]), (1, [4, 5, 6, 7]), (0, [4, 5, 6, 7])],
    [(3, [0, 4, 1, 5]), (2, [0, 4, 1, 5]), (0, [0, 4, 1, 5]), (1, [0, 4, 1, 5]), (3, [3, 7, 2, 6]), (2, [3, 7, 2, 6]), (0, [3, 7, 2, 6]), (1, [3, 7, 2, 6])],
    [(2, [5, 1, 4, 0]), (1, [5, 1, 4, 0]), (0, [5, 1, 4, 0]), (3, [5, 1, 4, 0]), (2, [6, 2, 7, 3]), (3, [6, 2, 7, 3]), (1, [6, 2, 7, 3]), (0, [6, 2, 7, 3])],
    [(3, [4, 0, 5, 3]), (2, [4, 0, 5, 3]), (1, [4, 0, 5, 3]), (0, [4, 0, 5, 3]), (0, [7, 2, 6, 1]), (1, [7, 2, 6, 1]), (3, [7, 2, 6, 1]), (2, [7, 2, 6, 1])],
    [(1, [4, 3, 5, 2]), (3, [4, 3, 5, 2]), (0, [4, 3, 5, 2]), (2, [4, 3, 5, 2]), (2, [7, 1, 6, 0]), (0, [7, 1, 6, 0]), (1, [7, 1, 6, 0]), (3, [7, 1, 6, 0])],
    [(0, [3, 4, 1, 7]), (2, [2, 5, 0, 6]), (3, [2, 5, 0, 6]), (2, [3, 4, 1, 7]), (1, [3, 4, 1, 7]), (3, [3, 4, 1, 7]), (1, [2, 5, 0, 6]), (0, [2, 5, 0, 6])],
    [(3, [1, 3, 2, 5]), (2, [1, 3, 2, 5]), (0, [1, 3, 2, 5]), (2, [7, 0, 6, 4]), (1, [1, 3, 2, 5]), (0, [7, 0, 6, 4]), (1, [7, 0, 6, 4]), (3, [7, 0, 6, 4])],
    [(0, [5, 2, 6, 4]), (1, [3, 1, 7, 0]), (1, [5, 2, 6, 4]), (3, [3, 1, 7, 0]), (2, [5, 2, 6, 4]), (2, [3, 1, 7, 0]), (3, [5, 2, 6, 4]), (0, [3, 1, 7, 0])],
    [(2, [0, 7, 2, 1]), (0, [4, 5, 6, 3]), (3, [0, 7, 2, 1]), (1, [4, 5, 6, 3]), (3, [4, 5, 6, 3]), (1, [0, 7, 2, 1]), (2, [4, 5, 6, 3]), (0, [0, 7, 2, 1])],
    [(2, [0, 6, 2, 4]), (3, [0, 6, 2, 4]), (0, [0, 6, 2, 4]), (3, [7, 1, 5, 3]), (2, [7, 1, 5, 3]), (1, [7, 1, 5, 3]), (1, [0, 6, 2, 4]), (0, [7, 1, 5, 3])],
    [(3, [4, 0, 3, 1]), (0, [4, 0, 3, 1]), (2, [4, 0, 3, 1]), (1, [7, 2, 5, 6]), (2, [7, 2, 5, 6]), (0, [7, 2, 5, 6]), (3, [7, 2, 5, 6]), (1, [4, 0, 3, 1])],
    [(3, [4, 2, 6, 0]), (1, [4, 2, 6, 0]), (2, [5, 1, 3, 7]), (2, [4, 2, 6, 0]), (0, [4, 2, 6, 0]), (1, [5, 1, 3, 7]), (3, [5, 1, 3, 7]), (0, [5, 1, 3, 7])],
];

/// For each output nibble, most significant first: `(crumb j, byte a, byte b)`.
#[rustfmt::skip]
const OUTPUT_CRUMBS: [(u8, u8, u8); 16] = [
    (3, 0, 6), (3, 3, 2), (3, 1, 5), (3, 4, 7), (2, 0, 6), (2, 3, 2), (2, 1, 5), (2, 4, 7),
    (1, 0, 6), (1, 3, 2), (1, 1, 5), (1, 4, 7), (0, 0, 6), (0, 3, 2), (0, 1, 5), (0, 4, 7),
];

/// For each output nibble, its value for each of the 16 crumb pairs (`a` in bits 0–1), as one
/// hex digit per entry.
const OUTPUT_ENCODING: [&[u8; 16]; 16] = [
    b"39fc6a4710bed285",
    b"d3e086192cb475fa",
    b"4813eb0752dfa9c6",
    b"8f5ac7219d406e3b",
    b"16d9f3e4ab25c870",
    b"687c139af052dbe4",
    b"5cb2ad73680e49f1",
    b"d9a42f187b65e03c",
    b"1c3e92d587bfa406",
    b"218bd470a3cfe659",
    b"14af6dbe970c5832",
    b"2085fde91ca376b4",
    b"f2d5a8961be3c704",
    b"814e0635d9cf7ab2",
    b"3ec4715b2680fad9",
    b"e87d946c2a5b03f1",
];

/// Bits `j` and `j + 4` of `v`, as a 2-bit value.
fn crumb(v: u8, j: u8) -> u8 {
    (v >> j) & 1 | ((v >> (j + 4)) & 1) << 1
}

fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

/// Compute `f(challenge)` from `challenge[2..18]`. `challenge` must be at least 18 bytes.
pub fn fingerprint_challenge(challenge: &[u8]) -> [u8; FINGERPRINT_LEN] {
    assert!(challenge.len() >= 18, "challenge must be at least 18 bytes");
    let mut y = [0u8; 16];
    for (i, slot) in y.iter_mut().enumerate() {
        *slot = INV_SBOX[(challenge[2 + i] ^ INPUT_KEY[i]) as usize];
    }
    let mut state = [0u8; 8];
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = y[i] ^ y[i + 8];
    }
    for (keys, wiring) in ROUND_KEYS.iter().zip(&ROUND_WIRING) {
        let mut next = [0u8; 8];
        for ((slot, &key), &(j, sources)) in next.iter_mut().zip(keys).zip(wiring) {
            let w = sources
                .iter()
                .enumerate()
                .fold(0u8, |w, (k, &s)| w | crumb(state[s as usize], j) << (2 * k));
            *slot = INV_SBOX[(w ^ key) as usize];
        }
        state = next;
    }
    let nibble = |n: usize| {
        let (j, a, b) = OUTPUT_CRUMBS[n];
        let index = crumb(state[a as usize], j) | crumb(state[b as usize], j) << 2;
        hex_digit(OUTPUT_ENCODING[n][index as usize])
    };
    let mut out = [0u8; FINGERPRINT_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = nibble(2 * i) << 4 | nibble(2 * i + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn matches_harpos7_golden_vector() {
        // HarpoS7 `HarpoFingerprintTests.FingerprintChallenge` (MIT).
        let challenge: [u8; 20] = [
            184, 13, 177, 179, 217, 72, 76, 110, 66, 64, 64, 63, 99, 198, 181, 1, 44, 197, 46, 127,
        ];
        assert_eq!(
            fingerprint_challenge(&challenge),
            [0xe2, 0x87, 0xc1, 0xcb, 0x65, 0x9b, 0x9e, 0xdf],
        );
    }

    #[test]
    fn inverse_sbox_is_aes() {
        // Spot checks against FIPS-197: InvSbox(0x00) = 0x52, InvSbox(0x63) = 0x00 (S(0) = 0x63).
        assert_eq!(INV_SBOX[0x00], 0x52);
        assert_eq!(INV_SBOX[0x63], 0x00);
        let mut seen = [false; 256];
        for &v in &INV_SBOX {
            seen[v as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "not a permutation");
    }

    /// `(challenge[2..18], f(challenge))` pairs computed by the port of HarpoS7's white-box
    /// gate network before it was replaced (which matched this network on all 19,689 of 20,000
    /// random challenges it could evaluate; it failed on the rest, which this network handles
    /// and which PLCSIM accepted in live tests).
    #[rustfmt::skip]
    const HARPOS7_PORT_VECTORS: [(&str, &str); 64] = [
        ("5000162e0128cef80f60d6e157e3c734", "7b33715d681c8b80"),
        ("afa8dd985545c16a24a7f6bdb9730a48", "39e45677dece33b5"),
        ("2d38b642dd5d1f27895d3c4a0d03a203", "ba5de4a01d4b3182"),
        ("b87bfaafcc4165a7e7b15efa8449e4d9", "9273ee3f728df8ef"),
        ("30f067416f81b3232ab50dc40e8860e7", "84ecc0cac1f31550"),
        ("d5915ced5612b4c244944bbd5516e1e6", "144f9f641543a000"),
        ("5fba57597c98b29d431df65f141a5499", "51bec4b52629e685"),
        ("182d7d08177676fbbda3a987dd5f0828", "47429f42e8797ef4"),
        ("fa98ca3b9957e1307211d2467010c9ab", "eba4bece19a46a70"),
        ("086a6d3549e6ff021985d096fde1e047", "c8b424a2d4cf84db"),
        ("7757a24ec11f175cae894a014f7f4d34", "76443cccf9634354"),
        ("c16fb3e5b6783a9d7326218749c0b878", "a682a27664ec579f"),
        ("090fc2a07b23c6a3bf99ecf851d0283a", "29d3a03db36fc646"),
        ("e01624a6e83686ec750bb13600c2b09c", "1bbe25072eed26b7"),
        ("75d771352aa3155bf2a8e54eb90e019e", "f0a18b8c94cea601"),
        ("91e5417b059f3539caacf8de379cecd5", "eb85d0fc5fd17a2d"),
        ("5175e1664751b794593a0aa5aace4e9f", "5fffac0f377ca6f6"),
        ("92aceb8f5cd47715c4448201ed704739", "d638cbd5843bc8b0"),
        ("2490585583b30e984224e045dd012eb8", "30ad31922177d8fd"),
        ("06685d40719a41b3bf24392048dbd7f6", "0b9167d1fa7e997b"),
        ("654066c1de3af410e2ccbb085a1a8c43", "8b921eba384de171"),
        ("d27cb482ac6c2addc8f6780c626ce8f9", "210c2d739be9c1b7"),
        ("7e73fd2f3161a8c45e0c2fbe1f1e03de", "be13ea6cff279d98"),
        ("33140fb20acc534ab212b0970a6b2875", "1b63616822871635"),
        ("18a46178f2804b581560a23eaac24cc1", "4246fbcd144f3491"),
        ("aa5e3a9ef105fac0f6d5d46511ede50f", "d2657156d1571d69"),
        ("f5a1a4269d7a0115bc399ee04e02a80a", "4e9319e03c350c5e"),
        ("55db6bca32258f72bb74ca1a167922c1", "648ae0fef48cd7c1"),
        ("37cf4b46ad721748930e3f21bef4f4f2", "d682f3b8bd6c76fe"),
        ("a9caefe9d5e9205f391956a771d37f09", "5f1e9f6893c404ae"),
        ("039995b58aebddc93947696480ae99f3", "3e7be5d602d38baa"),
        ("d89c704a379588bcde78408975abe19a", "ce89e03480a4088a"),
        ("7dd43160a2b70f32223ef09484b1d3ef", "e017a898adb0a031"),
        ("8571de3b2b550293a5ab2e82c38eb7fc", "cada35e02fe3a2b8"),
        ("3bb11b364dbca236f2996f50d4503b82", "04fe30feab423942"),
        ("4d7466b36ab95a181d5834748fb0d2eb", "ed5b5c7a1d86b152"),
        ("e990f06af3db56c27f9daedfb43a2be1", "71e089de1ef1be3a"),
        ("6be7abd1c47b76da7ab09784f41b2ec0", "4716bb38ec8cb899"),
        ("2d1c7114c779a0998fc39dcdf36abc84", "67630a209f03f1f8"),
        ("fcbc92fd0c69cc5692e4ded74c236546", "66ec7514580ed1bd"),
        ("d82d467d70d0e321557d0eed2263dcbb", "ad81eee2014fd859"),
        ("89a9aff3abc20ab06b3b3738dd7ad567", "e553b58640759f2a"),
        ("fa25cd39749486e3bc6c2bcc93be6ee9", "4e42c374b2f5d28b"),
        ("5e50c92921ca59bc0ae152a78cca8064", "f149961a81dc5b0d"),
        ("6adc20c760cb34bddc05c68ef6638a5c", "e790b63dfb01a702"),
        ("2aed08ad159ff077d512ba5f3ed53ab5", "89fe50b583ffc509"),
        ("36cb22077c8172a8dd05880e5b39955d", "7dc9ab460795e5a2"),
        ("62148f670032fe3ad69051eb970067c6", "d3bc64087ec7efdf"),
        ("6614d435696a435c96aef8f3717826c9", "dd5b2a2be4c5293b"),
        ("1beb80a535547e302f2e015bccd3768e", "3592e28be0673bf1"),
        ("163fdd6c3aade11ac463293d90da2cdf", "5dd62cb749d6f307"),
        ("f7a8e80a360569ce1871738f27974bef", "5f76fc08ec88b637"),
        ("72f468d44911d2ba4d829fba945adc28", "59a53f268c280da6"),
        ("6f3cbcfd484cdf57180a2bbc3a44420b", "2809c9338e7431b4"),
        ("e7af7a0ea312287527833e0cab223048", "e39beff102852f4d"),
        ("1922ba40885e2612d4b376e6abf79ad5", "00110e6d8b2840a0"),
        ("a899dc0a8cfd3e29486e24483e14d672", "b70c081ee3cace12"),
        ("f73be367198400f07526647546c0b6fd", "961aae8c11f3c3d7"),
        ("67c202ccf6a9650c8ab68e32f0c4261c", "7e40c44a11a9e3e2"),
        ("a7ae5e9f8c14d88475efa2d456f54347", "3cd8db43936c2fbf"),
        ("3b4ee07887c71520cf9f5629c42d1200", "9b86f333bde8c394"),
        ("3524a6611a576c4fcdb3c9faab4ae829", "03bf1d30a8e1688b"),
        ("7c74056a6437075b1374233418f235ea", "2c7c2b39143ad516"),
        ("50040001ccc34ae4dfaaeeb1312a0de9", "05eb8a495a36dd51"),
    ];

    #[test]
    fn matches_the_harpos7_gate_network() {
        for (input, expected) in HARPOS7_PORT_VECTORS {
            let mut challenge = [0u8; 20];
            challenge[2..18].copy_from_slice(&unhex::<16>(input));
            assert_eq!(
                fingerprint_challenge(&challenge),
                unhex::<8>(expected),
                "{input}"
            );
        }
    }
}
