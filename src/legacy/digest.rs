// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from bonk-dev/HarpoS7 `HarpoS7/Integrity/HarpoPacketDigest.cs` (MIT, (c) 2024 bonk).
// The chained response digests follow gijzelaerr/s7commplus `s7commplus/_fragment_hmac.py`
// (MIT; see LICENSE-gijzelaerr-s7commplus).

//! The per-PDU integrity digest for the legacy (non-TLS) dialect.
//!
//! Every S7CommPlus PDU after `CreateObject` carries `HMAC-SHA256(session_key[..24], data)`
//! over its data part. The PLC drops the connection on a missing or wrong digest. A response
//! the PLC splits into several chunks carries a digest on each, chained from one chunk to the
//! next (`ResponseDigests`).

use hmac::{Hmac, Mac};
use sha2::digest::generic_array::GenericArray;
use sha2::Sha256;

use crate::error::{Error, Result};

/// The derived session key is 24 bytes; those 24 bytes are the HMAC key.
pub const SESSION_KEY_LEN: usize = 24;
/// Length of an integrity digest — the full HMAC-SHA256 output.
pub const DIGEST_LEN: usize = 32;

/// Compute a PDU's integrity digest: `HMAC-SHA256(session_key[..24], data)` (32 bytes).
///
/// `data` is the S7CommPlus data part covered by the digest (i.e. excluding the 4-byte
/// `72 ver len` header, the digest field itself, and the trailer).
pub fn packet_digest(session_key: &[u8], data: &[u8]) -> Result<[u8; DIGEST_LEN]> {
    if session_key.len() < SESSION_KEY_LEN {
        return Err(Error::Crypto(format!(
            "session key must be at least {SESSION_KEY_LEN} bytes (got {})",
            session_key.len()
        )));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&session_key[..SESSION_KEY_LEN])
        .expect("HMAC accepts a key of any length");
    mac.update(data);
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&mac.finalize().into_bytes());
    Ok(digest)
}

/// Checks the digests of one response's chunks, in the order they arrive.
///
/// Only a response's first chunk carries a plain [`packet_digest`]. Later chunks carry a digest
/// chained from the previous one, but real devices use one of two dialects in the field:
///
/// * **State-resume** (PLCSIM Advanced, and real S7-1200/1500 e.g. FW 4.2): the PLC keeps using
///   its HMAC-SHA256 context after finalizing it, as if OpenSSL's `SHA256_Final` were followed
///   by more `SHA256_Update` calls: the inner and outer SHA-256 states resume from their previous
///   digests and their byte counts keep growing (Biham et al., *Rogue7*, 2019, §3.1).
/// * **Feed-forward** (real S7-1200/1500 e.g. FW 4.6): each later chunk's digest is a *fresh*
///   HMAC over the previous chunk's digest followed by this chunk's fragment,
///   `HMAC(key, digest_{n-1} || fragment_n)`.
///
/// Either way the chunks are chained, so none can be dropped, reordered, or spliced in from
/// another response. This verifier accepts whichever dialect the PLC uses, since both are keyed
/// MACs over the previous chunk.
pub(crate) struct ResponseDigests {
    inner: ChainedSha256,
    outer: ChainedSha256,
    key: [u8; SESSION_KEY_LEN],
    /// The previous chunk's digest, for the feed-forward dialect.
    last: [u8; DIGEST_LEN],
}

impl ResponseDigests {
    /// The digest state of a new response under `session_key` (its first 24 bytes).
    pub(crate) fn new(session_key: &[u8]) -> Result<Self> {
        let key = session_key.get(..SESSION_KEY_LEN).ok_or_else(|| {
            Error::Crypto(format!(
                "session key must be at least {SESSION_KEY_LEN} bytes (got {})",
                session_key.len()
            ))
        })?;
        let pad = |byte: u8| {
            let mut pad = [byte; 64];
            pad.iter_mut().zip(key).for_each(|(p, k)| *p ^= k);
            pad
        };
        Ok(ResponseDigests {
            inner: ChainedSha256::after_block(&pad(0x36)),
            outer: ChainedSha256::after_block(&pad(0x5c)),
            key: key.try_into().expect("SESSION_KEY_LEN bytes"),
            last: [0u8; DIGEST_LEN],
        })
    }

    /// Check the next chunk's `digest` over its `fragment`, accepting either chaining dialect.
    pub(crate) fn verify(&mut self, digest: &[u8], fragment: &[u8]) -> Result<()> {
        let inner = self.inner.finalize_and_continue(fragment);
        let chained = self.outer.finalize_and_continue(&inner);
        // Feed-forward: HMAC(key, previous_digest || fragment).
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key");
        mac.update(&self.last);
        mac.update(fragment);
        let fed = mac.finalize().into_bytes();
        // Constant time, as for any MAC check.
        let ok = |expected: &[u8]| {
            digest.len() == DIGEST_LEN
                && expected
                    .iter()
                    .zip(digest)
                    .fold(0, |acc, (a, b)| acc | (a ^ b))
                    == 0
        };
        if ok(&chained) || ok(&fed) {
            // `ok` only returns true when `digest` is exactly DIGEST_LEN, so this never truncates.
            self.last.copy_from_slice(&digest[..DIGEST_LEN]);
            return Ok(());
        }
        Err(Error::integrity(
            "legacy response digest mismatch: altered in transit, or not from this session",
        ))
    }
}

/// SHA-256 initial hash value (FIPS 180-4, §5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A SHA-256 state between `SHA256_Final` and the next `SHA256_Update` the way the PLC keeps
/// it: the chaining value, and the count of message bytes absorbed so far (padding excluded).
/// No partial block is buffered, since finalizing consumes it.
struct ChainedSha256 {
    state: [u32; 8],
    len: u64,
}

impl ChainedSha256 {
    /// The state after absorbing one 64-byte `block` (an HMAC pad) from the initial value.
    fn after_block(block: &[u8; 64]) -> Self {
        let mut state = SHA256_IV;
        sha2::compress256(&mut state, &[GenericArray::clone_from_slice(block)]);
        ChainedSha256 { state, len: 64 }
    }

    /// Absorb `data` and finalize, returning the digest, which also becomes the chaining value
    /// the next call resumes from. The padding is sized by `data` alone, since nothing is
    /// buffered, but its length field counts every byte absorbed so far.
    fn finalize_and_continue(&mut self, data: &[u8]) -> [u8; 32] {
        self.len += data.len() as u64;
        let padded_len = (data.len() + 1 + 8).div_ceil(64) * 64;
        let mut msg = Vec::with_capacity(padded_len);
        msg.extend_from_slice(data);
        msg.push(0x80);
        msg.resize(padded_len - 8, 0);
        msg.extend_from_slice(&(self.len * 8).to_be_bytes());
        let blocks: Vec<_> = msg
            .chunks_exact(64)
            .map(GenericArray::clone_from_slice)
            .collect();
        sha2::compress256(&mut self.state, &blocks);
        let mut digest = [0u8; 32];
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Golden vectors lifted verbatim from HarpoS7
    // `HarpoS7.Tests/Integrity/HarpoPacketDigestTests.cs` (MIT).
    #[test]
    fn matches_harpos7_vectors() {
        // Vector 1 (PLCSIM session key).
        assert_eq!(
            packet_digest(
                &hex!("a233875e3c7fc059c016128de590ab3c28bc04c277fa7c51"),
                &hex!(
                    "31 00 00 04 d4 00 00 00 03 70 40 00
                     00 34 70 40 00 00 00 00 00 04 e8 89
                     69 00 12 00 00 00 00 89 6a 00 13 00
                     89 6b 00 04 00 00 03 00 00 00 00"
                ),
            )
            .unwrap(),
            hex!("44e681f7e915bafa3b8c9eacb9d1f6bb47ebf1469c49c41efb6fc8156d35426a"),
        );

        // Vector 2.
        assert_eq!(
            packet_digest(
                &hex!("4eaf8d971ffcf45a995947cc06bff85b0a2df1ba6f3ae94d"),
                &hex!(
                    "31 00 00 04 d4 00 00 00 03 70 00 10
                     3d 34 70 00 10 3d 00 00 00 04 e8 89
                     69 00 12 00 00 00 00 89 6a 00 13 00
                     89 6b 00 04 00 00 03 00 00 00 00"
                ),
            )
            .unwrap(),
            hex!("30cb4a65de8a03c3a1a290537c23c6e36db12d9bbf3ccde1212c54ea421c5fc3"),
        );

        // Vector 3 (real-PLC session key — exercises the same HMAC).
        assert_eq!(
            packet_digest(
                &hex!("65c4f179980a43cb60e1194ba500f5b9d04f374b56374866"),
                &hex!(
                    "31 00 00 04 d4 00 00 00 03 70 00 10
                     3d 34 70 00 10 3d 00 00 00 04 e8 89
                     69 00 12 00 00 00 00 89 6a 00 13 00
                     89 6b 00 04 00 00 03 00 00 00 00"
                ),
            )
            .unwrap(),
            hex!("a8bb3f236afad6774f4487136d0055771422def8ea862a8c90d2d0b54b1951f1"),
        );
    }

    #[test]
    fn rejects_short_session_key() {
        assert!(packet_digest(&[0u8; 23], b"data").is_err());
        assert!(ResponseDigests::new(&[0u8; 23]).is_err());
    }

    /// A chunk's `(digest, fragment)`.
    type Chunk = ([u8; 32], Vec<u8>);

    /// A response's chunks: gijzelaerr/s7commplus's
    /// `legacy_fragment_hmac.json` (MIT), which that project generated with OpenSSL by calling
    /// `SHA256_Update` on its HMAC contexts again after `SHA256_Final`. The key `00 01 .. 17` and
    /// the fragment bytes `(i * 13 + size) % 256` are synthetic.
    fn openssl_chunks() -> (Vec<u8>, Vec<Chunk>) {
        #[rustfmt::skip]
        let vectors = [
            (976, hex!("fddc00b479d5a02c8d25fb7af591ebc4f7df0693b7b6a2348e8fc2635390ac13")),
            (976, hex!("a838a6d7ec24cfd6d9f4879bb57f42759075a909029b27c4f725903022798180")),
            (454, hex!("c551f7af6f3186dcca7ec4d0861e820afed3f86155f4d6dc1d42b707c9f2541b")),
            (55, hex!("89f37b0b5d1fbbb883df4c0ab7f37e959336685dd8644b1f1e4e03528218110b")),
            (56, hex!("755c7d5b46d547fcb908a2118e5cf64cd1db872c9b6e20c667844e751da9afa2")),
            (63, hex!("7f58e4ce028844dd880f99d8aae481c572fd9e0a9f3635ee28799e0a7761ff0c")),
            (64, hex!("a57dff6df1f2988d41d2ec58fd745722d325772e220dbeff3b5fd158227a18f9")),
            (65, hex!("797726ae7eda3b84783eb33034f7eb62130af2a6f71fb9f07aa81c0346888b9d")),
            (0, hex!("a445e1cf5260be0c2f15c62d54fe7998bf05bed1a5da17e4e258e5d0765b3894")),
        ];
        let key = (0..24).collect();
        let chunks = vectors
            .into_iter()
            .map(|(size, digest)| {
                (
                    digest,
                    (0..size).map(|i| ((i * 13 + size) % 256) as u8).collect(),
                )
            })
            .collect();
        (key, chunks)
    }

    #[test]
    fn chained_digests_match_openssl() {
        let (key, chunks) = openssl_chunks();
        let mut digests = ResponseDigests::new(&key).unwrap();
        for (digest, fragment) in &chunks {
            digests.verify(digest, fragment).unwrap();
        }
    }

    /// A real PLC (S7-1200 FW 4.6) chains continuation chunks as a *fresh* HMAC over the
    /// previous chunk's digest followed by the fragment — `HMAC(key, digest_{n-1} || frag)`.
    /// The verifier must accept that dialect too.
    #[test]
    fn feed_forward_dialect_is_verified_too() {
        let key = (0..24).collect::<Vec<u8>>();
        let frag_of = |lo: u32, hi: u32| (lo..hi).map(|i| (i * 13 % 256) as u8).collect::<Vec<_>>();
        // First chunk of a response: plain digest.
        let frag1 = frag_of(0, 300);
        let d1 = packet_digest(&key, &frag1).unwrap();
        // Continuation chunks: HMAC(key, prev_digest || fragment).
        let fed = |prev: &[u8], frag: &[u8]| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(prev);
            mac.update(frag);
            mac.finalize().into_bytes()
        };
        let frag2 = frag_of(100, 500);
        let d2 = fed(&d1, &frag2);
        let frag3 = frag_of(7, 60);
        let d3 = fed(&d2, &frag3);

        let mut digs = ResponseDigests::new(&key).unwrap();
        digs.verify(&d1, &frag1).unwrap();
        digs.verify(d2.as_slice(), &frag2).unwrap();
        digs.verify(d3.as_slice(), &frag3).unwrap();
    }

    /// A digest from the wrong dialect (state-resume where the PLC used feed-forward, or vice
    /// versa) is still rejected.
    #[test]
    fn wrong_dialect_is_rejected() {
        let key = (0..24).collect::<Vec<u8>>();
        let frag1: Vec<u8> = (0..300u32).map(|i| (i * 7 % 256) as u8).collect();
        let d1 = packet_digest(&key, &frag1).unwrap();
        let frag2: Vec<u8> = (100..500u32).map(|i| (i * 13 % 256) as u8).collect();
        // Feed-forward expects HMAC(key, d1 || frag2); give it the plain-over-frag2 digest.
        let plain2 = packet_digest(&key, &frag2).unwrap();
        let mut digs = ResponseDigests::new(&key).unwrap();
        digs.verify(&d1, &frag1).unwrap();
        assert!(matches!(
            digs.verify(&plain2, &frag2),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn first_chunk_digest_is_the_plain_packet_digest() {
        let (key, chunks) = openssl_chunks();
        let (digest, fragment) = &chunks[0];
        assert_eq!(&packet_digest(&key, fragment).unwrap(), digest);
    }

    #[test]
    fn corruption_of_any_chunk_is_rejected() {
        let (key, chunks) = openssl_chunks();
        // Verify the chunks before `bad`, then chunk `bad` after `corrupt`ing it.
        let check = |bad: usize, corrupt: fn(&mut [u8; 32], &mut Vec<u8>)| {
            let mut digests = ResponseDigests::new(&key).unwrap();
            for (digest, fragment) in &chunks[..bad] {
                digests.verify(digest, fragment).unwrap();
            }
            let (mut digest, mut fragment) = chunks[bad].clone();
            corrupt(&mut digest, &mut fragment);
            digests.verify(&digest, &fragment).unwrap_err()
        };
        for bad in 0..chunks.len() {
            let e = check(bad, |digest, _| digest[31] ^= 1);
            assert!(matches!(e, Error::Integrity(_)), "{e}");
            check(bad, |_, fragment| fragment.push(0));
        }
    }

    #[test]
    fn chunks_cannot_be_skipped_reordered_or_spliced() {
        let (key, chunks) = openssl_chunks();
        let mut digests = ResponseDigests::new(&key).unwrap();
        digests.verify(&chunks[0].0, &chunks[0].1).unwrap();
        assert!(
            digests.verify(&chunks[2].0, &chunks[2].1).is_err(),
            "skipped"
        );

        // Another response's first chunk carries a valid plain digest, but not a chained one.
        let mut digests = ResponseDigests::new(&key).unwrap();
        digests.verify(&chunks[0].0, &chunks[0].1).unwrap();
        let other = b"the first chunk of another response";
        let plain = packet_digest(&key, other).unwrap();
        assert!(digests.verify(&plain, other).is_err(), "spliced");

        // A continuation chunk can't open a response.
        let mut digests = ResponseDigests::new(&key).unwrap();
        assert!(
            digests.verify(&chunks[1].0, &chunks[1].1).is_err(),
            "out of order"
        );
    }

    #[test]
    fn wrong_key_or_digest_length_is_rejected() {
        let (key, chunks) = openssl_chunks();
        let mut digests = ResponseDigests::new(&[0x55; 24]).unwrap();
        assert!(digests.verify(&chunks[0].0, &chunks[0].1).is_err());
        let mut digests = ResponseDigests::new(&key).unwrap();
        assert!(digests.verify(&chunks[0].0[..31], &chunks[0].1).is_err());
    }

    #[test]
    fn chained_sha256_from_the_initial_value_is_plain_sha256() {
        use sha2::Digest;
        for size in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 976] {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let mut state = ChainedSha256 {
                state: SHA256_IV,
                len: 0,
            };
            assert_eq!(
                state.finalize_and_continue(&data),
                <[u8; 32]>::from(Sha256::digest(&data)),
                "size {size}"
            );
        }
    }
}
