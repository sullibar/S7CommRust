// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Ported from `bonk-dev/HarpoS7` (MIT):
//   HarpoS7.Utilities/Auth/BlobMetadataWriter.cs  (RealPlc family flags)
//   HarpoS7.Family0/Auth/RealPlcAuthenticator.cs  (WriteMetadata)
// See `LICENSE-HarpoS7`.

//! The RealPlc (S7-1200/1500) auth blob: metadata header + family flags.
//!
//! The full blob is 180 bytes, laid out as `metadata(48)`, `seed(60)`, `IV(16)`,
//! `enc-challenge(16)`, `enc-key2(16+8)`, `checksum(16)`. This module covers the metadata
//! header and the [`PublicKeyFamily`] flag table; the 60-byte EC seed is built in
//! [`super::seed`] and the encryption chain in [`super::auth`].
//!
//! Unlike the PLCSIM path ([`crate::legacy::blob`]), the metadata's symmetric key-id is
//! derived from **key2** (not key1), and the family flags encode S7-1500 (`00:`) vs
//! S7-1200 (`01:`) rather than VPLC (`03:`). Blob length is 180, not 216.

use crate::legacy::blob::derive_key_id;

/// Length of the full RealPlc encrypted-key blob (`EncryptedBlobLengthRealPlc`).
pub const REALPLC_BLOB_LEN: usize = 180;

/// The public-key family the PLC advertises via its fingerprint prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyFamily {
    /// S7-1500, fingerprint prefix `00:`.
    S71500,
    /// S7-1200, fingerprint prefix `01:`.
    S71200,
}

impl PublicKeyFamily {
    /// `GetSymmetricKeyFlags` — `KeyTypeSymmetricSessionKey | KeyFamily{Cpu1500,Cpu1200}`.
    fn symmetric_key_flags(self) -> u32 {
        match self {
            PublicKeyFamily::S71500 => 0x0001,
            PublicKeyFamily::S71200 => 0x0101,
        }
    }

    /// `GetPublicKeyFlags` — `KeyTypeCommPublicKey | KeyFamily{Cpu1500,Cpu1200}`.
    fn public_key_flags(self) -> u32 {
        match self {
            PublicKeyFamily::S71500 => 0x0010,
            PublicKeyFamily::S71200 => 0x0110,
        }
    }
}

/// Write the 48-byte RealPlc blob metadata header into `dest`. Returns the next writable
/// offset (always 48). The symmetric key-id is derived from `key2` (24 bytes); the public
/// key-id from the first 24 bytes of the 40-byte `public_key`.
pub fn write_metadata(
    dest: &mut [u8],
    public_key: &[u8],
    key2: &[u8],
    family: PublicKeyFamily,
) -> usize {
    dest[0..4].copy_from_slice(&0xFEE1_DEADu32.to_le_bytes());
    dest[4..8].copy_from_slice(&(REALPLC_BLOB_LEN as u32).to_le_bytes());
    dest[8..12].copy_from_slice(&1u32.to_le_bytes()); // security key version
    dest[12..16].copy_from_slice(&1u32.to_le_bytes()); // legacy CSI security level
    dest[16..24].copy_from_slice(&derive_key_id(key2)); // NOTE: key2, not key1
    dest[24..28].copy_from_slice(&family.symmetric_key_flags().to_le_bytes());
    dest[28..32].copy_from_slice(&0u32.to_le_bytes());
    dest[32..40].copy_from_slice(&derive_key_id(public_key));
    dest[40..44].copy_from_slice(&family.public_key_flags().to_le_bytes());
    dest[44..48].copy_from_slice(&0u32.to_le_bytes());
    48
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // The first 48 bytes of the AuthenticateRealPlc golden blobs
    // (HarpoS7.Tests/Auth/LegacyAuthenticationSchemeTests.cs, MIT). Deterministic fill
    // makes key2 = [0x35; 24] in all three cases.
    const KEY2: [u8; 24] = [0x35; 24];

    #[test]
    fn write_metadata_s71500_header() {
        // S71500 case: pubkey 0x8456A269…, expected metadata = first 48 B of the blob.
        let public_key = hex!(
            "8456A269961222 16C921C571FF11E0BEFAFDB1D70B5D4BC8390F5B0CC273EC142A03F2A04E6F1593"
        );
        let expected = hex!(
            "ADDEE1FE B4000000 01000000 01000000"
            "4E0C313B5E08E43B 01000000 00000000"
            "9416D147087B1B18 10000000 00000000"
        );
        let mut dest = [0u8; REALPLC_BLOB_LEN];
        let n = write_metadata(&mut dest, &public_key, &KEY2, PublicKeyFamily::S71500);
        assert_eq!(n, 48);
        assert_eq!(&dest[..48], &expected);
    }

    #[test]
    fn write_metadata_s71200_header() {
        // FamilyOne case: pubkey 0xE0E1F04A…, sym flags 0x0101, pub flags 0x0110.
        let public_key = hex!(
            "E0E1F04A5CA3F9014817 8689BD0C930AB9DB867B4F0AB109623959AA32316B7880ED1B4F9A9B189F"
        );
        let expected = hex!(
            "ADDEE1FE B4000000 01000000 01000000"
            "4E0C313B5E08E43B 01010000 00000000"
            "1A73081F096B42BD 10010000 00000000"
        );
        let mut dest = [0u8; REALPLC_BLOB_LEN];
        let n = write_metadata(&mut dest, &public_key, &KEY2, PublicKeyFamily::S71200);
        assert_eq!(n, 48);
        assert_eq!(&dest[..48], &expected);
    }
}
