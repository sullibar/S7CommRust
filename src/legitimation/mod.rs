// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Legitimation/*, LGPL-3.0-or-later.

//! Legitimation (authentication).
//!
//! Both of the reference driver's schemes, chosen as it chooses them ([`scheme_for`]):
//!
//! * **New** (S7-1500 FW ≥ V3.1, S7-1200 FW ≥ V4.7, S7-1200 G2): fetch a challenge from
//!   `ServerSessionRequest` via `GetVarSubstreamed`, build a credentials [`PValue::Struct`],
//!   AES-256-CBC/PKCS7-encrypt it with `key = sha256(oms_secret)` and `iv = challenge[..16]`,
//!   then submit the ciphertext as a `Blob` to `Legitimate` via `SetVariable`. Each further
//!   legitimation on the same session hashes the previous key again (the reference "rolls" it).
//! * **Legacy** (S7-1500 FW V2.9–V3.0, S7-1200 FW V4.3–V4.6, software controllers): fetch the
//!   same challenge and submit `sha1(password) XOR challenge` as a USInt array to
//!   `ServerSessionResponse` ([`legacy_challenge_response`]).
//!
//! The flow is driven by [`crate::Connection::legitimate`]; this module provides the scheme
//! selection, the payload builder and the crypto.

pub mod crypto;

use crate::error::{Error, Result};
use crate::value::PValue;
use crate::wire::pdu::ids;

/// How a PLC wants to be legitimated (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegitimationScheme {
    /// `sha1(password) XOR challenge` to `ServerSessionResponse`; password only.
    Legacy,
    /// The AES-encrypted credentials payload to `Legitimate`; a username selects a user login.
    New,
}

/// Choose the legitimation scheme for a PLC from the description it gives of itself in its
/// `ServerSessionVersion` ([`crate::Connection::plc_description`], e.g.
/// `1;6ES7 214-1AG40-0XB0 ;V4.5`), as the reference driver's `legitimate` does:
///
/// | device (3 digits after a `1` or `7`) | firmware | scheme |
/// |---|---|---|
/// | S7-1500 (`5xx`) | < V2.9 | not supported |
/// | S7-1500 | V2.9 – V3.0 | legacy |
/// | S7-1500 | ≥ V3.1 | new |
/// | S7-1200 G2 (`2xx`, order number with `50-0XB0`) | any | new |
/// | S7-1200 (`2xx`) | < V4.3 | not supported |
/// | S7-1200 | V4.3 – V4.6 | legacy |
/// | S7-1200 | ≥ V4.7 | new |
/// | software controller (`6xx`) | < V21.9 | not supported |
/// | software controller | ≥ V21.9 | legacy |
///
/// Anything else, or a description that doesn't parse, is an error. The reference reads the
/// description with the regular expression `^[^;]*;[^;]*[17]\s?(\d{3}).*;[VS](\d{1,2}\.\d+)$`
/// (case-insensitive); this is the same match, written out.
pub fn scheme_for(description: &str) -> Result<LegitimationScheme> {
    let (device, firmware) = parse_description(description).ok_or_else(|| {
        Error::protocol(format!(
            "legitimation: can't tell the device and firmware from the PLC's description \
             '{description}'"
        ))
    })?;
    let unsupported = || {
        Err(Error::protocol(format!(
            "legitimation: firmware {}.{} of device {device} is not supported (description \
             '{description}')",
            firmware / 100,
            firmware % 100
        )))
    };
    match device.as_bytes()[0] {
        b'5' if firmware < 209 => unsupported(),
        b'5' if firmware < 301 => Ok(LegitimationScheme::Legacy),
        b'5' => Ok(LegitimationScheme::New),
        b'2' if description.contains("50-0XB0") => Ok(LegitimationScheme::New),
        b'2' if firmware < 403 => unsupported(),
        b'2' if firmware < 407 => Ok(LegitimationScheme::Legacy),
        b'2' => Ok(LegitimationScheme::New),
        b'6' if firmware < 2109 => unsupported(),
        b'6' => Ok(LegitimationScheme::Legacy),
        _ => Err(Error::protocol(format!(
            "legitimation: device {device} is not supported (description '{description}')"
        ))),
    }
}

/// The device number (three digits) and the firmware as `major * 100 + minor` from a PLC
/// description, matching the reference's regular expression (see [`scheme_for`]).
fn parse_description(description: &str) -> Option<(String, u32)> {
    let first = description.find(';')?;
    let last = description.rfind(';')?;
    if last == first {
        return None; // the device must be in the second field, before the last `;`
    }
    // `[^;]*` is greedy, so the device is the last match of `[17]\s?\d{3}` in the second field.
    let second = &description[first + 1..];
    let second = &second[..second.find(';')?];
    let chars: Vec<char> = second.chars().collect();
    let digits_at = |i: usize| -> Option<String> {
        let three: String = chars.get(i..i + 3)?.iter().collect();
        three.chars().all(|c| c.is_ascii_digit()).then_some(three)
    };
    let device = (0..chars.len()).rev().find_map(|i| {
        if !matches!(chars[i], '1' | '7') {
            return None;
        }
        // `\s?` is greedy too: a whitespace character is taken if the digits follow it.
        if chars.get(i + 1).is_some_and(|c| c.is_whitespace()) {
            if let Some(d) = digits_at(i + 2) {
                return Some(d);
            }
        }
        digits_at(i + 1)
    })?;
    // `[VS](\d{1,2}\.\d+)$` after the last `;`.
    let version = &description[last + 1..];
    let mut v = version.chars();
    if !matches!(v.next()?.to_ascii_uppercase(), 'V' | 'S') {
        return None;
    }
    let (major, minor) = v.as_str().split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if !digits(major) || major.len() > 2 || !digits(minor) {
        return None;
    }
    let firmware = major.parse::<u32>().ok()? * 100 + minor.parse::<u32>().ok()?;
    Some((device, firmware))
}

/// The legacy scheme's answer to `challenge`: `sha1(password) XOR challenge`, as the reference's
/// `legitimateLegacy` computes it. The challenge must be 20 bytes, the length of a SHA-1.
pub fn legacy_challenge_response(password: &str, challenge: &[u8]) -> Result<Vec<u8>> {
    // The hash is all the PLC checks, so it is as good as the password: wipe it after use.
    let hash = zeroize::Zeroizing::new(crypto::sha1(password.as_bytes()));
    if challenge.len() != hash.len() {
        return Err(Error::protocol(format!(
            "legacy legitimation: challenge of {} bytes, expected {}",
            challenge.len(),
            hash.len()
        )));
    }
    Ok(hash.iter().zip(challenge).map(|(h, c)| h ^ c).collect())
}

/// Legitimation method discriminator (`LegitimationType`).
pub mod legitimation_type {
    /// Legacy login (selected by an empty username).
    pub const LEGACY: u32 = 1;
    /// New (username + password) login.
    pub const NEW: u32 = 2;
}

/// Build the legitimation credentials payload (`buildLegitimationPayload`): a struct with
/// the legitimation type and username/password blobs.
///
/// Mirrors the reference exactly: an **empty username** selects the *legacy* login (type
/// `LEGACY`, password stored as its **SHA-1 hash** — the common "password for full access"
/// case); a **non-empty username** selects the *new* login (type `NEW`, plaintext UTF-8
/// username and password). Both forms are AES-encrypted by the caller for fw ≥ V3.1.
pub fn build_legitimation_payload(username: &str, password: &str) -> PValue {
    let (type_value, password_data) = if username.is_empty() {
        (
            legitimation_type::LEGACY,
            crypto::sha1(password.as_bytes()).to_vec(),
        )
    } else {
        (legitimation_type::NEW, password.as_bytes().to_vec())
    };

    PValue::Struct {
        id: ids::LID_LEGITIMATION_PAYLOAD_STRUCT,
        elements: vec![
            (
                ids::LID_LEGITIMATION_PAYLOAD_TYPE,
                PValue::UDInt(type_value),
            ),
            (
                ids::LID_LEGITIMATION_PAYLOAD_USERNAME,
                PValue::Blob {
                    root_id: 0,
                    data: username.as_bytes().to_vec(),
                },
            ),
            (
                ids::LID_LEGITIMATION_PAYLOAD_PASSWORD,
                PValue::Blob {
                    root_id: 0,
                    data: password_data,
                },
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_follows_the_reference_selection() {
        use LegitimationScheme::{Legacy, New};
        for (description, scheme) in [
            // The reference's own examples.
            ("1;6ES7 214-1AG40-0XB0 ;V4.5", Some(Legacy)),
            ("1;6ES7 510-1DJ01-0AB0;V2.9", Some(Legacy)),
            ("1;6ES7 672-7FC01-0YA0;V21.9", Some(Legacy)),
            ("1;6ES7 212-1HG50-0XB0;V1.0", Some(New)), // S7-1200 G2
            // The boundaries.
            ("1;6ES7 511-1AK02-0AB0;V2.8", None),
            ("1;6ES7 511-1AK02-0AB0;V3.0", Some(Legacy)),
            ("1;6ES7 511-1AK02-0AB0;V3.1", Some(New)),
            ("1;6ES7 215-1AG40-0XB0 ;V4.2", None),
            ("1;6ES7 215-1AG40-0XB0 ;V4.3", Some(Legacy)),
            ("1;6ES7 212-1AE40-0XB0 ;V4.6", Some(Legacy)),
            ("1;6ES7 212-1AE40-0XB0 ;V4.7", Some(New)),
            ("1;6ES7 672-7FC01-0YA0;V21.8", None),
            // PLCSIM Advanced: the 1500 behind "SIM-01500", firmware "S4.1".
            ("1;6ES7 SIM-01500-APLC;S4.1", Some(New)),
            ("1;6es7 511-1ak02-0ab0;v3.1", Some(New)),
            // Unknown devices and unreadable descriptions.
            ("1;6ES7 315-2EH14-0AB0;V3.2", None),
            ("1;6ES7 511-1AK02-0AB0", None),
            ("6ES7 511-1AK02-0AB0;V3.1", None),
            ("1;6ES7 511-1AK02-0AB0;V3.1a", None),
            ("1;6ES7 511-1AK02-0AB0;V123.1", None),
            ("", None),
        ] {
            assert_eq!(scheme_for(description).ok(), scheme, "{description:?}");
        }
    }

    #[test]
    fn the_device_is_the_last_match_in_the_second_field() {
        // `7 215` and `1 234` both match `[17]\s?\d{3}`; the greedy `[^;]*` takes the last.
        assert_eq!(
            parse_description("1;6ES7 215 1 234;V4.5"),
            Some(("234".into(), 405))
        );
        // A digit run after the last `;` isn't in the second field.
        assert_eq!(parse_description("1;X;7 511;V3.1"), None);
    }

    #[test]
    fn the_legacy_response_is_sha1_xor_challenge() {
        // sha1("secret") = e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4
        let challenge: Vec<u8> = (0u8..20).collect();
        let hash = crypto::sha1(b"secret");
        assert_eq!(
            hash,
            hex_literal::hex!("e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4")
        );
        let response = legacy_challenge_response("secret", &challenge).unwrap();
        let expected: Vec<u8> = hash.iter().zip(0u8..).map(|(h, i)| h ^ i).collect();
        assert_eq!(response, expected);
        assert_eq!(legacy_challenge_response("secret", &[0; 20]).unwrap(), hash);
        assert!(legacy_challenge_response("secret", &[0; 16]).is_err());
    }

    #[test]
    fn payload_serializes_to_struct() {
        let payload = build_legitimation_payload("user", "pw");
        let mut out = Vec::new();
        payload.serialize(&mut out).unwrap();
        // flags 00, datatype 0x17 (struct), struct id 40400 = 0x00009dd0 fixed.
        assert_eq!(&out[0..6], &[0x00, 0x17, 0x00, 0x00, 0x9d, 0xd0]);
        // ends with the struct terminator 0x00.
        assert_eq!(*out.last().unwrap(), 0x00);
    }

    #[test]
    fn empty_username_uses_legacy_type_and_sha1_password() {
        let payload = build_legitimation_payload("", "secret");
        match payload {
            PValue::Struct { id, elements } => {
                assert_eq!(id, ids::LID_LEGITIMATION_PAYLOAD_STRUCT);
                assert_eq!(elements[0].1, PValue::UDInt(legitimation_type::LEGACY));
                // Password element is the SHA-1 of the password (20 bytes), not plaintext.
                match &elements[2].1 {
                    PValue::Blob { data, .. } => {
                        assert_eq!(data.as_slice(), &crypto::sha1(b"secret")[..]);
                        assert_eq!(data.len(), 20);
                    }
                    other => panic!("expected Blob, got {other:?}"),
                }
            }
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    #[test]
    fn nonempty_username_uses_new_type_and_plaintext_password() {
        let payload = build_legitimation_payload("admin", "pw");
        if let PValue::Struct { elements, .. } = payload {
            assert_eq!(elements[0].1, PValue::UDInt(legitimation_type::NEW));
            assert_eq!(
                elements[2].1,
                PValue::Blob {
                    root_id: 0,
                    data: b"pw".to_vec()
                }
            );
        } else {
            panic!("expected Struct");
        }
    }
}
