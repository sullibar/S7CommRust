// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// The RealPlc (families 00:/01:) legacy handshake. Auth crypto ported from bonk-dev/HarpoS7
// (`LegacyAuthenticationScheme.AuthenticateRealPlc`); the auth `SetMultiVariables` request
// templates + patch offsets are from HarpoS7's PoC (`SetMultiVarsRequest`), MIT.

//! Legacy non-TLS handshake for **real** S7-1200/1500 hardware (public-key families `00:` /
//! `01:`), the counterpart to the family-`03:` PLCSIM path in [`crate::legacy::session`].
//!
//! The flow mirrors PLCSIM — plaintext `CreateObject`, then a challenge-response auth carrying
//! the 180-byte encrypted-key blob, after which every PDU is a ProtocolVersion-`0x03` frame with
//! the HMAC-SHA256 digest (shared transport in [`crate::legacy::session`]). The only differences
//! are the [`crate::legacy::family0`] crypto and the S7-1500/1200 request templates below.
//!
//! **Status:** the crypto + the request assembly are validated offline (byte-exact vs the
//! `AuthenticateRealPlc` golden vectors and the reference request template). The *live*
//! handshake has not yet been tested against physical S7-1200/1500 hardware — no `00:`/`01:`
//! unit has been available; only the PLCSIM (`03:`) legacy path is live-validated.

use crate::error::{Error, Result};
use crate::legacy::blob::derive_key_id;
use crate::legacy::family0::auth::authenticate_real_plc;
use crate::legacy::family0::blob::{PublicKeyFamily, REALPLC_BLOB_LEN};
use crate::legacy::pubkey_store;
use crate::legacy::session::{
    build_auth_request, decode_vlq_u64, find_challenge, recv_response, set_auth_request_lengths,
    LegacySession, CREATE_OBJECT_POC,
};
use crate::transport::IsoTcp;
use crate::wire::pdu::Hex;

// The two auth `SetMultiVariables` templates (S71500_AUTH_TEMPLATE / S71200_AUTH_TEMPLATE),
// captured from HarpoS7's PoC; each embeds a sample blob we overwrite.
include!("realplc_templates.rs");

/// Assemble the auth `SetMultiVariables` request for a real S7-1200/1500: patch the public/session
/// key ids, the 180-byte blob, and the session id into the family-specific template.
pub(crate) fn build_real_plc_request(
    family: PublicKeyFamily,
    pubkey_id: &[u8; 8],
    symkey_id: &[u8; 8],
    blob: &[u8],
    session_id: u32,
) -> Vec<u8> {
    // (template, (publicKeyIdOffset, symmetricKeyIdOffset, encryptedKeyBlobOffset))
    let (template, offsets): (&[u8], _) = match family {
        PublicKeyFamily::S71500 => (&S71500_AUTH_TEMPLATE, (0x40, 0x60, 0x7D)),
        PublicKeyFamily::S71200 => (&S71200_AUTH_TEMPLATE, (0x40, 0x61, 0x7E)),
    };
    build_auth_request(template, offsets, pubkey_id, symkey_id, blob, session_id)
}

/// Read the VLQ value of session-setup attribute `attr` (marker `82 <attr> 00 04 <vlq>`) from a
/// telegram, or `None` if the attribute isn't present.
fn extract_setup_value(buf: &[u8], attr: u8) -> Option<Vec<u8>> {
    let marker = [0x82, attr, 0x00, 0x04];
    let start = buf.windows(4).position(|w| w == marker)? + 4;
    let mut end = start;
    while end < buf.len() && buf[end] & 0x80 != 0 {
        end += 1;
    }
    end += 1; // include the terminating (high-bit-clear) byte
    buf.get(start..end).map(<[u8]>::to_vec)
}

/// Copy the PLC's session-setup values (members 0x3b–0x3e of attribute 306 in its `CreateObject`
/// response `resp`) into the auth request `frame`, and fix its lengths.
fn echo_setup_values(frame: &mut Vec<u8>, resp: &[u8]) {
    for attr in [0x3bu8, 0x3c, 0x3d, 0x3e] {
        match extract_setup_value(resp, attr) {
            Some(v) => {
                log::debug!(
                    "real-PLC: echoing session-setup value {attr:#04x} = {}",
                    Hex(&v)
                );
                splice_setup_value(frame, attr, &v);
            }
            None => {
                log::debug!("real-PLC: no session-setup value {attr:#04x}; keeping the template's")
            }
        }
    }
    set_auth_request_lengths(frame);
}

/// Replace session-setup attribute `attr`'s value in the auth request `frame` with `value`, a VLQ
/// of any length: the PLC's value need not encode to as many octets as the template's (2 or 4).
/// It used to be skipped when it didn't, leaving the template's value from a different unit,
/// which the PLC rejects (-258). The caller recomputes the frame lengths. The last marker is
/// the one taken: the setup values follow the encrypted-key blob, whose random bytes could hold
/// the marker by chance. Returns whether the attribute was found.
fn splice_setup_value(frame: &mut Vec<u8>, attr: u8, value: &[u8]) -> bool {
    let marker = [0x82, attr, 0x00, 0x04];
    let Some(p) = frame.windows(4).rposition(|w| w == marker) else {
        return false;
    };
    let start = p + 4;
    let end = frame[start..]
        .iter()
        .position(|o| o & 0x80 == 0)
        .map_or(frame.len(), |i| start + i + 1);
    frame.splice(start..end, value.iter().copied());
    true
}

/// Scan a response for fingerprint-like ASCII strings (`hh:<hex...>`) — a diagnostic aid when
/// family detection fails (so we can see what fingerprint the PLC actually presents).
pub fn scan_fingerprints(resp: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= resp.len() {
        if resp[i].is_ascii_hexdigit() && resp[i + 1].is_ascii_hexdigit() && resp[i + 2] == b':' {
            let mut end = i + 3;
            while end < resp.len() && resp[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end - (i + 3) >= 8 {
                out.push(String::from_utf8_lossy(&resp[i..end]).into_owned());
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Detect the real-PLC key family + fingerprint id from a `CreateObject` response by locating
/// the fingerprint string `00:<16hex>` (S7-1500) or `01:<16hex>` (S7-1200).
pub fn detect_real_plc(resp: &[u8]) -> Option<(PublicKeyFamily, String)> {
    for (prefix, family) in [
        (b"00:", PublicKeyFamily::S71500),
        (b"01:", PublicKeyFamily::S71200),
    ] {
        if let Some(p) = resp.windows(3).position(|w| w == prefix) {
            if let Some(id) = resp.get(p + 3..p + 3 + 16) {
                if id.iter().all(u8::is_ascii_hexdigit) {
                    return Some((family, String::from_utf8_lossy(id).to_uppercase()));
                }
            }
        }
    }
    // Fallback: some firmware advertises only the 2-char family in attribute 233
    // (`a3 81 69 .. 02 30 3X`) with no key-id. Return the family with an empty id.
    for w in resp.windows(7) {
        if w[0] == 0x81 && w[1] == 0x69 && w[4] == 0x02 && w[5] == b'0' {
            match w[6] {
                b'0' => return Some((PublicKeyFamily::S71500, String::new())),
                b'1' => return Some((PublicKeyFamily::S71200, String::new())),
                _ => {}
            }
        }
    }
    None
}

/// The result of [`real_plc_handshake`].
pub(crate) enum RealPlcOutcome {
    /// Auth succeeded.
    Authenticated(LegacySession),
    /// The PLC's family was detected but it advertised no key-id fingerprint we could match, and
    /// no key was passed. The caller can retry with each bundled key for `family`.
    KeyNotBundled { family: PublicKeyFamily },
}

/// Perform the legacy handshake for a real S7-1200/1500 on an already COTP-connected socket:
/// plaintext `CreateObject` → RealPlc challenge-response auth.
///
/// The key family is auto-detected from the PLC's fingerprint. `public_key` overrides the key;
/// pass `None` to look it up from the bundled [`pubkey_store`] by fingerprint — if that lookup
/// fails, this returns [`RealPlcOutcome::KeyNotBundled`] (not an error) so the caller can auto-try
/// the family's bundled keys.
pub(crate) fn real_plc_handshake(
    tcp: &mut IsoTcp,
    public_key: Option<&[u8]>,
    fill_random: &mut dyn FnMut(&mut [u8]),
) -> Result<RealPlcOutcome> {
    log::debug!("real-PLC: → CreateObject");
    tcp.send_iso_packet(&CREATE_OBJECT_POC[7..])?;
    let resp = recv_response(tcp)?;
    log::trace!("real-PLC: ← {}", Hex(&resp));
    let create = crate::proto::parse_create_object_response(&resp)?;
    let session_id = create
        .session_id()
        .ok_or_else(|| Error::protocol("real-PLC CreateObject returned no session id"))?;
    let session_id2 = create.session_id2().unwrap_or(0);
    let plc_description = create.plc_description();
    let challenge = find_challenge(&resp)
        .ok_or_else(|| Error::protocol("real-PLC CreateObject: challenge (attr 303) not found"))?;

    log::info!(
        "real-PLC: session 0x{session_id:08x}; PLC describes itself as {plc_description:?}; \
         fingerprints {:?}",
        scan_fingerprints(&resp)
    );
    let (family, fingerprint) = detect_real_plc(&resp).ok_or_else(|| {
        Error::protocol(format!(
            "real-PLC: no 00:/01: fingerprint (not a legacy S7-1200/1500?); \
             fingerprints seen = {:?}",
            scan_fingerprints(&resp)
        ))
    })?;
    let public_key: &[u8] = match public_key {
        Some(k) => {
            log::info!("real-PLC: family {family:?}, key id {fingerprint:?}; using the key given");
            k
        }
        None => match pubkey_store::lookup(family, &fingerprint) {
            Some(k) => {
                log::info!("real-PLC: family {family:?}, key id {fingerprint:?}; key bundled");
                k
            }
            // Family known but key-id not advertised/bundled — let the caller auto-try the family.
            None => {
                log::info!(
                    "real-PLC: family {family:?}, key id {fingerprint:?}; no bundled key matches"
                );
                return Ok(RealPlcOutcome::KeyNotBundled { family });
            }
        },
    };

    let mut blob = [0u8; REALPLC_BLOB_LEN];
    let mut session_key = [0u8; 24];
    authenticate_real_plc(
        &mut blob,
        &mut session_key,
        &challenge,
        public_key,
        family,
        fill_random,
    );

    let mut frame = build_real_plc_request(
        family,
        &derive_key_id(public_key),
        &derive_key_id(&session_key),
        &blob,
        session_id,
    );

    // Echo the PLC's own session-setup values (attr-306 members 0x3b-0x3e from the CreateObject
    // response) into the auth request; the template's captured values are from a different unit
    // and cause an internal -258 rejection.
    echo_setup_values(&mut frame, &resp);

    // (Not logged as hex: the request carries the encrypted session key material.)
    log::debug!(
        "real-PLC: → auth SetMultiVariables ({} bytes)",
        frame.len() - 7
    );
    tcp.send_iso_packet(&frame[7..])?;
    let r = recv_response(tcp)?;
    log::trace!("real-PLC: ← {}", Hex(&r));
    let rv = r.get(14..).map_or(u64::MAX, decode_vlq_u64);
    if rv != 0 {
        return Err(Error::protocol(format!(
            "real-PLC auth rejected: ReturnValue=0x{rv:016x} (errorcode={})",
            rv as u16 as i16
        )));
    }
    log::info!("real-PLC: auth accepted");
    Ok(RealPlcOutcome::Authenticated(LegacySession {
        session_key,
        session_id,
        session_id2,
        plc_description,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Validate the request assembly against ground-truth requests generated by HarpoS7's
    // SetMultiVarsRequest.WriteS71500/1200 (session id 0x7000103D), for all three golden cases.
    fn check(family: PublicKeyFamily, pubkey_hex: &str, sk: &[u8], blob: &[u8], expected: &[u8]) {
        let public_key = hex(pubkey_hex);
        let req = build_real_plc_request(
            family,
            &derive_key_id(&public_key),
            &derive_key_id(sk),
            blob,
            0x7000_103D,
        );
        assert_eq!(&req[..], expected);
    }

    #[test]
    fn build_request_matches_reference_s71500() {
        check(
            PublicKeyFamily::S71500,
            "8456A26996122216C921C571FF11E0BEFAFDB1D70B5D4BC8390F5B0CC273EC142A03F2A04E6F1593",
            include_bytes!("../../tests/vectors/family0/auth/s71500-sk.bin"),
            include_bytes!("../../tests/vectors/family0/auth/s71500-blob.bin"),
            include_bytes!("../../tests/vectors/family0/auth/s71500-req.bin"),
        );
    }

    #[test]
    fn build_request_matches_reference_s71200() {
        let pk = "e0e1f04a5ca3f90148178689bd0c930ab9db867b4f0ab109623959aa32316b7880ed1b4f9a9b189f";
        check(
            PublicKeyFamily::S71200,
            pk,
            include_bytes!("../../tests/vectors/family0/auth/s71200a-sk.bin"),
            include_bytes!("../../tests/vectors/family0/auth/s71200a-blob.bin"),
            include_bytes!("../../tests/vectors/family0/auth/s71200a-req.bin"),
        );
        check(
            PublicKeyFamily::S71200,
            pk,
            include_bytes!("../../tests/vectors/family0/auth/s71200b-sk.bin"),
            include_bytes!("../../tests/vectors/family0/auth/s71200b-blob.bin"),
            include_bytes!("../../tests/vectors/family0/auth/s71200b-req.bin"),
        );
    }

    /// The S7-1500 golden auth request, before the setup values are echoed into it.
    fn s71500_request(blob: &[u8]) -> Vec<u8> {
        let public_key =
            hex("8456A26996122216C921C571FF11E0BEFAFDB1D70B5D4BC8390F5B0CC273EC142A03F2A04E6F1593");
        let sk = include_bytes!("../../tests/vectors/family0/auth/s71500-sk.bin");
        build_real_plc_request(
            PublicKeyFamily::S71500,
            &derive_key_id(&public_key),
            &derive_key_id(sk),
            blob,
            0x7000_103D,
        )
    }

    /// A `CreateObject` response stand-in carrying session-setup `values` as `(attr, vlq)`.
    fn setup_response(values: &[(u8, &[u8])]) -> Vec<u8> {
        let mut resp = vec![0xa3, 0x82, 0x32, 0x00, 0x17]; // attribute 306, a struct
        for (attr, v) in values {
            resp.extend_from_slice(&[0x82, *attr, 0x00, 0x04]);
            resp.extend_from_slice(v);
        }
        resp.push(0);
        resp
    }

    fn assert_lengths_consistent(frame: &[u8]) {
        assert_eq!(
            usize::from(u16::from_be_bytes([frame[2], frame[3]])),
            frame.len()
        );
        assert_eq!(
            usize::from(u16::from_be_bytes([frame[9], frame[10]])),
            frame.len() - 15
        );
        assert_eq!(&frame[frame.len() - 4..], &[0x72, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn setup_values_of_any_vlq_length_are_echoed() {
        let blob = include_bytes!("../../tests/vectors/family0/auth/s71500-blob.bin");
        let template = s71500_request(blob);
        // The template holds 2- and 4-octet values; the PLC's may encode to 1, 3 or 5 octets.
        let values: [(u8, &[u8]); 4] = [
            (0x3b, &[0x05]),
            (0x3c, &[0x81, 0x80, 0x00]),
            (0x3d, &[0x8f, 0xff, 0xff, 0xff, 0x7f]),
            (0x3e, &[0x84, 0x00]),
        ];
        let mut frame = template.clone();
        echo_setup_values(&mut frame, &setup_response(&values));
        for (attr, v) in values {
            assert_eq!(
                extract_setup_value(&frame, attr).as_deref(),
                Some(v),
                "attr {attr:#x}"
            );
        }
        assert_lengths_consistent(&frame);
        assert_eq!(
            frame.len() + (2 + 2 + 4 + 4),
            template.len() + (1 + 3 + 5 + 2)
        );
        // Everything between the length fields and the first setup value is untouched, the blob
        // included.
        let first = template.windows(2).position(|w| w == [0x82, 0x3b]).unwrap();
        assert_eq!(&frame[11..first], &template[11..first]);
    }

    #[test]
    fn a_setup_value_the_plc_omits_keeps_the_template_value() {
        let blob = include_bytes!("../../tests/vectors/family0/auth/s71500-blob.bin");
        let template = s71500_request(blob);
        let mut frame = template.clone();
        echo_setup_values(&mut frame, &setup_response(&[(0x3c, &[0x84, 0x01])]));
        assert_eq!(
            extract_setup_value(&frame, 0x3b),
            extract_setup_value(&template, 0x3b)
        );
        assert_eq!(
            extract_setup_value(&frame, 0x3c).as_deref(),
            Some(&[0x84, 0x01][..])
        );
        assert_eq!(frame.len(), template.len());
        assert_lengths_consistent(&frame);
    }

    #[test]
    fn a_setup_marker_inside_the_blob_is_left_alone() {
        // The blob is random; one holding the marker by chance must not be patched.
        let mut blob = *include_bytes!("../../tests/vectors/family0/auth/s71500-blob.bin");
        blob[10..15].copy_from_slice(&[0x82, 0x3b, 0x00, 0x04, 0x07]);
        let template = s71500_request(&blob);
        let mut frame = template.clone();
        echo_setup_values(&mut frame, &setup_response(&[(0x3b, &[0x09])]));
        let at = template
            .windows(5)
            .position(|w| w == [0x82, 0x3b, 0x00, 0x04, 0x07])
            .unwrap();
        assert_eq!(&frame[at..at + 5], &[0x82, 0x3b, 0x00, 0x04, 0x07]);
        assert_eq!(
            frame
                .windows(5)
                .filter(|w| *w == [0x82, 0x3b, 0x00, 0x04, 0x09])
                .count(),
            1
        );
        assert_lengths_consistent(&frame);
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }
}
