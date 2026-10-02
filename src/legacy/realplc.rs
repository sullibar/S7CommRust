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
//! `AuthenticateRealPlc` golden vectors and the reference request template), and the *live*
//! handshake — auth plus symbolic browse — has been validated against physical S7-1200/1500
//! hardware over the `00:`/`01:` public-key families. Only the optimized-blob DB layouts
//! remain outstanding for real-hardware coverage.

use crate::error::{Error, Result};
use crate::legacy::blob::derive_key_id;
use crate::legacy::family0::auth::authenticate_real_plc;
use crate::legacy::family0::blob::{PublicKeyFamily, REALPLC_BLOB_LEN};
use crate::legacy::pubkey_store;
use crate::legacy::session::{
    build_auth_request, decode_vlq_u64, find_challenge, recv_response, CREATE_OBJECT_POC,
};
use crate::transport::IsoTcp;

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

/// Overwrite session-setup attribute `attr`'s value in `frame` with `value`, in place (only if the
/// existing value has the same VLQ length — the S7-1200/1500 setup values are all 2 or 4 bytes).
fn patch_setup_value(frame: &mut [u8], attr: u8, value: &[u8]) {
    let marker = [0x82, attr, 0x00, 0x04];
    if let Some(p) = frame.windows(4).position(|w| w == marker) {
        let start = p + 4;
        let mut end = start;
        while end < frame.len() && frame[end] & 0x80 != 0 {
            end += 1;
        }
        end += 1;
        if end - start == value.len() {
            frame[start..end].copy_from_slice(value);
        }
    }
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
pub enum RealPlcOutcome {
    /// Auth succeeded: the derived 24-byte session key and the session ids (the second is the
    /// server-session container, used as the RequestId for subsequent object creation).
    Authenticated {
        session_key: [u8; 24],
        session_id: u32,
        session_id2: u32,
    },
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
pub fn real_plc_handshake(
    tcp: &mut IsoTcp,
    public_key: Option<&[u8]>,
    fill_random: &mut dyn FnMut(&mut [u8]),
) -> Result<RealPlcOutcome> {
    tcp.send_iso_packet(&CREATE_OBJECT_POC[7..])?;
    let resp = recv_response(tcp)?;
    let create = crate::proto::parse_create_object_response(&resp)?;
    let session_id = create
        .session_id()
        .ok_or_else(|| Error::protocol("real-PLC CreateObject returned no session id"))?;
    let session_id2 = create.session_id2().unwrap_or(0);
    let challenge = find_challenge(&resp)
        .ok_or_else(|| Error::protocol("real-PLC CreateObject: challenge (attr 303) not found"))?;

    log::info!(
        "real-PLC CreateObject ok: session=0x{session_id:08x}, {} bytes, fingerprints={:?}",
        resp.len(),
        scan_fingerprints(&resp)
    );
    log::debug!("real-PLC CreateObject response = {resp:02x?}");
    let (family, fingerprint) = detect_real_plc(&resp).ok_or_else(|| {
        Error::protocol(format!(
            "real-PLC: no 00:/01: fingerprint (not a legacy S7-1200/1500?); \
             fingerprints seen = {:?}",
            scan_fingerprints(&resp)
        ))
    })?;
    let public_key: &[u8] = match public_key {
        Some(k) => k,
        None => match pubkey_store::lookup(family, &fingerprint) {
            Some(k) => k,
            // Family known but key-id not advertised/bundled — let the caller auto-try the family.
            None => return Ok(RealPlcOutcome::KeyNotBundled { family }),
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
    for attr in [0x3bu8, 0x3c, 0x3d, 0x3e] {
        if let Some(v) = extract_setup_value(&resp, attr) {
            patch_setup_value(&mut frame, attr, &v);
        }
    }

    tcp.send_iso_packet(&frame[7..])?;
    let r = recv_response(tcp)?;
    let rv = r.get(14..).map_or(u64::MAX, decode_vlq_u64);
    if rv != 0 {
        return Err(Error::protocol(format!(
            "real-PLC auth rejected: ReturnValue=0x{rv:016x} (errorcode={})",
            rv as u16 as i16
        )));
    }
    Ok(RealPlcOutcome::Authenticated {
        session_key,
        session_id,
        session_id2,
    })
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

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }
}
