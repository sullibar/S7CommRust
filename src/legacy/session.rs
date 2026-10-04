// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Legacy (pre-TLS, FW < 2.9) session bootstrap. Auth scheme ported from bonk-dev/HarpoS7
// (`LegacyAuthenticationScheme.AuthenticatePlcSim`), MIT; framing/templates captured from its
// PoC. The "real-PLC session-setup" fix was discovered empirically against PLCSIM Advanced FW2.8.

//! Legacy non-TLS session: COTP + plaintext `CreateObject` + PlcSim challenge-response auth,
//! after which every PDU is wrapped in a ProtocolVersion-`0x03` frame carrying a 32-byte
//! HMAC-SHA256 digest keyed by the derived session key.
//!
//! Hardware-validated end-to-end (auth + digest + reads) on an S7-PLCSIM **Advanced** FW2.8
//! instance. That product uses the PlcSim P-256 crypto but a real-PLC request layout, so the
//! auth `SetMultiVariables` must carry the **real-PLC (S71500) session-setup attribute values**
//! — the captured PlcSim values make the firmware reject the auth (internal error -258).

use crate::error::{Error, Result};
use crate::legacy::auth::authenticate_plcsim;
use crate::legacy::blob::{derive_key_id, PLCSIM_PUBLIC_KEY};
use crate::legacy::digest::{packet_digest, ResponseDigests};
use crate::transport::IsoTcp;
use crate::wire::vlq;

// Auth `SetMultiVariables` patch offsets (into the framed template, TPKT included).
const PUBKEY_ID_OFFSET: usize = 0x42;
const SYMKEY_ID_OFFSET: usize = 0x63;
const BLOB_OFFSET: usize = 0x80;

/// The `CreateObject` request HarpoS7's PoC sends — a fully-populated `ServerSession`
/// (name, client RID 0x80c3c901, host/adapter strings, "Read Write" mode, SubscriptionContainer).
#[rustfmt::skip]
pub(crate) const CREATE_OBJECT_POC: [u8; 272] = [
    0x03, 0x00, 0x01, 0x10, 0x02, 0xf0, 0x80, 0x72, 0x01, 0x01, 0x01, 0x31, 0x00, 0x00, 0x04, 0xca,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x20, 0x36, 0x00, 0x00, 0x01, 0x1d, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, 0xd3, 0x82, 0x1f, 0x00, 0x00, 0xa3, 0x81, 0x69,
    0x00, 0x15, 0x15, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
    0x5f, 0x31, 0x43, 0x39, 0x43, 0x33, 0x38, 0x31, 0xa3, 0x82, 0x21, 0x00, 0x15, 0x41, 0x30, 0x3a,
    0x3a, 0x3a, 0x36, 0x2e, 0x30, 0x3a, 0x3a, 0x41, 0x53, 0x49, 0x58, 0x20, 0x41, 0x58, 0x38, 0x38,
    0x31, 0x37, 0x39, 0x20, 0x55, 0x53, 0x42, 0x20, 0x33, 0x2e, 0x30, 0x20, 0x74, 0x6f, 0x20, 0x47,
    0x69, 0x67, 0x61, 0x62, 0x69, 0x74, 0x20, 0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
    0x41, 0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x2e, 0x54, 0x43, 0x50, 0x49, 0x50, 0x2e, 0x31, 0xa3,
    0x82, 0x28, 0x00, 0x15, 0x0a, 0x52, 0x65, 0x61, 0x64, 0x20, 0x57, 0x72, 0x69, 0x74, 0x65, 0xa3,
    0x82, 0x29, 0x00, 0x15, 0x0b, 0x48, 0x4d, 0x49, 0x20, 0x52, 0x54, 0x20, 0x4f, 0x4d, 0x53, 0x2b,
    0xa3, 0x82, 0x2a, 0x00, 0x15, 0x08, 0x59, 0x6f, 0x75, 0x72, 0x48, 0x6f, 0x73, 0x74, 0xa3, 0x82,
    0x2b, 0x00, 0x04, 0x02, 0xa3, 0x82, 0x2c, 0x00, 0x12, 0x01, 0xc9, 0xc3, 0x81, 0xa3, 0x82, 0x2d,
    0x00, 0x15, 0x0f, 0x52, 0x65, 0x61, 0x64, 0x2f, 0x57, 0x72, 0x69, 0x74, 0x65, 0x20, 0x74, 0x61,
    0x67, 0x73, 0xa1, 0x00, 0x00, 0x00, 0xd3, 0x81, 0x7f, 0x00, 0x00, 0xa3, 0x81, 0x69, 0x00, 0x15,
    0x15, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e,
    0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0xa2, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x72, 0x01, 0x00, 0x00,
];

/// The auth `SetMultiVariables` (HarpoS7 PoC `SetMultiVarsRequest.PlcSimData`). We patch in the
/// session id, the public/session key ids, the encrypted blob, and the real-PLC session-setup.
#[rustfmt::skip]
const AUTH_SETMULTI_TEMPLATE: [u8; 433] = [
    0x03, 0x00, 0x01, 0xb1, 0x02, 0xf0, 0x80, 0x72, 0x02, 0x01, 0xa2, 0x31, 0x00, 0x00, 0x05, 0x42,
    0x00, 0x00, 0x00, 0x02, 0x70, 0x40, 0x00, 0x00, 0x34, 0x70, 0x40, 0x00, 0x00, 0x03, 0x03, 0x8e,
    0x26, 0x82, 0x32, 0x82, 0x2b, 0x01, 0x00, 0x17, 0x00, 0x00, 0x07, 0x08, 0x8e, 0x09, 0x00, 0x04,
    0x00, 0x8e, 0x0a, 0x00, 0x02, 0x00, 0x8e, 0x0b, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21, 0x8e, 0x22,
    0x00, 0x05, 0xad, 0xa6, 0xed, 0xb0, 0x8a, 0xfd, 0x91, 0xd2, 0x84, 0x8e, 0x23, 0x00, 0x04, 0x86,
    0x10, 0x8e, 0x24, 0x00, 0x04, 0x00, 0x00, 0x8e, 0x0c, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21, 0x8e,
    0x22, 0x00, 0x05, 0xc0, 0xf6, 0xa2, 0xaf, 0xdc, 0xc9, 0xbc, 0xbb, 0xbe, 0x8e, 0x23, 0x00, 0x04,
    0x84, 0x86, 0x01, 0x8e, 0x24, 0x00, 0x04, 0x00, 0x00, 0x8e, 0x0d, 0x00, 0x14, 0x00, 0x81, 0x58,
    0xad, 0xde, 0xe1, 0xfe, 0xd8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xbe, 0x3b, 0x5e, 0x92, 0xfb, 0x12, 0xd9, 0x81, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x84, 0xd2, 0x48, 0x5f, 0x01, 0x6b, 0x9b, 0x5a, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9d, 0xe7, 0x29, 0xe7, 0x42, 0x0d, 0x09, 0x14, 0xf3, 0x2f, 0x62, 0x49, 0x35, 0x79, 0x2b, 0xbc,
    0x5d, 0xab, 0xdb, 0x36, 0x98, 0x91, 0xe8, 0x93, 0xb0, 0x4e, 0x2a, 0x84, 0x74, 0xb5, 0x98, 0xd8,
    0xc2, 0xbf, 0x2f, 0x5c, 0x85, 0x2f, 0x8b, 0xac, 0x94, 0x07, 0x7f, 0xe9, 0xc5, 0xff, 0x40, 0x8f,
    0x2c, 0x98, 0xfd, 0x39, 0xbf, 0x30, 0x28, 0xfb, 0x01, 0xae, 0x40, 0x26, 0x9b, 0x69, 0xe8, 0xe4,
    0xa5, 0x2d, 0x6c, 0x32, 0x88, 0x5f, 0x15, 0x05, 0x64, 0x15, 0x10, 0x64, 0xf6, 0xe5, 0x6d, 0x24,
    0x94, 0x14, 0xbc, 0xfd, 0xe8, 0x65, 0x46, 0x9e, 0x15, 0x56, 0x08, 0xfb, 0x01, 0x93, 0x5a, 0x7d,
    0xd5, 0xa9, 0xca, 0xd1, 0xef, 0x90, 0x8f, 0x92, 0x26, 0xab, 0x47, 0xed, 0x42, 0x6f, 0x86, 0xe2,
    0x1f, 0x05, 0x88, 0x7d, 0xdb, 0xbf, 0x6a, 0xc7, 0x0c, 0x08, 0x62, 0x53, 0xfb, 0xa6, 0xac, 0xe3,
    0x1d, 0x12, 0x7f, 0x27, 0x28, 0xf1, 0x4b, 0xaf, 0x1a, 0x86, 0x62, 0x7d, 0xd0, 0x96, 0x03, 0x01,
    0x1a, 0x6b, 0xdf, 0xe8, 0x44, 0xc6, 0xa6, 0xd8, 0x09, 0x45, 0xa3, 0x86, 0x46, 0xcf, 0xb1, 0x81,
    0x1e, 0xf6, 0x14, 0x7f, 0x46, 0xea, 0x10, 0xfb, 0x00, 0x02, 0x00, 0x17, 0x00, 0x00, 0x01, 0x3a,
    0x82, 0x3b, 0x00, 0x04, 0x85, 0x40, 0x82, 0x3c, 0x00, 0x04, 0x85, 0x00, 0x82, 0x3d, 0x00, 0x04,
    0x84, 0x80, 0xc1, 0x00, 0x82, 0x3e, 0x00, 0x04, 0x84, 0x80, 0xc1, 0x00, 0x82, 0x3f, 0x00, 0x15,
    0x00, 0x82, 0x40, 0x00, 0x15, 0x00, 0x82, 0x41, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x04,
    0x02, 0x00, 0x00, 0x00, 0x04, 0xe8, 0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x89, 0x6a,
    0x00, 0x13, 0x00, 0x89, 0x6b, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x02, 0x00,
    0x00,
];

/// An authenticated legacy session, as a handshake leaves it.
pub(crate) struct LegacySession {
    /// The derived session key (never logged).
    pub session_key: [u8; 24],
    pub session_id: u32,
    pub session_id2: u32,
    /// See [`crate::proto::CreateObjectResponse::plc_description`].
    pub plc_description: Option<String>,
}

/// Perform the legacy handshake on an already COTP-connected socket: plaintext `CreateObject`
/// (full `ServerSession`) → PlcSim challenge-response auth (with the real-PLC session-setup fix).
/// `fill_random` supplies the auth's ephemeral key material.
pub(crate) fn handshake(
    tcp: &mut IsoTcp,
    fill_random: &mut dyn FnMut(&mut [u8]),
) -> Result<LegacySession> {
    // 1. Plaintext CreateObject → session id + per-session challenge (attribute 303).
    log::debug!("legacy: → CreateObject (PLCSIM key family)");
    tcp.send_iso_packet(&CREATE_OBJECT_POC[7..])?;
    let resp = recv_response(tcp)?;
    log::trace!("legacy: ← {}", crate::wire::pdu::Hex(&resp));
    let create = crate::proto::parse_create_object_response(&resp)?;
    let session_id = create
        .session_id()
        .ok_or_else(|| Error::protocol("legacy CreateObject returned no session id"))?;
    let session_id2 = create.session_id2().unwrap_or(0);
    let plc_description = create.plc_description();
    log::info!(
        "legacy: session 0x{session_id:08x}; PLC describes itself as {plc_description:?}; \
         fingerprints {:?}",
        crate::legacy::realplc::scan_fingerprints(&resp)
    );
    let challenge = find_challenge(&resp)
        .ok_or_else(|| Error::protocol("legacy CreateObject: challenge (attr 303) not found"))?;

    // 2. Build the encrypted-key blob + derive the session key, then assemble the auth request.
    let (blob, session_key) = authenticate_plcsim(&PLCSIM_PUBLIC_KEY, &challenge, fill_random);
    let mut frame = build_auth_request(
        &AUTH_SETMULTI_TEMPLATE,
        (PUBKEY_ID_OFFSET, SYMKEY_ID_OFFSET, BLOB_OFFSET),
        &derive_key_id(&PLCSIM_PUBLIC_KEY),
        &derive_key_id(&session_key),
        &blob,
        session_id,
    );
    // The real-PLC (S71500) session-setup values 0x3b-0x3e (PLCSIM Advanced requires these; the
    // captured PlcSim values trigger an internal firmware error -258).
    patch_after(&mut frame, &[0x82, 0x3b, 0x00, 0x04], &[0x84, 0x00]);
    patch_after(&mut frame, &[0x82, 0x3c, 0x00, 0x04], &[0x84, 0x00]);
    patch_after(
        &mut frame,
        &[0x82, 0x3d, 0x00, 0x04],
        &[0x84, 0x81, 0x82, 0x40],
    );
    patch_after(
        &mut frame,
        &[0x82, 0x3e, 0x00, 0x04],
        &[0x84, 0x81, 0x82, 0x40],
    );

    // 3. Send the auth and require ReturnValue == 0 (otherwise the session is not authenticated).
    // (Not logged as hex: the request carries the encrypted session key material.)
    log::debug!(
        "legacy: → auth SetMultiVariables ({} bytes)",
        frame.len() - 7
    );
    tcp.send_iso_packet(&frame[7..])?;
    let r = recv_response(tcp)?;
    log::trace!("legacy: ← {}", crate::wire::pdu::Hex(&r));
    let rv = r.get(14..).map_or(u64::MAX, decode_vlq_u64);
    if rv != 0 {
        return Err(Error::protocol(format!(
            "legacy auth rejected: ReturnValue=0x{rv:016x} (errorcode={})",
            rv as u16 as i16
        )));
    }
    log::info!("legacy: auth accepted");
    Ok(LegacySession {
        session_key,
        session_id,
        session_id2,
        plc_description,
    })
}

/// Assemble an auth `SetMultiVariables` request from a captured `template` (TPKT included):
/// patch in the session id, the public/session key ids and the encrypted-key `blob`.
/// `offsets` = (public key id, session key id, blob), as found in the template.
///
/// The key ids are VLQs whose length depends on the value (9 octets for most ids, fewer when the
/// top byte is zero — ~1/256 of session keys), so the template's ids are *replaced* rather than
/// overwritten in place, and the PDU / TPKT lengths are recomputed. Overwriting in place would
/// leave a stale template byte behind a short id, which the PLC rejects (errorcode -255).
pub(crate) fn build_auth_request(
    template: &[u8],
    (pubkey_off, symkey_off, blob_off): (usize, usize, usize),
    pubkey_id: &[u8; 8],
    symkey_id: &[u8; 8],
    blob: &[u8],
    session_id: u32,
) -> Vec<u8> {
    let mut frame = template.to_vec();
    // Back to front, so each patch leaves the earlier offsets valid.
    frame[blob_off..blob_off + blob.len()].copy_from_slice(blob);
    for (off, id) in [(symkey_off, symkey_id), (pubkey_off, pubkey_id)] {
        let old_len = vlq_u64_len(&frame[off..]);
        frame.splice(off..off + old_len, key_id_vlq(id));
    }
    // The session id appears twice: the request header and the SetMultiVariables object id.
    frame[0x14..0x18].copy_from_slice(&session_id.to_be_bytes());
    frame[0x19..0x1d].copy_from_slice(&session_id.to_be_bytes());
    set_auth_request_lengths(&mut frame);
    frame
}

/// Set an auth request's TPKT length (whole frame) and PDU data length (7-byte TPKT/COTP,
/// `72 02 <len>` header and `72 02 00 00` trailer excluded) after values were spliced in.
pub(crate) fn set_auth_request_lengths(frame: &mut [u8]) {
    let tpkt_len = u16::try_from(frame.len()).expect("auth request fits a TPKT");
    frame[2..4].copy_from_slice(&tpkt_len.to_be_bytes());
    frame[9..11].copy_from_slice(&(tpkt_len - 15).to_be_bytes());
}

/// Length in octets of the S7p `UInt64` VLQ at the start of `b` (1–9; see [`decode_vlq_u64`]).
fn vlq_u64_len(b: &[u8]) -> usize {
    b.iter()
        .take(8)
        .position(|o| o & 0x80 == 0)
        .map_or(9, |i| i + 1)
}

/// Wrap a normal (V2) framed PDU as a legacy ProtocolVersion-`0x03` PDU carrying the HMAC
/// digest over its data part: `72 03 <1+32+len> 20 <digest> <data> 72 03 00 00`.
pub fn frame_v3(session_key: &[u8; 24], v2_framed: &[u8]) -> Result<Vec<u8>> {
    let data = &v2_framed[4..v2_framed.len() - 4];
    let digest = packet_digest(session_key, data)?;
    let chunk_len = u16::try_from(1 + 32 + data.len())
        .map_err(|_| Error::protocol("legacy request too large for one V3 chunk (64 KiB)"))?;
    let mut out = vec![0x72, 0x03];
    out.extend_from_slice(&chunk_len.to_be_bytes());
    out.push(0x20);
    out.extend_from_slice(&digest);
    out.extend_from_slice(data);
    out.extend_from_slice(&[0x72, 0x03, 0x00, 0x00]);
    Ok(out)
}

/// Receive a full response (skipping unsolicited `0xfe` SystemEvents), reassembling the V3 digest
/// framing across as many telegrams as it spans, and return a clean single PDU the
/// `proto::parse_*` helpers accept. A large Explore response arrives as several telegrams whose
/// `72 03 <len>` chunks concatenate up to the final `72 03 00 00` trailer.
///
/// Every chunk's digest is checked under `session_key` ([`ResponseDigests`]); a chunk that fails
/// is an [`Error::Integrity`].
///
/// `partial` holds the PDU gathered so far. It survives an error (a read timeout between
/// telegrams), so the next call resumes the same PDU, and is emptied once the PDU is complete.
pub fn recv_and_strip(
    tcp: &mut IsoTcp,
    session_key: &[u8; 24],
    partial: &mut PartialResponse,
) -> Result<Vec<u8>> {
    loop {
        let telegram = recv_response(tcp)?;
        if accumulate_chunks(&telegram, session_key, partial)? {
            break; // saw the len==0 trailer → PDU complete
        }
        if partial.body.len() > crate::wire::pdu::MAX_TELEGRAM_LEN {
            return Err(Error::framing(
                "legacy telegram exceeds the reassembly size cap",
            ));
        }
    }
    let data = std::mem::take(partial).body;
    log::trace!("legacy: reassembled {} bytes", data.len());
    Ok(crate::wire::pdu::frame_single_pdu(V3, &data))
}

/// ProtocolVersion of the legacy, digest-protected chunks.
const V3: u8 = 0x03;

/// A legacy PDU whose chunks are still arriving.
#[derive(Default)]
pub(crate) struct PartialResponse {
    /// The chunks' fragments so far.
    body: Vec<u8>,
    /// Their digest state; `None` until the first chunk.
    digests: Option<ResponseDigests>,
}

/// Receive the next response, skipping unsolicited SystemEvent (`0xfe`) keep-alives. A fatal
/// SystemEvent (one carrying error data) ends the connection, as on the TLS path; it used to be
/// skipped too, leaving the caller to wait for the read timeout.
pub(crate) fn recv_response(tcp: &mut IsoTcp) -> Result<Vec<u8>> {
    loop {
        let t = tcp.recv_iso_packet()?;
        if t.get(1) == Some(&0xfe) {
            if crate::proto::parse_system_event(&t).is_ok_and(|ev| ev.is_fatal()) {
                log::debug!(
                    "legacy: fatal SystemEvent ({} bytes): {}",
                    t.len(),
                    crate::wire::pdu::UnredactedHex(&t)
                );
                return Err(Error::closed(
                    "PLC sent a fatal SystemEvent; connection must be re-established",
                ));
            }
            log::debug!(
                "legacy: skipped SystemEvent ({} bytes): {}",
                t.len(),
                crate::wire::pdu::UnredactedHex(&t)
            );
            continue;
        }
        return Ok(t);
    }
}

/// Strip the legacy V3 chunk framing from one telegram, verifying each chunk and appending its
/// fragment to `partial`. Every `72 03 <len>` chunk holds `20 <32-byte digest> <fragment>`;
/// fragments concatenate up to the `72 03 00 00` trailer. Returns `true` once the trailer is seen
/// (the PDU is complete); `false` means the PDU continues in a following telegram.
fn accumulate_chunks(
    payload: &[u8],
    session_key: &[u8; 24],
    partial: &mut PartialResponse,
) -> Result<bool> {
    let mut i = 0;
    while i + 4 <= payload.len() {
        if payload[i] != 0x72 {
            return Err(Error::framing(format!(
                "bad chunk byte 0x{:02x}",
                payload[i]
            )));
        }
        // Once the session key is in place every PDU is digest-protected, so a chunk of
        // another protocol version would be one that skipped the check.
        if payload[i + 1] != V3 {
            return Err(Error::integrity(format!(
                "legacy chunk has protocol version 0x{:02x}, not the digest-protected 0x03",
                payload[i + 1]
            )));
        }
        let len = u16::from_be_bytes([payload[i + 2], payload[i + 3]]) as usize;
        i += 4;
        if len == 0 {
            log::trace!("legacy: trailer ({}-byte telegram)", payload.len());
            return Ok(true); // trailer => PDU complete
        }
        if i + len > payload.len() {
            return Err(Error::framing("legacy chunk length exceeds telegram"));
        }
        let chunk = &payload[i..i + len];
        i += len;
        // 1-byte digest length (32) + digest, then the fragment.
        if chunk.first() != Some(&0x20) {
            return Err(Error::integrity("legacy chunk carries no digest"));
        }
        let (digest, fragment) = chunk[1..]
            .split_at_checked(32)
            .ok_or_else(|| Error::framing("legacy chunk shorter than its digest"))?;
        let digests = match &mut partial.digests {
            Some(digests) => digests,
            None => partial.digests.insert(ResponseDigests::new(session_key)?),
        };
        digests.verify(digest, fragment)?;
        // The chunk sizes a PLC uses, and how it packs chunks into telegrams, are what the mock
        // PLC's profiles need; field logs are the only place to measure them.
        log::trace!(
            "legacy: chunk with {} fragment bytes ({}-byte telegram)",
            fragment.len(),
            payload.len()
        );
        partial.body.extend_from_slice(fragment);
    }
    Ok(false) // no trailer in this telegram => more telegrams follow
}

/// Find the 20-byte attr-303 challenge (`82 2f 10 02 14` then 20 bytes) in the response.
pub(crate) fn find_challenge(resp: &[u8]) -> Option<[u8; 20]> {
    let marker = [0x82u8, 0x2f, 0x10, 0x02, 0x14];
    let pos = resp.windows(marker.len()).position(|w| w == marker)?;
    let start = pos + marker.len();
    let bytes = resp.get(start..start + 20)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Some(out)
}

/// Encode an 8-byte key id as the request-level VLQ (read as a little-endian u64, then VLQ).
pub(crate) fn key_id_vlq(key_id: &[u8; 8]) -> Vec<u8> {
    let mut buf = Vec::new();
    vlq::encode_u64(&mut buf, u64::from_le_bytes(*key_id)).expect("vec write is infallible");
    buf
}

/// Decode an S7p `UInt64` VLQ (matches upstream `S7p.DecodeUInt64Vlq`); `u64::MAX` when `b` ends
/// inside the VLQ (a truncated reply then reads as a rejection rather than panicking).
pub(crate) fn decode_vlq_u64(mut b: &[u8]) -> u64 {
    vlq::decode_u64(&mut b).unwrap_or(u64::MAX)
}

/// Overwrite the bytes immediately following the first occurrence of `pat` in `buf` with `val`.
fn patch_after(buf: &mut [u8], pat: &[u8], val: &[u8]) {
    if let Some(p) = buf.windows(pat.len()).position(|w| w == pat) {
        let start = p + pat.len();
        buf[start..start + val.len()].copy_from_slice(val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlq_u64_len_matches_encoding() {
        for v in [0u64, 0x7f, 0x80, 1 << 55, (1 << 56) - 1, 1 << 56, u64::MAX] {
            let enc = key_id_vlq(&v.to_le_bytes());
            assert_eq!(vlq_u64_len(&enc), enc.len(), "value 0x{v:x}");
            assert_eq!(decode_vlq_u64(&enc), v, "value 0x{v:x}");
        }
    }

    /// A key id whose top byte is zero encodes as an 8-octet VLQ instead of 9; the request must
    /// shrink accordingly rather than keep a stale template byte (PLC: errorcode -255).
    #[test]
    fn auth_request_handles_short_key_id() {
        let offsets = (PUBKEY_ID_OFFSET, SYMKEY_ID_OFFSET, BLOB_OFFSET);
        let pubkey_id = derive_key_id(&PLCSIM_PUBLIC_KEY);
        let blob = [0xa5u8; crate::legacy::blob::PLCSIM_BLOB_LEN];
        for (symkey_id, len) in [
            ([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], 9),
            ([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00], 8),
            ([0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00], 6),
        ] {
            let frame = build_auth_request(
                &AUTH_SETMULTI_TEMPLATE,
                offsets,
                &pubkey_id,
                &symkey_id,
                &blob,
                0x7000_0f8f,
            );
            let shrink = 9 - len;
            assert_eq!(frame.len(), AUTH_SETMULTI_TEMPLATE.len() - shrink);
            assert_eq!(
                usize::from(u16::from_be_bytes([frame[2], frame[3]])),
                frame.len()
            );
            assert_eq!(
                usize::from(u16::from_be_bytes([frame[9], frame[10]])),
                frame.len() - 15
            );
            assert_eq!(&frame[0x14..0x18], &0x7000_0f8fu32.to_be_bytes());
            assert_eq!(&frame[0x19..0x1d], &0x7000_0f8fu32.to_be_bytes());

            let pk = &frame[PUBKEY_ID_OFFSET..];
            assert_eq!(decode_vlq_u64(pk), u64::from_le_bytes(pubkey_id));
            let sk = &frame[SYMKEY_ID_OFFSET..];
            assert_eq!(vlq_u64_len(sk), len);
            assert_eq!(decode_vlq_u64(sk), u64::from_le_bytes(symkey_id));
            // The next attribute (0x8e 0x23) follows the id directly.
            assert_eq!(&sk[len..len + 2], &[0x8e, 0x23]);
            // Everything after the id is the template, shifted.
            let blob_at = BLOB_OFFSET - shrink;
            assert_eq!(&frame[blob_at..blob_at + blob.len()], &blob);
            assert_eq!(
                &frame[blob_at + blob.len()..],
                &AUTH_SETMULTI_TEMPLATE[BLOB_OFFSET + blob.len()..]
            );
        }
    }

    #[test]
    fn short_digest_chunk_is_an_error_not_a_panic() {
        // `72 03 00 01 20`: a V3 chunk marked as digested but only one byte long used to panic
        // slicing past the 33-byte marker + digest.
        let mut partial = PartialResponse::default();
        assert!(
            accumulate_chunks(&[0x72, 0x03, 0x00, 0x01, 0x20], &[0; 24], &mut partial).is_err()
        );
    }

    /// A one-chunk telegram carrying `fragment` with its digest under `key`.
    fn chunk(key: &[u8; 24], fragment: &[u8]) -> Vec<u8> {
        let mut telegram = vec![0x72, 0x03];
        telegram.extend_from_slice(&(1 + 32 + fragment.len() as u16).to_be_bytes());
        telegram.push(0x20);
        telegram.extend_from_slice(&packet_digest(key, fragment).unwrap());
        telegram.extend_from_slice(fragment);
        telegram
    }

    #[test]
    fn digest_chunks_reassemble() {
        let key = [7; 24];
        let mut telegram = chunk(&key, b"abc");
        let mut partial = PartialResponse::default();
        assert!(!accumulate_chunks(&telegram, &key, &mut partial).unwrap());
        telegram.extend_from_slice(&[0x72, 0x03, 0x00, 0x00]);
        let mut partial = PartialResponse::default();
        assert!(accumulate_chunks(&telegram, &key, &mut partial).unwrap());
        assert_eq!(partial.body, b"abc");
    }

    #[test]
    fn a_chunk_with_a_bad_or_missing_digest_is_rejected() {
        let key = [7; 24];
        let reject = |telegram: &[u8]| {
            let e = accumulate_chunks(telegram, &key, &mut PartialResponse::default()).unwrap_err();
            assert!(matches!(e, Error::Integrity(_)), "{e}");
        };
        let good = chunk(&key, b"abc");
        let mut tampered = good.clone();
        *tampered.last_mut().unwrap() ^= 1;
        reject(&tampered);
        reject(&chunk(&[8; 24], b"abc")); // another session's key
                                          // The same chunk without its digest, as a V3 chunk and as an unprotected V2 one.
        let mut bare = vec![0x72, 0x03, 0x00, 0x03];
        bare.extend_from_slice(b"abc");
        reject(&bare);
        bare[1] = 0x02;
        reject(&bare);
    }

    /// One response captured from PLCSIM Advanced FW V2.8: its session key and the two telegrams
    /// it arrived in (see `tests/vectors/legacy/README.md`).
    const PLCSIM_KEY: &[u8; 24] =
        include_bytes!("../../tests/vectors/legacy/plcsim-session-key.bin");
    const PLCSIM_TELEGRAMS: [&[u8]; 2] = [
        include_bytes!("../../tests/vectors/legacy/plcsim-response-telegram1.bin"),
        include_bytes!("../../tests/vectors/legacy/plcsim-response-telegram2.bin"),
    ];

    #[test]
    fn a_plcsim_response_verifies_across_telegrams() {
        let mut partial = PartialResponse::default();
        assert!(!accumulate_chunks(PLCSIM_TELEGRAMS[0], PLCSIM_KEY, &mut partial).unwrap());
        assert!(accumulate_chunks(PLCSIM_TELEGRAMS[1], PLCSIM_KEY, &mut partial).unwrap());
        // The fragments of the 975- and 209-byte chunks, less their marker and digest.
        assert_eq!(partial.body.len(), 975 - 33 + 209 - 33);
        assert_eq!(partial.body[0], crate::wire::pdu::opcode::RESPONSE);
    }

    #[test]
    fn a_plcsim_continuation_chunk_does_not_verify_on_its_own() {
        // The second chunk's digest is chained to the first chunk: it is not a plain digest,
        // and does not verify as the first chunk of a response.
        let mut partial = PartialResponse::default();
        let e = accumulate_chunks(PLCSIM_TELEGRAMS[1], PLCSIM_KEY, &mut partial).unwrap_err();
        assert!(matches!(e, Error::Integrity(_)), "{e}");
    }

    #[test]
    fn truncated_auth_return_value_is_a_rejection_not_a_panic() {
        // The auth reply's ReturnValue VLQ cut off mid-value used to index past the buffer.
        assert_eq!(decode_vlq_u64(&[0x80]), u64::MAX);
        assert_eq!(decode_vlq_u64(&[]), u64::MAX);
        assert_eq!(decode_vlq_u64(&[0x00]), 0);
    }

    #[test]
    fn oversized_v3_request_is_rejected() {
        let framed = crate::wire::pdu::frame_single_pdu(0x02, &vec![0u8; 70_000]);
        assert!(frame_v3(&[7u8; 24], &framed).is_err());
    }
}
