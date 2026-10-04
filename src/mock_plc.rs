// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! A mock legacy (V3-digest) PLC on loopback, for tests.
//!
//! The mock starts where the login ends: it signs with the all-zero session key that
//! [`session_for`] hands the client, since the real login needs Siemens' private key on the PLC
//! side (HarpoS7's vectors and hardware tests cover the login). There is no TLS either.
//!
//! It runs in one of two ways:
//!
//! * **Scripted** ([`mock_connection`]): each test drives the PLC side with a closure, using
//!   [`MockPlc::recv_request`], [`MockPlc::response`] and [`MockPlc::send`].
//! * **Emulated** ([`run`]): a small in-memory PLC ([`Plc`]) answers the driver's requests the
//!   way a firmware [`Profile`] says. This is what lets CI cover the S7-1200 legacy path, which
//!   PLCSIM can't simulate.
//!
//! # Where the behaviour comes from
//!
//! An emulator written from our own assumptions passes our own bugs, so every behaviour here comes
//! from a capture or a measurement, and its doc comment says which. The sources are:
//!
//! * **PLCSIM live run**: PLCSIM Advanced, CPU 1511-1 PN FW V2.8, legacy path, driven
//!   by this crate (request size limit, `SystemLimits`, item error -61, state-resume digests on
//!   1746 of 1746 continuation chunks).
//! * **`tests/vectors`**: the PLCSIM captures this mock replays (Explore responses, a two-chunk
//!   response with its session key).
//! * **First s7tool logs**: this crate's `s7tool` against an S7-1215C FW V4.2 and
//!   S7-1214C FW V4.6 (and FW 4.5/4.7 CPUs): request limits, digest dialects, DeleteObject on close.
//! * **Field run**: the Python driver (gijzelaerr/s7commplus) against
//!   the same FW V4.2 1215C, traced down to TPKT frames: chunk sizes, keep-alives, rejections.
//!
//! Requests the mock has no measured answer for make it panic ("not measured"), so a test can't
//! quietly rely on a guess. A panic in the mock thread is re-raised by [`run`].
//!
//! # Open questions
//!
//! These aren't known well enough to encode, so the mock stays permissive (it accepts) or refuses
//! to guess (it panics):
//!
//! * **IntegrityId acceptance.** Observed: the crate's first request after login (the limits read)
//!   carries id 1 and works on FW 4.2 (first s7tool logs). In the traced flow (session
//!   activation + legitimation), an activation with id 1 is rejected and the first data request
//!   needs one id skipped (field run). The full rule is unknown, so the mock accepts any
//!   id and only records it ([`Logged::integrity_id`]).
//! * **Chunk sizes.** FW 4.2 is measured (976-byte fragments at most, field run), as is
//!   PLCSIM (942, `tests/vectors/legacy`). The s7tool logs only record reassembled sizes, so FW 4.6
//!   is unmeasured; its profile assumes FW 4.2's size.
//! * **When keep-alives are sent.** FW 4.2 sent one about every 5 s during the traced session,
//!   including three between the chunks of one response. None appeared in the crate's own s7tool
//!   sessions with the same CPU, so something in the traced flow seems to turn them on.
//!   The mock has no clock: it sends one after every `n` chunks ([`Profile::keepalive_every`]).
//! * **FW 4.6/4.7** beyond the digest dialect, the request limits and the DeleteObject return value:
//!   no rejection rules, keep-alives or size limit are encoded.
//! * **Request size limit on S7-1200s.** Only PLCSIM is measured (resets the connection on a COTP
//!   frame over 1024 bytes); S7-1200s accept anything here.
//! * **Over-limit requests and byte-offset (ClassicBlob) access on S7-1200 CPUs.** Only PLCSIM's answers
//!   are measured; on an S7-1200 profile the mock panics instead.
//! * **Writes on S7-1200s** were never attempted in the field; the mock accepts them on every
//!   profile.
//! * **The exact bytes after the return value** in DeleteObject and SetMultiVariables responses: the
//!   driver reads only the header, and the mock writes the layout of the crate's own parse tests.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::panic::AssertUnwindSafe;
use std::thread::JoinHandle;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::digest::generic_array::GenericArray;
use sha2::Sha256;

use crate::connection::Connection;
use crate::legacy::session::LegacySession;
use crate::proto::PObject;
use crate::transport::IsoTcp;
use crate::value::PValue;
use crate::wire::pdu::{self, functioncode};
use crate::wire::vlq;

// ---------------------------------------------------------------------------------------------
// Firmware profiles
// ---------------------------------------------------------------------------------------------

/// How a PLC signs the continuation chunks of a response it splits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// Every response goes out as one chunk, whatever its size, so it only ever carries the plain
    /// digest. What the scripted mock has always done.
    Single,
    /// The PLC resumes its finalized HMAC-SHA256 state for the next chunk (Rogue7 §3.1).
    StateResume,
    /// Each continuation chunk carries `HMAC(key, previous digest || fragment)`.
    FeedForward,
}

/// PLCSIM's answers to byte-offset (ClassicBlob) access that it refuses.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RawAccess {
    /// Item error for a read of an optimized DB or past the end of an area (-61).
    pub(crate) read_refused: u64,
    /// Item error for such a write (-61).
    pub(crate) write_refused: u64,
}

/// What a firmware does, as far as the driver can tell. Each field says where it was measured.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Profile {
    /// For test messages.
    pub(crate) name: &'static str,
    /// What the PLC calls itself in its `ServerSessionVersion` (the CreateObject response; logged
    /// by s7tool for the S7-1200 CPUs).
    pub(crate) description: &'static str,
    /// How continuation chunks are signed.
    pub(crate) dialect: Dialect,
    /// Most response bytes one chunk carries (its fragment, digest excluded).
    pub(crate) max_fragment: usize,
    /// Send a 16-byte keep-alive SystemEvent after every this many chunks, if set.
    pub(crate) keepalive_every: Option<usize>,
    /// Reject a Get/SetMultiVariables whose ObjectQualifier uses the V1 layout (a fixed-width
    /// key qualifier instead of a VLQ plus terminator).
    pub(crate) reject_v1_qualifier: bool,
    /// Reject the Explore of the DB wildcard `0x8A11FFFF`.
    pub(crate) reject_db_wildcard_explore: bool,
    /// Reset the connection on a COTP frame (TPDU) longer than this, if set.
    pub(crate) max_tpdu: Option<usize>,
    /// `SystemLimits` LID 1000: most items per GetMultiVariables.
    pub(crate) tags_per_read: i32,
    /// `SystemLimits` LID 1001: most items per SetMultiVariables.
    pub(crate) tags_per_write: i32,
    /// Return value of a request with more items than the limit, if measured.
    pub(crate) over_limit: Option<u64>,
    /// Byte-offset access and its refusals, if measured.
    pub(crate) raw_access: Option<RawAccess>,
    /// `EffectiveProtectionLevel` (attribute 1842), if measured.
    pub(crate) protection_level: Option<u32>,
    /// Return value of the DeleteObject of the session (`Connection::close`).
    pub(crate) session_delete_return: u64,
}

/// The scripted mock: one chunk per response, no rules. Not a firmware.
pub(crate) const SCRIPTED: Profile = Profile {
    name: "scripted",
    description: "1;6ES7 MOCK;V0.0",
    dialect: Dialect::Single,
    max_fragment: usize::MAX,
    keepalive_every: None,
    reject_v1_qualifier: false,
    reject_db_wildcard_explore: false,
    max_tpdu: None,
    tags_per_read: 100,
    tags_per_write: 100,
    over_limit: None,
    raw_access: None,
    protection_level: None,
    session_delete_return: 0,
};

/// S7-1215C 6ES7 215-1AG40-0XB0, FW V4.2.
pub(crate) const FW42_1215C: Profile = Profile {
    name: "FW42_1215C",
    // First s7tool logs.
    description: "1;6ES7 215-1AG40-0XB0 ;V4.2",
    // First s7tool logs (a 107924-byte Explore verified) and field run (360
    // continuation chunks verified as state-resume).
    dialect: Dialect::StateResume,
    // Field run: chunk length fields of at most 0x3f1 = 1 + 32 + 976 (279 of 360
    // chunks at that size, the rest 972..975).
    max_fragment: 976,
    // Field run: a keep-alive about every 5 s, three of them between the chunks of one
    // response (after chunks 28, 38 and 80). The mock has no clock; 8 chunks makes a mid-size
    // response carry one (see the module's open questions).
    keepalive_every: Some(8),
    // Field run: a GetMultiVariables with the V1 layout got the notice and a closed
    // connection; the V2 layout works.
    reject_v1_qualifier: true,
    // Field run: Explore of 0x8A11FFFF got the notice; Explore of RID 3 works.
    reject_db_wildcard_explore: true,
    max_tpdu: None,
    // First s7tool logs.
    tags_per_read: 50,
    tags_per_write: 50,
    over_limit: None,
    raw_access: None,
    // Field run (password-protected program).
    protection_level: Some(3),
    // First s7tool logs: a plain 0.
    session_delete_return: 0,
};

/// S7-1214C 6ES7 214-1BG40-0XB0, FW V4.6.
pub(crate) const FW46_1214C: Profile = Profile {
    name: "FW46_1214C",
    // First s7tool logs.
    description: "1;6ES7 214-1BG40-0XB0 ;V4.6",
    // First s7tool logs: the state-resume digest failed on the first multi-chunk Explore,
    // the feed-forward one verified (`src/legacy/digest.rs`).
    dialect: Dialect::FeedForward,
    // Not measured: FW 4.2's size (see the module's open questions).
    max_fragment: 976,
    keepalive_every: None,
    reject_v1_qualifier: false,
    reject_db_wildcard_explore: false,
    max_tpdu: None,
    // First s7tool logs.
    tags_per_read: 50,
    tags_per_write: 50,
    over_limit: None,
    raw_access: None,
    // First s7tool logs.
    protection_level: Some(3),
    // First s7tool logs.
    session_delete_return: 0x2023_8000_0085_002d,
};

/// PLCSIM Advanced, CPU 1511-1 PN FW V2.8, legacy path.
pub(crate) const PLCSIM_FW28: Profile = Profile {
    name: "PLCSIM_FW28",
    // `Connection::plc_description`'s example, from PLCSIM Advanced.
    description: "1;6ES7 SIM-01500-APLC;S4.1",
    // Live run (1746/1746 continuation chunks) and `tests/vectors/legacy`.
    dialect: Dialect::StateResume,
    // `tests/vectors/legacy`: the first chunk's length field is 975 = 1 + 32 + 942.
    max_fragment: 942,
    // None seen.
    keepalive_every: None,
    reject_v1_qualifier: false,
    reject_db_wildcard_explore: false,
    // Live run: a request over ~1 KB in one COTP frame reset the connection (80 items
    // fine, 120 not); the same request in DT frames of 1021 data bytes worked.
    max_tpdu: Some(1024),
    // Live run (FW 2.8; FW 2.9 the same).
    tags_per_read: 100,
    tags_per_write: 100,
    // Live run: a read of more than 100 items.
    over_limit: Some(0xa027_a600_007b_fffc),
    // Live run: an optimized DB, or one byte past the end of an area.
    raw_access: Some(RawAccess {
        read_refused: 0x8206_8d00_02bf_ffc3,
        write_refused: 0x8206_8d00_0188_ffc3,
    }),
    protection_level: None,
    // s7tool against PLCSIM's legacy path (DeleteObject on close).
    session_delete_return: 0x2023_8000_0088_002d,
};

/// The notice SystemEvent body an S7-1215C (FW V4.2) sends before it closes the connection
/// over a rejected request (field run): the four header `u32`s, then a fixed-width
/// Struct (`00 00 00 17`) with id 40300 and no members.
const FW42_REJECT_NOTICE: [u8; 28] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x9d, 0x6c, 0x00, 0x00, 0x00, 0x00,
];

/// A keep-alive SystemEvent body from the same CPU and run.
const FW42_KEEPALIVE: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The session id [`session_for`] gives the client.
const SESSION_ID: u32 = 0x7000_0001;

/// The session the mock PLC's handshake would leave: the all-zero key the mock signs with.
pub(crate) fn session_for(profile: &Profile) -> LegacySession {
    LegacySession {
        session_key: [0; 24],
        session_id: SESSION_ID,
        session_id2: 0x7000_0002,
        plc_description: Some(profile.description.into()),
    }
}

/// The session of the scripted mock.
pub(crate) fn mock_session() -> LegacySession {
    session_for(&SCRIPTED)
}

// ---------------------------------------------------------------------------------------------
// Signing (written apart from `legacy::digest`, and checked against the PLCSIM capture)
// ---------------------------------------------------------------------------------------------

/// SHA-256's initial hash value (FIPS 180-4 §5.3.3).
const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A SHA-256 that, like the PLC's, keeps going after it is finalized: the next chunk starts from
/// the previous digest, and the length in the padding counts every message byte so far.
struct ResumedSha256 {
    h: [u32; 8],
    absorbed: u64,
}

impl ResumedSha256 {
    /// The state after the HMAC pad block `key ^ pad_byte`.
    fn keyed(key: &[u8; 24], pad_byte: u8) -> Self {
        let mut block = [pad_byte; 64];
        for (b, k) in block.iter_mut().zip(key) {
            *b ^= k;
        }
        let mut h = SHA256_H0;
        sha2::compress256(&mut h, &[GenericArray::clone_from_slice(&block)]);
        ResumedSha256 { h, absorbed: 64 }
    }

    fn finish(&mut self, data: &[u8]) -> [u8; 32] {
        self.absorbed += data.len() as u64;
        let mut tail = data.to_vec();
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&(self.absorbed * 8).to_be_bytes());
        let blocks: Vec<_> = tail
            .chunks(64)
            .map(GenericArray::clone_from_slice)
            .collect();
        sha2::compress256(&mut self.h, &blocks);
        let mut out = [0u8; 32];
        for (o, word) in out.chunks_mut(4).zip(self.h) {
            o.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn hmac_sha256(key: &[u8; 24], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Signs the chunks of one response, in order.
struct ChunkSigner {
    key: [u8; 24],
    dialect: Dialect,
    inner: ResumedSha256,
    outer: ResumedSha256,
    prev: Option<[u8; 32]>,
}

impl ChunkSigner {
    fn new(key: &[u8; 24], dialect: Dialect) -> Self {
        ChunkSigner {
            key: *key,
            dialect,
            inner: ResumedSha256::keyed(key, 0x36),
            outer: ResumedSha256::keyed(key, 0x5c),
            prev: None,
        }
    }

    fn sign(&mut self, fragment: &[u8]) -> [u8; 32] {
        let digest = match (self.dialect, self.prev) {
            (Dialect::StateResume, _) => {
                let inner = self.inner.finish(fragment);
                self.outer.finish(&inner)
            }
            (Dialect::FeedForward, Some(prev)) => hmac_sha256(&self.key, &[&prev, fragment]),
            _ => hmac_sha256(&self.key, &[fragment]),
        };
        self.prev = Some(digest);
        digest
    }
}

// ---------------------------------------------------------------------------------------------
// The wire side
// ---------------------------------------------------------------------------------------------

/// Why the mock stopped serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum End {
    /// The client closed the connection.
    ClientClosed,
    /// The mock sent the rejection notice and closed the connection.
    Rejected(&'static str),
    /// The mock reset the connection without a word.
    Reset(&'static str),
}

/// One received request.
pub(crate) struct Request {
    /// The V2 body (the data of the V3 frame).
    pub(crate) body: Vec<u8>,
    /// How many COTP DT frames it arrived in.
    pub(crate) dt_frames: usize,
}

/// A stand-in for a legacy (V3-digest) PLC on loopback, with the all-zero session key
/// [`mock_session`] gives the client.
pub(crate) struct MockPlc {
    pub(crate) stream: TcpStream,
    /// Sequence number of the last request received, which a response must echo.
    pub(crate) seq: u16,
    profile: Profile,
    key: [u8; 24],
    /// Chunks sent since the last keep-alive.
    chunks_since_keepalive: usize,
    /// Keep-alives sent so far.
    keepalives: usize,
    /// Corrupt this chunk (0-based) of the next response to this function: a test knob, not PLC
    /// behaviour.
    corrupt: Option<(u16, usize)>,
}

impl MockPlc {
    /// Accept the client on `listener` and answer its COTP connection request.
    fn accept(listener: &TcpListener, profile: Profile) -> Self {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut cr = [0u8; 36];
        stream.read_exact(&mut cr).unwrap();
        stream
            .write_all(&[3, 0, 0, 11, 6, 0xd0, 0, 1, 0, 1, 0])
            .unwrap();
        MockPlc {
            stream,
            seq: 0,
            profile,
            key: [0; 24],
            chunks_since_keepalive: 0,
            keepalives: 0,
            corrupt: None,
        }
    }

    /// Read one request TSDU and return its V2 body (the `data` of the V3 frame).
    pub(crate) fn recv_request(&mut self) -> Vec<u8> {
        match self.next_request() {
            Ok(req) => req.body,
            Err(end) => panic!("mock PLC: no request ({end:?})"),
        }
    }

    /// The next request, or why the connection ended. Applies the profile's frame size limit and
    /// checks the request's digest (a PLC drops the connection on a wrong one).
    fn next_request(&mut self) -> Result<Request, End> {
        let mut tsdu = Vec::new();
        let mut dt_frames = 0;
        loop {
            let mut hdr = [0u8; 4];
            if self.stream.read_exact(&mut hdr).is_err() {
                return Err(End::ClientClosed);
            }
            let len = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
            if let Some(max) = self.profile.max_tpdu {
                if len.saturating_sub(4) > max {
                    // Closing with the frame unread resets the connection, as PLCSIM did.
                    let _ = self.stream.shutdown(Shutdown::Both);
                    return Err(End::Reset("COTP frame over the TPDU size"));
                }
            }
            let mut rest = vec![0u8; len - 4];
            if self.stream.read_exact(&mut rest).is_err() {
                return Err(End::ClientClosed);
            }
            dt_frames += 1;
            tsdu.extend_from_slice(&rest[3..]);
            if rest[2] & 0x80 != 0 {
                break;
            }
        }
        assert_eq!(&tsdu[..2], &[0x72, 0x03], "mock PLC: not a V3 request");
        assert_eq!(tsdu[4], 0x20, "mock PLC: request carries no digest");
        let data = &tsdu[4 + 33..tsdu.len() - 4];
        if tsdu[5..37] != hmac_sha256(&self.key, &[data]) {
            let _ = self.stream.shutdown(Shutdown::Both);
            return Err(End::Reset("wrong request digest"));
        }
        let body = data.to_vec();
        self.seq = u16::from_be_bytes([body[7], body[8]]);
        Ok(Request { body, dt_frames })
    }

    /// A successful response body to `function`, answering the last request, followed by
    /// `rest`.
    pub(crate) fn response(&self, function: u16, rest: &[u8]) -> Vec<u8> {
        let mut body = vec![pdu::opcode::RESPONSE, 0, 0];
        body.extend_from_slice(&function.to_be_bytes());
        body.extend_from_slice(&[0, 0]); // reserved
        body.extend_from_slice(&self.seq.to_be_bytes());
        body.extend_from_slice(&[0, 0]); // transport flags, return value 0
        body.extend_from_slice(rest);
        body
    }

    /// An Explore response body listing `objects`, answering the last request.
    pub(crate) fn explore_response(&self, explore_id: u32, objects: &[PObject]) -> Vec<u8> {
        let mut rest = explore_id.to_be_bytes().to_vec();
        rest.push(0); // integrity id
        for o in objects {
            o.serialize(&mut rest).unwrap();
        }
        rest.extend_from_slice(&[0; 4]);
        self.response(functioncode::EXPLORE, &rest)
    }

    /// The V3 telegram carrying `body`, as one COTP DT frame.
    pub(crate) fn frame(body: &[u8]) -> Vec<u8> {
        let mut v3 = vec![0x72, 0x03];
        v3.extend_from_slice(&((1 + 32 + body.len()) as u16).to_be_bytes());
        v3.push(0x20);
        v3.extend_from_slice(&crate::legacy::digest::packet_digest(&[0; 24], body).unwrap());
        v3.extend_from_slice(body);
        v3.extend_from_slice(&[0x72, 0x03, 0, 0]);
        dt_frame(&v3)
    }

    /// Send a response body the way the profile's PLC does: split into chunks of at most
    /// [`Profile::max_fragment`] bytes, each signed per [`Profile::dialect`] and in its own COTP
    /// frame, the trailer in the last one's frame (both as measured on FW 4.2 and in the PLCSIM
    /// capture), with keep-alives in between if the profile sends them.
    pub(crate) fn send(&mut self, body: &[u8]) {
        let fragments: Vec<&[u8]> = match self.profile.dialect {
            Dialect::Single => vec![body],
            _ => body.chunks(self.profile.max_fragment).collect(),
        };
        let function = body
            .get(3..5)
            .map_or(0, |f| u16::from_be_bytes([f[0], f[1]]));
        let corrupt = match self.corrupt {
            Some((f, chunk)) if f == function => {
                self.corrupt = None;
                Some(chunk)
            }
            _ => None,
        };
        let mut signer = ChunkSigner::new(&self.key, self.profile.dialect);
        let last = fragments.len() - 1;
        for (i, fragment) in fragments.into_iter().enumerate() {
            let mut digest = signer.sign(fragment);
            if corrupt == Some(i) {
                digest[0] ^= 1;
            }
            let mut chunk = vec![0x72, 0x03];
            chunk.extend_from_slice(&((1 + 32 + fragment.len()) as u16).to_be_bytes());
            chunk.push(0x20);
            chunk.extend_from_slice(&digest);
            chunk.extend_from_slice(fragment);
            if i == last {
                chunk.extend_from_slice(&[0x72, 0x03, 0, 0]);
            }
            self.write(&dt_frame(&chunk));
            self.chunks_since_keepalive += 1;
            if self
                .profile
                .keepalive_every
                .is_some_and(|n| self.chunks_since_keepalive >= n)
            {
                self.chunks_since_keepalive = 0;
                self.keepalives += 1;
                self.write(&dt_frame(&system_event(&FW42_KEEPALIVE)));
            }
        }
    }

    /// Refuse the last request as FW 4.2 does: the notice SystemEvent, then close.
    fn reject(&mut self) {
        self.write(&dt_frame(&system_event(&FW42_REJECT_NOTICE)));
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn write(&mut self, bytes: &[u8]) {
        // The client may already have given up (a test of its error handling); not our concern.
        let _ = self.stream.write_all(bytes);
    }

    /// Answer the GetMultiVariables the client sends at connect for the request limits.
    pub(crate) fn answer_limits(&mut self, max: i32) {
        let req = self.recv_request();
        assert_eq!(&req[3..5], &functioncode::GET_MULTI_VARIABLES.to_be_bytes());
        let mut rest = Vec::new();
        for item in [1u8, 2] {
            rest.push(item);
            PValue::DInt(max).serialize(&mut rest).unwrap();
        }
        rest.extend_from_slice(&[0, 0, 0]); // end of values, end of errors, integrity id
        let body = self.response(functioncode::GET_MULTI_VARIABLES, &rest);
        self.send(&body);
    }
}

/// `payload` as one COTP DT frame with the end-of-TSDU bit (TPKT included).
fn dt_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![3, 0];
    f.extend_from_slice(&((7 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[2, 0xf0, 0x80]);
    f.extend_from_slice(payload);
    f
}

/// A SystemEvent telegram: `72 fe <len>` and the body, no trailer (as the FW 4.2 CPU sends it,
/// field run).
fn system_event(body: &[u8]) -> Vec<u8> {
    let mut t = vec![0x72, 0xfe];
    t.extend_from_slice(&(body.len() as u16).to_be_bytes());
    t.extend_from_slice(body);
    t
}

/// A legacy `Connection` to a scripted mock PLC that runs `script` after answering the limits
/// read.
pub(crate) fn mock_connection(
    timeout: Duration,
    script: impl FnOnce(MockPlc) + Send + 'static,
) -> (Connection, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let plc = std::thread::spawn(move || {
        let mut plc = MockPlc::accept(&listener, SCRIPTED);
        plc.answer_limits(100);
        script(plc);
    });
    let tcp = IsoTcp::connect(addr, timeout).unwrap();
    let conn = Connection::legacy_after_handshake(tcp, mock_session(), addr, timeout).unwrap();
    (conn, plc)
}

// ---------------------------------------------------------------------------------------------
// Request parsing (the mock's own, so a bug in the crate's codec can't pass on both sides)
// ---------------------------------------------------------------------------------------------

/// A cursor over a request body; running off the end is a test failure.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn at(b: &'a [u8], pos: usize) -> Self {
        Reader { b, pos }
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = self
            .b
            .get(self.pos..self.pos + n)
            .unwrap_or_else(|| panic!("mock PLC: request ends at {} (want {n} more)", self.pos));
        self.pos += n;
        s
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    /// An unsigned VLQ: 7 bits per byte, most significant first, the high bit on all but the last.
    fn vlq(&mut self) -> u32 {
        let mut v: u32 = 0;
        for _ in 0..5 {
            let b = self.u8();
            v = (v << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                return v;
            }
        }
        panic!("mock PLC: VLQ longer than 5 bytes");
    }

    /// Skip a VLQ of any width (signed or 64-bit values).
    fn skip_vlq(&mut self) {
        while self.u8() & 0x80 != 0 {}
    }

    fn expect(&mut self, bytes: &[u8], what: &str) {
        assert_eq!(self.take(bytes.len()), bytes, "mock PLC: {what}");
    }
}

/// Which ObjectQualifier layout a request used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Qualifier {
    /// Key qualifier as a VLQ plus a `00` terminator (what this crate sends).
    V2,
    /// Key qualifier as a fixed-width `u32`, no terminator (a V1 layout some clients send).
    V1,
}

/// Read an ObjectQualifier, `between` bytes the function puts before the integrity id, the
/// integrity id, and check that exactly `tail` bytes (the fill) remain. The two layouts are told
/// apart by which one leaves exactly `tail` bytes.
fn qualifier_and_integrity_id(r: &mut Reader, between: usize, tail: usize) -> (Qualifier, u32) {
    r.expect(&[0x00, 0x00, 0x04, 0xe8], "ObjectQualifier id 1256");
    r.expect(&[0x89, 0x69, 0x00, 0x12], "ParentRID 1257");
    r.take(4);
    r.expect(&[0x89, 0x6a, 0x00, 0x13], "CompositionAID 1258");
    r.skip_vlq();
    r.expect(&[0x89, 0x6b, 0x00, 0x04], "KeyQualifier 1259");
    let rest = &r.b[r.pos..];
    for layout in [Qualifier::V2, Qualifier::V1] {
        if let Some(id) = layout_then_id(rest, layout, between, tail) {
            r.take(rest.len());
            return (layout, id);
        }
    }
    panic!("mock PLC: ObjectQualifier in neither the V1 nor the V2 layout");
}

/// If `rest` (what follows `89 6b 00 04`) is a key qualifier in `layout`, `between` bytes, a VLQ
/// integrity id and exactly `tail` bytes, the integrity id.
fn layout_then_id(rest: &[u8], layout: Qualifier, between: usize, tail: usize) -> Option<u32> {
    let mut i = match layout {
        Qualifier::V2 => {
            let key_len = rest.iter().position(|b| b & 0x80 == 0)? + 1;
            (*rest.get(key_len)? == 0).then_some(key_len + 1)?
        }
        Qualifier::V1 => 4,
    };
    i += between;
    let mut id: u32 = 0;
    loop {
        let b = *rest.get(i)?;
        i += 1;
        id = id.checked_mul(128)? | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            break;
        }
    }
    (rest.len().checked_sub(i)? == tail).then_some(id)
}

/// An item address as the mock reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Address {
    area: u32,
    sub_area: u32,
    lids: Vec<u32>,
}

fn read_addresses(r: &mut Reader, count: u32) -> Vec<Address> {
    (0..count)
        .map(|_| {
            r.vlq(); // symbol CRC
            let area = r.vlq();
            let ids = r.vlq();
            let sub_area = r.vlq();
            let lids = (1..ids).map(|_| r.vlq()).collect();
            Address {
                area,
                sub_area,
                lids,
            }
        })
        .collect()
}

/// Read one value and return its bytes (flags, datatype, payload) as sent. Only the scalar
/// types and the plain Blob the tests write are known; anything else is a test failure.
fn read_value(r: &mut Reader) -> Vec<u8> {
    let start = r.pos;
    let flags = r.u8();
    assert_eq!(
        flags, 0,
        "mock PLC: value flags 0x{flags:02x} not supported"
    );
    match r.u8() {
        // Bool, USInt, SInt, Byte
        0x01 | 0x02 | 0x06 | 0x0a => {
            r.take(1);
        }
        // UInt, Int, Word
        0x03 | 0x07 | 0x0b => {
            r.take(2);
        }
        // DWord, Real, RID
        0x0c | 0x0e | 0x12 => {
            r.take(4);
        }
        // LWord, LReal, Timestamp
        0x0d | 0x0f | 0x10 => {
            r.take(8);
        }
        // UDInt, ULInt, DInt, LInt, Timespan, AID
        0x04 | 0x05 | 0x08 | 0x09 | 0x11 | 0x13 => r.skip_vlq(),
        // Blob: root id, length, bytes
        0x14 => {
            r.vlq();
            let len = r.vlq() as usize;
            r.take(len);
        }
        other => panic!("mock PLC: value datatype 0x{other:02x} not supported"),
    }
    r.b[start..r.pos].to_vec()
}

/// The bytes of a plain Blob value (as [`read_value`] returns it).
fn blob_bytes(value: &[u8]) -> Vec<u8> {
    let mut r = Reader::at(value, 0);
    r.expect(&[0x00, 0x14], "a Blob value for byte-offset access");
    r.vlq();
    let len = r.vlq() as usize;
    r.take(len).to_vec()
}

// ---------------------------------------------------------------------------------------------
// The emulated PLC
// ---------------------------------------------------------------------------------------------

/// The Explore of the PLC program (RID 3) with the browse attributes, from PLCSIM FW V2.8: the
/// data blocks "Data block.1" (0x8a0e0001) and "Data_block_1" (0x8a0e0002), among others.
const PROGRAM: &[u8] = include_bytes!("../tests/vectors/proto/explore_program.bin");
/// The type info of "Data block.1" (members `value.1`, `plain`, `arr.x`, `nested.s`).
const TI_DB1: &[u8] = include_bytes!("../tests/vectors/proto/explore_ti_92000001.bin");
/// The type info of "Data_block_1" (one member, `toto`: Int, LID 9).
const TI_DB2: &[u8] = include_bytes!("../tests/vectors/proto/explore_ti_92000002.bin");
/// The recursive Explore of the device tree (rid 0x22), 13 KB: a multi-chunk response.
const DEVICE_TREE: &[u8] = include_bytes!("../tests/vectors/proto/explore_device_tree.bin");
/// The CPU execution unit (RID 52) in RUN.
const CPU_STATE_RUN: &[u8] = include_bytes!("../tests/vectors/proto/explore_cpu_state_run.bin");

/// RID of the device tree (an Explore of it is a large, multi-chunk response).
pub(crate) const DEVICE_TREE_RID: u32 = 0x22;
/// The DB wildcard that FW 4.2 refuses to explore.
pub(crate) const DB_WILDCARD: u32 = 0x8a11_ffff;

/// A data block.
#[derive(Debug, Clone)]
pub(crate) struct Db {
    /// Its relation id (the access area, `0x8a0e0000` + number).
    pub(crate) relid: u32,
    /// Its type info's relid (what a read of LID 1 returns).
    pub(crate) ti_relid: u32,
    /// Optimized blocks have no byte layout (PLCSIM refuses byte-offset access to them).
    pub(crate) optimized: bool,
    /// Its bytes, for byte-offset access to a standard block.
    pub(crate) bytes: Vec<u8>,
}

/// The PLC's memory and object tree.
#[derive(Debug, Clone)]
pub(crate) struct Plc {
    pub(crate) dbs: Vec<Db>,
    /// Bit memory (`%M`).
    pub(crate) m_area: Vec<u8>,
    /// Symbolic values by access area and LIDs, as sent on the wire (flags, datatype, payload).
    pub(crate) symbols: HashMap<(u32, Vec<u32>), Vec<u8>>,
    /// Captured Explore responses (framed PDUs) by the explored id.
    pub(crate) explores: HashMap<u32, &'static [u8]>,
    /// Corrupt this chunk of the next response to this function (a test knob).
    pub(crate) corrupt_chunk: Option<(u16, usize)>,
}

/// `value` as the bytes a GetMultiVariables carries.
pub(crate) fn wire_value(value: &PValue) -> Vec<u8> {
    let mut out = Vec::new();
    value.serialize(&mut out).unwrap();
    out
}

impl Plc {
    /// The PLCSIM FW V2.8 project the `tests/vectors` captures come from: its program tree, the
    /// type info of its two (optimized) data blocks, the device tree and the CPU state. The
    /// pairing of DB 1/2 with type info 0x92000001/2 follows the numbers; the LID-1 reads that
    /// returned them weren't captured. The M area is the 16 KB a CPU 1511 has (PLCSIM read it
    /// whole, live run). Tag values start at zero.
    pub(crate) fn plcsim_project() -> Plc {
        let int0 = wire_value(&PValue::Int(0));
        let mut symbols = HashMap::new();
        // "Data block.1": value.1, plain (Int, LIDs 9 and 10).
        symbols.insert((0x8a0e_0001, vec![9]), int0.clone());
        symbols.insert((0x8a0e_0001, vec![10]), int0.clone());
        // "Data_block_1".toto (Int, LID 9).
        symbols.insert((0x8a0e_0002, vec![9]), int0);
        let explores = HashMap::from([
            (3, PROGRAM),
            (0x9200_0001, TI_DB1),
            (0x9200_0002, TI_DB2),
            (DEVICE_TREE_RID, DEVICE_TREE),
            (52, CPU_STATE_RUN),
        ]);
        Plc {
            dbs: vec![
                Db {
                    relid: 0x8a0e_0001,
                    ti_relid: 0x9200_0001,
                    optimized: true,
                    bytes: Vec::new(),
                },
                Db {
                    relid: 0x8a0e_0002,
                    ti_relid: 0x9200_0002,
                    optimized: true,
                    bytes: Vec::new(),
                },
            ],
            m_area: vec![0; 16 * 1024],
            symbols,
            explores,
            corrupt_chunk: None,
        }
    }

    /// The stored bytes of a symbol (flags, datatype, payload), for test assertions.
    pub(crate) fn symbol(&self, area: u32, lids: &[u32]) -> Option<&[u8]> {
        self.symbols.get(&(area, lids.to_vec())).map(Vec::as_slice)
    }
}

/// A request the mock answered (or refused).
#[derive(Debug, Clone)]
pub(crate) struct Logged {
    pub(crate) function: u16,
    /// The IntegrityId it carried (accepted whatever it is; see the module's open questions).
    pub(crate) integrity_id: Option<u32>,
    /// How many COTP DT frames it came in.
    pub(crate) dt_frames: usize,
    /// How many items it read or wrote (Get/SetMultiVariables).
    pub(crate) items: usize,
}

/// What a session with the emulated PLC left behind.
#[derive(Debug)]
pub(crate) struct Served {
    pub(crate) plc: Plc,
    pub(crate) requests: Vec<Logged>,
    pub(crate) end: End,
    /// Keep-alives sent.
    pub(crate) keepalives: usize,
}

/// What to do with a request.
enum Outcome {
    Respond(Vec<u8>),
    Reject(&'static str),
}

/// A response header answering `seq`, with return value `rv`; transport flags `0x34` as in every
/// captured response.
fn response_header(function: u16, seq: u16, rv: u64) -> Vec<u8> {
    let mut b = vec![pdu::opcode::RESPONSE, 0, 0];
    b.extend_from_slice(&function.to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&seq.to_be_bytes());
    b.push(0x34);
    vlq::encode_u64(&mut b, rv).unwrap();
    b
}

/// The value or item error of a Get/SetMultiVariables item.
type ItemResult = Result<Vec<u8>, u64>;

impl Plc {
    fn handle(&mut self, req: &Request, p: &Profile, log: &mut Logged) -> Outcome {
        let b = &req.body;
        let seq = u16::from_be_bytes([b[7], b[8]]);
        let session = u32::from_be_bytes(b[9..13].try_into().unwrap());
        assert_eq!(session, SESSION_ID, "mock PLC: request for another session");
        let mut r = Reader::at(b, 14);
        match log.function {
            functioncode::GET_MULTI_VARIABLES => {
                r.u32(); // link id
                let count = r.vlq();
                r.vlq(); // field count
                let addrs = read_addresses(&mut r, count);
                let (layout, id) = qualifier_and_integrity_id(&mut r, 0, 4);
                log.integrity_id = Some(id);
                log.items = addrs.len();
                if layout == Qualifier::V1 && p.reject_v1_qualifier {
                    return Outcome::Reject("V1 ObjectQualifier");
                }
                if addrs.len() > p.tags_per_read as usize {
                    return over_limit(p, functioncode::GET_MULTI_VARIABLES, seq, addrs.len());
                }
                let items: Vec<ItemResult> = addrs.iter().map(|a| self.read(a, p)).collect();
                let mut body = response_header(functioncode::GET_MULTI_VARIABLES, seq, 0);
                for (i, item) in items.iter().enumerate() {
                    if let Ok(value) = item {
                        vlq::encode_u32(&mut body, i as u32 + 1).unwrap();
                        body.extend_from_slice(value);
                    }
                }
                body.push(0);
                for (i, item) in items.iter().enumerate() {
                    if let Err(code) = item {
                        vlq::encode_u32(&mut body, i as u32 + 1).unwrap();
                        vlq::encode_u64(&mut body, *code).unwrap();
                    }
                }
                body.extend_from_slice(&[0, 0]); // end of errors, integrity id
                Outcome::Respond(body)
            }
            functioncode::SET_MULTI_VARIABLES => {
                assert_eq!(r.u32(), 0, "mock PLC: only address-based writes");
                let count = r.vlq();
                r.vlq(); // field count
                let addrs = read_addresses(&mut r, count);
                let values: Vec<Vec<u8>> = (1..=count)
                    .map(|i| {
                        assert_eq!(r.vlq(), i, "mock PLC: item numbers out of order");
                        read_value(&mut r)
                    })
                    .collect();
                assert_eq!(r.u8(), 0, "mock PLC: fill byte");
                let (layout, id) = qualifier_and_integrity_id(&mut r, 0, 4);
                log.integrity_id = Some(id);
                log.items = addrs.len();
                if layout == Qualifier::V1 && p.reject_v1_qualifier {
                    return Outcome::Reject("V1 ObjectQualifier");
                }
                if addrs.len() > p.tags_per_write as usize {
                    return over_limit(p, functioncode::SET_MULTI_VARIABLES, seq, addrs.len());
                }
                let mut body = response_header(functioncode::SET_MULTI_VARIABLES, seq, 0);
                for (i, (a, v)) in addrs.iter().zip(values).enumerate() {
                    if let Err(code) = self.write(a, v, p) {
                        vlq::encode_u32(&mut body, i as u32 + 1).unwrap();
                        vlq::encode_u64(&mut body, code).unwrap();
                    }
                }
                body.extend_from_slice(&[0, 0]); // end of errors, integrity id
                Outcome::Respond(body)
            }
            functioncode::EXPLORE => {
                let id = r.u32();
                r.vlq(); // explore request id
                r.take(4); // recursive, 1, parents, 0
                let attrs = r.vlq();
                for _ in 0..attrs {
                    r.vlq();
                }
                log.integrity_id = Some(r.vlq());
                r.expect(&[0; 5], "Explore fill");
                if id == DB_WILDCARD && p.reject_db_wildcard_explore {
                    return Outcome::Reject("DB wildcard explore");
                }
                let capture = self.explores.get(&id).unwrap_or_else(|| {
                    panic!(
                        "mock PLC ({}): no capture of an Explore of 0x{id:08x}",
                        p.name
                    )
                });
                let mut body = capture[4..capture.len() - 4].to_vec();
                body[7..9].copy_from_slice(&seq.to_be_bytes());
                Outcome::Respond(body)
            }
            functioncode::GET_VAR_SUBSTREAMED => {
                let object = r.u32();
                r.take(3); // address descriptor flag, datatype, count
                let address = r.vlq();
                let (_, id) = qualifier_and_integrity_id(&mut r, 2, 4);
                log.integrity_id = Some(id);
                let level = match (object, address, p.protection_level) {
                    (SESSION_ID, 1842, Some(level)) => level,
                    _ => panic!(
                        "mock PLC ({}): no measured answer to reading attribute {address} of \
                         0x{object:08x}",
                        p.name
                    ),
                };
                let mut body = response_header(functioncode::GET_VAR_SUBSTREAMED, seq, 0);
                body.push(0);
                body.extend_from_slice(&wire_value(&PValue::UDInt(level)));
                body.push(0); // integrity id
                Outcome::Respond(body)
            }
            functioncode::DELETE_OBJECT => {
                let object = r.u32();
                assert_eq!(r.u8(), 0);
                let (_, id) = qualifier_and_integrity_id(&mut r, 0, 4);
                log.integrity_id = Some(id);
                assert_eq!(object, SESSION_ID, "mock PLC: only the session is deleted");
                let mut body =
                    response_header(functioncode::DELETE_OBJECT, seq, p.session_delete_return);
                body.extend_from_slice(&object.to_be_bytes());
                Outcome::Respond(body)
            }
            other => panic!(
                "mock PLC ({}): no measured behaviour for function 0x{other:04x}",
                p.name
            ),
        }
    }

    fn db(&self, relid: u32) -> &Db {
        self.dbs
            .iter()
            .find(|d| d.relid == relid)
            .unwrap_or_else(|| panic!("mock PLC: no DB 0x{relid:08x}"))
    }

    /// One item of a GetMultiVariables.
    fn read(&self, a: &Address, p: &Profile) -> ItemResult {
        const OBJECT_ROOT: u32 = 201;
        const SYSTEM_LIMITS: u32 = 1037;
        match (a.area, a.sub_area, a.lids.as_slice()) {
            (OBJECT_ROOT, SYSTEM_LIMITS, [1000]) => Ok(wire_value(&PValue::DInt(p.tags_per_read))),
            (OBJECT_ROOT, SYSTEM_LIMITS, [1001]) => Ok(wire_value(&PValue::DInt(p.tags_per_write))),
            (area, 2550, [1]) => Ok(wire_value(&PValue::RID(self.db(area).ti_relid))),
            (_, _, &[3, start, len]) => {
                let raw = raw_access(p);
                let bytes = self.raw_area(a).ok_or(raw.read_refused)?;
                let range = start as usize..(start + len) as usize;
                let data = bytes.get(range).ok_or(raw.read_refused)?.to_vec();
                Ok(wire_value(&PValue::Blob { root_id: 0, data }))
            }
            _ => self
                .symbols
                .get(&(a.area, a.lids.clone()))
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| panic!("mock PLC ({}): no symbol {a:?}", p.name)),
        }
    }

    /// One item of a SetMultiVariables.
    fn write(&mut self, a: &Address, value: Vec<u8>, p: &Profile) -> Result<(), u64> {
        if let &[3, start, len] = a.lids.as_slice() {
            let raw = raw_access(p);
            let data = blob_bytes(&value);
            assert_eq!(data.len(), len as usize, "mock PLC: blob length");
            let bytes = self.raw_area_mut(a).ok_or(raw.write_refused)?;
            let range = start as usize..(start + len) as usize;
            bytes
                .get_mut(range)
                .ok_or(raw.write_refused)?
                .copy_from_slice(&data);
            return Ok(());
        }
        let slot = self
            .symbols
            .get_mut(&(a.area, a.lids.clone()))
            .unwrap_or_else(|| panic!("mock PLC ({}): no symbol {a:?}", p.name));
        assert_eq!(
            slot[..2],
            value[..2],
            "mock PLC: a write of another datatype (no measured answer)"
        );
        *slot = value;
        Ok(())
    }

    /// The bytes behind a byte-offset address: `None` for an optimized DB.
    fn raw_area(&self, a: &Address) -> Option<&Vec<u8>> {
        match (a.area, a.sub_area) {
            (82, 3736) => Some(&self.m_area),
            (area, 2550) => {
                let db = self.db(area);
                (!db.optimized).then_some(&db.bytes)
            }
            _ => panic!("mock PLC: no byte-offset area {a:?}"),
        }
    }

    fn raw_area_mut(&mut self, a: &Address) -> Option<&mut Vec<u8>> {
        match (a.area, a.sub_area) {
            (82, 3736) => Some(&mut self.m_area),
            (area, 2550) => {
                let db = self.dbs.iter_mut().find(|d| d.relid == area)?;
                (!db.optimized).then_some(&mut db.bytes)
            }
            _ => panic!("mock PLC: no byte-offset area {a:?}"),
        }
    }
}

fn raw_access(p: &Profile) -> RawAccess {
    p.raw_access.unwrap_or_else(|| {
        panic!(
            "mock PLC ({}): byte-offset access not measured on this firmware",
            p.name
        )
    })
}

/// The answer to a request over the item limit, where it was measured.
fn over_limit(p: &Profile, function: u16, seq: u16, items: usize) -> Outcome {
    let rv = p.over_limit.unwrap_or_else(|| {
        panic!(
            "mock PLC ({}): {items} items, over the advertised limit; the answer wasn't measured",
            p.name
        )
    });
    let mut body = response_header(function, seq, rv);
    body.extend_from_slice(&[0, 0, 0]);
    Outcome::Respond(body)
}

/// Serve requests from `plc` until the client closes the connection or a rule ends it.
fn serve(mut mock: MockPlc, mut plc: Plc) -> Served {
    let mut requests = Vec::new();
    let profile = mock.profile;
    let end = loop {
        mock.corrupt = plc.corrupt_chunk.take().or(mock.corrupt);
        let req = match mock.next_request() {
            Ok(req) => req,
            Err(end) => break end,
        };
        let mut log = Logged {
            function: u16::from_be_bytes([req.body[3], req.body[4]]),
            integrity_id: None,
            dt_frames: req.dt_frames,
            items: 0,
        };
        let outcome = plc.handle(&req, &profile, &mut log);
        requests.push(log);
        match outcome {
            Outcome::Respond(body) => mock.send(&body),
            Outcome::Reject(why) => {
                mock.reject();
                break End::Rejected(why);
            }
        }
    };
    Served {
        plc,
        requests,
        end,
        keepalives: mock.keepalives,
    }
}

/// Start an emulated `plc` that behaves like `profile`, listening on loopback for one client.
fn spawn_mock(profile: Profile, plc: Plc) -> (std::net::SocketAddr, JoinHandle<Served>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = std::thread::spawn(move || serve(MockPlc::accept(&listener, profile), plc));
    (addr, mock)
}

/// Connect a legacy `Connection` to an emulated `plc` that behaves like `profile`, hand it to
/// `client`, and return what `client` returned with what the PLC saw. A panic in the mock (a
/// request it has no measured answer for) is raised here, before any failure it caused in
/// `client`.
pub(crate) fn run<T>(
    profile: Profile,
    plc: Plc,
    client: impl FnOnce(Connection) -> T,
) -> (T, Served) {
    let timeout = Duration::from_secs(5);
    let (addr, mock) = spawn_mock(profile, plc);
    let out = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let tcp = IsoTcp::connect(addr, timeout).unwrap();
        let conn =
            Connection::legacy_after_handshake(tcp, session_for(&profile), addr, timeout).unwrap();
        client(conn)
    }));
    let served = mock.join();
    match (out, served) {
        (_, Err(mock_panic)) => std::panic::resume_unwind(mock_panic),
        (Err(client_panic), _) => std::panic::resume_unwind(client_panic),
        (Ok(out), Ok(served)) => (out, served),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::proto::{self, Area, ItemAddress};

    /// The PLCSIM FW V2.8 capture of one two-chunk response and its session key (see
    /// `tests/vectors/legacy/README.md`).
    const PLCSIM_KEY: &[u8; 24] = include_bytes!("../tests/vectors/legacy/plcsim-session-key.bin");
    const PLCSIM_TELEGRAMS: [&[u8]; 2] = [
        include_bytes!("../tests/vectors/legacy/plcsim-response-telegram1.bin"),
        include_bytes!("../tests/vectors/legacy/plcsim-response-telegram2.bin"),
    ];

    /// The three firmware profiles.
    const PROFILES: [Profile; 3] = [FW42_1215C, FW46_1214C, PLCSIM_FW28];

    /// "Data_block_1".toto, by address.
    fn toto() -> ItemAddress {
        ItemAddress {
            symbol_crc: 0,
            access_area: 0x8a0e_0002,
            access_sub_area: 2550,
            lid: vec![9],
        }
    }

    fn device_tree_objects() -> Vec<PObject> {
        proto::parse_explore_response(DEVICE_TREE, true)
            .unwrap()
            .objects
    }

    /// How many chunks the device-tree Explore takes under `profile`.
    fn device_tree_chunks(profile: &Profile) -> usize {
        (DEVICE_TREE.len() - 8).div_ceil(profile.max_fragment)
    }

    // --- Phase 2: chunks and digest dialects ------------------------------------------------

    /// The mock's state-resume signer reproduces both digests of the PLCSIM capture, so it is
    /// checked against the PLC itself rather than against the driver's verifier.
    #[test]
    fn state_resume_signing_matches_the_plcsim_capture() {
        let mut signer = ChunkSigner::new(PLCSIM_KEY, Dialect::StateResume);
        for (i, telegram) in PLCSIM_TELEGRAMS.into_iter().enumerate() {
            let len = usize::from(u16::from_be_bytes([telegram[2], telegram[3]]));
            let chunk = &telegram[4..4 + len];
            assert_eq!(chunk[0], 0x20);
            if i == 0 {
                assert_eq!(chunk.len() - 33, PLCSIM_FW28.max_fragment);
            }
            assert_eq!(signer.sign(&chunk[33..]), chunk[1..33], "chunk {i}");
        }
    }

    #[test]
    fn dialects_agree_on_the_first_chunk_only() {
        let key = [7; 24];
        let mut resume = ChunkSigner::new(&key, Dialect::StateResume);
        let mut fed = ChunkSigner::new(&key, Dialect::FeedForward);
        let first = crate::legacy::digest::packet_digest(&key, b"first").unwrap();
        assert_eq!(resume.sign(b"first"), first);
        assert_eq!(fed.sign(b"first"), first);
        assert_ne!(resume.sign(b"second"), fed.sign(b"second"));
    }

    /// Explore the device tree under `profile` and check the driver reassembled it exactly.
    fn explore_device_tree(profile: Profile) -> Served {
        let (objects, served) = run(profile, Plc::plcsim_project(), |mut conn| {
            conn.explore(DEVICE_TREE_RID, 1, 0, &[]).unwrap().objects
        });
        assert_eq!(objects, device_tree_objects(), "{}", profile.name);
        assert!(device_tree_chunks(&profile) > 10);
        served
    }

    #[test]
    fn the_driver_verifies_state_resume_chunks() {
        explore_device_tree(Profile {
            keepalive_every: None,
            ..FW42_1215C
        });
        explore_device_tree(PLCSIM_FW28);
    }

    #[test]
    fn the_driver_verifies_feed_forward_chunks() {
        explore_device_tree(FW46_1214C);
    }

    #[test]
    fn keepalives_between_chunks_are_skipped() {
        let served = explore_device_tree(FW42_1215C);
        assert!(served.keepalives >= 1);
        // One after every chunk, the most a client can meet.
        let served = explore_device_tree(Profile {
            keepalive_every: Some(1),
            ..FW42_1215C
        });
        assert!(served.keepalives > device_tree_chunks(&FW42_1215C));
    }

    #[test]
    fn a_wrong_digest_in_any_chunk_poisons_the_connection() {
        for profile in PROFILES {
            for chunk in 0..device_tree_chunks(&profile) {
                let mut plc = Plc::plcsim_project();
                plc.corrupt_chunk = Some((functioncode::EXPLORE, chunk));
                let ((e, poisoned), served) = run(profile, plc, |mut conn| {
                    let e = conn.explore(DEVICE_TREE_RID, 1, 0, &[]).unwrap_err();
                    (e, conn.is_poisoned())
                });
                let at = format!("{} chunk {chunk}: {e}", profile.name);
                assert!(matches!(e, Error::Integrity(_)), "{at}");
                assert!(e.is_connection_lost() && poisoned, "{at}");
                assert_eq!(served.end, End::ClientClosed, "{at}");
            }
        }
    }

    // --- Phase 3: rejections -----------------------------------------------------------------

    /// Check that `e` is how the driver reports the FW 4.2 rejection notice, and that the mock
    /// sent it for `why`.
    fn assert_rejected(e: &Error, poisoned: bool, served: &Served, why: &'static str) {
        assert!(matches!(e, Error::Closed(_)), "{e}");
        assert!(e.to_string().contains("fatal SystemEvent"), "{e}");
        assert!(e.is_connection_lost() && poisoned, "{e}");
        assert_eq!(served.end, End::Rejected(why));
    }

    /// A GetMultiVariables of "Data_block_1".toto with the V1 ObjectQualifier layout, as the
    /// Python driver sent it in the field run: the key qualifier as a fixed `u32`, no terminator.
    fn v1_read(seq: u16) -> Vec<u8> {
        let mut req = proto::build_get_multi_request(seq, SESSION_ID, &[toto()], true, 9).unwrap();
        let v2 = [0x89, 0x6b, 0x00, 0x04, 0x00, 0x00];
        let at = req.windows(6).position(|w| w == v2).unwrap();
        req.splice(at + 4..at + 6, [0, 0, 0, 0]);
        req
    }

    #[test]
    fn fw42_refuses_a_v1_qualifier_with_the_notice_and_closes() {
        let ((e, poisoned, after), served) = run(FW42_1215C, Plc::plcsim_project(), |mut conn| {
            // The same read with the V2 layout (what the driver sends) works.
            assert_eq!(conn.read_variables(&[toto()]).unwrap().values.len(), 1);
            let e = conn.request_response(&v1_read(100)).unwrap_err();
            let after = conn.read_variables(&[toto()]).unwrap_err();
            (e, conn.is_poisoned(), after)
        });
        assert_rejected(&e, poisoned, &served, "V1 ObjectQualifier");
        assert!(matches!(after, Error::Closed(_)), "{after}");
    }

    #[test]
    fn fw42_refuses_the_db_wildcard_explore() {
        let ((e, poisoned), served) = run(FW42_1215C, Plc::plcsim_project(), |mut conn| {
            // The structured browse of the program (RID 3) works.
            assert_eq!(conn.datablock_list().unwrap().len(), 2);
            let e = conn.explore(DB_WILDCARD, 1, 0, &[]).unwrap_err();
            (e, conn.is_poisoned())
        });
        assert_rejected(&e, poisoned, &served, "DB wildcard explore");
    }

    #[test]
    fn the_qualifier_layouts_are_told_apart() {
        let v2 = proto::build_get_multi_request(5, SESSION_ID, &[toto()], true, 300).unwrap();
        for (req, want) in [(v2, Qualifier::V2), (v1_read(5), Qualifier::V1)] {
            let body = &req[4..req.len() - 4];
            let mut r = Reader::at(body, 14 + 4);
            let n = r.vlq();
            r.vlq();
            read_addresses(&mut r, n);
            let (layout, id) = qualifier_and_integrity_id(&mut r, 0, 4);
            assert_eq!(layout, want);
            assert_eq!(id, if want == Qualifier::V2 { 300 } else { 9 });
        }
    }

    // --- Phase 4: limits ---------------------------------------------------------------------

    #[test]
    fn plcsim_resets_a_request_over_1_kb_in_one_frame() {
        let (addr, mock) = spawn_mock(PLCSIM_FW28, Plc::plcsim_project());
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(&[0; 36]).unwrap(); // the CR (not checked)
        let mut cc = [0; 11];
        s.read_exact(&mut cc).unwrap();
        // One DT frame with a 1100-byte TPDU, unsegmented.
        let frame = dt_frame(&[0x72; 1097]);
        assert_eq!(frame.len() - 4, 1100);
        let _ = s.write_all(&frame);
        let mut buf = [0; 16];
        let answered = matches!(s.read(&mut buf), Ok(n) if n > 0);
        assert!(!answered, "the PLC answered");
        let served = mock.join().unwrap();
        assert_eq!(served.end, End::Reset("COTP frame over the TPDU size"));
    }

    #[test]
    fn the_driver_segments_requests_over_1_kb() {
        let (values, served) = run(PLCSIM_FW28, Plc::plcsim_project(), |mut conn| {
            conn.read_tags(&["Data_block_1.toto"; 100]).unwrap()
        });
        assert!(values.iter().all(|v| matches!(v, Ok(PValue::Int(0)))));
        let read = served.requests.iter().find(|r| r.items == 100).unwrap();
        assert!(read.dt_frames > 1, "{read:?}");
        assert_eq!(served.end, End::ClientClosed);
    }

    #[test]
    fn plcsim_refuses_more_than_100_items() {
        let (resp, served) = run(PLCSIM_FW28, Plc::plcsim_project(), |mut conn| {
            assert_eq!(conn.max_tags_per_read(), 100);
            // The driver splits a larger read to fit.
            let resp = conn.read_variables(&vec![toto(); 150]).unwrap();
            assert_eq!(resp.values.len(), 150);
            // One request over the limit, built by hand.
            let req = proto::build_get_multi_request(500, SESSION_ID, &vec![toto(); 101], true, 99)
                .unwrap();
            proto::parse_get_multi_response(&conn.request_response(&req).unwrap()).unwrap()
        });
        assert_eq!(resp.header.return_value, 0xa027_a600_007b_fffc);
        assert!(!resp.header.is_ok());
        assert!(resp.values.is_empty() && resp.errors.is_empty());
        let items: Vec<usize> = served.requests.iter().map(|r| r.items).collect();
        assert_eq!(items, [2, 100, 50, 101]);
    }

    #[test]
    fn plcsim_refuses_byte_access_to_an_optimized_db_or_past_the_end() {
        let ((), served) = run(PLCSIM_FW28, Plc::plcsim_project(), |mut conn| {
            conn.write_area(Area::Memory, 100, &[0xde, 0xad]).unwrap();
            assert_eq!(
                conn.read_area(Area::Memory, 99, 4).unwrap(),
                [0, 0xde, 0xad, 0]
            );
            let e = conn.read_area(Area::Db(1), 0, 2).unwrap_err().to_string();
            assert!(
                e.contains("0x82068d0002bfffc3") && e.contains("optimized"),
                "{e}"
            );
            let e = conn.read_area(Area::Memory, 16 * 1024 - 1, 2).unwrap_err();
            assert!(e.to_string().contains("0x82068d0002bfffc3"), "{e}");
            let e = conn.write_area(Area::Db(1), 0, &[1]).unwrap_err();
            assert!(e.to_string().contains("0x82068d000188ffc3"), "{e}");
            assert!(
                !conn.is_poisoned(),
                "an item error leaves the connection usable"
            );
            assert_eq!(conn.cpu_state().unwrap(), crate::CpuState::Run);
        });
        assert_eq!(served.plc.m_area[99..103], [0, 0xde, 0xad, 0]);
    }

    // --- Phase 5: the profiles end to end ----------------------------------------------------

    /// Connect, list the DBs, read, browse, write, explore something large, close: against
    /// every profile.
    #[test]
    fn a_session_works_against_every_profile() {
        for profile in PROFILES {
            let (out, served) = run(profile, Plc::plcsim_project(), |mut conn| {
                assert_eq!(conn.plc_description(), Some(profile.description));
                assert_eq!(conn.max_tags_per_read(), profile.tags_per_read as usize);
                assert_eq!(conn.max_tags_per_write(), profile.tags_per_write as usize);
                let dbs = conn.datablock_list()?;
                let names: Vec<&str> = dbs.iter().map(|d| d.name.as_str()).collect();
                assert_eq!(names, ["Data block.1", "Data_block_1"]);
                assert_eq!(dbs[1].ti_relid, 0x9200_0002);
                assert_eq!(conn.read_tag("Data_block_1.toto")?, PValue::Int(0));
                let vars = conn.browse_datablock(dbs[1].relid, dbs[1].ti_relid, &dbs[1].name)?;
                assert_eq!(vars.len(), 1);
                assert_eq!(vars[0].name, "Data_block_1.toto");
                assert_eq!(
                    conn.read_tag("\"Data block.1\".\"value.1\"")?,
                    PValue::Int(0)
                );
                conn.write_tag("Data_block_1.toto", PValue::Int(456))?;
                assert_eq!(conn.read_tag("Data_block_1.toto")?, PValue::Int(456));
                let tree = conn.explore(DEVICE_TREE_RID, 1, 0, &[])?;
                assert_eq!(tree.objects, device_tree_objects());
                if let Some(level) = profile.protection_level {
                    assert_eq!(conn.effective_protection_level()?, level);
                }
                conn.close()
            });
            let name = profile.name;
            out.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(served.end, End::ClientClosed, "{name}");
            // The write arrived as an Int (datatype 0x07), 456 = 0x01c8.
            assert_eq!(
                served.plc.symbol(0x8a0e_0002, &[9]),
                Some(&[0x00, 0x07, 0x01, 0xc8][..]),
                "{name}"
            );
            let last = served.requests.last().unwrap();
            assert_eq!(last.function, functioncode::DELETE_OBJECT, "{name}");
            if profile.keepalive_every.is_some() {
                assert!(served.keepalives > 0, "{name}");
            }
            // The mock accepts any IntegrityId; this records the driver's: each class counts
            // from 1 (the first, 1, is what FW 4.2 accepted in the s7tool logs).
            for set_class in [false, true] {
                let ids: Vec<u32> = served
                    .requests
                    .iter()
                    .filter(|r| {
                        let set = matches!(
                            r.function,
                            functioncode::SET_MULTI_VARIABLES | functioncode::DELETE_OBJECT
                        );
                        set == set_class
                    })
                    .map(|r| r.integrity_id.unwrap())
                    .collect();
                let want: Vec<u32> = (1..=ids.len() as u32).collect();
                assert_eq!(ids, want, "{name}, set class {set_class}");
            }
        }
    }

    #[test]
    fn a_request_the_mock_has_no_answer_for_fails_the_test() {
        let caught = std::panic::catch_unwind(|| {
            run(FW42_1215C, Plc::plcsim_project(), |mut conn| {
                let _ = conn.read_area(Area::Memory, 0, 1);
            })
        });
        let panic = caught.unwrap_err();
        let msg = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap_or_default();
        assert!(msg.contains("not measured"), "{msg}");
    }
}
