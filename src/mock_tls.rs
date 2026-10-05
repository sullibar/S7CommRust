// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! A mock TLS PLC on loopback, for tests of the TLS transport and of legitimation.
//!
//! It plays the PLC side of [`Connection::connect`]: the COTP handshake, InitSsl, a TLS 1.3
//! handshake (with the test-only certificate in `tests/vectors/tls`, which the unpinned client
//! accepts like any other), CreateObject and the session setup, and the limits read. Then each
//! test drives it with a script, through [`MockTlsPlc::recv_request`], [`MockTlsPlc::response`]
//! and the send functions, which can split a telegram into chunks, put a SystemEvent between
//! them or pack a large telegram into one ISO packet.
//!
//! Unlike [`crate::mock_plc`], nothing here is measured PLC behaviour beyond what the reference
//! driver and the crate's own parsers define; the tests use it for the client's side.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::connection::Connection;
use crate::proto::PObject;
use crate::value::PValue;
use crate::wire::pdu::{self, functioncode, ids, protocol_version};
use crate::wire::vlq;

const CERT: &[u8] = include_bytes!("../tests/vectors/tls/mock-plc-cert.der");
const KEY: &[u8] = include_bytes!("../tests/vectors/tls/mock-plc-key.pk8.der");

/// The session id the mock gives the client.
pub(crate) const SESSION_ID: u32 = 0x7000_0101;

/// The PLC side of a TLS connection.
pub(crate) struct MockTlsPlc {
    stream: TcpStream,
    tls: rustls::ServerConnection,
    /// Decrypted bytes not yet taken as a request.
    plain: Vec<u8>,
    /// Sequence number of the last request received.
    pub(crate) seq: u16,
}

/// A server config for the mock: TLS 1.3, the client's cipher suites, no session tickets.
fn server_config() -> Arc<rustls::ServerConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

/// `payload` as COTP DT frames of at most `max` bytes each, the last with the end-of-TSDU bit.
fn dt_frames(payload: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let parts: Vec<&[u8]> = payload.chunks(max).collect();
    for (i, part) in parts.iter().enumerate() {
        out.extend_from_slice(&[3, 0]);
        out.extend_from_slice(&((7 + part.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[2, 0xf0, if i + 1 == parts.len() { 0x80 } else { 0 }]);
        out.extend_from_slice(part);
    }
    out
}

impl MockTlsPlc {
    /// Accept the client and take it through COTP, InitSsl and the TLS handshake.
    fn accept(listener: &TcpListener) -> Self {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut cr = [0u8; 36];
        stream.read_exact(&mut cr).unwrap();
        stream
            .write_all(&[3, 0, 0, 11, 6, 0xd0, 0, 1, 0, 1, 0])
            .unwrap();
        let mut plc = MockTlsPlc {
            stream,
            tls: rustls::ServerConnection::new(server_config()).unwrap(),
            plain: Vec::new(),
            seq: 0,
        };
        // InitSsl, in plaintext.
        let init = plc.recv_tsdu();
        plc.seq = u16::from_be_bytes([init[11], init[12]]);
        let body = plc.response(functioncode::INIT_SSL, &[]);
        let framed = pdu::frame_single_pdu(protocol_version::V1, &body);
        plc.send_tsdu(&framed);
        // The TLS handshake.
        loop {
            plc.flush_tls();
            if !plc.tls.is_handshaking() {
                break;
            }
            let tsdu = plc.recv_tsdu();
            plc.feed(&tsdu);
        }
        plc
    }

    /// One TSDU from the client (its DT frames up to the end-of-TSDU bit).
    fn recv_tsdu(&mut self) -> Vec<u8> {
        let mut tsdu = Vec::new();
        loop {
            let mut hdr = [0u8; 4];
            self.stream.read_exact(&mut hdr).unwrap();
            let len = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
            let mut rest = vec![0u8; len - 4];
            self.stream.read_exact(&mut rest).unwrap();
            tsdu.extend_from_slice(&rest[3..]);
            if rest[2] & 0x80 != 0 {
                return tsdu;
            }
        }
    }

    /// Send `payload` as one TSDU (in DT frames of up to 8 KiB).
    fn send_tsdu(&mut self, payload: &[u8]) {
        let _ = self.stream.write_all(&dt_frames(payload, 8192));
    }

    /// Feed TLS bytes from the client into rustls and keep the plaintext.
    fn feed(&mut self, mut tls: &[u8]) {
        while !tls.is_empty() {
            self.tls.read_tls(&mut tls).unwrap();
            self.tls.process_new_packets().unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match self.tls.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => self.plain.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("mock TLS PLC: {e}"),
                }
            }
        }
    }

    /// The TLS records rustls has to send, as one byte string.
    fn take_tls(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Send what rustls has to send, as one TSDU.
    fn flush_tls(&mut self) {
        let out = self.take_tls();
        if !out.is_empty() {
            self.send_tsdu(&out);
        }
    }

    /// The next request telegram's body (its chunks' payloads), recording its sequence number.
    pub(crate) fn recv_request(&mut self) -> Vec<u8> {
        loop {
            if let Some((body, end)) = whole_telegram(&self.plain) {
                self.plain.drain(..end);
                self.seq = u16::from_be_bytes([body[7], body[8]]);
                return body;
            }
            let tsdu = self.recv_tsdu();
            self.feed(&tsdu);
        }
    }

    /// A successful response body to `function`, answering the last request, followed by `rest`.
    pub(crate) fn response(&self, function: u16, rest: &[u8]) -> Vec<u8> {
        let mut body = vec![pdu::opcode::RESPONSE, 0, 0];
        body.extend_from_slice(&function.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&self.seq.to_be_bytes());
        body.extend_from_slice(&[0, 0]); // transport flags, return value 0
        body.extend_from_slice(rest);
        body
    }

    /// Encrypt `plain` and send it as one TSDU.
    pub(crate) fn send_plain(&mut self, plain: &[u8]) {
        self.tls.writer().write_all(plain).unwrap();
        self.flush_tls();
    }

    /// Send `body` as one V2 telegram in one chunk.
    pub(crate) fn send(&mut self, body: &[u8]) {
        self.send_plain(&pdu::frame_single_pdu(protocol_version::V2, body));
    }

    /// Send `body` as a V2 telegram in chunks of at most `max` payload bytes, each chunk a TSDU
    /// of its own, with `between` (raw bytes, e.g. a SystemEvent) sent after the first chunk.
    pub(crate) fn send_chunked(&mut self, body: &[u8], max: usize, between: &[u8]) {
        let chunks = pdu::split_framed_pdu(&pdu::frame_single_pdu(protocol_version::V2, body), max);
        for (i, chunk) in chunks.iter().enumerate() {
            self.send_plain(chunk);
            if i == 0 && !between.is_empty() {
                self.send_plain(between);
            }
        }
    }

    /// Send the TLS `close_notify`, keeping the TCP connection open.
    pub(crate) fn close_notify(&mut self) {
        self.tls.send_close_notify();
        self.flush_tls();
    }

    /// Answer the session setup: CreateObject, its SetMultiVariables and the limits read.
    fn serve_session_setup(&mut self, description: &str) {
        let req = self.recv_request();
        assert_eq!(&req[3..5], &functioncode::CREATE_OBJECT.to_be_bytes());
        let mut session = PObject::new(SESSION_ID, ids::CLASS_SERVER_SESSION, 0);
        session.add_attribute(
            ids::SERVER_SESSION_VERSION,
            PValue::Struct {
                id: 314,
                elements: vec![(319, PValue::WString(description.into()))],
            },
        );
        let mut rest = vec![2];
        vlq::encode_u32(&mut rest, SESSION_ID).unwrap();
        vlq::encode_u32(&mut rest, SESSION_ID + 1).unwrap();
        session.serialize(&mut rest).unwrap();
        rest.extend_from_slice(&[0; 4]);
        let body = self.response(functioncode::CREATE_OBJECT, &rest);
        self.send_plain(&pdu::frame_single_pdu(protocol_version::V1, &body));

        let req = self.recv_request();
        assert_eq!(&req[3..5], &functioncode::SET_MULTI_VARIABLES.to_be_bytes());
        self.send(&self.response(functioncode::SET_MULTI_VARIABLES, &[0, 0]));

        let req = self.recv_request();
        assert_eq!(&req[3..5], &functioncode::GET_MULTI_VARIABLES.to_be_bytes());
        let mut rest = Vec::new();
        for item in [1u8, 2] {
            rest.push(item);
            PValue::DInt(100).serialize(&mut rest).unwrap();
        }
        rest.extend_from_slice(&[0, 0, 0]);
        self.send(&self.response(functioncode::GET_MULTI_VARIABLES, &rest));
    }
}

/// The body of the complete telegram at the start of `plain` and the bytes it takes, if it is
/// all there.
fn whole_telegram(plain: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut body = Vec::new();
    let mut i = 0;
    loop {
        let len = usize::from(u16::from_be_bytes([*plain.get(i + 2)?, *plain.get(i + 3)?]));
        if len == 0 {
            return Some((body, i + 4));
        }
        body.extend_from_slice(plain.get(i + 4..i + 4 + len)?);
        i += 4 + len;
    }
}

/// A TLS `Connection` to a mock PLC that describes itself as `description` (the
/// `ServerSessionVersion` text legitimation picks its scheme by), which runs `script` once the
/// session is set up.
pub(crate) fn mock_tls_connection(
    description: &str,
    timeout: Duration,
    script: impl FnOnce(MockTlsPlc) + Send + 'static,
) -> (Connection, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let description = description.to_string();
    let plc = std::thread::spawn(move || {
        let mut plc = MockTlsPlc::accept(&listener);
        plc.serve_session_setup(&description);
        script(plc);
    });
    let conn = Connection::connect(addr, timeout).unwrap();
    (conn, plc)
}

/// Pack `chunks` of plaintext into TLS records and send them all as ONE ISO packet: what a PLC
/// may do with a large response, and what overflowed rustls' plaintext buffer.
pub(crate) fn send_in_one_packet(plc: &mut MockTlsPlc, plain: &[u8]) {
    plc.tls.writer().write_all(plain).unwrap();
    let records = plc.take_tls();
    plc.send_tsdu(&records);
}
