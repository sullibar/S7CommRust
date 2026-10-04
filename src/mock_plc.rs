// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! A mock legacy (V3-digest) PLC on loopback, for tests.
//!
//! The mock starts where the login ends: it signs with the all-zero session key that
//! [`mock_session`] hands the client, since the real login needs Siemens' private key on the PLC
//! side. Each test scripts the PLC side with a closure ([`mock_connection`]).

use std::time::Duration;

use crate::connection::Connection;
use crate::proto::PObject;
use crate::transport::IsoTcp;
use crate::value::PValue;
use crate::wire::pdu::{self, functioncode};

/// A stand-in for a legacy (V3-digest) PLC on loopback, with the all-zero session key
/// [`mock_connection`] gives the client. Every reply is a single chunk, so its digest is the
/// plain [`packet_digest`](crate::legacy::digest::packet_digest).
pub(crate) struct MockPlc {
    pub(crate) stream: std::net::TcpStream,
    /// Sequence number of the last request received, which a response must echo.
    pub(crate) seq: u16,
}

impl MockPlc {
    /// Read one request TSDU and return its V2 body (the `data` of the V3 frame).
    pub(crate) fn recv_request(&mut self) -> Vec<u8> {
        use std::io::Read;
        let mut tsdu = Vec::new();
        loop {
            let mut hdr = [0u8; 4];
            self.stream.read_exact(&mut hdr).unwrap();
            let len = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
            let mut rest = vec![0u8; len - 4];
            self.stream.read_exact(&mut rest).unwrap();
            tsdu.extend_from_slice(&rest[3..]);
            if rest[2] & 0x80 != 0 {
                break;
            }
        }
        let body = tsdu[4 + 33..tsdu.len() - 4].to_vec();
        self.seq = u16::from_be_bytes([body[7], body[8]]);
        body
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
        let mut f = vec![3, 0];
        f.extend_from_slice(&((7 + v3.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[2, 0xf0, 0x80]);
        f.extend_from_slice(&v3);
        f
    }

    pub(crate) fn send(&mut self, body: &[u8]) {
        use std::io::Write;
        self.stream.write_all(&Self::frame(body)).unwrap();
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

/// The session the mock PLC's handshake would leave: the all-zero key [`MockPlc`] signs with.
pub(crate) fn mock_session() -> crate::legacy::session::LegacySession {
    crate::legacy::session::LegacySession {
        session_key: [0; 24],
        session_id: 0x7000_0001,
        session_id2: 0x7000_0002,
        plc_description: Some("1;6ES7 MOCK;V0.0".into()),
    }
}

/// A legacy `Connection` to a mock PLC that runs `script` after answering the limits read.
pub(crate) fn mock_connection(
    timeout: Duration,
    script: impl FnOnce(MockPlc) + Send + 'static,
) -> (Connection, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let plc = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut cr = [0u8; 36];
        stream.read_exact(&mut cr).unwrap();
        stream
            .write_all(&[3, 0, 0, 11, 6, 0xd0, 0, 1, 0, 1, 0])
            .unwrap();
        let mut plc = MockPlc { stream, seq: 0 };
        plc.answer_limits(100);
        script(plc);
    });
    let tcp = IsoTcp::connect(addr, timeout).unwrap();
    let conn = Connection::legacy_after_handshake(tcp, mock_session(), addr, timeout).unwrap();
    (conn, plc)
}
