// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Net/S7Client.cs + Net/MsgSocket.cs,
// LGPL-3.0-or-later.

//! Blocking TCP transport with TPKT (RFC 1006) + COTP (ISO 8073 class 0) framing.
//!
//! This mirrors the reference driver's `S7Client`/`MsgSocket`: it owns the socket and
//! exchanges ISO transport packets. The COTP connection is established with a Connection
//! Request (CR) / Connection Confirm (CC) handshake, after which payloads travel inside
//! COTP Data (DT) frames.
//!
//! Once TLS is activated, the *encrypted TLS record bytes* are themselves carried as the
//! payload of DT frames — this transport stays unchanged.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{Error, Result};

/// Default S7 / ISO-on-TCP port.
pub const ISO_TCP_PORT: u16 = 102;

/// Default calling (source) TSAP — the local TSAP value (`0x0600` in the reference driver).
pub const DEFAULT_CALLING_TSAP: u16 = 0x0600;

/// Default called (destination) TSAP for S7CommPlus: ASCII `"SIMATIC-ROOT-HMI"` (16 bytes).
pub const DEFAULT_CALLED_TSAP: &[u8; 16] = b"SIMATIC-ROOT-HMI";

const TPKT_HEADER_LEN: usize = 4;
const COTP_DT_HEADER: [u8; 3] = [0x02, 0xf0, 0x80]; // LI=2, DT, TPDU-NR + EOT
const COTP_PDU_TYPE_CR: u8 = 0xe0;
const COTP_PDU_TYPE_CC: u8 = 0xd0;
const COTP_PDU_TYPE_DT: u8 = 0xf0;

/// TPDU size proposed in the connection request (parameter value `0x0a` = 2^10 bytes).
const PROPOSED_TPDU_SIZE: usize = 1024;
/// COTP parameter code for the TPDU size (in the CR and the CC).
const COTP_PARAM_TPDU_SIZE: u8 = 0xc0;

/// A blocking ISO-on-TCP transport.
pub(crate) struct IsoTcp {
    stream: TcpStream,
    /// Largest payload one DT frame may carry: the negotiated TPDU size minus the DT header.
    max_dt_payload: usize,
    /// Bytes read from the socket but not yet consumed as a whole TPKT frame.
    rx: Vec<u8>,
    /// DT fragments of the TSDU being reassembled (no EOT seen yet).
    tsdu: Vec<u8>,
}

impl IsoTcp {
    /// Connect to `addr`, then perform the COTP CR/CC handshake using the default TSAPs.
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> Result<Self> {
        Self::connect_with_tsap(addr, DEFAULT_CALLING_TSAP, DEFAULT_CALLED_TSAP, timeout)
    }

    /// Connect and perform the COTP handshake with explicit TSAPs.
    pub fn connect_with_tsap<A: ToSocketAddrs>(
        addr: A,
        calling_tsap: u16,
        called_tsap: &[u8],
        timeout: Duration,
    ) -> Result<Self> {
        let mut last_err: Option<Error> = None;
        let mut stream = None;
        for sa in addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&sa, timeout) {
                Ok(s) => {
                    log::debug!("TCP connected to {sa}");
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    log::debug!("TCP connect to {sa} failed: {e}");
                    last_err = Some(e.into());
                }
            }
        }
        let stream = stream.ok_or_else(|| {
            last_err.unwrap_or_else(|| Error::framing("no socket addresses resolved"))
        })?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut this = IsoTcp {
            stream,
            max_dt_payload: PROPOSED_TPDU_SIZE - COTP_DT_HEADER.len(),
            rx: Vec::new(),
            tsdu: Vec::new(),
        };
        this.iso_connect(calling_tsap, called_tsap)?;
        Ok(this)
    }

    /// Perform the COTP Connection Request / Connection Confirm exchange.
    fn iso_connect(&mut self, calling_tsap: u16, called_tsap: &[u8]) -> Result<()> {
        let cr = build_cotp_cr(calling_tsap, called_tsap);
        self.stream.write_all(&cr)?;
        self.stream.flush()?;

        let frame = self.recv_tpkt_frame()?;
        // frame = COTP (starting at LI byte) ... ; byte[1] is the PDU type.
        if frame.len() < 2 {
            return Err(Error::framing("COTP confirm too short"));
        }
        if frame[1] != COTP_PDU_TYPE_CC {
            return Err(Error::framing(format!(
                "expected COTP CC (0x{COTP_PDU_TYPE_CC:02x}), got 0x{:02x}",
                frame[1]
            )));
        }
        // The PLC may confirm a smaller TPDU than we proposed, never a larger one.
        let tpdu = confirmed_tpdu_size(&frame)
            .unwrap_or(PROPOSED_TPDU_SIZE)
            .min(PROPOSED_TPDU_SIZE);
        log::debug!("COTP connected, TPDU size {tpdu}");
        self.max_dt_payload = tpdu - COTP_DT_HEADER.len();
        Ok(())
    }

    /// Send `payload` as one or more COTP DT frames, each within the negotiated TPDU size, with
    /// the EOT bit set only on the final frame. A frame over the TPDU size makes the PLC drop the
    /// connection (seen on legacy requests over ~1 KB; the TLS path also splits at the
    /// S7CommPlus level, so its records already fit).
    pub fn send_iso_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut pos = 0;
        loop {
            let remaining = payload.len() - pos;
            let chunk = remaining.min(self.max_dt_payload);
            let is_last = pos + chunk >= payload.len();

            let total = TPKT_HEADER_LEN + COTP_DT_HEADER.len() + chunk;
            let mut frame = Vec::with_capacity(total);
            frame.push(0x03);
            frame.push(0x00);
            frame.extend_from_slice(&(total as u16).to_be_bytes());
            frame.push(COTP_DT_HEADER[0]);
            frame.push(COTP_DT_HEADER[1]);
            // TPDU-NR + EOT byte: 0x80 marks end-of-TSDU, 0x00 marks "more follow".
            frame.push(if is_last { 0x80 } else { 0x00 });
            frame.extend_from_slice(&payload[pos..pos + chunk]);

            self.stream.write_all(&frame)?;
            pos += chunk;
            if is_last {
                break;
            }
        }
        self.stream.flush()?;
        Ok(())
    }

    /// Receive a complete ISO payload, reassembling COTP DT fragments until EOT.
    ///
    /// Resumable: a read timeout keeps the fragments and bytes received so far, and the next call
    /// continues the same frame. (Losing them would leave the stream out of step, which is what a
    /// timeout while polling for notifications used to do.)
    pub fn recv_iso_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let frame = self.recv_tpkt_frame()?;
            // frame layout: [LI][PDU type][...]. For DT: [0x02][0xF0][TPDU-NR+EOT][data..].
            if frame.len() < 3 {
                return Err(Error::framing("COTP DT frame too short"));
            }
            if frame[1] != COTP_PDU_TYPE_DT {
                return Err(Error::framing(format!(
                    "expected COTP DT (0x{COTP_PDU_TYPE_DT:02x}), got 0x{:02x}",
                    frame[1]
                )));
            }
            let li = frame[0] as usize; // length indicator counts bytes after itself
            let data_start = 1 + li;
            if data_start > frame.len() {
                return Err(Error::framing("COTP header length indicator out of range"));
            }
            let eot = frame[2] & 0x80 != 0;
            self.tsdu.extend_from_slice(&frame[data_start..]);
            if eot {
                return Ok(std::mem::take(&mut self.tsdu));
            }
            if self.tsdu.len() > crate::wire::pdu::MAX_TELEGRAM_LEN {
                return Err(Error::framing("COTP TSDU exceeds the reassembly size cap"));
            }
        }
    }

    /// Read one TPKT frame and return the COTP portion (everything after the 4-byte
    /// TPKT header, starting at the COTP length-indicator byte).
    ///
    /// Bytes are read into `rx` and only consumed once the whole frame is there, so a
    /// read timeout part-way through loses nothing.
    fn recv_tpkt_frame(&mut self) -> Result<Vec<u8>> {
        loop {
            if let [version, _, hi, lo, ..] = self.rx[..] {
                if version != 0x03 {
                    return Err(Error::framing(format!("bad TPKT version 0x{version:02x}")));
                }
                let total = usize::from(u16::from_be_bytes([hi, lo]));
                if total < TPKT_HEADER_LEN {
                    return Err(Error::framing("TPKT length smaller than header"));
                }
                if self.rx.len() >= total {
                    let frame = self.rx[TPKT_HEADER_LEN..total].to_vec();
                    self.rx.drain(..total);
                    return Ok(frame);
                }
            }
            let mut buf = [0u8; 8192];
            let n = match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed by the PLC",
                    )))
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            self.rx.extend_from_slice(&buf[..n]);
        }
    }
}

/// The TPDU size a COTP Connection Confirm carries (`frame` starts at the length indicator):
/// parameters follow the 6 fixed bytes after it, each as code, length, value.
fn confirmed_tpdu_size(frame: &[u8]) -> Option<usize> {
    let end = (1 + usize::from(*frame.first()?)).min(frame.len());
    let mut params = frame.get(7..end)?;
    while let [code, len, rest @ ..] = params {
        let (value, tail) = rest.split_at_checked(usize::from(*len))?;
        if *code == COTP_PARAM_TPDU_SIZE {
            // 2^7 = 128 .. 2^13 = 8192 are the sizes ISO 8073 defines.
            return match value {
                [exp @ 7..=13] => Some(1 << exp),
                _ => None,
            };
        }
        params = tail;
    }
    None
}

/// Build the COTP Connection Request telegram (TPKT + COTP CR with TSAP parameters).
fn build_cotp_cr(calling_tsap: u16, called_tsap: &[u8]) -> Vec<u8> {
    // COTP fixed part after the length indicator: CR, DST-REF(0), SRC-REF(1), class 0.
    let mut cotp = vec![
        COTP_PDU_TYPE_CR,
        0x00,
        0x00, // DST-REF
        0x00,
        0x01, // SRC-REF
        0x00, // class / option
    ];
    // Parameter: TPDU size, len 1, value 0x0a = 1024 bytes (PROPOSED_TPDU_SIZE).
    cotp.extend_from_slice(&[COTP_PARAM_TPDU_SIZE, 0x01, 0x0a]);
    // Parameter: calling (source) TSAP (0xC1), len 2.
    cotp.push(0xc1);
    cotp.push(0x02);
    cotp.extend_from_slice(&calling_tsap.to_be_bytes());
    // Parameter: called (destination) TSAP (0xC2), len N.
    cotp.push(0xc2);
    cotp.push(called_tsap.len() as u8);
    cotp.extend_from_slice(called_tsap);

    // Length indicator = number of bytes after the LI byte itself.
    let li = cotp.len() as u8;
    let total = TPKT_HEADER_LEN + 1 + cotp.len();

    let mut frame = Vec::with_capacity(total);
    frame.push(0x03);
    frame.push(0x00);
    frame.extend_from_slice(&(total as u16).to_be_bytes());
    frame.push(li);
    frame.extend_from_slice(&cotp);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_telegram_matches_reference() {
        let cr = build_cotp_cr(DEFAULT_CALLING_TSAP, DEFAULT_CALLED_TSAP);
        // TPKT length = 0x24 (36), COTP LI = 0x1f (31).
        assert_eq!(&cr[0..4], &[0x03, 0x00, 0x00, 0x24]);
        assert_eq!(cr[4], 0x1f);
        assert_eq!(cr[5], COTP_PDU_TYPE_CR);
        // calling TSAP 0x0600
        assert_eq!(&cr[14..18], &[0xc1, 0x02, 0x06, 0x00]);
        // called TSAP "SIMATIC-ROOT-HMI"
        assert_eq!(cr[18], 0xc2);
        assert_eq!(cr[19], 0x10);
        assert_eq!(&cr[20..36], b"SIMATIC-ROOT-HMI");
        assert_eq!(cr.len(), 36);
    }

    #[test]
    fn confirmed_tpdu_size_parses_the_cc_parameter() {
        // LI, CC, dst-ref, src-ref, class, then TPDU size 2^9 and a calling TSAP.
        let cc = [9 + 4, 0xd0, 0, 1, 0, 1, 0, 0xc0, 1, 9, 0xc1, 2, 6, 0];
        assert_eq!(confirmed_tpdu_size(&cc), Some(512));
        assert_eq!(confirmed_tpdu_size(&[6, 0xd0, 0, 1, 0, 1, 0]), None); // no parameters
        assert_eq!(
            confirmed_tpdu_size(&[9, 0xd0, 0, 1, 0, 1, 0, 0xc0, 1, 30]),
            None
        );
        assert_eq!(
            confirmed_tpdu_size(&[9, 0xd0, 0, 1, 0, 1, 0, 0xc0, 5]),
            None
        ); // truncated
    }

    #[test]
    fn large_payloads_are_segmented_to_the_confirmed_tpdu_size() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // A fake PLC: confirm a 512-byte TPDU, then record the DT frames of one TSDU.
        let plc = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut cr = [0u8; 36];
            s.read_exact(&mut cr).unwrap();
            s.write_all(&[3, 0, 0, 14, 9, 0xd0, 0, 1, 0, 1, 0, 0xc0, 1, 9])
                .unwrap();
            let mut frames = Vec::new();
            loop {
                let mut hdr = [0u8; 4];
                s.read_exact(&mut hdr).unwrap();
                let mut rest = vec![0u8; usize::from(u16::from_be_bytes([hdr[2], hdr[3]])) - 4];
                s.read_exact(&mut rest).unwrap();
                let eot = rest[2] & 0x80 != 0;
                frames.push((rest.len(), eot));
                if eot {
                    return frames;
                }
            }
        });
        let mut tcp = IsoTcp::connect(addr, Duration::from_secs(5)).unwrap();
        tcp.send_iso_packet(&[0xab; 1200]).unwrap();
        // COTP TPDUs of at most 512 bytes (3-byte DT header + 509 data), EOT only on the last.
        assert_eq!(
            plc.join().unwrap(),
            vec![(512, false), (512, false), (3 + 1200 - 2 * 509, true)]
        );
    }

    /// A fake PLC that accepts one connection, confirms it, and hands the socket to `script`.
    fn fake_plc(
        script: impl FnOnce(TcpStream) + Send + 'static,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut cr = [0u8; 36];
            s.read_exact(&mut cr).unwrap();
            s.write_all(&[3, 0, 0, 11, 6, 0xd0, 0, 1, 0, 1, 0]).unwrap();
            script(s);
        });
        (addr, handle)
    }

    #[test]
    fn a_timeout_mid_frame_resumes_where_it_stopped() {
        // Two DT fragments of one TSDU; the PLC stalls inside the first frame and between them.
        let first: Vec<u8> = [&[3, 0, 0, 10, 2, 0xf0, 0x00][..], b"abc"].concat();
        let second: Vec<u8> = [&[3, 0, 0, 9, 2, 0xf0, 0x80][..], b"de"].concat();
        let (addr, plc) = fake_plc(move |mut s| {
            s.write_all(&first[..5]).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            s.write_all(&first[5..]).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            s.write_all(&second).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let mut tcp = IsoTcp::connect(addr, Duration::from_millis(150)).unwrap();
        let mut timeouts = 0;
        let payload = loop {
            match tcp.recv_iso_packet() {
                Ok(p) => break p,
                Err(e) if e.is_timeout() => timeouts += 1,
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(payload, b"abcde");
        assert!(
            timeouts >= 2,
            "expected the stalls to time out, got {timeouts}"
        );
        plc.join().unwrap();
    }
}
