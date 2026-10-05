// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Reimplements thomas-v2/S7CommPlusDriver OpenSSL/OpenSSLConnector.cs + Native.cs
// using rustls (the OpenSSL P/Invoke layer is intentionally NOT ported).

//! TLS channel built on rustls in memory-buffer mode.
//!
//! The reference driver drives OpenSSL through memory BIOs: the app owns the socket and
//! pumps bytes through the BIOs. rustls' `read_tls` / `write_tls` / `process_new_packets`
//! is the same model, so the architecture ports ~1:1. Encrypted TLS records are carried
//! as the payload of COTP DT frames via [`IsoTcp`].
//!
//! Two protocol-critical details are reproduced byte-for-byte:
//!
//! * **Cipher suites / version:** TLS 1.3 only, `TLS_AES_256_GCM_SHA384` and
//!   `TLS_AES_128_GCM_SHA256`, matching the reference `SslActivate`.
//! * **Exported keying material (RFC 5705):** label `"EXPERIMENTAL_OMS"`, **no context**
//!   (`use_context = 0` → [`None`], *not* `Some(&[])`), 32 bytes — the linchpin for
//!   legitimation. One wrong byte means silent auth failure.
//!
//! The PLC presents a self-signed certificate. Unless one is pinned, any certificate is accepted,
//! as upstream does. That leaves the connection open to an **active** man-in-the-middle: it can
//! terminate TLS on both sides, so it knows both exported secrets and can read (and replay) the
//! legitimation payload — the plaintext password for a user login, or the SHA-1 of the
//! password, which is all the PLC checks, for a legacy one. The secret only binds legitimation
//! to *a* TLS session, not to the PLC. Pinning the certificate's SHA-256 fingerprint
//! (`Connection::connect_pinned`) closes that: the handshake then fails unless the peer presents
//! that certificate and signs with its key, much as TIA Portal has the user trust the PLC's
//! certificate.
//!
//! The client also honours `SSLKEYLOGFILE` whenever it is set, writing the session keys there
//! for Wireshark — leave it unset in production.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};

use crate::error::{Error, Result};
use crate::transport::tcp::IsoTcp;

/// RFC 5705 exporter label used to derive the legitimation key material.
pub const OMS_EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL_OMS";

/// Length of the exported keying material, in bytes.
pub const OMS_SECRET_LEN: usize = 32;

/// Placeholder SNI. The PLC ignores it (the accept-all verifier ignores the name too).
const DUMMY_SNI: &str = "s7-plc";

/// A rustls-backed TLS channel pumped over an [`IsoTcp`] transport.
pub(crate) struct TlsChannel {
    conn: rustls::ClientConnection,
}

impl TlsChannel {
    /// Build a new TLS client configured to match the reference driver.
    ///
    /// Honours `SSLKEYLOGFILE` (via [`rustls::KeyLogFile`]) so sessions can be decrypted
    /// in Wireshark — essential for confirming the exported secret against the C# driver.
    pub fn new(pin: Option<[u8; 32]>) -> Result<Self> {
        let base = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ],
            ..base
        };
        let algorithms = provider.signature_verification_algorithms;

        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PlcCertVerifier { algorithms, pin }))
            .with_no_client_auth();
        config.key_log = Arc::new(rustls::KeyLogFile::new());

        let server_name = ServerName::try_from(DUMMY_SNI)
            .map_err(|_| Error::framing("invalid server name"))?
            .to_owned();
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
        Ok(Self { conn })
    }

    /// Drive the TLS handshake to completion, pumping records over `tcp`.
    pub fn handshake(&mut self, tcp: &mut IsoTcp) -> Result<()> {
        loop {
            // Drain everything rustls wants to send (each flight as one ISO packet).
            while self.conn.wants_write() {
                let mut out = Vec::new();
                self.conn.write_tls(&mut out)?;
                if out.is_empty() {
                    break;
                }
                tcp.send_iso_packet(&out)?;
            }
            if !self.conn.is_handshaking() {
                break;
            }
            // Need more from the peer.
            let pkt = tcp.recv_iso_packet()?;
            self.feed_tls(&pkt)?;
        }
        Ok(())
    }

    /// The negotiated protocol version, cipher suite and the PLC certificate's fingerprint, for logs
    /// (the fingerprint identifies the device, so it is left out under [`crate::set_log_redaction`]).
    pub fn describe(&self) -> String {
        let fingerprint = match self.peer_certificate_sha256() {
            Some(_) if crate::logging::redacting() => "<certificate>".into(),
            Some(fp) => fp.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            None => "none".into(),
        };
        let version = self
            .conn
            .protocol_version()
            .map_or("?".into(), |v| format!("{v:?}"));
        let suite = self
            .conn
            .negotiated_cipher_suite()
            .map_or("?".into(), |s| format!("{:?}", s.suite()));
        format!("{version}, {suite}, PLC certificate SHA-256 {fingerprint}")
    }

    /// SHA-256 fingerprint of the certificate the PLC presented, once the handshake has run.
    pub fn peer_certificate_sha256(&self) -> Option<[u8; 32]> {
        self.conn
            .peer_certificates()
            .and_then(<[_]>::first)
            .map(fingerprint)
    }

    /// Export the 32-byte `EXPERIMENTAL_OMS` keying material (RFC 5705).
    ///
    /// Available only after the handshake completes.
    pub fn export_oms_secret(&self) -> Result<[u8; OMS_SECRET_LEN]> {
        let secret = [0u8; OMS_SECRET_LEN];
        // context = None reproduces OpenSSL's `use_context = 0` exactly.
        let secret = self
            .conn
            .export_keying_material(secret, OMS_EXPORTER_LABEL, None)?;
        Ok(secret)
    }

    /// Encrypt and send `plaintext` (a S7CommPlus telegram) over the channel.
    pub fn send(&mut self, tcp: &mut IsoTcp, plaintext: &[u8]) -> Result<()> {
        self.conn.writer().write_all(plaintext)?;
        while self.conn.wants_write() {
            let mut out = Vec::new();
            self.conn.write_tls(&mut out)?;
            if out.is_empty() {
                break;
            }
            tcp.send_iso_packet(&out)?;
        }
        Ok(())
    }

    /// Send the TLS `close_notify` alert, ending the TLS session cleanly.
    pub fn close(&mut self, tcp: &mut IsoTcp) -> Result<()> {
        self.conn.send_close_notify();
        while self.conn.wants_write() {
            let mut out = Vec::new();
            self.conn.write_tls(&mut out)?;
            if out.is_empty() {
                break;
            }
            tcp.send_iso_packet(&out)?;
        }
        Ok(())
    }

    /// Receive and decrypt the next chunk of application data.
    ///
    /// Returns whatever plaintext rustls yields once at least one byte is available;
    /// callers parse the S7CommPlus framing on top.
    pub fn recv(&mut self, tcp: &mut IsoTcp) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let pkt = tcp.recv_iso_packet()?;
            self.feed_tls(&pkt)?;
            let mut buf = [0u8; 4096];
            loop {
                match self.conn.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
        }
    }

    /// Feed received TLS record bytes into rustls and process them.
    fn feed_tls(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(data);
        while (cursor.position() as usize) < data.len() {
            let n = self.conn.read_tls(&mut cursor)?;
            if n == 0 {
                break;
            }
            self.conn.process_new_packets()?;
        }
        Ok(())
    }
}

/// SHA-256 fingerprint of a DER certificate.
fn fingerprint(cert: &CertificateDer<'_>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.as_ref()).into()
}

/// The PLC's certificate verifier. The PLC presents a self-signed certificate, which no CA
/// vouches for, so the only check possible is against a fingerprint the user pins.
///
/// Without a pin any certificate is accepted, as upstream does, and the handshake signature goes
/// unchecked too: it would only prove the peer holds the key of a certificate nobody vouched for.
/// With a pin the certificate must have that fingerprint, and the handshake must be signed with
/// its key, so a man in the middle can't replay the PLC's certificate without the key.
#[derive(Debug)]
struct PlcCertVerifier {
    algorithms: WebPkiSupportedAlgorithms,
    pin: Option<[u8; 32]>,
}

/// A PLC certificate whose fingerprint isn't the pinned one.
struct PinMismatch {
    expected: [u8; 32],
    got: [u8; 32],
}

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        write!(
            f,
            "the PLC's certificate has SHA-256 {}, not the pinned {}",
            hex(&self.got),
            hex(&self.expected)
        )
    }
}

// rustls shows certificate errors with `Debug`, so make that the readable message too.
impl std::fmt::Debug for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for PinMismatch {}

impl ServerCertVerifier for PlcCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match self.pin {
            Some(expected) if fingerprint(end_entity) != expected => {
                let mismatch = PinMismatch {
                    expected,
                    got: fingerprint(end_entity),
                };
                Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                    OtherError(Arc::new(mismatch)),
                )))
            }
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        match self.pin {
            Some(_) => rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms),
            None => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        match self.pin {
            Some(_) => rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms),
            None => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_is_exact() {
        // Guard against accidental edits: the label must be these 16 bytes exactly.
        assert_eq!(OMS_EXPORTER_LABEL, b"EXPERIMENTAL_OMS");
        assert_eq!(OMS_EXPORTER_LABEL.len(), 16);
    }

    #[test]
    fn client_config_builds() {
        // Exercises the provider/cipher-suite/verifier wiring without a network.
        let ch = TlsChannel::new(None).expect("TLS client config should build");
        // No handshake yet, so keying material must not be available.
        assert!(ch.export_oms_secret().is_err());
        assert_eq!(ch.peer_certificate_sha256(), None);
        assert!(TlsChannel::new(Some([7; 32])).is_ok());
    }

    #[test]
    fn a_pinned_verifier_accepts_only_that_certificate() {
        let verify = |pin, cert: &[u8]| {
            let verifier = PlcCertVerifier {
                algorithms: rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
                pin,
            };
            let name = ServerName::try_from(DUMMY_SNI).unwrap();
            verifier.verify_server_cert(
                &CertificateDer::from(cert),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
        };
        let cert = b"the PLC's DER certificate";
        let pin = fingerprint(&CertificateDer::from(&cert[..]));
        assert!(verify(Some(pin), cert).is_ok());
        assert!(verify(None, cert).is_ok());
        assert!(verify(None, b"any other certificate").is_ok());
        let e = verify(Some(pin), b"another PLC's certificate").unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("not the pinned"), "{msg}");
        assert!(
            msg.contains(&format!("{:02x}{:02x}", pin[0], pin[1])),
            "{msg}"
        );
    }

    #[test]
    fn the_fingerprint_is_sha256_of_the_der() {
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        assert_eq!(
            fingerprint(&CertificateDer::from(&b"abc"[..])),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }
}
