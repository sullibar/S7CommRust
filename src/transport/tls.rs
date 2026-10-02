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
//! The PLC presents a self-signed certificate, and an accept-all verifier is used, as upstream
//! does. That leaves the connection open to an **active** man-in-the-middle: it can terminate
//! TLS on both sides, so it knows both exported secrets and can read (and replay) the
//! legitimation payload — the plaintext password for a user login, or the SHA-1 of the
//! password, which is all the PLC checks, for a legacy one. The secret only binds legitimation
//! to *a* TLS session, not to the PLC. (TIA Portal, by contrast, has the user trust the PLC's
//! certificate.) Use it on networks you trust.
//!
//! The client also honours `SSLKEYLOGFILE` whenever it is set, writing the session keys there
//! for Wireshark — leave it unset in production.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

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
    pub fn new() -> Result<Self> {
        let base = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ],
            ..base
        };
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();

        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier { schemes }))
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

/// Accept-all server certificate verifier (the PLC uses a self-signed cert).
#[derive(Debug)]
struct AcceptAllVerifier {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
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
        let ch = TlsChannel::new().expect("TLS client config should build");
        // No handshake yet, so keying material must not be available.
        assert!(ch.export_oms_secret().is_err());
    }
}
