// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver S7CommPlusConnection.cs, LGPL-3.0-or-later.

//! High-level connection orchestration (`S7CommPlusConnection`).
//!
//! Drives the connect sequence:
//!
//! 1. TCP + COTP connect.
//! 2. Unencrypted `InitSsl` bootstrap.
//! 3. TLS 1.3 handshake (everything after is encrypted).
//! 4. `CreateObject` → server session.
//!
//! Legitimation and the data operations (Explore, Get/SetMultiVariables) build on the
//! `request_response` helper and follow.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::legitimation::{build_legitimation_payload, crypto};
use crate::proto::item_address::{CONTROLLER_AREA_VALUE_ACTUAL, DB_VALUE_ACTUAL};
use crate::proto::object::PObject;
use crate::proto::{
    self, Area, CreateObjectResponse, GetMultiVariablesResponse, GetVarSubstreamedResponse,
    ItemAddress, SetMultiVariablesResponse, SetVariableResponse,
};
use crate::transport::{IsoTcp, TlsChannel};
use crate::value::strings::{decode_s7_string, decode_wstring, encode_s7_string, encode_wstring};
use crate::value::PValue;
use crate::wire::pdu::{self, functioncode, ids, protocol_version};

/// Controller areas browsable by symbol: `(AccessArea RID, type-info relid, label)`, in the
/// order the reference tries them (M, then Q, then I).
const CONTROLLER_AREAS: [(u32, u32, &str); 3] = [
    (82, 0x9003_0000, "MArea"),
    (81, 0x9002_0000, "QArea"),
    (80, 0x9001_0000, "IArea"),
];
/// Class id of a data-block object in an Explore of the PLC program.
const DB_CLASS_RID: u32 = 2574;
/// RID of the PLC program object (Explore root for browsing).
const PLC_PROGRAM_RID: u32 = 3;
/// Attribute id `ObjectVariableTypeName` (an object's name).
const OBJECT_VARIABLE_TYPE_NAME: u32 = 233;
/// Attributes requested when browsing for data blocks (so DB objects are returned).
const BROWSE_ATTRS: [u32; 3] = [
    OBJECT_VARIABLE_TYPE_NAME,
    2521, /* BlockNumber */
    4288, /* Comment */
];
/// RID of the OMS type-info container (`Ids.ObjectOMSTypeInfoContainer`) — one Explore returns
/// every block's type info at once.
const OMS_TYPE_INFO_CONTAINER_RID: u32 = 537;
/// Recursion guard for the browse walk (nested structs; S7 types are not cyclic).
const MAX_BROWSE_DEPTH: usize = 16;
/// How many variables to read per `GetMultiVariables` request when reading a browsed batch, at
/// most. 48 was the measured sweet spot on a live S7-1200 (~12% faster than 32); the batch is also
/// capped at the PLC's own item limit. [`Connection::read_var_values`] adaptively splits any batch
/// a PLC refuses, so a larger value never loses data — it just costs a retry. Override with
/// `S7_READ_BATCH`.
const READ_BATCH: usize = 48;
/// Items per Get/SetMultiVariables request until the PLC's own limits are read (the reference's
/// `CommRessources` default).
const DEFAULT_TAGS_PER_REQUEST: usize = 20;
/// RID of the CPU's execution unit (`NativeObjects.theCPUexecUnit_Rid`).
const CPU_EXEC_UNIT_RID: u32 = 52;
/// The execution unit's attribute holding its operating state (a struct).
const CPU_OPERATING_STATE: u32 = 2237;
/// The member of [`CPU_OPERATING_STATE`] holding the classic S7 operating-state code.
const CPU_OPERATING_STATE_CODE: u32 = 3486;

/// The CPU's operating state, from [`Connection::cpu_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuState {
    /// RUN: the user program is executing.
    Run,
    /// STOP.
    Stop,
    /// Any other classic S7 operating-state code (a startup or hold state, for example), as the
    /// PLC reported it.
    Other(i32),
}

/// A discovered data block: its name, object relation id, number, and type-info relation id.
#[derive(Debug, Clone)]
pub struct DataBlock {
    /// The block's symbolic name (e.g. `"Data_block_1"`).
    pub name: String,
    /// The block's object relation id (used as the access area for its tags).
    pub relid: u32,
    /// The DB number (the `N` in `DBN`).
    pub number: u32,
    /// Relation id of the block's type-info object (its member layout).
    pub ti_relid: u32,
}

/// A variable discovered by the browse walk (or resolved by [`Connection::resolve_var`]): its
/// fully-qualified symbol path, the access address parts, and its datatype. Read/write it via
/// [`VarInfo::address`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarInfo {
    /// Fully-qualified symbol path (e.g. `"Motor_DB.axis[2].speed"`; area tags have no DB prefix).
    /// Levels containing `.`, `[` or `]` are double-quoted, so the path round-trips through
    /// [`Connection::resolve_symbol`].
    pub name: String,
    /// `AccessArea` — the DB relation id, or the M/Q/I area RID.
    pub access_area: u32,
    /// `AccessSubArea` — `DB_ValueActual` for DBs, `ControllerArea_ValueActual` for M/Q/I.
    pub access_sub_area: u32,
    /// The access LID sequence.
    pub lids: Vec<u32>,
    /// The member's softdatatype (1=Bool, 7=DInt, 8=Real, 19=String, 62=WString, …; see
    /// [`crate::value::datatype::softdatatype`]).
    pub softdatatype: u8,
    /// Declared max length for `String`/`WString` members (0 otherwise).
    pub string_max_len: u16,
}

impl VarInfo {
    /// The [`ItemAddress`] to read or write this variable.
    pub fn address(&self) -> ItemAddress {
        ItemAddress {
            symbol_crc: 0,
            access_area: self.access_area,
            access_sub_area: self.access_sub_area,
            lid: self.lids.clone(),
        }
    }
}

/// A handle to an active subscription on the PLC. Poll it with [`Connection::next_notification`].
/// The subscription lives until [`Connection::delete_subscription`] or the connection is dropped;
/// the connection tracks its credit, so the handle is a plain id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscription {
    /// The subscription object id the PLC allocated.
    pub object_id: u32,
}

/// Most notifications kept for subscriptions that are not being polled right now (see
/// [`Connection::next_notification`]); past this the oldest is dropped.
const MAX_QUEUED_NOTIFICATIONS: usize = 4096;

/// Length of a legacy real-PLC public key (the bundled keys and [`Connection::connect_real_plc_with_key`]).
const REAL_PLC_PUBLIC_KEY_LEN: usize = 40;

/// A resolved symbol: its address and the leaf member's type-info element (none for a bare DB).
type ResolvedSymbol = (ItemAddress, Option<crate::proto::VartypeElement>);

/// Default per-operation socket timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A connected S7CommPlus session.
pub struct Connection {
    tcp: IsoTcp,
    /// TLS channel: `Some` for the TLS transport, `None` for the legacy non-TLS transport.
    tls: Option<TlsChannel>,
    /// Buffered TLS plaintext awaiting telegram deframing (TLS transport only).
    rbuf: Vec<u8>,
    /// Read cursor into `rbuf`: bytes before this are consumed. Avoids re-shifting the buffer on
    /// every chunk (the buffer is cleared once a telegram is fully consumed).
    rpos: usize,
    /// Session key for the legacy non-TLS transport. `Some` ⇒ legacy mode: requests are wrapped
    /// in the ProtocolVersion-0x03 per-PDU HMAC digest framing instead of going through TLS.
    legacy_session_key: Option<[u8; 24]>,
    session_id: u32,
    session_id2: u32,
    sequence_number: u16,
    /// Integrity id counter for "get"-class requests.
    integrity_id: u32,
    /// Integrity id counter for "set"-class requests (Set*/Delete/CreateObject).
    integrity_id_set: u32,
    /// Whether requests carry an integrity id (enabled after the session exists).
    with_integrity: bool,
    /// Cache of type-info objects by relation id (populated lazily during browsing).
    type_info_cache: HashMap<u32, Arc<PObject>>,
    /// Whether the whole type-info container is in [`Self::type_info_cache`] already, so
    /// [`Connection::prefetch_type_container`] needn't fetch it again.
    type_container_prefetched: bool,
    /// Cached data-block list (lazily populated by [`Connection::datablock_list`]).
    db_list: Option<Arc<[DataBlock]>>,
    /// Resolved symbols, so a repeated [`Connection::read_tag`] / `write_tag` of the same name
    /// skips the walk through the type info.
    symbol_cache: HashMap<String, ResolvedSymbol>,
    /// Set once a request/response fails partway through. A poisoned connection has an
    /// unknown sequence/integrity-id state relative to the PLC, so every subsequent
    /// [`Connection::request_response`] short-circuits with [`Error::Closed`].
    poisoned: bool,
    /// How this connection was established, so [`Connection::reconnect`] can re-create it.
    reconnect_target: ReconnectTarget,
    /// When set, read operations transparently reconnect + retry once on a lost connection.
    auto_reconnect: bool,
    /// Notification telegrams (with their subscription id) received while waiting for something
    /// else — a response, or another subscription's notification; delivered in order by
    /// [`Connection::next_notification`].
    pending_notifications: VecDeque<(u32, Vec<u8>)>,
    /// Current credit limit of each finite-credit subscription, topped up as notifications arrive.
    credit_limits: HashMap<u32, i16>,
    /// Legacy transport: a telegram whose chunks are still arriving (kept across a read timeout,
    /// like the TLS path's `rbuf`).
    legacy_partial: crate::legacy::session::PartialResponse,
    /// Most items the PLC accepts in one GetMultiVariables (`SystemLimits`, read at connect).
    max_read_tags: usize,
    /// Most items the PLC accepts in one SetMultiVariables (`SystemLimits`, read at connect).
    max_write_tags: usize,
    /// The PLC's description of itself in its `ServerSessionVersion` (see
    /// [`Connection::plc_description`]).
    plc_description: Option<String>,
    /// Keep the next request's contents out of the log (it carries credentials).
    redact_next_request: bool,
}

/// Captures how a [`Connection`] was created so it can be re-established after a network drop.
#[derive(Debug, Clone)]
enum ReconnectTarget {
    Tls {
        addrs: Vec<SocketAddr>,
        timeout: Duration,
        /// The pinned certificate fingerprint, if any (see [`Connection::connect_pinned`]).
        pin: Option<[u8; 32]>,
    },
    LegacyPlcsim {
        addrs: Vec<SocketAddr>,
        timeout: Duration,
    },
    RealPlc {
        addrs: Vec<SocketAddr>,
        timeout: Duration,
        /// The public key that authenticated (so reconnect skips the auto-key trial). `None`
        /// means "auto-detect/look up by fingerprint again".
        key: Option<Vec<u8>>,
    },
}

impl Connection {
    /// Connect to a PLC at `addr` and drive the sequence through session creation.
    ///
    /// Any certificate the PLC presents is accepted (it is self-signed), so an active man in the
    /// middle can impersonate the PLC and read the legitimation payload;
    /// [`Connection::connect_pinned`] prevents that.
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> Result<Self> {
        Self::connect_tls(addr.to_socket_addrs()?.collect(), timeout, None)
    }

    /// Like [`Connection::connect`], but only to the PLC whose TLS certificate has the SHA-256
    /// fingerprint `certificate_sha256`, which must also have signed the handshake. Anything
    /// else fails the handshake with [`Error::Tls`]. Learn the fingerprint from
    /// [`Connection::peer_certificate_sha256`] on a connection over a network you trust (or from
    /// the certificate TIA Portal shows); the PLC keeps its certificate across restarts, but a new
    /// one comes with a hardware configuration that changes it.
    pub fn connect_pinned<A: ToSocketAddrs>(
        addr: A,
        timeout: Duration,
        certificate_sha256: [u8; 32],
    ) -> Result<Self> {
        Self::connect_tls(
            addr.to_socket_addrs()?.collect(),
            timeout,
            Some(certificate_sha256),
        )
    }

    fn connect_tls(
        addrs: Vec<SocketAddr>,
        timeout: Duration,
        pin: Option<[u8; 32]>,
    ) -> Result<Self> {
        let mut tcp = IsoTcp::connect(addrs.as_slice(), timeout)?;

        // Step 2: unencrypted InitSsl bootstrap (sequence number 1).
        let init_req = proto::init_ssl_request_default();
        log::debug!("→ InitSsl ({} bytes)", init_req.len());
        log::trace!("→ {}", pdu::Hex(&init_req));
        tcp.send_iso_packet(&init_req)?;
        let init_resp_bytes = tcp.recv_iso_packet()?;
        log::trace!("← {}", pdu::Hex(&init_resp_bytes));
        let init_resp = proto::parse_init_ssl_response(&init_resp_bytes)?;
        if !init_resp.is_ok() {
            return Err(Error::protocol(format!(
                "InitSsl rejected: return_value=0x{:016x}",
                init_resp.return_value
            )));
        }

        // Step 3: TLS handshake.
        let mut tls = TlsChannel::new(pin)?;
        tls.handshake(&mut tcp)?;
        log::info!("TLS: {}", tls.describe());

        let mut conn = Connection {
            tcp,
            tls: Some(tls),
            rbuf: Vec::new(),
            rpos: 0,
            legacy_session_key: None,
            session_id: ids::OBJECT_NULL_SERVER_SESSION,
            session_id2: 0,
            sequence_number: 1, // InitSsl consumed sequence number 1
            integrity_id: 0,
            integrity_id_set: 0,
            with_integrity: false,
            type_info_cache: HashMap::new(),
            type_container_prefetched: false,
            db_list: None,
            symbol_cache: HashMap::new(),
            poisoned: false,
            reconnect_target: ReconnectTarget::Tls {
                addrs,
                timeout,
                pin,
            },
            auto_reconnect: false,
            pending_notifications: VecDeque::new(),
            credit_limits: HashMap::new(),
            legacy_partial: Default::default(),
            max_read_tags: DEFAULT_TAGS_PER_REQUEST,
            max_write_tags: DEFAULT_TAGS_PER_REQUEST,
            plc_description: None,
            redact_next_request: false,
        };

        // Step 4: CreateObject → session.
        let create_resp = conn.create_session()?;
        conn.plc_description = create_resp.plc_description();
        log::info!(
            "session 0x{:08x}; PLC describes itself as {:?}",
            conn.session_id,
            conn.plc_description
        );
        log::debug!(
            "ServerSessionVersion: {:?}",
            create_resp.server_session_version()
        );
        // Step 4b: SetMultiVariables session setup — echo ServerSessionVersion (306) back.
        // The PLC rejects later requests (Explore, reads) until this completes.
        let server_session_version =
            create_resp
                .server_session_version()
                .cloned()
                .ok_or_else(|| {
                    Error::protocol("CreateObject response missing ServerSessionVersion (306)")
                })?;
        conn.setup_session(&server_session_version)?;
        // Subsequent requests carry an integrity id.
        conn.with_integrity = true;
        conn.read_request_limits()?;
        Ok(conn)
    }

    /// Connect to a **legacy** (pre-TLS, S7-1500 FW < 2.9) PLC: TCP + COTP, then plaintext
    /// `CreateObject` and the PlcSim challenge-response authentication. After this, every request
    /// is wrapped in the ProtocolVersion-`0x03` per-PDU HMAC-SHA256 digest framing instead of
    /// TLS. All the high-level operations (`read_tag`, `browse`, …) then work unchanged.
    ///
    /// Hardware-validated on an S7-PLCSIM **Advanced** FW2.8 instance.
    pub fn connect_legacy<A: ToSocketAddrs>(addr: A, timeout: Duration) -> Result<Self> {
        let addrs: Vec<std::net::SocketAddr> = addr.to_socket_addrs()?.collect();
        let mut tcp = IsoTcp::connect(addrs.as_slice(), timeout)?;
        let session = crate::legacy::session::handshake(&mut tcp, &mut |b| {
            getrandom::getrandom(b).expect("OS CSPRNG")
        })?;
        let target = ReconnectTarget::LegacyPlcsim { addrs, timeout };
        Self::new_legacy(tcp, session, target)
    }

    /// Connect to a **real** S7-1200/1500 on legacy (pre-TLS) firmware. The key family (`00:`
    /// = S7-1500, `01:` = S7-1200) and the PLC's public key are auto-detected from the fingerprint
    /// in the `CreateObject` response and looked up in the bundled key store. If the PLC uses
    /// a key that isn't bundled, use
    /// [`Self::connect_real_plc_with_key`]. After auth, the transport and all high-level operations
    /// are identical to [`Self::connect_legacy`].
    ///
    /// **Status:** the auth crypto and request assembly are validated offline (byte-exact vs the
    /// `AuthenticateRealPlc` golden vectors); the *live* handshake against physical hardware has
    /// not yet been verified (no real `00:`/`01:` unit was available).
    pub fn connect_real_plc<A: ToSocketAddrs>(addr: A, timeout: Duration) -> Result<Self> {
        Self::connect_real_plc_impl(addr, timeout, None)
    }

    /// Like [`Self::connect_real_plc`] but with an explicit 40-byte `public_key` (for a PLC whose
    /// key is not in the bundled store). The family is still auto-detected from the fingerprint.
    pub fn connect_real_plc_with_key<A: ToSocketAddrs>(
        addr: A,
        timeout: Duration,
        public_key: &[u8],
    ) -> Result<Self> {
        if public_key.len() != REAL_PLC_PUBLIC_KEY_LEN {
            return Err(Error::Crypto(format!(
                "real-PLC public key must be {REAL_PLC_PUBLIC_KEY_LEN} bytes (got {})",
                public_key.len()
            )));
        }
        Self::connect_real_plc_impl(addr, timeout, Some(public_key))
    }

    fn connect_real_plc_impl<A: ToSocketAddrs>(
        addr: A,
        timeout: Duration,
        public_key: Option<&[u8]>,
    ) -> Result<Self> {
        use crate::legacy::realplc::{real_plc_handshake, RealPlcOutcome};
        // Resolve once so we can reconnect: a wrong key makes the PLC reset the connection.
        let addrs: Vec<std::net::SocketAddr> = addr.to_socket_addrs()?.collect();
        let mut rng = |b: &mut [u8]| getrandom::getrandom(b).expect("OS CSPRNG");

        // Phase 1: try the explicit/auto-looked-up key; discover the family if none is bundled.
        let mut tcp = IsoTcp::connect(addrs.as_slice(), timeout)?;
        let family = match real_plc_handshake(&mut tcp, public_key, &mut rng)? {
            RealPlcOutcome::Authenticated(session) => {
                let target = ReconnectTarget::RealPlc {
                    addrs: addrs.clone(),
                    timeout,
                    key: public_key.map(<[u8]>::to_vec),
                };
                return Self::new_legacy(tcp, session, target);
            }
            RealPlcOutcome::KeyNotBundled { family } => family,
        };

        // Phase 2: the PLC advertised only its family — auto-try each bundled key for it.
        let candidates = crate::legacy::pubkey_store::candidates(family);
        log::info!(
            "real-PLC {family:?}: key id not advertised — auto-trying {} bundled key(s)",
            candidates.len()
        );
        let mut last_err: Option<Error> = None;
        for (i, key) in candidates.iter().enumerate() {
            let mut t = match IsoTcp::connect(addrs.as_slice(), timeout) {
                Ok(t) => t,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match real_plc_handshake(&mut t, Some(key), &mut rng) {
                Ok(RealPlcOutcome::Authenticated(session)) => {
                    log::info!(
                        "real-PLC: authenticated with bundled key {}/{}",
                        i + 1,
                        candidates.len()
                    );
                    let target = ReconnectTarget::RealPlc {
                        addrs: addrs.clone(),
                        timeout,
                        key: Some(key.to_vec()), // the bundled key that worked
                    };
                    return Self::new_legacy(t, session, target);
                }
                Ok(RealPlcOutcome::KeyNotBundled { .. }) => {} // unreachable with a key
                Err(e) => last_err = Some(e), // wrong key → PLC reset; try the next candidate
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::protocol(format!(
                "real-PLC {family:?}: none of the {} bundled keys authenticated; pass the key explicitly",
                candidates.len()
            ))
        }))
    }

    /// Build a legacy (non-TLS) `Connection` from a handshaken socket + derived session key, and
    /// read the PLC's request limits.
    fn new_legacy(
        tcp: IsoTcp,
        session: crate::legacy::session::LegacySession,
        reconnect_target: ReconnectTarget,
    ) -> Result<Self> {
        let crate::legacy::session::LegacySession {
            session_key,
            session_id,
            session_id2,
            plc_description,
        } = session;
        let mut conn = Connection {
            tcp,
            tls: None,
            rbuf: Vec::new(),
            rpos: 0,
            legacy_session_key: Some(session_key),
            session_id,
            session_id2,
            sequence_number: 2,
            integrity_id: 0,
            integrity_id_set: 0,
            with_integrity: true,
            type_info_cache: HashMap::new(),
            type_container_prefetched: false,
            db_list: None,
            symbol_cache: HashMap::new(),
            poisoned: false,
            reconnect_target,
            auto_reconnect: false,
            pending_notifications: VecDeque::new(),
            credit_limits: HashMap::new(),
            legacy_partial: Default::default(),
            max_read_tags: DEFAULT_TAGS_PER_REQUEST,
            max_write_tags: DEFAULT_TAGS_PER_REQUEST,
            plc_description,
            redact_next_request: false,
        };
        conn.read_request_limits()?;
        Ok(conn)
    }

    /// Read how many items the PLC accepts per Get/SetMultiVariables (its `SystemLimits`, as the
    /// reference's `CommRessources.ReadMax` does), so larger reads and writes are split to fit.
    /// Over the limit the PLC refuses the whole request. Best effort: if the PLC doesn't answer,
    /// the conservative default stays; only a lost connection is an error.
    fn read_request_limits(&mut self) -> Result<()> {
        let limit = |lid| ItemAddress {
            symbol_crc: 0,
            access_area: ids::OBJECT_ROOT,
            access_sub_area: ids::SYSTEM_LIMITS,
            lid: vec![lid],
        };
        let resp = match self.read_variables(&[
            limit(ids::TAGS_PER_READ_REQUEST_MAX),
            limit(ids::TAGS_PER_WRITE_REQUEST_MAX),
        ]) {
            Ok(resp) => resp,
            Err(e) if self.poisoned => return Err(e),
            Err(e) => {
                log::debug!("PLC request limits unavailable ({e}); keeping the defaults");
                return Ok(());
            }
        };
        let read = |item| {
            resp.value(item)
                .and_then(PValue::as_i64)
                .and_then(|v| usize::try_from(v).ok())
                .filter(|&v| v > 0)
        };
        if let Some(n) = read(1) {
            self.max_read_tags = n;
        }
        if let Some(n) = read(2) {
            self.max_write_tags = n;
        }
        log::info!(
            "PLC request limits: {} items per read, {} per write",
            self.max_read_tags,
            self.max_write_tags
        );
        Ok(())
    }

    /// Most items one `GetMultiVariables` may carry, as the PLC reported at connect (20 if it
    /// didn't). [`Connection::read_variables`] splits larger reads to fit.
    pub fn max_tags_per_read(&self) -> usize {
        self.max_read_tags
    }

    /// Most items one `SetMultiVariables` may carry, as the PLC reported at connect (20 if it
    /// didn't). [`Connection::write_variables`] splits larger writes to fit.
    pub fn max_tags_per_write(&self) -> usize {
        self.max_write_tags
    }

    /// The PLC's description of itself, sent when the session opens: on PLCSIM Advanced
    /// `1;6ES7 SIM-01500-APLC;S4.1` (a counter, the order number and the firmware version, it
    /// seems). `None` if the PLC sent none.
    pub fn plc_description(&self) -> Option<&str> {
        self.plc_description.as_deref()
    }

    /// SHA-256 fingerprint of the TLS certificate the PLC presented, to pin with
    /// [`Connection::connect_pinned`]. `None` on a legacy (non-TLS) connection.
    pub fn peer_certificate_sha256(&self) -> Option<[u8; 32]> {
        self.tls.as_ref()?.peer_certificate_sha256()
    }

    /// The negotiated session id.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// The secondary session id.
    pub fn session_id2(&self) -> u32 {
        self.session_id2
    }

    /// Re-establish the connection using the parameters it was created with, after a network drop.
    /// This starts a **fresh session**: a new session id, the sequence/integrity counters reset,
    /// and the type-info/DB caches are cleared. Any prior legitimation and subscriptions are lost
    /// and must be redone by the caller. Clears the poisoned state on success.
    ///
    /// For the legacy real-PLC transport this reuses the key that authenticated, so it skips the
    /// slow auto-key trial.
    pub fn reconnect(&mut self) -> Result<()> {
        let auto = self.auto_reconnect;
        let fresh = match self.reconnect_target.clone() {
            ReconnectTarget::Tls {
                addrs,
                timeout,
                pin,
            } => Self::connect_tls(addrs, timeout, pin)?,
            ReconnectTarget::LegacyPlcsim { addrs, timeout } => {
                Self::connect_legacy(addrs.as_slice(), timeout)?
            }
            ReconnectTarget::RealPlc {
                addrs,
                timeout,
                key,
            } => match key {
                Some(k) => Self::connect_real_plc_with_key(addrs.as_slice(), timeout, &k)?,
                None => Self::connect_real_plc(addrs.as_slice(), timeout)?,
            },
        };
        *self = fresh;
        self.auto_reconnect = auto;
        Ok(())
    }

    /// End the session cleanly, as the reference driver's `Disconnect` does: delete the server
    /// session object, so the PLC frees it (and its subscriptions) at once rather than when it
    /// notices the closed socket, then close TLS and the socket. Dropping a `Connection` closes
    /// the socket too, just without telling the PLC first. On a poisoned connection there is
    /// nothing sensible left to say, so this only closes the socket.
    pub fn close(mut self) -> Result<()> {
        if self.poisoned {
            return Ok(());
        }
        let deleted = self.delete_object(self.session_id);
        if let Some(tls) = self.tls.as_mut() {
            if !self.poisoned {
                let _ = tls.close(&mut self.tcp); // best effort; the socket closes regardless
            }
        }
        deleted
    }

    /// Enable/disable transparent auto-reconnect for **read** operations (default off). When on, a
    /// read that fails with a lost connection reconnects (see [`Connection::reconnect`]) and retries
    /// once. Writes and subscriptions are never auto-retried — a write may already have been applied,
    /// and a subscription is bound to the old session — so handle those with an explicit
    /// [`Connection::reconnect`] plus your own re-subscribe / re-issue.
    pub fn set_auto_reconnect(&mut self, enabled: bool) {
        self.auto_reconnect = enabled;
    }

    /// The exported `EXPERIMENTAL_OMS` keying material (for TLS legitimation). Errors on a legacy
    /// connection, which has no TLS layer.
    pub fn export_oms_secret(&self) -> Result<[u8; crate::transport::tls::OMS_SECRET_LEN]> {
        self.tls
            .as_ref()
            .ok_or_else(|| Error::protocol("export_oms_secret: not a TLS connection"))?
            .export_oms_secret()
    }

    /// Allocate the next sequence number (matches the reference `GetNextSequenceNumber`).
    fn next_sequence_number(&mut self) -> u16 {
        self.sequence_number = if self.sequence_number == u16::MAX {
            1
        } else {
            self.sequence_number + 1
        };
        self.sequence_number
    }

    /// Perform CreateObject for the null server session and record the new ids.
    fn create_session(&mut self) -> Result<CreateObjectResponse> {
        let seq = self.next_sequence_number();
        let req = proto::build_create_session_request(seq, self.session_id, false, 0)?;
        let resp_bytes = self.request_response(&req)?;
        let resp = proto::parse_create_object_response(&resp_bytes)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "CreateObject rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        self.session_id = resp
            .session_id()
            .ok_or_else(|| Error::protocol("CreateObject returned no session id"))?;
        self.session_id2 = resp.session_id2().unwrap_or(0);
        Ok(resp)
    }

    /// Step 4b: session setup. Echo the `ServerSessionVersion` Struct back to the session
    /// object via SetMultiVariables (no integrity id), completing session establishment.
    fn setup_session(&mut self, server_session_version: &PValue) -> Result<()> {
        let seq = self.next_sequence_number();
        let req = proto::build_session_setup_request(seq, self.session_id, server_session_version)?;
        let resp_bytes = self.request_response(&req)?;
        let resp = proto::parse_set_multi_response(&resp_bytes)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "session setup (SetMultiVariables) rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        Ok(())
    }

    /// Allocate the next integrity id for `function_code` (matches `GetNextIntegrityId`):
    /// Set/Delete/CreateObject share one counter, everything else another. Both start at 0
    /// and pre-increment, so the first id of each class is 1.
    fn next_integrity_id(&mut self, function_code: u16) -> u32 {
        let counter = match function_code {
            functioncode::SET_MULTI_VARIABLES
            | functioncode::SET_VARIABLE
            | functioncode::SET_VAR_SUBSTREAMED
            | functioncode::DELETE_OBJECT
            | functioncode::CREATE_OBJECT => &mut self.integrity_id_set,
            _ => &mut self.integrity_id,
        };
        *counter = if *counter == u32::MAX {
            0
        } else {
            *counter + 1
        };
        *counter
    }

    /// Read one or more symbolic variables via GetMultiVariables. If auto-reconnect is enabled
    /// (see [`Connection::set_auto_reconnect`]) and the connection is lost, this reconnects and
    /// retries once (reads are idempotent, so retrying is safe).
    ///
    /// More addresses than the PLC accepts per request ([`Connection::max_tags_per_read`]) are
    /// read in several requests and merged into one response, with item numbers still counting
    /// from 1 across the whole `addresses` slice.
    pub fn read_variables(
        &mut self,
        addresses: &[ItemAddress],
    ) -> Result<GetMultiVariablesResponse> {
        let max = self.max_read_tags.max(1);
        if addresses.len() <= max {
            return self.read_variables_retrying(addresses);
        }
        let mut merged: Option<GetMultiVariablesResponse> = None;
        for (n, chunk) in addresses.chunks(max).enumerate() {
            let resp = self.read_variables_retrying(chunk)?;
            let offset = (n * max) as u32;
            let out = merged.get_or_insert_with(|| GetMultiVariablesResponse {
                header: resp.header,
                values: Vec::with_capacity(addresses.len()),
                errors: Vec::new(),
                integrity_id: 0,
            });
            out.header = resp.header;
            out.integrity_id = resp.integrity_id;
            out.values
                .extend(resp.values.into_iter().map(|(i, v)| (i + offset, v)));
            out.errors
                .extend(resp.errors.into_iter().map(|(i, e)| (i + offset, e)));
        }
        Ok(merged.expect("more than one chunk"))
    }

    fn read_variables_retrying(
        &mut self,
        addresses: &[ItemAddress],
    ) -> Result<GetMultiVariablesResponse> {
        match self.read_variables_once(addresses) {
            Err(_) if self.auto_reconnect && self.poisoned => {
                self.reconnect()?;
                self.read_variables_once(addresses)
            }
            other => other,
        }
    }

    fn read_variables_once(
        &mut self,
        addresses: &[ItemAddress],
    ) -> Result<GetMultiVariablesResponse> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::GET_MULTI_VARIABLES)
        } else {
            0
        };
        let req = proto::build_get_multi_request(
            seq,
            self.session_id,
            addresses,
            with_integrity,
            integrity,
        )?;
        let resp_bytes = self.request_response(&req)?;
        let resp = proto::parse_get_multi_response(&resp_bytes)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "GetMultiVariables rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        Ok(resp)
    }

    /// Write one or more symbolic variables via SetMultiVariables (paired by position).
    ///
    /// A rejected *item* does not make this fail: check the response's `errors` (or use
    /// [`Connection::write_tags`], which does). More items than the PLC accepts per request
    /// ([`Connection::max_tags_per_write`]) are written in several requests — not atomically, so
    /// if a later request fails the earlier ones have already been applied — and the responses are
    /// merged, with item numbers counting from 1 across the whole slice.
    pub fn write_variables(
        &mut self,
        addresses: &[ItemAddress],
        values: &[PValue],
    ) -> Result<SetMultiVariablesResponse> {
        if addresses.len() != values.len() {
            return Err(Error::protocol(format!(
                "write_variables: {} addresses but {} values",
                addresses.len(),
                values.len()
            )));
        }
        let max = self.max_write_tags.max(1);
        if addresses.len() <= max {
            return self.write_variables_once(addresses, values);
        }
        let mut merged: Option<SetMultiVariablesResponse> = None;
        for (n, (addrs, vals)) in addresses.chunks(max).zip(values.chunks(max)).enumerate() {
            let resp = self.write_variables_once(addrs, vals)?;
            let offset = (n * max) as u32;
            let out = merged.get_or_insert_with(|| SetMultiVariablesResponse {
                header: resp.header,
                errors: Vec::new(),
                integrity_id: 0,
            });
            out.header = resp.header;
            out.integrity_id = resp.integrity_id;
            out.errors
                .extend(resp.errors.into_iter().map(|(i, e)| (i + offset, e)));
        }
        Ok(merged.expect("more than one chunk"))
    }

    fn write_variables_once(
        &mut self,
        addresses: &[ItemAddress],
        values: &[PValue],
    ) -> Result<SetMultiVariablesResponse> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::SET_MULTI_VARIABLES)
        } else {
            0
        };
        let req = proto::build_set_multi_request(
            seq,
            self.session_id,
            addresses,
            values,
            with_integrity,
            integrity,
        )?;
        let resp_bytes = self.request_response(&req)?;
        let resp = proto::parse_set_multi_response(&resp_bytes)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "SetMultiVariables rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        Ok(resp)
    }

    /// Create a subscription that monitors `items`, refreshed every `cycle_time_ms` milliseconds.
    /// The PLC then pushes notifications; read them with [`Connection::next_notification`].
    ///
    /// Uses an unlimited credit limit, so no periodic credit top-up is needed and each cycle
    /// yields a notification (empty when nothing changed) — [`Connection::next_notification`]
    /// therefore returns within the socket read timeout.
    pub fn subscribe(
        &mut self,
        items: &[proto::SubscriptionItem],
        cycle_time_ms: u16,
    ) -> Result<Subscription> {
        self.subscribe_with(
            items,
            cycle_time_ms,
            proto::subscription::DEFAULT_ROUTE_MODE,
            proto::subscription::DEFAULT_CREDIT_LIMIT,
        )
    }

    /// Like [`Connection::subscribe`] but with an explicit route mode and credit limit (advanced;
    /// see the reference route-mode/credit table). With a finite credit limit the PLC stops
    /// sending once the credit runs out; [`Connection::next_notification`] tops it up
    /// automatically before that happens.
    pub fn subscribe_with(
        &mut self,
        items: &[proto::SubscriptionItem],
        cycle_time_ms: u16,
        route_mode: u8,
        credit_limit: i16,
    ) -> Result<Subscription> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::CREATE_OBJECT)
        } else {
            0
        };
        let req = proto::build_subscription_create_request(
            seq,
            self.session_id,
            self.session_id2,
            with_integrity,
            integrity,
            1, // change counter (first subscription on this connection)
            route_mode,
            cycle_time_ms,
            credit_limit,
            items,
        )?;
        let resp_bytes = self.request_response(&req)?;
        let resp = proto::parse_create_object_response(&resp_bytes)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "subscription create rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        let object_id = resp
            .object_ids
            .first()
            .copied()
            .ok_or_else(|| Error::protocol("subscription create returned no object id"))?;
        Ok(self.register_subscription(object_id, credit_limit))
    }

    /// Track a new subscription's credit (only a finite one needs topping up).
    fn register_subscription(&mut self, object_id: u32, credit_limit: i16) -> Subscription {
        if credit_limit >= 0 {
            self.credit_limits.insert(object_id, credit_limit);
        }
        Subscription { object_id }
    }

    /// Create an **alarm** subscription (program/system alarms). The PLC then pushes alarm
    /// notifications; read them with [`Connection::next_notification`] and decode via
    /// [`proto::Notification::alarms`]. Uses an unlimited credit limit.
    ///
    /// Alarms are event-driven: when no alarm arrives within the socket read timeout,
    /// [`Connection::next_notification`] returns a timeout error **without** poisoning the
    /// connection, so you can simply poll again.
    ///
    /// NOTE: the PLC only sends alarm events if the program actually defines and triggers alarms
    /// (e.g. `Program_Alarm` instructions). The subscription is created regardless.
    pub fn subscribe_alarms(&mut self) -> Result<Subscription> {
        self.subscribe_alarms_with(-1)
    }

    /// Like [`Connection::subscribe_alarms`] but with an explicit credit limit (`-1` = unlimited).
    pub fn subscribe_alarms_with(&mut self, credit_limit: i16) -> Result<Subscription> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::CREATE_OBJECT)
        } else {
            0
        };
        let req = proto::build_alarm_subscription_create_request(
            seq,
            self.session_id,
            self.session_id2,
            with_integrity,
            integrity,
            credit_limit,
        )?;
        let resp_bytes = self.request_response(&req)?;
        let resp = proto::parse_create_object_response(&resp_bytes)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "alarm subscription create rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        let object_id = resp
            .object_ids
            .first()
            .copied()
            .ok_or_else(|| Error::protocol("alarm subscription returned no object id"))?;
        Ok(self.register_subscription(object_id, credit_limit))
    }

    /// Delete a server object by id (e.g. tear down a subscription, freeing it on the PLC instead
    /// of relying on the connection dropping). Uses the set-class integrity counter.
    pub fn delete_object(&mut self, object_id: u32) -> Result<()> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::DELETE_OBJECT)
        } else {
            0
        };
        let req = proto::build_delete_object_request(
            seq,
            self.session_id,
            object_id,
            with_integrity,
            integrity,
        )?;
        let resp = self.request_response(&req)?;
        let header = proto::parse_delete_object_response(&resp)?;
        if !header.is_ok() {
            return Err(Error::protocol(format!(
                "DeleteObject rejected: return_value=0x{:016x}",
                header.return_value
            )));
        }
        // If it was a subscription, forget its credit and anything still queued for it.
        self.credit_limits.remove(&object_id);
        self.pending_notifications
            .retain(|(id, _)| *id != object_id);
        Ok(())
    }

    /// Delete a subscription (from [`Connection::subscribe`] / [`Connection::subscribe_alarms`]),
    /// freeing it on the PLC.
    pub fn delete_subscription(&mut self, sub: &Subscription) -> Result<()> {
        self.delete_object(sub.object_id)
    }

    /// Block until the PLC pushes the next notification for `sub`, and parse it. Notifications for
    /// other subscriptions that arrive meanwhile are kept for their own `next_notification` call
    /// (or [`Connection::next_any_notification`]).
    ///
    /// Times out per the connection's socket read timeout. A timeout does **not** poison the
    /// connection — even one in the middle of a telegram, whose bytes are kept for the next call —
    /// so an event-driven (alarm) subscription can simply poll again. For a cyclic subscription a
    /// notification arrives each cycle, so a timeout there means the PLC went silent.
    ///
    /// For a subscription with a *finite* credit limit this tops the credit up (a no-response
    /// `SetVariable`) before the credit tick reaches the limit, keeping the flow going. With the
    /// default unlimited credit there is nothing to do.
    pub fn next_notification(&mut self, sub: &Subscription) -> Result<proto::Notification> {
        self.next_notification_for(Some(sub.object_id))
    }

    /// Like [`Connection::next_notification`], but returns the next notification of *any*
    /// subscription on this connection (see [`proto::Notification::subscription_object_id`]), for
    /// a single loop serving several subscriptions.
    pub fn next_any_notification(&mut self) -> Result<proto::Notification> {
        self.next_notification_for(None)
    }

    fn next_notification_for(&mut self, want: Option<u32>) -> Result<proto::Notification> {
        if self.poisoned {
            return Err(Error::closed(
                "connection poisoned by an earlier transport failure; reconnect required",
            ));
        }
        let wanted = |id: Option<u32>| want.is_none() || id.is_none() || id == want;
        // Deliver notifications buffered while awaiting a response before reading the socket.
        let queued = self
            .pending_notifications
            .iter()
            .position(|(id, _)| wanted(Some(*id)));
        let bytes = match queued.and_then(|i| self.pending_notifications.remove(i)) {
            Some((_, bytes)) => bytes,
            None => loop {
                let bytes = match self.recv_notification_telegram() {
                    Ok(b) => b,
                    Err(e) => {
                        // The receive path keeps partial telegrams, so a timeout leaves the
                        // connection usable.
                        if !e.is_timeout() {
                            self.poisoned = true;
                        }
                        return Err(e);
                    }
                };
                match notification_subscription_id(&bytes) {
                    Some(id) if !wanted(Some(id)) => self.queue_notification(id, bytes),
                    _ => break bytes,
                }
            },
        };
        let notif = proto::parse_notification(&bytes)?;
        self.top_up_credit(&notif)?;
        Ok(notif)
    }

    /// Finite-credit auto-refresh: raise a subscription's credit limit one tick before it expires.
    fn top_up_credit(&mut self, notif: &proto::Notification) -> Result<()> {
        let object_id = notif.subscription_object_id;
        let Some(&limit) = self.credit_limits.get(&object_id) else {
            return Ok(()); // unlimited credit (or not one of ours)
        };
        if i16::from(notif.credit_tick) < limit - 1 {
            return Ok(());
        }
        const STEP: i16 = 5;
        let next = ((limit + STEP) % 255).max(STEP);
        self.credit_limits.insert(object_id, next);
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::SET_VARIABLE)
        } else {
            0
        };
        let req = proto::subscription::build_credit_limit_request(
            seq,
            self.session_id,
            object_id,
            with_integrity,
            integrity,
            next,
        )?;
        if let Err(e) = self.send_no_response(&req) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// Keep a notification for a later `next_notification` call. The queue is bounded: a
    /// subscription nobody polls must not grow memory without limit, so past the cap the oldest
    /// notification is dropped (and logged).
    fn queue_notification(&mut self, subscription_id: u32, bytes: Vec<u8>) {
        if self.pending_notifications.len() >= MAX_QUEUED_NOTIFICATIONS {
            if let Some((id, _)) = self.pending_notifications.pop_front() {
                log::warn!(
                    "notification queue full ({MAX_QUEUED_NOTIFICATIONS}); dropped the oldest \
                     (subscription 0x{id:08x}) — poll every subscription or delete unused ones"
                );
            }
        }
        self.pending_notifications
            .push_back((subscription_id, bytes));
    }

    /// Send a framed request without waiting for a reply (for `0x74` "no response" requests like
    /// the subscription credit top-up). Transport-aware (legacy V3 digest vs TLS).
    fn send_no_response(&mut self, framed: &[u8]) -> Result<()> {
        let (_, function, seq) = pdu::header_fields(framed).unwrap_or_default();
        log::debug!(
            "→ {} seq={seq} ({} bytes, no response expected)",
            pdu::function_name(function),
            framed.len()
        );
        log::trace!("→ {}", pdu::Hex(framed));
        if let Some(key) = self.legacy_session_key {
            let v3 = crate::legacy::session::frame_v3(&key, framed)?;
            self.tcp.send_iso_packet(&v3)
        } else {
            self.send_tls(framed)
        }
    }

    /// Send a framed telegram over TLS, split into chunks that each fit one COTP frame (see
    /// [`pdu::MAX_CHUNK_PAYLOAD`]), every chunk in its own TLS record.
    fn send_tls(&mut self, framed: &[u8]) -> Result<()> {
        let tls = self
            .tls
            .as_mut()
            .ok_or_else(|| Error::protocol("no TLS channel on a non-legacy connection"))?;
        for chunk in pdu::split_framed_pdu(framed, pdu::MAX_CHUNK_PAYLOAD) {
            tls.send(&mut self.tcp, &chunk)?;
        }
        Ok(())
    }

    /// Read a single object attribute via GetVarSubstreamed.
    pub fn get_var_substreamed(&mut self, address: u32) -> Result<GetVarSubstreamedResponse> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::GET_VAR_SUBSTREAMED)
        } else {
            0
        };
        let req = proto::build_get_var_substreamed_request(
            protocol_version::V2,
            seq,
            self.session_id,
            self.session_id, // InObjectId: read attributes of the session object
            address,
            with_integrity,
            integrity,
        )?;
        let resp_bytes = self.request_response(&req)?;
        proto::parse_get_var_substreamed_response(&resp_bytes)
    }

    /// Write a single object attribute via SetVariable.
    pub fn set_variable(&mut self, address: u32, value: &PValue) -> Result<SetVariableResponse> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::SET_VARIABLE)
        } else {
            0
        };
        let req = proto::build_set_variable_request(
            protocol_version::V2,
            seq,
            self.session_id,
            self.session_id, // InObjectId: write attributes of the session object
            address,
            value,
            with_integrity,
            integrity,
        )?;
        let resp_bytes = self.request_response(&req)?;
        proto::parse_set_variable_response(&resp_bytes)
    }

    /// Explore the object tree under `explore_id` and return the raw response telegram
    /// bytes (decode with [`crate::proto::parse_explore_response`]). `recursive` =
    /// `ExploreChildsRecursive`, `parents` = `ExploreParents`. `attrs` restricts which
    /// attributes are returned per object (empty = all); some objects (e.g. data blocks)
    /// only appear when the relevant attributes are requested.
    pub fn explore_raw(
        &mut self,
        explore_id: u32,
        recursive: u8,
        parents: u8,
        attrs: &[u32],
    ) -> Result<Vec<u8>> {
        self.explore_request(explore_id, ids::NONE, recursive, parents, attrs)
    }

    /// [`Connection::explore_raw`] with an `ExploreRequestId`, which some objects use to select
    /// what they list (the alarm subsystem's pending alarms, for one).
    fn explore_request(
        &mut self,
        explore_id: u32,
        request_id: u32,
        recursive: u8,
        parents: u8,
        attrs: &[u32],
    ) -> Result<Vec<u8>> {
        let seq = self.next_sequence_number();
        let with_integrity = self.with_integrity;
        let integrity = if with_integrity {
            self.next_integrity_id(functioncode::EXPLORE)
        } else {
            0
        };
        let req = proto::build_explore_request(
            protocol_version::V2,
            seq,
            self.session_id,
            explore_id,
            request_id,
            recursive,
            parents,
            attrs,
            with_integrity,
            integrity,
        )?;
        self.request_response(&req)
    }

    /// Whether requests currently carry an integrity id.
    pub fn with_integrity(&self) -> bool {
        self.with_integrity
    }

    /// Explore the object tree under `explore_id` and decode the response. `attrs` restricts
    /// the returned attributes (empty = all).
    pub fn explore(
        &mut self,
        explore_id: u32,
        recursive: u8,
        parents: u8,
        attrs: &[u32],
    ) -> Result<proto::ExploreResponse> {
        let with_integrity = self.with_integrity;
        let raw = self.explore_raw(explore_id, recursive, parents, attrs)?;
        let resp = proto::parse_explore_response(&raw, with_integrity)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "Explore rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        Ok(resp)
    }

    /// Diagnostic: Explore `relid` and return a human-readable dump of the returned object
    /// tree (relid/class/attributes/vartype+varname list sizes). Used to probe live PLC
    /// behaviour that differs from the PLCSIM captures.
    pub fn explore_dump(&mut self, relid: u32, recursive: u8, parents: u8) -> Result<String> {
        self.explore_dump_attrs(relid, recursive, parents, &[])
    }

    /// Diagnostic: Explore `relid` (recursive) and collect every `Blob` attribute matching
    /// `attr` across all returned objects, as `(object_relid, bytes)`.
    pub fn explore_attr_blobs(&mut self, relid: u32, attr: u32) -> Result<Vec<(u32, Vec<u8>)>> {
        let resp = self.explore(relid, 1, 0, &[attr])?;
        let mut out = Vec::new();
        fn scan(obj: &PObject, attr: u32, out: &mut Vec<(u32, Vec<u8>)>) {
            for (id, v) in &obj.attributes {
                if *id == attr {
                    if let PValue::Blob { data, .. } = v {
                        out.push((obj.relation_id, data.clone()));
                    }
                }
            }
            for c in &obj.objects {
                scan(c, attr, out);
            }
        }
        for o in &resp.objects {
            scan(o, attr, &mut out);
        }
        Ok(out)
    }

    /// Like [`Connection::explore_dump`] but restricts the returned attributes to `attrs`
    /// (an empty slice returns all). Long attribute values (blobs) are shown as a hex prefix.
    pub fn explore_dump_attrs(
        &mut self,
        relid: u32,
        recursive: u8,
        parents: u8,
        attrs: &[u32],
    ) -> Result<String> {
        let resp = self.explore(relid, recursive, parents, attrs)?;
        let mut out = String::new();
        fn dump(obj: &PObject, d: usize, out: &mut String) {
            use std::fmt::Write;
            let pad = "  ".repeat(d);
            let _ = writeln!(
                out,
                "{pad}obj relid=0x{:08x} class=0x{:08x} attrs={} vartypes={:?} varnames={:?} subs={}",
                obj.relation_id,
                obj.class_id,
                obj.attributes.len(),
                obj.vartype_list.as_ref().map(|v| v.elements.len()),
                obj.varname_list.as_ref().map(|v| v.names.len()),
                obj.objects.len(),
            );
            for (id, v) in &obj.attributes {
                let vs = format!("{v:?}");
                let vs = if vs.len() > 80 {
                    format!("{}…", &vs[..80])
                } else {
                    vs
                };
                let _ = writeln!(out, "{pad}  attr 0x{id:x} ({id}) = {vs}");
            }
            if let Some(vt) = &obj.vartype_list {
                for (i, e) in vt.elements.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "{pad}  vartype[{i}] lid={} sdt={} crc=0x{:08x} rel={:?}",
                        e.lid, e.softdatatype, e.symbol_crc, e.offset_info.relation_id
                    );
                }
            }
            if let Some(vn) = &obj.varname_list {
                let _ = writeln!(out, "{pad}  varnames={:?}", vn.names);
            }
            for (rid, val) in &obj.relations {
                let _ = writeln!(out, "{pad}  relation 0x{rid:x} -> 0x{val:08x}");
            }
            for c in &obj.objects {
                dump(c, d + 1, out);
            }
        }
        use std::fmt::Write;
        let _ = writeln!(
            out,
            "explore(0x{relid:08x}, rec={recursive}, par={parents}): {} objects",
            resp.objects.len()
        );
        for o in &resp.objects {
            dump(o, 1, &mut out);
        }
        Ok(out)
    }

    /// Fetch (and cache) the type-info object for `ti_relid` — an Explore of the type, whose
    /// `VartypeList`/`VarnameList` describe its members. Every type object an Explore returns is
    /// cached under its own relid, without its nested objects (they are cached under theirs).
    pub fn type_info(&mut self, ti_relid: u32) -> Result<PObject> {
        Ok(PObject::clone(&*self.cached_type_info(ti_relid)?))
    }

    /// [`Connection::type_info`] without the copy: the cache shares each type object, so the
    /// browse walk and symbol resolution don't deep-clone a member list per lookup.
    fn cached_type_info(&mut self, ti_relid: u32) -> Result<Arc<PObject>> {
        if let Some(obj) = self.type_info_cache.get(&ti_relid) {
            return Ok(Arc::clone(obj));
        }
        let resp = self.explore(ti_relid, 1, 0, &[])?;
        let mut first = None;
        for obj in type_objects(resp.objects) {
            let obj = Arc::new(obj);
            first.get_or_insert_with(|| Arc::clone(&obj));
            self.type_info_cache.insert(obj.relation_id, obj);
        }
        if let Some(obj) = self.type_info_cache.get(&ti_relid) {
            return Ok(Arc::clone(obj));
        }
        // The explored id isn't always the type object's own relid (e.g. controller areas);
        // fall back to the first object that carries type info.
        if let Some(obj) = first {
            self.type_info_cache.insert(ti_relid, Arc::clone(&obj));
            return Ok(obj);
        }
        Err(Error::protocol(format!(
            "type info for relid {ti_relid} carries no member list \
             (PLC withheld the interface — likely a know-how-protected block)"
        )))
    }

    /// Forget the cached data-block list, type info and resolved symbols, so the next lookup
    /// asks the PLC again — e.g. after a program download changed the blocks. (A reconnect
    /// starts with empty caches anyway.)
    pub fn clear_caches(&mut self) {
        self.type_info_cache.clear();
        self.type_container_prefetched = false;
        self.db_list = None;
        self.symbol_cache.clear();
    }

    /// Discover (and cache) the data blocks: name, relid, number, and type-info relid.
    pub fn datablock_list(&mut self) -> Result<Vec<DataBlock>> {
        Ok(self.data_blocks()?.to_vec())
    }

    /// [`Connection::datablock_list`], shared rather than copied.
    fn data_blocks(&mut self) -> Result<Arc<[DataBlock]>> {
        if let Some(list) = &self.db_list {
            return Ok(Arc::clone(list));
        }
        // DB objects only appear in the Explore when the browse attributes are requested.
        let resp = self.explore(PLC_PROGRAM_RID, 1, 0, &BROWSE_ATTRS)?;
        let mut dbs = Vec::new();
        for program in &resp.objects {
            for ob in &program.objects {
                if ob.class_id == DB_CLASS_RID && (ob.relation_id >> 16) == 0x8a0e {
                    let name = ob
                        .attributes
                        .iter()
                        .find_map(|(id, v)| match (id, v) {
                            (&OBJECT_VARIABLE_TYPE_NAME, PValue::WString(s)) => Some(s.clone()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    dbs.push(DataBlock {
                        name,
                        relid: ob.relation_id,
                        number: ob.relation_id & 0xffff,
                        ti_relid: 0,
                    });
                }
            }
        }
        // Reading LID 1 of a DB returns its type-info relid: one batched read for all of them
        // (it used to be a round trip per DB).
        let addrs: Vec<ItemAddress> = dbs
            .iter()
            .map(|db| ItemAddress {
                symbol_crc: 0,
                access_area: db.relid,
                access_sub_area: DB_VALUE_ACTUAL,
                lid: vec![1],
            })
            .collect();
        if !addrs.is_empty() {
            let items = self.read_variables(&addrs)?.into_items(addrs.len());
            for (db, item) in dbs.iter_mut().zip(items) {
                if let Ok(PValue::RID(ti)) = item {
                    db.ti_relid = ti;
                }
            }
        }
        let found = dbs.len();
        dbs.retain(|d| d.ti_relid != 0);
        log::debug!(
            "data blocks: {} ({} without readable type info skipped): {:?}",
            dbs.len(),
            found - dbs.len(),
            dbs.iter()
                .map(|d| (d.number, d.name.as_str()))
                .collect::<Vec<_>>()
        );
        let list: Arc<[DataBlock]> = dbs.into();
        self.db_list = Some(Arc::clone(&list));
        Ok(list)
    }

    /// Fetch the OMS type-info container in one (multi-fragment) Explore and cache every type
    /// object that carries a member list, keyed by relation id. This is the canonical, bulk
    /// source of type info the reference uses for browsing (`ObjectOMSTypeInfoContainer`): one
    /// round-trip for the whole program instead of a per-type Explore, and complete for large
    /// programs. Best-effort — [`Connection::type_info`] still falls back to a per-type Explore
    /// on a cache miss. Fetched once per connection (until [`Connection::clear_caches`]): on an
    /// S7-1215C it is about 100 KB and takes 6 s (field run), and `browse_vars`
    /// asks for it on every call.
    pub fn prefetch_type_container(&mut self) -> Result<()> {
        if self.type_container_prefetched {
            return Ok(());
        }
        let resp = self.explore(OMS_TYPE_INFO_CONTAINER_RID, 1, 0, &[])?;
        for obj in type_objects(resp.objects) {
            self.type_info_cache
                .entry(obj.relation_id)
                .or_insert_with(|| Arc::new(obj));
        }
        self.type_container_prefetched = true;
        Ok(())
    }

    /// Enumerate every readable leaf variable in the whole PLC program (all data blocks plus the
    /// M/Q/I areas) as a flat [`VarInfo`] list, descending into nested structs/FBs and expanding
    /// arrays (including arrays of structs) to their elements. Bulk-prefetches the type container
    /// first. Blocks whose interface the PLC withholds (know-how protected) contribute nothing. A lost
    /// connection is an error rather than a partial list.
    pub fn browse_vars(&mut self) -> Result<Vec<VarInfo>> {
        let dbs = self.data_blocks()?;
        if let Err(e) = self.prefetch_type_container() {
            self.skip_unless_lost(e, "the type-info prefetch")?; // best effort
        }
        let mut out = Vec::new();
        for db in dbs.iter() {
            let prefix = quote_level(&db.name);
            let walked = self.walk_type(
                db.relid,
                DB_VALUE_ACTUAL,
                db.ti_relid,
                &prefix,
                &[],
                0,
                &mut out,
            );
            if let Err(e) = walked {
                self.skip_unless_lost(e, &prefix)?;
            }
        }
        for (rid, ti, label) in CONTROLLER_AREAS {
            let walked =
                self.walk_type(rid, CONTROLLER_AREA_VALUE_ACTUAL, ti, "", &[], 0, &mut out);
            if let Err(e) = walked {
                self.skip_unless_lost(e, label)?;
            }
        }
        Ok(out)
    }

    /// Browsing skips a part the PLC won't describe (a know-how-protected block, an empty area)
    /// and goes on — unless the connection is gone, when continuing would only produce a partial
    /// list that looks complete.
    fn skip_unless_lost(&self, e: Error, what: &str) -> Result<()> {
        if self.poisoned {
            return Err(e);
        }
        log::debug!("browse: skipping {what}: {e}");
        Ok(())
    }

    /// Enumerate the readable leaf variables of one data block (name prefixed by the DB name).
    pub fn browse_datablock(
        &mut self,
        db_relid: u32,
        ti_relid: u32,
        name: &str,
    ) -> Result<Vec<VarInfo>> {
        let mut out = Vec::new();
        let prefix = quote_level(name);
        self.walk_type(
            db_relid,
            DB_VALUE_ACTUAL,
            ti_relid,
            &prefix,
            &[],
            0,
            &mut out,
        )?;
        Ok(out)
    }

    /// Enumerate the readable leaf variables of one controller area (M/Q/I; bare tag names).
    pub fn browse_controller_area(&mut self, area_rid: u32, ti_relid: u32) -> Result<Vec<VarInfo>> {
        let mut out = Vec::new();
        self.walk_type(
            area_rid,
            CONTROLLER_AREA_VALUE_ACTUAL,
            ti_relid,
            "",
            &[],
            0,
            &mut out,
        )?;
        Ok(out)
    }

    /// Recursively enumerate the members of the type at `ti_relid`, appending a [`VarInfo`] leaf
    /// for every scalar/string element. Mirrors the reference `Browser.AddSubNodes` +
    /// `BuildFlatList` walk, but keeps only the symbolic LID access sequence (byte offsets are for
    /// non-optimized access, which we don't do). `lids` is the access sequence so far.
    #[allow(clippy::too_many_arguments)]
    fn walk_type(
        &mut self,
        area: u32,
        sub_area: u32,
        ti_relid: u32,
        prefix: &str,
        lids: &[u32],
        depth: usize,
        out: &mut Vec<VarInfo>,
    ) -> Result<()> {
        if depth > MAX_BROWSE_DEPTH {
            return Ok(());
        }
        // A shared handle, not a borrow of the cache, so the loop can recurse (&mut self).
        let ti = self.cached_type_info(ti_relid)?;
        let (Some(names), Some(types)) = (&ti.varname_list, &ti.vartype_list) else {
            return Ok(()); // no member list (empty area, or interface withheld)
        };
        for (mname, elem) in names.names.iter().zip(&types.elements) {
            let oi = &elem.offset_info;
            let name = if prefix.is_empty() {
                quote_level(mname)
            } else {
                format!("{prefix}.{}", quote_level(mname))
            };
            let mut base = lids.to_vec();
            base.push(elem.lid);
            let sdt = elem.softdatatype;
            let has_rel = oi.has_relation();

            if oi.is_1dim || oi.is_mdim {
                // Enumerate array elements: `(display suffix, zero-based element id)`.
                let elems: Vec<(String, u32)> = if oi.is_1dim {
                    let lower = oi.array_lower_bounds;
                    (0..oi.array_element_count)
                        .map(|k| (format!("[{}]", lower + k as i32), k))
                        .collect()
                } else {
                    mdim_elements(oi, sdt)
                };
                for (suffix, id) in elems {
                    let ename = format!("{name}{suffix}");
                    let mut elids = base.clone();
                    elids.push(id);
                    if has_rel {
                        elids.push(1); // struct-array: extra id between index and member LID
                        if let Some(rel) = oi.relation_id {
                            let walked =
                                self.walk_type(area, sub_area, rel, &ename, &elids, depth + 1, out);
                            if let Err(e) = walked {
                                self.skip_unless_lost(e, &ename)?;
                            }
                        }
                    } else {
                        out.push(VarInfo {
                            name: ename,
                            access_area: area,
                            access_sub_area: sub_area,
                            lids: elids,
                            softdatatype: sdt,
                            string_max_len: oi.string_max_len,
                        });
                    }
                }
            } else if has_rel {
                // Nested struct / FB / system-library type (IEC_TIMER, DTL, …): descend.
                if let Some(rel) = oi.relation_id {
                    let walked = self.walk_type(area, sub_area, rel, &name, &base, depth + 1, out);
                    if let Err(e) = walked {
                        self.skip_unless_lost(e, &name)?;
                    }
                }
            } else {
                out.push(VarInfo {
                    name,
                    access_area: area,
                    access_sub_area: sub_area,
                    lids: base,
                    softdatatype: sdt,
                    string_max_len: oi.string_max_len,
                });
            }
        }
        Ok(())
    }

    /// Read the current values of browsed variables in batched `GetMultiVariables` requests.
    /// Returns one entry per input var (in order): `Some(value)` if read, `None` if that item
    /// genuinely errored on the PLC. A whole batch failing propagates as `Err`.
    ///
    /// A batch whose items *all* come back errored is treated as "the PLC refused a batch this
    /// large" and is retried in halves down to single items — so a per-request item cap degrades
    /// to correct (if slower) reads rather than spurious "not readable" results.
    pub fn read_var_values(&mut self, vars: &[VarInfo]) -> Result<Vec<Option<PValue>>> {
        let batch = std::env::var("S7_READ_BATCH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(READ_BATCH)
            .min(self.max_read_tags.max(1));
        let mut out = Vec::with_capacity(vars.len());
        for chunk in vars.chunks(batch) {
            self.read_chunk_adaptive(chunk, &mut out)?;
        }
        Ok(out)
    }

    /// Read one chunk, tolerating a PLC per-request cap: an over-large batch is refused either as
    /// a header-level rejection (`Err`) or as every item erroring — in both cases (when the chunk
    /// has more than one item) we split in half and retry. A genuinely unreadable *single* item
    /// becomes `None` rather than aborting the whole read; only a lost connection propagates.
    fn read_chunk_adaptive(
        &mut self,
        chunk: &[VarInfo],
        out: &mut Vec<Option<PValue>>,
    ) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let addrs: Vec<ItemAddress> = chunk.iter().map(VarInfo::address).collect();
        match self.read_variables(&addrs) {
            Ok(resp) => {
                let vals: Vec<Option<PValue>> = resp
                    .into_items(chunk.len())
                    .into_iter()
                    .map(std::result::Result::ok)
                    .collect();
                if chunk.len() > 1 && vals.iter().all(Option::is_none) {
                    self.split_and_read(chunk, out)
                } else {
                    out.extend(vals);
                    Ok(())
                }
            }
            // A real transport loss must propagate; a protocol rejection of an over-cap batch is
            // recoverable by splitting. A single item that still fails is recorded as `None`.
            Err(e) if self.poisoned => Err(e),
            Err(_) if chunk.len() > 1 => self.split_and_read(chunk, out),
            Err(_) => {
                out.push(None);
                Ok(())
            }
        }
    }

    /// Split a chunk in half and read each half (used by the adaptive read to back off an
    /// over-large batch).
    fn split_and_read(&mut self, chunk: &[VarInfo], out: &mut Vec<Option<PValue>>) -> Result<()> {
        let mid = chunk.len() / 2;
        self.read_chunk_adaptive(&chunk[..mid], out)?;
        self.read_chunk_adaptive(&chunk[mid..], out)
    }

    /// Resolve a symbol like `"Data_block_1.toto"` to its [`ItemAddress`] by walking the
    /// block's type info. Handles nested structs/FBs and 1-D/M-D array indexing
    /// (`"DB.arr[2]"`, `"DB.m[1,2]"`). Paths can be written as TIA Portal shows them: names may
    /// be double-quoted, which is required when they contain `.`, `[` or `]`
    /// (`"\"Data block.1\".\"value.1\""`), and array-DB elements are `"\"Array DB\"[2]"`.
    pub fn resolve_symbol(&mut self, symbol: &str) -> Result<ItemAddress> {
        Ok(self.resolve_full(symbol)?.0)
    }

    /// Like [`Connection::resolve_symbol`], but returns a [`VarInfo`] that also carries the
    /// member's softdatatype and declared string length. A [`PValue`] alone doesn't say what it
    /// means (a `DATE` reads as `UInt`, a `STRING` and a `DATE_AND_TIME` both read as a USInt
    /// array), so use this to interpret a value, e.g. with [`crate::value::datetime::format`].
    ///
    /// For a whole array (no `[..]` index) the softdatatype is the element type. A bare DB name
    /// has no member, so its softdatatype is `0`.
    pub fn resolve_var(&mut self, symbol: &str) -> Result<VarInfo> {
        let (addr, leaf) = self.resolve_full(symbol)?;
        Ok(VarInfo {
            name: symbol.to_string(),
            access_area: addr.access_area,
            access_sub_area: addr.access_sub_area,
            lids: addr.lid,
            softdatatype: leaf.as_ref().map_or(0, |e| e.softdatatype),
            string_max_len: leaf.as_ref().map_or(0, |e| e.offset_info.string_max_len),
        })
    }

    /// Like [`Connection::resolve_symbol`] but also returns the resolved leaf member's
    /// type-info element (datatype, string max length, …).
    fn resolve_full(&mut self, symbol: &str) -> Result<ResolvedSymbol> {
        if let Some(hit) = self.symbol_cache.get(symbol) {
            return Ok(hit.clone());
        }
        let resolved = self.resolve_uncached(symbol)?;
        let addr = &resolved.0;
        log::debug!(
            "resolved {symbol} → area 0x{:08x}, sub-area {}, LIDs {:?}",
            addr.access_area,
            addr.access_sub_area,
            addr.lid
        );
        self.symbol_cache
            .insert(symbol.to_owned(), resolved.clone());
        Ok(resolved)
    }

    fn resolve_uncached(&mut self, symbol: &str) -> Result<ResolvedSymbol> {
        let mut levels = parse_symbol_path(symbol)?;
        let first = levels[0].0.clone();

        // Determine the access root. A data block consumes the first path level (the DB
        // name); a controller area (M/Q/I) does not — the first level is already a tag in it.
        let dbs = self.data_blocks()?;
        let (access_area, access_sub_area, root_ti, start) =
            if let Some(db) = dbs.iter().find(|d| d.name == first).cloned() {
                // Array DB elements: TIA writes `"DB"[2]`; the PLC exposes them as member `THIS`.
                if !levels[0].1.is_empty() {
                    let indices = std::mem::take(&mut levels[0].1);
                    levels.insert(1, ("THIS".to_string(), indices));
                }
                (db.relid, DB_VALUE_ACTUAL, db.ti_relid, 1usize)
            } else {
                let mut found = None;
                for (rid, ti, _label) in CONTROLLER_AREAS {
                    // An area with no tags has no member list; it just can't hold the symbol.
                    let info = match self.cached_type_info(ti) {
                        Ok(info) => info,
                        Err(e) if self.poisoned => return Err(e),
                        Err(_) => continue,
                    };
                    let present = info
                        .varname_list
                        .as_ref()
                        .is_some_and(|n| n.names.contains(&first));
                    if present {
                        found = Some((rid, CONTROLLER_AREA_VALUE_ACTUAL, ti, 0usize));
                        break;
                    }
                }
                found.ok_or_else(|| {
                    let hint = dbs
                        .iter()
                        .find(|d| d.name.contains('.') && symbol.starts_with(d.name.as_str()))
                        .map(|d| {
                            format!(
                                " (names containing '.' must be double-quoted: \"{}\")",
                                d.name
                            )
                        })
                        .unwrap_or_default();
                    Error::protocol(format!(
                        "symbol '{symbol}' not found in any data block or M/Q/I area{hint}"
                    ))
                })?
            };

        let mut addr = ItemAddress {
            symbol_crc: 0,
            access_area,
            access_sub_area,
            lid: Vec::new(),
        };
        let mut ti_relid = root_ti;
        let mut leaf: Option<crate::proto::VartypeElement> = None;
        let mut i = start;
        while i < levels.len() {
            let (name, indices) = &levels[i];
            let ti = self.cached_type_info(ti_relid)?;
            let names = ti
                .varname_list
                .as_ref()
                .ok_or_else(|| Error::protocol("type info missing VarnameList"))?;
            let vt = ti
                .vartype_list
                .as_ref()
                .ok_or_else(|| Error::protocol("type info missing VartypeList"))?;
            let idx = names
                .names
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| Error::protocol(format!("member '{name}' not found")))?;
            let elem = vt
                .elements
                .get(idx)
                .ok_or_else(|| Error::protocol("VartypeList shorter than VarnameList"))?
                .clone();
            let oi = &elem.offset_info;
            addr.lid.push(elem.lid);

            // Array indexing: append the (zero-based, row-major) element id, plus an extra
            // `.1` when the elements are structs (array-of-struct).
            if !indices.is_empty() {
                let array_lid = array_element_id(oi, indices)
                    .ok_or_else(|| Error::protocol(format!("bad array index for '{name}'")))?;
                addr.lid.push(array_lid);
                if oi.has_relation() {
                    addr.lid.push(1);
                }
            } else if (oi.is_1dim || oi.is_mdim) && oi.has_relation() && i + 1 < levels.len() {
                // A whole array-of-struct can be read as the leaf, but its members can only be
                // reached through an element.
                return Err(Error::protocol(format!(
                    "'{name}' is an array; index it to reach its members"
                )));
            }

            let relation_id = oi.relation_id;
            leaf = Some(elem);
            i += 1;
            match relation_id {
                // Descend into a nested struct/FB for the next path level.
                Some(rel) if i < levels.len() => ti_relid = rel,
                _ => break,
            }
        }
        if i < levels.len() {
            return Err(Error::protocol(format!(
                "could not fully resolve '{symbol}' (stopped before '{}')",
                levels[i].0
            )));
        }
        Ok((addr, leaf))
    }

    /// Read a single tag by symbol name (e.g. `"Data_block_1.toto"`).
    pub fn read_tag(&mut self, symbol: &str) -> Result<PValue> {
        let addr = self.resolve_symbol(symbol)?;
        let resp = self.read_variables(&[addr])?;
        if let Some(v) = resp.value(1) {
            Ok(v.clone())
        } else if let Some((_, e)) = resp.errors.first() {
            Err(Error::protocol(format!(
                "read '{symbol}' returned error 0x{e:016x}"
            )))
        } else {
            Err(Error::protocol(format!(
                "read '{symbol}' returned no value"
            )))
        }
    }

    /// Write a single tag by symbol name (e.g. `"Data_block_1.titi"`). The `value` type must
    /// match the PLC variable's type.
    pub fn write_tag(&mut self, symbol: &str, value: PValue) -> Result<()> {
        let addr = self.resolve_symbol(symbol)?;
        self.write_resolved(symbol, addr, value)
    }

    /// Read several tags by name in one `GetMultiVariables` round-trip (several, past the PLC's
    /// item limit). Returns one result per symbol, in order; a per-item failure — including a
    /// symbol that doesn't resolve — is `Err` for that entry, and the others still succeed. Only
    /// a failed request or a lost connection fails the whole call. More efficient than repeated
    /// [`Connection::read_tag`] for a known set of tags.
    pub fn read_tags(&mut self, symbols: &[&str]) -> Result<Vec<Result<PValue>>> {
        let mut resolved = Vec::with_capacity(symbols.len());
        for s in symbols {
            match self.resolve_symbol(s) {
                Ok(addr) => resolved.push(Ok(addr)),
                Err(e) if self.poisoned => return Err(e),
                Err(e) => resolved.push(Err(e)),
            }
        }
        let addrs: Vec<ItemAddress> = resolved
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        let mut items = if addrs.is_empty() {
            Vec::new().into_iter()
        } else {
            self.read_variables(&addrs)?
                .into_items(addrs.len())
                .into_iter()
        };
        Ok(resolved
            .into_iter()
            .zip(symbols)
            .map(|(addr, s)| {
                addr?;
                items
                    .next()
                    .expect("one item per resolved symbol")
                    .map_err(|code| {
                        Error::protocol(format!("read '{s}' failed (return_value=0x{code:016x})"))
                    })
            })
            .collect())
    }

    /// Write several tags by name in one `SetMultiVariables` round-trip (paired by position). The
    /// value type must match each PLC variable. Errors if any item is rejected, naming the first.
    pub fn write_tags(&mut self, pairs: &[(&str, PValue)]) -> Result<()> {
        let mut addrs = Vec::with_capacity(pairs.len());
        let mut values = Vec::with_capacity(pairs.len());
        for (name, value) in pairs {
            addrs.push(self.resolve_symbol(name)?);
            values.push(value.clone());
        }
        let resp = self.write_variables(&addrs, &values)?;
        if let Some((item, e)) = resp.errors.first() {
            let name = pairs
                .get((*item as usize).wrapping_sub(1))
                .map(|(n, _)| *n)
                .unwrap_or("?");
            return Err(Error::protocol(format!(
                "write '{name}' rejected: item {item} return_value=0x{e:016x}"
            )));
        }
        Ok(())
    }

    /// Read an S7 `STRING` tag by name. On the wire a STRING is a USInt array
    /// `[max_len, actual_len, chars…]` in ISO-8859-1; this decodes it to a Rust `String`.
    pub fn read_string(&mut self, symbol: &str) -> Result<String> {
        match self.read_tag(symbol)? {
            PValue::USIntArray(bytes) => Ok(decode_s7_string(&bytes)),
            other => Err(Error::protocol(format!(
                "'{symbol}' did not read back as a STRING (got {other:?})"
            ))),
        }
    }

    /// Write an S7 `STRING` tag by name. The variable's declared max length frames the written
    /// buffer; longer text is truncated, and characters outside ISO-8859-1 become `?`.
    pub fn write_string(&mut self, symbol: &str, value: &str) -> Result<()> {
        let (addr, max_len) = self.resolve_string(symbol)?;
        let payload = encode_s7_string(value, max_len.min(254) as u8);
        self.write_resolved(symbol, addr, PValue::USIntArray(payload))
    }

    /// Read an S7 `WSTRING` tag by name. On the wire a WSTRING is a UInt array
    /// `[max_len, actual_len, code units…]` in UTF-16; this decodes it to a Rust `String`.
    pub fn read_wstring(&mut self, symbol: &str) -> Result<String> {
        let v = self.read_tag(symbol)?;
        decode_wstring(&v).ok_or_else(|| {
            Error::protocol(format!(
                "'{symbol}' did not read back as a WSTRING (got {v:?})"
            ))
        })
    }

    /// Write an S7 `WSTRING` tag by name. The variable's declared max length frames the written
    /// buffer; longer text is truncated to that many UTF-16 code units.
    pub fn write_wstring(&mut self, symbol: &str, value: &str) -> Result<()> {
        let (addr, max_len) = self.resolve_string(symbol)?;
        self.write_resolved(symbol, addr, encode_wstring(value, max_len))
    }

    /// Resolve a `STRING`/`WSTRING` symbol to its address and declared max length. The length
    /// comes from the type info when its offset info carries it; array elements' offset info
    /// doesn't, so it is then taken from the `[max_len, actual_len, …]` header of the current
    /// value (falling back to the default 254).
    fn resolve_string(&mut self, symbol: &str) -> Result<(ItemAddress, u16)> {
        let (addr, leaf) = self.resolve_full(symbol)?;
        let declared = leaf
            .map(|e| e.offset_info.string_max_len)
            .filter(|&m| m > 0);
        let max_len = match declared {
            Some(m) => m,
            None => {
                let resp = self.read_variables(std::slice::from_ref(&addr))?;
                match resp.value(1) {
                    Some(PValue::USIntArray(b)) => b.first().map(|&m| u16::from(m)),
                    Some(PValue::Array { items, .. }) => match items.first() {
                        Some(PValue::UInt(m)) => Some(*m),
                        _ => None,
                    },
                    _ => None,
                }
                .unwrap_or(254)
            }
        };
        Ok((addr, max_len))
    }

    /// Write one already-resolved value, turning an item-level rejection into an error.
    fn write_resolved(&mut self, symbol: &str, addr: ItemAddress, value: PValue) -> Result<()> {
        let resp = self.write_variables(&[addr], &[value])?;
        if let Some((item, e)) = resp.errors.first() {
            return Err(Error::protocol(format!(
                "write '{symbol}' rejected: item {item} return_value=0x{e:016x}"
            )));
        }
        Ok(())
    }

    /// Read `len` bytes at byte offset `start` of `area`, as the classic S7 protocol does: a
    /// standard (not optimized) data block, the inputs, outputs, or bit memory. To read several
    /// ranges in one request, pass [`ItemAddress::raw`] addresses to
    /// [`Connection::read_variables`].
    pub fn read_area(&mut self, area: Area, start: u32, len: u32) -> Result<Vec<u8>> {
        let resp = self.read_variables(&[ItemAddress::raw(area, start, len)])?;
        match resp.into_items(1).pop() {
            Some(Ok(PValue::Blob { data, .. })) => Ok(data),
            Some(Ok(other)) => Err(Error::protocol(format!(
                "{area:?} read did not return bytes (got {other:?})"
            ))),
            Some(Err(code)) => Err(raw_access_refused("reading", area, start, len, code)),
            None => Err(Error::protocol(format!("{area:?} read returned no value"))),
        }
    }

    /// Write `data` at byte offset `start` of `area` (see [`Connection::read_area`]).
    pub fn write_area(&mut self, area: Area, start: u32, data: &[u8]) -> Result<()> {
        let len = u32::try_from(data.len())
            .map_err(|_| Error::protocol("write_area: data longer than 4 GiB"))?;
        let value = PValue::Blob {
            root_id: 0,
            data: data.to_vec(),
        };
        let resp = self.write_variables(&[ItemAddress::raw(area, start, len)], &[value])?;
        match resp.errors.first() {
            Some(&(_, code)) => Err(raw_access_refused("writing", area, start, len, code)),
            None => Ok(()),
        }
    }

    /// Read the CPU's operating state.
    ///
    /// The CPU's execution unit reports it as the classic S7 operating-state code (8 = RUN,
    /// 4 = STOP) in member 3486 of its attribute 2237, as found by switching PLCSIM Advanced
    /// (FW V2.8 and V2.9) between RUN and STOP. Any other code is returned as
    /// [`CpuState::Other`].
    pub fn cpu_state(&mut self) -> Result<CpuState> {
        let resp = self.explore(CPU_EXEC_UNIT_RID, 0, 0, &[CPU_OPERATING_STATE])?;
        let state = resp
            .objects
            .iter()
            .find(|o| o.relation_id == CPU_EXEC_UNIT_RID)
            .and_then(|o| o.attribute(CPU_OPERATING_STATE));
        let code = match state {
            Some(PValue::Struct { elements, .. }) => elements
                .iter()
                .find(|(id, _)| *id == CPU_OPERATING_STATE_CODE)
                .map(|(_, v)| v),
            _ => None,
        };
        match code {
            Some(PValue::DInt(8)) => Ok(CpuState::Run),
            Some(PValue::DInt(4)) => Ok(CpuState::Stop),
            Some(PValue::DInt(other)) => Ok(CpuState::Other(*other)),
            _ => Err(Error::protocol(format!(
                "CPU execution unit reported no operating state (got {state:?})"
            ))),
        }
    }

    /// Read the alarms pending on the PLC: a snapshot, with no subscription needed (it works
    /// alongside one, too). Each [`Alarm`](crate::proto::Alarm) is as an alarm notification
    /// delivers it.
    pub fn active_alarms(&mut self) -> Result<Vec<proto::Alarm>> {
        use proto::alarm::{ALARM_SUBSYSTEM_RID, DAI_ATTRIBUTES, UPDATE_RELEVANT_DAI};
        let raw = self.explore_request(
            ALARM_SUBSYSTEM_RID,
            UPDATE_RELEVANT_DAI,
            1,
            0,
            &DAI_ATTRIBUTES,
        )?;
        let resp = proto::parse_explore_response(&raw, self.with_integrity)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "reading the pending alarms rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        proto::alarm::alarms_in(&resp.objects)
    }

    /// Read the session's effective protection level (`EffectiveProtectionLevel`). `1` means
    /// full access (no legitimation needed); higher values mean access is restricted until
    /// [`Connection::legitimate`] succeeds.
    pub fn effective_protection_level(&mut self) -> Result<u32> {
        let resp = self.get_var_substreamed(ids::EFFECTIVE_PROTECTION_LEVEL)?;
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "reading protection level rejected: return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        match resp.value {
            PValue::UDInt(v) => Ok(v),
            other => Err(Error::protocol(format!(
                "unexpected protection-level value type: {other:?}"
            ))),
        }
    }

    /// Authenticate (the "new", firmware ≥ V3.1 path): fetch the server-session challenge,
    /// AES-encrypt the credentials payload with the exported keying material, and submit it.
    pub fn legitimate(&mut self, username: &str, password: &str) -> Result<()> {
        // 1. Fetch the challenge.
        let challenge_resp = self.get_var_substreamed(ids::SERVER_SESSION_REQUEST)?;
        if !challenge_resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "challenge request rejected: return_value=0x{:016x}",
                challenge_resp.header.return_value
            )));
        }
        let challenge = match challenge_resp.value {
            PValue::USIntArray(bytes) => bytes,
            other => {
                return Err(Error::protocol(format!(
                    "unexpected challenge value type: {other:?}"
                )))
            }
        };
        if challenge.len() < crypto::AES_BLOCK_LEN {
            return Err(Error::protocol("challenge shorter than one AES block"));
        }

        // 2. Derive key/IV and encrypt the credentials payload.
        let secret = self.export_oms_secret()?;
        let key = crypto::sha256(&secret);
        let iv = &challenge[..crypto::AES_BLOCK_LEN];
        let mut payload = Vec::new();
        build_legitimation_payload(username, password).serialize(&mut payload)?;
        let ciphertext = crypto::encrypt_aes256_cbc_pkcs7(&key, iv, &payload)?;

        // 3. Submit the encrypted response, keeping it out of the log.
        self.redact_next_request = true;
        let resp = self.set_variable(
            ids::LEGITIMATE,
            &PValue::Blob {
                root_id: 0,
                data: ciphertext,
            },
        )?;
        // Denied if the error bit is set OR the low 16 bits (as a signed int) are negative — the
        // reference treats `(Int16)ReturnValue < 0` as access-denied, and `is_ok` checks both.
        if !resp.header.is_ok() {
            return Err(Error::protocol(format!(
                "legitimation rejected (access denied): return_value=0x{:016x}",
                resp.header.return_value
            )));
        }
        Ok(())
    }

    /// Send a framed request telegram and read the next response telegram. Uses TLS, or — for a
    /// legacy connection — the ProtocolVersion-0x03 per-PDU HMAC digest framing over plain COTP.
    ///
    /// Any failure poisons the connection (see [`Connection::is_poisoned`]); the error then
    /// reports a lost connection ([`Error::is_connection_lost`]).
    pub fn request_response(&mut self, framed_request: &[u8]) -> Result<Vec<u8>> {
        if self.poisoned {
            return Err(Error::closed(
                "connection poisoned by an earlier transport failure; reconnect required",
            ));
        }
        let redact = std::mem::take(&mut self.redact_next_request);
        let (_, function, seq) = pdu::header_fields(framed_request).unwrap_or_default();
        let name = pdu::function_name(function);
        log::debug!("→ {name} seq={seq} ({} bytes)", framed_request.len());
        if redact {
            log::trace!("→ (contents not logged: they carry credentials)");
        } else {
            log::trace!("→ {}", pdu::Hex(framed_request));
        }
        let started = std::time::Instant::now();
        let result = self.request_response_inner(framed_request);
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        match result {
            Ok(response) => {
                match return_value(&response).filter(|&rv| rv != 0) {
                    Some(rv) => log::debug!(
                        "← {name} seq={seq} return_value=0x{rv:016x} ({} bytes, {ms:.1} ms)",
                        response.len()
                    ),
                    None => {
                        log::debug!("← {name} seq={seq} ({} bytes, {ms:.1} ms)", response.len())
                    }
                }
                log::trace!("← {}", pdu::Hex(&response));
                Ok(response)
            }
            // Any failure here leaves the sequence/integrity-id counters out of sync with the
            // PLC, so the connection can no longer be reused. Poison it and surface the error.
            Err(e) => {
                self.poisoned = true;
                let e = if e.is_timeout() {
                    // The response may still arrive and would then be taken as the answer to the
                    // next request: unlike a quiet notification poll, this is not retryable.
                    Error::closed(format!(
                        "no response within the timeout ({e}); reconnect required"
                    ))
                } else {
                    e
                };
                log::warn!("{name} seq={seq} failed after {ms:.1} ms, connection poisoned: {e}");
                Err(e)
            }
        }
    }

    /// Whether an earlier failure left the connection out of step with the PLC. Every request on
    /// a poisoned connection fails with [`Error::Closed`]; [`Connection::reconnect`] (or a new
    /// connection) is the only way on.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn request_response_inner(&mut self, framed_request: &[u8]) -> Result<Vec<u8>> {
        if let Some(key) = self.legacy_session_key {
            let v3 = crate::legacy::session::frame_v3(&key, framed_request)?;
            self.tcp.send_iso_packet(&v3)?;
        } else {
            self.send_tls(framed_request)?;
        }
        let response = self.recv_response()?;
        check_response_header(framed_request, &response)?;
        Ok(response)
    }

    /// Receive the next telegram for the active transport (TLS, or legacy V3-digest framing).
    fn recv_one_telegram(&mut self) -> Result<Vec<u8>> {
        if let Some(key) = &self.legacy_session_key {
            crate::legacy::session::recv_and_strip(&mut self.tcp, key, &mut self.legacy_partial)
        } else {
            self.recv_telegram()
        }
    }

    /// Handle a `SystemEvent` (`0xfe`) keep-alive: `Ok(true)` if it was one (and non-fatal, so skip
    /// it), `Ok(false)` if `bytes` is not a SystemEvent, `Err` if it was a fatal one.
    fn skip_if_system_event(&self, bytes: &[u8]) -> Result<bool> {
        if !proto::is_system_event(bytes) {
            return Ok(false);
        }
        let ev = proto::parse_system_event(bytes)?;
        if ev.is_fatal() {
            return Err(Error::closed(
                "PLC sent a fatal SystemEvent; connection must be re-established",
            ));
        }
        log::debug!(
            "skipping SystemEvent keep-alive (confirmed_bytes={})",
            ev.confirmed_bytes
        );
        Ok(true)
    }

    /// Receive the next **response** telegram. Skips `SystemEvent` keep-alives and buffers any
    /// `Notification` telegrams (an active subscription pushes them asynchronously between our
    /// request/response exchanges) for later delivery via [`Connection::next_notification`].
    fn recv_response(&mut self) -> Result<Vec<u8>> {
        loop {
            let bytes = self.recv_one_telegram()?;
            if self.skip_if_system_event(&bytes)? {
                continue;
            }
            if let Some(id) = notification_subscription_id(&bytes) {
                log_notification(id, &bytes, "queued while awaiting a response");
                self.queue_notification(id, bytes);
                continue;
            }
            return Ok(bytes);
        }
    }

    /// Receive the next **notification** telegram (skipping `SystemEvent` keep-alives).
    fn recv_notification_telegram(&mut self) -> Result<Vec<u8>> {
        loop {
            let bytes = self.recv_one_telegram()?;
            if self.skip_if_system_event(&bytes)? {
                continue;
            }
            match notification_subscription_id(&bytes) {
                Some(id) => log_notification(id, &bytes, ""),
                None => {
                    log::debug!(
                        "← unexpected telegram while awaiting a notification ({} bytes)",
                        bytes.len()
                    );
                    log::trace!("← {}", pdu::Hex(&bytes));
                }
            }
            return Ok(bytes);
        }
    }

    /// Read one complete S7CommPlus telegram from the encrypted stream, reassembling the
    /// multi-chunk framing (each chunk a `72 ver len` header; the telegram ends at the
    /// `72 ver 00 00` trailer). Returns the telegram re-wrapped as a single framed PDU so
    /// the `proto::parse_*` helpers can consume it directly.
    ///
    /// Nothing is consumed from `rbuf` until the whole telegram is there, so a read timeout
    /// part-way through keeps every byte for the next call.
    fn recv_telegram(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some((version, end, body_len)) = scan_telegram(&self.rbuf[self.rpos..])? {
                // Re-frame as a single chunk directly (what `pdu::frame_single_pdu` produces),
                // copying each chunk's payload once.
                let raw = &self.rbuf[self.rpos..self.rpos + end];
                let mut framed = Vec::with_capacity(body_len + 8);
                framed.extend_from_slice(&[pdu::PROTOCOL_ID, version]);
                framed
                    .extend_from_slice(&u16::try_from(body_len).unwrap_or(u16::MAX).to_be_bytes());
                let mut i = 0;
                while i + 4 < end {
                    let len = usize::from(u16::from_be_bytes([raw[i + 2], raw[i + 3]]));
                    framed.extend_from_slice(&raw[i + 4..i + 4 + len]);
                    i += 4 + len;
                }
                framed.extend_from_slice(&[pdu::PROTOCOL_ID, version, 0, 0]);
                self.rpos += end;
                if self.rpos == self.rbuf.len() {
                    self.rbuf.clear();
                    self.rpos = 0;
                } else if self.rpos > self.rbuf.len() / 2 {
                    self.rbuf.drain(..self.rpos);
                    self.rpos = 0;
                }
                return Ok(framed);
            }
            let chunk = self
                .tls
                .as_mut()
                .ok_or_else(|| Error::protocol("no TLS channel on a non-legacy connection"))?
                .recv(&mut self.tcp)?;
            if chunk.is_empty() {
                return Err(Error::framing("TLS stream closed mid-telegram"));
            }
            self.rbuf.extend_from_slice(&chunk);
        }
    }
}

/// Find a complete telegram at the start of `buf`: `(trailer version, length including the
/// trailer, total body length)`, or `None` if more bytes are needed. Only reads `buf`, so the
/// caller can retry after the next read.
fn scan_telegram(buf: &[u8]) -> Result<Option<(u8, usize, usize)>> {
    let mut i = 0;
    let mut body_len = 0;
    while let Some(&[id, version, hi, lo]) = buf.get(i..i + 4) {
        if id != pdu::PROTOCOL_ID {
            return Err(Error::framing(format!(
                "bad S7CommPlus chunk header byte 0x{id:02x}"
            )));
        }
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if len == 0 {
            return Ok(Some((version, i + 4, body_len))); // trailer => end of telegram
        }
        body_len += len;
        if body_len > pdu::MAX_TELEGRAM_LEN {
            return Err(Error::framing("telegram exceeds the reassembly size cap"));
        }
        i += 4 + len;
    }
    Ok(None)
}

/// Every object in `objects` (recursively) that carries a member list, each detached from its
/// nested objects — moved, not cloned, so a deep tree is not copied once per level.
fn type_objects(objects: Vec<PObject>) -> Vec<PObject> {
    let mut out = Vec::new();
    let mut stack = objects;
    while let Some(mut obj) = stack.pop() {
        stack.append(&mut obj.objects);
        if obj.vartype_list.is_some() {
            out.push(obj);
        }
    }
    out
}

/// The error for a byte-offset access the PLC refused. PLCSIM answers the same error code
/// (-61) for a range past the area's end as for a data block that is optimized.
fn raw_access_refused(verb: &str, area: Area, start: u32, len: u32, code: u64) -> Error {
    let hint = match area {
        Area::Db(_) => "past the block's end, or an optimized block",
        _ => "past the area's end",
    };
    Error::protocol(format!(
        "{verb} {len} bytes at {start} of {area:?} refused ({hint}?): return_value=0x{code:016x}"
    ))
}

/// The return value of a framed response (the VLQ after its 10-byte header), for logs.
fn return_value(response: &[u8]) -> Option<u64> {
    let h = pdu::parse_header(response).ok()?;
    let mut cur = std::io::Cursor::new(response.get(h.body_offset + 10..)?);
    crate::wire::vlq::decode_u64(&mut cur).ok()
}

/// Log a received notification telegram for subscription `id`.
fn log_notification(id: u32, bytes: &[u8], note: &str) {
    let note = if note.is_empty() {
        String::new()
    } else {
        format!(", {note}")
    };
    log::debug!(
        "← Notification for subscription 0x{id:08x} ({} bytes{note})",
        bytes.len()
    );
    log::trace!("← {}", pdu::Hex(bytes));
}

/// Check that the framed `response` answers the framed `request`: a Response with the request's
/// sequence number and function code, or the generic Error function a PLC may answer any failed
/// request with. Anything else means the telegram stream is out of step with our requests, which
/// no later request can recover from.
fn check_response_header(request: &[u8], response: &[u8]) -> Result<()> {
    let (_, function, sequence) = pdu::header_fields(request)
        .ok_or_else(|| Error::protocol("request too short for its header"))?;
    let Some((got_opcode, got_function, got_sequence)) = pdu::header_fields(response) else {
        return Err(Error::protocol("response too short for its header"));
    };
    let answers = got_opcode == pdu::opcode::RESPONSE
        && got_sequence == sequence
        && (got_function == function || got_function == functioncode::ERROR);
    if !answers {
        return Err(Error::closed(format!(
            "telegram out of step: expected the response to function 0x{function:04x} sequence \
             {sequence}, got opcode 0x{got_opcode:02x} function 0x{got_function:04x} sequence \
             {got_sequence}; reconnect required"
        )));
    }
    Ok(())
}

/// The subscription a framed telegram notifies about, if it is a `Notification` (`0x33`). A
/// notification too short to carry the id reads as subscription 0 (and fails to parse later),
/// so it is never mistaken for a response.
fn notification_subscription_id(buf: &[u8]) -> Option<u32> {
    let h = pdu::parse_header(buf).ok()?;
    let body = buf.get(h.body_offset..)?;
    if body.first() != Some(&pdu::opcode::NOTIFICATION) {
        return None;
    }
    Some(
        body.get(1..5)
            .map_or(0, |id| u32::from_be_bytes(id.try_into().expect("4 bytes"))),
    )
}

/// Split a symbol path into its levels, each a name plus any array indices:
/// `DB.arr[2].x` → `[("DB", []), ("arr", [2]), ("x", [])]`, `DB.m[1,2]` → `[.., ("m", [1, 2])]`.
///
/// A name may be wrapped in double quotes, as TIA Portal writes it, so it can contain `.`, `[`
/// or `]`: `"Data block.1"."value.1"` → `[("Data block.1", []), ("value.1", [])]`. Indices
/// follow the closing quote (`"my arr"[2]`). An unterminated quote is an error.
fn parse_symbol_path(symbol: &str) -> Result<Vec<(String, Vec<i32>)>> {
    let mut levels = Vec::new();
    let mut name = String::new();
    let mut indices = Vec::new();
    let mut chars = symbol.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if !indices.is_empty() {
                    return Err(Error::protocol(format!(
                        "unexpected '\"' after an array index in symbol '{symbol}'"
                    )));
                }
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some(q) => name.push(q),
                        None => {
                            return Err(Error::protocol(format!(
                                "unterminated quote in symbol '{symbol}'"
                            )))
                        }
                    }
                }
            }
            '.' => levels.push((std::mem::take(&mut name), std::mem::take(&mut indices))),
            '[' => {
                let mut inner = String::new();
                loop {
                    match chars.next() {
                        Some(']') => break,
                        Some(c) => inner.push(c),
                        None => {
                            return Err(Error::protocol(format!(
                                "unterminated '[' in symbol '{symbol}'"
                            )))
                        }
                    }
                }
                // A bad index must not silently select the whole array.
                for part in inner.split(',') {
                    let index = part.trim().parse::<i32>().map_err(|_| {
                        Error::protocol(format!(
                            "bad array index '{}' in symbol '{symbol}'",
                            part.trim()
                        ))
                    })?;
                    indices.push(index);
                }
            }
            _ if !indices.is_empty() => {
                return Err(Error::protocol(format!(
                    "unexpected '{c}' after an array index in symbol '{symbol}'"
                )))
            }
            _ => name.push(c),
        }
    }
    levels.push((name, indices));
    Ok(levels)
}

/// Format one browsed member name as a symbol path level, double-quoting it (TIA style) when it
/// contains characters that [`parse_symbol_path`] would otherwise treat as syntax.
fn quote_level(name: &str) -> String {
    if name.contains(['.', '[', ']']) {
        format!("\"{name}\"")
    } else {
        name.to_string()
    }
}

/// Compute the zero-based, row-major element id for an array access (the LID appended for
/// `[..]`), porting the reference's 1-dim and M-dim access-sequence math. Returns `None` on
/// a dimension/bounds mismatch.
#[allow(clippy::needless_range_loop)]
fn array_element_id(oi: &crate::proto::OffsetInfo, indices: &[i32]) -> Option<u32> {
    if oi.is_1dim {
        if indices.len() != 1 {
            return None;
        }
        let zero = indices[0].checked_sub(oi.array_lower_bounds)?;
        if zero < 0 || (zero as u32) >= oi.array_element_count {
            return None;
        }
        Some(zero as u32)
    } else if oi.is_mdim {
        let dim_count = oi.mdim_element_count.iter().filter(|&&c| c > 0).count();
        if dim_count == 0 || dim_count != indices.len() {
            return None;
        }
        // Normalize indices against the (reversed) per-dimension lower bounds.
        let mut idx = vec![0i64; dim_count];
        for i in 0..dim_count {
            let lb = oi.mdim_lower_bounds[dim_count - i - 1];
            let v = indices[i].checked_sub(lb)?;
            if v < 0 || (v as u32) >= oi.mdim_element_count[dim_count - i - 1] {
                return None;
            }
            idx[i] = v as i64;
        }
        // Row-major strides.
        let mut dim_size = vec![1u64; dim_count];
        let mut g = 1u64;
        for i in 0..dim_count - 1 {
            dim_size[i] = g;
            g *= oi.mdim_element_count[i] as u64;
        }
        dim_size[dim_count - 1] = g;
        let mut array_index = 0i64;
        for i in 0..dim_count {
            array_index += idx[i] * dim_size[dim_count - i - 1] as i64;
        }
        u32::try_from(array_index).ok()
    } else {
        None
    }
}

/// Enumerate the elements of an M-dimensional array as `(display suffix, zero-based access id)`,
/// porting the reference `Browser.AddSubNodes` M-dim loop (dimension 0 varies fastest; names list
/// the dimensions high-to-low; `BBOOL` arrays skip ids to the next byte boundary per row).
fn mdim_elements(oi: &crate::proto::OffsetInfo, softdatatype: u8) -> Vec<(String, u32)> {
    let actdim = oi.mdim_element_count.iter().filter(|&&c| c > 0).count();
    if actdim == 0 {
        return Vec::new();
    }
    let total = oi.array_element_count;
    let mut out = Vec::new();
    let mut xx = [0u32; 6];
    let mut id = 0u32;
    let mut n = 1u32;
    loop {
        let mut name = String::from("[");
        for j in (0..actdim).rev() {
            let v = xx[j] as i64 + oi.mdim_lower_bounds[j] as i64;
            name.push_str(&v.to_string());
            name.push(if j > 0 { ',' } else { ']' });
        }
        out.push((name, id));

        xx[0] += 1;
        // BBOOL arrays: the id of the fastest dimension only advances in units up to 8 per byte.
        if softdatatype == crate::value::datatype::softdatatype::BBOOL
            && xx[0] >= oi.mdim_element_count[0]
            && oi.mdim_element_count[0] % 8 != 0
        {
            id += 8 - (xx[0] % 8);
        }
        for dim in 0..5 {
            if xx[dim] >= oi.mdim_element_count[dim] {
                xx[dim] = 0;
                xx[dim + 1] += 1;
            }
        }
        id += 1;
        n += 1;
        if n > total {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::OffsetInfo;

    fn levels(symbol: &str) -> Vec<(String, Vec<i32>)> {
        parse_symbol_path(symbol).unwrap()
    }

    fn lv(name: &str, indices: &[i32]) -> (String, Vec<i32>) {
        (name.to_string(), indices.to_vec())
    }

    #[test]
    fn parse_symbol_path_handles_names_and_indices() {
        assert_eq!(levels("toto"), [lv("toto", &[])]);
        assert_eq!(levels("DB.arr[2]"), [lv("DB", &[]), lv("arr", &[2])]);
        assert_eq!(levels("DB.m[1,2]"), [lv("DB", &[]), lv("m", &[1, 2])]);
        assert_eq!(levels("DB.a[ -3 ]"), [lv("DB", &[]), lv("a", &[-3])]);
        assert_eq!(
            levels("DB.s[1].x"),
            [lv("DB", &[]), lv("s", &[1]), lv("x", &[])]
        );
    }

    #[test]
    fn parse_symbol_path_handles_quoted_names() {
        // Issue #1: TIA names may contain dots.
        assert_eq!(
            levels("\"Data block.1\".\"value.1\""),
            [lv("Data block.1", &[]), lv("value.1", &[])]
        );
        assert_eq!(
            levels("\"Data_block_1\".toto"),
            [lv("Data_block_1", &[]), lv("toto", &[])]
        );
        assert_eq!(
            levels("DB.\"my.arr\"[3].\"a[b]\""),
            [lv("DB", &[]), lv("my.arr", &[3]), lv("a[b]", &[])]
        );
        assert!(parse_symbol_path("\"Data block.1.value").is_err());
    }

    #[test]
    fn parse_symbol_path_rejects_bad_indices() {
        // These used to drop the index and silently address the whole array.
        for bad in [
            "DB.arr[abc]",
            "DB.arr[]",
            "DB.arr[1",
            "DB.m[1,]",
            "DB.arr[1]x",
            "DB.arr[1]\"x\"",
        ] {
            assert!(parse_symbol_path(bad).is_err(), "{bad}");
        }
        // Repeated brackets still read as one multi-dimensional index.
        assert_eq!(levels("DB.m[1][2]"), [lv("DB", &[]), lv("m", &[1, 2])]);
    }

    #[test]
    fn quote_level_round_trips_through_parser() {
        assert_eq!(quote_level("plain_name"), "plain_name");
        assert_eq!(quote_level("value.1"), "\"value.1\"");
        let path = format!(
            "{}.{}[2]",
            quote_level("Data block.1"),
            quote_level("arr.x")
        );
        assert_eq!(levels(&path), [lv("Data block.1", &[]), lv("arr.x", &[2])]);
    }

    #[test]
    fn array_element_id_1dim() {
        // Array[1..10] -> index 3 maps to element id 2.
        let oi = OffsetInfo {
            is_1dim: true,
            array_lower_bounds: 1,
            array_element_count: 10,
            ..Default::default()
        };
        assert_eq!(array_element_id(&oi, &[3]), Some(2));
        assert_eq!(array_element_id(&oi, &[1]), Some(0));
        assert_eq!(array_element_id(&oi, &[0]), None); // below lower bound
        assert_eq!(array_element_id(&oi, &[10]), Some(9)); // last element
        assert_eq!(array_element_id(&oi, &[11]), None); // one past the upper bound
        assert_eq!(array_element_id(&oi, &[1, 2]), None); // wrong dim count
    }

    #[test]
    fn array_element_id_2dim() {
        // Counts {3,4}; element [1,2] per the reference formula:
        //   indexes=[1,2], dimSize=[1,3] -> 1*dimSize[1] + 2*dimSize[0] = 1*3 + 2*1 = 5.
        let mut oi = OffsetInfo {
            is_mdim: true,
            ..Default::default()
        };
        oi.mdim_element_count[0] = 3;
        oi.mdim_element_count[1] = 4;
        assert_eq!(array_element_id(&oi, &[1, 2]), Some(5));
        assert_eq!(array_element_id(&oi, &[0, 0]), Some(0));
        assert_eq!(array_element_id(&oi, &[3, 2]), Some(11)); // last element
                                                              // One past the end in either dimension must not wrap into a neighbouring row.
        assert_eq!(array_element_id(&oi, &[4, 0]), None);
        assert_eq!(array_element_id(&oi, &[0, 3]), None);
    }

    #[test]
    fn mdim_elements_2d_enumeration() {
        // A 2-D array with dim0 count=2 (fastest), dim1 count=3, lower bounds 0. The reference
        // loop enumerates a linear access id (dim0 varies fastest) and names the dimensions
        // high-to-low, so the rightmost index is the fastest-varying.
        let oi = OffsetInfo {
            is_mdim: true,
            array_element_count: 6,
            mdim_element_count: [2, 3, 0, 0, 0, 0],
            mdim_lower_bounds: [0, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        let got = mdim_elements(&oi, 7 /* DInt softdatatype, not BBOOL */);
        assert_eq!(
            got,
            vec![
                ("[0,0]".into(), 0),
                ("[0,1]".into(), 1),
                ("[1,0]".into(), 2),
                ("[1,1]".into(), 3),
                ("[2,0]".into(), 4),
                ("[2,1]".into(), 5),
            ]
        );
    }

    #[test]
    fn mdim_elements_honours_lower_bounds() {
        // Non-zero lower bounds shift the displayed indices but not the access ids.
        let oi = OffsetInfo {
            is_mdim: true,
            array_element_count: 4,
            mdim_element_count: [2, 2, 0, 0, 0, 0],
            mdim_lower_bounds: [1, 10, 0, 0, 0, 0],
            ..Default::default()
        };
        let got = mdim_elements(&oi, 7 /* DInt softdatatype, not BBOOL */);
        assert_eq!(
            got,
            vec![
                ("[10,1]".into(), 0),
                ("[10,2]".into(), 1),
                ("[11,1]".into(), 2),
                ("[11,2]".into(), 3),
            ]
        );
    }

    /// A stand-in for a legacy (V3-digest) PLC on loopback, with the all-zero session key
    /// [`mock_connection`] gives the client. Every reply is a single chunk, so its digest is the
    /// plain [`packet_digest`](crate::legacy::digest::packet_digest).
    struct MockPlc {
        stream: std::net::TcpStream,
        /// Sequence number of the last request received, which a response must echo.
        seq: u16,
    }

    impl MockPlc {
        /// Read one request TSDU and return its V2 body (the `data` of the V3 frame).
        fn recv_request(&mut self) -> Vec<u8> {
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
        fn response(&self, function: u16, rest: &[u8]) -> Vec<u8> {
            let mut body = vec![pdu::opcode::RESPONSE, 0, 0];
            body.extend_from_slice(&function.to_be_bytes());
            body.extend_from_slice(&[0, 0]); // reserved
            body.extend_from_slice(&self.seq.to_be_bytes());
            body.extend_from_slice(&[0, 0]); // transport flags, return value 0
            body.extend_from_slice(rest);
            body
        }

        /// An Explore response body listing `objects`, answering the last request.
        fn explore_response(&self, explore_id: u32, objects: &[PObject]) -> Vec<u8> {
            let mut rest = explore_id.to_be_bytes().to_vec();
            rest.push(0); // integrity id
            for o in objects {
                o.serialize(&mut rest).unwrap();
            }
            rest.extend_from_slice(&[0; 4]);
            self.response(functioncode::EXPLORE, &rest)
        }

        /// The V3 telegram carrying `body`, as one COTP DT frame.
        fn frame(body: &[u8]) -> Vec<u8> {
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

        fn send(&mut self, body: &[u8]) {
            use std::io::Write;
            self.stream.write_all(&Self::frame(body)).unwrap();
        }

        /// Answer the GetMultiVariables the client sends at connect for the request limits.
        fn answer_limits(&mut self, max: i32) {
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

    /// A notification telegram body for `subscription` with `credit_tick` and one DInt value.
    fn notification(subscription: u32, credit_tick: u8) -> Vec<u8> {
        let mut b = vec![pdu::opcode::NOTIFICATION];
        b.extend_from_slice(&subscription.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, credit_tick, 1, 1]);
        b.extend_from_slice(&[0x9b, 0x01]);
        PValue::DInt(subscription as i32).serialize(&mut b).unwrap();
        b.push(0);
        b
    }

    /// The session the mock PLC's handshake would leave: the all-zero key [`MockPlc`] signs with.
    fn mock_session() -> crate::legacy::session::LegacySession {
        crate::legacy::session::LegacySession {
            session_key: [0; 24],
            session_id: 0x7000_0001,
            session_id2: 0x7000_0002,
            plc_description: Some("1;6ES7 MOCK;V0.0".into()),
        }
    }

    /// A legacy `Connection` to a mock PLC that runs `script` after answering the limits read.
    fn mock_connection(
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
        let target = ReconnectTarget::LegacyPlcsim {
            addrs: vec![addr],
            timeout,
        };
        let conn = Connection::new_legacy(tcp, mock_session(), target).unwrap();
        (conn, plc)
    }

    #[test]
    fn connect_reads_the_request_limits() {
        let (conn, plc) = mock_connection(Duration::from_secs(5), |_| {});
        assert_eq!(conn.max_tags_per_read(), 100);
        assert_eq!(conn.max_tags_per_write(), 100);
        plc.join().unwrap();
    }

    #[test]
    fn notifications_are_routed_to_their_subscription() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            plc.send(&notification(0xa, 0));
            plc.send(&notification(0xb, 0));
            plc.send(&notification(0xa, 0));
        });
        let a = Subscription { object_id: 0xa };
        let b = Subscription { object_id: 0xb };
        // B's notification is behind one of A's; A's is kept for its own call.
        let first = conn.next_notification(&b).unwrap();
        assert_eq!(first.subscription_object_id, 0xb);
        let second = conn.next_notification(&a).unwrap();
        assert_eq!(second.subscription_object_id, 0xa);
        let third = conn.next_any_notification().unwrap();
        assert_eq!(third.subscription_object_id, 0xa);
        plc.join().unwrap();
    }

    #[test]
    fn credit_is_topped_up_for_the_subscription_that_needs_it() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            // Unlimited B at a high tick needs nothing; finite A one tick before its limit does.
            plc.send(&notification(0xb, 200));
            plc.send(&notification(0xa, 9));
            let req = plc.recv_request();
            assert_eq!(&req[3..5], &functioncode::SET_VARIABLE.to_be_bytes());
            assert_eq!(&req[14..18], &0xau32.to_be_bytes(), "top-up must target A");
        });
        let a = conn.register_subscription(0xa, 10);
        let b = conn.register_subscription(0xb, -1);
        conn.next_notification(&b).unwrap();
        conn.next_notification(&a).unwrap();
        assert_eq!(conn.credit_limits.get(&0xa), Some(&15));
        plc.join().unwrap();
    }

    #[test]
    fn a_request_timeout_poisons_the_connection() {
        let (mut conn, plc) = mock_connection(Duration::from_millis(200), |mut plc| {
            plc.recv_request(); // never answered
            std::thread::sleep(Duration::from_millis(500));
        });
        let addr = ItemAddress {
            symbol_crc: 0,
            access_area: 1,
            access_sub_area: 2,
            lid: vec![3],
        };
        let e = conn
            .read_variables(std::slice::from_ref(&addr))
            .unwrap_err();
        // A late response would be taken as the answer to the next request: not retryable.
        assert!(!e.is_timeout(), "{e}");
        assert!(e.is_connection_lost(), "{e}");
        assert!(conn.is_poisoned());
        assert!(matches!(
            conn.read_variables(&[addr]),
            Err(Error::Closed(_))
        ));
        plc.join().unwrap();
    }

    #[test]
    fn a_response_with_a_bad_digest_poisons_the_connection() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            use std::io::Write;
            plc.recv_request();
            // Never parsed: the digest is checked first.
            let mut frame = MockPlc::frame(&[pdu::opcode::RESPONSE, 0, 0, 0, 0]);
            frame[7 + 4 + 1] ^= 1; // first digest byte, after TPKT/COTP and `72 03 len 20`
            plc.stream.write_all(&frame).unwrap();
        });
        let addr = ItemAddress {
            symbol_crc: 0,
            access_area: 1,
            access_sub_area: 2,
            lid: vec![3],
        };
        let e = conn
            .read_variables(std::slice::from_ref(&addr))
            .unwrap_err();
        assert!(matches!(e, Error::Integrity(_)), "{e}");
        assert!(e.is_connection_lost(), "{e}");
        assert!(conn.is_poisoned());
        plc.join().unwrap();
    }

    #[test]
    fn a_notification_with_a_bad_digest_poisons_the_connection() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            use std::io::Write;
            let mut frame = MockPlc::frame(&notification(0xa, 0));
            let trailer = frame.len() - 4;
            frame[trailer - 1] ^= 1; // last fragment byte
            plc.stream.write_all(&frame).unwrap();
        });
        let e = conn.next_any_notification().unwrap_err();
        assert!(matches!(e, Error::Integrity(_)), "{e}");
        assert!(conn.is_poisoned());
        plc.join().unwrap();
    }

    #[test]
    fn a_notification_timeout_mid_telegram_resumes() {
        let (mut conn, plc) = mock_connection(Duration::from_millis(150), |mut plc| {
            use std::io::Write;
            let frame = MockPlc::frame(&notification(0xa, 0));
            plc.stream.write_all(&frame[..20]).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            plc.stream.write_all(&frame[20..]).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let a = Subscription { object_id: 0xa };
        let e = conn.next_notification(&a).unwrap_err();
        assert!(e.is_timeout(), "{e}");
        assert!(!conn.is_poisoned());
        let n = loop {
            match conn.next_notification(&a) {
                Ok(n) => break n,
                Err(e) if e.is_timeout() => continue,
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(n.values, vec![(1, PValue::DInt(0xa))]);
        plc.join().unwrap();
    }

    /// Whether the request body `req` contains the serialized `addr`.
    fn has_address(req: &[u8], addr: &ItemAddress) -> bool {
        let mut bytes = Vec::new();
        addr.serialize(&mut bytes).unwrap();
        req.windows(bytes.len()).any(|w| w == bytes)
    }

    #[test]
    fn read_area_reads_a_byte_range() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            let req = plc.recv_request();
            assert_eq!(&req[3..5], &functioncode::GET_MULTI_VARIABLES.to_be_bytes());
            assert!(has_address(&req, &ItemAddress::raw(Area::Memory, 10, 3)));
            let mut rest = vec![1]; // item 1
            let value = PValue::Blob {
                root_id: 0,
                data: vec![1, 2, 3],
            };
            value.serialize(&mut rest).unwrap();
            rest.extend_from_slice(&[0, 0, 0]); // end of values, end of errors, integrity id
            plc.send(&plc.response(functioncode::GET_MULTI_VARIABLES, &rest));

            // The same read, refused as PLCSIM refuses an optimized block.
            plc.recv_request();
            let mut rest = vec![0, 1]; // no values; an error for item 1
            crate::wire::vlq::encode_u64(&mut rest, 0x8206_8d00_02bf_ffc3).unwrap();
            rest.extend_from_slice(&[0, 0]);
            plc.send(&plc.response(functioncode::GET_MULTI_VARIABLES, &rest));
        });
        assert_eq!(conn.read_area(Area::Memory, 10, 3).unwrap(), [1, 2, 3]);
        let e = conn.read_area(Area::Db(1), 0, 4).unwrap_err();
        assert!(e.to_string().contains("optimized"), "{e}");
        assert!(
            !conn.is_poisoned(),
            "an item error leaves the connection usable"
        );
        plc.join().unwrap();
    }

    #[test]
    fn write_area_writes_the_bytes_as_a_blob() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            let req = plc.recv_request();
            assert_eq!(&req[3..5], &functioncode::SET_MULTI_VARIABLES.to_be_bytes());
            assert!(has_address(&req, &ItemAddress::raw(Area::Db(5), 2, 2)));
            // Item 1's value: a Blob (flags 0, type 0x14, root id 0, length 2) of the bytes.
            assert!(req.windows(7).any(|w| w == [1, 0, 0x14, 0, 2, 0xab, 0xcd]));
            plc.send(&plc.response(functioncode::SET_MULTI_VARIABLES, &[0, 0]));
        });
        conn.write_area(Area::Db(5), 2, &[0xab, 0xcd]).unwrap();
        plc.join().unwrap();
    }

    /// The CPU execution unit reporting operating-state `code`, as PLCSIM does.
    fn exec_unit(code: i32) -> PObject {
        let mut unit = PObject::new(CPU_EXEC_UNIT_RID, 2179, 0);
        unit.add_attribute(
            CPU_OPERATING_STATE,
            PValue::Struct {
                id: 3481,
                elements: vec![
                    (3484, PValue::Word(1)),
                    (CPU_OPERATING_STATE_CODE, PValue::DInt(code)),
                ],
            },
        );
        unit
    }

    #[test]
    fn cpu_state_maps_the_operating_state_code() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            for code in [8, 4, 6] {
                let req = plc.recv_request();
                assert_eq!(&req[3..5], &functioncode::EXPLORE.to_be_bytes());
                assert_eq!(&req[14..18], &CPU_EXEC_UNIT_RID.to_be_bytes());
                plc.send(&plc.explore_response(CPU_EXEC_UNIT_RID, &[exec_unit(code)]));
            }
            plc.recv_request();
            let bare = PObject::new(CPU_EXEC_UNIT_RID, 2179, 0);
            plc.send(&plc.explore_response(CPU_EXEC_UNIT_RID, &[bare]));
        });
        assert_eq!(conn.cpu_state().unwrap(), CpuState::Run);
        assert_eq!(conn.cpu_state().unwrap(), CpuState::Stop);
        assert_eq!(conn.cpu_state().unwrap(), CpuState::Other(6));
        assert!(conn.cpu_state().is_err());
        plc.join().unwrap();
    }

    /// The type-info container is fetched once per connection, not on every `browse_vars`:
    /// an S7-1215C's is ~100 KB and took 6 s, three times per s7tool report (field run).
    /// `clear_caches` fetches it again.
    #[test]
    fn the_type_container_is_fetched_once() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            // Two fetches, then the mock hangs up: a third request would fail the test.
            for _ in 0..2 {
                let req = plc.recv_request();
                assert_eq!(&req[3..5], &functioncode::EXPLORE.to_be_bytes());
                assert_eq!(&req[14..18], &OMS_TYPE_INFO_CONTAINER_RID.to_be_bytes());
                plc.send(&plc.explore_response(OMS_TYPE_INFO_CONTAINER_RID, &[]));
            }
        });
        conn.prefetch_type_container().unwrap();
        conn.prefetch_type_container().unwrap();
        conn.clear_caches();
        conn.prefetch_type_container().unwrap();
        conn.prefetch_type_container().unwrap();
        plc.join().unwrap();
    }

    #[test]
    fn active_alarms_explores_the_alarm_subsystem() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            let req = plc.recv_request();
            assert_eq!(&req[3..5], &functioncode::EXPLORE.to_be_bytes());
            // Explore id 8 (the alarm subsystem), request id 2667 (VLQ 94 6b), children.
            assert_eq!(&req[14..21], &[0, 0, 0, 8, 0x94, 0x6b, 1]);
            let mut alarm = PObject::new(0x8a7e_0001, 2681, 0);
            alarm.add_attribute(2670, PValue::LWord(0x8a7e_0001_002a_0000)); // CpuAlarmId
            alarm.add_attribute(
                2673, // Coming
                PValue::Struct {
                    id: 0,
                    elements: vec![(3475, PValue::Timestamp(0))],
                },
            );
            let mut subsystem = PObject::new(8, 2668, 0);
            subsystem.objects.push(alarm);
            plc.send(&plc.explore_response(8, &[subsystem]));
        });
        let alarms = conn.active_alarms().unwrap();
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].cpu_alarm_id, 0x8a7e_0001_002a_0000);
        assert_eq!(alarms[0].state, crate::proto::AlarmState::Coming);
        plc.join().unwrap();
    }

    /// The reply to `cpu_state`'s Explore, captured from PLCSIM Advanced FW V2.8 (legacy) in RUN.
    /// Its object header carries attribute id flags (`92 59 06`); byte 0x47 is the state code.
    const CPU_STATE_RUN: &[u8] = include_bytes!("../tests/vectors/proto/explore_cpu_state_run.bin");

    #[test]
    fn cpu_state_from_a_plcsim_capture() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            // The PDU data, without the `72 03 len` header and the trailer, answering the
            // request's sequence number rather than the captured one.
            let mut body = CPU_STATE_RUN[4..CPU_STATE_RUN.len() - 4].to_vec();
            plc.recv_request();
            body[7..9].copy_from_slice(&plc.seq.to_be_bytes());
            plc.send(&body);
            // The same reply in STOP: the code is 4 there, the only change in this attribute.
            assert_eq!(body[0x47 - 4], 8);
            body[0x47 - 4] = 4;
            plc.recv_request();
            body[7..9].copy_from_slice(&plc.seq.to_be_bytes());
            plc.send(&body);
        });
        assert_eq!(conn.cpu_state().unwrap(), CpuState::Run);
        assert_eq!(conn.cpu_state().unwrap(), CpuState::Stop);
        plc.join().unwrap();
    }

    /// A framed telegram: opcode, function code and sequence number in the header, rest zero.
    fn telegram(opcode: u8, function: u16, sequence: u16) -> Vec<u8> {
        let mut body = vec![opcode, 0, 0];
        body.extend_from_slice(&function.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(&[0; 6]);
        pdu::frame_single_pdu(protocol_version::V2, &body)
    }

    #[test]
    fn a_response_must_answer_its_request() {
        use functioncode::{ERROR, EXPLORE, GET_MULTI_VARIABLES};
        use pdu::opcode::{NOTIFICATION, REQUEST, RESPONSE};
        let request = telegram(REQUEST, GET_MULTI_VARIABLES, 7);
        let check = |response: Vec<u8>| check_response_header(&request, &response);
        check(telegram(RESPONSE, GET_MULTI_VARIABLES, 7)).unwrap();
        check(telegram(RESPONSE, ERROR, 7)).unwrap(); // a failed request, answered generically
        for (opcode, function, sequence) in [
            (RESPONSE, GET_MULTI_VARIABLES, 6), // the answer to an earlier request
            (RESPONSE, EXPLORE, 7),             // the answer to another request
            (NOTIFICATION, GET_MULTI_VARIABLES, 7),
        ] {
            let e = check(telegram(opcode, function, sequence)).unwrap_err();
            assert!(matches!(e, Error::Closed(_)), "{e}");
        }
        assert!(check(telegram(RESPONSE, GET_MULTI_VARIABLES, 7)[..10].to_vec()).is_err());
    }

    #[test]
    fn a_response_to_another_request_poisons_the_connection() {
        let (mut conn, plc) = mock_connection(Duration::from_secs(5), |mut plc| {
            plc.recv_request();
            plc.seq = plc.seq.wrapping_sub(1); // answer the previous request instead
            plc.send(&plc.response(functioncode::GET_MULTI_VARIABLES, &[0, 0, 0]));
        });
        let e = conn.read_area(Area::Memory, 0, 1).unwrap_err();
        assert!(matches!(e, Error::Closed(_)), "{e}");
        assert!(e.is_connection_lost());
        assert!(conn.is_poisoned());
        plc.join().unwrap();
    }

    #[test]
    fn scan_telegram_waits_for_the_trailer() {
        let t = [0x72, 2, 0, 2, 9, 9, 0x72, 2, 0, 1, 8, 0x72, 2, 0, 0];
        for cut in 0..t.len() {
            assert_eq!(scan_telegram(&t[..cut]).unwrap(), None, "cut {cut}");
        }
        assert_eq!(scan_telegram(&t).unwrap(), Some((2, t.len(), 3)));
        assert!(scan_telegram(&[0x55, 2, 0, 0]).is_err());
    }
}
