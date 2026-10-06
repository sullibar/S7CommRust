// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// s7tool — a minimal CLI built *on top of* the `s7commplus` crate, to exercise the driver
// against a live PLC: browse the symbol tree, read tags by name, and write them back.
//
// It lives in its own crate (depending on `s7commplus` by path) precisely to show the
// driver being consumed as an ordinary library dependency — copy this `src/` + the dep
// line in `Cargo.toml` into your own app and you have a working starting point.
//
//   s7tool --ip 192.168.0.1                          # interactive prompt
//   s7tool --ip 192.168.0.1 browse                   # one-shot: dump every tag + value
//   s7tool --ip 192.168.0.1 read Data_block_1.toto   # one-shot: read by symbol
//   s7tool --ip 192.168.0.1 write Data_block_1.titi 456
//   S7_PLC_IP=192.168.0.1 s7tool                     # IP/port may also come from env

use std::io::{self, Write};
use std::time::Duration;

use s7commplus::value::datatype::softdatatype as sdt;
use s7commplus::value::{datetime, strings, PValue};
use s7commplus::{
    Alarm, Area, AssociatedValue, Connection, CpuState, Error, Result, SubscriptionItem, VarInfo,
};

/// Print a line, and record it in the session log (where [`privacy::Private`] parts of it become
/// placeholders).
macro_rules! out {
    () => {
        out!("")
    };
    ($($arg:tt)*) => {{
        let line = format!($($arg)*);
        println!("{}", crate::privacy::screen(&line));
        log::info!(target: "s7tool::out", "{line}");
    }};
}

mod batch;
mod diag;
mod logfile;
mod privacy;
mod probe;

const PROMPT: &str = "s7> ";

fn main() {
    let cfg = match Config::from_args() {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("s7tool: {msg}\n");
            print_usage();
            std::process::exit(2);
        }
    };
    if let Some(batch) = &cfg.batch {
        // Each step runs as its own s7tool process with its own session log.
        logfile::to_stderr();
        match batch::run(batch) {
            Ok(true) => std::process::exit(0),
            Ok(false) => std::process::exit(1),
            Err(msg) => {
                eprintln!("s7tool: {msg}");
                std::process::exit(2);
            }
        }
    }
    let log_path = match &cfg.log {
        Log::Off => {
            logfile::to_stderr();
            None
        }
        Log::File(path) => match logfile::to_file(path.as_deref(), !cfg.full_log) {
            Ok(path) => {
                eprintln!("session log: {}", path.display());
                Some(path)
            }
            Err(e) => {
                eprintln!("s7tool: can't create the session log: {e}");
                std::process::exit(2);
            }
        },
    };
    // The address may come from the environment rather than the command line.
    let _ = privacy::plc(&cfg.ip);
    logfile::header(&std::env::args().skip(1).collect::<Vec<_>>());
    let result = run(cfg);
    if let Err(e) = &result {
        log::error!(target: "s7tool", "{}", privacy::error(e));
        eprintln!("error: {e}");
    }
    if let Some(path) = &log_path {
        eprintln!("session log written to {}", path.display());
    }
    if result.is_err() {
        std::process::exit(1);
    }
}

/// Where the session log goes.
enum Log {
    /// A file: the given path, or `s7tool-<UTC time>.log` in the current directory.
    File(Option<std::path::PathBuf>),
    /// No file: warnings to stderr only.
    Off,
}

/// Connection target plus the (possibly empty) one-shot command.
struct Config {
    ip: String,
    port: u16,
    /// Use the legacy (pre-TLS, FW < 2.9) PLCSIM (`03:`) transport instead of TLS.
    legacy: bool,
    /// Use the legacy real-hardware (`00:`/`01:`) transport, auto-detecting family + key.
    real_plc: bool,
    /// The PLC's pinned TLS certificate fingerprint (SHA-256), if any.
    pin: Option<[u8; 32]>,
    /// Try TLS, then the legacy real-PLC and PLCSIM schemes, until one connects.
    auto: bool,
    log: Log,
    /// Keep project data, addresses and paths in the session log (`--full-log`).
    full_log: bool,
    command: Vec<String>,
    /// `--targets <file>`: run the command against every PLC in the file instead.
    batch: Option<batch::Batch>,
    /// Socket timeout for connecting and for each request (`--timeout`, default 10 s).
    timeout: Duration,
}

impl Config {
    /// Parse `--ip/-i`, `--port/-p`, `-h/--help`, then treat the first bare token (and
    /// everything after it) as the command. IP/port fall back to `S7_PLC_IP`/`S7_PLC_PORT`.
    fn from_args() -> std::result::Result<Config, String> {
        let mut ip = std::env::var("S7_PLC_IP").ok();
        let mut port: u16 = std::env::var("S7_PLC_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(s7commplus::transport::tcp::ISO_TCP_PORT);
        let mut legacy = std::env::var("S7_LEGACY").is_ok();
        let mut real_plc = std::env::var("S7_REAL_PLC").is_ok();
        let mut pin = std::env::var("S7_PLC_CERT_SHA256").ok();
        let mut auto = false;
        let mut log = Log::File(None);
        let mut full_log = false;
        let mut command = Vec::new();
        let mut targets: Option<std::path::PathBuf> = None;
        let mut out_dir: Option<std::path::PathBuf> = None;
        let mut step_timeout = Duration::from_secs(20 * 60);
        let mut timeout: Option<u64> = None;
        let mut explicit_log = false;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--ip" | "-i" => ip = Some(args.next().ok_or("--ip needs a value")?),
                "--port" | "-p" => {
                    let v = args.next().ok_or("--port needs a value")?;
                    port = v.parse().map_err(|_| format!("invalid port: {v}"))?;
                }
                "--legacy" | "-l" => legacy = true,
                "--real-plc" => real_plc = true,
                "--pin" => pin = Some(args.next().ok_or("--pin needs a value")?),
                "--auto" => auto = true,
                "--log" => {
                    log = Log::File(Some(args.next().ok_or("--log needs a path")?.into()));
                    explicit_log = true;
                }
                "--no-log" => {
                    log = Log::Off;
                    explicit_log = true;
                }
                "--full-log" => full_log = true,
                "--targets" => targets = Some(args.next().ok_or("--targets needs a file")?.into()),
                "--out" => out_dir = Some(args.next().ok_or("--out needs a folder")?.into()),
                "--step-timeout" => {
                    let v = args.next().ok_or("--step-timeout needs minutes")?;
                    let min: u64 = v
                        .parse()
                        .ok()
                        .filter(|&m| m > 0)
                        .ok_or(format!("invalid --step-timeout: {v}"))?;
                    step_timeout = Duration::from_secs(min * 60);
                }
                "--timeout" => {
                    let v = args.next().ok_or("--timeout needs seconds")?;
                    timeout = Some(
                        v.parse()
                            .ok()
                            .filter(|s| (1..=600).contains(s))
                            .ok_or(format!("invalid --timeout (1–600 s): {v}"))?,
                    );
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                // First non-flag token starts the command; take the rest verbatim so tag
                // names are never mistaken for flags.
                _ => {
                    command.push(arg);
                    command.extend(args.by_ref());
                    break;
                }
            }
        }

        if let Some(targets_file) = targets {
            if legacy || real_plc || auto || pin.is_some() || explicit_log {
                return Err("with --targets, give the transport per PLC in the file \
                            (--auto is the default); every step writes its own log in --out"
                    .into());
            }
            return Ok(Config {
                ip: String::new(),
                port,
                legacy,
                real_plc,
                pin: None,
                auto,
                log,
                full_log,
                command: Vec::new(),
                timeout: Duration::from_secs(timeout.unwrap_or(10)),
                batch: Some(batch::Batch {
                    targets_file,
                    steps: batch::split_steps(&command),
                    out_dir,
                    step_timeout,
                    full_log,
                    timeout,
                }),
            });
        }
        if out_dir.is_some() {
            return Err("--out goes with --targets".into());
        }
        let ip = ip.ok_or("no PLC address — pass --ip <addr> or set S7_PLC_IP")?;
        let pin = match pin {
            Some(hex) => Some(
                parse_hex(&hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(format!(
                        "--pin needs 64 hex digits (a SHA-256), got {hex:?}"
                    ))?,
            ),
            None => None,
        };
        if pin.is_some() && (legacy || real_plc || auto) {
            return Err("--pin applies to TLS connections only".into());
        }
        if auto && (legacy || real_plc) {
            return Err("--auto picks the path itself; drop --legacy / --real-plc".into());
        }
        Ok(Config {
            ip,
            port,
            legacy,
            real_plc,
            pin,
            auto,
            log,
            full_log,
            command,
            timeout: Duration::from_secs(timeout.unwrap_or(10)),
            batch: None,
        })
    }
}

fn run(cfg: Config) -> Result<()> {
    let mode = if cfg.auto {
        "trying each path"
    } else if cfg.real_plc {
        "legacy real-PLC (00:/01:)"
    } else if cfg.legacy {
        "legacy PLCSIM (03:)"
    } else {
        "TLS"
    };
    out!(
        "connecting to {}:{} ({mode}) ...",
        privacy::plc(&cfg.ip),
        cfg.port
    );
    let timeout = cfg.timeout;
    let mut conn = if cfg.auto {
        connect_auto((cfg.ip.as_str(), cfg.port), timeout)?
    } else if cfg.real_plc {
        // S7_REAL_PLC_KEY=<hex 40-byte pubkey> forces an explicit key (for a PLC whose key
        // isn't in the bundled store); otherwise the key is auto-selected by fingerprint.
        let key = match std::env::var("S7_REAL_PLC_KEY") {
            Ok(hex) => Some(
                parse_hex(&hex).map_err(|e| Error::Protocol(format!("S7_REAL_PLC_KEY: {e}")))?,
            ),
            Err(_) => None,
        };
        match key {
            Some(key) => {
                Connection::connect_real_plc_with_key((cfg.ip.as_str(), cfg.port), timeout, &key)?
            }
            None => Connection::connect_real_plc((cfg.ip.as_str(), cfg.port), timeout)?,
        }
    } else if cfg.legacy {
        Connection::connect_legacy((cfg.ip.as_str(), cfg.port), timeout)?
    } else if let Some(pin) = cfg.pin {
        Connection::connect_pinned((cfg.ip.as_str(), cfg.port), timeout, pin)?
    } else {
        Connection::connect((cfg.ip.as_str(), cfg.port), timeout)?
    };
    // Over TLS, show the certificate fingerprint to pin with --pin.
    let certificate = conn
        .peer_certificate_sha256()
        .map(|fp| {
            format!(
                ", certificate SHA-256 = {}",
                privacy::certificate(hex(&fp).replace(' ', ""))
            )
        })
        .unwrap_or_default();
    out!(
        "connected — session_id = 0x{:08x}{certificate}",
        conn.session_id()
    );
    if let Some(description) = conn.plc_description() {
        out!("PLC describes itself as {description:?}");
    }

    if cfg.command.is_empty() {
        repl(&mut conn)?;
    } else {
        dispatch(&mut conn, &cfg.command)?;
    }
    // End the session cleanly, so the PLC frees it right away.
    conn.close()
}

/// Connect over whichever path the PLC speaks: TLS, then the legacy scheme of real S7-1200/1500
/// CPUs, then PLCSIM's. Only a PLC refusing a path moves on to the next; any other failure (no
/// route, no answer) ends the attempt.
fn connect_auto(addr: (&str, u16), timeout: Duration) -> Result<Connection> {
    out!("trying TLS ...");
    match Connection::connect(addr, timeout) {
        Ok(conn) => return Ok(conn),
        // "InitSsl rejected" covers both no-TLS signals real hardware sends: a genuine
        // InitSsl response carrying an error return value, and an error/abort function code
        // (Error2 0x05a9) from firmware that predates TLS S7CommPlus. Either way, fall through.
        Err(e) if e.to_string().contains("InitSsl rejected") => {
            out!("  no TLS: {}", privacy::error(e))
        }
        Err(e) => return Err(e),
    }
    out!("trying the legacy scheme of real S7-1200/1500 CPUs ...");
    match Connection::connect_real_plc(addr, timeout) {
        Ok(conn) => return Ok(conn),
        Err(e) if e.to_string().contains("no 00:/01: fingerprint") => {
            out!("  not a real CPU's key family: {}", privacy::error(e))
        }
        Err(e) => return Err(e),
    }
    out!("trying the legacy PLCSIM scheme ...");
    Connection::connect_legacy(addr, timeout)
}

/// Decode a hex string (a public key from the environment).
fn parse_hex(hex: &str) -> std::result::Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "expected an even number of hex digits, got {hex:?}"
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Split a REPL line on whitespace, except inside double quotes, since TIA names such as
/// `"My DB".x` may contain spaces. The quotes stay in the token: they are part of the symbol
/// syntax (see [`unquote`] for plain arguments).
fn split_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token: Option<String> = None;
    let mut quoted = false;
    for c in line.chars() {
        if c.is_whitespace() && !quoted {
            tokens.extend(token.take());
            continue;
        }
        if c == '"' {
            quoted = !quoted;
        }
        token.get_or_insert_with(String::new).push(c);
    }
    tokens.extend(token);
    tokens
}

/// A plain argument without its surrounding quotes, so `legit "" pw` passes an empty user and
/// `legit admin "two words"` a password with a space.
fn unquote(arg: &str) -> &str {
    arg.strip_prefix('"')
        .and_then(|a| a.strip_suffix('"'))
        .filter(|inner| !inner.contains('"'))
        .unwrap_or(arg)
}

/// Read commands from stdin until EOF or `quit`, dispatching each. A failed command prints
/// its error but keeps the session alive.
fn repl(conn: &mut Connection) -> Result<()> {
    out!("interactive mode — 'help' for commands, 'quit' to exit.");
    let stdin = io::stdin();
    loop {
        print!("{PROMPT}");
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            out!();
            break; // EOF (Ctrl-D / Ctrl-Z)
        }
        let parts = split_line(&line);
        match parts.first().map(String::as_str) {
            None => continue,
            Some("quit" | "exit" | "q") => break,
            Some(_) => {
                if let Err(e) = dispatch(conn, &parts) {
                    log::error!(target: "s7tool", "{}", privacy::error(&e));
                    eprintln!("error: {e}");
                }
            }
        }
    }
    Ok(())
}

/// Run one command (`cmd[0]` is the verb, the rest are arguments).
fn dispatch(conn: &mut Connection, cmd: &[String]) -> Result<()> {
    log::info!(target: "s7tool", "> {}", logfile::command_for_log(cmd));
    let result = run_command(conn, cmd);
    if result.is_err() {
        // The error may name a data block s7tool hasn't printed.
        remember_db_names(conn);
    }
    result
}

/// Have the session log look out for every data block's name, which a driver error may show (a
/// symbol that isn't found names the block it should have been quoted as, say). The list is
/// cached by the connection, so this costs a request only if nothing has needed it before.
fn remember_db_names(conn: &mut Connection) {
    if let Ok(dbs) = conn.datablock_list() {
        for db in &dbs {
            privacy::remember(&db.name);
        }
    }
}

fn run_command(conn: &mut Connection, cmd: &[String]) -> Result<()> {
    match cmd[0].as_str() {
        "help" | "?" => {
            print_help();
            Ok(())
        }
        "dbs" => list_dbs(conn),
        "xexplore" => {
            // xexplore <hexrelid> [recursive=1] [parents=0] [attr...] — diagnostic explore dump.
            // Trailing decimal ids restrict the requested attributes (e.g. 2544 = InterfaceDesc).
            if cmd.len() < 2 {
                out!("usage: xexplore <hexrelid> [recursive] [parents] [attr_id...]");
                return Ok(());
            }
            let Ok(relid) = u32::from_str_radix(cmd[1].trim_start_matches("0x"), 16) else {
                out!("bad hex relid: {}", cmd[1]);
                return Ok(());
            };
            let rec = cmd.get(2).and_then(|s| s.parse().ok()).unwrap_or(1u8);
            let par = cmd.get(3).and_then(|s| s.parse().ok()).unwrap_or(0u8);
            let attrs: Vec<u32> = cmd
                .get(4..)
                .unwrap_or(&[])
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            print!("{}", conn.explore_dump_attrs(relid, rec, par, &attrs)?);
            Ok(())
        }
        "xblob" => {
            // xblob <hexrelid> <attr_decimal> <outfile> — save matching blob attribute(s) to a file.
            if cmd.len() != 4 {
                out!("usage: xblob <hexrelid> <attr> <outfile>");
                return Ok(());
            }
            let Ok(relid) = u32::from_str_radix(cmd[1].trim_start_matches("0x"), 16) else {
                out!("bad hex relid: {}", cmd[1]);
                return Ok(());
            };
            let Ok(attr) = cmd[2].parse::<u32>() else {
                out!("bad attr: {}", cmd[2]);
                return Ok(());
            };
            let blobs = conn.explore_attr_blobs(relid, attr)?;
            for (i, (objrel, data)) in blobs.iter().enumerate() {
                let path = if blobs.len() > 1 {
                    format!("{}.{i}", cmd[3])
                } else {
                    cmd[3].clone()
                };
                std::fs::write(&path, data)
                    .map_err(|e| Error::Protocol(format!("write {path:?}: {e}")))?;
                out!(
                    "wrote {} bytes (obj 0x{objrel:08x}) -> {}",
                    data.len(),
                    privacy::path(&path)
                );
            }
            if blobs.is_empty() {
                out!("no blob attribute {attr} found under 0x{relid:08x}");
            }
            Ok(())
        }
        "xidents" | "idents" => {
            // xidents <hexrelid> — extract + inflate the compressed identity/comment blobs of a
            // DB/object: attr 2449 (IdentES identity XML) and 2546 (LineComments). These are zlib
            // streams that use a preset dictionary (see s7commplus::decompress_blob). NOTE: this is
            // identity/comment metadata, NOT the member layout — firmware may withhold both.
            if cmd.len() < 2 {
                out!("usage: xidents <hexrelid>   (a DB/object relid, e.g. from `dbs`)");
                return Ok(());
            }
            let Ok(relid) = u32::from_str_radix(cmd[1].trim_start_matches("0x"), 16) else {
                out!("bad hex relid: {}", cmd[1]);
                return Ok(());
            };
            let mut any = false;
            for (attr, label) in [(2449u32, "IdentES (identity)"), (2546, "LineComments")] {
                for (objrel, data) in conn.explore_attr_blobs(relid, attr)? {
                    if data.is_empty() {
                        continue;
                    }
                    any = true;
                    print!(
                        "obj 0x{objrel:08x} attr {attr} ({label}), {} compressed bytes:",
                        data.len()
                    );
                    match inflate_metadata_blob(&data) {
                        Ok(xml) => out!("\n{}\n", privacy::text(xml)),
                        Err(e) => out!(" <decompress failed: {}>", privacy::error(e)),
                    }
                }
            }
            if !any {
                out!(
                    "no identity/comment blobs served for 0x{relid:08x} (firmware may withhold them)"
                );
            }
            Ok(())
        }
        "xverify" => xverify(conn),
        "info" => diag::info(conn),
        "report" => diag::report(conn),
        "probe" => probe::probe(conn),
        "browse" => browse(conn, cmd.get(1).map(String::as_str)),
        "read" => {
            if cmd.len() < 2 {
                out!("usage: read <symbol> [<symbol> ...]");
                return Ok(());
            }
            for sym in &cmd[1..] {
                read_one(conn, sym);
            }
            Ok(())
        }
        "write" => {
            if cmd.len() != 3 {
                out!("usage: write <symbol> <value>");
                return Ok(());
            }
            write_one(conn, &cmd[1], &cmd[2])
        }
        "level" => {
            let level = conn.effective_protection_level()?;
            let note = if level <= 1 {
                "full access — no legitimation needed"
            } else {
                "restricted — 'legit <user> <pass>' may be required"
            };
            out!("effective protection level = {level} ({note})");
            Ok(())
        }
        "legit" => {
            if cmd.len() != 3 {
                out!("usage: legit <username> <password>   (empty user: legit \"\" <password>)");
                return Ok(());
            }
            conn.legitimate(unquote(&cmd[1]), unquote(&cmd[2]))?;
            out!("legitimation accepted.");
            Ok(())
        }
        "sub" => {
            // sub [count=6] [cycle_ms=1000] [notifications=5] [credit] — subscribe to the first
            // `count` scalar tags and print `notifications` updates. A finite `credit` (e.g. 5)
            // exercises the auto-refresh; omit for unlimited credit.
            let count: usize = cmd.get(1).and_then(|s| s.parse().ok()).unwrap_or(6);
            let cycle: u16 = cmd.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
            let notifs: usize = cmd.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            let credit: Option<i16> = cmd.get(4).and_then(|s| s.parse().ok());
            subscribe_demo(conn, count, cycle, notifs, credit)
        }
        "alarms" => {
            // alarms [polls=10] — subscribe to program/system alarms and poll for events.
            let polls: usize = cmd.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
            alarms_demo(conn, polls)
        }
        "pending" => pending(conn),
        "state" => {
            match conn.cpu_state()? {
                CpuState::Run => out!("RUN"),
                CpuState::Stop => out!("STOP"),
                CpuState::Other(code) => out!("operating state code {code}"),
            }
            Ok(())
        }
        "rawread" => {
            let (Some(area), Some(start), Some(len), 4) = (
                cmd.get(1).and_then(|s| parse_area(s)),
                cmd.get(2).and_then(|s| s.parse().ok()),
                cmd.get(3).and_then(|s| s.parse().ok()),
                cmd.len(),
            ) else {
                out!("usage: rawread <DB<n>|I|Q|M> <start> <len>");
                return Ok(());
            };
            out!(
                "{}",
                privacy::value(hex(&conn.read_area(area, start, len)?))
            );
            Ok(())
        }
        "rawwrite" => {
            let (Some(area), Some(start), Some(data), 4) = (
                cmd.get(1).and_then(|s| parse_area(s)),
                cmd.get(2).and_then(|s| s.parse().ok()),
                cmd.get(3)
                    .and_then(|s| parse_hex(s).ok())
                    .filter(|d| !d.is_empty()),
                cmd.len(),
            ) else {
                out!("usage: rawwrite <DB<n>|I|Q|M> <start> <hex bytes, e.g. 01ff>");
                return Ok(());
            };
            conn.write_area(area, start, &data)?;
            out!("wrote {} byte(s)", data.len());
            Ok(())
        }
        other => {
            out!("unknown command '{}' — type 'help'", privacy::name(other));
            Ok(())
        }
    }
}

/// Cross-check: every browsed variable's address must equal what `resolve_symbol` computes from
/// its name (two independent LID implementations agreeing means both are right).
fn xverify(conn: &mut Connection) -> Result<()> {
    let vars = conn.browse_vars()?;
    let (mut ok, mut bad) = (0u32, 0u32);
    for v in &vars {
        match conn.resolve_symbol(&v.name) {
            Ok(addr)
                if addr.access_area == v.access_area
                    && addr.access_sub_area == v.access_sub_area
                    && addr.lid == v.lids =>
            {
                ok += 1
            }
            Ok(addr) => {
                bad += 1;
                out!(
                    "MISMATCH {}: browse lids={:?} area=0x{:x}  resolve lids={:?} area=0x{:x}",
                    privacy::name(&v.name),
                    v.lids,
                    v.access_area,
                    addr.lid,
                    addr.access_area
                );
            }
            Err(e) => {
                bad += 1;
                out!(
                    "UNRESOLVED {}: {}",
                    privacy::name(&v.name),
                    privacy::error(e)
                );
            }
        }
    }
    out!(
        "xverify: {ok} consistent, {bad} mismatched (of {} vars)",
        vars.len()
    );
    Ok(())
}

/// List the alarms pending on the PLC.
fn pending(conn: &mut Connection) -> Result<()> {
    let alarms = conn.active_alarms()?;
    out!("{} pending alarm(s)", alarms.len());
    alarms.iter().for_each(print_alarm);
    Ok(())
}

/// List the data blocks the driver discovers in the PLC program.
fn list_dbs(conn: &mut Connection) -> Result<()> {
    let dbs = conn.datablock_list()?;
    if dbs.is_empty() {
        out!("(no data blocks found)");
        return Ok(());
    }
    for db in &dbs {
        out!(
            "DB{:<5} {} relid=0x{:08x}  ti=0x{:08x}",
            db.number,
            privacy::name(&db.name).padded(26),
            db.relid,
            db.ti_relid
        );
    }
    Ok(())
}

/// Print every readable tag and its current value. With no `target`, dumps all data blocks plus
/// the M/Q/I controller areas; otherwise limits to one DB name or area (`M`/`Q`/`I`). Uses the
/// bulk type-info container + a flat variable list, so nested structs and arrays (including
/// arrays of structs) are fully expanded, and value reads are batched.
fn browse(conn: &mut Connection, target: Option<&str>) -> Result<()> {
    let dbs = conn.datablock_list()?;
    // One bulk fetch of the whole program's type info (best effort; speeds up every block).
    let _ = conn.prefetch_type_container();

    for db in &dbs {
        if target.is_some_and(|t| !db.name.eq_ignore_ascii_case(t)) {
            continue;
        }
        out!(
            "DB \"{}\" (DB{}, relid 0x{:08x}):",
            privacy::name(&db.name),
            db.number,
            db.relid
        );
        match conn.browse_datablock(db.relid, db.ti_relid, &db.name) {
            Ok(vars) => print_values(conn, &vars, Some(&db.name)),
            // A DB whose interface the PLC withholds (TComSize=0, no VartypeList) is the signature
            // of a know-how-protected FB — not recoverable without the block's know-how password.
            Err(e) => {
                out!(
                    "  (skipped — interface withheld by PLC, likely know-how protected: {})",
                    privacy::error(e)
                )
            }
        }
        out!();
    }

    // Controller areas (M/Q/I): tags addressed by bare name, no DB prefix.
    for (area_rid, ti_relid, label, key) in [
        (82u32, 0x9003_0000u32, "M area", "M"),
        (81, 0x9002_0000, "Q area", "Q"),
        (80, 0x9001_0000, "I area", "I"),
    ] {
        if target.is_some_and(|t| !t.eq_ignore_ascii_case(key) && !t.eq_ignore_ascii_case(label)) {
            continue;
        }
        let vars = match conn.browse_controller_area(area_rid, ti_relid) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if vars.is_empty() && target.is_none() {
            continue; // skip empty areas in a full dump
        }
        out!("{label} ({} tags):", vars.len());
        print_values(conn, &vars, None);
        out!();
    }
    Ok(())
}

/// Read (batched) and print each variable as `name : Type = value`. `strip` removes a leading
/// `"<prefix>."` from the displayed name (the DB name), so members read like a nested listing.
fn print_values(conn: &mut Connection, vars: &[VarInfo], strip: Option<&str>) {
    let values = match conn.read_var_values(vars) {
        Ok(v) => v,
        Err(e) => {
            out!("  (read failed: {})", privacy::error(e));
            return;
        }
    };
    for (var, val) in vars.iter().zip(values) {
        // The DB level is double-quoted in `VarInfo::name` when the DB name contains a `.`.
        let disp = match strip {
            Some(p) => var
                .name
                .strip_prefix(p)
                .or_else(|| var.name.strip_prefix(&format!("\"{p}\"")))
                .and_then(|s| s.strip_prefix('.'))
                .unwrap_or(&var.name),
            None => &var.name,
        };
        let tname = sdt_name(var.softdatatype);
        let disp = privacy::name(disp);
        match val {
            Some(v) => out!(
                "  {disp} : {tname} = {}",
                privacy::value(fmt_typed(var.softdatatype, &v))
            ),
            None => out!("  {disp} : {tname} -> (no value / not readable)"),
        }
    }
}

/// Subscribe to the first `count` scalar tags and print `notifs` update notifications, showing
/// the credit/change flow and the per-tag values the PLC pushes. A finite `credit` limit
/// exercises the auto-refresh (the flow continues past the limit); `None` = unlimited.
fn subscribe_demo(
    conn: &mut Connection,
    count: usize,
    cycle_ms: u16,
    notifs: usize,
    credit: Option<i16>,
) -> Result<()> {
    use std::collections::HashMap;
    // Pick scalar tags (skip S7 STRING/struct forms to keep the demo output simple).
    let chosen: Vec<VarInfo> = conn
        .browse_vars()?
        .into_iter()
        .filter(|v| v.softdatatype != 19)
        .take(count)
        .collect();
    if chosen.is_empty() {
        out!("no subscribable tags found");
        return Ok(());
    }
    // reference id -> (name, softdatatype) so notifications can be printed by tag name.
    let mut meta: HashMap<u32, (String, u8)> = HashMap::new();
    let items: Vec<SubscriptionItem> = chosen
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let reference_id = (i + 1) as u32;
            meta.insert(reference_id, (v.name.clone(), v.softdatatype));
            SubscriptionItem {
                reference_id,
                address: v.address(),
            }
        })
        .collect();

    let sub = match credit {
        Some(c) => conn.subscribe_with(&items, cycle_ms, 0x14, c)?,
        None => conn.subscribe(&items, cycle_ms)?,
    };
    out!(
        "subscribed to {} tag(s), cycle {cycle_ms} ms, credit {} (object 0x{:08x}); waiting for {notifs} notification(s)...",
        items.len(),
        credit.map_or_else(|| "unlimited".to_string(), |c| c.to_string()),
        sub.object_id
    );
    for i in 1..=notifs {
        let n = conn.next_notification(&sub)?;
        out!(
            "notification #{i}: seq={} credit_tick={} values={} errors={}",
            n.sequence_number,
            n.credit_tick,
            n.values.len(),
            n.errors.len()
        );
        for (ref_id, val) in &n.values {
            let (name, sdt) = meta
                .get(ref_id)
                .cloned()
                .unwrap_or_else(|| (format!("ref#{ref_id}"), 0));
            out!(
                "   {} = {}",
                privacy::name(&name),
                privacy::value(fmt_typed(sdt, val))
            );
        }
        for (ref_id, code) in &n.errors {
            let name = meta
                .get(ref_id)
                .map(|(n, _)| n.clone())
                .unwrap_or_else(|| format!("ref#{ref_id}"));
            out!("   {} -> error 0x{code:02x}", privacy::name(&name));
        }
    }
    Ok(())
}

/// Subscribe to alarms and poll for `polls` reads, printing any alarm events (coming/going, id,
/// domain, timestamp). Timeouts (no alarm) are shown but don't abort — alarms are event-driven.
fn alarms_demo(conn: &mut Connection, polls: usize) -> Result<()> {
    let sub = conn.subscribe_alarms()?;
    out!(
        "alarm subscription created (object 0x{:08x}); polling {polls} time(s) for alarm events...",
        sub.object_id
    );
    let mut total = 0usize;
    for i in 1..=polls {
        match conn.next_notification(&sub) {
            Ok(n) => {
                let alarms = n.alarms();
                if alarms.is_empty() {
                    out!("  poll #{i}: notification, no alarm objects");
                }
                total += alarms.len();
                alarms.iter().for_each(print_alarm);
            }
            Err(e) if e.is_timeout() => out!("  poll #{i}: (no alarm within timeout)"),
            Err(e) => return Err(e),
        }
    }
    out!("done: {total} alarm event(s) received.");
    Ok(())
}

/// Print one alarm event: its state and ids, its message text, and its associated values.
fn print_alarm(a: &Alarm) {
    // (`type_name` is a transient object name, such as `TempDai_1`, not the alarm's.)
    out!(
        "  ALARM {:?} id=0x{:016x} domain={} msgtype={} seq={} @ {}",
        a.state,
        a.cpu_alarm_id,
        a.alarm_domain,
        a.message_type,
        a.sequence_counter,
        a.timestamp
    );
    // Render the message text (prefer en-US = 1033, else the first language sent). A PLC sends a
    // single space for an alarm without text.
    let text = a
        .message(1033)
        .or_else(|| a.texts.first().and_then(|t| a.message(t.language_id)));
    if let Some(msg) = text.filter(|m| !m.trim().is_empty()) {
        out!("      text: {}", privacy::text(msg));
    }
    for (i, v) in a.associated_values.iter().enumerate() {
        if *v != AssociatedValue::Unused {
            out!("      SD_{} = {}", i + 1, privacy::value(v));
        }
    }
}

/// Read and print one tag by symbol name, interpreted via its softdatatype.
fn read_one(conn: &mut Connection, sym: &str) {
    let read = conn
        .resolve_var(sym)
        .and_then(|var| Ok((var.softdatatype, conn.read_tag(sym)?)));
    let name = privacy::name(sym);
    match read {
        Ok((ty, v)) => out!(
            "  {name} : {} = {}",
            sdt_name(ty),
            privacy::value(fmt_typed(ty, &v))
        ),
        Err(e) => {
            remember_db_names(conn);
            out!("  {name} -> ERROR: {}", privacy::error(e))
        }
    }
}

/// Write one tag, then read it back to confirm. Strings and chars are written from the text as
/// typed; for other types the PLC value's wire type must match, so we read the current value
/// first and parse the user's text into that same `PValue` variant.
fn write_one(conn: &mut Connection, sym: &str, input: &str) -> Result<()> {
    let ty = conn.resolve_var(sym)?.softdatatype;
    match ty {
        // STRING / WSTRING: the driver frames them from the variable's declared max length.
        sdt::STRING => conn.write_string(sym, input)?,
        sdt::WSTRING => conn.write_wstring(sym, input)?,
        // CHAR is one ISO-8859-1 byte, WCHAR one UTF-16 code unit.
        sdt::CHAR | sdt::WCHAR => {
            let mut chars = input.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else {
                return Err(Error::Protocol(format!(
                    "{} expects a single character, got {input:?}",
                    sdt_name(ty)
                )));
            };
            let value = if ty == sdt::CHAR {
                u8::try_from(u32::from(c)).ok().map(PValue::USInt)
            } else {
                u16::try_from(u32::from(c)).ok().map(PValue::UInt)
            }
            .ok_or_else(|| Error::Protocol(format!("{c:?} does not fit in a {}", sdt_name(ty))))?;
            conn.write_tag(sym, value)?;
        }
        _ => {
            let current = conn.read_tag(sym)?;
            let value = parse_like(&current, input).ok_or_else(|| {
                Error::Protocol(format!("can't parse {input:?} as {}", type_name(&current)))
            })?;
            conn.write_tag(sym, value)?;
        }
    }
    out!(
        "  {} := {}",
        privacy::name(sym),
        privacy::value(fmt_typed(ty, &conn.read_tag(sym)?))
    );
    Ok(())
}

/// Parse `s` into the same `PValue` variant as `template` (so the wire type matches the PLC
/// variable). Integer/word types accept an optional `0x` hex prefix. Returns `None` for an
/// unparseable value or an unsupported (composite) template type.
fn parse_like(template: &PValue, s: &str) -> Option<PValue> {
    use PValue::*;
    let s = s.trim();
    Some(match template {
        Bool(_) => Bool(parse_bool(s)?),
        USInt(_) => USInt(u8::try_from(parse_uint(s)?).ok()?),
        UInt(_) => UInt(u16::try_from(parse_uint(s)?).ok()?),
        UDInt(_) => UDInt(u32::try_from(parse_uint(s)?).ok()?),
        ULInt(_) => ULInt(parse_uint(s)?),
        Byte(_) => Byte(u8::try_from(parse_uint(s)?).ok()?),
        Word(_) => Word(u16::try_from(parse_uint(s)?).ok()?),
        DWord(_) => DWord(u32::try_from(parse_uint(s)?).ok()?),
        LWord(_) => LWord(parse_uint(s)?),
        SInt(_) => SInt(s.parse().ok()?),
        Int(_) => Int(s.parse().ok()?),
        DInt(_) => DInt(s.parse().ok()?),
        LInt(_) => LInt(s.parse().ok()?),
        Real(_) => Real(s.parse().ok()?),
        LReal(_) => LReal(s.parse().ok()?),
        _ => return None,
    })
}

/// Parse an unsigned integer, accepting an optional `0x`/`0X` hex prefix.
fn parse_uint(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Parse a boolean from common spellings.
/// Parse a raw-access area: `DB<n>`, `I`, `Q` or `M` (any case).
fn parse_area(s: &str) -> Option<Area> {
    match s.to_ascii_uppercase().as_str() {
        "I" => Some(Area::Inputs),
        "Q" => Some(Area::Outputs),
        "M" => Some(Area::Memory),
        db => db.strip_prefix("DB")?.parse().ok().map(Area::Db),
    }
}

/// Format bytes as space-separated hex.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "t" | "on" | "yes" | "y" => Some(true),
        "0" | "false" | "f" | "off" | "no" | "n" => Some(false),
        _ => None,
    }
}

/// Render a value using the softdatatype `ty` it was read as: STRING/WSTRING as quoted text,
/// CHAR/WCHAR as quoted characters, date/time types as calendar/duration strings, and whole
/// arrays element by element. Anything else falls back to [`fmt_value`].
fn fmt_typed(ty: u8, v: &PValue) -> String {
    // A single STRING reads back as exactly `max_len + 2` bytes; a whole array of them as the
    // element buffers back to back.
    if let (sdt::STRING, PValue::USIntArray(b)) = (ty, v) {
        let stride = usize::from(b.first().copied().unwrap_or(0)) + 2;
        if b.len() > stride && b.len() % stride == 0 {
            let items: Vec<String> = b
                .chunks(stride)
                .map(|c| format!("{:?}", strings::decode_s7_string(c)))
                .collect();
            return format!("[{}]", items.join(", "));
        }
    }
    // Likewise a whole array of WSTRINGs (`max_len + 2` code units each) and of DATE_AND_TIMEs
    // (8 bytes each).
    if let (sdt::WSTRING, PValue::Array { items, .. }) = (ty, v) {
        let stride = match items.first() {
            Some(PValue::UInt(max)) => usize::from(*max) + 2,
            _ => 0,
        };
        if stride > 0 && items.len() > stride && items.len() % stride == 0 {
            let items: Vec<String> = items
                .chunks(stride)
                .map(|c| {
                    let element = PValue::Array {
                        element_type: v.datatype(),
                        flags: 0,
                        items: c.to_vec(),
                    };
                    format!(
                        "{:?}",
                        strings::decode_wstring(&element).unwrap_or_default()
                    )
                })
                .collect();
            return format!("[{}]", items.join(", "));
        }
    }
    if let (sdt::DATE_AND_TIME, PValue::USIntArray(b)) = (ty, v) {
        if b.len() > 8 && b.len() % 8 == 0 {
            let items: Vec<String> = b
                .chunks(8)
                .map(|c| {
                    datetime::format(ty, &PValue::USIntArray(c.to_vec()))
                        .unwrap_or_else(|| format!("{c:?}"))
                })
                .collect();
            return format!("[{}]", items.join(", "));
        }
    }
    let text = match (ty, v) {
        (sdt::STRING, PValue::USIntArray(b)) => Some(strings::decode_s7_string(b)),
        (sdt::WSTRING, _) => strings::decode_wstring(v),
        _ => None,
    };
    if let Some(s) = text {
        return format!("{s:?}");
    }
    if let Some(s) = datetime::format(ty, v) {
        return s;
    }
    match (ty, v) {
        (sdt::CHAR, PValue::USInt(b)) => format!("{:?}", char::from(*b)),
        (sdt::WCHAR, PValue::UInt(u)) => format!(
            "{:?}",
            char::from_u32(u32::from(*u)).unwrap_or(char::REPLACEMENT_CHARACTER)
        ),
        // A whole array (no index) reads back as an array of the element type.
        (_, PValue::Array { items, .. }) => {
            let items: Vec<String> = items.iter().map(|i| fmt_typed(ty, i)).collect();
            format!("[{}]", items.join(", "))
        }
        (_, PValue::USIntArray(b)) => {
            let items: Vec<String> = b
                .iter()
                .map(|&n| fmt_typed(ty, &PValue::USInt(n)))
                .collect();
            format!("[{}]", items.join(", "))
        }
        _ => fmt_value(v),
    }
}

/// Render a `PValue` compactly for display (word types also show hex), without knowing its
/// softdatatype — see [`fmt_typed`].
fn fmt_value(v: &PValue) -> String {
    use PValue::*;
    match v {
        Bool(b) => b.to_string(),
        USInt(n) => n.to_string(),
        UInt(n) => n.to_string(),
        UDInt(n) => n.to_string(),
        ULInt(n) => n.to_string(),
        SInt(n) => n.to_string(),
        Int(n) => n.to_string(),
        DInt(n) => n.to_string(),
        LInt(n) => n.to_string(),
        Byte(n) => format!("{n} (0x{n:02x})"),
        Word(n) => format!("{n} (0x{n:04x})"),
        DWord(n) => format!("{n} (0x{n:08x})"),
        LWord(n) => format!("{n} (0x{n:016x})"),
        Real(x) => x.to_string(),
        LReal(x) => x.to_string(),
        WString(s) => format!("{s:?}"),
        USIntArray(b) => format!("{b:?}"),
        Array { items, .. } => {
            let items: Vec<String> = items.iter().map(fmt_value).collect();
            format!("[{}]", items.join(", "))
        }
        // A whole struct/UDT/system type (IEC_TIMER, …) read in one go: its members' offsets
        // live in the type info, so show the raw member block.
        PackedStruct { id, data, .. } => {
            let hex: Vec<String> = data.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "<packed struct 0x{id:08x}, {} bytes: {}>",
                data.len(),
                hex.join(" ")
            )
        }
        RID(n) => format!("RID(0x{n:08x})"),
        other => format!("{other:?}"),
    }
}

/// The variant name of a scalar `PValue`, for error messages.
fn type_name(v: &PValue) -> &'static str {
    use PValue::*;
    match v {
        Bool(_) => "Bool",
        USInt(_) => "USInt",
        UInt(_) => "UInt",
        UDInt(_) => "UDInt",
        ULInt(_) => "ULInt",
        SInt(_) => "SInt",
        Int(_) => "Int",
        DInt(_) => "DInt",
        LInt(_) => "LInt",
        Byte(_) => "Byte",
        Word(_) => "Word",
        DWord(_) => "DWord",
        LWord(_) => "LWord",
        Real(_) => "Real",
        LReal(_) => "LReal",
        _ => "this type",
    }
}

/// Display name for a softdatatype (the TIA Portal name; unknowns become `sdtN`).
fn sdt_name(ty: u8) -> String {
    sdt::name(ty).map_or_else(|| format!("sdt{ty}"), str::to_string)
}

/// Full usage text (stderr; shown for `-h` and argument errors).
fn print_usage() {
    eprintln!(
        "s7tool — minimal CLI for the s7commplus driver\n\
         \n\
         USAGE:\n\
         \x20   s7tool [--ip <addr>] [--port <n>] [--auto | --legacy | --real-plc | --pin <sha256>]\n\
         \x20          [--log <file>] [--full-log | --no-log] [COMMAND ...]\n\
         \n\
         CONNECTION (flags must precede the command):\n\
         \x20   -i, --ip <addr>     PLC address           (or env S7_PLC_IP)\n\
         \x20   -p, --port <n>      ISO-on-TCP port, def 102 (or env S7_PLC_PORT)\n\
         \x20   -l, --legacy        legacy non-TLS transport, PLCSIM key family (03:),\n\
         \x20                       e.g. PLCSIM Advanced FW < 2.9    (or env S7_LEGACY)\n\
         \x20       --real-plc      legacy non-TLS transport for a physical S7-1200/1500 on\n\
         \x20                       older firmware (00:/01:); the key is picked by its\n\
         \x20                       fingerprint, or S7_REAL_PLC_KEY=<80 hex digits>\n\
         \x20                       sets it                           (or env S7_REAL_PLC)\n\
         \x20       --pin <sha256>  TLS: accept only the PLC whose certificate has this\n\
         \x20                       SHA-256 (64 hex digits, shown on connect)\n\
         \x20                                                  (or env S7_PLC_CERT_SHA256)\n\
         \x20       --auto          try TLS, then --real-plc, then --legacy: for a PLC whose\n\
         \x20                       path you don't know\n\
         \x20       --timeout <s>   how long to wait for the PLC (connect and each answer),\n\
         \x20                       default 10; more for a slow or busy CPU\n\
         \n\
         SESSION LOG:\n\
         \x20   Every run writes s7tool-<UTC time>.log in the current directory: each request\n\
         \x20   and response, and everything s7tool prints. It is safe to send on: tag and\n\
         \x20   block names, values and alarm texts become placeholders, IP addresses, paths\n\
         \x20   and your user name are replaced, and telegrams are logged only up to their\n\
         \x20   header. The screen still shows everything. No passwords or keys, ever.\n\
         \x20       --log <file>    write it to <file> instead\n\
         \x20       --full-log      keep names, values, addresses and whole telegrams in it\n\
         \x20       --no-log        don't write one\n\
         \n\
         SEVERAL PLCs IN A ROW:\n\
         \x20   s7tool --targets <file> [--out <folder>] [--step-timeout <min>] [--full-log]\n\
         \x20          [STEP ...]\n\
         \x20   The file lists one PLC per line: <ip>[:port] [label] [--auto | --real-plc |\n\
         \x20   --legacy | --pin <sha256>]; --auto when no transport is given; # starts a\n\
         \x20   comment. Each STEP runs against each PLC in turn, in a session of its own with\n\
         \x20   its own log, all in --out (default s7tool-batch-<UTC time>), next to a\n\
         \x20   summary.txt that names PLCs by label only. STEPs are single words\n\
         \x20   (report probe), or whole commands separated by + (report + read \"DB\".x);\n\
         \x20   default: report probe. A step still running after --step-timeout (default\n\
         \x20   20) minutes is stopped.\n\
         \n\
         With no COMMAND, s7tool connects and opens an interactive prompt.\n"
    );
    eprint!("{}", help_body());
    eprintln!(
        "\nEXAMPLES:\n\
         \x20   s7tool --ip 192.168.0.1\n\
         \x20   s7tool --ip 192.168.0.1 browse\n\
         \x20   s7tool --ip 192.168.0.1 read Data_block_1.toto Data_block_1.titi\n\
         \x20   s7tool --ip 192.168.0.1 write Data_block_1.titi 456\n\
         \x20   s7tool --ip 192.168.0.1 --legacy read Data_block_1.toto\n\
         \x20   s7tool --ip 192.168.0.1 --auto report     # everything, read-only, for a bug report\n\
         \x20   s7tool --targets plcs.txt                  # report, then probe, on every PLC"
    );
}

/// Inflate a compressed metadata blob (attr 2449 IdentES / 2546 LineComments) to its XML text.
/// These carry a 4-byte dictionary-version prefix before the zlib stream on this firmware, but
/// not universally — try `start_offset = 4` first, then fall back to 0.
fn inflate_metadata_blob(data: &[u8]) -> Result<String> {
    let out = match s7commplus::decompress_blob(data, 4) {
        Ok(o) => o,
        Err(_) => s7commplus::decompress_blob(data, 0)?,
    };
    String::from_utf8(out).map_err(|e| Error::Protocol(format!("blob is not UTF-8: {e}")))
}

/// Command list (stdout; shown for the `help` command inside the REPL).
fn print_help() {
    print!("{}", help_body());
}

fn help_body() -> &'static str {
    "COMMANDS:\n\
     \x20   info                what the PLC is (order number, firmware) and the session\n\
     \x20   report              run every read-only command below in turn, for the log\n\
     \x20   probe               read-only: how the PLC answers a read over its item limit and\n\
     \x20                       byte reads at the edges of M and of each DB (for the mock PLC)\n\
     \x20   browse [DB|M|Q|I]   recursively list tags with their current values\n\
     \x20   dbs                 list the data blocks\n\
     \x20   read <sym>...       read one or more tags by symbol name\n\
     \x20   write <sym> <val>   write a tag (parsed per the tag's declared type)\n\
     \x20   level               show the effective protection level\n\
     \x20   legit <user> <pw>   authenticate (legitimation); empty user: legit \"\" <pw>\n\
     \x20   xidents <relid>     decompress a DB's identity/comment XML (attr 2449/2546)\n\
     \x20   sub [n] [ms] [k] [c]  subscribe to n tags; print k notifications every ms (opt credit c)\n\
     \x20   alarms [polls]      subscribe to program/system alarms and poll for events\n\
     \x20   pending             list the alarms pending now (no subscription needed)\n\
     \x20   state               show the CPU operating state (RUN/STOP)\n\
     \x20   rawread <area> <start> <len>   read bytes at a byte offset of area DB<n>, I, Q or M\n\
     \x20                       (DB<n> must be a standard, not optimized, data block)\n\
     \x20   rawwrite <area> <start> <hex>  write bytes at a byte offset (e.g. rawwrite M 10 01ff)\n\
     \x20   help                show this help\n\
     \x20   quit                exit (interactive mode)\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_access_arguments_parse() {
        assert_eq!(parse_area("db5"), Some(Area::Db(5)));
        assert_eq!(parse_area("M"), Some(Area::Memory));
        assert_eq!(parse_area("i"), Some(Area::Inputs));
        assert_eq!(parse_area("Q"), Some(Area::Outputs));
        assert_eq!(parse_area("DB"), None);
        assert_eq!(parse_area("DB70000"), None);
        assert_eq!(parse_area("X"), None);
        assert_eq!(hex(&[0, 0xab]), "00 ab");
    }

    #[test]
    fn split_line_keeps_quoted_names_whole() {
        assert_eq!(
            split_line("read \"My DB\".x  plain.y\n"),
            ["read", "\"My DB\".x", "plain.y"]
        );
        assert_eq!(split_line("legit \"\" pw"), ["legit", "\"\"", "pw"]);
        assert_eq!(split_line("   "), Vec::<String>::new());
    }

    #[test]
    fn unquote_strips_only_whole_token_quotes() {
        assert_eq!(unquote("\"\""), "");
        assert_eq!(unquote("\"two words\""), "two words");
        assert_eq!(unquote("\"DB\".x"), "\"DB\".x");
        assert_eq!(unquote("\"a\".\"b\""), "\"a\".\"b\"");
        assert_eq!(unquote("plain"), "plain");
    }

    /// A whole array of WSTRINGs or DATE_AND_TIMEs shows every element, not just the first.
    #[test]
    fn whole_arrays_of_wstrings_and_date_and_times() {
        let wstring = |max: u16, s: &str| {
            let mut units = vec![max, s.encode_utf16().count() as u16];
            units.extend(s.encode_utf16());
            units.resize(usize::from(max) + 2, 0);
            units
        };
        let mut units = wstring(4, "ab");
        units.extend(wstring(4, "Wé"));
        units.extend(wstring(4, ""));
        let array = PValue::Array {
            element_type: s7commplus::value::datatype::tag::UINT,
            flags: s7commplus::value::datatype::flags::ARRAY,
            items: units.into_iter().map(PValue::UInt).collect(),
        };
        assert_eq!(fmt_typed(sdt::WSTRING, &array), r#"["ab", "Wé", ""]"#);
        let single = PValue::Array {
            element_type: s7commplus::value::datatype::tag::UINT,
            flags: s7commplus::value::datatype::flags::ARRAY,
            items: wstring(4, "ab").into_iter().map(PValue::UInt).collect(),
        };
        assert_eq!(fmt_typed(sdt::WSTRING, &single), r#""ab""#);

        let dt = [0x24, 0x03, 0x15, 0x13, 0x45, 0x30, 0x12, 0x36];
        let mut bytes = dt.to_vec();
        bytes.extend([0x99, 0x12, 0x31, 0x23, 0x59, 0x59, 0x00, 0x05]);
        assert_eq!(
            fmt_typed(sdt::DATE_AND_TIME, &PValue::USIntArray(bytes)),
            "[2024-03-15 13:45:30.123, 1999-12-31 23:59:59]"
        );
        assert_eq!(
            fmt_typed(sdt::DATE_AND_TIME, &PValue::USIntArray(dt.to_vec())),
            "2024-03-15 13:45:30.123"
        );
    }

    #[test]
    fn parse_hex_rejects_bad_input_instead_of_panicking() {
        assert_eq!(parse_hex("0aFF").unwrap(), vec![0x0a, 0xff]);
        assert!(parse_hex("abc").is_err()); // odd length
        assert!(parse_hex("zz").is_err());
        assert!(parse_hex("é0").is_err()); // non-ASCII used to panic slicing a char
    }
}
