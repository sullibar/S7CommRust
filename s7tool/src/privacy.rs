// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! Keeping the PLC's project and the tester's computer out of the session log, so the log can be
//! sent along with a bug report from a site that isn't ours.
//!
//! The screen shows everything; the log file gets placeholders. Where s7tool prints a tag or
//! block name, a value, an alarm text or the PLC's address, it wraps it in a [`Private`], whose
//! text carries both forms between marker characters: [`screen`] keeps the real one, and the log
//! writer ([`RedactingWriter`]) the placeholder. Names keep a stable placeholder (`<name7>`) for
//! the whole run, so a log still shows which lines are about the same tag.
//!
//! The writer also goes over every log line, the driver's too: IPv4 addresses become `<ip1>`,
//! `<ip2>`, … (the PLC's own is `<plc>`), the home directory becomes `~`, an absolute path keeps
//! only its file name, and a name s7tool has already printed is replaced wherever it shows up
//! again (an error message, say). The driver itself cuts its telegram dumps after the PDU header
//! and leaves names out ([`s7commplus::set_log_redaction`]). `--full-log` turns all of this off.
//!
//! This is best effort for the readable text: a name inside an error message is only caught once
//! s7tool has printed it. The telegram bytes, where most of a project lives, are not logged.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::{LazyLock, Mutex};

// The markers are private-use characters: env_logger drops control characters on the way to
// the log file, which would leave both halves of a `Private` in it.
/// Starts a [`Private`]: the real text follows.
const OPEN: char = '\u{e000}';
/// Separates the real text from the placeholder.
const SPLIT: char = '\u{e001}';
/// Ends a [`Private`].
const CLOSE: char = '\u{e002}';

/// The shortest name looked for in other log lines; shorter ones (`x`, `M`) would also match
/// ordinary words.
const MIN_TRACKED_NAME: usize = 3;

/// Text that is shown on screen but replaced in the session log.
pub struct Private {
    real: String,
    placeholder: String,
}

impl Private {
    fn new(real: impl fmt::Display, placeholder: impl Into<String>) -> Private {
        let real = real.to_string().replace([OPEN, SPLIT, CLOSE], "\u{fffd}");
        Private {
            real,
            placeholder: placeholder.into(),
        }
    }

    /// Left-aligned in a column `width` characters wide, on screen and in the log alike (a
    /// format width would count the hidden half too).
    pub fn padded(mut self, width: usize) -> Private {
        self.real = format!("{:<width$}", self.real);
        self.placeholder = format!("{:<width$}", self.placeholder);
        self
    }
}

impl fmt::Display for Private {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{OPEN}{}{SPLIT}{}{CLOSE}", self.real, self.placeholder)
    }
}

/// A tag, block, module or other project name: `<nameN>` in the log, the same N each time.
pub fn name(name: &str) -> Private {
    let placeholder = registry().name(name);
    Private::new(name, placeholder)
}

/// A tag's value (or bytes read from the PLC's memory).
pub fn value(value: impl fmt::Display) -> Private {
    Private::new(value, "<value>")
}

/// Free text from the project: an alarm message, a block's comments.
pub fn text(text: impl fmt::Display) -> Private {
    Private::new(text, "<text>")
}

/// The PLC's address, as given on the command line.
pub fn plc(addr: &str) -> Private {
    registry().plc(addr);
    Private::new(addr, "<plc>")
}

/// The PLC's certificate fingerprint, which identifies that one device.
pub fn certificate(fingerprint: impl fmt::Display) -> Private {
    Private::new(fingerprint, "<certificate>")
}

/// A user name for the PLC.
pub fn user(user: &str) -> Private {
    Private::new(user, "<user>")
}

/// A file path: only its file name in the log.
pub fn path(path: &str) -> Private {
    Private::new(path, file_name(path))
}

/// `line` as shown on screen: every [`Private`] in it as its real text.
pub fn screen(line: &str) -> String {
    resolve(line, false)
}

/// `line` for the session log: with `redact`, every [`Private`] as its placeholder and the
/// addresses, paths and known names scrubbed; without, as on screen.
pub fn for_log(line: &str, redact: bool) -> String {
    if !redact {
        return screen(line);
    }
    let line = resolve(line, true);
    registry().scrub(&line)
}

/// Keep one side of each [`Private`] in `line`.
fn resolve(line: &str, placeholders: bool) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let inner = &rest[start + OPEN.len_utf8()..];
        let Some(end) = inner.find(CLOSE) else {
            rest = inner;
            break;
        };
        let (real, placeholder) = inner[..end]
            .split_once(SPLIT)
            .unwrap_or((&inner[..end], ""));
        out.push_str(if placeholders { placeholder } else { real });
        rest = &inner[end + CLOSE.len_utf8()..];
    }
    out.push_str(rest);
    out
}

/// What the log writer replaces, learned as the run goes.
struct Registry {
    /// Names printed so far, and their placeholders.
    names: HashMap<String, String>,
    /// IPv4 addresses seen so far, and their placeholders.
    ips: HashMap<String, String>,
    /// The tester's home directory and user name, from the environment.
    home: Option<String>,
    user: Option<String>,
}

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
        let env = |keys: &[&str]| {
            keys.iter()
                .find_map(|k| std::env::var(k).ok())
                .filter(|v| v.len() > 1)
        };
        Mutex::new(Registry {
            names: HashMap::new(),
            ips: HashMap::new(),
            home: env(&["HOME", "USERPROFILE"]),
            user: env(&["USER", "USERNAME", "LOGNAME"]),
        })
    });
    // A panic while holding the lock leaves the data usable.
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

impl Registry {
    fn name(&mut self, name: &str) -> String {
        let n = self.names.len() + 1;
        self.names
            .entry(name.to_owned())
            .or_insert_with(|| format!("<name{n}>"))
            .clone()
    }

    fn plc(&mut self, addr: &str) {
        if is_ipv4(addr) {
            self.ips.insert(addr.to_owned(), "<plc>".into());
        } else {
            self.names.insert(addr.to_owned(), "<plc>".into());
        }
    }

    fn scrub(&mut self, line: &str) -> String {
        let line = match &self.home {
            Some(home) => line.replace(home.as_str(), "~"),
            None => line.to_owned(),
        };
        let line = self.scrub_ips(&line);
        let mut out = String::with_capacity(line.len());
        let mut token = String::new();
        for c in line.chars() {
            if c.is_whitespace() {
                out.push_str(&self.scrub_token(&token));
                token.clear();
                out.push(c);
            } else {
                token.push(c);
            }
        }
        out.push_str(&self.scrub_token(&token));
        out
    }

    /// Replace each IPv4 address in `line`, except `0.0.0.0` and loopback.
    fn scrub_ips(&mut self, line: &str) -> String {
        let b = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut copied = 0;
        let mut i = 0;
        while i < b.len() {
            let starts = b[i].is_ascii_digit()
                && (i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'.'));
            if let Some(len) = starts.then(|| ipv4_len(&b[i..])).flatten() {
                let ip = &line[i..i + len];
                if ip != "0.0.0.0" && !ip.starts_with("127.") {
                    let n = self.ips.len() + 1;
                    let placeholder = self
                        .ips
                        .entry(ip.to_owned())
                        .or_insert_with(|| format!("<ip{n}>"));
                    out.push_str(&line[copied..i]);
                    out.push_str(placeholder);
                    copied = i + len;
                }
                i += len;
            } else {
                i += 1;
            }
        }
        out.push_str(&line[copied..]);
        out
    }

    /// One whitespace-free token: a path, the user name, or a name printed before.
    fn scrub_token(&self, token: &str) -> String {
        let core = token.trim_matches(|c: char| "\"'`()[]{},;:".contains(c));
        if core.is_empty() {
            return token.to_owned();
        }
        let replacement = if is_absolute_path(core) {
            Some(file_name(core))
        } else if self.user.as_deref() == Some(core) {
            Some("<user>".to_owned())
        } else if core.chars().count() >= MIN_TRACKED_NAME {
            self.names.get(core).cloned()
        } else {
            None
        };
        match replacement {
            Some(r) => token.replacen(core, &r, 1),
            None => token.to_owned(),
        }
    }
}

/// The length of the IPv4 address `b` starts with, if it starts with one that isn't followed by
/// more digits or another dotted number.
fn ipv4_len(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    for part in 0..4 {
        if part > 0 {
            if b.get(i) != Some(&b'.') {
                return None;
            }
            i += 1;
        }
        let digits = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=3).contains(&digits) {
            return None;
        }
        let n: u32 = std::str::from_utf8(&b[i..i + digits]).ok()?.parse().ok()?;
        if n > 255 {
            return None;
        }
        i += digits;
    }
    let more = b.get(i).is_some_and(|c| c.is_ascii_digit())
        || (b.get(i) == Some(&b'.') && b.get(i + 1).is_some_and(|c| c.is_ascii_digit()));
    (!more).then_some(i)
}

fn is_ipv4(s: &str) -> bool {
    ipv4_len(s.as_bytes()) == Some(s.len())
}

/// An absolute path on macOS, Linux or Windows, or one under the home directory.
fn is_absolute_path(s: &str) -> bool {
    let b = s.as_bytes();
    (s.starts_with('/') && s[1..].contains('/'))
        || s.starts_with("~/")
        || s.starts_with("~\\")
        || s.starts_with("\\\\")
        || (b.len() > 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'\\' | b'/'))
}

/// A path's last component, after `<dir>/` when there is a directory part.
fn file_name(path: &str) -> String {
    match path.trim_end_matches(['/', '\\']).rsplit_once(['/', '\\']) {
        Some((_, name)) if !name.is_empty() => format!("<dir>/{name}"),
        Some(_) => "<dir>".to_owned(),
        None => path.to_owned(),
    }
}

/// A writer for log records that passes each complete line through [`for_log`].
pub struct RedactingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
    redact: bool,
}

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W, redact: bool) -> Self {
        RedactingWriter {
            inner,
            pending: Vec::new(),
            redact,
        }
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        let line = String::from_utf8_lossy(line);
        self.inner.write_all(for_log(&line, self.redact).as_bytes())
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(end) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            self.write_line(&line)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.write_line(&line)?;
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_shows_real_text_and_log_the_placeholder() {
        let line = format!("  {} : Int = {}", name("Pump_speed"), value(42));
        assert_eq!(screen(&line), "  Pump_speed : Int = 42");
        let logged = for_log(&line, true);
        assert!(logged.starts_with("  <name"), "{logged}");
        assert!(logged.ends_with("> : Int = <value>"), "{logged}");
        assert_eq!(for_log(&line, false), screen(&line));
        // The same name keeps its placeholder.
        assert_eq!(
            for_log(&format!("{}", name("Pump_speed")), true),
            logged[2..logged.find(" :").unwrap()]
        );
    }

    #[test]
    fn markers_in_real_text_cannot_break_out() {
        let line = format!("{}", text("a\u{e002}b\u{e000}c"));
        assert_eq!(for_log(&line, true), "<text>");
        assert_eq!(screen(&line), "a\u{fffd}b\u{fffd}c");
    }

    /// The markers have to survive env_logger's output layer, which drops control characters.
    #[test]
    fn placeholders_survive_env_logger() {
        #[derive(Clone, Default)]
        struct Shared(std::sync::Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let buf = Shared::default();
        let logger = env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .format_timestamp(None)
            .target(env_logger::Target::Pipe(Box::new(RedactingWriter::new(
                buf.clone(),
                true,
            ))))
            .build();
        let line = format!("{} = {}", name("Valve_open"), value(true));
        log::Log::log(
            &logger,
            &log::Record::builder()
                .args(format_args!("{line}"))
                .level(log::Level::Info)
                .target("s7tool::out")
                .build(),
        );
        log::Log::flush(&logger);
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(!logged.contains("Valve_open"), "{logged}");
        assert!(logged.trim_end().ends_with("> = <value>"), "{logged}");
    }

    #[test]
    fn names_printed_before_are_caught_in_other_lines() {
        let _ = name("Conveyor_Motor_3");
        assert_eq!(
            for_log("error: member 'Conveyor_Motor_3' not found", true),
            format!(
                "error: member '{}' not found",
                registry().names["Conveyor_Motor_3"]
            )
        );
        // Short names would hit ordinary words, so they aren't looked for.
        let _ = name("M");
        assert_eq!(for_log("M area (3 tags):", true), "M area (3 tags):");
    }

    #[test]
    fn ip_addresses_are_replaced() {
        let _ = plc("192.168.17.42");
        let logged = for_log(
            "TCP connected to 192.168.17.42:102 via 10.0.0.1, mask 0.0.0.0",
            true,
        );
        assert!(
            logged.starts_with("TCP connected to <plc>:102 via <ip"),
            "{logged}"
        );
        assert!(logged.ends_with(">, mask 0.0.0.0"), "{logged}");
        // Versions, times and longer dotted numbers are not addresses.
        for kept in [
            "s7tool 0.3.1 on macos",
            "12:00:00.123456Z",
            "1.2.3.4.5",
            "V4.2.3",
            "1.5 ms",
        ] {
            assert_eq!(for_log(kept, true), kept);
        }
        assert!(!is_ipv4("256.1.1.1"));
    }

    #[test]
    fn paths_keep_only_their_file_name() {
        for (path, logged) in [
            ("/Users/someone/Desktop/run.log", "<dir>/run.log"),
            ("C:\\Users\\someone\\run.log", "<dir>/run.log"),
            ("~/testing/run.log", "<dir>/run.log"),
            ("/Users/someone/", "<dir>/someone"),
        ] {
            assert_eq!(
                for_log(&format!("--log {path} report"), true),
                format!("--log {logged} report")
            );
        }
        assert_eq!(for_log("1/2 done, a/b", true), "1/2 done, a/b");
        assert_eq!(screen(&path("/x/y/z.log").to_string()), "/x/y/z.log");
    }

    #[test]
    fn the_writer_redacts_whole_lines() {
        let mut out = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut out, true);
            let line = format!("value {}\n", value(7));
            let (a, b) = line.split_at(4);
            w.write_all(a.as_bytes()).unwrap();
            w.write_all(b.as_bytes()).unwrap();
            w.write_all(b"tail").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(String::from_utf8(out).unwrap(), "value <value>\ntail");
    }
}
