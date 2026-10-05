// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! Keeping the PLC's project and the tester's computer out of the session log, so the log can be
//! sent along with a bug report from a site that isn't ours.
//!
//! The screen shows everything; the log file gets placeholders. Where s7tool prints a tag or
//! block name, a value, an alarm text or the PLC's address, it wraps it in a [`Private`], whose
//! text carries both forms between marker characters: [`screen`] keeps the real one, and the log
//! ([`for_log`], on each record before env_logger writes it, then [`RedactingWriter`] on each
//! line) the placeholder. Names keep a stable placeholder (`<name7>`) for the whole run, so a log
//! still shows which lines are about the same tag. A `Private` never spans lines or carries
//! control characters, and where its markers are broken the log gets `<redacted>` (it fails
//! closed).
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
/// Stands for a line break in a [`Private`]'s real text, so that a `Private` never spans lines
/// (the log writer goes line by line).
const NEWLINE: char = '\u{e003}';

/// What the log gets where it can't tell which part of a line is private: a `Private` whose end
/// or start is missing.
const REDACTED: &str = "<redacted>";

/// The shortest name looked for in other log lines; shorter ones (`x`, `M`) would also match
/// ordinary words.
const MIN_TRACKED_NAME: usize = 3;

/// Whether a name is looked for in other log lines: not too short, and not a plain lowercase
/// word, which s7tool's own text uses too (a tag named `done` would turn "report done" into
/// "report <name…>").
fn is_tracked(name: &str) -> bool {
    name.chars().count() >= MIN_TRACKED_NAME && !name.chars().all(|c| c.is_ascii_lowercase())
}

/// Text that is shown on screen but replaced in the session log.
pub struct Private {
    real: String,
    placeholder: String,
}

impl Private {
    fn new(real: impl fmt::Display, placeholder: impl Into<String>) -> Private {
        Private {
            real: clean(&real.to_string(), &NEWLINE.to_string()),
            placeholder: clean(&placeholder.into(), " "),
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

/// `text` made safe to carry inside a [`Private`]: no marker characters, each line break as
/// `newline`, and no other control characters (an escape sequence could make env_logger's output
/// layer swallow the markers around it), tabs aside. Each becomes U+FFFD.
fn clean(text: &str, newline: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => out.push_str(newline),
            '\t' => out.push('\t'),
            OPEN | SPLIT | CLOSE | NEWLINE => out.push('\u{fffd}'),
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
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

/// `text` as shown on screen: every [`Private`] in it as its real text.
pub fn screen(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find([OPEN, SPLIT, CLOSE]) {
        let marker = rest[start..].chars().next().unwrap_or(OPEN);
        out.push_str(&rest[..start]);
        rest = &rest[start + marker.len_utf8()..];
        if marker != OPEN {
            continue; // a stray marker: drop it
        }
        let end = rest.find(CLOSE).unwrap_or(rest.len());
        let inner = &rest[..end];
        let real = inner.split_once(SPLIT).map_or(inner, |(real, _)| real);
        out.extend(real.chars().filter_map(|c| match c {
            NEWLINE => Some('\n'),
            OPEN | SPLIT => None,
            c => Some(c),
        }));
        rest = rest.get(end + CLOSE.len_utf8()..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// `text` for the session log: with `redact`, every [`Private`] as its placeholder and the
/// addresses, paths and known names scrubbed; without, as on screen.
pub fn for_log(text: &str, redact: bool) -> String {
    log_line(text, redact, &mut false)
}

/// [`for_log`] for one line of a stream of lines: `open` says whether an earlier line left a
/// [`Private`] unfinished, whose rest this line then starts with.
fn log_line(text: &str, redact: bool, open: &mut bool) -> String {
    if !redact {
        return screen(text);
    }
    let text = placeholders(text, open);
    registry().scrub(&text)
}

/// Every [`Private`] in `text` as its placeholder. This fails closed: from a `Private` whose end
/// is missing, `<redacted>` replaces the rest of `text` (and `open` is set, so that the next
/// line is dropped up to the end marker), and so does it replace the text before a stray
/// separator or end marker (whose `Private` lost its start).
fn placeholders(text: &str, open: &mut bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    if *open {
        match rest.find(CLOSE) {
            Some(end) => {
                rest = &rest[end + CLOSE.len_utf8()..];
                *open = false;
            }
            None => return line_end(rest).to_owned(),
        }
    }
    while let Some(start) = rest.find([OPEN, SPLIT, CLOSE]) {
        let marker = rest[start..].chars().next().unwrap_or(OPEN);
        let after = &rest[start + marker.len_utf8()..];
        if marker != OPEN {
            out.push_str(REDACTED);
            rest = after;
            continue;
        }
        out.push_str(&rest[..start]);
        let Some(end) = after.find(CLOSE) else {
            out.push_str(REDACTED);
            out.push_str(line_end(after));
            *open = true;
            return out;
        };
        // The placeholder follows the last separator; one with a start marker in it means an
        // end marker went missing, and real text could follow that start.
        out.push_str(match after[..end].rsplit_once(SPLIT) {
            Some((_, placeholder)) if !placeholder.contains(OPEN) => placeholder,
            _ => REDACTED,
        });
        rest = &after[end + CLOSE.len_utf8()..];
    }
    out.push_str(rest);
    out
}

/// The line break `text` ends with, if any.
fn line_end(text: &str) -> &str {
    if text.ends_with("\r\n") {
        "\r\n"
    } else if text.ends_with('\n') {
        "\n"
    } else {
        ""
    }
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
        } else if is_tracked(core) {
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
///
/// Log records reach it already redacted (see [`crate::logfile`]); it is the second line of
/// defence, for anything written to the log some other way. A [`Private`] left unfinished at the
/// end of a line keeps the following lines out of the log until its end marker.
pub struct RedactingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
    redact: bool,
    /// Inside a [`Private`] that an earlier line started.
    open: bool,
}

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W, redact: bool) -> Self {
        RedactingWriter {
            inner,
            pending: Vec::new(),
            redact,
            open: false,
        }
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        let line = String::from_utf8_lossy(line);
        let line = log_line(&line, self.redact, &mut self.open);
        self.inner.write_all(line.as_bytes())
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
        let line = format!("{}", text("a\u{e002}b\u{e000}c\u{e003}d"));
        assert_eq!(for_log(&line, true), "<text>");
        assert_eq!(screen(&line), "a\u{fffd}b\u{fffd}c\u{fffd}d");
    }

    /// The whole of a multi-line text (a block's comment XML, an alarm text) stays out of the
    /// log, also when the log writer sees it one line at a time.
    #[test]
    fn multi_line_text_stays_out_of_the_log() {
        let xml = "<Ident>\r\n  <Comment>Secret_pump</Comment>\n</Ident>";
        let line = format!("attr 2449:\n{}\nend", text(xml));
        assert_eq!(
            screen(&line),
            "attr 2449:\n<Ident>\n  <Comment>Secret_pump</Comment>\n</Ident>\nend"
        );
        assert_eq!(for_log(&line, true), "attr 2449:\n<text>\nend");
        let mut out = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut out, true);
            w.write_all(format!("{line}\n").as_bytes()).unwrap();
            w.flush().unwrap();
        }
        assert_eq!(String::from_utf8(out).unwrap(), "attr 2449:\n<text>\nend\n");
    }

    /// Escape sequences in a value could make env_logger's output layer swallow the markers
    /// around it; they never get into a `Private`.
    #[test]
    fn control_characters_are_replaced() {
        let v = value("a\u{1b}]0;b\u{7}c\td\u{85}");
        assert_eq!(screen(&v.to_string()), "a\u{fffd}]0;b\u{fffd}c\td\u{fffd}");
        assert_eq!(for_log(&v.to_string(), true), "<value>");
        // A placeholder stays on its line too.
        assert_eq!(for_log(&path("x/a\nb").to_string(), true), "<dir>/a b");
    }

    /// Where a marker is missing, the log gets `<redacted>` rather than what might be real text.
    #[test]
    fn broken_markers_fail_closed() {
        let cases = [
            // No end marker: the rest of the text goes.
            ("a \u{e000}Secret_1\u{e001}<value> b", "a <redacted>"),
            // No separator.
            ("a \u{e000}Secret_1\u{e002} b", "a <redacted> b"),
            // No start marker: the text before the separator and the end marker goes.
            (
                "a Secret_1\u{e001}<value>\u{e002} b",
                "<redacted><redacted> b",
            ),
            // A lost end marker, then a whole `Private`: only the last placeholder is used.
            (
                "\u{e000}Secret_1\u{e001}<value> \u{e000}Secret_2\u{e001}<text>\u{e002}",
                "<text>",
            ),
            // ... unless that one lost its separator.
            (
                "\u{e000}Secret_1\u{e001}<value> \u{e000}Secret_2 x\u{e002}",
                "<redacted>",
            ),
        ];
        for (line, logged) in cases {
            assert_eq!(for_log(line, true), logged, "{line:?}");
            assert!(!screen(line).contains(['\u{e000}', '\u{e001}', '\u{e002}']));
        }
    }

    /// A `Private` that a line leaves open keeps the next lines out of the log until it ends.
    #[test]
    fn the_writer_drops_lines_inside_an_unfinished_private() {
        let mut out = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut out, true);
            w.write_all(
                b"a \xee\x80\x80Secret_1\nSecret_2\nSecret_3\xee\x80\x81<v>\xee\x80\x82 b\nc\n",
            )
            .unwrap();
            w.flush().unwrap();
        }
        assert_eq!(String::from_utf8(out).unwrap(), "a <redacted>\n\n b\nc\n");
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
        // Short names and plain words would hit s7tool's own text, so they aren't looked for.
        let _ = name("M");
        let _ = name("done");
        assert_eq!(for_log("M area (3 tags):", true), "M area (3 tags):");
        assert_eq!(
            for_log("report done: 7 of 7 steps succeeded", true),
            "report done: 7 of 7 steps succeeded"
        );
    }

    #[test]
    fn ip_addresses_are_replaced() {
        let _ = plc("192.0.2.42");
        let logged = for_log(
            "TCP connected to 192.0.2.42:102 via 192.0.2.1, mask 0.0.0.0",
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
