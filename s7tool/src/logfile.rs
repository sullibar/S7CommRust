// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! The session log: everything the driver does (each request and response) and everything
//! s7tool prints, timestamped, in a text file. It is what to send along with a bug report,
//! especially from a PLC this project hasn't been tested against.
//!
//! By default the log keeps the PLC's project and the tester's computer out of it (see
//! [`crate::privacy`]); `--full-log` keeps everything but passwords. The driver keeps passwords
//! and key material out of its log records; see [`command_for_log`] for the command lines s7tool
//! itself records.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::LevelFilter;
use s7commplus::value::datetime::S7DateTime;

use crate::privacy::{self, RedactingWriter};

/// Send log records to a new file at `path` (default: `s7tool-<UTC time>.log` in the current
/// directory) and return its path. Driver and s7tool records are kept down to trace level;
/// `RUST_LOG` can change that. With `redact`, project data and the tester's paths and addresses
/// are replaced (see [`crate::privacy`]).
pub fn to_file(path: Option<&Path>, redact: bool) -> std::io::Result<PathBuf> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(format!("s7tool-{}.log", file_stamp())),
    };
    let file = File::create(&path)?;
    s7commplus::set_log_redaction(redact);
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .filter_module("s7commplus", LevelFilter::Trace)
        .filter_module("s7tool", LevelFilter::Trace)
        .parse_env(env_logger::Env::default())
        .format_timestamp_micros()
        .target(env_logger::Target::Pipe(Box::new(RedactingWriter::new(
            file, redact,
        ))))
        .init();
    Ok(path)
}

/// Without a session log: warnings to stderr, as before (`RUST_LOG` raises the level).
pub fn to_stderr() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .target(env_logger::Target::Pipe(Box::new(RedactingWriter::new(
            std::io::stderr(),
            false,
        ))))
        .init();
}

/// Record what is being run and with what, at the top of the log.
pub fn header(args: &[String]) {
    log::info!(
        target: "s7tool",
        "s7tool {} (s7commplus {}, commit {}) on {}/{}",
        env!("CARGO_PKG_VERSION"),
        s7commplus::VERSION,
        env!("S7TOOL_GIT_COMMIT"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    log::info!(target: "s7tool", "command line: {}", command_line_for_log(args));
}

/// s7tool's arguments for the log: the connection flags' values marked private, then the
/// command as [`command_for_log`] shows it.
pub fn command_line_for_log(args: &[String]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = args.get(i + 1);
        let shown = match (arg, value) {
            ("--ip" | "-i", Some(v)) => Some(privacy::plc(v).to_string()),
            ("--pin", Some(v)) => Some(privacy::certificate(v).to_string()),
            ("--log", Some(v)) => Some(privacy::path(v).to_string()),
            ("--port" | "-p", Some(v)) => Some(v.clone()),
            _ => None,
        };
        if let Some(shown) = shown {
            out.push(arg.to_owned());
            out.push(shown);
            i += 2;
        } else if arg.starts_with('-') {
            out.push(arg.to_owned());
            i += 1;
        } else {
            out.push(command_for_log(&args[i..]));
            break;
        }
    }
    out.join(" ")
}

/// A command for the log: passwords replaced, names, values and paths marked private. Numbers
/// (counts, offsets, object ids) stay as typed.
pub fn command_for_log(cmd: &[String]) -> String {
    let Some(verb) = cmd.first() else {
        return String::new();
    };
    let args = &cmd[1..];
    let shown: Vec<String> = match verb.as_str() {
        "legit" => args
            .iter()
            .enumerate()
            .map(|(i, a)| match i {
                0 if args.len() > 1 => privacy::user(a).to_string(),
                _ => "<password>".to_owned(),
            })
            .collect(),
        "read" => args.iter().map(|a| privacy::name(a).to_string()).collect(),
        "write" => args
            .iter()
            .enumerate()
            .map(|(i, a)| match i {
                0 => privacy::name(a).to_string(),
                _ => privacy::value(a).to_string(),
            })
            .collect(),
        "browse" => args
            .iter()
            .map(|a| match a.to_ascii_uppercase().as_str() {
                "M" | "Q" | "I" => a.clone(),
                _ => privacy::name(a).to_string(),
            })
            .collect(),
        "xblob" => args
            .iter()
            .enumerate()
            .map(|(i, a)| match i {
                2 => privacy::path(a).to_string(),
                _ => a.clone(),
            })
            .collect(),
        "help" | "?" | "dbs" | "xexplore" | "xidents" | "idents" | "xverify" | "info"
        | "report" | "probe" | "level" | "sub" | "alarms" | "pending" | "state" | "rawread" => {
            args.to_vec()
        }
        "rawwrite" => args
            .iter()
            .enumerate()
            .map(|(i, a)| match i {
                2 => privacy::value(a).to_string(),
                _ => a.clone(),
            })
            .collect(),
        // Anything else may be a mistyped tag name.
        _ => {
            return std::iter::once(verb)
                .chain(args)
                .map(|a| privacy::name(a).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        }
    };
    std::iter::once(verb.clone())
        .chain(shown)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The current UTC time as `YYYYMMDD-HHMMSS`, for log file names.
fn file_stamp() -> String {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);
    let t = S7DateTime::from_unix_nanos(ns);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn logged(line: String) -> String {
        privacy::for_log(&line, true)
    }

    #[test]
    fn passwords_are_masked_even_in_a_full_log() {
        let line = command_line_for_log(&strings(&[
            "--ip",
            "192.0.2.10",
            "legit",
            "admin",
            "hunter2",
        ]));
        assert_eq!(
            privacy::screen(&line),
            "--ip 192.0.2.10 legit admin <password>"
        );
        assert_eq!(logged(line), "--ip <plc> legit <user> <password>");
        assert_eq!(
            privacy::screen(&command_for_log(&strings(&["legit", "\"\"", "pw"]))),
            "legit \"\" <password>"
        );
        // A lone argument is the password (the command is malformed, but don't log it).
        assert_eq!(
            command_for_log(&strings(&["legit", "pw"])),
            "legit <password>"
        );
        assert_eq!(command_for_log(&strings(&["legit"])), "legit");
    }

    #[test]
    fn project_data_and_paths_are_private() {
        let line = command_line_for_log(&strings(&[
            "--port",
            "102",
            "--log",
            "/Users/someone/plc.log",
            "--auto",
            "write",
            "Tank.level",
            "17",
        ]));
        assert_eq!(
            privacy::screen(&line),
            "--port 102 --log /Users/someone/plc.log --auto write Tank.level 17"
        );
        let logged = logged(line);
        assert!(
            logged.starts_with("--port 102 --log <dir>/plc.log --auto write <name"),
            "{logged}"
        );
        assert!(logged.ends_with("> <value>"), "{logged}");
        assert_eq!(logged_command(&["sub", "6", "1000", "5"]), "sub 6 1000 5");
        assert_eq!(logged_command(&["browse", "m"]), "browse m");
        assert_eq!(logged_command(&["rawread", "M", "0", "4"]), "rawread M 0 4");
        assert_eq!(
            logged_command(&["rawwrite", "M", "0", "01ff"]),
            "rawwrite M 0 <value>"
        );
        assert!(logged_command(&["Tank.level"]).starts_with("<name"));
    }

    fn logged_command(cmd: &[&str]) -> String {
        logged(command_for_log(&strings(cmd)))
    }

    #[test]
    fn file_names_sort_by_time() {
        let stamp = file_stamp();
        assert_eq!(stamp.len(), 15);
        assert_eq!(&stamp[8..9], "-");
        assert!(stamp.starts_with("20"));
    }
}
