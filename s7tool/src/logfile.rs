// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! The session log: everything the driver does (each request and response, with its bytes) and
//! everything s7tool prints, timestamped, in a text file. It is what to send along with a bug
//! report, especially from a PLC this project hasn't been tested against.
//!
//! The driver keeps passwords and key material out of its log records; see [`mask_secrets`] for
//! the command lines s7tool itself records.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::LevelFilter;
use s7commplus::value::datetime::S7DateTime;

/// Send log records to a new file at `path` (default: `s7tool-<UTC time>.log` in the current
/// directory) and return its path. Driver and s7tool records are kept down to trace level;
/// `RUST_LOG` can change that.
pub fn to_file(path: Option<&Path>) -> std::io::Result<PathBuf> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(format!("s7tool-{}.log", file_stamp())),
    };
    let file = File::create(&path)?;
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .filter_module("s7commplus", LevelFilter::Trace)
        .filter_module("s7tool", LevelFilter::Trace)
        .parse_env(env_logger::Env::default())
        .format_timestamp_micros()
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    Ok(path)
}

/// Without a session log: warnings to stderr, as before (`RUST_LOG` raises the level).
pub fn to_stderr() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
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
    log::info!(target: "s7tool", "command line: {}", mask_secrets(args).join(" "));
}

/// `args` with passwords replaced: the last argument of a `legit` command.
pub fn mask_secrets(args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    if let Some(i) = out.iter().position(|a| a == "legit") {
        if out.len() > i + 2 {
            if let Some(last) = out.last_mut() {
                *last = "<password>".into();
            }
        }
    }
    out
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

    #[test]
    fn passwords_are_masked() {
        assert_eq!(
            mask_secrets(&strings(&["--ip", "1.2.3.4", "legit", "admin", "hunter2"])),
            strings(&["--ip", "1.2.3.4", "legit", "admin", "<password>"])
        );
        assert_eq!(
            mask_secrets(&strings(&["legit", "\"\"", "pw"])),
            strings(&["legit", "\"\"", "<password>"])
        );
        // Not enough arguments to hold a password: nothing to mask.
        assert_eq!(mask_secrets(&strings(&["legit"])), strings(&["legit"]));
        assert_eq!(
            mask_secrets(&strings(&["read", "x"])),
            strings(&["read", "x"])
        );
    }

    #[test]
    fn file_names_sort_by_time() {
        let stamp = file_stamp();
        assert_eq!(stamp.len(), 15);
        assert_eq!(&stamp[8..9], "-");
        assert!(stamp.starts_with("20"));
    }
}
