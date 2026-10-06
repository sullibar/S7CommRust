// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! `--targets <file>`: run the same steps against every PLC listed in a text file, one after the
//! other, without typing the command for each.
//!
//! Each step of each PLC runs as its own `s7tool` process (this executable, with `--ip` and
//! `--log` filled in), so it gets its own session and its own session log, a PLC's names never
//! end up in another PLC's log, and a step that hangs can be stopped without losing the rest.
//! The run's folder holds those logs plus `summary.txt`, which is built from the (redacted) logs
//! and names PLCs by their label only, so the folder can be sent on as it is.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One PLC from the targets file.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// The address as `--ip` takes it (no port).
    pub ip: String,
    pub port: Option<u16>,
    /// Names the PLC in log file names and the summary (never its address).
    pub label: String,
    /// Transport flags for this PLC (`--real-plc`, `--legacy`, `--pin <sha256>`); `--auto` when
    /// none is given.
    pub flags: Vec<String>,
}

/// Options of a batch run.
pub struct Batch {
    pub targets_file: PathBuf,
    /// The steps, each a command line (`report`, `probe`, `read "DB".x`).
    pub steps: Vec<Vec<String>>,
    pub out_dir: Option<PathBuf>,
    pub step_timeout: Duration,
    pub full_log: bool,
    /// `--timeout` seconds, passed on to every step.
    pub timeout: Option<u64>,
}

/// Parse a targets file: one PLC per line, `<ip>[:port] [label] [flags]`, in any order after the
/// address; blank lines and `#` comments are skipped. A missing label becomes `plcNN` (its line
/// position); labels are made file-name safe and unique.
pub fn parse_targets(text: &str) -> Result<Vec<Target>, String> {
    let mut targets: Vec<Target> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = |msg: String| format!("targets file line {}: {msg}", n + 1);
        let mut tokens = line.split_whitespace();
        let addr = tokens.next().unwrap_or_default();
        let (ip, port) = split_port(addr).map_err(at)?;
        let mut label = None;
        let mut flags = Vec::new();
        while let Some(tok) = tokens.next() {
            match tok {
                "--auto" | "--real-plc" | "--legacy" => flags.push(tok.to_string()),
                "--pin" => {
                    let v = tokens.next().ok_or_else(|| at("--pin needs a value".into()))?;
                    flags.extend(["--pin".to_string(), v.to_string()]);
                }
                t if t.starts_with('-') => {
                    return Err(at(format!(
                        "unknown option {t:?} (per-PLC options: --auto, --real-plc, --legacy, --pin <sha256>)"
                    )))
                }
                t if label.is_none() => label = Some(t.to_string()),
                t => return Err(at(format!("unexpected {t:?} after the label"))),
            }
        }
        if flags.is_empty() {
            flags.push("--auto".into());
        }
        let label = safe_label(label.as_deref(), targets.len() + 1);
        let label = unique_label(label, &targets);
        targets.push(Target {
            ip,
            port,
            label,
            flags,
        });
    }
    if targets.is_empty() {
        return Err("the targets file lists no PLC".into());
    }
    Ok(targets)
}

/// `192.168.0.1`, `192.168.0.1:102`, `[fe80::1]:102` or a bare IPv6 address.
fn split_port(addr: &str) -> Result<(String, Option<u16>), String> {
    let parse = |p: &str| {
        p.parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| format!("invalid port {p:?}"))
    };
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unclosed '[' in {addr:?}"))?;
        return match after.strip_prefix(':') {
            Some(p) => Ok((host.to_string(), Some(parse(p)?))),
            None if after.is_empty() => Ok((host.to_string(), None)),
            None => Err(format!("unexpected {after:?} after the address")),
        };
    }
    match addr.matches(':').count() {
        0 => Ok((addr.to_string(), None)),
        1 => {
            let (host, p) = addr.split_once(':').unwrap_or((addr, ""));
            Ok((host.to_string(), Some(parse(p)?)))
        }
        _ => Ok((addr.to_string(), None)), // IPv6 without a port
    }
}

fn safe_label(label: Option<&str>, position: usize) -> String {
    let cleaned: String = label
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    if cleaned.trim_matches('_').is_empty() {
        format!("plc{position:02}")
    } else {
        cleaned
    }
}

fn unique_label(label: String, taken: &[Target]) -> String {
    if !taken.iter().any(|t| t.label == label) {
        return label;
    }
    (2..)
        .map(|i| format!("{label}-{i}"))
        .find(|l| !taken.iter().any(|t| &t.label == l))
        .unwrap_or(label)
}

/// The steps from the command words: split on `+` when one is given (`report + read DB.x`),
/// otherwise each word is a step (`report probe`). No words: `report`, then `probe`.
pub fn split_steps(words: &[String]) -> Vec<Vec<String>> {
    if words.is_empty() {
        return vec![vec!["report".into()], vec!["probe".into()]];
    }
    if words.iter().any(|w| w == "+") {
        words
            .split(|w| w == "+")
            .filter(|s| !s.is_empty())
            .map(<[String]>::to_vec)
            .collect()
    } else {
        words.iter().map(|w| vec![w.clone()]).collect()
    }
}

/// How one step of one PLC went.
struct Outcome {
    label: String,
    step: String,
    status: String,
    secs: f32,
    log: String,
    /// From the step's log: the report's own tally, warnings and errors, the last error record.
    notes: Vec<String>,
}

/// Run every step against every target. Returns whether all of them succeeded.
pub fn run(batch: &Batch) -> Result<bool, String> {
    let text = fs::read_to_string(&batch.targets_file)
        .map_err(|e| format!("can't read {}: {e}", batch.targets_file.display()))?;
    let targets = parse_targets(&text)?;
    let exe = std::env::current_exe().map_err(|e| format!("can't find s7tool itself: {e}"))?;
    let out_dir = batch
        .out_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("s7tool-batch-{}", crate::logfile::file_stamp())));
    fs::create_dir_all(&out_dir).map_err(|e| format!("can't create {}: {e}", out_dir.display()))?;

    let steps: Vec<String> = batch.steps.iter().map(|s| s.join(" ")).collect();
    println!(
        "{} PLC(s) × {} step(s) [{}], logs in {}",
        targets.len(),
        steps.len(),
        steps.join(", "),
        out_dir.display()
    );
    let mut outcomes = Vec::new();
    for (i, target) in targets.iter().enumerate() {
        for (j, step) in batch.steps.iter().enumerate() {
            let log_name = format!(
                "{:02}-{}-{}.log",
                i + 1,
                target.label,
                safe_label(Some(&step[0]), j + 1)
            );
            let log_path = out_dir.join(&log_name);
            println!();
            println!(
                "=== [{}/{}] {} ({}{}) — {}",
                i + 1,
                targets.len(),
                target.label,
                target.ip,
                target.port.map(|p| format!(":{p}")).unwrap_or_default(),
                steps[j]
            );
            let mut cmd = Command::new(&exe);
            cmd.arg("--ip").arg(&target.ip);
            if let Some(port) = target.port {
                cmd.arg("--port").arg(port.to_string());
            }
            cmd.args(&target.flags).arg("--log").arg(&log_path);
            if batch.full_log {
                cmd.arg("--full-log");
            }
            if let Some(secs) = batch.timeout {
                cmd.arg("--timeout").arg(secs.to_string());
            }
            cmd.args(step).stdin(Stdio::null());
            let started = Instant::now();
            let mut status = String::new();
            // A step that got no connection at all is tried once more: a field network (or a
            // busy PLC) can miss one connect, which would otherwise cost the PLC every step.
            for attempt in 1..=2 {
                status = match cmd.spawn() {
                    Ok(mut child) => wait_with_timeout(&mut child, batch.step_timeout),
                    Err(e) => format!("not started: {e}"),
                };
                if status == "ok" || attempt == 2 || connected(&log_path) {
                    break;
                }
                println!("=== no connection; trying '{}' once more in 5 s", steps[j]);
                std::thread::sleep(Duration::from_secs(5));
            }
            let failed = status != "ok";
            outcomes.push(Outcome {
                label: target.label.clone(),
                step: steps[j].clone(),
                status,
                secs: started.elapsed().as_secs_f32(),
                log: log_name,
                notes: log_notes(&log_path),
            });
            // A PLC that never answered won't answer the next step either: don't wait for
            // another connect timeout per step.
            if failed && !connected(&log_path) {
                for later in &steps[j + 1..] {
                    println!("=== skipping '{later}' on {}: no connection", target.label);
                    outcomes.push(Outcome {
                        label: target.label.clone(),
                        step: later.clone(),
                        status: "skipped".into(),
                        secs: 0.0,
                        log: "-".into(),
                        notes: vec!["no connection in the step before".into()],
                    });
                }
                break;
            }
        }
    }

    let summary = summary_text(&outcomes, &steps, targets.len());
    let summary_path = out_dir.join("summary.txt");
    fs::write(&summary_path, &summary)
        .map_err(|e| format!("can't write {}: {e}", summary_path.display()))?;
    println!();
    print!("{summary}");
    println!("summary written to {}", summary_path.display());
    Ok(outcomes.iter().all(|o| o.status == "ok"))
}

/// Wait for a step, stopping it once `limit` has passed.
fn wait_with_timeout(child: &mut std::process::Child, limit: Duration) -> String {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return "ok".into(),
            Ok(Some(status)) => {
                return match status.code() {
                    Some(code) => format!("FAILED (exit {code})"),
                    None => "FAILED".into(),
                }
            }
            Ok(None) if started.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return format!("STOPPED after {} min", limit.as_secs() / 60);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => return format!("FAILED (wait: {e})"),
        }
    }
}

/// What a step's (redacted) log says about it: the report's own tally, how many warning and
/// error records it has, and the last error.
fn log_notes(path: &Path) -> Vec<String> {
    let Ok(file) = fs::File::open(path) else {
        return vec!["no session log".into()];
    };
    let (mut warnings, mut errors) = (0, 0);
    let (mut tally, mut last_error) = (None, None);
    for line in BufReader::new(file).lines().map_while(|l| l.ok()) {
        if line.contains(" WARN ") {
            warnings += 1;
        }
        if line.contains(" ERROR ") {
            errors += 1;
            last_error = line.split_once("] ").map(|(_, m)| m.trim().to_string());
        }
        if let Some(i) = line.find("report done:") {
            tally = Some(line[i..].trim().to_string());
        }
    }
    let mut notes = Vec::new();
    notes.extend(tally);
    notes.push(format!(
        "{warnings} warning(s), {errors} error(s) in the log"
    ));
    if let Some(e) = last_error {
        notes.push(format!("last error: {}", shorten(&e, 200)));
    }
    notes
}

/// Whether the step got as far as a session (its log has s7tool's "connected" line).
fn connected(log: &Path) -> bool {
    fs::read_to_string(log).is_ok_and(|text| text.contains("] connected — "))
}

fn shorten(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

fn summary_text(outcomes: &[Outcome], steps: &[String], plcs: usize) -> String {
    let ok = outcomes.iter().filter(|o| o.status == "ok").count();
    let mut s = format!(
        "s7tool {} batch: {plcs} PLC(s) × {} step(s) [{}] — {ok} of {} succeeded\n\n",
        env!("CARGO_PKG_VERSION"),
        steps.len(),
        steps.join(", "),
        outcomes.len()
    );
    for o in outcomes {
        s.push_str(&format!(
            "{:<20} {:<12} {:<22} {:>7.1}s  {}\n",
            o.label, o.step, o.status, o.secs, o.log
        ));
        for note in &o.notes {
            s.push_str(&format!("{:<20} {:<12} - {note}\n", "", ""));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn targets_file_lines() {
        let text = "\
# line press PLCs
192.168.0.10  press-1
192.168.0.11:1102 --real-plc mixer   # port, transport and label in any order
  10.0.0.5   # no label

[fe80::1]:102 v6 --pin 00112233
192.168.0.12 press-1
";
        let t = parse_targets(text).unwrap();
        assert_eq!(t.len(), 5);
        assert_eq!(t[0].ip, "192.168.0.10");
        assert_eq!((t[0].port, t[0].label.as_str()), (None, "press-1"));
        assert_eq!(t[0].flags, ["--auto"]);
        assert_eq!(t[1].port, Some(1102));
        assert_eq!(
            (t[1].label.as_str(), t[1].flags.as_slice()),
            ("mixer", &["--real-plc".to_string()][..])
        );
        assert_eq!(t[2].label, "plc03");
        assert_eq!((t[3].ip.as_str(), t[3].port), ("fe80::1", Some(102)));
        assert_eq!(t[3].flags, ["--pin", "00112233"]);
        assert_eq!(t[4].label, "press-1-2", "labels stay unique");
    }

    #[test]
    fn targets_file_errors() {
        assert!(parse_targets("# nothing\n\n").is_err());
        assert!(parse_targets("192.168.0.1:0").is_err());
        assert!(parse_targets("192.168.0.1:x").is_err());
        assert!(parse_targets("192.168.0.1 --verbose").is_err());
        assert!(parse_targets("192.168.0.1 a b").is_err());
        assert!(parse_targets("192.168.0.1 --pin").is_err());
        let e = parse_targets("1.2.3.4\n1.2.3.5 --bogus").unwrap_err();
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn labels_are_file_name_safe() {
        let t = parse_targets("1.2.3.4 Line/1:press").unwrap();
        assert_eq!(t[0].label, "Line_1_press");
        assert_eq!(parse_targets("1.2.3.4 ///").unwrap()[0].label, "plc01");
    }

    #[test]
    fn steps() {
        assert_eq!(split_steps(&[]), [words("report"), words("probe")]);
        assert_eq!(
            split_steps(&words("info report")),
            [words("info"), words("report")]
        );
        assert_eq!(
            split_steps(&words("report + read \"DB\".x \"DB\".y + probe")),
            [
                words("report"),
                words("read \"DB\".x \"DB\".y"),
                words("probe")
            ]
        );
    }

    #[test]
    fn notes_from_a_log() {
        let dir = std::env::temp_dir().join(format!("s7tool-batch-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("x.log");
        fs::write(
            &log,
            "[2000-01-01T00:00:00.000000Z INFO  s7tool::out] report done: 6 of 7 steps succeeded\n\
             [2000-01-01T00:00:00.000000Z WARN  s7commplus::connection] x\n\
             [2000-01-01T00:00:00.000000Z ERROR s7tool] report step 'a' failed: <name3> not found\n",
        )
        .unwrap();
        let notes = log_notes(&log);
        assert_eq!(notes[0], "report done: 6 of 7 steps succeeded");
        assert_eq!(notes[1], "1 warning(s), 1 error(s) in the log");
        assert!(notes[2].ends_with("<name3> not found"), "{notes:?}");
        assert_eq!(log_notes(&dir.join("missing.log")), ["no session log"]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_step_that_runs_too_long_is_stopped() {
        let mut child = if cfg!(windows) {
            Command::new("ping")
                .args(["-n", "30", "127.0.0.1"])
                .stdout(Stdio::null())
                .spawn()
        } else {
            Command::new("sleep").arg("30").spawn()
        }
        .unwrap();
        let started = Instant::now();
        let status = wait_with_timeout(&mut child, Duration::from_millis(500));
        assert!(status.starts_with("STOPPED"), "{status}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
