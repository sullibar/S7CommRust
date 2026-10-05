// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! What the driver's log records may contain about the PLC's project.

use std::sync::atomic::{AtomicBool, Ordering};

static REDACT: AtomicBool = AtomicBool::new(false);

/// Keep the PLC's project data out of the driver's log records, for a log that will leave the
/// site: telegram dumps stop after the PDU header (function, sequence number, session), and
/// symbol and data-block names are left out. Sizes, return values, timings and SystemEvents are
/// still logged. Off by default; it applies to every connection in the process.
pub fn set_log_redaction(on: bool) {
    REDACT.store(on, Ordering::Relaxed);
}

/// Whether [`set_log_redaction`] is on.
pub(crate) fn redacting() -> bool {
    REDACT.load(Ordering::Relaxed)
}

/// `name` for a log record, or a placeholder while redaction is on.
pub(crate) fn name(name: &str) -> &str {
    if redacting() {
        "<name>"
    } else {
        name
    }
}
