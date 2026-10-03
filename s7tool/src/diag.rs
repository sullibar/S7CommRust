// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! `info` and `report`: what the PLC is, and a read-only run through what the driver can do
//! with it, for the session log.

use s7commplus::proto::PObject;
use s7commplus::value::PValue;
use s7commplus::{Connection, CpuState, Result};

/// RID of the device tree (the hardware configuration's modules).
const DEVICE_TREE: u32 = 0x22;
/// A module's name, as ASCII bytes.
const MODULE_NAME: u32 = 2256;
/// A module's identification record: its order number, then its firmware version.
const MODULE_IDENTIFICATION: u32 = 4114;

/// Print what the PLC is and the session's parameters.
pub fn info(conn: &mut Connection) -> Result<()> {
    out!(
        "PLC description:  {}",
        conn.plc_description().unwrap_or("(none sent)")
    );
    match cpu_module(conn) {
        Ok(Some(m)) => out!(
            "CPU module:       {} — {} — firmware {}",
            m.name.as_deref().unwrap_or("?"),
            m.order_number.as_deref().unwrap_or("?"),
            m.firmware.as_deref().unwrap_or("?")
        ),
        Ok(None) => out!("CPU module:       no identification record in the device tree"),
        Err(e) => out!("CPU module:       device tree not readable: {e}"),
    }
    match conn.peer_certificate_sha256() {
        Some(fp) => out!(
            "transport:        TLS, certificate SHA-256 {}",
            crate::hex(&fp).replace(' ', "")
        ),
        None => out!("transport:        legacy (non-TLS)"),
    }
    out!(
        "session:          0x{:08x} (0x{:08x})",
        conn.session_id(),
        conn.session_id2()
    );
    out!(
        "request limits:   {} items per read, {} per write",
        conn.max_tags_per_read(),
        conn.max_tags_per_write()
    );
    match conn.effective_protection_level() {
        Ok(level) => out!("protection level: {level}"),
        Err(e) => out!("protection level: not readable: {e}"),
    }
    match conn.cpu_state() {
        Ok(CpuState::Run) => out!("CPU state:        RUN"),
        Ok(CpuState::Stop) => out!("CPU state:        STOP"),
        Ok(CpuState::Other(code)) => out!("CPU state:        code {code}"),
        Err(e) => out!("CPU state:        not readable: {e}"),
    }
    Ok(())
}

/// The CPU's name, order number and firmware version, from its module in the device tree.
#[derive(Debug, Default, PartialEq)]
struct CpuModule {
    name: Option<String>,
    order_number: Option<String>,
    firmware: Option<String>,
}

fn cpu_module(conn: &mut Connection) -> Result<Option<CpuModule>> {
    let resp = conn.explore(DEVICE_TREE, 1, 0, &[])?;
    let mut pending: Vec<&PObject> = resp.objects.iter().collect();
    while let Some(obj) = pending.pop() {
        if let Some(PValue::Blob { data, .. }) = obj.attribute(MODULE_IDENTIFICATION) {
            let (order_number, firmware) = identification(data);
            if order_number.is_some() {
                let name = match obj.attribute(MODULE_NAME) {
                    Some(PValue::Blob { data, .. }) => {
                        Some(String::from_utf8_lossy(data).trim().to_string())
                    }
                    _ => None,
                };
                return Ok(Some(CpuModule {
                    name,
                    order_number,
                    firmware,
                }));
            }
        }
        pending.extend(&obj.objects);
    }
    Ok(None)
}

/// The order number and firmware version in a module's identification record. On PLCSIM
/// Advanced it reads `… "6ES7 511-1AK02-0AB0" + spaces, 00 00, 'V' 02 08 00 …`, which is
/// firmware V2.8.0. Real CPUs may lay it out differently; the session log has the raw bytes.
fn identification(data: &[u8]) -> (Option<String>, Option<String>) {
    let Some(start) = data.windows(4).position(|w| w == b"6ES7") else {
        return (None, None);
    };
    let len = data[start..]
        .iter()
        .position(|b| !(0x20..0x7f).contains(b))
        .unwrap_or(data.len() - start);
    let order_number = String::from_utf8_lossy(&data[start..start + len])
        .trim_end()
        .to_string();
    let rest = &data[start + len..];
    let firmware = rest
        .iter()
        .position(|&b| b == b'V')
        .and_then(|v| rest.get(v + 1..v + 4))
        .map(|n| format!("V{}.{}.{}", n[0], n[1], n[2]));
    (Some(order_number), firmware)
}

/// One step of [`report`]: its title and what it runs.
type Step = (&'static str, fn(&mut Connection) -> Result<()>);

/// Run everything read-only s7tool can do against the PLC, one step after another, so that a
/// single run leaves a complete session log. A failing step is reported and the rest still run,
/// on a new connection if the failure lost this one. Nothing is written to the PLC.
pub fn report(conn: &mut Connection) -> Result<()> {
    let steps: [Step; 7] = [
        ("PLC and session", info),
        ("data blocks", crate::list_dbs),
        ("every tag with its value", |c| crate::browse(c, None)),
        ("browsed names against resolve_symbol", crate::xverify),
        ("a subscription to five tags", |c| {
            crate::subscribe_demo(c, 5, 500, 5, None)
        }),
        ("pending alarms", crate::pending),
        ("device tree", |c| {
            let resp = c.explore(DEVICE_TREE, 1, 0, &[])?;
            out!(
                "{} object(s); the session log has them in full",
                resp.objects.len()
            );
            Ok(())
        }),
    ];
    let mut failed = 0;
    for (title, step) in steps {
        out!("");
        out!("== {title}");
        if let Err(e) = step(conn) {
            failed += 1;
            out!("FAILED: {e}");
            log::error!(target: "s7tool", "report step '{title}' failed: {e}");
            if conn.is_poisoned() {
                out!("(connection lost; reconnecting for the remaining steps)");
                conn.reconnect()?;
            }
        }
    }
    out!("");
    out!(
        "report done: {} of {} steps succeeded",
        steps.len() - failed,
        steps.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identification_record_from_plcsim() {
        // Attribute 4114 of PLCSIM Advanced's CPU 1511-1 PN (FW V2.8) module.
        let mut data = vec![0x00, 0x20, 0x00, 0x38, 0x01, 0x00, 0x00, 0x2a];
        data.extend_from_slice(b"6ES7 511-1AK02-0AB0");
        data.extend_from_slice(&[b' '; 17]);
        data.extend_from_slice(&[0, 0, b'V', 2, 8, 0, 0, 0, 0, 0]);
        assert_eq!(
            identification(&data),
            (Some("6ES7 511-1AK02-0AB0".into()), Some("V2.8.0".into()))
        );
        assert_eq!(identification(b"no order number"), (None, None));
        // An order number without a version after it.
        assert_eq!(
            identification(b"..6ES7 214-1AG40-0XB0"),
            (Some("6ES7 214-1AG40-0XB0".into()), None)
        );
    }
}
