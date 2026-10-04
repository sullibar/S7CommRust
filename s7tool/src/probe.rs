// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! `probe`: how the PLC answers requests at the edge of what it accepts, for the session log.
//!
//! The driver's mock PLC copies S7-1200 firmware only where a field log measured it, and these
//! answers are still unknown for S7-1200/1500 CPUs: a read one item over the advertised
//! limit, and byte-offset reads past the end of the M area or of an optimized data block. Each
//! answer is printed as the PLC gave it (a return value, an item error, or a closed connection);
//! the bytes read are not printed. Nothing is written. A request that costs the connection is
//! followed by a reconnect, so the remaining steps still run.

use s7commplus::proto::ItemAddress;
use s7commplus::wire::pdu::ids;
use s7commplus::{Area, Connection, Result};

/// M-area byte offsets to read one byte at: around each power of two a CPU's M area might end at.
const M_OFFSETS: [u32; 12] = [
    0, 1023, 1024, 2047, 2048, 4095, 4096, 8191, 8192, 16383, 16384, 65535,
];
/// Most data blocks to try a byte read on.
const MAX_DBS: usize = 20;

/// Run the probe steps.
pub fn probe(conn: &mut Connection) -> Result<()> {
    out!("== a read over the item limit");
    over_limit(conn)?;
    out!("");
    out!("== one-byte reads of the M area by byte offset");
    for offset in M_OFFSETS {
        let label = format!("M byte {offset}");
        let result = conn.read_area(Area::Memory, offset, 1).map(|_| ());
        report(conn, &label, result)?;
    }
    out!("");
    out!("== one-byte reads of each data block by byte offset (fails on an optimized block)");
    let dbs = conn.datablock_list()?;
    for db in dbs.iter().take(MAX_DBS) {
        let label = format!("DB{} {}", db.number, crate::privacy::name(&db.name));
        let result = match u16::try_from(db.number) {
            Ok(n) => conn.read_area(Area::Db(n), 0, 1).map(|_| ()),
            Err(_) => continue,
        };
        report(conn, &label, result)?;
    }
    if dbs.len() > MAX_DBS {
        out!("({} more data blocks not tried)", dbs.len() - MAX_DBS);
    }
    Ok(())
}

/// Read the item limit itself, as many times as the PLC allows and then once more, in one
/// request each.
fn over_limit(conn: &mut Connection) -> Result<()> {
    let limit = conn.max_tags_per_read();
    out!("the PLC advertises {limit} items per read");
    // The address the driver reads at connect, so it is valid on any PLC.
    let item = ItemAddress {
        symbol_crc: 0,
        access_area: ids::OBJECT_ROOT,
        access_sub_area: ids::SYSTEM_LIMITS,
        lid: vec![ids::TAGS_PER_READ_REQUEST_MAX],
    };
    for n in [limit, limit + 1] {
        let label = format!("{n} items in one request");
        let result = conn
            .read_variables_unsplit(&vec![item.clone(); n])
            .map(|resp| {
                out!(
                    "{label}: answered, {} value(s), {} item error(s), return value 0x{:016x}",
                    resp.values.len(),
                    resp.errors.len(),
                    resp.header.return_value
                );
            });
        if result.is_err() {
            report(conn, &label, result)?;
        }
    }
    Ok(())
}

/// Print how a step went; after a lost connection, say so and reconnect.
fn report(conn: &mut Connection, label: &str, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => out!("{label}: ok"),
        Err(e) => {
            out!("{label}: refused: {e}");
            if conn.is_poisoned() {
                out!("{label}: the connection was lost; reconnecting");
                conn.reconnect()?;
            }
        }
    }
    Ok(())
}
