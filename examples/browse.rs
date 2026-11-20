// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// Browse + read every member of every data block, by symbol name, using only the Rust
// driver (no PLCSIM API). Walks the type info, then reads each scalar/string/array element.
//
//   S7_PLC_IP=192.168.0.1 cargo run --example browse

use std::time::Duration;

use s7commplus::value::PValue;
use s7commplus::Connection;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    if let Err(e) = run() {
        eprintln!("browse failed: {e}");
        std::process::exit(1);
    }
}

fn run() -> s7commplus::Result<()> {
    let ip = std::env::var("S7_PLC_IP").unwrap_or_else(|_| {
        eprintln!("set S7_PLC_IP (e.g. S7_PLC_IP=192.168.0.1)");
        std::process::exit(2);
    });
    let port: u16 = std::env::var("S7_PLC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(s7commplus::transport::tcp::ISO_TCP_PORT);

    println!("connecting to {ip}:{port} ...");
    let mut conn = Connection::connect((ip.as_str(), port), Duration::from_secs(10))?;
    println!("  session_id = 0x{:08x}\n", conn.session_id());

    let dbs = conn.datablock_list()?;
    for db in &dbs {
        println!(
            "DB \"{}\" (DB{}, relid 0x{:08x}):",
            db.name, db.number, db.relid
        );
        match walk(&mut conn, &db.name, db.ti_relid, 1) {
            Ok(()) => {}
            // A lost connection fails every block after it: stop.
            Err(e) if e.is_connection_lost() || conn.is_poisoned() => return Err(e),
            // The PLC withholds the interface of some blocks (know-how protected, or safety
            // blocks on an F-CPU): skip them and go on with the next.
            Err(e) => println!("  (skipped: {e})"),
        }
        println!();
    }

    // Controller areas (M/Q/I): tags here are addressed by their bare name (no prefix).
    for (ti, label) in [
        (0x9003_0000u32, "M area"),
        (0x9002_0000, "Q area"),
        (0x9001_0000, "I area"),
    ] {
        match conn.type_info(ti) {
            Ok(info) => {
                let count = info
                    .varname_list
                    .as_ref()
                    .map(|n| n.names.len())
                    .unwrap_or(0);
                println!("{label} ({count} tags):");
                walk(&mut conn, "", ti, 1)?;
            }
            Err(e) => println!("{label}: (none) [{e}]"),
        }
        println!();
    }
    Ok(())
}

fn walk(
    conn: &mut Connection,
    prefix: &str,
    ti_relid: u32,
    depth: usize,
) -> s7commplus::Result<()> {
    let ti = conn.type_info(ti_relid)?;
    let names = match &ti.varname_list {
        Some(n) => &n.names,
        None => return Ok(()),
    };
    let elems = match &ti.vartype_list {
        Some(v) => &v.elements,
        None => return Ok(()),
    };
    let indent = "  ".repeat(depth);
    for (i, name) in names.iter().enumerate() {
        let Some(elem) = elems.get(i) else { break };
        let oi = &elem.offset_info;
        let full = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        let tname = sdt_name(elem.softdatatype);

        // Nested struct (not an array): recurse.
        if oi.has_relation() && elem.softdatatype == 17 && !oi.is_1dim && !oi.is_mdim {
            println!("{indent}{name} : Struct");
            if depth < 5 {
                if let Some(rel) = oi.relation_id {
                    walk(conn, &full, rel, depth + 1)?;
                }
            }
            continue;
        }

        // 1-D array of scalars: read each element.
        if oi.is_1dim && !oi.has_relation() {
            let lb = oi.array_lower_bounds;
            let count = oi.array_element_count.min(16) as i32;
            println!(
                "{indent}{name} : Array[{}..{}] of {tname}",
                lb,
                lb + oi.array_element_count as i32 - 1
            );
            for idx in lb..lb + count {
                let sym = format!("{full}[{idx}]");
                match conn.read_tag(&sym) {
                    Ok(v) => println!("{indent}  {sym} = {}", fmt(&v)),
                    Err(e) => println!("{indent}  {sym} -> ERR: {e}"),
                }
            }
            continue;
        }

        // String: decode to text.
        if elem.softdatatype == 19 {
            match conn.read_string(&full) {
                Ok(s) => println!("{indent}{name} : String = {s:?}"),
                Err(e) => println!("{indent}{name} : String -> ERR: {e}"),
            }
            continue;
        }

        // Plain scalar.
        match conn.read_tag(&full) {
            Ok(v) => println!("{indent}{name} : {tname} = {}", fmt(&v)),
            Err(e) => println!("{indent}{name} : {tname} -> ERR: {e}"),
        }
    }
    Ok(())
}

fn fmt(v: &PValue) -> String {
    match v {
        PValue::USIntArray(b) => format!("USIntArray[{}]", b.len()),
        other => format!("{other:?}"),
    }
}

fn sdt_name(sdt: u8) -> &'static str {
    match sdt {
        1 => "Bool",
        2 => "Byte",
        3 => "Char",
        4 => "Word",
        5 => "Int",
        6 => "DWord",
        7 => "DInt",
        8 => "Real",
        9 => "Date",
        11 => "Time",
        17 => "Struct",
        19 => "String",
        48 => "LReal",
        49 => "ULInt",
        50 => "LInt",
        51 => "LWord",
        52 => "USInt",
        53 => "UInt",
        54 => "UDInt",
        55 => "SInt",
        62 => "WString",
        67 => "DTL",
        other => Box::leak(format!("sdt{other}").into_boxed_str()),
    }
}
