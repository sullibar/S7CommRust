// SPDX-License-Identifier: LGPL-3.0-or-later
//! Read tags from a legacy (pre-TLS) PLC via the high-level `Connection` API.
//!
//! `S7_PLC_IP=192.168.0.1 cargo run -p s7commplus --example legacy_read` (`S7_PLC_PORT` and
//! `S7_TAGS="a;b"` are optional).

use std::time::Duration;

use s7commplus::Connection;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let ip = std::env::var("S7_PLC_IP").unwrap_or_else(|_| {
        eprintln!("set S7_PLC_IP (e.g. S7_PLC_IP=192.168.0.1)");
        std::process::exit(2);
    });

    let port: u16 = std::env::var("S7_PLC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(102);
    let mut conn = match Connection::connect_legacy((ip.as_str(), port), Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("legacy connect failed: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "connected (legacy), session id = 0x{:08x}",
        conn.session_id()
    );

    // Discover data blocks (browse over the legacy transport).
    match conn.datablock_list() {
        Ok(dbs) => {
            println!("data blocks:");
            for db in &dbs {
                println!("  {} (relid 0x{:08x})", db.name, db.relid);
            }
        }
        Err(e) => println!("datablock_list error: {e}"),
    }

    // Read the requested tags (overridable via S7_TAGS="a;b;c" — semicolons, since an
    // M-dim index like `arr[0,3]` contains a comma).
    let tags =
        std::env::var("S7_TAGS").unwrap_or_else(|_| "Data_block_1.toto;Data_block_1.titi".into());
    for tag in tags.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        match conn.read_tag(tag) {
            Ok(v) => println!("{tag} = {v:?}"),
            Err(e) => println!("{tag} -> ERROR: {e}"),
        }
    }
}
