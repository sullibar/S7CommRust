// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! Live tests against a PLCSIM Advanced instance running one of the test projects described in
//! `tools/plcsim/README.md`. They are `#[ignore]`d, so `cargo test` skips them; run them with
//!
//! ```sh
//! S7_PLC_IP=169.254.130.10 cargo test --test live -- --ignored            # TLS project
//! S7_PLC_IP=169.254.130.10 S7_LEGACY=1 cargo test --test live -- --ignored # legacy project
//! ```
//!
//! Tests that need the other project (or the alarm) say so and pass without doing anything. They
//! run one at a time (a lock serializes them) and put back every value they change.
//! `S7_LIVE_SOAK` sets the number of connections the soak test makes (default 25).

use std::sync::Mutex;
use std::time::Duration;

use s7commplus::proto::{ItemAddress, SubscriptionItem};
use s7commplus::value::PValue;
use s7commplus::{Area, AssociatedValue, Connection, CpuState, Error};

/// Serializes the tests: PLCSIM handles a few connections at a time, and tests that change a
/// value must not overlap.
static PLC: Mutex<()> = Mutex::new(());

const TIMEOUT: Duration = Duration::from_secs(10);
/// An Int in both test projects.
const TOTO: &str = "Data_block_1.toto";

fn lock() -> std::sync::MutexGuard<'static, ()> {
    PLC.lock().unwrap_or_else(|e| e.into_inner())
}

fn address() -> String {
    let ip = std::env::var("S7_PLC_IP").expect("set S7_PLC_IP to the PLCSIM instance's address");
    let port = std::env::var("S7_PLC_PORT").unwrap_or_else(|_| "102".into());
    format!("{ip}:{port}")
}

fn legacy() -> bool {
    std::env::var("S7_LEGACY").is_ok()
}

fn connect() -> Connection {
    if legacy() {
        Connection::connect_legacy(address(), TIMEOUT).expect("legacy connect")
    } else {
        Connection::connect(address(), TIMEOUT).expect("TLS connect")
    }
}

/// Whether the test runs on this project; says why not when it doesn't.
fn needs_tls(test: &str) -> bool {
    if legacy() {
        eprintln!("{test}: skipped (needs the TLS project)");
    }
    !legacy()
}

/// The byte-offset area of the data block called `name`.
fn db(conn: &mut Connection, name: &str) -> Area {
    let dbs = conn.datablock_list().unwrap();
    let block = dbs.iter().find(|d| d.name == name).expect(name);
    Area::Db(u16::try_from(block.number).unwrap())
}

fn read_int(conn: &mut Connection, symbol: &str) -> i16 {
    match conn.read_tag(symbol).unwrap() {
        PValue::Int(v) => v,
        other => panic!("{symbol} is not an Int: {other:?}"),
    }
}

#[test]
#[ignore]
fn connects_and_reads_the_request_limits() {
    let _plc = lock();
    let conn = connect();
    assert_eq!(
        conn.max_tags_per_read(),
        100,
        "PLCSIM's TagsPerReadRequestMax"
    );
    assert_eq!(conn.max_tags_per_write(), 100);
    assert_eq!(conn.peer_certificate_sha256().is_some(), !legacy());
    conn.close().unwrap();
}

#[test]
#[ignore]
fn every_browsed_name_resolves_to_its_address() {
    let _plc = lock();
    let mut conn = connect();
    let vars = conn.browse_vars().unwrap();
    assert!(!vars.is_empty());
    for v in &vars {
        let addr = conn.resolve_symbol(&v.name).unwrap();
        assert_eq!(addr, v.address(), "{}", v.name);
    }
    eprintln!("{} names round-trip", vars.len());
}

#[test]
#[ignore]
fn a_read_beyond_the_item_limit_is_split() {
    let _plc = lock();
    let mut conn = connect();
    let names: Vec<&str> = [TOTO, "\"Data block.1\".plain"].repeat(125);
    let values = conn.read_tags(&names).unwrap();
    assert_eq!(values.len(), 250);
    assert!(values.iter().all(Result::is_ok));
}

#[test]
#[ignore]
fn a_written_value_reads_back() {
    let _plc = lock();
    let mut conn = connect();
    let old = read_int(&mut conn, TOTO);
    conn.write_tag(TOTO, PValue::Int(old.wrapping_add(1)))
        .unwrap();
    assert_eq!(read_int(&mut conn, TOTO), old.wrapping_add(1));
    conn.write_tag(TOTO, PValue::Int(old)).unwrap();
    assert_eq!(read_int(&mut conn, TOTO), old);
}

#[test]
#[ignore]
fn bit_memory_round_trips_by_byte_offset() {
    let _plc = lock();
    let mut conn = connect();
    // MB199..MB204: the four bytes written and one on either side, which must not change.
    let old = conn.read_area(Area::Memory, 199, 6).unwrap();
    conn.write_area(Area::Memory, 200, &[0xde, 0xad, 0xbe, 0xef])
        .unwrap();
    let mut expected = old.clone();
    expected[1..5].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(conn.read_area(Area::Memory, 199, 6).unwrap(), expected);
    conn.write_area(Area::Memory, 200, &old[1..5]).unwrap();
    assert_eq!(conn.read_area(Area::Memory, 199, 6).unwrap(), old);
}

#[test]
#[ignore]
fn an_optimized_block_refuses_byte_offset_access() {
    let _plc = lock();
    let mut conn = connect();
    let data_block_1 = db(&mut conn, "Data_block_1");
    let e = conn.read_area(data_block_1, 0, 2).unwrap_err();
    assert!(e.to_string().contains("optimized"), "{e}");
    assert!(!conn.is_poisoned());
}

#[test]
#[ignore]
fn a_standard_block_reads_as_declared() {
    if !needs_tls("a_standard_block_reads_as_declared") {
        return;
    }
    let _plc = lock();
    let mut conn = connect();
    // "Std DB" (tools/plcsim/s7commrusttest/stddb.scl): a = 1, b = 2.5, c = TRUE, s = 'std'
    // (String[10]), st.x = 77, arr = 4 × Int 0.
    let std_db = db(&mut conn, "Std DB");
    let bytes = conn.read_area(std_db, 0, 32).unwrap();
    let mut expected = vec![0x00, 0x01, 0x40, 0x20, 0x00, 0x00, 0x01, 0x00];
    expected.extend_from_slice(&[10, 3, b's', b't', b'd', 0, 0, 0, 0, 0, 0, 0]);
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x4d]);
    expected.extend_from_slice(&[0; 8]);
    assert_eq!(bytes, expected);
    // A byte-offset write shows up symbolically, and back.
    conn.write_area(std_db, 20, &123_456i32.to_be_bytes())
        .unwrap();
    assert_eq!(
        conn.read_tag("\"Std DB\".st.x").unwrap(),
        PValue::DInt(123_456)
    );
    conn.write_tag("\"Std DB\".st.x", PValue::DInt(77)).unwrap();
    assert_eq!(conn.read_area(std_db, 20, 4).unwrap(), [0, 0, 0, 0x4d]);
}

#[test]
#[ignore]
fn the_cpu_is_running() {
    let _plc = lock();
    assert_eq!(connect().cpu_state().unwrap(), CpuState::Run);
}

/// A subscription to `toto` and `"Data block.1".plain`, with `credit`.
fn subscribe(conn: &mut Connection, credit: i16) -> s7commplus::Subscription {
    let items: Vec<SubscriptionItem> = [TOTO, "\"Data block.1\".plain"]
        .iter()
        .enumerate()
        .map(|(i, name)| SubscriptionItem {
            reference_id: i as u32 + 1,
            address: conn.resolve_symbol(name).unwrap(),
        })
        .collect();
    conn.subscribe_with(&items, 100, 0x14, credit).unwrap()
}

#[test]
#[ignore]
fn a_finite_credit_subscription_keeps_flowing() {
    let _plc = lock();
    let mut conn = connect();
    let sub = subscribe(&mut conn, 5);
    for _ in 0..12 {
        conn.next_notification(&sub).unwrap();
    }
    conn.delete_subscription(&sub).unwrap();
}

#[test]
#[ignore]
fn a_write_on_a_subscribed_connection_is_notified() {
    // gijzelaerr/s7commplus reports the PLC resetting a connection that carries a subscription
    // when it writes with SetVarSubStreamed. This crate writes with SetMultiVariables.
    let _plc = lock();
    let mut conn = connect();
    let old = read_int(&mut conn, TOTO);
    let sub = subscribe(&mut conn, -1);
    conn.next_notification(&sub).unwrap();
    let new = old.wrapping_add(10);
    conn.write_tag(TOTO, PValue::Int(new)).unwrap();
    let seen = (0..20).any(|_| {
        let n = conn.next_notification(&sub).unwrap();
        n.values
            .iter()
            .any(|(r, v)| *r == 1 && *v == PValue::Int(new))
    });
    conn.write_tag(TOTO, PValue::Int(old)).unwrap();
    assert!(seen, "the written value was never notified");
    assert!(!conn.is_poisoned());
    conn.delete_subscription(&sub).unwrap();
}

#[test]
#[ignore]
fn a_large_recursive_explore_decodes() {
    let _plc = lock();
    let mut conn = connect();
    // Hundreds of chunks on the legacy path, each digest-checked.
    let resp = conn.explore(0xc9, 1, 0, &[]).unwrap();
    assert!(!resp.objects.is_empty());
}

#[test]
#[ignore]
fn reconnect_starts_a_new_session() {
    let _plc = lock();
    let mut conn = connect();
    let before = conn.generation();
    conn.reconnect().unwrap();
    // Not the session id: reconnect closes the old socket first, and the PLC
    // may then hand out the freed id again (PLCSIM does).
    assert_ne!(conn.generation(), before);
    read_int(&mut conn, TOTO);
}

#[test]
#[ignore]
fn a_pinned_certificate_is_enforced() {
    if !needs_tls("a_pinned_certificate_is_enforced") {
        return;
    }
    let _plc = lock();
    let pin = connect().peer_certificate_sha256().unwrap();
    let mut conn = Connection::connect_pinned(address(), TIMEOUT, pin).unwrap();
    read_int(&mut conn, TOTO);
    let mut wrong = pin;
    wrong[31] ^= 1;
    let e = Connection::connect_pinned(address(), TIMEOUT, wrong)
        .err()
        .expect("a wrong pin must fail");
    assert!(matches!(e, Error::Tls(_)), "{e}");
}

#[test]
#[ignore]
fn an_alarm_comes_and_goes() {
    if !needs_tls("an_alarm_comes_and_goes") {
        return;
    }
    let _plc = lock();
    let mut ctl = connect();
    if ctl.resolve_symbol("\"AlarmDB\".trig").is_err() {
        eprintln!("an_alarm_comes_and_goes: skipped (no AlarmDB; see tools/plcsim/alarms.scl)");
        return;
    }
    ctl.write_tag("\"AlarmDB\".trig", PValue::Bool(false))
        .unwrap();
    ctl.write_tag("\"AlarmDB\".val", PValue::Int(-5)).unwrap();
    let mut sub_conn = connect();
    let sub = sub_conn.subscribe_alarms().unwrap();
    let next_alarm = |conn: &mut Connection| loop {
        match conn.next_notification(&sub) {
            Ok(n) if !n.alarms().is_empty() => break n.alarms().remove(0),
            Ok(_) => continue,
            Err(e) if e.is_timeout() => continue,
            Err(e) => panic!("{e}"),
        }
    };

    ctl.write_tag("\"AlarmDB\".trig", PValue::Bool(true))
        .unwrap();
    let came = next_alarm(&mut sub_conn);
    assert_eq!(came.state, s7commplus::AlarmState::Coming);
    assert_eq!(came.associated_values[0], AssociatedValue::Int(-5));
    assert!(came.associated_values[1..]
        .iter()
        .all(|v| *v == AssociatedValue::Unused));
    let pending = ctl.active_alarms().unwrap();
    assert!(pending.iter().any(|a| a.cpu_alarm_id == came.cpu_alarm_id));

    ctl.write_tag("\"AlarmDB\".trig", PValue::Bool(false))
        .unwrap();
    let went = next_alarm(&mut sub_conn);
    assert_eq!(went.state, s7commplus::AlarmState::Going);
    assert_eq!(went.cpu_alarm_id, came.cpu_alarm_id);
    // An alarm going keeps the sequence counter it came with; the next coming increments it.
    assert_eq!(went.sequence_counter, came.sequence_counter);
    assert!(ctl.active_alarms().unwrap().is_empty());
}

#[test]
#[ignore]
fn many_connections_in_a_row() {
    let _plc = lock();
    let n: usize = std::env::var("S7_LIVE_SOAK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    for i in 0..n {
        let mut conn = connect();
        let value = conn
            .read_variables(&[ItemAddress::raw(Area::Memory, 0, 1)])
            .unwrap_or_else(|e| panic!("connection {i}: {e}"));
        assert_eq!(value.values.len(), 1, "connection {i}");
        conn.close().unwrap();
    }
}
