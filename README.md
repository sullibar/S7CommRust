# s7commplus

[![CI](https://github.com/sullibar/S7CommRust/actions/workflows/ci.yml/badge.svg)](https://github.com/sullibar/S7CommRust/actions/workflows/ci.yml)
[![License: LGPL v3+](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)

A Rust port of [`thomas-v2/S7CommPlusDriver`](https://github.com/thomas-v2/S7CommPlusDriver):
a driver for the proprietary Siemens **S7CommPlus** protocol used to read and write the
symbolic ("optimized") variable space of S7-1200 / S7-1500 PLCs.

It speaks the modern **TLS-wrapped** dialect and — through a separate code path — the older,
non-TLS "integrity-protected" scheme, so one API reaches both current and legacy firmware.

> **Status: end-to-end reads, writes, browsing, subscriptions, alarms, and authentication —
> live-validated on real and simulated hardware.**
>
> - **TLS path** (`connect`): COTP → `InitSsl` → TLS 1.3 handshake → session → browse
>   (Explore) → read/write symbolic tags by name → subscriptions → alarms → legitimation.
>   Validated end-to-end against a **PLCSIM Advanced V2.9** instance; legitimation is proven
>   both ways (correct password accepted, wrong password denied).
> - **Legacy path**: the non-TLS scheme for older firmware. `connect_legacy` (the PLCSIM key
>   family) is validated end-to-end against a **PLCSIM Advanced FW V2.8** instance.
>   `connect_real_plc` (physical S7-1200/1500 on older firmware) is validated offline against
>   golden vectors but has **not yet been tested on hardware**.
>
> Known gaps: alarm *reception* is unit-tested but not yet confirmed against a program with
> firing alarms; a few upstream-unimplemented value types (`Variant`, `S7String`) remain
> explicit errors because there is no wire format to port.

## Use as a library

`s7commplus` is a normal Rust library crate — add it as a dependency and drive a PLC through
the [`Connection`] API:

```toml
[dependencies]
s7commplus = "0.1.0"
```

```rust
use std::time::Duration;
use s7commplus::{Connection, value::PValue};

fn main() -> s7commplus::Result<()> {
    // Connect: TLS 1.3 handshake and session setup all happen here.
    let mut plc = Connection::connect("192.168.0.1:102", Duration::from_secs(10))?;

    // Read and write tags by symbol name — the driver resolves the address for you.
    let titi = plc.read_tag("Data_block_1.titi")?;   // e.g. PValue::Int(123)
    println!("titi = {titi:?}");
    plc.write_tag("Data_block_1.titi", PValue::Int(456))?;

    // Strings and M/Q/I-area tags (addressed by bare name) work too.
    println!("name = {:?}", plc.read_string("Data_block_1.name")?);
    Ok(())
}
```

### What you can do

- **Connect** — `connect` (TLS), or `connect_legacy` / `connect_real_plc` (older firmware).
  The PLC's per-request item limit is read at connect, and larger reads and writes are split
  to fit (`max_tags_per_read` / `max_tags_per_write`). `close` ends the session cleanly.
- **Browse** — `datablock_list`, `explore`, `type_info`, `resolve_symbol`, and `resolve_var`
  (which adds the tag's softdatatype, to interpret its value).
- **Read / write by name** — `read_tag` / `write_tag`, batched `read_tags` / `write_tags`,
  and the string helpers `read_string` / `write_string` and `read_wstring` / `write_wstring`.
- **Read / write by byte offset** — `read_area` / `write_area` on a standard (not optimized)
  data block or the I/Q/M areas, as the classic S7 protocol does: `Area::Db(5)`,
  `Area::Inputs`, `Area::Outputs`, `Area::Memory`. Batch several ranges by passing
  `ItemAddress::raw` addresses to `read_variables`.
- **CPU state** — `cpu_state` reports RUN, STOP, or another operating-state code.
- **Subscribe** — `subscribe` / `subscribe_with` for cyclic value pushes, then
  `next_notification` (per subscription) or `next_any_notification` (one loop for all); a
  finite credit limit is auto-refreshed for you. `delete_subscription` frees it on the PLC.
- **Alarms** — `active_alarms` lists the alarms pending now; `subscribe_alarms` pushes alarm
  events, read with `Notification::alarms()`. `Alarm::message()` formats localized alarm text
  with substituted associated values.
- **Authenticate** — `legitimate(user, password)` against a password-protected program.
- **Recover** — after a failed request the connection is *poisoned* (`is_poisoned`; the error
  reports `is_connection_lost`): call `reconnect`, or enable `set_auto_reconnect` to retry reads
  transparently. A notification poll that times out (`Error::is_timeout`) can simply be retried.

Values flow through the `value::PValue` enum, which models the ~90 PLC datatypes.

## `s7tool` — a minimal browse/read/write CLI

The repo is a Cargo workspace, and [`s7tool`](s7tool/) is a small binary crate that depends
on `s7commplus` **by path** — so it doubles as a worked example of consuming the driver and
as a quick way to poke at a live PLC. Copy its `src/main.rs` and dependency line as the
starting point for your own app.

```sh
# Interactive prompt — type: browse, read <tag>, write <tag> <val>, level, help, quit
cargo run -p s7tool -- --ip 192.168.0.1

# ...or one-shot commands:
cargo run -p s7tool -- --ip 192.168.0.1 browse
cargo run -p s7tool -- --ip 192.168.0.1 read Data_block_1.toto Data_block_1.titi
cargo run -p s7tool -- --ip 192.168.0.1 write Data_block_1.titi 456
cargo run -p s7tool -- --ip 192.168.0.1 rawread DB5 0 16    # bytes 0..16 of standard DB5
cargo run -p s7tool -- --ip 192.168.0.1 state               # RUN / STOP
cargo run -p s7tool -- --ip 192.168.0.1 pending             # alarms pending now

# Older, non-TLS firmware: --legacy for PLCSIM, --real-plc for a physical S7-1200/1500.
cargo run -p s7tool -- --ip 192.168.0.1 --legacy browse
cargo run -p s7tool -- --ip 192.168.0.1 --real-plc browse
```

`write` infers the tag's type by reading its current value first, so `write DB.x 1` does the
right thing whether `x` is a Bool, Int, Real, or String. The PLC address can also come from
the `S7_PLC_IP` / `S7_PLC_PORT` environment variables.

## Firmware requirements

The **TLS** path (`connect`) targets the modern S7CommPlus dialect:

- S7-1500 firmware ≥ V2.9, S7-1200 firmware ≥ V4.3, engineered with TIA Portal ≥ V17.

Older firmware speaks a different, non-TLS "integrity-protected" scheme. That path
(`connect_legacy`) is **not** part of upstream `S7CommPlusDriver`; its cryptography is ported
from [HarpoS7](https://github.com/bonk-dev/HarpoS7) (MIT — see `LICENSE-HarpoS7`).

## Build & test

```sh
cargo build
cargo test       # codec + protocol unit tests run without hardware
cargo clippy --all-targets
```

The `examples/` directory contains runnable probes (`read`, `write`, `browse`, `mq`,
`legitimate`, `legacy_read`, …) that expect a reachable PLC; point them at one with
`S7_PLC_IP=<addr>`. Set `SSLKEYLOGFILE=<path>` to dump TLS secrets for Wireshark analysis — the
driver honours it whenever it is set, so don't leave it set in production.

For a bulk dump of every tag and its live value to a spreadsheet, use the `export_csv`
example:

```sh
S7_PLC_IP=192.168.0.1 cargo run --example export_csv -- tags.csv
# older firmware: add --legacy (PLCSIM family) or --real-plc (S7-1200/1500 hardware)
```

## License

LGPL-3.0-or-later. This is a derivative work of `thomas-v2/S7CommPlusDriver`
(LGPL-3.0-or-later); see [`LICENSE`](LICENSE). The legacy (non-TLS) support in `src/legacy/`
is derived from HarpoS7 and used under the MIT License; see [`LICENSE-HarpoS7`](LICENSE-HarpoS7). The
real-PLC seed and key derivation (`src/legacy/family0/`), the challenge fingerprint
(`src/legacy/fingerprint.rs`) and the chained response digests (`src/legacy/digest.rs`) follow
[gijzelaerr/s7commplus](https://github.com/gijzelaerr/s7commplus) (MIT); see
[`LICENSE-gijzelaerr-s7commplus`](LICENSE-gijzelaerr-s7commplus).
