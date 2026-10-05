# s7commplus

[![CI](https://github.com/sullibar/S7CommRust/actions/workflows/ci.yml/badge.svg)](https://github.com/sullibar/S7CommRust/actions/workflows/ci.yml)
[![License: LGPL v3+](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)

A Rust driver for the Siemens **S7CommPlus** protocol: read and write tags by name on
S7-1200 / S7-1500 PLCs, including optimized data blocks. It's a port of
[`thomas-v2/S7CommPlusDriver`](https://github.com/thomas-v2/S7CommPlusDriver).

It supports both protocol versions:

- **TLS**: newer firmware (S7-1200 V4.5+, S7-1500 V2.9+, TIA Portal V17+)
- **Legacy (non-TLS)**: older firmware, and newer firmware whose project doesn't use TLS

## Tested on

| CPU                | Order number   | Firmware | Connection          | Result |
|--------------------|----------------|----------|---------------------|--------|
| S7-1215C           | 6ES7 215-1AG40 | V4.2     | legacy `--real-plc` | ✅ |
| S7-1215C           | 6ES7 215-1AG40 | V4.3     | legacy `--real-plc` | ✅ |
| S7-1215C           | 6ES7 215-1AG40 | V4.4     | legacy `--real-plc` | ✅ |
| S7-1212C           | 6ES7 212-1HE40 | V4.5     | legacy `--real-plc` | ✅ |
| S7-1214C           | 6ES7 214-1BG40 | V4.6     | legacy `--real-plc` | ✅ |
| S7-1212C           | 6ES7 212-1AE40 | V4.7     | legacy `--real-plc` | ✅ |
| S7-1215C           | 6ES7 215-1AG40 | V4.5     | TLS                 | ✅ |
| S7-1214            | 6ES7 214-1AE30 | V2.2     | —                   | ❌ firmware too old |
| PLCSIM Advanced    | —              | V2.9     | TLS                 | ✅ |
| PLCSIM Advanced    | —              | V2.8     | legacy `--legacy`   | ✅ |

**No physical S7-1500 has been tested yet.** If you have one, a test log would help a lot
(see [Testing on your PLC](#testing-on-your-plc)).

## Features

- **Connect** over TLS (`connect`, `connect_pinned`) or the legacy protocol (`connect_real_plc`
  for hardware, `connect_legacy` for PLCSIM)
- **Browse** data blocks and tags
- **Read / write** by tag name, one at a time or in batches; strings included
- **Read / write by byte offset** on standard DBs and the I/Q/M areas
- **CPU state** (RUN / STOP)
- **Subscriptions** (values pushed by the PLC)
- **Alarms**: pending alarms and alarm events
- **Password login** (`legitimate`), in the legacy or new scheme the firmware takes; TLS
  connections only
- **Reconnect** after a lost connection, by hand or automatically

Not supported: the `Variant` and `S7String` types.

## Use as a library

```toml
[dependencies]
s7commplus = "0.1.0"
```

```rust
use std::time::Duration;
use s7commplus::{Connection, value::PValue};

fn main() -> s7commplus::Result<()> {
    let mut plc = Connection::connect("192.168.0.1:102", Duration::from_secs(10))?;

    let titi = plc.read_tag("Data_block_1.titi")?;   // e.g. PValue::Int(123)
    println!("titi = {titi:?}");
    plc.write_tag("Data_block_1.titi", PValue::Int(456))?;

    println!("name = {:?}", plc.read_string("Data_block_1.name")?);
    Ok(())
}
```

For an older PLC, use `Connection::connect_real_plc` instead of `connect`.

## `s7tool`: command-line tool

[`s7tool`](s7tool/) lets you try the driver on a PLC without writing code. It's also a
good example to copy.

```sh
cargo run -p s7tool -- --ip 192.168.0.1                       # interactive prompt
cargo run -p s7tool -- --ip 192.168.0.1 browse
cargo run -p s7tool -- --ip 192.168.0.1 read Data_block_1.titi
cargo run -p s7tool -- --ip 192.168.0.1 write Data_block_1.titi 456
cargo run -p s7tool -- --ip 192.168.0.1 state                 # RUN / STOP
cargo run -p s7tool -- --ip 192.168.0.1 --real-plc browse     # older firmware
cargo run -p s7tool -- --ip 192.168.0.1 --auto browse         # try every protocol
```

Each run saves a log file (`s7tool-<time>.log`). Passwords are not written to it.

### Testing on your PLC

```sh
cargo build --release -p s7tool
s7tool --ip <plc address> --auto report
```

This only reads; it never writes to the PLC. It produces a log file. Open an issue and attach
it. The log contains your tag names and values, so check it before sharing.

If the PLC has a password, run `s7tool --ip <plc address> --auto`, then type
`legit <user> <password>` and `report` at the prompt.

## Build & test

```sh
cargo build
cargo test        # no PLC needed
cargo clippy --all-targets
```

Live tests against PLCSIM Advanced (setup in [`tools/plcsim`](tools/plcsim/README.md)):

```sh
S7_PLC_IP=169.254.130.10 cargo test --test live -- --ignored   # add S7_LEGACY=1 for legacy
```

`examples/` has small programs (`read`, `write`, `browse`, `export_csv`, …) that use
`S7_PLC_IP=<addr>`.

## License

LGPL-3.0-or-later, as a derivative of `thomas-v2/S7CommPlusDriver`; see [`LICENSE`](LICENSE).

The legacy protocol code in `src/legacy/` comes from:

- [HarpoS7](https://github.com/bonk-dev/HarpoS7) (MIT), see [`LICENSE-HarpoS7`](LICENSE-HarpoS7)
- [gijzelaerr/s7commplus](https://github.com/gijzelaerr/s7commplus) (MIT) for `family0/`,
  `fingerprint.rs` and `digest.rs`, see [`LICENSE-gijzelaerr-s7commplus`](LICENSE-gijzelaerr-s7commplus)
