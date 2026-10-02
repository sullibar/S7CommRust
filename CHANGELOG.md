# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Symbol paths can now be written exactly as TIA Portal shows them
  ([#1](https://github.com/sullibar/S7CommRust/issues/1)). Previously any quoted path, such
  as `"Data_block_1".toto` or the PLC tag `"Flag"`, failed with "not found":
  - names may be double-quoted, which is required when they contain `.`, `[` or `]`:
    `"Data block.1"."value.1"`. Browsed `VarInfo::name`s quote such levels so they round-trip
    through `resolve_symbol`;
  - array-DB elements resolve with TIA's `"Array DB"[2]` syntax.

## [0.1.0] - 2026-07-05

First public release — a Rust port of
[`thomas-v2/S7CommPlusDriver`](https://github.com/thomas-v2/S7CommPlusDriver) for the
proprietary Siemens S7CommPlus protocol (S7-1200 / S7-1500).

### Added

- **TLS path** (`Connection::connect`, modern firmware): COTP → `InitSsl` → TLS 1.3 handshake
  → session, then:
  - browsing — `datablock_list`, `explore`, `type_info`, `resolve_symbol`;
  - read/write symbolic tags by name — `read_tag`/`write_tag`, batched `read_tags`/`write_tags`,
    and `read_string`/`write_string`;
  - cyclic subscriptions — `subscribe` / `subscribe_with` / `next_notification`;
  - alarms — `subscribe_alarms`, with localized text via `Alarm::message`;
  - authentication — `legitimate`.
- **Legacy path** (`Connection::connect_legacy` / `connect_real_plc`, pre-TLS firmware): the
  non-TLS integrity-protected scheme, with cryptography ported from
  [HarpoS7](https://github.com/bonk-dev/HarpoS7) (MIT).
- The [`value::PValue`] type system (~90 PLC datatypes) with byte-exact (de)serialization,
  S7 date/time decoding, and optimized (zlib preset-dictionary) type-metadata blob inflate.
- A `s7tool` CLI (browse/read/write by symbol) and an `export_csv` example (bulk browse → CSV).

[0.1.0]: https://github.com/sullibar/S7CommRust/releases/tag/v0.1.0
[`value::PValue`]: https://docs.rs/s7commplus/latest/s7commplus/value/enum.PValue.html
