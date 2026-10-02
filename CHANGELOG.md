# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The legacy real-PLC (S7-1200/1500) authentication computes its seed with an x-only ECDH and
  a PRESENT-80 variant instead of the ~84,000 lines of HarpoS7 "monolith" code they replace
  ([#2](https://github.com/sullibar/S7CommRust/issues/2); identified by
  [gijzelaerr/s7commplus](https://github.com/gijzelaerr/s7commplus)). Output is unchanged:
  byte-identical on HarpoS7's golden vectors and on 20,000 random handshakes against the
  original.
- The legacy challenge fingerprint (used by both the PLCSIM and the real-PLC legacy paths) is
  computed as the fixed substitution-permutation network it is, instead of HarpoS7's 3,400-line
  white-box table port. It agrees with that port on every challenge the port could handle, and
  it also handles the ~1.6% the port could not, so legacy connections no longer reconnect to get
  a usable challenge (PLCSIM Advanced FW V2.8 accepted every such challenge in live tests).
  Together with the previous entry, the crate source shrinks from about 99,000 to about 15,500
  lines.

### Added

- `Connection::read_wstring` / `write_wstring` for `WSTRING` tags, which read back as a UInt
  array `[max_len, actual_len, UTF-16 code units…]`, and a public `value::strings` module with
  the `STRING`/`WSTRING` codecs for values that come from batched reads or subscriptions.
- `Connection::resolve_var`: resolves a symbol to a `VarInfo`, so a single tag's softdatatype is
  available to interpret its value (a `DATE` reads as `UInt`; `STRING` and `DATE_AND_TIME` both
  read as a USInt array).
- `value::datatype::softdatatype::name` (TIA Portal type names) and the `STRUCT`, `IEC_TIMER`
  and `BBOOL` constants.
- `datetime::format` renders `S5TIME` (via the new `S7Duration::from_s5time`).
- Arrays of structs/UDTs can be read and written as a whole element (`"DB".arrUdt[1]`) or a
  whole array (`"DB".arrUdt`): the value is a `PValue::Array` of `PackedStruct`s. Previously
  this failed with "array of variable-length datatype 0x17 not yet supported" (the reference
  driver doesn't decode it either).
- s7tool decodes values by their declared type in `browse`, `read` and `sub`: `WString`,
  `Char`/`WChar` as text, all date/time types (`read` previously showed `Time_Of_Day` as raw
  milliseconds and a whole `DTL` as raw bytes), whole arrays element by element, and names every
  type (`Bool` in optimized blocks, `WChar`, `LTime`, `S5Time`, … previously showed as `sdtN`).
  `write` handles `WString`, `Char` and `WChar`.

### Fixed

- Legacy connections no longer fail about 1 time in 256 with "legacy auth rejected (errorcode
  -255)". The key ids in the auth request are variable-length, and a short one left a stale
  template byte behind it; they are now spliced in and the frame lengths recomputed.
- Requests larger than about 1 KB no longer make the PLC drop the connection (e.g. a
  subscription to more than ~50 tags). They were sent as one TLS record, exceeding the
  1024-byte COTP TPDU size negotiated with the PLC; they are now split into S7CommPlus chunks
  of the size the PLC itself uses, one TLS record each.
- Symbol paths can now be written exactly as TIA Portal shows them
  ([#1](https://github.com/sullibar/S7CommRust/issues/1)). Previously any quoted path, such
  as `"Data_block_1".toto` or the PLC tag `"Flag"`, failed with "not found":
  - names may be double-quoted, which is required when they contain `.`, `[` or `]`:
    `"Data block.1"."value.1"`. Browsed `VarInfo::name`s quote such levels so they round-trip
    through `resolve_symbol`;
  - array-DB elements resolve with TIA's `"Array DB"[2]` syntax.
- Array indices one past the upper bound are now rejected. Previously, on a multi-dimensional
  array they wrapped into the next row (`arr[0,3]` of `Array[0..1, 0..2]` read `arr[1,0]`),
  and on a 1-D array the PLC rejected them with an opaque error code.
- `write_string` on an element of an `Array of String[n]` no longer gets rejected by the PLC:
  the type info of array elements carries no max length, so it fell back to 254. The length is
  now taken from the current value's header.
- s7tool no longer shows every USInt array as a `String` (a `Date_And_Time` displayed as
  `"\u{1}"`, for example).

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
