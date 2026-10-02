// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/Datatype.cs + Core/PValue.cs,
// LGPL-3.0-or-later.

//! S7CommPlus value datatype tags and datatype-flags.

/// Datatype tag (the second byte of a serialized [`crate::value::PValue`]).
pub mod tag {
    /// Null / absent value.
    pub const NULL: u8 = 0x00;
    /// Boolean.
    pub const BOOL: u8 = 0x01;
    /// Unsigned 8-bit (`USInt`).
    pub const USINT: u8 = 0x02;
    /// Unsigned 16-bit (`UInt`), fixed-width on the wire.
    pub const UINT: u8 = 0x03;
    /// Unsigned 32-bit (`UDInt`), VLQ-encoded.
    pub const UDINT: u8 = 0x04;
    /// Unsigned 64-bit (`ULInt`), VLQ-encoded.
    pub const ULINT: u8 = 0x05;
    /// Signed 8-bit (`SInt`).
    pub const SINT: u8 = 0x06;
    /// Signed 16-bit (`Int`), fixed-width.
    pub const INT: u8 = 0x07;
    /// Signed 32-bit (`DInt`), signed-VLQ.
    pub const DINT: u8 = 0x08;
    /// Signed 64-bit (`LInt`), signed-VLQ.
    pub const LINT: u8 = 0x09;
    /// 8-bit bit-string (`Byte`).
    pub const BYTE: u8 = 0x0a;
    /// 16-bit bit-string (`Word`), fixed-width.
    pub const WORD: u8 = 0x0b;
    /// 32-bit bit-string (`DWord`), fixed-width.
    pub const DWORD: u8 = 0x0c;
    /// 64-bit bit-string (`LWord`), fixed-width.
    pub const LWORD: u8 = 0x0d;
    /// 32-bit IEEE float (`Real`).
    pub const REAL: u8 = 0x0e;
    /// 64-bit IEEE float (`LReal`).
    pub const LREAL: u8 = 0x0f;
    /// Timestamp — fixed `u64` (nanoseconds since 1970).
    pub const TIMESTAMP: u8 = 0x10;
    /// Timespan — signed-VLQ `i64` (nanosecond duration).
    pub const TIMESPAN: u8 = 0x11;
    /// Relation ID — fixed `u32`.
    pub const RID: u8 = 0x12;
    /// Attribute ID — VLQ `u32`.
    pub const AID: u8 = 0x13;
    /// Blob — a root id plus raw bytes.
    pub const BLOB: u8 = 0x14;
    /// WString — UTF-8 text with a VLQ byte-length prefix (see [`crate::value::PValue::WString`]).
    pub const WSTRING: u8 = 0x15;
    /// Variant — untyped container (no wire format ported; upstream `NotImplementedException`).
    pub const VARIANT: u8 = 0x16;
    /// Struct — packed or non-packed member block.
    pub const STRUCT: u8 = 0x17;
    /// S7String — legacy string (no wire format ported; upstream `NotImplementedException`).
    pub const S7STRING: u8 = 0x19;
}

/// S7 "soft" datatype ids — the semantic type of a symbol as reported by the type-info
/// browse (see [`crate::VarInfo::softdatatype`]). Distinct from the wire [`tag`] bytes: e.g. a
/// `Date` and a `UInt` share the same wire encoding (`tag::UINT`) but different soft ids.
/// Values match `Softdatatype` in the reference driver.
pub mod softdatatype {
    /// BOOL — single bit.
    pub const BOOL: u8 = 1;
    /// BYTE — 8-bit bit-string.
    pub const BYTE: u8 = 2;
    /// CHAR — single ISO-8859-1 byte.
    pub const CHAR: u8 = 3;
    /// WORD — 16-bit bit-string.
    pub const WORD: u8 = 4;
    /// INT — signed 16-bit.
    pub const INT: u8 = 5;
    /// DWORD — 32-bit bit-string.
    pub const DWORD: u8 = 6;
    /// DINT — signed 32-bit.
    pub const DINT: u8 = 7;
    /// REAL — 32-bit IEEE float.
    pub const REAL: u8 = 8;
    /// DATE — `UInt` days since 1990-01-01.
    pub const DATE: u8 = 9;
    /// TIME_OF_DAY — `UDInt` milliseconds since midnight.
    pub const TIME_OF_DAY: u8 = 10;
    /// TIME — `DInt` signed milliseconds (IEC duration).
    pub const TIME: u8 = 11;
    /// S5TIME — legacy S5 timer (16-bit BCD).
    pub const S5TIME: u8 = 12;
    /// DATE_AND_TIME (DT) — 8-byte BCD timestamp.
    pub const DATE_AND_TIME: u8 = 14;
    /// STRUCT — a structured member (struct, UDT, FB instance, system type).
    pub const STRUCT: u8 = 17;
    /// STRING — S7 string (ISO-8859-1, length-prefixed).
    pub const STRING: u8 = 19;
    /// IEC_TIMER — the TP/TON/TOF instance struct.
    pub const IEC_TIMER: u8 = 31;
    /// BBOOL — a byte-aligned BOOL, as used for `Bool` members of optimized blocks.
    pub const BBOOL: u8 = 40;
    /// LREAL — 64-bit IEEE float.
    pub const LREAL: u8 = 48;
    /// ULINT — unsigned 64-bit.
    pub const ULINT: u8 = 49;
    /// LINT — signed 64-bit.
    pub const LINT: u8 = 50;
    /// LWORD — 64-bit bit-string.
    pub const LWORD: u8 = 51;
    /// USINT — unsigned 8-bit.
    pub const USINT: u8 = 52;
    /// UINT — unsigned 16-bit.
    pub const UINT: u8 = 53;
    /// UDINT — unsigned 32-bit.
    pub const UDINT: u8 = 54;
    /// SINT — signed 8-bit.
    pub const SINT: u8 = 55;
    /// WCHAR — single UTF-16 code unit.
    pub const WCHAR: u8 = 61;
    /// WSTRING — wide string (UTF-16, length-prefixed).
    pub const WSTRING: u8 = 62;
    /// LTIME — `LInt` signed nanoseconds (IEC duration).
    pub const LTIME: u8 = 64;
    /// LTIME_OF_DAY — `ULInt` nanoseconds since midnight.
    pub const LTOD: u8 = 65;
    /// LDT — `ULInt` nanoseconds since 1970-01-01 (== the wire `Timestamp`).
    pub const LDT: u8 = 66;
    /// DTL — a struct of {YEAR:UInt, MONTH/DAY/WEEKDAY/HOUR/MINUTE/SECOND:USInt, NANOSECOND:UDInt}.
    pub const DTL: u8 = 67;

    /// The TIA Portal name of a softdatatype id (e.g. `"Time_Of_Day"` for 10), or `None` for an
    /// id this table does not know. [`BBOOL`] — how optimized blocks report `Bool` members — is
    /// named `"Bool"`, as TIA Portal shows it.
    pub fn name(sdt: u8) -> Option<&'static str> {
        Some(match sdt {
            BOOL | BBOOL => "Bool",
            BYTE => "Byte",
            CHAR => "Char",
            WORD => "Word",
            INT => "Int",
            DWORD => "DWord",
            DINT => "DInt",
            REAL => "Real",
            DATE => "Date",
            TIME_OF_DAY => "Time_Of_Day",
            TIME => "Time",
            S5TIME => "S5Time",
            DATE_AND_TIME => "Date_And_Time",
            STRUCT => "Struct",
            STRING => "String",
            20 => "Pointer",
            22 => "Any",
            23 => "Block_FB",
            24 => "Block_FC",
            25 => "Block_DB",
            28 => "Counter",
            29 => "Timer",
            30 => "IEC_Counter",
            IEC_TIMER => "IEC_Timer",
            LREAL => "LReal",
            ULINT => "ULInt",
            LINT => "LInt",
            LWORD => "LWord",
            USINT => "USInt",
            UINT => "UInt",
            UDINT => "UDInt",
            SINT => "SInt",
            WCHAR => "WChar",
            WSTRING => "WString",
            63 => "Variant",
            LTIME => "LTime",
            LTOD => "LTime_Of_Day",
            LDT => "LDT",
            DTL => "DTL",
            68 => "IEC_LTimer",
            69 => "IEC_SCounter",
            70 => "IEC_DCounter",
            71 => "IEC_LCounter",
            72 => "IEC_UCounter",
            73 => "IEC_USCounter",
            74 => "IEC_UDCounter",
            75 => "IEC_ULCounter",
            _ => return None,
        })
    }
}

/// Datatype-flags bits (the first byte of a serialized value).
pub mod flags {
    /// Regular array: a VLQ element count followed by that many elements.
    pub const ARRAY: u8 = 0x10;
    /// Address array.
    pub const ADDRESS_ARRAY: u8 = 0x20;
    /// Sparse array: (VLQ key, value) pairs terminated by a zero byte.
    pub const SPARSE_ARRAY: u8 = 0x40;

    /// Mask of all the array-shape flags.
    pub const ANY_ARRAY: u8 = ARRAY | ADDRESS_ARRAY | SPARSE_ARRAY;
}
