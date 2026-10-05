// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Alarming/{AlarmsDai,AlarmsAsCgs,AlarmsAssociatedValues,
// AlarmsAlarmTexts}.cs, LGPL-3.0-or-later.

//! Alarming: the structured alarm event carried in an alarm-subscription notification's
//! trailing object block (the "DAI" — Data-Associated-Info object), plus localized alarm texts
//! and typed associated values, with placeholder substitution to render the final message.

use core::fmt;

use crate::error::{Error, Result};
use crate::proto::object::PObject;
use crate::value::datatype::softdatatype as sdt;
use crate::value::datetime::S7DateTime;
use crate::value::PValue;

// DAI (Data-Associated-Info) attribute ids (reference `Ids.cs`).
const OBJECT_VARIABLE_TYPE_NAME: u32 = 233;
const DAI_CPU_ALARM_ID: u32 = 2670;
const DAI_ALL_STATES_INFO: u32 = 2671;
const DAI_ALARM_DOMAIN: u32 = 2672;
const DAI_COMING: u32 = 2673;
const DAI_GOING: u32 = 2677;
const DAI_ALARM_TEXTS: u32 = 2715;
const DAI_MESSAGE_TYPE: u32 = 4079;
const DAI_HMI_INFO: u32 = 7813;
const DAI_SEQUENCE_COUNTER: u32 = 7917;

// The Explore of the pending alarms follows gijzelaerr/s7commplus `build_alarm_explore_request`.

/// RID of the alarm subsystem (`NativeObjects.theAlarmSubsystem_Rid`).
pub(crate) const ALARM_SUBSYSTEM_RID: u32 = 8;
/// Explore request id under which the alarm subsystem lists its pending alarms
/// (`AlarmSubsystem.itsUpdateRelevantDAI`).
pub(crate) const UPDATE_RELEVANT_DAI: u32 = 2667;
/// The attributes an Explore of the pending alarms asks for: what [`Alarm::from_object`] reads.
pub(crate) const DAI_ATTRIBUTES: [u32; 10] = [
    DAI_CPU_ALARM_ID,
    DAI_ALL_STATES_INFO,
    DAI_ALARM_DOMAIN,
    DAI_COMING,
    DAI_GOING,
    DAI_MESSAGE_TYPE,
    DAI_HMI_INFO,
    OBJECT_VARIABLE_TYPE_NAME,
    DAI_SEQUENCE_COUNTER,
    DAI_ALARM_TEXTS,
];

/// The alarms among an Explore's `objects`: every object, at any depth, that carries a
/// `CpuAlarmId`.
pub(crate) fn alarms_in(objects: &[PObject]) -> Result<Vec<Alarm>> {
    let mut alarms = Vec::new();
    let mut pending: Vec<&PObject> = objects.iter().rev().collect();
    while let Some(obj) = pending.pop() {
        if obj.attribute(DAI_CPU_ALARM_ID).is_some() {
            alarms.push(Alarm::from_object(obj)?);
        }
        pending.extend(obj.objects.iter().rev());
    }
    Ok(alarms)
}

// AS_CGS (the coming/going struct) member ids.
const AS_CGS_ALL_STATES_INFO: u32 = 3474;
const AS_CGS_TIMESTAMP: u32 = 3475;
const AS_CGS_ASSOCIATED_VALUES: u32 = 3476;
const AS_CGS_ACK_TIMESTAMP: u32 = 3646;

// Type-info ids used as the blob root id of each associated value (`0x02000000 + softdatatype`).
const TI_BASE: u32 = 0x0200_0000;
const TI_BOOL: u32 = TI_BASE + 1;
const TI_BYTE: u32 = TI_BASE + 2;
const TI_CHAR: u32 = TI_BASE + 3;
const TI_WORD: u32 = TI_BASE + 4;
const TI_INT: u32 = TI_BASE + 5;
const TI_DWORD: u32 = TI_BASE + 6;
const TI_DINT: u32 = TI_BASE + 7;
const TI_REAL: u32 = TI_BASE + 8;
const TI_LREAL: u32 = TI_BASE + 48;
const TI_USINT: u32 = TI_BASE + 52;
const TI_UINT: u32 = TI_BASE + 53;
const TI_UDINT: u32 = TI_BASE + 54;
const TI_SINT: u32 = TI_BASE + 55;
const TI_WCHAR: u32 = TI_BASE + 61;
const TI_ULINT: u32 = TI_BASE + 49;
const TI_LINT: u32 = TI_BASE + 50;
const TI_LWORD: u32 = TI_BASE + 51;
// Date and time types: the value in the type's big-endian memory layout, as for the others.
const TI_DATE: u32 = TI_BASE + 9;
const TI_TIME_OF_DAY: u32 = TI_BASE + 10;
const TI_TIME: u32 = TI_BASE + 11;
const TI_S5TIME: u32 = TI_BASE + 12;
const TI_DATE_AND_TIME: u32 = TI_BASE + 14;
const TI_LTIME: u32 = TI_BASE + 64;
const TI_LTOD: u32 = TI_BASE + 65;
const TI_LDT: u32 = TI_BASE + 66;
const TI_DTL: u32 = TI_BASE + 67;
const TI_STRING_START: u32 = 0x020a_0000;
const TI_STRING_END: u32 = 0x020a_ffff;
const TI_WSTRING_START: u32 = 0x020b_0000;
const TI_WSTRING_END: u32 = 0x020b_ffff;

/// Whether an alarm event is the alarm *coming* (activating) or *going* (clearing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmState {
    /// The alarm is activating (condition became true).
    Coming,
    /// The alarm is clearing (condition became false).
    Going,
}

/// A single associated value (SD_1..SD_10) carried with an alarm, decoded to a typed value.
/// `Display` renders the value in its natural form (used when substituting into alarm text).
///
/// Date and time values are [`AssociatedValue::Text`], formatted as
/// [`crate::value::datetime::format`] does.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AssociatedValue {
    /// Boolean associated value.
    Bool(bool),
    /// Integer associated value (any width up to 64 bits signed, widened to `i64`).
    Int(i64),
    /// An unsigned 64-bit associated value (`ULInt`, `LWord`), which may not fit an `i64`.
    UInt(u64),
    /// Floating-point associated value. A `Real` is widened by way of its shortest decimal form,
    /// so 12.756 stays 12.756 rather than 12.755999565124512.
    Real(f64),
    /// Text associated value.
    Text(String),
    /// A value whose type-info id wasn't recognized (kept so SD indices stay aligned).
    Unsupported,
    /// A slot the alarm doesn't use: the PLC sends all ten, the unused ones empty.
    Unused,
}

impl fmt::Display for AssociatedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssociatedValue::Bool(b) => write!(f, "{b}"),
            AssociatedValue::Int(v) => write!(f, "{v}"),
            AssociatedValue::UInt(v) => write!(f, "{v}"),
            AssociatedValue::Real(v) => write!(f, "{v}"),
            AssociatedValue::Text(s) => write!(f, "{s}"),
            AssociatedValue::Unsupported | AssociatedValue::Unused => Ok(()),
        }
    }
}

/// Localized alarm texts for one language (`AlarmsAlarmTexts`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlarmText {
    /// TIA language id these texts are in (e.g. 1033 = en-US).
    pub language_id: u16,
    /// The info text (`AS_1`).
    pub info_text: String,
    /// The main alarm text (`AS_2`), with `@n%fmt@` placeholders for associated values.
    pub alarm_text: String,
    /// Additional texts `AS_3..=AS_11` (info text 1..9).
    pub additional_texts: [String; 9],
}

/// A decoded alarm event from an alarm-subscription notification.
#[derive(Debug, Clone, PartialEq)]
pub struct Alarm {
    /// The name of the object that carried the alarm (`ObjectVariableTypeName`). Not the alarm's
    /// own name: PLCSIM sends transient names such as `TempDai_1` in notifications and
    /// `ExplDai_2` in [`Connection::active_alarms`](crate::Connection::active_alarms).
    pub type_name: String,
    /// The CPU-assigned unique alarm id.
    pub cpu_alarm_id: u64,
    /// Bitfield of all state flags for this alarm.
    pub all_states_info: u8,
    /// The alarm domain (OB/program area) the alarm belongs to.
    pub alarm_domain: u16,
    /// The alarm's message type/class.
    pub message_type: i32,
    /// Monotonic sequence counter for this alarm's events.
    pub sequence_counter: u32,
    /// Whether this event is the alarm coming or going.
    pub state: AlarmState,
    /// The state info of the coming/going event.
    pub state_info: u8,
    /// When the alarm came or went (nanosecond precision, UTC).
    pub timestamp: S7DateTime,
    /// When the alarm was acknowledged (epoch/zero if not acknowledged).
    pub ack_timestamp: S7DateTime,
    /// Associated values SD_1..SD_10 (index 0 = SD_1), decoded to typed values; the slots the
    /// alarm doesn't use are [`AssociatedValue::Unused`].
    pub associated_values: Vec<AssociatedValue>,
    /// The type-info id of each associated value, in the same order (`0x0200_0000` plus the
    /// softdatatype for an elementary type; 0 where the slot carried no blob). A `%x` in the
    /// alarm text shows a negative value in its type's width.
    pub associated_value_types: Vec<u32>,
    /// Localized alarm texts (one entry per language present in the notification).
    pub texts: Vec<AlarmText>,
    /// The raw HmiInfo blob.
    pub hmi_info: Vec<u8>,
}

impl Alarm {
    /// Parse an alarm event from its notification `PObject` (the "DAI" object), mirroring
    /// `AlarmsDai.FromNotificationObject` + `AlarmsAsCgs.FromValueStruct`.
    pub fn from_object(obj: &PObject) -> Result<Alarm> {
        let type_name = obj
            .attribute(OBJECT_VARIABLE_TYPE_NAME)
            .and_then(PValue::as_str)
            .unwrap_or("")
            .to_string();
        let cpu_alarm_id = obj
            .attribute(DAI_CPU_ALARM_ID)
            .and_then(PValue::as_u64)
            .ok_or_else(|| Error::protocol("alarm object missing CpuAlarmId (2670)"))?;
        let all_states_info = obj
            .attribute(DAI_ALL_STATES_INFO)
            .and_then(PValue::as_u64)
            .unwrap_or(0) as u8;
        let alarm_domain = obj
            .attribute(DAI_ALARM_DOMAIN)
            .and_then(PValue::as_u64)
            .unwrap_or(0) as u16;
        let message_type = obj
            .attribute(DAI_MESSAGE_TYPE)
            .and_then(PValue::as_i64)
            .unwrap_or(0) as i32;
        let sequence_counter = obj
            .attribute(DAI_SEQUENCE_COUNTER)
            .and_then(PValue::as_u64)
            .unwrap_or(0) as u32;
        let hmi_info = obj
            .attribute(DAI_HMI_INFO)
            .and_then(PValue::as_bytes)
            .unwrap_or(&[])
            .to_vec();

        // Exactly one of Coming / Going is present.
        let (state, cgs) = if let Some(v) = obj.attribute(DAI_COMING) {
            (AlarmState::Coming, v)
        } else if let Some(v) = obj.attribute(DAI_GOING) {
            (AlarmState::Going, v)
        } else {
            return Err(Error::protocol(
                "alarm object has neither Coming (2673) nor Going (2677)",
            ));
        };
        let elements = match cgs {
            PValue::Struct { elements, .. } => elements,
            other => {
                return Err(Error::protocol(format!(
                    "alarm coming/going value is not a Struct: {other:?}"
                )))
            }
        };
        let get = |id: u32| elements.iter().find(|(k, _)| *k == id).map(|(_, v)| v);

        let state_info = get(AS_CGS_ALL_STATES_INFO)
            .and_then(PValue::as_u64)
            .unwrap_or(0) as u8;
        let timestamp = S7DateTime::from_unix_nanos(
            get(AS_CGS_TIMESTAMP).and_then(PValue::as_i64).unwrap_or(0),
        );
        let ack_timestamp = S7DateTime::from_unix_nanos(
            get(AS_CGS_ACK_TIMESTAMP)
                .and_then(PValue::as_i64)
                .unwrap_or(0),
        );
        // Associated values: a blob array whose element 0 is type info and elements 1..=10 are
        // SD_1..SD_10; each blob's root id is its type-info id.
        let slots: &[PValue] = match get(AS_CGS_ASSOCIATED_VALUES) {
            Some(PValue::Array { items, .. }) => items.get(1..).unwrap_or(&[]),
            _ => &[],
        };
        let slots = &slots[..slots.len().min(10)];
        let associated_values = slots.iter().map(decode_associated_value).collect();
        let associated_value_types = slots
            .iter()
            .map(|v| match v {
                PValue::Blob { root_id, .. } => *root_id,
                _ => 0,
            })
            .collect();

        let texts = match obj.attribute(DAI_ALARM_TEXTS) {
            Some(PValue::SparseArray { entries, .. }) => parse_alarm_texts(entries),
            _ => Vec::new(),
        };

        Ok(Alarm {
            type_name,
            cpu_alarm_id,
            all_states_info,
            alarm_domain,
            message_type,
            sequence_counter,
            state,
            state_info,
            timestamp,
            ack_timestamp,
            associated_values,
            associated_value_types,
            texts,
            hmi_info,
        })
    }

    /// The localized texts for `language_id` (an LCID, e.g. 1033 = en-US, 1031 = de-DE), if the
    /// notification carried them.
    pub fn text(&self, language_id: u16) -> Option<&AlarmText> {
        self.texts.iter().find(|t| t.language_id == language_id)
    }

    /// Render the final alarm message for `language_id`: the alarm text with `@n%fmt@` placeholders
    /// replaced by the associated values SD_1..SD_10. Returns `None` if no text for that language.
    pub fn message(&self, language_id: u16) -> Option<String> {
        let t = self.text(language_id)?;
        Some(substitute(
            &t.alarm_text,
            &self.associated_values,
            &self.associated_value_types,
        ))
    }
}

/// The width in bits of an integer associated value of type-info id `ti` (64 if unknown).
fn integer_bits(ti: u32) -> u32 {
    match ti {
        TI_BYTE | TI_USINT | TI_SINT | TI_CHAR => 8,
        TI_WORD | TI_UINT | TI_INT => 16,
        TI_DWORD | TI_UDINT | TI_DINT => 32,
        _ => 64,
    }
}

/// Decode one associated-value blob (`root_id` = type-info id) into a typed value. Big-endian.
fn decode_associated_value(v: &PValue) -> AssociatedValue {
    let PValue::Blob { root_id, data } = v else {
        return AssociatedValue::Unsupported;
    };
    if data.is_empty() {
        // Every type the PLC can send carries at least one byte.
        return AssociatedValue::Unused;
    }
    let b = data.as_slice();
    let i16be = |o: usize| b.get(o..o + 2).map(|s| i16::from_be_bytes([s[0], s[1]]));
    let u16be = |o: usize| b.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]));
    let u32be = |o: usize| {
        b.get(o..o + 4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    };
    let i32be = |o: usize| {
        b.get(o..o + 4)
            .map(|s| i32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    };
    let u64be = |o: usize| {
        b.get(o..o + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
    };
    // A date or time, formatted as the value layer does; `None` when out of range.
    let time = |ty: u8, v: Option<PValue>| {
        v.and_then(|v| crate::value::datetime::format(ty, &v))
            .map(AssociatedValue::Text)
    };
    let opt = match *root_id {
        TI_BOOL => b.first().map(|&x| AssociatedValue::Bool(x != 0)),
        TI_BYTE | TI_USINT => b.first().map(|&x| AssociatedValue::Int(i64::from(x))),
        TI_SINT => b.first().map(|&x| AssociatedValue::Int(i64::from(x as i8))),
        TI_CHAR => b
            .first()
            .map(|&x| AssociatedValue::Text((x as char).to_string())),
        TI_WORD | TI_UINT => u16be(0).map(|x| AssociatedValue::Int(i64::from(x))),
        TI_INT => i16be(0).map(|x| AssociatedValue::Int(i64::from(x))),
        TI_DWORD | TI_UDINT => u32be(0).map(|x| AssociatedValue::Int(i64::from(x))),
        TI_DINT => i32be(0).map(|x| AssociatedValue::Int(i64::from(x))),
        TI_LINT => u64be(0).map(|x| AssociatedValue::Int(x as i64)),
        TI_ULINT | TI_LWORD => u64be(0).map(AssociatedValue::UInt),
        // Widened through the shortest decimal that reads back as the same f32, which is what
        // the alarm text means: f64::from(12.756f32) is 12.755999565124512.
        TI_REAL => u32be(0).map(|x| {
            let r = f32::from_bits(x);
            AssociatedValue::Real(r.to_string().parse().unwrap_or(f64::from(r)))
        }),
        TI_LREAL => u64be(0).map(|x| AssociatedValue::Real(f64::from_bits(x))),
        TI_DATE => time(sdt::DATE, u16be(0).map(PValue::UInt)),
        TI_TIME_OF_DAY => time(sdt::TIME_OF_DAY, u32be(0).map(PValue::UDInt)),
        TI_TIME => time(sdt::TIME, i32be(0).map(PValue::DInt)),
        TI_S5TIME => time(sdt::S5TIME, u16be(0).map(PValue::Word)),
        TI_DATE_AND_TIME => time(
            sdt::DATE_AND_TIME,
            b.get(0..8).map(|s| PValue::USIntArray(s.to_vec())),
        ),
        TI_LTIME => time(sdt::LTIME, u64be(0).map(|x| PValue::LInt(x as i64))),
        TI_LTOD => time(sdt::LTOD, u64be(0).map(PValue::ULInt)),
        TI_LDT => time(sdt::LDT, u64be(0).map(PValue::ULInt)),
        TI_DTL => time(
            sdt::DTL,
            b.get(0..12).map(|s| PValue::USIntArray(s.to_vec())),
        ),
        TI_WCHAR => u16be(0).and_then(|x| {
            char::from_u32(u32::from(x)).map(|c| AssociatedValue::Text(c.to_string()))
        }),
        // String[n]: [max_len, act_len, chars… (ISO-8859-1)].
        id if id > TI_STRING_START && id <= TI_STRING_END => b.get(1).map(|&act| {
            let end = (2 + act as usize).min(b.len());
            AssociatedValue::Text(b[2..end].iter().map(|&c| c as char).collect())
        }),
        // WString[n]: [max_len:u16, act_len:u16, chars…:UTF-16BE].
        id if id > TI_WSTRING_START && id <= TI_WSTRING_END => u16be(2).map(|act| {
            let units: Vec<u16> = b[4..]
                .chunks_exact(2)
                .take(act as usize)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            AssociatedValue::Text(String::from_utf16_lossy(&units))
        }),
        _ => None,
    };
    opt.unwrap_or(AssociatedValue::Unsupported)
}

/// Parse the DAI AlarmTexts sparse blob array (`AlarmsAlarmTexts`): key = `(lcid << 16) | textid`,
/// value = the UTF-8 text. Groups texts by language.
fn parse_alarm_texts(entries: &[(u32, PValue)]) -> Vec<AlarmText> {
    let mut out: Vec<AlarmText> = Vec::new();
    for (key, value) in entries {
        let bytes = match value.as_bytes() {
            Some(b) => b,
            None => continue,
        };
        let text = String::from_utf8_lossy(bytes).into_owned();
        let lcid = (key >> 16) as u16;
        let textid = (key & 0xffff) as u16;
        let at = match out.iter_mut().find(|t| t.language_id == lcid) {
            Some(t) => t,
            None => {
                out.push(AlarmText {
                    language_id: lcid,
                    ..Default::default()
                });
                out.last_mut().unwrap()
            }
        };
        match textid {
            1 => at.info_text = text,
            2 => at.alarm_text = text,
            n @ 3..=11 => at.additional_texts[(n - 3) as usize] = text,
            _ => {}
        }
    }
    out
}

/// Replace `@n%fmt@` (and `@n@`) placeholders in `text` with the associated value SD_n. `@@` is a
/// literal `@`. Unmatched/out-of-range placeholders, and those of a value whose type isn't
/// decoded ([`AssociatedValue::Unsupported`]), are left as-is. The `%fmt` is a best-effort
/// C-printf-style hint (`d`/`u`/`x`/`f`/`e`/`s`/`b`); without one the value's natural form is
/// used. `types` are the values' type-info ids (see [`Alarm::associated_value_types`]).
fn substitute(text: &str, values: &[AssociatedValue], types: &[u32]) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' {
            // Copy this UTF-8 char whole.
            let ch_len = utf8_len(bytes[i]);
            let end = (i + ch_len).min(bytes.len());
            out.push_str(&text[i..end]);
            i = end;
            continue;
        }
        // At '@'. Handle escape "@@".
        if bytes.get(i + 1) == Some(&b'@') {
            out.push('@');
            i += 2;
            continue;
        }
        // Parse "@<digits>[%<fmt>]@".
        let mut j = i + 1;
        let start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            out.push('@'); // no index → literal
            i += 1;
            continue;
        }
        let index: usize = text[start..j].parse().unwrap_or(0);
        let mut spec = "";
        if bytes.get(j) == Some(&b'%') {
            let fmt_start = j + 1;
            let mut k = fmt_start;
            while k < bytes.len() && bytes[k] != b'@' {
                k += 1;
            }
            if k >= bytes.len() {
                out.push('@'); // unterminated → literal
                i += 1;
                continue;
            }
            spec = &text[fmt_start..k];
            j = k;
        }
        if bytes.get(j) != Some(&b'@') {
            out.push('@'); // malformed → literal
            i += 1;
            continue;
        }
        // Valid placeholder spanning i..=j. Substitute SD_index (1-based).
        let slot = index.wrapping_sub(1);
        match values.get(slot) {
            // Out of range, or a value that isn't decoded: leave as-is.
            None | Some(AssociatedValue::Unsupported) => out.push_str(&text[i..=j]),
            Some(v) => {
                let bits = types.get(slot).map_or(64, |&ti| integer_bits(ti));
                out.push_str(&apply_format(v, spec, bits))
            }
        }
        i = j + 1;
    }
    out
}

/// Apply a best-effort C-printf-style format spec to an associated value, an integer one being
/// `bits` wide.
fn apply_format(v: &AssociatedValue, spec: &str, bits: u32) -> String {
    // Honor a `.N` precision if present (e.g. "6.2f" -> precision 2). The text comes from the
    // PLC; clamp it, since a precision past u16::MAX makes `format!` panic.
    let precision = || {
        spec.rsplit_once('.')
            .and_then(|(_, p)| {
                p.trim_end_matches(|c: char| c.is_ascii_alphabetic())
                    .parse::<usize>()
                    .ok()
            })
            .map(|p| p.min(32))
    };
    match spec.chars().last() {
        Some(conv @ ('x' | 'X')) => {
            let n = match v {
                // A negative value in two's complement of its own width, as C shows it.
                AssociatedValue::Int(n) => *n as u64 & (u64::MAX >> (64 - bits.clamp(1, 64))),
                AssociatedValue::UInt(n) => *n,
                other => return other.to_string(),
            };
            if conv == 'X' {
                format!("{n:X}")
            } else {
                format!("{n:x}")
            }
        }
        Some(conv @ ('f' | 'F' | 'e' | 'E' | 'g' | 'G')) => {
            let n = match v {
                AssociatedValue::Real(r) => *r,
                AssociatedValue::Int(n) => *n as f64,
                AssociatedValue::UInt(n) => *n as f64,
                other => return other.to_string(),
            };
            match conv {
                // C's default precision is 6.
                'f' | 'F' => {
                    let prec = precision().unwrap_or(6);
                    format!("{n:.prec$}")
                }
                'e' => c_exponent(n, precision().unwrap_or(6)),
                'E' => c_exponent(n, precision().unwrap_or(6)).to_uppercase(),
                _ => match precision() {
                    Some(prec) => format!("{n:.prec$}"),
                    None => format!("{n}"),
                },
            }
        }
        _ => v.to_string(),
    }
}

/// `n` in C's `%e` form: `1.275600e+01`.
fn c_exponent(n: f64, precision: usize) -> String {
    let s = format!("{n:.precision$e}");
    match s.split_once('e') {
        Some((mantissa, exp)) => {
            let exp: i32 = exp.parse().unwrap_or(0);
            let sign = if exp < 0 { '-' } else { '+' };
            format!("{mantissa}e{sign}{:02}", exp.unsigned_abs())
        }
        None => s, // NaN, inf
    }
}

/// UTF-8 byte length from a leading byte.
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::datatype::{flags, tag};

    fn blob(root_id: u32, data: Vec<u8>) -> PValue {
        PValue::Blob { root_id, data }
    }

    #[test]
    fn decode_typed_associated_values() {
        assert_eq!(
            decode_associated_value(&blob(TI_BOOL, vec![1])),
            AssociatedValue::Bool(true)
        );
        assert_eq!(
            decode_associated_value(&blob(TI_INT, vec![0xff, 0xfe])),
            AssociatedValue::Int(-2)
        );
        assert_eq!(
            decode_associated_value(&blob(TI_UDINT, vec![0, 0, 0x30, 0x39])),
            AssociatedValue::Int(12345)
        );
        assert_eq!(
            decode_associated_value(&blob(TI_REAL, 1.5f32.to_be_bytes().to_vec())),
            AssociatedValue::Real(1.5)
        );
        // String[10]: max=10, act=3, "abc"
        assert_eq!(
            decode_associated_value(&blob(TI_STRING_START + 10, vec![10, 3, b'a', b'b', b'c'])),
            AssociatedValue::Text("abc".into())
        );
    }

    #[test]
    fn substitute_placeholders() {
        let vals = vec![AssociatedValue::Int(42), AssociatedValue::Real(12.756)];
        assert_eq!(substitute("Level=@1%d@ ok", &vals, &[]), "Level=42 ok");
        assert_eq!(substitute("P=@2%.2f@bar", &vals, &[]), "P=12.76bar");
        assert_eq!(substitute("plain @@ text", &vals, &[]), "plain @ text");
        // Out-of-range and malformed placeholders are left intact.
        assert_eq!(substitute("@5%d@", &vals, &[]), "@5%d@");
        assert_eq!(substitute("email@host", &vals, &[]), "email@host");
    }

    #[test]
    fn real_values_keep_their_decimal_form() {
        let v = decode_associated_value(&blob(TI_REAL, 12.756f32.to_be_bytes().to_vec()));
        assert_eq!(v, AssociatedValue::Real(12.756));
        assert_eq!(v.to_string(), "12.756");
        // %f without a precision has C's 6 digits; %e is C's form too.
        assert_eq!(
            substitute("@1%f@", std::slice::from_ref(&v), &[TI_REAL]),
            "12.756000"
        );
        assert_eq!(
            substitute("@1%e@", std::slice::from_ref(&v), &[TI_REAL]),
            "1.275600e+01"
        );
        assert_eq!(substitute("@1%.2E@", &[v], &[TI_REAL]), "1.28E+01");
        assert_eq!(c_exponent(0.00012, 1), "1.2e-04");
    }

    #[test]
    fn hex_of_a_negative_value_has_its_type_width() {
        let vals = [
            decode_associated_value(&blob(TI_INT, vec![0xff, 0xfe])),
            decode_associated_value(&blob(TI_SINT, vec![0x80])),
            decode_associated_value(&blob(TI_DINT, (-1i32).to_be_bytes().to_vec())),
            decode_associated_value(&blob(TI_LINT, (-2i64).to_be_bytes().to_vec())),
            decode_associated_value(&blob(TI_LWORD, u64::MAX.to_be_bytes().to_vec())),
        ];
        let types = [TI_INT, TI_SINT, TI_DINT, TI_LINT, TI_LWORD];
        assert_eq!(
            substitute("@1%x@ @2%X@ @3%x@ @4%x@ @5%X@ @5%u@", &vals, &types),
            format!(
                "fffe 80 ffffffff fffffffffffffffe FFFFFFFFFFFFFFFF {}",
                u64::MAX
            )
        );
        // Without the types, the full 64 bits.
        assert_eq!(substitute("@1%x@", &vals, &[]), "fffffffffffffffe");
    }

    #[test]
    fn date_and_time_values_and_undecoded_types() {
        let decode = |ti: u32, data: &[u8]| decode_associated_value(&blob(ti, data.to_vec()));
        let text = |s: &str| AssociatedValue::Text(s.into());
        assert_eq!(
            decode(TI_TIME, &(-4386i32).to_be_bytes()),
            text("T#-4s386ms")
        );
        assert_eq!(
            decode(TI_TIME_OF_DAY, &45_930_500u32.to_be_bytes()),
            text("12:45:30.5")
        );
        assert_eq!(decode(TI_DATE, &[0, 0]), text("1990-01-01 00:00:00"));
        assert_eq!(decode(TI_S5TIME, &[0x02, 0x00]), text("T#2s"));
        assert_eq!(
            decode(
                TI_DATE_AND_TIME,
                &[0x24, 0x03, 0x15, 0x13, 0x45, 0x30, 0x12, 0x36]
            ),
            text("2024-03-15 13:45:30.123")
        );
        assert_eq!(
            decode(TI_LTIME, &1_500_000_000i64.to_be_bytes()),
            text("T#1s500ms")
        );
        assert_eq!(
            decode(TI_LDT, &1_643_006_313_000_000_000u64.to_be_bytes()),
            text("2022-01-24 06:38:33")
        );
        assert_eq!(
            decode(TI_LTOD, &3_600_000_000_000u64.to_be_bytes()),
            text("01:00:00")
        );
        assert_eq!(
            decode(TI_DTL, &[0x07, 0xe8, 3, 15, 6, 13, 45, 30, 0, 0, 0, 0]),
            text("2024-03-15 13:45:30")
        );
        // Out of range: not a time.
        assert_eq!(
            decode(TI_TIME_OF_DAY, &90_000_000u32.to_be_bytes()),
            AssociatedValue::Unsupported
        );
        // A value whose type isn't decoded keeps its placeholder in the text.
        let vals = [AssociatedValue::Unsupported, AssociatedValue::Int(1)];
        assert_eq!(
            substitute("a @1%d@ b @2@", &vals, &[TI_BASE + 63, TI_INT]),
            "a @1%d@ b 1"
        );
    }

    #[test]
    fn parse_texts_by_language() {
        // key = (lcid<<16)|textid. en-US=1033. textid 2 = AlarmText, 1 = Infotext.
        let entries = vec![
            ((1033u32 << 16) | 2, blob(0, b"Motor @1%d@ fault".to_vec())),
            ((1033u32 << 16) | 1, blob(0, b"info".to_vec())),
        ];
        let texts = parse_alarm_texts(&entries);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].language_id, 1033);
        assert_eq!(texts[0].alarm_text, "Motor @1%d@ fault");
        assert_eq!(texts[0].info_text, "info");
    }

    #[test]
    fn full_alarm_with_text_and_values() {
        let cgs = PValue::Struct {
            id: 0,
            elements: vec![
                (AS_CGS_ALL_STATES_INFO, PValue::USInt(0x07)),
                (
                    AS_CGS_TIMESTAMP,
                    PValue::Timestamp(1_643_006_313_302_251_251),
                ),
                (
                    AS_CGS_ASSOCIATED_VALUES,
                    PValue::Array {
                        element_type: tag::BLOB,
                        flags: flags::ARRAY,
                        items: vec![
                            blob(AS_CGS_ASSOCIATED_VALUES, vec![0, 0, 0, 0]), // index 0 = type info
                            blob(TI_INT, vec![0x00, 0x05]),                   // SD_1 = 5
                        ],
                    },
                ),
                (AS_CGS_ACK_TIMESTAMP, PValue::Timestamp(0)),
            ],
        };
        let mut obj = PObject::new(0, 0, 0);
        obj.add_attribute(
            OBJECT_VARIABLE_TYPE_NAME,
            PValue::WString("Motor_Fault".into()),
        );
        obj.add_attribute(DAI_CPU_ALARM_ID, PValue::LWord(0x11));
        obj.add_attribute(DAI_ALARM_DOMAIN, PValue::UInt(258));
        obj.add_attribute(DAI_COMING, cgs);
        obj.add_attribute(
            DAI_ALARM_TEXTS,
            PValue::SparseArray {
                element_type: tag::BLOB,
                entries: vec![(
                    (1033u32 << 16) | 2,
                    blob(0, b"Motor speed @1%d@ rpm".to_vec()),
                )],
            },
        );

        let a = Alarm::from_object(&obj).unwrap();
        assert_eq!(a.state, AlarmState::Coming);
        assert_eq!(a.associated_values, vec![AssociatedValue::Int(5)]);
        assert_eq!(a.message(1033).unwrap(), "Motor speed 5 rpm");
        assert!(a.message(1031).is_none()); // no de-DE text present
    }

    /// A pending alarm `id` as the alarm subsystem lists it: a DAI object with a coming state.
    fn dai(id: u64) -> PObject {
        let mut obj = PObject::new(0x8a7e_0000 + id as u32, 2681, 0);
        obj.add_attribute(DAI_CPU_ALARM_ID, PValue::LWord(id));
        obj.add_attribute(
            DAI_COMING,
            PValue::Struct {
                id: 0,
                elements: vec![(AS_CGS_TIMESTAMP, PValue::Timestamp(0))],
            },
        );
        obj
    }

    #[test]
    fn alarms_in_finds_alarms_at_any_depth() {
        let mut subsystem = PObject::new(ALARM_SUBSYSTEM_RID, 2668, 0);
        subsystem.objects.push(dai(2));
        let mut nested = PObject::new(9, 1, 0);
        nested.objects.push(dai(3));
        subsystem.objects.push(nested);
        let ids: Vec<u64> = alarms_in(&[dai(1), subsystem])
            .unwrap()
            .iter()
            .map(|a| a.cpu_alarm_id)
            .collect();
        assert_eq!(ids, [1, 2, 3]);
        assert!(alarms_in(&[PObject::new(ALARM_SUBSYSTEM_RID, 2668, 0)])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn alarms_in_reports_a_malformed_alarm() {
        let mut broken = PObject::new(1, 2681, 0);
        broken.add_attribute(DAI_CPU_ALARM_ID, PValue::LWord(1)); // neither coming nor going
        assert!(alarms_in(&[dai(1), broken]).is_err());
    }

    #[test]
    fn missing_coming_going_errors() {
        let mut obj = PObject::new(0, 0, 0);
        obj.add_attribute(DAI_CPU_ALARM_ID, PValue::LWord(1));
        assert!(Alarm::from_object(&obj).is_err());
    }

    #[test]
    fn an_empty_slot_is_unused() {
        let unused = blob(1, Vec::new());
        assert_eq!(decode_associated_value(&unused), AssociatedValue::Unused);
        assert_eq!(AssociatedValue::Unused.to_string(), "");
        // An empty string still carries its length header, so it is a value.
        let empty_string = blob(TI_STRING_START + 10, vec![10, 0]);
        assert_eq!(
            decode_associated_value(&empty_string),
            AssociatedValue::Text(String::new())
        );
    }

    // Captured from PLCSIM Advanced V2.9 (TLS) with a `Program_Alarm` whose SIG is a DB bool and
    // whose SD_1 is an Int, no alarm text configured (tools/plcsim/alarms.scl).

    /// The alarms pending (`Connection::active_alarms`): the alarm as it came with SD_1 = 7. (SD_1
    /// had been changed to 42 since, but an alarm keeps the values it came with.)
    const PENDING: &[u8] = include_bytes!("../../tests/vectors/proto/alarm_explore_pending.bin");
    /// The alarm going (SD_1 still 42), then coming again with SD_1 = -7, from an alarm
    /// subscription.
    const GOING: &[u8] = include_bytes!("../../tests/vectors/proto/alarm_notification_going.bin");
    const COMING: &[u8] = include_bytes!("../../tests/vectors/proto/alarm_notification_coming.bin");

    /// SD_1 as an Int and the nine slots the alarm doesn't use.
    fn assert_one_int_value(alarm: &Alarm, sd_1: i64) {
        assert_eq!(alarm.associated_values.len(), 10);
        assert_eq!(alarm.associated_values[0], AssociatedValue::Int(sd_1));
        assert!(alarm.associated_values[1..]
            .iter()
            .all(|v| *v == AssociatedValue::Unused));
    }

    #[test]
    fn a_pending_alarm_captured_from_plcsim() {
        let resp = crate::proto::parse_explore_response(PENDING, true).unwrap();
        assert!(resp.header.is_ok());
        let alarms = alarms_in(&resp.objects).unwrap();
        assert_eq!(alarms.len(), 1);
        let a = &alarms[0];
        assert_eq!(a.state, AlarmState::Coming);
        assert_eq!(a.cpu_alarm_id, 0x8a0e_000a_0001_0000);
        assert_eq!(a.alarm_domain, 256);
        assert_one_int_value(a, 7);
        assert_eq!(a.texts.len(), 1);
        assert_eq!(a.texts[0].language_id, 1033);
        assert_eq!(a.message(1033).as_deref(), Some(" ")); // no text configured
    }

    #[test]
    fn going_and_coming_notifications_captured_from_plcsim() {
        let going = crate::proto::parse_notification(GOING).unwrap().alarms();
        let coming = crate::proto::parse_notification(COMING).unwrap().alarms();
        assert_eq!((going.len(), coming.len()), (1, 1));
        let (going, coming) = (&going[0], &coming[0]);
        assert_eq!(going.state, AlarmState::Going);
        assert_eq!(coming.state, AlarmState::Coming);
        assert_eq!(going.cpu_alarm_id, coming.cpu_alarm_id);
        assert_one_int_value(going, 42);
        assert_one_int_value(coming, -7);
        assert_eq!(coming.sequence_counter, going.sequence_counter + 1);
        let at = |a: &Alarm| a.timestamp.to_string();
        assert!(at(going) < at(coming), "{} {}", at(going), at(coming));
    }

    #[test]
    fn huge_precision_in_alarm_text_is_clamped() {
        // The format spec comes from the PLC's alarm text; a precision past u16::MAX made
        // `format!` panic.
        let s = apply_format(&AssociatedValue::Real(1.5), "1.65536f", 64);
        assert!(s.starts_with("1.5"));
        assert_eq!(apply_format(&AssociatedValue::Real(1.5), ".2f", 64), "1.50");
    }
}
