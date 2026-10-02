// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors

//! Interpretation of the S7 date/time datatypes (DTL, DATE, TIME_OF_DAY, TIME, LDT, …) that
//! ride on top of the generic [`PValue`] scalars.
//!
//! The wire/value layer only knows a `Date` is a `UInt` and a `DTL` is a struct — the *meaning*
//! comes from the symbol's [`softdatatype`](crate::value::datatype::softdatatype). These helpers
//! turn a `(softdatatype, PValue)` pair into a calendar date/time or a duration, and format it.

use core::fmt;

use crate::value::datatype::softdatatype as sdt;
use crate::value::PValue;

const NANOS_PER_SEC: i64 = 1_000_000_000;
const SECS_PER_DAY: i64 = 86_400;

/// A broken-down calendar date-time (no timezone — S7 clocks are wall-clock/UTC by convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7DateTime {
    /// Calendar year (e.g. 2026).
    pub year: i32,
    /// Month, 1–12.
    pub month: u8,
    /// Day of month, 1–31.
    pub day: u8,
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–59.
    pub second: u8,
    /// Nanoseconds within the second, 0–999_999_999.
    pub nanosecond: u32,
}

impl fmt::Display for S7DateTime {
    /// ISO-8601-ish: `YYYY-MM-DD HH:MM:SS` plus `.fractional` when sub-second precision exists.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )?;
        if self.nanosecond != 0 {
            // Trim trailing zeros of the 9-digit fraction for readability.
            let mut frac = format!("{:09}", self.nanosecond);
            while frac.ends_with('0') {
                frac.pop();
            }
            write!(f, ".{frac}")?;
        }
        Ok(())
    }
}

/// A signed duration, as used by IEC `TIME`/`LTIME`. Renders like `T#1d2h3m4s500ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7Duration {
    /// Signed duration in nanoseconds.
    pub nanos: i64,
}

impl fmt::Display for S7Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let neg = self.nanos < 0;
        let mut n = self.nanos.unsigned_abs();
        let ns = (n % NANOS_PER_SEC as u64) as u32;
        n /= NANOS_PER_SEC as u64;
        let (secs, mins, hours) = (n % 60, (n / 60) % 60, (n / 3600) % 24);
        let days = n / SECS_PER_DAY as u64;
        write!(f, "T#")?;
        if neg {
            write!(f, "-")?;
        }
        if days != 0 {
            write!(f, "{days}d")?;
        }
        if hours != 0 {
            write!(f, "{hours}h")?;
        }
        if mins != 0 {
            write!(f, "{mins}m")?;
        }
        write!(f, "{secs}s")?;
        if ns != 0 {
            // Prefer ms/us/ns granularity depending on precision.
            if ns % 1_000_000 == 0 {
                write!(f, "{}ms", ns / 1_000_000)?;
            } else {
                write!(f, "{ns}ns")?;
            }
        }
        Ok(())
    }
}

/// A time of day (since midnight), used by `TIME_OF_DAY`/`LTOD`. Renders `HH:MM:SS[.fraction]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7TimeOfDay {
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–59.
    pub second: u8,
    /// Nanoseconds within the second, 0–999_999_999.
    pub nanosecond: u32,
}

impl fmt::Display for S7TimeOfDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}:{:02}", self.hour, self.minute, self.second)?;
        if self.nanosecond != 0 {
            let mut frac = format!("{:09}", self.nanosecond);
            while frac.ends_with('0') {
                frac.pop();
            }
            write!(f, ".{frac}")?;
        }
        Ok(())
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: (year, month, day) from days since 1970-01-01.
fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    (y as i32, m as u8, d as u8)
}

fn hms_from_day_nanos(mut ns: i64) -> (u8, u8, u8, u32) {
    let sub = ns.rem_euclid(NANOS_PER_SEC) as u32;
    ns = ns.div_euclid(NANOS_PER_SEC);
    let secs = ns.rem_euclid(SECS_PER_DAY);
    (
        (secs / 3600) as u8,
        ((secs % 3600) / 60) as u8,
        (secs % 60) as u8,
        sub,
    )
}

impl S7DateTime {
    /// From nanoseconds since the Unix epoch (1970-01-01) — the `LDT` / wire `Timestamp` form.
    pub fn from_unix_nanos(ns: i64) -> S7DateTime {
        let days = ns.div_euclid(NANOS_PER_SEC * SECS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let (hour, minute, second, nanosecond) =
            hms_from_day_nanos(ns.rem_euclid(NANOS_PER_SEC * SECS_PER_DAY));
        S7DateTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        }
    }

    /// From an S7 `DATE` value: days since 1990-01-01 (time set to midnight).
    pub fn from_date_days(days: u16) -> S7DateTime {
        let epoch = days_from_civil(1990, 1, 1);
        let (year, month, day) = civil_from_days(epoch + i64::from(days));
        S7DateTime {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
            nanosecond: 0,
        }
    }

    /// Decode a `DTL` value. Accepts either the struct form (≥8 ordered members: YEAR, MONTH,
    /// DAY, WEEKDAY, HOUR, MINUTE, SECOND, NANOSECOND) or the packed 12-byte big-endian form
    /// (`PackedStruct`/`Blob`/`USIntArray` payload).
    pub fn from_dtl(v: &PValue) -> Option<S7DateTime> {
        match v {
            PValue::Struct { elements, .. } if elements.len() >= 8 => {
                let g = |i: usize| elements[i].1.as_u64();
                Some(S7DateTime {
                    year: g(0)? as i32,
                    month: g(1)? as u8,
                    day: g(2)? as u8,
                    // elements[3] = weekday (ignored)
                    hour: g(4)? as u8,
                    minute: g(5)? as u8,
                    second: g(6)? as u8,
                    nanosecond: g(7)? as u32,
                })
            }
            _ => {
                let b = v.as_bytes()?;
                if b.len() < 12 {
                    return None;
                }
                Some(S7DateTime {
                    year: i32::from(u16::from_be_bytes([b[0], b[1]])),
                    month: b[2],
                    day: b[3],
                    // b[4] = weekday (ignored)
                    hour: b[5],
                    minute: b[6],
                    second: b[7],
                    nanosecond: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
                })
            }
        }
    }

    /// Decode a `DATE_AND_TIME` (DT): 8 BCD bytes (year, month, day, hour, min, sec, then 3
    /// millisecond digits + weekday nibble). Two-digit year: 90–99 ⇒ 1990s, else 2000s.
    pub fn from_date_and_time(b: &[u8]) -> Option<S7DateTime> {
        if b.len() < 8 {
            return None;
        }
        let bcd = |x: u8| -> Option<u32> {
            let (hi, lo) = (x >> 4, x & 0x0f);
            if hi > 9 || lo > 9 {
                None
            } else {
                Some(u32::from(hi) * 10 + u32::from(lo))
            }
        };
        let yy = bcd(b[0])?;
        let year = if yy >= 90 { 1900 + yy } else { 2000 + yy } as i32;
        let millis = bcd(b[6])? * 10 + u32::from(b[7] >> 4);
        Some(S7DateTime {
            year,
            month: bcd(b[1])? as u8,
            day: bcd(b[2])? as u8,
            hour: bcd(b[3])? as u8,
            minute: bcd(b[4])? as u8,
            second: bcd(b[5])? as u8,
            nanosecond: millis * 1_000_000,
        })
    }
}

impl S7Duration {
    /// Decode an `S5TIME` word: a 3-digit BCD count in bits 0–11 and a time base in bits 12–13
    /// (0 = 10 ms, 1 = 100 ms, 2 = 1 s, 3 = 10 s). `None` if the count is not valid BCD.
    pub fn from_s5time(w: u16) -> Option<S7Duration> {
        let mut count = 0i64;
        for shift in [8, 4, 0] {
            let digit = (w >> shift) & 0x0f;
            if digit > 9 {
                return None;
            }
            count = count * 10 + i64::from(digit);
        }
        let base_ms = [10, 100, 1_000, 10_000][usize::from((w >> 12) & 0x3)];
        Some(S7Duration {
            nanos: count * base_ms * 1_000_000,
        })
    }
}

impl S7TimeOfDay {
    fn from_day_nanos(ns: i64) -> S7TimeOfDay {
        let (hour, minute, second, nanosecond) =
            hms_from_day_nanos(ns.rem_euclid(NANOS_PER_SEC * SECS_PER_DAY));
        S7TimeOfDay {
            hour,
            minute,
            second,
            nanosecond,
        }
    }
}

/// Render a `(softdatatype, value)` pair as a human-readable date/time/duration string, or
/// `None` if `softdatatype` is not a date/time type (the caller should format the raw value).
pub fn format(softdatatype: u8, v: &PValue) -> Option<String> {
    match softdatatype {
        sdt::DATE => Some(S7DateTime::from_date_days(v.as_u64()? as u16).to_string()),
        // Both the softdatatype and the value come from the PLC, so a 64-bit value can arrive where a
        // 32-bit one is expected: overflow means "not a valid time", not a panic.
        sdt::TIME_OF_DAY => Some(
            S7TimeOfDay::from_day_nanos(i64::try_from(v.as_u64()?).ok()?.checked_mul(1_000_000)?)
                .to_string(),
        ),
        sdt::LTOD => Some(S7TimeOfDay::from_day_nanos(v.as_i64()?).to_string()),
        sdt::TIME => Some(
            S7Duration {
                nanos: v.as_i64()?.checked_mul(1_000_000)?,
            }
            .to_string(),
        ),
        sdt::LTIME => Some(S7Duration { nanos: v.as_i64()? }.to_string()),
        sdt::S5TIME => S7Duration::from_s5time(v.as_u64()? as u16).map(|d| d.to_string()),
        sdt::LDT => Some(S7DateTime::from_unix_nanos(v.as_i64()?).to_string()),
        sdt::DTL => S7DateTime::from_dtl(v).map(|d| d.to_string()),
        sdt::DATE_AND_TIME => S7DateTime::from_date_and_time(v.as_bytes()?).map(|d| d.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip_and_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(days_from_civil(2000, 2, 29)), (2000, 2, 29));
        assert_eq!(
            civil_from_days(days_from_civil(2024, 12, 31)),
            (2024, 12, 31)
        );
    }

    #[test]
    fn date_days_since_1990() {
        // DATE#1990-01-01 == 0.
        assert_eq!(
            S7DateTime::from_date_days(0).to_string(),
            "1990-01-01 00:00:00"
        );
        // 1990 is not a leap year, so day 365 == 1991-01-01.
        assert_eq!(
            S7DateTime::from_date_days(365).to_string(),
            "1991-01-01 00:00:00"
        );
    }

    #[test]
    fn ldt_unix_nanos() {
        // 2022-01-24 06:38:33.302251251 UTC — the compile time seen in the real IdentES blob era.
        let dt = S7DateTime::from_unix_nanos(1_643_006_313_302_251_251);
        assert_eq!(dt.year, 2022);
        assert_eq!(dt.month, 1);
        assert_eq!((dt.hour, dt.minute, dt.second), (6, 38, 33));
        assert_eq!(dt.nanosecond, 302_251_251);
    }

    #[test]
    fn dtl_from_struct() {
        let v = PValue::Struct {
            id: 0,
            elements: vec![
                (1, PValue::UInt(2024)),
                (2, PValue::USInt(3)),
                (3, PValue::USInt(15)),
                (4, PValue::USInt(6)), // weekday
                (5, PValue::USInt(13)),
                (6, PValue::USInt(45)),
                (7, PValue::USInt(30)),
                (8, PValue::UDInt(500_000_000)),
            ],
        };
        assert_eq!(format(sdt::DTL, &v).unwrap(), "2024-03-15 13:45:30.5");
    }

    #[test]
    fn dtl_from_packed_bytes() {
        // 12-byte big-endian DTL: 2024-03-15 13:45:30.0
        let bytes = vec![
            0x07, 0xE8, // year 2024
            0x03, 0x0F, // month 3, day 15
            0x06, // weekday
            0x0D, 0x2D, 0x1E, // 13:45:30
            0x00, 0x00, 0x00, 0x00, // 0 ns
        ];
        let v = PValue::Blob {
            root_id: 0,
            data: bytes,
        };
        assert_eq!(format(sdt::DTL, &v).unwrap(), "2024-03-15 13:45:30");
    }

    #[test]
    fn time_and_tod() {
        // TIME = -4386ms → -4s386ms.
        assert_eq!(
            format(sdt::TIME, &PValue::DInt(-4386)).unwrap(),
            "T#-4s386ms"
        );
        // TIME_OF_DAY = 45_930_500 ms → 12:45:30.5
        assert_eq!(
            format(sdt::TIME_OF_DAY, &PValue::UDInt(45_930_500)).unwrap(),
            "12:45:30.5"
        );
    }

    #[test]
    fn s5time() {
        // 0x0200: BCD 200, base 10 ms → 2 s (the value seen on the PLCSIM rig).
        assert_eq!(format(sdt::S5TIME, &PValue::Word(0x0200)).unwrap(), "T#2s");
        // 0x2123: BCD 123, base 1 s → 2m3s; 0x3999: 999 × 10 s, the S5TIME maximum.
        assert_eq!(
            format(sdt::S5TIME, &PValue::Word(0x2123)).unwrap(),
            "T#2m3s"
        );
        assert_eq!(
            format(sdt::S5TIME, &PValue::Word(0x3999)).unwrap(),
            "T#2h46m30s"
        );
        // 0x0015: 15 × 10 ms.
        assert_eq!(
            format(sdt::S5TIME, &PValue::Word(0x0015)).unwrap(),
            "T#0s150ms"
        );
        // Not BCD.
        assert!(format(sdt::S5TIME, &PValue::Word(0x00a0)).is_none());
    }

    #[test]
    fn non_datetime_returns_none() {
        assert!(format(sdt::DINT, &PValue::DInt(5)).is_none());
    }

    #[test]
    fn accessors() {
        assert_eq!(PValue::DInt(-7).as_i64(), Some(-7));
        assert_eq!(PValue::UDInt(9).as_u64(), Some(9));
        assert_eq!(PValue::Real(1.5).as_f64(), Some(1.5));
        assert_eq!(PValue::Bool(true).as_bool(), Some(true));
        assert_eq!(PValue::USInt(0).as_bool(), Some(false));
        assert_eq!(PValue::WString("hi".into()).as_str(), Some("hi"));
        assert_eq!(PValue::ULInt(u64::MAX).as_i64(), None); // doesn't fit i64
        assert_eq!(PValue::ULInt(u64::MAX).as_u64(), Some(u64::MAX));
    }
}
