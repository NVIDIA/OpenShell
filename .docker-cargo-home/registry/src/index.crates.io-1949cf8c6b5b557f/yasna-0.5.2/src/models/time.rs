// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// Date and time between 1950-01-01T00:00:00Z and 2049-12-31T23:59:59Z.
/// It cannot express fractional seconds and leap seconds.
/// It doesn't carry timezone information.
///
/// Corresponds to ASN.1 UTCTime type. Often used in conjunction with
/// [`GeneralizedTime`].
///
/// # Features
///
/// This struct is enabled by `time` feature.
///
/// ```toml
/// [dependencies]
/// yasna = { version = "*", features = ["time"] }
/// ```
///
/// # Examples
///
/// ```
/// # fn main() {
/// use yasna::models::UTCTime;
/// let datetime = *UTCTime::parse(b"8201021200Z").unwrap().datetime();
/// assert_eq!(datetime.year(), 1982);
/// assert_eq!(datetime.month() as u8, 1);
/// assert_eq!(datetime.day(), 2);
/// assert_eq!(datetime.hour(), 12);
/// assert_eq!(datetime.minute(), 0);
/// assert_eq!(datetime.second(), 0);
/// assert_eq!(datetime.nanosecond(), 0);
/// # }
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UTCTime {
    datetime: OffsetDateTime,
}

impl UTCTime {
    /// Parses ASN.1 string representation of UTCTime.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::UTCTime;
    /// let datetime = UTCTime::parse(b"000229123456Z").unwrap();
    /// assert_eq!(&datetime.to_string(), "000229123456Z");
    /// ```
    ///
    /// # Errors
    ///
    /// It returns `None` if the given string does not specify a correct
    /// datetime.
    ///
    /// # Interpretation
    ///
    /// While neither X.680 nor X.690 specify interpretation of 2-digits year,
    /// X.501 specifies that UTCTime in Time shall be interpreted as between
    /// 1950 and 2049. This method parses the string according to the X.501
    /// rule.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 11 {
            return None;
        }
        // i: a position of [Z+-].
        let i = if [b'+', b'-', b'Z'].contains(&buf[10]) { 10 } else { 12 };
        if buf.len() < i+1 || ![b'+', b'-', b'Z'].contains(&buf[i]) {
            return None;
        }
        let len = if buf[i] == b'Z' { i+1 } else { i+5 };
        if len != buf.len() {
            return None;
        }
        if !buf[..i].iter().all(|&b| b'0' <= b && b <= b'9') ||
            !buf[i+1..].iter().all(|&b| b'0' <= b && b <= b'9')
        {
            return None;
        }
        let year_short: i32 =
            ((buf[0] - b'0') as i32) * 10 + ((buf[1] - b'0') as i32);
        let year = if year_short < 50 {
            year_short + 2000
        } else {
            year_short + 1900
        };
        let month = Month::try_from((buf[2] - b'0') * 10 + (buf[3] - b'0')).ok()?;
        let day = (buf[4] - b'0') * 10 + (buf[5] - b'0');
        let hour = (buf[6] - b'0') * 10 + (buf[7] - b'0');
        let minute = (buf[8] - b'0') * 10 + (buf[9] - b'0');
        let second = if i == 12 {
            (buf[10] - b'0') * 10 + (buf[11] - b'0')
        } else {
            0
        };
        let offset_hour: i8 = if buf[i] == b'Z' {
            0
        } else {
            ((buf[i+1] - b'0') as i8) * 10 + ((buf[i+2] - b'0') as i8)
        };
        let offset_minute: i8 = if buf[i] == b'Z' {
            0
        } else {
            ((buf[i+3] - b'0') as i8) * 10 + ((buf[i+4] - b'0') as i8)
        };
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let time = Time::from_hms(hour, minute, second).ok()?;
        let datetime = PrimitiveDateTime::new(date, time);
        if !(offset_hour < 24 && offset_minute < 60) {
            return None;
        }
        let offset = if buf[i] == b'+' {
            UtcOffset::from_hms(offset_hour, offset_minute, 0).ok()?
        } else {
            UtcOffset::from_hms(-offset_hour, -offset_minute, 0).ok()?
        };
        let datetime = datetime.assume_offset(offset).to_offset(UtcOffset::UTC);
        // While the given local datatime is in [1950, 2050) by definition,
        // the UTC datetime can be out of bounds. We check this.
        if !(1950 <= datetime.year() && datetime.year() < 2050) {
            return None;
        }
        return Some(UTCTime {
            datetime: datetime,
        });
    }

    /// Constructs `UTCTime` from an `OffsetDateTime`.
    ///
    /// # Panics
    ///
    /// Panics when UTCTime can't represent the datetime. That is:
    ///
    /// - The year is not between 1950 and 2049.
    /// - It is in a leap second.
    /// - It has a non-zero nanosecond value.
    pub fn from_datetime(datetime: OffsetDateTime) -> Self {
        let datetime = datetime.to_offset(UtcOffset::UTC);
        assert!(1950 <= datetime.year() && datetime.year() < 2050,
            "Can't express a year {:?} in UTCTime", datetime.year());
        assert!(datetime.nanosecond() < 1_000_000_000,
            "Can't express a leap second in UTCTime");
        assert!(datetime.nanosecond() == 0,
            "Can't express a non-zero nanosecond in UTCTime");
        return UTCTime {
            datetime: datetime,
        };
    }

    /// Constructs `UTCTime` from an `OffsetDateTime`.
    ///
    /// # Errors
    ///
    /// It returns `None` when UTCTime can't represent the datetime. That is:
    ///
    /// - The year is not between 1950 and 2049.
    /// - It is in a leap second.
    /// - It has a non-zero nanosecond value.
    pub fn from_datetime_opt(datetime: OffsetDateTime) -> Option<Self> {
        let datetime = datetime.to_offset(UtcOffset::UTC);
        if !(1950 <= datetime.year() && datetime.year() < 2050) {
            return None;
        }
        if !(datetime.nanosecond() == 0) {
            return None;
        }
        return Some(UTCTime {
            datetime: datetime,
        });
    }

    /// Returns the `OffsetDateTime` it represents.
    pub fn datetime(&self) -> &OffsetDateTime {
        &self.datetime
    }

    /// Returns ASN.1 canonical representation of the datetime as `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13);
        buf.push((self.datetime.year() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.year() % 10) as u8 + b'0');
        buf.push((self.datetime.month() as u8 / 10 % 10) + b'0');
        buf.push((self.datetime.month() as u8 % 10) + b'0');
        buf.push((self.datetime.day() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.day() % 10) as u8 + b'0');
        buf.push((self.datetime.hour() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.hour() % 10) as u8 + b'0');
        buf.push((self.datetime.minute() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.minute() % 10) as u8 + b'0');
        buf.push((self.datetime.second() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.second() % 10) as u8 + b'0');
        buf.push(b'Z');
        return buf;
    }

    /// Returns ASN.1 canonical representation of the datetime as `String`.
    pub fn to_string(&self) -> String {
        String::from_utf8(self.to_bytes()).unwrap()
    }
}

/// Date and time between 0000-01-01T00:00:00Z and 9999-12-31T23:59:60.999...Z.
///
/// It can contain arbitrary length of decimal fractional seconds.
/// However, it doesn't carry accuracy information.
/// It can also contain leap seconds.
///
/// The datetime is canonicalized to UTC.
/// It doesn't carry timezone information.
///
/// Corresponds to ASN.1 GeneralizedTime type. Often used in conjunction with
/// [`UTCTime`].
///
/// # Features
///
/// This struct is enabled by `time` feature.
///
/// ```toml
/// [dependencies]
/// yasna = { version = "*", features = ["time"] }
/// ```
///
/// # Examples
///
/// ```
/// # fn main() {
/// use yasna::models::GeneralizedTime;
/// let datetime =
///     *GeneralizedTime::parse(b"19851106210627.3Z").unwrap().datetime();
/// assert_eq!(datetime.year(), 1985);
/// assert_eq!(datetime.month() as u8, 11);
/// assert_eq!(datetime.day(), 6);
/// assert_eq!(datetime.hour(), 21);
/// assert_eq!(datetime.minute(), 6);
/// assert_eq!(datetime.second(), 27);
/// assert_eq!(datetime.nanosecond(), 300_000_000);
/// # }
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GeneralizedTime {
    datetime: OffsetDateTime,
    sub_nano: Vec<u8>,
    // TODO: time does not support leap seconds. This is a simple hack to support round-tripping.
    is_leap_second: bool,
}

impl GeneralizedTime {
    /// Almost same as `parse`. It takes `default_offset` however.
    /// GeneralizedTime value can omit offset in local time.
    /// In that case, `default_offset` is used instead.
    fn parse_general(buf: &[u8], default_offset: Option<UtcOffset>) -> Option<Self> {
        if buf.len() < 10 {
            return None;
        }
        if !buf[..10].iter().all(|&b| b'0' <= b && b <= b'9') {
            return None;
        }
        let year: i32 =
            ((buf[0] - b'0') as i32) * 1000 + ((buf[1] - b'0') as i32) * 100
            + ((buf[2] - b'0') as i32) * 10 + ((buf[3] - b'0') as i32);
        let month = Month::try_from((buf[4] - b'0') * 10 + (buf[5] - b'0')).ok()?;
        let day = (buf[6] - b'0') * 10 + (buf[7] - b'0');
        let hour = (buf[8] - b'0') * 10 + (buf[9] - b'0');
        // i: current position on `buf`
        let mut i = 10;
        // The factor to scale the fraction part to nanoseconds.
        let mut fraction_scale : i64 = 1_000_000_000;
        let mut minute: u8;
        if i+2 <= buf.len() &&
                buf[i..i+2].iter().all(|&b| b'0' <= b && b <= b'9') {
            minute = (buf[i] - b'0') * 10 + (buf[i + 1] - b'0');
            i += 2;
        } else {
            fraction_scale = 3_600_000_000_000;
            minute = 0;
        }
        let mut second: u8;
        if i+2 <= buf.len() &&
                buf[i..i+2].iter().all(|&b| b'0' <= b && b <= b'9') {
            second = (buf[i] - b'0') * 10 + (buf[i + 1] - b'0');
            i += 2;
        } else {
            if fraction_scale == 1_000_000_000 {
                fraction_scale = 60_000_000_000;
            }
            second = 0;
        }
        let mut nanosecond = 0;
        let mut sub_nano = Vec::new();
        if i+2 <= buf.len() && (buf[i] == b'.' || buf[i] == b',')
                && b'0' <= buf[i+1] && buf[i+1] <= b'9' {
            i += 1;
            let mut j = 0;
            while i+j < buf.len() && b'0' <= buf[i+j] && buf[i+j] <= b'9' {
                sub_nano.push(b'0');
                j += 1;
            }
            let mut carry : i64 = 0;
            for k in (0..j).rev() {
                let digit = (buf[i+k] - b'0') as i64;
                let sum = digit * fraction_scale + carry;
                carry = sum / 10;
                sub_nano[k] = b'0' + ((sum % 10) as u8);
            }
            nanosecond = (carry % 1_000_000_000) as u32;
            second += (carry / 1_000_000_000 % 60) as u8;
            minute += (carry / 60_000_000_000) as u8;
            while let Some(&digit) = sub_nano.last() {
                if digit == b'0' {
                    sub_nano.pop();
                } else {
                    break;
                }
            }
            i += j;
        }
        let mut is_leap_second = false;
        if second == 60 {
            // TODO: `time` doesn't accept leap seconds, so we use a flag to preserve
            is_leap_second = true;
            second = 59;
        }
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let time = Time::from_hms_nano(hour, minute, second, nanosecond).ok()?;
        let naive_datetime = PrimitiveDateTime::new(date, time);
        let datetime: OffsetDateTime;
        if i == buf.len() {
            // Local datetime with no timezone information.
            datetime = naive_datetime
                .assume_offset(default_offset?)
                .to_offset(UtcOffset::UTC);
        } else if i < buf.len() && buf[i] == b'Z' {
            // UTC time.
            datetime = naive_datetime.assume_utc();
            i += 1;
        } else if i < buf.len() && (buf[i] == b'+' || buf[i] == b'-') {
            // Local datetime with offset information.
            let offset_sign = buf[i];
            i += 1;
            if !(i+2 <= buf.len() &&
                    buf[i..i+2].iter().all(|&b| b'0' <= b && b <= b'9')) {
                return None;
            }
            let offset_hour =
                ((buf[i] - b'0') as i8) * 10 + ((buf[i+1] - b'0') as i8);
            i += 2;
            let offset_minute;
            if i+2 <= buf.len() &&
                    buf[i..i+2].iter().all(|&b| b'0' <= b && b <= b'9') {
                offset_minute =
                    ((buf[i] - b'0') as i8) * 10 + ((buf[i+1] - b'0') as i8);
                i += 2;
            } else {
                offset_minute = 0;
            }
            if !(offset_hour < 24 && offset_minute < 60) {
                return None;
            }
            let offset = if offset_sign == b'+' {
                UtcOffset::from_hms(offset_hour, offset_minute, 0)
            } else {
                UtcOffset::from_hms(-offset_hour, -offset_minute, 0)
            };
            datetime = naive_datetime
                .assume_offset(offset.ok()?)
                .to_offset(UtcOffset::UTC);
        } else {
            return None;
        }
        if i != buf.len() {
            return None;
        }
        // While the given local datatime is in [0, 10000) by definition,
        // the UTC datetime can be out of bounds. We check this.
        if !(0 <= datetime.year() && datetime.year() < 10000) {
            return None;
        }
        return Some(GeneralizedTime {
            datetime: datetime,
            sub_nano: sub_nano,
            is_leap_second,
        });
    }

    /// Parses ASN.1 string representation of GeneralizedTime.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::GeneralizedTime;
    /// let datetime = GeneralizedTime::parse(b"1985110621.14159Z").unwrap();
    /// assert_eq!(&datetime.to_string(), "19851106210829.724Z");
    /// ```
    ///
    /// # Errors
    ///
    /// It returns `None` if the given string does not specify a correct
    /// datetime.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        Self::parse_general(buf, None)
    }

    /// Parses ASN.1 string representation of GeneralizedTime, with the
    /// default timezone for local time given.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::GeneralizedTime;
    /// let datetime = GeneralizedTime::parse(b"1985110621.14159Z").unwrap();
    /// assert_eq!(&datetime.to_string(), "19851106210829.724Z");
    /// ```
    ///
    /// # Errors
    ///
    /// It returns `None` if the given string does not specify a correct
    /// datetime.
    pub fn parse_with_offset(buf: &[u8], default_offset: UtcOffset) -> Option<Self> {
        Self::parse_general(buf, Some(default_offset))
    }

    /// Constructs `GeneralizedTime` from an `OffsetDateTime`.
    ///
    /// # Panics
    ///
    /// Panics when GeneralizedTime can't represent the datetime. That is:
    ///
    /// - The year is not between 0 and 9999.
    pub fn from_datetime(datetime: OffsetDateTime) -> Self {
        let datetime = datetime.to_offset(UtcOffset::UTC);
        assert!(0 <= datetime.year() && datetime.year() < 10000,
            "Can't express a year {:?} in GeneralizedTime", datetime.year());
        return GeneralizedTime {
            datetime: datetime,
            sub_nano: Vec::new(),
            is_leap_second: false,
        };
    }

    /// Constructs `GeneralizedTime` from an `OffsetDateTime`.
    ///
    /// # Errors
    ///
    /// It returns `None` when GeneralizedTime can't represent the datetime.
    /// That is:
    ///
    /// - The year is not between 0 and 9999.
    pub fn from_datetime_opt(datetime: OffsetDateTime) -> Option<Self> {
        let datetime = datetime.to_offset(UtcOffset::UTC);
        if !(0 <= datetime.year() && datetime.year() < 10000) {
            return None;
        }
        return Some(GeneralizedTime {
            datetime: datetime,
            sub_nano: Vec::new(),
            is_leap_second: false,
        });
    }

    /// Constructs `GeneralizedTime` from an `OffsetDateTime` and sub-nanoseconds
    /// digits.
    ///
    /// # Panics
    ///
    /// Panics when GeneralizedTime can't represent the datetime. That is:
    ///
    /// - The year is not between 0 and 9999.
    ///
    /// It also panics if `sub_nano` contains a non-digit character.
    pub fn from_datetime_and_sub_nano(datetime: OffsetDateTime, sub_nano: &[u8]) -> Self {
        let datetime = datetime.to_offset(UtcOffset::UTC);
        assert!(0 <= datetime.year() && datetime.year() < 10000,
            "Can't express a year {:?} in GeneralizedTime", datetime.year());
        assert!(sub_nano.iter().all(|&b| b'0' <= b && b <= b'9'),
            "sub_nano contains a non-digit character");
        let mut sub_nano = sub_nano.to_vec();
        while sub_nano.len() > 0 && *sub_nano.last().unwrap() == b'0' {
            sub_nano.pop();
        }
        return GeneralizedTime {
            datetime: datetime,
            sub_nano: sub_nano,
            is_leap_second: false,
        };
    }

    /// Constructs `GeneralizedTime` from an `OffsetDateTime` and sub-nanoseconds
    /// digits.
    ///
    /// # Errors
    ///
    /// It returns `None` when GeneralizedTime can't represent the datetime.
    /// That is:
    ///
    /// - The year is not between 0 and 9999.
    ///
    /// It also returns `None` if `sub_nano` contains a non-digit character.
    pub fn from_datetime_and_sub_nano_opt(
        datetime: OffsetDateTime,
        sub_nano: &[u8],
    ) -> Option<Self> {
        let datetime = datetime.to_offset(UtcOffset::UTC);
        if !(0 <= datetime.year() && datetime.year() < 10000) {
            return None;
        }
        if !(sub_nano.iter().all(|&b| b'0' <= b && b <= b'9')) {
            return None;
        }
        let mut sub_nano = sub_nano.to_vec();
        while sub_nano.len() > 0 && *sub_nano.last().unwrap() == b'0' {
            sub_nano.pop();
        }
        return Some(GeneralizedTime {
            datetime: datetime,
            sub_nano: sub_nano,
            is_leap_second: false,
        });
    }

    /// Returns the `OffsetDateTime` it represents.
    ///
    /// Leap seconds and sub-nanoseconds digits will be discarded.
    pub fn datetime(&self) -> &OffsetDateTime {
        &self.datetime
    }

    /// Returns sub-nanoseconds digits of the datetime.
    pub fn sub_nano(&self) -> &[u8] {
        &self.sub_nano
    }

    /// Returns ASN.1 canonical representation of the datetime as `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.push((self.datetime.year() / 1000 % 10) as u8 + b'0');
        buf.push((self.datetime.year() / 100 % 10) as u8 + b'0');
        buf.push((self.datetime.year() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.year() % 10) as u8 + b'0');
        buf.push((self.datetime.month() as u8 / 10 % 10) + b'0');
        buf.push((self.datetime.month() as u8 % 10) + b'0');
        buf.push((self.datetime.day() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.day() % 10) as u8 + b'0');
        buf.push((self.datetime.hour() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.hour() % 10) as u8 + b'0');
        buf.push((self.datetime.minute() / 10 % 10) as u8 + b'0');
        buf.push((self.datetime.minute() % 10) as u8 + b'0');
        let mut second = self.datetime.second();
        let nanosecond = self.datetime.nanosecond();
        // Cope with leap seconds.
        if self.is_leap_second {
            debug_assert!(second == 59,
                "is_leap_second is set, but second = {}", second);
            second += 1;
        }
        buf.push((second / 10 % 10) as u8 + b'0');
        buf.push((second % 10) as u8 + b'0');
        buf.push(b'.');
        buf.push((nanosecond / 100_000_000 % 10) as u8 + b'0');
        buf.push((nanosecond / 10_000_000 % 10) as u8 + b'0');
        buf.push((nanosecond / 1_000_000 % 10) as u8 + b'0');
        buf.push((nanosecond / 100_000 % 10) as u8 + b'0');
        buf.push((nanosecond / 10_000 % 10) as u8 + b'0');
        buf.push((nanosecond / 1_000 % 10) as u8 + b'0');
        buf.push((nanosecond / 100 % 10) as u8 + b'0');
        buf.push((nanosecond / 10 % 10) as u8 + b'0');
        buf.push((nanosecond % 10) as u8 + b'0');
        buf.extend_from_slice(&self.sub_nano);
        // Truncates trailing zeros.
        while buf.len() > 14 && {
                let b = *buf.last().unwrap(); b == b'0' || b == b'.' } {
            buf.pop();
        }
        buf.push(b'Z');
        return buf;
    }

    /// Returns ASN.1 canonical representation of the datetime as `String`.
    pub fn to_string(&self) -> String {
        String::from_utf8(self.to_bytes()).unwrap()
    }
}

#[test]
fn test_utctime_parse() {
    let datetime = *UTCTime::parse(b"8201021200Z").unwrap().datetime();
    assert_eq!(datetime.year(), 1982);
    assert_eq!(datetime.month() as u8, 1);
    assert_eq!(datetime.day(), 2);
    assert_eq!(datetime.hour(), 12);
    assert_eq!(datetime.minute(), 0);
    assert_eq!(datetime.second(), 0);
    assert_eq!(datetime.nanosecond(), 0);

    let datetime = *UTCTime::parse(b"0101021200Z").unwrap().datetime();
    assert_eq!(datetime.year(), 2001);
    assert_eq!(datetime.month() as u8, 1);
    assert_eq!(datetime.day(), 2);
    assert_eq!(datetime.hour(), 12);
    assert_eq!(datetime.minute(), 0);
    assert_eq!(datetime.second(), 0);
    assert_eq!(datetime.nanosecond(), 0);

    let datetime = UTCTime::parse(b"8201021200Z").unwrap();
    assert_eq!(&datetime.to_string(), "820102120000Z");

    let datetime = UTCTime::parse(b"8201020700-0500").unwrap();
    assert_eq!(&datetime.to_string(), "820102120000Z");

    let datetime = UTCTime::parse(b"0101021200Z").unwrap();
    assert_eq!(&datetime.to_string(), "010102120000Z");

    let datetime = UTCTime::parse(b"010102120034Z").unwrap();
    assert_eq!(&datetime.to_string(), "010102120034Z");

    let datetime = UTCTime::parse(b"000229123456Z").unwrap();
    assert_eq!(&datetime.to_string(), "000229123456Z");
}

#[test]
fn test_generalized_time_parse() {
    let datetime =
        *GeneralizedTime::parse(b"19851106210627.3Z").unwrap().datetime();
    assert_eq!(datetime.year(), 1985);
    assert_eq!(datetime.month() as u8, 11);
    assert_eq!(datetime.day(), 6);
    assert_eq!(datetime.hour(), 21);
    assert_eq!(datetime.minute(), 6);
    assert_eq!(datetime.second(), 27);
    assert_eq!(datetime.nanosecond(), 300_000_000);

    let datetime = GeneralizedTime::parse(b"19851106210627.3-0500").unwrap();
    assert_eq!(&datetime.to_string(), "19851107020627.3Z");

    let datetime = GeneralizedTime::parse(b"198511062106Z").unwrap();
    assert_eq!(&datetime.to_string(), "19851106210600Z");

    let datetime = GeneralizedTime::parse(b"198511062106.456Z").unwrap();
    assert_eq!(&datetime.to_string(), "19851106210627.36Z");

    let datetime = GeneralizedTime::parse(b"1985110621Z").unwrap();
    assert_eq!(&datetime.to_string(), "19851106210000Z");

    let datetime = GeneralizedTime::parse(b"1985110621.14159Z").unwrap();
    assert_eq!(&datetime.to_string(), "19851106210829.724Z");

    let datetime =
        GeneralizedTime::parse(b"19990101085960.1234+0900").unwrap();
    assert_eq!(&datetime.to_string(), "19981231235960.1234Z");

    let datetime =
        GeneralizedTime::parse(
            b"20080229033411.3625431984612391672391625532918636000680000-0500"
        ).unwrap();
    assert_eq!(&datetime.to_string(),
        "20080229083411.362543198461239167239162553291863600068Z");
}
