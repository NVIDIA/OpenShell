// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Time utilities shared across `OpenShell` crates.

use prost_types::{Duration as ProtoDuration, Timestamp};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Earliest second accepted by `google.protobuf.Timestamp` (0001-01-01 UTC).
pub const MIN_TIMESTAMP_SECONDS: i64 = -62_135_596_800;
/// Latest second accepted by `google.protobuf.Timestamp` (9999-12-31T23:59:59 UTC).
pub const MAX_TIMESTAMP_SECONDS: i64 = 253_402_300_799;
/// Largest absolute seconds component accepted by `google.protobuf.Duration`.
pub const MAX_DURATION_SECONDS: i64 = 315_576_000_000;

/// Error returned when a protobuf well-known time value is not canonical or
/// cannot be represented by the requested Rust type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtoTimeError {
    #[error("timestamp seconds are outside the protobuf range")]
    TimestampOutOfRange,
    #[error("timestamp nanos must be between 0 and 999999999")]
    InvalidTimestampNanos,
    #[error("duration seconds are outside the protobuf range")]
    DurationOutOfRange,
    #[error("duration nanos are outside the protobuf range or have a different sign than seconds")]
    InvalidDurationNanos,
    #[error("negative protobuf duration cannot be represented by std::time::Duration")]
    NegativeDuration,
    #[error("time conversion overflowed the destination type")]
    Overflow,
}

/// Return the current Unix timestamp in milliseconds, saturating to [`i64::MAX`]
/// on overflow.  Returns `0` if the system clock is before the Unix epoch.
///
/// Prefer this over local implementations of the same pattern.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Validate a protobuf timestamp's range and canonical nanosecond component.
pub fn validate_timestamp(value: &Timestamp) -> Result<(), ProtoTimeError> {
    if !(MIN_TIMESTAMP_SECONDS..=MAX_TIMESTAMP_SECONDS).contains(&value.seconds) {
        return Err(ProtoTimeError::TimestampOutOfRange);
    }
    if !(0..1_000_000_000).contains(&value.nanos) {
        return Err(ProtoTimeError::InvalidTimestampNanos);
    }
    Ok(())
}

/// Convert Unix epoch milliseconds to a canonical protobuf timestamp.
pub fn timestamp_from_millis(value: i64) -> Result<Timestamp, ProtoTimeError> {
    let timestamp = Timestamp {
        seconds: value.div_euclid(1_000),
        nanos: i32::try_from(value.rem_euclid(1_000) * 1_000_000)
            .map_err(|_| ProtoTimeError::Overflow)?,
    };
    validate_timestamp(&timestamp)?;
    Ok(timestamp)
}

/// Convert a legacy timestamp where zero meant "unset" to WKT presence.
pub fn optional_timestamp_from_legacy_millis(
    value: i64,
) -> Result<Option<Timestamp>, ProtoTimeError> {
    if value == 0 {
        Ok(None)
    } else {
        timestamp_from_millis(value).map(Some)
    }
}

/// Convert a protobuf timestamp to Unix epoch milliseconds.
///
/// Nanoseconds finer than one millisecond are truncated toward the start of the
/// represented second. New protobuf-facing code should retain the `Timestamp`
/// instead of using this compatibility helper.
pub fn timestamp_to_millis(value: &Timestamp) -> Result<i64, ProtoTimeError> {
    validate_timestamp(value)?;
    value
        .seconds
        .checked_mul(1_000)
        .and_then(|seconds| seconds.checked_add(i64::from(value.nanos / 1_000_000)))
        .ok_or(ProtoTimeError::Overflow)
}

/// Convert a Rust system time to a protobuf timestamp without losing nanos.
pub fn timestamp_from_system_time(value: SystemTime) -> Result<Timestamp, ProtoTimeError> {
    let timestamp = match value.duration_since(UNIX_EPOCH) {
        Ok(after_epoch) => Timestamp {
            seconds: i64::try_from(after_epoch.as_secs()).map_err(|_| ProtoTimeError::Overflow)?,
            nanos: i32::try_from(after_epoch.subsec_nanos())
                .map_err(|_| ProtoTimeError::Overflow)?,
        },
        Err(before_epoch) => {
            let duration = before_epoch.duration();
            let seconds =
                i64::try_from(duration.as_secs()).map_err(|_| ProtoTimeError::Overflow)?;
            if duration.subsec_nanos() == 0 {
                Timestamp {
                    seconds: -seconds,
                    nanos: 0,
                }
            } else {
                Timestamp {
                    seconds: seconds
                        .checked_neg()
                        .and_then(|v| v.checked_sub(1))
                        .ok_or(ProtoTimeError::Overflow)?,
                    nanos: i32::try_from(1_000_000_000 - duration.subsec_nanos())
                        .map_err(|_| ProtoTimeError::Overflow)?,
                }
            }
        }
    };
    validate_timestamp(&timestamp)?;
    Ok(timestamp)
}

/// Convert a protobuf timestamp to `SystemTime` without losing nanos.
pub fn system_time_from_timestamp(value: &Timestamp) -> Result<SystemTime, ProtoTimeError> {
    validate_timestamp(value)?;
    let nanos = u32::try_from(value.nanos).map_err(|_| ProtoTimeError::Overflow)?;
    if value.seconds >= 0 {
        let seconds = u64::try_from(value.seconds).map_err(|_| ProtoTimeError::Overflow)?;
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .ok_or(ProtoTimeError::Overflow)
    } else if value.nanos == 0 {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(value.seconds.unsigned_abs()))
            .ok_or(ProtoTimeError::Overflow)
    } else {
        let seconds_before = value
            .seconds
            .unsigned_abs()
            .checked_sub(1)
            .ok_or(ProtoTimeError::Overflow)?;
        UNIX_EPOCH
            .checked_sub(Duration::new(seconds_before, 1_000_000_000 - nanos))
            .ok_or(ProtoTimeError::Overflow)
    }
}

/// Validate a protobuf duration's range and canonical sign relationship.
pub fn validate_duration(value: &ProtoDuration) -> Result<(), ProtoTimeError> {
    if !(-MAX_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&value.seconds) {
        return Err(ProtoTimeError::DurationOutOfRange);
    }
    if !(-999_999_999..=999_999_999).contains(&value.nanos)
        || (value.seconds > 0 && value.nanos < 0)
        || (value.seconds < 0 && value.nanos > 0)
    {
        return Err(ProtoTimeError::InvalidDurationNanos);
    }
    Ok(())
}

/// Convert a nonnegative Rust duration to a protobuf duration.
pub fn duration_from_std(value: Duration) -> Result<ProtoDuration, ProtoTimeError> {
    let duration = ProtoDuration {
        seconds: i64::try_from(value.as_secs()).map_err(|_| ProtoTimeError::Overflow)?,
        nanos: i32::try_from(value.subsec_nanos()).map_err(|_| ProtoTimeError::Overflow)?,
    };
    validate_duration(&duration)?;
    Ok(duration)
}

/// Convert a nonnegative protobuf duration to a Rust duration.
pub fn duration_to_std(value: &ProtoDuration) -> Result<Duration, ProtoTimeError> {
    validate_duration(value)?;
    if value.seconds < 0 || value.nanos < 0 {
        return Err(ProtoTimeError::NegativeDuration);
    }
    let seconds = u64::try_from(value.seconds).map_err(|_| ProtoTimeError::Overflow)?;
    let nanos = u32::try_from(value.nanos).map_err(|_| ProtoTimeError::Overflow)?;
    Ok(Duration::new(seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_zero_timestamp_is_absent() {
        assert_eq!(optional_timestamp_from_legacy_millis(0), Ok(None));
    }

    #[test]
    fn negative_millis_produce_canonical_timestamp() {
        assert_eq!(
            timestamp_from_millis(-1).unwrap(),
            Timestamp {
                seconds: -1,
                nanos: 999_000_000,
            }
        );
    }

    #[test]
    fn system_time_round_trip_preserves_sub_millisecond_precision() {
        let original = UNIX_EPOCH - Duration::new(12, 345_678_901);
        let timestamp = timestamp_from_system_time(original).unwrap();
        assert_eq!(system_time_from_timestamp(&timestamp), Ok(original));
    }

    #[test]
    fn timestamp_validation_rejects_invalid_range_and_nanos() {
        assert_eq!(
            validate_timestamp(&Timestamp {
                seconds: MAX_TIMESTAMP_SECONDS + 1,
                nanos: 0,
            }),
            Err(ProtoTimeError::TimestampOutOfRange)
        );
        assert_eq!(
            validate_timestamp(&Timestamp {
                seconds: 0,
                nanos: -1,
            }),
            Err(ProtoTimeError::InvalidTimestampNanos)
        );
    }

    #[test]
    fn duration_round_trip_preserves_nanos() {
        let original = Duration::new(42, 123_456_789);
        let proto = duration_from_std(original).unwrap();
        assert_eq!(duration_to_std(&proto), Ok(original));
    }

    #[test]
    fn duration_validation_rejects_mixed_signs_and_negative_std_conversion() {
        assert_eq!(
            validate_duration(&ProtoDuration {
                seconds: 1,
                nanos: -1,
            }),
            Err(ProtoTimeError::InvalidDurationNanos)
        );
        assert_eq!(
            duration_to_std(&ProtoDuration {
                seconds: 0,
                nanos: -1,
            }),
            Err(ProtoTimeError::NegativeDuration)
        );
    }
}
