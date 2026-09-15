// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standard gRPC error details shared by gateway handlers and SDK clients.
//!
//! Retry guidance describes recovery from a failure. It never establishes that
//! repeating an arbitrary mutation is safe.

use std::collections::HashMap;
use std::time::Duration;

use prost::Message;
use tonic::{Code, Status};
pub use tonic_types::{ErrorDetails, StatusExt};

/// Domain of gateway-owned machine-readable error reasons.
pub const ERROR_DOMAIN: &str = "openshell.nvidia.com";

/// Decode supported details without trusting inconsistent envelopes or delays.
/// Unknown and malformed details remain available on the original status.
pub fn decode_details(status: &Status) -> Option<ErrorDetails> {
    let envelope = tonic_types::pb::Status::decode(status.details()).ok()?;
    if envelope.code != status.code() as i32 || envelope.message != status.message() {
        return None;
    }
    let mut details = ErrorDetails::new();
    for detail in envelope.details {
        match detail.type_url.rsplit('/').next() {
            Some("google.rpc.BadRequest") => {
                if let Ok(value) = tonic_types::pb::BadRequest::decode(detail.value.as_slice()) {
                    for violation in value.field_violations {
                        details.add_bad_request_violation(violation.field, violation.description);
                    }
                }
            }
            Some("google.rpc.ErrorInfo") => {
                if let Ok(value) = tonic_types::pb::ErrorInfo::decode(detail.value.as_slice()) {
                    details.set_error_info(value.reason, value.domain, value.metadata);
                }
            }
            Some("google.rpc.RetryInfo") => {
                if let Ok(value) = tonic_types::pb::RetryInfo::decode(detail.value.as_slice())
                    && let Some(delay) = value.retry_delay
                    && (0..=315_576_000_000).contains(&delay.seconds)
                    && (0..1_000_000_000).contains(&delay.nanos)
                {
                    details.set_retry_info(Some(Duration::new(
                        delay.seconds.cast_unsigned(),
                        delay.nanos.cast_unsigned(),
                    )));
                }
            }
            _ => {}
        }
    }
    Some(details)
}

/// Return a field-level validation failure without reflecting the field value.
pub fn invalid_argument(field: &str, message: impl Into<String>) -> Status {
    let message = message.into();
    let mut details = ErrorDetails::with_bad_request_violation(field, message.clone());
    details.set_error_info("INVALID_ARGUMENT", ERROR_DOMAIN, HashMap::new());
    Status::with_error_details(Code::InvalidArgument, message, details)
}

/// Return a precondition failure with a stable reason.
pub fn failed_precondition(reason: &str, message: impl Into<String>) -> Status {
    Status::with_error_details(
        Code::FailedPrecondition,
        message,
        ErrorDetails::with_error_info(reason, ERROR_DOMAIN, HashMap::new()),
    )
}

/// A conditional write lost a race. Read fresh state before trying a new write.
pub fn resource_version_conflict(message: impl Into<String>, version: Option<u64>) -> Status {
    let mut metadata = HashMap::from([("recovery".into(), "REFRESH_STATE".into())]);
    if let Some(version) = version {
        metadata.insert("current_resource_version".into(), version.to_string());
    }
    Status::with_error_details(
        Code::Aborted,
        message,
        ErrorDetails::with_error_info("RESOURCE_VERSION_CONFLICT", ERROR_DOMAIN, metadata),
    )
}

/// Return a transient failure with a minimum delay for retry-safe operations.
pub fn unavailable(reason: &str, message: impl Into<String>, delay: Duration) -> Status {
    let mut details = ErrorDetails::with_error_info(reason, ERROR_DOMAIN, HashMap::new());
    details.set_retry_info(Some(delay));
    Status::with_error_details(Code::Unavailable, message, details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ignores_invalid_delay_and_preserves_other_details() {
        let status = invalid_argument("name", "invalid name");
        let mut envelope = tonic_types::pb::Status::decode(status.details()).unwrap();
        envelope.details.push(prost_types::Any {
            type_url: "type.googleapis.com/google.rpc.RetryInfo".into(),
            value: tonic_types::pb::RetryInfo {
                retry_delay: Some(prost_types::Duration {
                    seconds: -1,
                    nanos: 0,
                }),
            }
            .encode_to_vec(),
        });
        envelope.details.push(prost_types::Any {
            type_url: "type.googleapis.com/google.rpc.BadRequest".into(),
            value: vec![255],
        });
        let status = Status::with_details(
            status.code(),
            status.message(),
            envelope.encode_to_vec().into(),
        );
        let details = decode_details(&status).unwrap();
        assert!(details.retry_info().is_none());
        assert_eq!(
            details.bad_request().unwrap().field_violations[0].field,
            "name"
        );
        let mismatched = Status::with_details(
            Code::Internal,
            status.message(),
            status.details().to_vec().into(),
        );
        assert!(decode_details(&mismatched).is_none());
    }

    #[test]
    fn validation_identifies_the_field_and_reason() {
        let status = invalid_argument("spec.command[0]", "must not be empty");
        let details = status.get_error_details();
        assert_eq!(status.code(), Code::InvalidArgument);
        let violation = &details.bad_request().unwrap().field_violations[0];
        assert_eq!(violation.field, "spec.command[0]");
        assert_eq!(violation.description, "must not be empty");
        assert_eq!(details.error_info().unwrap().domain, ERROR_DOMAIN);
        assert!(details.retry_info().is_none());
    }

    #[test]
    fn conflict_requires_fresh_state_without_blind_retry_delay() {
        let status = resource_version_conflict("concurrent write", Some(17));
        let details = status.get_error_details();
        let info = details.error_info().unwrap();
        assert_eq!(status.code(), Code::Aborted);
        assert_eq!(info.reason, "RESOURCE_VERSION_CONFLICT");
        assert_eq!(info.metadata["recovery"], "REFRESH_STATE");
        assert_eq!(info.metadata["current_resource_version"], "17");
        assert!(details.retry_info().is_none());
    }

    #[test]
    fn temporary_unavailability_has_a_reason_and_delay() {
        let status = unavailable("GATEWAY_NOT_READY", "try later", Duration::from_secs(1));
        let details = status.get_error_details();
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(details.error_info().unwrap().reason, "GATEWAY_NOT_READY");
        assert_eq!(
            details.retry_info().unwrap().retry_delay,
            Some(Duration::from_secs(1))
        );
    }
}
