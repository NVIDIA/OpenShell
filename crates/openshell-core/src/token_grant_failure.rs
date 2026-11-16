// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential-free failures shared by dynamic token grants and their RPC boundary.
//!
//! Printable errors contain only a fixed message. Trusted in-process consumers
//! can inspect allowlisted classifications without retaining upstream diagnostics.

use std::collections::HashMap;
use std::fmt;

use prost::Message;
use tonic::{Code, Status};

use crate::proto::ProviderCredentialRefreshRecoveryAction;
use crate::rpc_error::{ERROR_DOMAIN, ErrorDetails, StatusExt};

/// Header that carries the supervisor-minted request ID of an HTTP exchange.
///
/// The supervisor sends it to token services and returns it on a refused
/// request, so every party can name the same exchange. The value is an opaque
/// random ID and grants nothing.
pub const REQUEST_ID_HEADER: &str = "x-openshell-request-id";

const FAILURE_MESSAGE: &str = "dynamic token grant failed";
const FAILURE_REASON: &str = "TOKEN_GRANT_FAILURE";
const MAX_DETAILS_BYTES: usize = 1024;

/// An allowlisted cause of a dynamic token-grant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenGrantFailureKind {
    /// The authenticated token service requires provider authorization.
    ProviderAuthorizationRequired,
    /// An authenticated component rejected the workload identity.
    WorkloadIdentityRejected,
    /// Local configuration or an authenticated configuration contract is invalid.
    Configuration,
    /// A grant operation exceeded its time limit.
    Timeout,
    /// A required service or connection is unavailable.
    Unavailable,
    /// Available evidence does not establish a more specific cause.
    Unclassified,
}

impl TokenGrantFailureKind {
    pub(crate) const ALL: [Self; 6] = [
        Self::ProviderAuthorizationRequired,
        Self::WorkloadIdentityRejected,
        Self::Configuration,
        Self::Timeout,
        Self::Unavailable,
        Self::Unclassified,
    ];

    const fn code(self) -> &'static str {
        match self {
            Self::ProviderAuthorizationRequired => "provider_authorization_required",
            Self::WorkloadIdentityRejected => "workload_identity_rejected",
            Self::Configuration => "configuration_error",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Unclassified => "unclassified",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }

    pub(crate) const fn recovery(self) -> ProviderCredentialRefreshRecoveryAction {
        match self {
            Self::ProviderAuthorizationRequired => {
                ProviderCredentialRefreshRecoveryAction::Reauthorize
            }
            Self::WorkloadIdentityRejected | Self::Configuration => {
                ProviderCredentialRefreshRecoveryAction::FixConfiguration
            }
            Self::Timeout | Self::Unavailable => ProviderCredentialRefreshRecoveryAction::Retry,
            Self::Unclassified => ProviderCredentialRefreshRecoveryAction::Investigate,
        }
    }

    const fn status_code(self) -> Code {
        match self {
            Self::ProviderAuthorizationRequired | Self::Configuration => Code::FailedPrecondition,
            Self::WorkloadIdentityRejected => Code::PermissionDenied,
            Self::Timeout => Code::DeadlineExceeded,
            Self::Unavailable => Code::Unavailable,
            Self::Unclassified => Code::Unknown,
        }
    }
}

/// The trusted local operation that observed a token-grant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenGrantStage {
    /// Validating the grant configuration.
    Configuration,
    /// Acquiring or validating workload identity.
    WorkloadIdentity,
    /// Calling the authenticated gateway RPC.
    GatewayRpc,
    /// Exchanging the workload identity for an intermediate token.
    IntermediateExchange,
    /// Calling the final token endpoint.
    TokenEndpoint,
    /// Preparing or injecting the token into the protected request.
    Injection,
}

impl TokenGrantStage {
    pub(crate) const ALL: [Self; 6] = [
        Self::Configuration,
        Self::WorkloadIdentity,
        Self::GatewayRpc,
        Self::IntermediateExchange,
        Self::TokenEndpoint,
        Self::Injection,
    ];

    /// Return the stable stage code for trusted local consumers.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::WorkloadIdentity => "workload_identity",
            Self::GatewayRpc => "gateway_rpc",
            Self::IntermediateExchange => "intermediate_exchange",
            Self::TokenEndpoint => "token_endpoint",
            Self::Injection => "injection",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|stage| stage.code() == code)
    }
}

/// A token-grant failure that cannot retain credentials or arbitrary diagnostics.
///
/// Both printable representations are generic, and the error has no source.
/// Structured getters are intended for trusted in-process consumers, not output
/// to a workload or local diagnostic stream.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TokenGrantFailure {
    kind: TokenGrantFailureKind,
    stage: TokenGrantStage,
    upstream_status: Option<u16>,
}

impl TokenGrantFailure {
    /// Construct a failure from a trusted local classification and operation.
    pub const fn new(kind: TokenGrantFailureKind, stage: TokenGrantStage) -> Self {
        Self {
            kind,
            stage,
            upstream_status: None,
        }
    }

    /// Attach an observed HTTP status, discarding values outside 100 through 599.
    #[must_use]
    pub fn with_upstream_status(mut self, status: u16) -> Self {
        self.upstream_status = (100..=599).contains(&status).then_some(status);
        self
    }

    /// Identify the operation that observed the failure without changing its cause.
    #[must_use]
    pub const fn at_stage(mut self, stage: TokenGrantStage) -> Self {
        self.stage = stage;
        self
    }

    /// Return the allowlisted failure classification for trusted local consumers.
    pub const fn kind(&self) -> TokenGrantFailureKind {
        self.kind
    }

    /// Return the operation that observed this failure.
    pub const fn stage(&self) -> TokenGrantStage {
        self.stage
    }

    /// Return an observed valid HTTP status without retaining its response body.
    pub const fn upstream_status(&self) -> Option<u16> {
        self.upstream_status
    }

    /// Return the stable allowlisted failure code for trusted local consumers.
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// Return who can resolve this failure, in the provider refresh vocabulary.
    pub const fn recovery(&self) -> ProviderCredentialRefreshRecoveryAction {
        self.kind.recovery()
    }

    /// Encode this failure with its default gRPC status code and generic message.
    pub fn to_status(self) -> Status {
        self.to_status_with_code(self.kind.status_code())
    }

    /// Encode this failure while preserving a gateway guard's gRPC status code.
    ///
    /// A success code cannot represent a failure and is replaced with `Unknown`.
    pub fn to_status_with_code(self, code: Code) -> Status {
        let code = if code == Code::Ok {
            Code::Unknown
        } else {
            code
        };
        let mut metadata = HashMap::from([
            ("version".to_owned(), "1".to_owned()),
            ("code".to_owned(), self.code().to_owned()),
            ("stage".to_owned(), self.stage.code().to_owned()),
        ]);
        if let Some(status) = self.upstream_status {
            metadata.insert("upstream_http_status".to_owned(), status.to_string());
        }
        Status::with_error_details(
            code,
            FAILURE_MESSAGE,
            ErrorDetails::with_error_info(FAILURE_REASON, ERROR_DOMAIN, metadata),
        )
    }

    /// Decode strictly bounded internal details, discarding all other diagnostics.
    ///
    /// Malformed messages or unknown and inconsistent classifications become an
    /// unclassified gateway RPC failure. This validates the failure contract,
    /// not peer identity: callers must authenticate the gateway before trusting
    /// a precise classification received over the network.
    pub fn from_status(status: &Status) -> Self {
        Self::decode_status(status).unwrap_or_else(|| {
            Self::new(
                TokenGrantFailureKind::Unclassified,
                TokenGrantStage::GatewayRpc,
            )
        })
    }

    fn decode_status(status: &Status) -> Option<Self> {
        if status.details().len() > MAX_DETAILS_BYTES
            || status.message() != FAILURE_MESSAGE
            || status.code() == Code::Ok
        {
            return None;
        }
        let envelope = tonic_types::pb::Status::decode(status.details()).ok()?;
        if envelope.code != status.code() as i32 || envelope.message != FAILURE_MESSAGE {
            return None;
        }
        let [detail] = envelope.details.as_slice() else {
            return None;
        };
        if detail.type_url != tonic_types::ErrorInfo::TYPE_URL {
            return None;
        }
        let info = tonic_types::pb::ErrorInfo::decode(detail.value.as_slice()).ok()?;
        if info.reason != FAILURE_REASON
            || info.domain != ERROR_DOMAIN
            || info.metadata.get("version")?.as_str() != "1"
            || info.metadata.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "version" | "code" | "stage" | "upstream_http_status"
                )
            })
        {
            return None;
        }
        let upstream_status = match info.metadata.get("upstream_http_status") {
            Some(value) => {
                if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                let status = value.parse::<u16>().ok()?;
                if !(100..=599).contains(&status) {
                    return None;
                }
                Some(status)
            }
            None => None,
        };
        Some(Self {
            kind: TokenGrantFailureKind::from_code(info.metadata.get("code")?)?,
            stage: TokenGrantStage::from_code(info.metadata.get("stage")?)?,
            upstream_status,
        })
    }
}

impl fmt::Display for TokenGrantFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(FAILURE_MESSAGE)
    }
}

impl fmt::Debug for TokenGrantFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(FAILURE_MESSAGE)
    }
}

impl std::error::Error for TokenGrantFailure {}

impl miette::Diagnostic for TokenGrantFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TokenGrantFailure {
        TokenGrantFailure::new(
            TokenGrantFailureKind::ProviderAuthorizationRequired,
            TokenGrantStage::IntermediateExchange,
        )
        .with_upstream_status(409)
    }

    fn envelope(status: &Status) -> tonic_types::pb::Status {
        tonic_types::pb::Status::decode(status.details()).unwrap()
    }

    fn replace_envelope(original: &Status, value: &tonic_types::pb::Status) -> Status {
        Status::with_details(
            original.code(),
            original.message(),
            value.encode_to_vec().into(),
        )
    }

    fn mutate_info(mutate: impl FnOnce(&mut tonic_types::pb::ErrorInfo)) -> Status {
        let status = sample().to_status();
        let mut value = envelope(&status);
        let mut info =
            tonic_types::pb::ErrorInfo::decode(value.details[0].value.as_slice()).unwrap();
        mutate(&mut info);
        value.details[0].value = info.encode_to_vec();
        replace_envelope(&status, &value)
    }

    fn assert_rejected(status: &Status) {
        assert_eq!(
            TokenGrantFailure::from_status(status),
            TokenGrantFailure::new(
                TokenGrantFailureKind::Unclassified,
                TokenGrantStage::GatewayRpc
            )
        );
    }

    #[test]
    fn every_kind_maps_to_code_recovery_and_grpc_status() {
        use ProviderCredentialRefreshRecoveryAction as Recovery;
        let table = TokenGrantFailureKind::ALL.map(|kind| {
            let failure = TokenGrantFailure::new(kind, TokenGrantStage::TokenEndpoint);
            (
                failure.code(),
                failure.recovery(),
                failure.to_status().code(),
            )
        });
        assert_eq!(
            table,
            [
                (
                    "provider_authorization_required",
                    Recovery::Reauthorize,
                    Code::FailedPrecondition
                ),
                (
                    "workload_identity_rejected",
                    Recovery::FixConfiguration,
                    Code::PermissionDenied
                ),
                (
                    "configuration_error",
                    Recovery::FixConfiguration,
                    Code::FailedPrecondition
                ),
                ("timeout", Recovery::Retry, Code::DeadlineExceeded),
                ("unavailable", Recovery::Retry, Code::Unavailable),
                ("unclassified", Recovery::Investigate, Code::Unknown),
            ]
        );
    }

    #[test]
    fn status_round_trips_classifications_without_printable_detail() {
        for kind in TokenGrantFailureKind::ALL {
            for stage in TokenGrantStage::ALL {
                let failure = TokenGrantFailure::new(kind, stage);
                assert_eq!(
                    TokenGrantFailure::from_status(&failure.to_status()),
                    failure
                );
            }
        }
        let failure = sample();
        let guarded = failure.to_status_with_code(Code::Unauthenticated);
        assert_eq!(guarded.code(), Code::Unauthenticated);
        assert_eq!(TokenGrantFailure::from_status(&guarded), failure);
        assert_eq!(failure.to_status_with_code(Code::Ok).code(), Code::Unknown);
        for status in [0, 99, 600] {
            assert_eq!(failure.with_upstream_status(status).upstream_status(), None);
        }
        assert_eq!(failure.to_string(), FAILURE_MESSAGE);
        assert_eq!(format!("{failure:?}"), FAILURE_MESSAGE);
        assert!(std::error::Error::source(&failure).is_none());
    }

    #[test]
    fn rejects_unknown_missing_or_noncanonical_metadata() {
        for (key, value) in [
            ("version", "2"),
            ("code", "SYNTHETIC_SECRET"),
            ("stage", "SYNTHETIC_SECRET"),
            ("unknown", "SYNTHETIC_SECRET"),
            ("upstream_http_status", "600"),
            ("upstream_http_status", "0409"),
            ("upstream_http_status", "4e2"),
        ] {
            assert_rejected(&mutate_info(|info| {
                info.metadata.insert(key.into(), value.into());
            }));
        }
        for key in ["version", "code", "stage"] {
            assert_rejected(&mutate_info(|info| {
                info.metadata.remove(key);
            }));
        }
        assert_rejected(&mutate_info(|info| info.reason = "SYNTHETIC_SECRET".into()));
        assert_rejected(&mutate_info(|info| info.domain = "SYNTHETIC_SECRET".into()));
    }

    #[test]
    fn rejects_malformed_inconsistent_or_foreign_envelopes() {
        let original = sample().to_status();
        let details = || original.details().to_vec().into();
        assert_rejected(&Status::unknown("SYNTHETIC_SECRET"));
        assert_rejected(&Status::with_details(
            Code::Internal,
            FAILURE_MESSAGE,
            details(),
        ));
        assert_rejected(&Status::with_details(
            original.code(),
            "SYNTHETIC_SECRET",
            details(),
        ));
        for bytes in [
            original.details()[..original.details().len() - 1].to_vec(),
            vec![0; MAX_DETAILS_BYTES + 1],
        ] {
            assert_rejected(&Status::with_details(
                original.code(),
                FAILURE_MESSAGE,
                bytes.into(),
            ));
        }
        let mutations: [fn(&mut tonic_types::pb::Status); 4] = [
            |value| value.message = "SYNTHETIC_SECRET".into(),
            |value| value.details[0].type_url = "type.googleapis.com/google.rpc.RetryInfo".into(),
            |value| value.details.clear(),
            |value| value.details.push(value.details[0].clone()),
        ];
        for mutate in mutations {
            let mut value = envelope(&original);
            mutate(&mut value);
            assert_rejected(&replace_envelope(&original, &value));
        }
    }
}
