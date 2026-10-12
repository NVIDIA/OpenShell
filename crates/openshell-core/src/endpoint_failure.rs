// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded causes for failed endpoint results.
//!
//! A cause holds a code and a stage from the closed sets of its domain, the
//! recovery action documented for the code, configured provider and
//! credential names, an optional HTTP status, and the supervisor's request ID.
//! The supervisor builds causes from typed failures and the gateway validates
//! reported causes against the same sets here, so neither side can accept a
//! code the other does not define. Each domain also names the endpoint results
//! it can explain. No cause carries remote text.
//!
//! A new producer adds a domain variant and one validation function in this
//! module that checks its result, code and stage sets, and code-to-recovery
//! mapping. Names, status, and the request ID are checked the same way for
//! every domain.

use crate::proto::{self, ProviderCredentialRefreshRecoveryAction};
use crate::token_grant_failure::{TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage};

/// Longest provider or credential name a reported cause may carry.
///
/// A reported name is also limited to printable ASCII, so status renderers
/// cannot be given control, bidirectional, or format characters.
pub const MAX_ENDPOINT_FAILURE_NAME_BYTES: usize = 253;

/// The bounded cause of one failed endpoint observation.
///
/// This explains why an exchange failed; it does not establish that the remote
/// endpoint is unhealthy. A token grant can fail before the request reaches it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointFailure {
    domain: proto::EndpointFailureDomain,
    code: &'static str,
    stage: &'static str,
    recovery: ProviderCredentialRefreshRecoveryAction,
    provider: String,
    credential_key: String,
    upstream_http_status: Option<u16>,
    request_id: String,
}

impl EndpointFailure {
    /// Describe a refused token grant on the exchange named by `request_id`.
    ///
    /// `provider` and `credential_key` are empty when the grant failed before
    /// a credential was selected. Names the gateway would reject are reported
    /// as empty too: one unreportable name must not discard the sandbox's
    /// whole status report.
    #[must_use]
    pub fn token_grant(
        failure: TokenGrantFailure,
        provider: &str,
        credential_key: &str,
        request_id: &str,
    ) -> Self {
        let (provider, credential_key) = if provider.is_empty() == credential_key.is_empty()
            && valid_name(provider)
            && valid_name(credential_key)
        {
            (provider, credential_key)
        } else {
            ("", "")
        };
        Self {
            domain: proto::EndpointFailureDomain::TokenGrant,
            code: failure.code(),
            stage: failure.stage().code(),
            recovery: failure.recovery(),
            provider: provider.to_string(),
            credential_key: credential_key.to_string(),
            upstream_http_status: failure.upstream_status(),
            request_id: request_id.to_string(),
        }
    }

    /// Return the protobuf form reported to the gateway.
    #[must_use]
    pub fn to_proto(&self) -> proto::EndpointFailure {
        proto::EndpointFailure {
            domain: self.domain.into(),
            code: self.code.to_string(),
            recovery_action: self.recovery.into(),
            provider: self.provider.clone(),
            credential_key: self.credential_key.clone(),
            stage: self.stage.to_string(),
            upstream_http_status: self.upstream_http_status.map(u32::from),
            request_id: self.request_id.clone(),
        }
    }
}

/// Why a reported cause was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointFailureValidationError {
    /// The domain is unspecified or unknown.
    Domain,
    /// The domain does not explain the endpoint result it accompanies.
    Result,
    /// The code is not in the domain's closed set.
    Code,
    /// The stage is not in the domain's closed set.
    Stage,
    /// The recovery action is not the one documented for the code.
    Recovery,
    /// A provider or credential name is malformed, or only one is present.
    Name,
    /// The HTTP status is outside 100 through 599.
    UpstreamStatus,
    /// The request ID is not a canonical lowercase UUID.
    RequestId,
}

impl EndpointFailureValidationError {
    /// Return a fixed description that contains none of the rejected values.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Domain => "endpoint failure domain is invalid",
            Self::Result => "endpoint failure domain does not explain this endpoint result",
            Self::Code => "endpoint failure code is not defined for its domain",
            Self::Stage => "endpoint failure stage is not defined for its domain",
            Self::Recovery => "endpoint failure recovery action does not match its code",
            Self::Name => "endpoint failure provider and credential names are invalid",
            Self::UpstreamStatus => "endpoint failure upstream HTTP status is invalid",
            Self::RequestId => "endpoint failure request_id must be a canonical UUID",
        }
    }
}

/// Check a reported cause, and the result it accompanies, against the closed
/// sets of its domain.
///
/// The gateway separately checks that a named provider is attached to the
/// reporting sandbox.
///
/// # Errors
///
/// Returns the first rule the cause breaks.
pub fn validate_endpoint_failure(
    failure: &proto::EndpointFailure,
    result: proto::EndpointResult,
) -> Result<(), EndpointFailureValidationError> {
    match proto::EndpointFailureDomain::try_from(failure.domain) {
        Ok(proto::EndpointFailureDomain::TokenGrant) => validate_token_grant(failure, result)?,
        Ok(proto::EndpointFailureDomain::Unspecified) | Err(_) => {
            return Err(EndpointFailureValidationError::Domain);
        }
    }
    let named = !failure.provider.is_empty();
    if named == failure.credential_key.is_empty()
        || !valid_name(&failure.provider)
        || !valid_name(&failure.credential_key)
    {
        return Err(EndpointFailureValidationError::Name);
    }
    if failure
        .upstream_http_status
        .is_some_and(|status| !(100..=599).contains(&status))
    {
        return Err(EndpointFailureValidationError::UpstreamStatus);
    }
    if !is_canonical_uuid(&failure.request_id) {
        return Err(EndpointFailureValidationError::RequestId);
    }
    Ok(())
}

/// Check the parts of a token-grant cause that its domain defines.
fn validate_token_grant(
    failure: &proto::EndpointFailure,
    result: proto::EndpointResult,
) -> Result<(), EndpointFailureValidationError> {
    // A refused grant means the endpoint's credential was unavailable.
    if result != proto::EndpointResult::CredentialUnavailable {
        return Err(EndpointFailureValidationError::Result);
    }
    let kind = TokenGrantFailureKind::from_code(&failure.code)
        .ok_or(EndpointFailureValidationError::Code)?;
    TokenGrantStage::from_code(&failure.stage).ok_or(EndpointFailureValidationError::Stage)?;
    if failure.recovery_action != i32::from(kind.recovery()) {
        return Err(EndpointFailureValidationError::Recovery);
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    name.len() <= MAX_ENDPOINT_FAILURE_NAME_BYTES
        && name.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "3e2d1c0b-9a8f-4e7d-b6c5-a4f3e2d1c0b9";
    const CREDENTIAL_UNAVAILABLE: proto::EndpointResult =
        proto::EndpointResult::CredentialUnavailable;

    fn reported() -> proto::EndpointFailure {
        EndpointFailure::token_grant(
            TokenGrantFailure::new(
                TokenGrantFailureKind::ProviderAuthorizationRequired,
                TokenGrantStage::GatewayRpc,
            )
            .with_upstream_status(409),
            "github",
            "access_token",
            REQUEST_ID,
        )
        .to_proto()
    }

    #[test]
    fn token_grant_failure_reports_its_code_stage_recovery_and_names() {
        assert_eq!(
            reported(),
            proto::EndpointFailure {
                domain: proto::EndpointFailureDomain::TokenGrant.into(),
                code: "provider_authorization_required".into(),
                recovery_action: ProviderCredentialRefreshRecoveryAction::Reauthorize.into(),
                provider: "github".into(),
                credential_key: "access_token".into(),
                stage: "gateway_rpc".into(),
                upstream_http_status: Some(409),
                request_id: REQUEST_ID.into(),
            }
        );
        assert_eq!(
            validate_endpoint_failure(&reported(), CREDENTIAL_UNAVAILABLE),
            Ok(())
        );
    }

    #[test]
    fn every_token_grant_classification_validates() {
        for kind in [
            TokenGrantFailureKind::ProviderAuthorizationRequired,
            TokenGrantFailureKind::WorkloadIdentityRejected,
            TokenGrantFailureKind::Configuration,
            TokenGrantFailureKind::Timeout,
            TokenGrantFailureKind::Unavailable,
            TokenGrantFailureKind::Unclassified,
        ] {
            for stage in [
                TokenGrantStage::Configuration,
                TokenGrantStage::WorkloadIdentity,
                TokenGrantStage::GatewayRpc,
                TokenGrantStage::IntermediateExchange,
                TokenGrantStage::TokenEndpoint,
                TokenGrantStage::Injection,
            ] {
                let failure = EndpointFailure::token_grant(
                    TokenGrantFailure::new(kind, stage),
                    "",
                    "",
                    REQUEST_ID,
                );
                assert_eq!(
                    validate_endpoint_failure(&failure.to_proto(), CREDENTIAL_UNAVAILABLE),
                    Ok(())
                );
            }
        }
    }

    type Mutation = fn(&mut proto::EndpointFailure);

    #[test]
    fn token_grant_causes_explain_only_credential_failures() {
        for result in [
            proto::EndpointResult::Unspecified,
            proto::EndpointResult::NoObservedExchange,
            proto::EndpointResult::HttpResponseReceived,
            proto::EndpointResult::PolicyDenied,
            proto::EndpointResult::TlsFailed,
            proto::EndpointResult::TransportFailed,
            proto::EndpointResult::UpstreamRejected,
        ] {
            assert_eq!(
                validate_endpoint_failure(&reported(), result),
                Err(EndpointFailureValidationError::Result),
                "{result:?}"
            );
        }
        assert_eq!(
            validate_endpoint_failure(&reported(), CREDENTIAL_UNAVAILABLE),
            Ok(())
        );
    }

    #[test]
    fn constructed_causes_always_pass_gateway_validation() {
        let oversized = "k".repeat(MAX_ENDPOINT_FAILURE_NAME_BYTES + 1);
        for (provider, credential_key) in [
            ("github", oversized.as_str()),
            ("git\u{202e}hub", "access_token"),
            ("github", "access token"),
            ("github", ""),
            ("", "access_token"),
        ] {
            let failure = EndpointFailure::token_grant(
                TokenGrantFailure::new(
                    TokenGrantFailureKind::Configuration,
                    TokenGrantStage::Injection,
                ),
                provider,
                credential_key,
                REQUEST_ID,
            )
            .to_proto();
            assert_eq!(
                validate_endpoint_failure(&failure, CREDENTIAL_UNAVAILABLE),
                Ok(())
            );
            assert!(failure.provider.is_empty() && failure.credential_key.is_empty());
        }
    }

    #[test]
    fn rejects_values_outside_the_closed_sets() {
        let cases: [(Mutation, EndpointFailureValidationError); 15] = [
            (|f| f.domain = 0, EndpointFailureValidationError::Domain),
            (|f| f.domain = 99, EndpointFailureValidationError::Domain),
            (
                |f| f.code = "reauthorization_required".into(),
                EndpointFailureValidationError::Code,
            ),
            (
                |f| f.code = "Provider_Authorization_Required".into(),
                EndpointFailureValidationError::Code,
            ),
            (
                |f| f.stage = "token service said no".into(),
                EndpointFailureValidationError::Stage,
            ),
            (
                |f| f.recovery_action = ProviderCredentialRefreshRecoveryAction::Retry.into(),
                EndpointFailureValidationError::Recovery,
            ),
            (|f| f.provider.clear(), EndpointFailureValidationError::Name),
            (
                |f| f.credential_key.clear(),
                EndpointFailureValidationError::Name,
            ),
            (
                |f| f.provider = "git\nhub".into(),
                EndpointFailureValidationError::Name,
            ),
            (
                |f| f.provider = "git\u{202e}hub".into(),
                EndpointFailureValidationError::Name,
            ),
            (
                |f| f.credential_key = "k".repeat(MAX_ENDPOINT_FAILURE_NAME_BYTES + 1),
                EndpointFailureValidationError::Name,
            ),
            (
                |f| f.upstream_http_status = Some(600),
                EndpointFailureValidationError::UpstreamStatus,
            ),
            (
                |f| f.upstream_http_status = Some(99),
                EndpointFailureValidationError::UpstreamStatus,
            ),
            (
                |f| f.request_id = REQUEST_ID.to_ascii_uppercase(),
                EndpointFailureValidationError::RequestId,
            ),
            (
                |f| f.request_id.clear(),
                EndpointFailureValidationError::RequestId,
            ),
        ];
        for (mutate, expected) in cases {
            let mut failure = reported();
            mutate(&mut failure);
            assert_eq!(
                validate_endpoint_failure(&failure, CREDENTIAL_UNAVAILABLE),
                Err(expected)
            );
        }
    }
}
