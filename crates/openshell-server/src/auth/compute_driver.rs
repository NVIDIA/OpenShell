// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compute-driver delegated sandbox bootstrap authentication.

use super::authenticator::{AuthFailureReason, AuthMechanism};
use super::authenticator::{AuthRejection, Authentication, Authenticator, bearer_credential};
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use crate::compute::ComputeRuntime;
use async_trait::async_trait;
use tonic::{Code, Status};

/// The only public gateway method on which driver-native credentials apply.
pub const ISSUE_SANDBOX_TOKEN_PATH: &str = "/openshell.v1.OpenShell/IssueSandboxToken";

#[derive(Clone, Debug)]
pub struct ComputeDriverAuthenticator {
    compute: ComputeRuntime,
}

impl ComputeDriverAuthenticator {
    pub fn new(compute: ComputeRuntime) -> Self {
        Self { compute }
    }
}

#[async_trait]
impl Authenticator for ComputeDriverAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Authentication, AuthRejection> {
        if path != ISSUE_SANDBOX_TOKEN_PATH {
            return Ok(Authentication::NotApplicable);
        }

        let Some(credential) = bearer_credential(headers) else {
            return Ok(Authentication::NotApplicable);
        };

        let authenticated = self
            .compute
            .authenticate_sandbox(credential)
            .await
            .map_err(|status| reject(driver_failure_reason(status.code()), status))?;
        let sandbox_id = authenticated.sandbox_id;
        if sandbox_id.is_empty() {
            return Err(reject(
                AuthFailureReason::UnknownIdentity,
                Status::permission_denied("compute driver returned an empty sandbox identity"),
            ));
        }
        if authenticated.runtime_identity.is_empty() {
            return Err(reject(
                AuthFailureReason::UnknownIdentity,
                Status::permission_denied("compute driver returned an empty runtime identity"),
            ));
        }

        Ok(Authentication::Accepted(Principal::Sandbox(
            SandboxPrincipal {
                sandbox_id,
                source: SandboxIdentitySource::ComputeDriver {
                    driver_name: self.compute.configured_driver_name().to_string(),
                    runtime_identity: authenticated.runtime_identity,
                },
                trust_domain: Some("openshell".to_string()),
            },
        )))
    }
}

fn reject(reason: AuthFailureReason, status: Status) -> AuthRejection {
    AuthRejection::new(AuthMechanism::ComputeDriver, reason, status)
}

fn driver_failure_reason(code: Code) -> AuthFailureReason {
    match code {
        Code::Unauthenticated
        | Code::PermissionDenied
        | Code::InvalidArgument
        | Code::FailedPrecondition => AuthFailureReason::InvalidCredential,
        Code::NotFound => AuthFailureReason::UnknownIdentity,
        _ => AuthFailureReason::IdentityProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::SandboxIdentitySource;
    use crate::compute::{NoopTestDriver, new_test_runtime_with_driver};
    use crate::persistence::Store;
    use std::sync::Arc;

    fn bearer_headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    async fn authenticator(driver: NoopTestDriver) -> ComputeDriverAuthenticator {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let compute = new_test_runtime_with_driver(store, "external-kubernetes", Arc::new(driver));
        ComputeDriverAuthenticator::new(compute)
    }

    #[tokio::test]
    async fn authenticates_driver_credential_on_issue_path() {
        let auth = authenticator(NoopTestDriver::authenticating_sandbox("sandbox-a")).await;

        let principal = auth
            .authenticate(
                &bearer_headers("driver-credential"),
                ISSUE_SANDBOX_TOKEN_PATH,
            )
            .await
            .unwrap()
            .principal()
            .expect("driver credential should authenticate");

        let Principal::Sandbox(principal) = principal else {
            panic!("expected sandbox principal");
        };
        assert_eq!(principal.sandbox_id, "sandbox-a");
        assert!(matches!(
            principal.source,
            SandboxIdentitySource::ComputeDriver {
                ref driver_name,
                ref runtime_identity,
            }
                if driver_name == "external-kubernetes"
                    && runtime_identity == "test-runtime"
        ));
    }

    #[tokio::test]
    async fn accepts_lowercase_bearer_scheme() {
        let auth = authenticator(NoopTestDriver::authenticating_sandbox("sandbox-a")).await;
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("bearer driver-credential"),
        );

        let principal = auth
            .authenticate(&headers, ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap();

        assert!(principal.principal().is_some());
    }

    #[tokio::test]
    async fn authenticator_is_scoped_to_issue_path() {
        let auth = authenticator(NoopTestDriver::failing_sandbox_authentication(
            Code::Unavailable,
            "driver must not be called",
        ))
        .await;

        let result = auth
            .authenticate(
                &bearer_headers("driver-credential"),
                "/openshell.v1.OpenShell/GetSandboxConfig",
            )
            .await
            .unwrap();

        assert!(matches!(result, Authentication::NotApplicable));
    }

    #[tokio::test]
    async fn missing_bearer_credential_falls_through() {
        let auth = authenticator(NoopTestDriver::authenticating_sandbox("sandbox-a")).await;

        let result = auth
            .authenticate(&http::HeaderMap::new(), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap();

        assert!(matches!(result, Authentication::NotApplicable));
    }

    #[tokio::test]
    async fn empty_driver_identity_is_rejected() {
        let auth = authenticator(NoopTestDriver::authenticating_sandbox("")).await;

        let error = auth
            .authenticate(
                &bearer_headers("driver-credential"),
                ISSUE_SANDBOX_TOKEN_PATH,
            )
            .await
            .expect_err("empty identity must fail closed");

        assert_eq!(error.status.code(), Code::PermissionDenied);
        assert_eq!(error.reason, AuthFailureReason::UnknownIdentity);
    }

    #[tokio::test]
    async fn empty_runtime_identity_is_rejected() {
        let auth = authenticator(NoopTestDriver::authenticating_sandbox_with_runtime(
            "sandbox-a",
            "",
        ))
        .await;

        let error = auth
            .authenticate(
                &bearer_headers("driver-credential"),
                ISSUE_SANDBOX_TOKEN_PATH,
            )
            .await
            .expect_err("empty runtime identity must fail closed");

        assert_eq!(error.status.code(), Code::PermissionDenied);
        assert_eq!(error.reason, AuthFailureReason::UnknownIdentity);
    }

    #[tokio::test]
    async fn driver_authentication_error_propagates() {
        let auth = authenticator(NoopTestDriver::failing_sandbox_authentication(
            Code::Unavailable,
            "driver unavailable",
        ))
        .await;

        let error = auth
            .authenticate(
                &bearer_headers("driver-credential"),
                ISSUE_SANDBOX_TOKEN_PATH,
            )
            .await
            .expect_err("driver errors must propagate");

        assert_eq!(error.status.code(), Code::Unavailable);
        assert_eq!(error.status.message(), "driver unavailable");
        assert_eq!(error.mechanism, AuthMechanism::ComputeDriver);
        assert_eq!(error.reason, AuthFailureReason::IdentityProviderUnavailable);
    }

    #[tokio::test]
    async fn driver_credential_rejection_is_classified_by_status() {
        for (code, reason) in [
            (Code::Unauthenticated, AuthFailureReason::InvalidCredential),
            (Code::PermissionDenied, AuthFailureReason::InvalidCredential),
            (Code::NotFound, AuthFailureReason::UnknownIdentity),
            (
                Code::DeadlineExceeded,
                AuthFailureReason::IdentityProviderUnavailable,
            ),
            (
                Code::Internal,
                AuthFailureReason::IdentityProviderUnavailable,
            ),
        ] {
            let auth = authenticator(NoopTestDriver::failing_sandbox_authentication(
                code,
                "driver says no",
            ))
            .await;

            let error = auth
                .authenticate(
                    &bearer_headers("driver-credential"),
                    ISSUE_SANDBOX_TOKEN_PATH,
                )
                .await
                .expect_err("driver errors must propagate");

            assert_eq!(error.status.code(), code);
            assert_eq!(error.reason, reason, "{code:?}");
        }
    }
}
