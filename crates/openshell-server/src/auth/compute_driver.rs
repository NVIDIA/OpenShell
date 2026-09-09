// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compute-driver delegated sandbox bootstrap authentication.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use crate::compute::ComputeRuntime;
use async_trait::async_trait;
use tonic::Status;

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
    ) -> Result<Option<Principal>, Status> {
        if path != ISSUE_SANDBOX_TOKEN_PATH {
            return Ok(None);
        }

        let Some(credential) = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };

        let sandbox_id = self.compute.authenticate_sandbox(credential).await?;
        if sandbox_id.is_empty() {
            return Err(Status::permission_denied(
                "compute driver returned an empty sandbox identity",
            ));
        }

        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id,
            source: SandboxIdentitySource::ComputeDriver {
                driver_name: self.compute.configured_driver_name().to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::SandboxIdentitySource;
    use crate::compute::{NoopTestDriver, new_test_runtime_with_driver};
    use crate::persistence::Store;
    use std::sync::Arc;
    use tonic::Code;

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
        let compute =
            new_test_runtime_with_driver(store, "external-kubernetes", Arc::new(driver)).await;
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
            .expect("driver credential should authenticate");

        let Principal::Sandbox(principal) = principal else {
            panic!("expected sandbox principal");
        };
        assert_eq!(principal.sandbox_id, "sandbox-a");
        assert!(matches!(
            principal.source,
            SandboxIdentitySource::ComputeDriver { ref driver_name }
                if driver_name == "external-kubernetes"
        ));
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

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn missing_bearer_credential_falls_through() {
        let auth = authenticator(NoopTestDriver::authenticating_sandbox("sandbox-a")).await;

        let result = auth
            .authenticate(&http::HeaderMap::new(), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap();

        assert!(result.is_none());
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

        assert_eq!(error.code(), Code::PermissionDenied);
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

        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.message(), "driver unavailable");
    }
}
