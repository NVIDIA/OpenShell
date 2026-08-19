// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor bootstrap authenticator adapter.
//!
//! The Kubernetes-specific `TokenReview` and pod lookup logic lives in the
//! Kubernetes driver. This module is intentionally gateway-small: it is
//! path-scoped to supervisor bootstrap RPCs, extracts a bearer token, delegates
//! validation to the active driver's bootstrap identity provider, and turns the
//! resulting registration-only identity into the principal shape expected by the
//! gateway auth router.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use openshell_core::supervisor_bootstrap::{
    SupervisorBootstrapBinding, SupervisorBootstrapIdentityProvider,
};
use std::sync::Arc;
use tonic::Status;
use tonic::async_trait;
use tracing::{debug, warn};

/// Legacy gRPC method path accepted by this authenticator. All other
/// non-bootstrap paths fall through so a gateway-minted JWT or user credential
/// is required there.
pub const ISSUE_SANDBOX_TOKEN_PATH: &str = "/openshell.v1.OpenShell/IssueSandboxToken";
/// Supervisor registration path accepted by this authenticator.
pub const REGISTER_SUPERVISOR_PATH: &str = "/openshell.v1.OpenShell/RegisterSupervisor";

/// Path-scoped authenticator backed by the active compute driver's bootstrap
/// identity provider.
pub struct SupervisorBootstrapAuthenticator {
    provider: Arc<dyn SupervisorBootstrapIdentityProvider>,
}

impl std::fmt::Debug for SupervisorBootstrapAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorBootstrapAuthenticator")
            .finish_non_exhaustive()
    }
}

impl SupervisorBootstrapAuthenticator {
    pub fn new(provider: Arc<dyn SupervisorBootstrapIdentityProvider>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl Authenticator for SupervisorBootstrapAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status> {
        if path != ISSUE_SANDBOX_TOKEN_PATH && path != REGISTER_SUPERVISOR_PATH {
            return Ok(None);
        }

        let Some(token) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };

        let Some(identity) = self.provider.authenticate_registration(token).await? else {
            debug!("supervisor bootstrap token did not authenticate; falling through");
            return Ok(None);
        };

        if path == REGISTER_SUPERVISOR_PATH {
            return Ok(Some(Principal::SupervisorBootstrap(identity)));
        }

        let SupervisorBootstrapBinding::BoundSandbox { sandbox_id } = identity.binding else {
            warn!(
                driver = %identity.driver,
                instance_name = %identity.instance_name,
                instance_id = %identity.instance_id,
                "bootstrap identity is not bound to a sandbox; rejecting legacy token issue"
            );
            return Err(Status::permission_denied(
                "supervisor instance is not bound to a sandbox identity",
            ));
        };

        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id,
            source: SandboxIdentitySource::SupervisorBootstrap {
                driver: identity.driver,
                instance_name: identity.instance_name,
                instance_id: identity.instance_id,
            },
            trust_domain: Some("openshell".to_string()),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::supervisor_bootstrap::SupervisorBootstrapIdentity;
    use std::sync::Mutex;

    struct FakeProvider {
        outcome: Result<Option<SupervisorBootstrapIdentity>, Status>,
        seen_tokens: Mutex<Vec<String>>,
    }

    impl FakeProvider {
        fn returning(outcome: Result<Option<SupervisorBootstrapIdentity>, Status>) -> Self {
            Self {
                outcome,
                seen_tokens: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SupervisorBootstrapIdentityProvider for FakeProvider {
        async fn authenticate_registration(
            &self,
            token: &str,
        ) -> Result<Option<SupervisorBootstrapIdentity>, Status> {
            self.seen_tokens.lock().unwrap().push(token.to_string());
            match &self.outcome {
                Ok(identity) => Ok(identity.clone()),
                Err(status) => Err(Status::new(status.code(), status.message())),
            }
        }
    }

    fn bearer_headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    fn identity(binding: SupervisorBootstrapBinding) -> SupervisorBootstrapIdentity {
        SupervisorBootstrapIdentity {
            driver: "kubernetes".to_string(),
            instance_name: "openshell-sandbox-a".to_string(),
            instance_id: "uid-a".to_string(),
            owner_name: "sandbox-owner-a".to_string(),
            owner_uid: "cr-uid-a".to_string(),
            binding,
        }
    }

    #[tokio::test]
    async fn authenticates_on_bootstrap_paths_only() {
        let provider = Arc::new(FakeProvider::returning(Ok(Some(identity(
            SupervisorBootstrapBinding::BoundSandbox {
                sandbox_id: "sandbox-a".to_string(),
            },
        )))));
        let auth = SupervisorBootstrapAuthenticator::new(provider.clone());

        let issue = auth
            .authenticate(&bearer_headers("bootstrap-token"), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap()
            .expect("expected principal");
        match issue {
            Principal::Sandbox(p) => {
                assert_eq!(p.sandbox_id, "sandbox-a");
                assert!(matches!(
                    p.source,
                    SandboxIdentitySource::SupervisorBootstrap { .. }
                ));
            }
            _ => panic!("expected sandbox principal"),
        }

        let register = auth
            .authenticate(&bearer_headers("bootstrap-token"), REGISTER_SUPERVISOR_PATH)
            .await
            .unwrap()
            .expect("expected principal");
        assert!(matches!(register, Principal::SupervisorBootstrap(_)));

        let off_path = auth
            .authenticate(
                &bearer_headers("bootstrap-token"),
                "/openshell.v1.OpenShell/GetSandboxConfig",
            )
            .await
            .unwrap();
        assert!(off_path.is_none());
        assert_eq!(provider.seen_tokens.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn missing_bearer_yields_none() {
        let provider = Arc::new(FakeProvider::returning(Ok(None)));
        let auth = SupervisorBootstrapAuthenticator::new(provider);
        let result = auth
            .authenticate(&http::HeaderMap::new(), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn issue_token_rejects_unbound_identity() {
        let provider = Arc::new(FakeProvider::returning(Ok(Some(identity(
            SupervisorBootstrapBinding::WarmPending,
        )))));
        let auth = SupervisorBootstrapAuthenticator::new(provider);
        let err = auth
            .authenticate(&bearer_headers("bootstrap-token"), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .expect_err("unbound identity must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn register_accepts_unbound_identity() {
        let provider = Arc::new(FakeProvider::returning(Ok(Some(identity(
            SupervisorBootstrapBinding::WarmPending,
        )))));
        let auth = SupervisorBootstrapAuthenticator::new(provider);
        let principal = auth
            .authenticate(&bearer_headers("bootstrap-token"), REGISTER_SUPERVISOR_PATH)
            .await
            .unwrap()
            .expect("expected principal");

        match principal {
            Principal::SupervisorBootstrap(identity) => {
                assert_eq!(identity.binding, SupervisorBootstrapBinding::WarmPending);
                assert_eq!(identity.owner_uid, "cr-uid-a");
            }
            _ => panic!("expected bootstrap principal"),
        }
    }
}
