// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes `ServiceAccount` bootstrap authenticator.
//!
//! Path-scoped to `IssueSandboxToken`. Validates a projected SA token
//! presented by a sandbox pod, reads the pod's `openshell.io/sandbox-id`
//! annotation, and returns a [`Principal::Sandbox`] with
//! [`SandboxIdentitySource::K8sServiceAccount`]. The `IssueSandboxToken`
//! handler then mints a gateway-signed JWT for that sandbox id; subsequent
//! gRPC calls from the supervisor use the gateway-minted JWT validated by
//! [`super::sandbox_jwt::SandboxJwtAuthenticator`].
//!
//! This is the only authenticator that talks to the K8s apiserver. It is
//! optional — the gateway boots without it in singleplayer deployments.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use async_trait::async_trait;
use std::sync::Arc;
use tonic::Status;
use tracing::{debug, warn};

/// gRPC method path that this authenticator accepts. All other paths fall
/// through (return `Ok(None)`) so a gateway-minted JWT is required there.
pub const ISSUE_SANDBOX_TOKEN_PATH: &str = "/openshell.v1.OpenShell/IssueSandboxToken";

/// Pod annotation that binds a sandbox pod to its UUID. Set by the
/// Kubernetes compute driver at pod-create time. The gateway treats this
/// annotation as authoritative; the K8s `Role` granted to the gateway must
/// not include `patch pods` (see plan §11.8).
#[allow(dead_code)]
pub const SANDBOX_ID_ANNOTATION: &str = "openshell.io/sandbox-id";

/// Resolved identity extracted from a validated SA token + pod lookup.
#[derive(Debug, Clone)]
pub struct ResolvedK8sIdentity {
    pub sandbox_id: String,
    pub pod_name: String,
    pub pod_uid: String,
}

/// Apiserver-facing operations the authenticator depends on. Split out so
/// tests can fake the apiserver without standing up a kube cluster.
#[async_trait]
pub trait K8sIdentityResolver: Send + Sync + 'static {
    /// Validate `token` via `TokenReview` (`aud == openshell-gateway`),
    /// extract the pod name/uid, then `GET` the pod and read
    /// `openshell.io/sandbox-id`. Returns `Ok(None)` when the token is
    /// well-formed but does not authenticate (e.g. wrong audience); returns
    /// `Err` for transport/server errors.
    async fn resolve(&self, token: &str) -> Result<Option<ResolvedK8sIdentity>, Status>;
}

/// Authenticator wrapper around a [`K8sIdentityResolver`].
pub struct K8sServiceAccountAuthenticator {
    resolver: Arc<dyn K8sIdentityResolver>,
}

impl std::fmt::Debug for K8sServiceAccountAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sServiceAccountAuthenticator")
            .finish_non_exhaustive()
    }
}

impl K8sServiceAccountAuthenticator {
    pub fn new(resolver: Arc<dyn K8sIdentityResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl Authenticator for K8sServiceAccountAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status> {
        // Scope: only the bootstrap RPC. Other paths fall through so the
        // SandboxJwtAuthenticator (or OIDC) handles them.
        if path != ISSUE_SANDBOX_TOKEN_PATH {
            return Ok(None);
        }

        let Some(token) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };

        let Some(resolved) = self.resolver.resolve(token).await? else {
            debug!("K8s SA token did not authenticate; falling through");
            return Ok(None);
        };

        if resolved.sandbox_id.is_empty() {
            warn!(
                pod = %resolved.pod_name,
                "pod missing openshell.io/sandbox-id annotation; rejecting"
            );
            return Err(Status::permission_denied(
                "pod is not bound to a sandbox identity",
            ));
        }

        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id: resolved.sandbox_id,
            source: SandboxIdentitySource::K8sServiceAccount {
                pod_name: resolved.pod_name,
                pod_uid: resolved.pod_uid,
            },
            trust_domain: Some("openshell".to_string()),
        })))
    }
}

/// Live resolver backed by a `kube::Client`. PR 2 ships this with a
/// `not_implemented` stub so the authenticator type and trait are in place
/// for PR 3's K8s driver wiring. The `TokenReview` + pod-`GET`
/// implementation lands when the K8s driver actually creates the
/// projected SA volume (PR 3).
#[allow(dead_code)]
pub struct LiveK8sResolver {
    client: kube::Client,
    audience: String,
    namespace: String,
}

impl LiveK8sResolver {
    #[allow(dead_code)]
    pub fn new(client: kube::Client, audience: String, namespace: String) -> Self {
        Self {
            client,
            audience,
            namespace,
        }
    }
}

#[async_trait]
impl K8sIdentityResolver for LiveK8sResolver {
    async fn resolve(&self, _token: &str) -> Result<Option<ResolvedK8sIdentity>, Status> {
        // Implementation lands in PR 3 with the K8s driver wiring.
        // Until then `IssueSandboxToken` is wired but only exercised via
        // the test harness (see fake resolver below).
        Err(Status::unimplemented(
            "K8s ServiceAccount bootstrap not yet enabled",
        ))
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// Fake resolver for unit tests. Returns the configured outcome on
    /// every call and records the tokens it observed.
    pub struct FakeResolver {
        pub outcome: Result<Option<ResolvedK8sIdentity>, Status>,
        pub seen_tokens: Mutex<Vec<String>>,
    }

    impl FakeResolver {
        pub fn returning(outcome: Result<Option<ResolvedK8sIdentity>, Status>) -> Self {
            Self {
                outcome,
                seen_tokens: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl K8sIdentityResolver for FakeResolver {
        async fn resolve(&self, token: &str) -> Result<Option<ResolvedK8sIdentity>, Status> {
            self.seen_tokens.lock().unwrap().push(token.to_string());
            match &self.outcome {
                Ok(opt) => Ok(opt.clone()),
                Err(s) => Err(Status::new(s.code(), s.message())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeResolver;
    use super::*;

    fn bearer_headers(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn authenticates_on_issue_path_only() {
        let resolved = ResolvedK8sIdentity {
            sandbox_id: "sandbox-a".to_string(),
            pod_name: "openshell-sandbox-a".to_string(),
            pod_uid: "uid-a".to_string(),
        };
        let fake = Arc::new(FakeResolver::returning(Ok(Some(resolved))));
        let auth = K8sServiceAccountAuthenticator::new(fake.clone());

        let on_issue = auth
            .authenticate(&bearer_headers("sa-jwt"), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap()
            .expect("expected principal");
        match on_issue {
            Principal::Sandbox(p) => {
                assert_eq!(p.sandbox_id, "sandbox-a");
                assert!(matches!(
                    p.source,
                    SandboxIdentitySource::K8sServiceAccount { .. }
                ));
            }
            _ => panic!("expected sandbox principal"),
        }

        let off_issue = auth
            .authenticate(
                &bearer_headers("sa-jwt"),
                "/openshell.v1.OpenShell/GetSandboxConfig",
            )
            .await
            .unwrap();
        assert!(
            off_issue.is_none(),
            "K8s SA authenticator must be scoped to IssueSandboxToken"
        );
        assert_eq!(
            fake.seen_tokens.lock().unwrap().len(),
            1,
            "off-path call must not consult the apiserver"
        );
    }

    #[tokio::test]
    async fn missing_bearer_yields_none() {
        let fake = Arc::new(FakeResolver::returning(Ok(None)));
        let auth = K8sServiceAccountAuthenticator::new(fake);
        let result = auth
            .authenticate(&http::HeaderMap::new(), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolver_returning_none_falls_through() {
        let fake = Arc::new(FakeResolver::returning(Ok(None)));
        let auth = K8sServiceAccountAuthenticator::new(fake);
        let result = auth
            .authenticate(
                &bearer_headers("not-a-real-sa-token"),
                ISSUE_SANDBOX_TOKEN_PATH,
            )
            .await
            .unwrap();
        assert!(result.is_none(), "non-authenticating tokens fall through");
    }

    #[tokio::test]
    async fn pod_without_annotation_is_rejected() {
        let resolved = ResolvedK8sIdentity {
            sandbox_id: String::new(),
            pod_name: "stray-pod".to_string(),
            pod_uid: "uid".to_string(),
        };
        let fake = Arc::new(FakeResolver::returning(Ok(Some(resolved))));
        let auth = K8sServiceAccountAuthenticator::new(fake);
        let err = auth
            .authenticate(&bearer_headers("sa-jwt"), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .expect_err("unbound pod must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn resolver_error_propagates() {
        let fake = Arc::new(FakeResolver::returning(Err(Status::unavailable(
            "apiserver down",
        ))));
        let auth = K8sServiceAccountAuthenticator::new(fake);
        let err = auth
            .authenticate(&bearer_headers("sa-jwt"), ISSUE_SANDBOX_TOKEN_PATH)
            .await
            .expect_err("resolver error must propagate");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
