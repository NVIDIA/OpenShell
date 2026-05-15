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
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tonic::Status;
use tracing::{debug, info, warn};

/// gRPC method path that this authenticator accepts. All other paths fall
/// through (return `Ok(None)`) so a gateway-minted JWT is required there.
pub const ISSUE_SANDBOX_TOKEN_PATH: &str = "/openshell.v1.OpenShell/IssueSandboxToken";

/// Pod annotation that binds a sandbox pod to its UUID. Set by the
/// Kubernetes compute driver at pod-create time. The gateway treats this
/// annotation as authoritative; the K8s `Role` granted to the gateway must
/// not include `patch pods` (see plan §11.8).
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

/// K8s apiserver discovery document (subset of fields used).
#[derive(Deserialize)]
struct ApiserverDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// JWKS key set returned by the apiserver's `/openid/v1/jwks` endpoint.
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    alg: Option<String>,
}

/// Claims subset extracted from a validated projected SA token. `exp`,
/// `aud`, and `serviceaccount` are validated by `jsonwebtoken` but we
/// don't read them post-decode — dead-code-allowed so the structural
/// match against the token shape stays explicit.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct K8sSaClaims {
    /// `system:serviceaccount:<namespace>:<sa-name>`
    sub: String,
    iss: String,
    /// The audience claim is always an array for projected SA tokens.
    #[serde(default)]
    aud: Vec<String>,
    exp: i64,
    #[serde(rename = "kubernetes.io")]
    kubernetes: K8sClaim,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct K8sClaim {
    namespace: String,
    pod: K8sPodClaim,
    #[serde(default)]
    serviceaccount: Option<K8sSaClaim>,
}

#[derive(Debug, Deserialize)]
struct K8sPodClaim {
    name: String,
    uid: String,
}

#[derive(Debug, Deserialize)]
struct K8sSaClaim {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    uid: String,
}

/// JWKS cache for the K8s apiserver's projected `ServiceAccount` token
/// issuer. Discovery + key fetch lazily on first validate; subsequent
/// validations are in-process signature checks. Refreshes on `kid` miss
/// so apiserver key rotation propagates without a restart.
pub struct K8sApiserverJwks {
    client: kube::Client,
    expected_audience: String,
    state: RwLock<JwksState>,
    refresh: Mutex<()>,
}

#[derive(Default)]
struct JwksState {
    issuer: Option<String>,
    jwks_path: Option<String>,
    keys: HashMap<String, DecodingKey>,
}

impl K8sApiserverJwks {
    pub fn new(client: kube::Client, expected_audience: String) -> Self {
        Self {
            client,
            expected_audience,
            state: RwLock::new(JwksState::default()),
            refresh: Mutex::new(()),
        }
    }

    /// Validate `token`, returning the parsed claims on success.
    #[allow(clippy::result_large_err)]
    async fn validate(&self, token: &str) -> Result<K8sSaClaims, Status> {
        // Decode the header to find the kid first; we lazily load on demand.
        let header = decode_header(token).map_err(|e| {
            debug!(error = %e, "K8s SA JWT header decode failed");
            Status::unauthenticated("invalid token")
        })?;
        let kid = header
            .kid
            .ok_or_else(|| Status::unauthenticated("invalid token: missing kid"))?;

        let (issuer, key) = if let Some(pair) = self.cached_key(&kid).await {
            pair
        } else {
            self.refresh_keys().await?;
            self.cached_key(&kid).await.ok_or_else(|| {
                debug!(kid = %kid, "K8s SA JWT kid not found in apiserver JWKS");
                Status::unauthenticated("invalid token: unknown signing key")
            })?
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.algorithms = vec![Algorithm::RS256];
        validation.set_issuer(&[&issuer]);
        validation.set_audience(&[&self.expected_audience]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);

        let data = decode::<K8sSaClaims>(token, &key, &validation).map_err(|e| {
            debug!(error = %e, "K8s SA JWT validation failed");
            Status::unauthenticated(format!("invalid SA token: {e}"))
        })?;
        Ok(data.claims)
    }

    async fn cached_key(&self, kid: &str) -> Option<(String, DecodingKey)> {
        let state = self.state.read().await;
        let issuer = state.issuer.clone()?;
        let key = state.keys.get(kid).cloned()?;
        Some((issuer, key))
    }

    /// Fetch the discovery document + JWKS and replace the cached state.
    /// Coalesces concurrent refreshes so the apiserver sees one fetch.
    #[allow(clippy::result_large_err)]
    async fn refresh_keys(&self) -> Result<(), Status> {
        let _guard = self.refresh.lock().await;
        info!("refreshing K8s apiserver JWKS");
        let discovery: ApiserverDiscovery = self
            .request_apiserver("/.well-known/openid-configuration")
            .await?;
        let jwks_path = jwks_path_from_uri(&discovery.jwks_uri).ok_or_else(|| {
            Status::internal(format!(
                "apiserver returned unusable jwks_uri '{}'",
                discovery.jwks_uri
            ))
        })?;
        let jwks: JwkSet = self.request_apiserver(&jwks_path).await?;
        let mut keys = HashMap::new();
        for key in &jwks.keys {
            if key.kty != "RSA" {
                continue;
            }
            let Some(ref kid) = key.kid else {
                continue;
            };
            if let Some(alg) = key.alg.as_deref()
                && alg != "RS256"
            {
                continue;
            }
            match DecodingKey::from_rsa_components(&key.n, &key.e) {
                Ok(dk) => {
                    keys.insert(kid.clone(), dk);
                }
                Err(e) => warn!(kid = %kid, error = %e, "skipped malformed apiserver JWK"),
            }
        }
        info!(
            count = keys.len(),
            issuer = %discovery.issuer,
            "loaded apiserver JWKS"
        );
        let mut state = self.state.write().await;
        state.issuer = Some(discovery.issuer);
        state.jwks_path = Some(jwks_path);
        state.keys = keys;
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    async fn request_apiserver<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, Status> {
        let req = http::Request::builder()
            .uri(path)
            .body(Vec::new())
            .map_err(|e| Status::internal(format!("apiserver request build: {e}")))?;
        self.client
            .request::<T>(req)
            .await
            .map_err(|e| Status::internal(format!("apiserver request failed: {e}")))
    }
}

/// Pull a path-only URI out of the `jwks_uri` field. The apiserver's
/// discovery doc returns an absolute URL (e.g.
/// `https://kubernetes.default.svc.cluster.local/openid/v1/jwks`); we
/// strip to the path so `kube::Client::request` can be reused.
fn jwks_path_from_uri(uri: &str) -> Option<String> {
    if uri.starts_with('/') {
        return Some(uri.to_string());
    }
    let parsed = url::Url::parse(uri).ok()?;
    let mut out = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        out.push('?');
        out.push_str(q);
    }
    Some(out)
}

/// Resolver backed by the apiserver's JWKS endpoint (for SA-token
/// signature verification) and `kube::Client` (for the per-pod
/// annotation lookup).
pub struct LiveK8sResolver {
    jwks: Arc<K8sApiserverJwks>,
    pods_api: Api<Pod>,
}

impl LiveK8sResolver {
    pub fn new(client: kube::Client, namespace: &str, expected_audience: String) -> Self {
        let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let jwks = Arc::new(K8sApiserverJwks::new(client, expected_audience));
        Self { jwks, pods_api }
    }
}

#[async_trait]
impl K8sIdentityResolver for LiveK8sResolver {
    async fn resolve(&self, token: &str) -> Result<Option<ResolvedK8sIdentity>, Status> {
        let claims = match self.jwks.validate(token).await {
            Ok(c) => c,
            Err(status) if status.code() == tonic::Code::Unauthenticated => {
                // Returning Ok(None) lets the chain fall through; the
                // outer router then returns Unauthenticated to the client.
                return Ok(None);
            }
            Err(other) => return Err(other),
        };

        debug!(
            sub = %claims.sub,
            iss = %claims.iss,
            pod_name = %claims.kubernetes.pod.name,
            "validated K8s SA token"
        );

        // Look up the pod and read its sandbox-id annotation.
        let pod = self
            .pods_api
            .get_opt(&claims.kubernetes.pod.name)
            .await
            .map_err(|e| {
                warn!(
                    pod = %claims.kubernetes.pod.name,
                    error = %e,
                    "failed to fetch sandbox pod for annotation lookup"
                );
                Status::internal(format!("pod GET failed: {e}"))
            })?;
        let Some(pod) = pod else {
            warn!(
                pod = %claims.kubernetes.pod.name,
                "sandbox pod referenced by SA token not found in this namespace"
            );
            return Err(Status::not_found("sandbox pod not found"));
        };

        // Defense-in-depth: confirm the pod UID matches the SA token's
        // `kubernetes.io.pod.uid`. Prevents a replayed token from a
        // recreated pod with the same name.
        let actual_uid = pod.metadata.uid.as_deref().unwrap_or_default();
        if actual_uid != claims.kubernetes.pod.uid {
            warn!(
                pod = %claims.kubernetes.pod.name,
                claimed_uid = %claims.kubernetes.pod.uid,
                actual_uid = %actual_uid,
                "SA token pod UID does not match live pod; rejecting"
            );
            return Err(Status::permission_denied("SA token pod UID mismatch"));
        }

        let sandbox_id = pod
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(SANDBOX_ID_ANNOTATION))
            .cloned()
            .unwrap_or_default();

        Ok(Some(ResolvedK8sIdentity {
            sandbox_id,
            pod_name: claims.kubernetes.pod.name,
            pod_uid: claims.kubernetes.pod.uid,
        }))
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

    #[test]
    fn jwks_path_extracts_absolute_url() {
        let path =
            jwks_path_from_uri("https://kubernetes.default.svc.cluster.local/openid/v1/jwks")
                .expect("apiserver-style URL must parse");
        assert_eq!(path, "/openid/v1/jwks");
    }

    #[test]
    fn jwks_path_preserves_relative_path() {
        let path = jwks_path_from_uri("/openid/v1/jwks").expect("relative path must round-trip");
        assert_eq!(path, "/openid/v1/jwks");
    }

    #[test]
    fn jwks_path_preserves_query_string() {
        let path = jwks_path_from_uri("https://apiserver/openid/v1/jwks?version=v1")
            .expect("query strings must be preserved");
        assert_eq!(path, "/openid/v1/jwks?version=v1");
    }

    #[test]
    fn jwks_path_rejects_garbage() {
        assert!(jwks_path_from_uri("not a url").is_none());
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
