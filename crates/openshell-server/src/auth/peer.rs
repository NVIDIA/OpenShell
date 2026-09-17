// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway peer authentication for internal replica-to-replica RPCs.
//!
//! Peer calls use Kubernetes projected `ServiceAccount` tokens, not an
//! OpenShell-managed shared secret. The caller presents its pod-bound gateway
//! `ServiceAccount` token with the peer audience; the receiver validates it with
//! the apiserver `TokenReview` API, checks the live pod UID and required labels,
//! and only then produces a [`Principal::Peer`].

use super::authenticator::Authenticator;
use super::principal::{PeerPrincipal, Principal};
use async_trait::async_trait;
use k8s_openapi::api::{
    authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo},
    core::v1::Pod,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::Status;
use tracing::{debug, info, warn};

/// gRPC path for internal gateway relay forwarding.
pub const PEER_RELAY_PATH: &str = "/openshell.v1.OpenShell/PeerRelay";
/// Audience used for gateway-to-gateway projected `ServiceAccount` tokens.
pub const DEFAULT_PEER_TOKEN_AUDIENCE: &str = "openshell-gateway-peer";
/// Environment variable overriding the expected peer token audience.
pub const PEER_TOKEN_AUDIENCE_ENV: &str = "OPENSHELL_PEER_TOKEN_AUDIENCE";
/// Environment variable carrying the projected peer `ServiceAccount` token path.
/// Uses the `*_TOKEN_FILE` convention from sandbox token env vars.
pub const PEER_SA_TOKEN_FILE_ENV: &str = "OPENSHELL_PEER_SERVICE_ACCOUNT_TOKEN_FILE";
/// Default mount path for the projected peer `ServiceAccount` token.
pub const DEFAULT_PEER_SA_TOKEN_FILE: &str = "/var/run/secrets/openshell-peer/token";
/// Environment variable with comma-separated `key=value` pod labels required
/// on authenticated gateway peer pods.
pub const PEER_REQUIRED_POD_LABELS_ENV: &str = "OPENSHELL_PEER_POD_LABELS";
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";

#[derive(Debug, Clone)]
pub struct ResolvedGatewayPeerIdentity {
    pub pod_name: String,
    pub pod_uid: String,
}

#[async_trait]
pub trait GatewayPeerIdentityResolver: Send + Sync + 'static {
    async fn resolve(&self, token: &str) -> Result<Option<ResolvedGatewayPeerIdentity>, Status>;
}

#[derive(Debug)]
struct PeerTokenReviewIdentity {
    pod_name: String,
    pod_uid: String,
}

pub struct PeerServiceAccountAuthenticator {
    resolver: Arc<dyn GatewayPeerIdentityResolver>,
}

impl std::fmt::Debug for PeerServiceAccountAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerServiceAccountAuthenticator")
            .finish_non_exhaustive()
    }
}

impl PeerServiceAccountAuthenticator {
    pub fn new(resolver: Arc<dyn GatewayPeerIdentityResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl Authenticator for PeerServiceAccountAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        path: &str,
    ) -> Result<Option<Principal>, Status> {
        if path != PEER_RELAY_PATH {
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
            debug!("K8s gateway peer token did not authenticate; falling through");
            return Ok(None);
        };

        if let Some(claimed_replica) = headers
            .get("x-openshell-peer-replica")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            && claimed_replica != resolved.pod_name.as_str()
        {
            warn!(
                claimed_replica,
                pod_name = %resolved.pod_name,
                "gateway peer replica header does not match authenticated pod"
            );
            return Err(Status::permission_denied(
                "gateway peer replica does not match authenticated pod",
            ));
        }

        Ok(Some(Principal::Peer(PeerPrincipal {
            replica_id: resolved.pod_name,
            pod_uid: resolved.pod_uid,
        })))
    }
}

/// Resolver backed by Kubernetes `TokenReview` and a live Pod lookup.
pub struct LiveGatewayPeerResolver {
    token_reviews_api: Api<TokenReview>,
    pods_api: Api<Pod>,
    expected_audience: String,
    namespace: String,
    expected_service_account: String,
    required_pod_labels: Vec<(String, String)>,
}

impl LiveGatewayPeerResolver {
    pub fn new(
        client: kube::Client,
        namespace: &str,
        expected_audience: String,
        expected_service_account: String,
        required_pod_labels: Vec<(String, String)>,
    ) -> Self {
        let token_reviews_api: Api<TokenReview> = Api::all(client.clone());
        let pods_api: Api<Pod> = Api::namespaced(client, namespace);
        Self {
            token_reviews_api,
            pods_api,
            expected_audience,
            namespace: namespace.to_string(),
            expected_service_account,
            required_pod_labels,
        }
    }
}

#[async_trait]
impl GatewayPeerIdentityResolver for LiveGatewayPeerResolver {
    async fn resolve(&self, token: &str) -> Result<Option<ResolvedGatewayPeerIdentity>, Status> {
        let review = TokenReview {
            metadata: ObjectMeta::default(),
            spec: TokenReviewSpec {
                audiences: Some(vec![self.expected_audience.clone()]),
                token: Some(token.to_string()),
            },
            status: None,
        };

        let review = self
            .token_reviews_api
            .create(&PostParams::default(), &review)
            .await
            .map_err(|err| {
                warn!(error = %err, "K8s TokenReview failed for gateway peer");
                Status::internal(format!("peer tokenreview failed: {err}"))
            })?;
        let status = review
            .status
            .ok_or_else(|| Status::internal("TokenReview response missing status"))?;
        let Some(identity) = peer_token_review_identity(
            &status,
            &self.expected_audience,
            &self.namespace,
            &self.expected_service_account,
        )?
        else {
            return Ok(None);
        };

        let pod = self
            .pods_api
            .get_opt(&identity.pod_name)
            .await
            .map_err(|err| {
                warn!(
                    pod = %identity.pod_name,
                    error = %err,
                    "failed to fetch gateway peer pod"
                );
                Status::internal(format!("gateway peer pod GET failed: {err}"))
            })?;
        let Some(pod) = pod else {
            warn!(
                pod = %identity.pod_name,
                "gateway peer pod referenced by SA token not found"
            );
            return Err(Status::not_found("gateway peer pod not found"));
        };

        let actual_uid = pod.metadata.uid.as_deref().unwrap_or_default();
        if actual_uid != identity.pod_uid {
            warn!(
                pod = %identity.pod_name,
                claimed_uid = %identity.pod_uid,
                actual_uid,
                "gateway peer SA token pod UID does not match live pod"
            );
            return Err(Status::permission_denied(
                "gateway peer SA token pod UID mismatch",
            ));
        }

        let actual_service_account = pod
            .spec
            .as_ref()
            .and_then(|spec| spec.service_account_name.as_deref())
            .unwrap_or("default");
        if actual_service_account != self.expected_service_account {
            warn!(
                pod = %identity.pod_name,
                service_account = %actual_service_account,
                expected_service_account = %self.expected_service_account,
                "gateway peer pod service account does not match TokenReview principal"
            );
            return Err(Status::permission_denied(
                "gateway peer pod service account mismatch",
            ));
        }

        validate_required_pod_labels(&pod, &self.required_pod_labels)?;

        info!(
            pod_name = %identity.pod_name,
            pod_uid = %identity.pod_uid,
            service_account = %self.expected_service_account,
            "validated gateway peer ServiceAccount token via TokenReview"
        );

        Ok(Some(ResolvedGatewayPeerIdentity {
            pod_name: identity.pod_name,
            pod_uid: identity.pod_uid,
        }))
    }
}

#[allow(clippy::result_large_err)]
fn peer_token_review_identity(
    status: &TokenReviewStatus,
    expected_audience: &str,
    namespace: &str,
    expected_service_account: &str,
) -> Result<Option<PeerTokenReviewIdentity>, Status> {
    if status.authenticated != Some(true) {
        debug!(
            error = status.error.as_deref().unwrap_or_default(),
            "K8s TokenReview did not authenticate gateway peer token"
        );
        return Ok(None);
    }

    let audiences = status.audiences.as_deref().unwrap_or_default();
    if !audiences.iter().any(|aud| aud == expected_audience) {
        warn!(
            expected_audience,
            audiences = ?audiences,
            "K8s TokenReview authenticated gateway peer token without expected audience"
        );
        return Err(Status::unauthenticated(
            "gateway peer token audience not accepted",
        ));
    }

    let user = status
        .user
        .as_ref()
        .ok_or_else(|| Status::permission_denied("TokenReview response missing user info"))?;
    let username = user
        .username
        .as_deref()
        .ok_or_else(|| Status::permission_denied("TokenReview response missing username"))?;
    let expected_username = format!("system:serviceaccount:{namespace}:{expected_service_account}");
    if username != expected_username {
        warn!(
            username,
            namespace,
            service_account = %expected_service_account,
            "K8s TokenReview principal is not the configured gateway service account"
        );
        return Err(Status::permission_denied(
            "gateway peer token is not from the configured service account",
        ));
    }

    let pod_name = user_extra_one(user, POD_NAME_EXTRA)?;
    let pod_uid = user_extra_one(user, POD_UID_EXTRA)?;
    Ok(Some(PeerTokenReviewIdentity { pod_name, pod_uid }))
}

#[allow(clippy::result_large_err)]
fn user_extra_one(user: &UserInfo, key: &str) -> Result<String, Status> {
    let Some(values) = user.extra.as_ref().and_then(|extra| extra.get(key)) else {
        return Err(Status::permission_denied(
            "gateway peer token is not pod-bound",
        ));
    };
    if values.len() != 1 || values[0].is_empty() {
        return Err(Status::permission_denied(
            "gateway peer token has invalid pod binding",
        ));
    }
    Ok(values[0].clone())
}

#[allow(clippy::result_large_err)]
fn validate_required_pod_labels(
    pod: &Pod,
    required_labels: &[(String, String)],
) -> Result<(), Status> {
    let labels = pod.metadata.labels.as_ref();
    for (key, expected) in required_labels {
        let actual = labels
            .and_then(|labels| labels.get(key))
            .map(String::as_str)
            .unwrap_or_default();
        if actual != expected {
            warn!(
                pod = %pod.metadata.name.as_deref().unwrap_or_default(),
                label = %key,
                expected,
                actual,
                "gateway peer pod missing required label"
            );
            return Err(Status::permission_denied(
                "gateway peer pod labels do not match",
            ));
        }
    }
    Ok(())
}

pub fn peer_token_audience_from_env() -> String {
    std::env::var(PEER_TOKEN_AUDIENCE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PEER_TOKEN_AUDIENCE.to_string())
}

pub fn peer_service_account_token_file_from_env() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(PEER_SA_TOKEN_FILE_ENV)
        && !path.trim().is_empty()
    {
        return Some(PathBuf::from(path.trim()));
    }

    let default_path = PathBuf::from(DEFAULT_PEER_SA_TOKEN_FILE);
    default_path.exists().then_some(default_path)
}

pub fn load_peer_service_account_token_from_env() -> Result<Option<String>, String> {
    let Some(path) = peer_service_account_token_file_from_env() else {
        return Ok(None);
    };

    let contents = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let token = contents.trim();
    if token.is_empty() {
        return Err(format!(
            "peer ServiceAccount token file {} is empty",
            path.display()
        ));
    }

    Ok(Some(token.to_string()))
}

pub fn required_pod_labels_from_env() -> Result<Vec<(String, String)>, String> {
    let raw = std::env::var(PEER_REQUIRED_POD_LABELS_ENV).unwrap_or_default();
    parse_required_pod_labels(&raw)
}

fn parse_required_pod_labels(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut labels = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(format!(
                "{PEER_REQUIRED_POD_LABELS_ENV} entry {entry:?} must be key=value"
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "{PEER_REQUIRED_POD_LABELS_ENV} entry {entry:?} must have non-empty key and value"
            ));
        }
        labels.push((key.to_string(), value.to_string()));
    }
    Ok(labels)
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::Mutex;

    pub struct FakeGatewayPeerResolver {
        pub outcome: Result<Option<ResolvedGatewayPeerIdentity>, Status>,
        pub seen_tokens: Mutex<Vec<String>>,
    }

    impl FakeGatewayPeerResolver {
        pub fn returning(outcome: Result<Option<ResolvedGatewayPeerIdentity>, Status>) -> Self {
            Self {
                outcome,
                seen_tokens: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl GatewayPeerIdentityResolver for FakeGatewayPeerResolver {
        async fn resolve(
            &self,
            token: &str,
        ) -> Result<Option<ResolvedGatewayPeerIdentity>, Status> {
            self.seen_tokens.lock().unwrap().push(token.to_string());
            match &self.outcome {
                Ok(opt) => Ok(opt.clone()),
                Err(status) => Err(Status::new(status.code(), status.message())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeGatewayPeerResolver;
    use super::*;
    use std::collections::BTreeMap;

    fn bearer_headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    fn token_review_status(
        authenticated: bool,
        audiences: Vec<&str>,
        username: &str,
        extra: Vec<(&str, &str)>,
    ) -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(authenticated),
            audiences: Some(audiences.into_iter().map(str::to_string).collect()),
            error: None,
            user: Some(UserInfo {
                username: Some(username.to_string()),
                uid: Some("sa-uid".to_string()),
                groups: Some(vec![
                    "system:serviceaccounts".to_string(),
                    "system:serviceaccounts:openshell".to_string(),
                    "system:authenticated".to_string(),
                ]),
                extra: Some(
                    extra
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), vec![value.to_string()]))
                        .collect(),
                ),
            }),
        }
    }

    #[test]
    fn peer_token_review_identity_extracts_pod_binding() {
        let status = token_review_status(
            true,
            vec![DEFAULT_PEER_TOKEN_AUDIENCE],
            "system:serviceaccount:openshell:openshell",
            vec![(POD_NAME_EXTRA, "openshell-0"), (POD_UID_EXTRA, "uid-a")],
        );

        let identity = peer_token_review_identity(
            &status,
            DEFAULT_PEER_TOKEN_AUDIENCE,
            "openshell",
            "openshell",
        )
        .unwrap()
        .expect("authenticated token should resolve");

        assert_eq!(identity.pod_name, "openshell-0");
        assert_eq!(identity.pod_uid, "uid-a");
    }

    #[test]
    fn peer_token_review_identity_rejects_wrong_service_account() {
        let status = token_review_status(
            true,
            vec![DEFAULT_PEER_TOKEN_AUDIENCE],
            "system:serviceaccount:openshell:default",
            vec![(POD_NAME_EXTRA, "openshell-0"), (POD_UID_EXTRA, "uid-a")],
        );

        let err = peer_token_review_identity(
            &status,
            DEFAULT_PEER_TOKEN_AUDIENCE,
            "openshell",
            "openshell",
        )
        .expect_err("wrong service account must fail closed");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn validate_required_pod_labels_rejects_mismatch() {
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("openshell-0".to_string()),
                labels: Some(BTreeMap::from([(
                    "app.kubernetes.io/name".to_string(),
                    "openshell".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = validate_required_pod_labels(
            &pod,
            &[(
                "app.kubernetes.io/instance".to_string(),
                "release-a".to_string(),
            )],
        )
        .expect_err("missing required label must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn authenticator_uses_resolved_pod_name_as_replica() {
        let resolver = Arc::new(FakeGatewayPeerResolver::returning(Ok(Some(
            ResolvedGatewayPeerIdentity {
                pod_name: "openshell-0".to_string(),
                pod_uid: "uid-a".to_string(),
            },
        ))));
        let auth = PeerServiceAccountAuthenticator::new(resolver);

        let principal = auth
            .authenticate(&bearer_headers("token-a"), PEER_RELAY_PATH)
            .await
            .unwrap()
            .expect("principal");

        let Principal::Peer(peer) = principal else {
            panic!("expected peer principal");
        };
        assert_eq!(peer.replica_id, "openshell-0");
        assert_eq!(peer.pod_uid, "uid-a");
    }

    #[test]
    fn parse_required_pod_labels_accepts_comma_list() {
        let labels = parse_required_pod_labels(
            "app.kubernetes.io/name=openshell,app.kubernetes.io/instance=dev",
        )
        .unwrap();
        assert_eq!(
            labels,
            vec![
                (
                    "app.kubernetes.io/name".to_string(),
                    "openshell".to_string()
                ),
                ("app.kubernetes.io/instance".to_string(), "dev".to_string())
            ]
        );
    }
}
