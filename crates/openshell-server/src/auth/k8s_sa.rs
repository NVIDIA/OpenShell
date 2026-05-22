// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes `ServiceAccount` bootstrap authenticator.
//!
//! Path-scoped to `IssueSandboxToken`. Validates a projected SA token
//! presented by a sandbox pod, reads the pod's `openshell.io/sandbox-id`
//! annotation, verifies the pod is controlled by the corresponding Sandbox CR,
//! and returns a [`Principal::Sandbox`] with
//! [`SandboxIdentitySource::K8sServiceAccount`]. The `IssueSandboxToken` handler
//! then mints a gateway-signed JWT for that sandbox id; subsequent gRPC calls
//! from the supervisor use the gateway-minted JWT validated by
//! [`super::sandbox_jwt::SandboxJwtAuthenticator`].
//!
//! This is the only authenticator that talks to the K8s apiserver. It is
//! optional — the gateway boots without it in singleplayer deployments.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use async_trait::async_trait;
use k8s_openapi::api::{
    authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo},
    core::v1::Pod,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, ApiResource, PostParams};
use kube::core::{DynamicObject, gvk::GroupVersionKind};
use std::sync::Arc;
use tonic::Status;
use tracing::{debug, info, warn};

/// gRPC method path that this authenticator accepts. All other paths fall
/// through (return `Ok(None)`) so a gateway-minted JWT is required there.
pub const ISSUE_SANDBOX_TOKEN_PATH: &str = "/openshell.v1.OpenShell/IssueSandboxToken";

/// Pod annotation that binds a sandbox pod to its UUID. Set by the
/// Kubernetes compute driver at pod-create time. The gateway accepts this
/// annotation only after validating the pod's `TokenReview` binding, live UID,
/// and owning Sandbox CR. The K8s `Role` granted to the gateway must not
/// include `patch pods` (see plan §11.8).
pub const SANDBOX_ID_ANNOTATION: &str = "openshell.io/sandbox-id";
const SANDBOX_API_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_API_VERSION: &str = "v1alpha1";
const SANDBOX_API_VERSION_FULL: &str = "agents.x-k8s.io/v1alpha1";
const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_ID_LABEL: &str = "openshell.ai/sandbox-id";
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";

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

#[derive(Debug)]
struct TokenReviewIdentity {
    pod_name: String,
    pod_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxOwnerReference {
    name: String,
    uid: String,
}

/// Resolver backed by the apiserver's `TokenReview` API and `kube::Client`
/// for the per-pod annotation lookup.
pub struct LiveK8sResolver {
    token_reviews_api: Api<TokenReview>,
    pods_api: Api<Pod>,
    sandboxes_api: Api<DynamicObject>,
    expected_audience: String,
    sandbox_namespace: String,
    expected_service_account: String,
}

impl LiveK8sResolver {
    pub fn new(
        client: kube::Client,
        namespace: &str,
        expected_audience: String,
        expected_service_account: String,
    ) -> Self {
        let token_reviews_api: Api<TokenReview> = Api::all(client.clone());
        let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let sandbox_gvk =
            GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let sandbox_resource = ApiResource::from_gvk(&sandbox_gvk);
        let sandboxes_api: Api<DynamicObject> =
            Api::namespaced_with(client, namespace, &sandbox_resource);
        Self {
            token_reviews_api,
            pods_api,
            sandboxes_api,
            expected_audience,
            sandbox_namespace: namespace.to_string(),
            expected_service_account,
        }
    }
}

#[async_trait]
impl K8sIdentityResolver for LiveK8sResolver {
    async fn resolve(&self, token: &str) -> Result<Option<ResolvedK8sIdentity>, Status> {
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
            .map_err(|e| {
                warn!(error = %e, "K8s TokenReview failed");
                Status::internal(format!("tokenreview failed: {e}"))
            })?;
        let status = review
            .status
            .ok_or_else(|| Status::internal("TokenReview response missing status"))?;
        let Some(identity) = token_review_identity(
            &status,
            &self.expected_audience,
            &self.sandbox_namespace,
            &self.expected_service_account,
        )?
        else {
            return Ok(None);
        };

        info!(
            pod_name = %identity.pod_name,
            pod_uid = %identity.pod_uid,
            service_account = %self.expected_service_account,
            "validated K8s SA token via TokenReview"
        );

        // Look up the pod and read its sandbox-id annotation.
        let pod = self
            .pods_api
            .get_opt(&identity.pod_name)
            .await
            .map_err(|e| {
                warn!(
                    pod = %identity.pod_name,
                    error = %e,
                    "failed to fetch sandbox pod for annotation lookup"
                );
                Status::internal(format!("pod GET failed: {e}"))
            })?;
        let Some(pod) = pod else {
            warn!(
                pod = %identity.pod_name,
                "sandbox pod referenced by SA token not found in this namespace"
            );
            return Err(Status::not_found("sandbox pod not found"));
        };

        // Defense-in-depth: confirm the pod UID matches the SA token's
        // `kubernetes.io.pod.uid`. Prevents a replayed token from a
        // recreated pod with the same name.
        let actual_uid = pod.metadata.uid.as_deref().unwrap_or_default();
        if actual_uid != identity.pod_uid {
            warn!(
                pod = %identity.pod_name,
                claimed_uid = %identity.pod_uid,
                actual_uid = %actual_uid,
                "SA token pod UID does not match live pod; rejecting"
            );
            return Err(Status::permission_denied("SA token pod UID mismatch"));
        }

        let sandbox_id = pod_sandbox_id(&pod)?;

        let owner = sandbox_owner_reference(&pod)?;
        let sandbox_cr = self.sandboxes_api.get_opt(&owner.name).await.map_err(|e| {
            warn!(
                pod = %identity.pod_name,
                sandbox_owner = %owner.name,
                error = %e,
                "failed to fetch owning Sandbox CR for pod identity validation"
            );
            Status::internal(format!("sandbox GET failed: {e}"))
        })?;
        let Some(sandbox_cr) = sandbox_cr else {
            warn!(
                pod = %identity.pod_name,
                sandbox_owner = %owner.name,
                "pod ownerReference points to a Sandbox CR that does not exist"
            );
            return Err(Status::permission_denied("sandbox owner not found"));
        };
        validate_sandbox_owner_reference(&owner, &sandbox_id, &sandbox_cr)?;

        Ok(Some(ResolvedK8sIdentity {
            sandbox_id,
            pod_name: identity.pod_name,
            pod_uid: identity.pod_uid,
        }))
    }
}

#[allow(clippy::result_large_err)]
fn token_review_identity(
    status: &TokenReviewStatus,
    expected_audience: &str,
    sandbox_namespace: &str,
    expected_service_account: &str,
) -> Result<Option<TokenReviewIdentity>, Status> {
    if status.authenticated != Some(true) {
        debug!(
            error = status.error.as_deref().unwrap_or_default(),
            "K8s TokenReview did not authenticate token"
        );
        return Ok(None);
    }

    let audiences = status.audiences.as_deref().unwrap_or_default();
    if !audiences.iter().any(|aud| aud == expected_audience) {
        warn!(
            expected_audience = %expected_audience,
            audiences = ?audiences,
            "K8s TokenReview authenticated token without expected audience"
        );
        return Err(Status::unauthenticated("SA token audience not accepted"));
    }

    let user = status
        .user
        .as_ref()
        .ok_or_else(|| Status::permission_denied("TokenReview response missing user info"))?;
    let username = user
        .username
        .as_deref()
        .ok_or_else(|| Status::permission_denied("TokenReview response missing username"))?;
    let expected_username =
        format!("system:serviceaccount:{sandbox_namespace}:{expected_service_account}");
    if username != expected_username {
        warn!(
            username = %username,
            sandbox_namespace = %sandbox_namespace,
            service_account = %expected_service_account,
            "K8s TokenReview principal is not the configured sandbox service account"
        );
        return Err(Status::permission_denied(
            "SA token is not from the configured sandbox service account",
        ));
    }

    let pod_name = user_extra_one(user, POD_NAME_EXTRA)?;
    let pod_uid = user_extra_one(user, POD_UID_EXTRA)?;
    Ok(Some(TokenReviewIdentity { pod_name, pod_uid }))
}

#[allow(clippy::result_large_err)]
fn user_extra_one(user: &UserInfo, key: &str) -> Result<String, Status> {
    let Some(values) = user.extra.as_ref().and_then(|extra| extra.get(key)) else {
        return Err(Status::permission_denied("SA token is not pod-bound"));
    };
    if values.len() != 1 || values[0].is_empty() {
        return Err(Status::permission_denied(
            "SA token has invalid pod binding",
        ));
    }
    Ok(values[0].clone())
}

#[allow(clippy::result_large_err)]
fn pod_sandbox_id(pod: &Pod) -> Result<String, Status> {
    let sandbox_id = pod
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(SANDBOX_ID_ANNOTATION))
        .cloned()
        .unwrap_or_default();
    if sandbox_id.is_empty() {
        return Err(Status::permission_denied(
            "pod is not bound to a sandbox identity",
        ));
    }
    Ok(sandbox_id)
}

#[allow(clippy::result_large_err)]
fn sandbox_owner_reference(pod: &Pod) -> Result<SandboxOwnerReference, Status> {
    let owner_refs = pod.metadata.owner_references.as_deref().unwrap_or_default();
    let mut sandbox_refs = owner_refs.iter().filter(|owner| {
        owner.api_version == SANDBOX_API_VERSION_FULL && owner.kind == SANDBOX_KIND
    });
    let Some(owner) = sandbox_refs.next() else {
        return Err(Status::permission_denied(
            "pod is not controlled by an OpenShell Sandbox",
        ));
    };
    if sandbox_refs.next().is_some() {
        return Err(Status::permission_denied(
            "pod has multiple OpenShell Sandbox owners",
        ));
    }
    if owner.controller != Some(true) {
        return Err(Status::permission_denied(
            "pod Sandbox ownerReference is not controlling",
        ));
    }
    if owner.name.is_empty() || owner.uid.is_empty() {
        return Err(Status::permission_denied(
            "pod Sandbox ownerReference is incomplete",
        ));
    }
    Ok(SandboxOwnerReference {
        name: owner.name.clone(),
        uid: owner.uid.clone(),
    })
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_owner_reference(
    owner: &SandboxOwnerReference,
    sandbox_id: &str,
    sandbox_cr: &DynamicObject,
) -> Result<(), Status> {
    let actual_uid = sandbox_cr.metadata.uid.as_deref().unwrap_or_default();
    if actual_uid != owner.uid {
        warn!(
            sandbox_owner = %owner.name,
            owner_uid = %owner.uid,
            actual_uid = %actual_uid,
            "pod Sandbox ownerReference UID does not match live Sandbox CR"
        );
        return Err(Status::permission_denied("sandbox owner UID mismatch"));
    }

    let actual_sandbox_id = sandbox_cr
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(SANDBOX_ID_LABEL))
        .map(String::as_str)
        .unwrap_or_default();
    if actual_sandbox_id != sandbox_id {
        warn!(
            sandbox_owner = %owner.name,
            owner_uid = %owner.uid,
            pod_sandbox_id = %sandbox_id,
            cr_sandbox_id = %actual_sandbox_id,
            "pod sandbox annotation does not match owning Sandbox CR label"
        );
        return Err(Status::permission_denied("sandbox owner ID mismatch"));
    }

    Ok(())
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
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    use std::collections::BTreeMap;

    fn bearer_headers(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
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
                        .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                        .collect::<BTreeMap<_, _>>(),
                ),
            }),
        }
    }

    fn sandbox_owner(name: &str, uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: SANDBOX_API_VERSION_FULL.to_string(),
            block_owner_deletion: None,
            controller: Some(true),
            kind: SANDBOX_KIND.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
        }
    }

    fn pod_with_owner_refs(owner_references: Vec<OwnerReference>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                owner_references: Some(owner_references),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn pod_with_sandbox_id(sandbox_id: Option<&str>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                annotations: sandbox_id.map(|id| {
                    BTreeMap::from([(SANDBOX_ID_ANNOTATION.to_string(), id.to_string())])
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn sandbox_cr(name: &str, uid: &str, sandbox_id: &str) -> DynamicObject {
        let sandbox_gvk =
            GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let sandbox_resource = ApiResource::from_gvk(&sandbox_gvk);
        let mut cr = DynamicObject::new(name, &sandbox_resource);
        cr.metadata.uid = Some(uid.to_string());
        cr.metadata.labels = Some(BTreeMap::from([(
            SANDBOX_ID_LABEL.to_string(),
            sandbox_id.to_string(),
        )]));
        cr
    }

    #[test]
    fn token_review_identity_extracts_pod_binding() {
        let status = token_review_status(
            true,
            vec!["openshell-gateway"],
            "system:serviceaccount:openshell:default",
            vec![
                (POD_NAME_EXTRA, "openshell-sandbox-a"),
                (POD_UID_EXTRA, "uid-a"),
            ],
        );

        let identity = token_review_identity(&status, "openshell-gateway", "openshell", "default")
            .unwrap()
            .expect("authenticated token should resolve");

        assert_eq!(identity.pod_name, "openshell-sandbox-a");
        assert_eq!(identity.pod_uid, "uid-a");
    }

    #[test]
    fn token_review_identity_returns_none_when_not_authenticated() {
        let status = TokenReviewStatus {
            authenticated: Some(false),
            error: Some("invalid audience".to_string()),
            ..Default::default()
        };

        assert!(
            token_review_identity(&status, "openshell-gateway", "openshell", "default")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn token_review_identity_requires_expected_audience() {
        let status = token_review_status(
            true,
            vec!["kubernetes.default.svc"],
            "system:serviceaccount:openshell:default",
            vec![
                (POD_NAME_EXTRA, "openshell-sandbox-a"),
                (POD_UID_EXTRA, "uid-a"),
            ],
        );

        let err = token_review_identity(&status, "openshell-gateway", "openshell", "default")
            .expect_err("wrong audience must fail closed");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn token_review_identity_requires_sandbox_namespace() {
        let status = token_review_status(
            true,
            vec!["openshell-gateway"],
            "system:serviceaccount:other:default",
            vec![
                (POD_NAME_EXTRA, "openshell-sandbox-a"),
                (POD_UID_EXTRA, "uid-a"),
            ],
        );

        let err = token_review_identity(&status, "openshell-gateway", "openshell", "default")
            .expect_err("other namespace must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn token_review_identity_requires_configured_service_account() {
        let status = token_review_status(
            true,
            vec!["openshell-gateway"],
            "system:serviceaccount:openshell:other",
            vec![
                (POD_NAME_EXTRA, "openshell-sandbox-a"),
                (POD_UID_EXTRA, "uid-a"),
            ],
        );

        let err = token_review_identity(&status, "openshell-gateway", "openshell", "default")
            .expect_err("other service account must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn token_review_identity_requires_pod_bound_extras() {
        let status = token_review_status(
            true,
            vec!["openshell-gateway"],
            "system:serviceaccount:openshell:default",
            vec![],
        );

        let err = token_review_identity(&status, "openshell-gateway", "openshell", "default")
            .expect_err("non pod-bound tokens must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn pod_sandbox_id_requires_annotation() {
        assert_eq!(
            pod_sandbox_id(&pod_with_sandbox_id(Some("sandbox-id-a"))).unwrap(),
            "sandbox-id-a"
        );

        let err = pod_sandbox_id(&pod_with_sandbox_id(None))
            .expect_err("missing sandbox-id annotation must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn sandbox_owner_reference_extracts_controlling_sandbox_owner() {
        let pod = pod_with_owner_refs(vec![sandbox_owner("sandbox-a", "cr-uid-a")]);

        let owner = sandbox_owner_reference(&pod).expect("expected Sandbox owner");

        assert_eq!(
            owner,
            SandboxOwnerReference {
                name: "sandbox-a".to_string(),
                uid: "cr-uid-a".to_string(),
            }
        );
    }

    #[test]
    fn sandbox_owner_reference_rejects_missing_owner() {
        let pod = pod_with_owner_refs(vec![]);

        let err = sandbox_owner_reference(&pod).expect_err("missing owner must fail");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn sandbox_owner_reference_requires_controlling_owner() {
        let mut owner = sandbox_owner("sandbox-a", "cr-uid-a");
        owner.controller = Some(false);
        let pod = pod_with_owner_refs(vec![owner]);

        let err = sandbox_owner_reference(&pod).expect_err("non-controller owner must fail");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn sandbox_owner_reference_rejects_ambiguous_sandbox_owners() {
        let pod = pod_with_owner_refs(vec![
            sandbox_owner("sandbox-a", "cr-uid-a"),
            sandbox_owner("sandbox-b", "cr-uid-b"),
        ]);

        let err = sandbox_owner_reference(&pod).expect_err("multiple owners must fail");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn validate_sandbox_owner_reference_requires_matching_cr_uid_and_label() {
        let owner = SandboxOwnerReference {
            name: "sandbox-a".to_string(),
            uid: "cr-uid-a".to_string(),
        };
        let cr = sandbox_cr("sandbox-a", "cr-uid-a", "sandbox-id-a");
        validate_sandbox_owner_reference(&owner, "sandbox-id-a", &cr)
            .expect("matching CR should be accepted");

        let wrong_uid = sandbox_cr("sandbox-a", "cr-uid-b", "sandbox-id-a");
        let err = validate_sandbox_owner_reference(&owner, "sandbox-id-a", &wrong_uid)
            .expect_err("wrong CR UID must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let wrong_label = sandbox_cr("sandbox-a", "cr-uid-a", "sandbox-id-b");
        let err = validate_sandbox_owner_reference(&owner, "sandbox-id-a", &wrong_label)
            .expect_err("wrong sandbox-id label must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
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
