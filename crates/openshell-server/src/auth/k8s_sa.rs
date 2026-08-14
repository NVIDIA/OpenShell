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
use kube::Error as KubeError;
use kube::api::{Api, ApiResource, PostParams};
use kube::core::{DynamicObject, gvk::GroupVersionKind};
use openshell_driver_kubernetes::OperatorNamespaceAllowlist;
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
const SANDBOX_API_VERSION_V1BETA1: &str = "v1beta1";
const SANDBOX_API_VERSION_V1ALPHA1: &str = "v1alpha1";
const SANDBOX_API_VERSION_FULL_V1BETA1: &str = "agents.x-k8s.io/v1beta1";
const SANDBOX_API_VERSION_FULL_V1ALPHA1: &str = "agents.x-k8s.io/v1alpha1";
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

/// Validates the namespace extracted from an SA token username against the
/// expected set for the active workspace mode.
#[derive(Debug, Clone)]
pub enum NamespaceValidator {
    /// Shared mode: accept only the single configured namespace.
    Exact(String),
    /// Managed mode: accept any namespace with the managed prefix
    /// (`openshell-{gateway_id}-`).
    Prefix(String),
    /// Operator mode: accept namespaces in the dynamic allowlist.
    Allowlist(OperatorNamespaceAllowlist),
}

impl NamespaceValidator {
    pub fn accepts(&self, namespace: &str) -> bool {
        match self {
            Self::Exact(expected) => namespace == expected,
            Self::Prefix(prefix) => namespace.starts_with(prefix.as_str()),
            Self::Allowlist(al) => al.contains(namespace),
        }
    }
}

#[derive(Debug)]
struct TokenReviewIdentity {
    namespace: String,
    pod_name: String,
    pod_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxOwnerReference {
    api_version: String,
    name: String,
    uid: String,
}

/// Resolver backed by the apiserver's `TokenReview` API and `kube::Client`
/// for the per-pod annotation lookup.
pub struct LiveK8sResolver {
    client: kube::Client,
    token_reviews_api: Api<TokenReview>,
    expected_audience: String,
    namespace_validator: NamespaceValidator,
    expected_service_account: String,
}

impl LiveK8sResolver {
    pub fn new(
        client: kube::Client,
        namespace_validator: NamespaceValidator,
        expected_audience: String,
        expected_service_account: String,
    ) -> Self {
        let token_reviews_api: Api<TokenReview> = Api::all(client.clone());
        Self {
            client,
            token_reviews_api,
            expected_audience,
            namespace_validator,
            expected_service_account,
        }
    }

    fn pods_api(&self, namespace: &str) -> Api<Pod> {
        Api::namespaced(self.client.clone(), namespace)
    }

    fn sandboxes_api(&self, namespace: &str, api_version: &str) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_API_GROUP, api_version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        Api::namespaced_with(self.client.clone(), namespace, &resource)
    }

    async fn get_sandbox_cr_for_owner(
        &self,
        namespace: &str,
        owner: &SandboxOwnerReference,
    ) -> Result<Option<DynamicObject>, KubeError> {
        let versions = if owner.api_version == SANDBOX_API_VERSION_FULL_V1ALPHA1 {
            [SANDBOX_API_VERSION_V1ALPHA1, SANDBOX_API_VERSION_V1BETA1]
        } else {
            [SANDBOX_API_VERSION_V1BETA1, SANDBOX_API_VERSION_V1ALPHA1]
        };

        for version in versions {
            let api = self.sandboxes_api(namespace, version);
            match api.get_opt(&owner.name).await {
                Ok(Some(sandbox_cr)) => return Ok(Some(sandbox_cr)),
                Ok(None) => {}
                Err(err) if should_try_next_sandbox_api_version(&err) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(None)
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
            &self.namespace_validator,
            &self.expected_service_account,
        )?
        else {
            return Ok(None);
        };

        info!(
            pod_name = %identity.pod_name,
            pod_uid = %identity.pod_uid,
            namespace = %identity.namespace,
            service_account = %self.expected_service_account,
            "validated K8s SA token via TokenReview"
        );

        let pods_api = self.pods_api(&identity.namespace);
        let pod = pods_api.get_opt(&identity.pod_name).await.map_err(|e| {
            warn!(
                pod = %identity.pod_name,
                namespace = %identity.namespace,
                error = %e,
                "failed to fetch sandbox pod for annotation lookup"
            );
            Status::internal(format!("pod GET failed: {e}"))
        })?;
        let Some(pod) = pod else {
            warn!(
                pod = %identity.pod_name,
                namespace = %identity.namespace,
                "sandbox pod referenced by SA token not found"
            );
            return Err(Status::not_found("sandbox pod not found"));
        };

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
        let sandbox_cr = self
            .get_sandbox_cr_for_owner(&identity.namespace, &owner)
            .await
            .map_err(|e| {
                warn!(
                    pod = %identity.pod_name,
                    sandbox_owner = %owner.name,
                    sandbox_owner_api_version = %owner.api_version,
                    error = %e,
                    "failed to fetch owning Sandbox CR for pod identity validation"
                );
                Status::internal(format!("sandbox GET failed: {e}"))
            })?;
        let Some(sandbox_cr) = sandbox_cr else {
            warn!(
                pod = %identity.pod_name,
                sandbox_owner = %owner.name,
                sandbox_owner_api_version = %owner.api_version,
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
    namespace_validator: &NamespaceValidator,
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

    let (namespace, sa_name) = parse_sa_username(username).ok_or_else(|| {
        warn!(
            username = %username,
            "K8s TokenReview username is not a service account"
        );
        Status::permission_denied("SA token username format not recognized")
    })?;

    if sa_name != expected_service_account {
        warn!(
            username = %username,
            service_account = %sa_name,
            expected = %expected_service_account,
            "K8s TokenReview principal is not the configured sandbox service account"
        );
        return Err(Status::permission_denied(
            "SA token is not from the configured sandbox service account",
        ));
    }

    if !namespace_validator.accepts(&namespace) {
        warn!(
            username = %username,
            namespace = %namespace,
            "K8s TokenReview SA namespace not accepted by workspace mode validator"
        );
        return Err(Status::permission_denied(
            "SA token is not from an accepted sandbox namespace",
        ));
    }

    let pod_name = user_extra_one(user, POD_NAME_EXTRA)?;
    let pod_uid = user_extra_one(user, POD_UID_EXTRA)?;
    Ok(Some(TokenReviewIdentity {
        namespace,
        pod_name,
        pod_uid,
    }))
}

fn parse_sa_username(username: &str) -> Option<(String, String)> {
    let rest = username.strip_prefix("system:serviceaccount:")?;
    let (namespace, sa_name) = rest.split_once(':')?;
    if namespace.is_empty() || sa_name.is_empty() {
        return None;
    }
    Some((namespace.to_string(), sa_name.to_string()))
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
    let mut sandbox_refs = owner_refs
        .iter()
        .filter(|owner| is_supported_sandbox_owner_reference(owner));
    let Some(owner) = sandbox_refs.next() else {
        let unsupported_sandbox_api_versions = owner_refs
            .iter()
            .filter(|owner| owner.kind == SANDBOX_KIND)
            .map(|owner| owner.api_version.as_str())
            .collect::<Vec<_>>();
        if !unsupported_sandbox_api_versions.is_empty() {
            warn!(
                api_versions = ?unsupported_sandbox_api_versions,
                supported_api_versions = ?[
                    SANDBOX_API_VERSION_FULL_V1BETA1,
                    SANDBOX_API_VERSION_FULL_V1ALPHA1,
                ],
                "pod Sandbox ownerReference uses unsupported apiVersion"
            );
        }
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
        api_version: owner.api_version.clone(),
        name: owner.name.clone(),
        uid: owner.uid.clone(),
    })
}

fn is_supported_sandbox_owner_reference(
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
) -> bool {
    owner.kind == SANDBOX_KIND
        && matches!(
            owner.api_version.as_str(),
            SANDBOX_API_VERSION_FULL_V1BETA1 | SANDBOX_API_VERSION_FULL_V1ALPHA1
        )
}

fn should_try_next_sandbox_api_version(err: &KubeError) -> bool {
    // Kubernetes returns a structured 404 for some missing API resources and a
    // raw "404 page not found" body for others. Both mean the probed
    // group/version is unavailable and the next supported Sandbox API version
    // should be tried.
    matches!(err, KubeError::Api(api) if api.code == 404)
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

    fn kube_api_error(code: u16, message: &str) -> KubeError {
        KubeError::Api(kube::core::ErrorResponse {
            status: if code == 404 {
                "404 Not Found".to_string()
            } else {
                "Failure".to_string()
            },
            message: message.to_string(),
            reason: "Failed to parse error data".to_string(),
            code,
        })
    }

    #[test]
    fn sandbox_api_version_probe_retries_on_structured_and_raw_404() {
        let structured = kube_api_error(404, "could not find the requested resource");
        assert!(should_try_next_sandbox_api_version(&structured));

        let raw = kube_api_error(404, "404 page not found\n");
        assert!(should_try_next_sandbox_api_version(&raw));
    }

    #[test]
    fn sandbox_api_version_probe_keeps_non_404_errors() {
        let err = kube_api_error(403, "sandboxes.agents.x-k8s.io is forbidden");
        assert!(!should_try_next_sandbox_api_version(&err));
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
        sandbox_owner_with_api_version(SANDBOX_API_VERSION_FULL_V1BETA1, name, uid)
    }

    fn sandbox_owner_with_api_version(api_version: &str, name: &str, uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: api_version.to_string(),
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
            GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION_V1BETA1, SANDBOX_KIND);
        let sandbox_resource = ApiResource::from_gvk(&sandbox_gvk);
        let mut cr = DynamicObject::new(name, &sandbox_resource);
        cr.metadata.uid = Some(uid.to_string());
        cr.metadata.labels = Some(BTreeMap::from([(
            SANDBOX_ID_LABEL.to_string(),
            sandbox_id.to_string(),
        )]));
        cr
    }

    fn exact_validator(ns: &str) -> NamespaceValidator {
        NamespaceValidator::Exact(ns.to_string())
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

        let validator = exact_validator("openshell");
        let identity = token_review_identity(&status, "openshell-gateway", &validator, "default")
            .unwrap()
            .expect("authenticated token should resolve");

        assert_eq!(identity.namespace, "openshell");
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
        let validator = exact_validator("openshell");

        assert!(
            token_review_identity(&status, "openshell-gateway", &validator, "default")
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
        let validator = exact_validator("openshell");

        let err = token_review_identity(&status, "openshell-gateway", &validator, "default")
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
        let validator = exact_validator("openshell");

        let err = token_review_identity(&status, "openshell-gateway", &validator, "default")
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
        let validator = exact_validator("openshell");

        let err = token_review_identity(&status, "openshell-gateway", &validator, "default")
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
        let validator = exact_validator("openshell");

        let err = token_review_identity(&status, "openshell-gateway", &validator, "default")
            .expect_err("non pod-bound tokens must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn namespace_validator_exact_accepts_matching() {
        let v = NamespaceValidator::Exact("openshell".to_string());
        assert!(v.accepts("openshell"));
        assert!(!v.accepts("other"));
    }

    #[test]
    fn namespace_validator_prefix_accepts_managed_namespaces() {
        let v = NamespaceValidator::Prefix("openshell-gw1-".to_string());
        assert!(v.accepts("openshell-gw1-workspace-a"));
        assert!(v.accepts("openshell-gw1-default"));
        assert!(!v.accepts("openshell-gw2-workspace-a"));
        assert!(!v.accepts("other"));
    }

    #[test]
    fn namespace_validator_allowlist_accepts_known_namespaces() {
        let al = OperatorNamespaceAllowlist::from_set(std::collections::BTreeSet::from([
            "ns-a".to_string(),
            "ns-b".to_string(),
        ]));
        let v = NamespaceValidator::Allowlist(al);
        assert!(v.accepts("ns-a"));
        assert!(v.accepts("ns-b"));
        assert!(!v.accepts("ns-c"));
    }

    #[test]
    fn token_review_identity_prefix_validator_accepts_managed_namespace() {
        let status = token_review_status(
            true,
            vec!["openshell-gateway"],
            "system:serviceaccount:openshell-gw1-workspace-a:default",
            vec![
                (POD_NAME_EXTRA, "openshell-sandbox-a"),
                (POD_UID_EXTRA, "uid-a"),
            ],
        );
        let validator = NamespaceValidator::Prefix("openshell-gw1-".to_string());

        let identity = token_review_identity(&status, "openshell-gateway", &validator, "default")
            .unwrap()
            .expect("managed namespace token should resolve");
        assert_eq!(identity.namespace, "openshell-gw1-workspace-a");
    }

    #[test]
    fn parse_sa_username_extracts_namespace_and_sa() {
        let (ns, sa) = parse_sa_username("system:serviceaccount:openshell:default").unwrap();
        assert_eq!(ns, "openshell");
        assert_eq!(sa, "default");

        assert!(parse_sa_username("system:node:nodename").is_none());
        assert!(parse_sa_username("system:serviceaccount::default").is_none());
        assert!(parse_sa_username("system:serviceaccount:ns:").is_none());
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
                api_version: SANDBOX_API_VERSION_FULL_V1BETA1.to_string(),
                name: "sandbox-a".to_string(),
                uid: "cr-uid-a".to_string(),
            }
        );
    }

    #[test]
    fn sandbox_owner_reference_accepts_v1alpha1_owner() {
        let pod = pod_with_owner_refs(vec![sandbox_owner_with_api_version(
            SANDBOX_API_VERSION_FULL_V1ALPHA1,
            "sandbox-a",
            "cr-uid-a",
        )]);

        let owner = sandbox_owner_reference(&pod).expect("expected v1alpha1 Sandbox owner");

        assert_eq!(
            owner,
            SandboxOwnerReference {
                api_version: SANDBOX_API_VERSION_FULL_V1ALPHA1.to_string(),
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
    fn sandbox_owner_reference_rejects_unsupported_sandbox_api_version() {
        let pod = pod_with_owner_refs(vec![sandbox_owner_with_api_version(
            "agents.x-k8s.io/v1",
            "sandbox-a",
            "cr-uid-a",
        )]);

        let err =
            sandbox_owner_reference(&pod).expect_err("unsupported apiVersion must fail closed");

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
            api_version: SANDBOX_API_VERSION_FULL_V1BETA1.to_string(),
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
