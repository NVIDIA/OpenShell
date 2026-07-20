// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes `ServiceAccount` supervisor bootstrap identity provider.
//!
//! Validates a projected SA token presented by a sandbox pod, reads the pod's
//! `openshell.io/sandbox-id` annotation, verifies the pod is controlled by the
//! corresponding Sandbox CR, and returns a registration-only driver bootstrap
//! identity. Warm pods may register before they are bound to a sandbox, so this
//! identity must not grant sandbox-scoped RPC access.
//!
//! This is the Kubernetes driver's apiserver-facing side of the supervisor
//! bootstrap boundary. The gateway owns the public registration stream and
//! token minting.

use k8s_openapi::api::{
    authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo},
    core::v1::Pod,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Error as KubeError;
use kube::api::{Api, ApiResource, PostParams};
use kube::core::{DynamicObject, gvk::GroupVersionKind};
use openshell_core::supervisor_bootstrap::{
    SupervisorBootstrapBinding, SupervisorBootstrapIdentity, SupervisorBootstrapIdentityProvider,
};
use std::sync::Arc;
use tonic::Status;
use tonic::async_trait;
use tracing::{debug, info, warn};

/// Pod annotation that binds a sandbox pod to its UUID. Set by the
/// Kubernetes compute driver at pod-create time.
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

/// Apiserver-facing operations the authenticator depends on. Split out so
/// tests can fake the apiserver without standing up a kube cluster.
#[async_trait]
pub trait K8sIdentityResolver: Send + Sync + 'static {
    /// Validate `token` via `TokenReview` (`aud == openshell-gateway`),
    /// extract the pod name/uid, then `GET` the pod and owning Sandbox CR.
    /// Returns `Ok(None)` when the token is well-formed but does not
    /// authenticate (e.g. wrong audience); returns `Err` for
    /// transport/server errors.
    async fn resolve(&self, token: &str) -> Result<Option<SupervisorBootstrapIdentity>, Status>;
}

/// Kubernetes implementation of the driver bootstrap identity provider.
pub struct KubernetesSupervisorBootstrapIdentityProvider {
    resolver: Arc<dyn K8sIdentityResolver>,
}

impl std::fmt::Debug for KubernetesSupervisorBootstrapIdentityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesSupervisorBootstrapIdentityProvider")
            .finish_non_exhaustive()
    }
}

impl KubernetesSupervisorBootstrapIdentityProvider {
    pub fn new(resolver: Arc<dyn K8sIdentityResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl SupervisorBootstrapIdentityProvider for KubernetesSupervisorBootstrapIdentityProvider {
    async fn authenticate_registration(
        &self,
        token: &str,
    ) -> Result<Option<SupervisorBootstrapIdentity>, Status> {
        self.resolver.resolve(token).await
    }
}

#[derive(Debug)]
struct TokenReviewIdentity {
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
    token_reviews_api: Api<TokenReview>,
    pods_api: Api<Pod>,
    sandboxes_api_v1beta1: Api<DynamicObject>,
    sandboxes_api_v1alpha1: Api<DynamicObject>,
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
        let sandbox_gvk_v1beta1 =
            GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION_V1BETA1, SANDBOX_KIND);
        let sandbox_resource_v1beta1 = ApiResource::from_gvk(&sandbox_gvk_v1beta1);
        let sandbox_gvk_v1alpha1 = GroupVersionKind::gvk(
            SANDBOX_API_GROUP,
            SANDBOX_API_VERSION_V1ALPHA1,
            SANDBOX_KIND,
        );
        let sandbox_resource_v1alpha1 = ApiResource::from_gvk(&sandbox_gvk_v1alpha1);
        let sandboxes_api_v1beta1: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), namespace, &sandbox_resource_v1beta1);
        let sandboxes_api_v1alpha1: Api<DynamicObject> =
            Api::namespaced_with(client, namespace, &sandbox_resource_v1alpha1);
        Self {
            token_reviews_api,
            pods_api,
            sandboxes_api_v1beta1,
            sandboxes_api_v1alpha1,
            expected_audience,
            sandbox_namespace: namespace.to_string(),
            expected_service_account,
        }
    }

    async fn get_sandbox_cr_for_owner(
        &self,
        owner: &SandboxOwnerReference,
    ) -> Result<Option<DynamicObject>, KubeError> {
        let apis = if owner.api_version == SANDBOX_API_VERSION_FULL_V1ALPHA1 {
            [&self.sandboxes_api_v1alpha1, &self.sandboxes_api_v1beta1]
        } else {
            [&self.sandboxes_api_v1beta1, &self.sandboxes_api_v1alpha1]
        };

        for api in apis {
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
    async fn resolve(&self, token: &str) -> Result<Option<SupervisorBootstrapIdentity>, Status> {
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

        let sandbox_id = pod_sandbox_id(&pod);

        let owner = sandbox_owner_reference(&pod)?;
        let sandbox_cr = self.get_sandbox_cr_for_owner(&owner).await.map_err(|e| {
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
        validate_sandbox_owner_reference(&owner, &sandbox_cr)?;
        if let Some(ref sandbox_id) = sandbox_id {
            validate_sandbox_owner_binding(&owner, sandbox_id, &sandbox_cr)?;
        }

        let binding = sandbox_id.map_or(SupervisorBootstrapBinding::WarmPending, |sandbox_id| {
            SupervisorBootstrapBinding::BoundSandbox { sandbox_id }
        });

        Ok(Some(SupervisorBootstrapIdentity {
            driver: "kubernetes".to_string(),
            instance_name: identity.pod_name,
            instance_id: identity.pod_uid,
            owner_name: owner.name,
            owner_uid: owner.uid,
            binding,
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
fn pod_sandbox_id(pod: &Pod) -> Option<String> {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(SANDBOX_ID_ANNOTATION))
        .cloned()
        .filter(|sandbox_id| !sandbox_id.is_empty())
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

    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_owner_binding(
    owner: &SandboxOwnerReference,
    sandbox_id: &str,
    sandbox_cr: &DynamicObject,
) -> Result<(), Status> {
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
        pub outcome: Result<Option<SupervisorBootstrapIdentity>, Status>,
        pub seen_tokens: Mutex<Vec<String>>,
    }

    impl FakeResolver {
        pub fn returning(outcome: Result<Option<SupervisorBootstrapIdentity>, Status>) -> Self {
            Self {
                outcome,
                seen_tokens: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl K8sIdentityResolver for FakeResolver {
        async fn resolve(
            &self,
            token: &str,
        ) -> Result<Option<SupervisorBootstrapIdentity>, Status> {
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
    use std::sync::Arc;

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

    fn bootstrap_identity(binding: SupervisorBootstrapBinding) -> SupervisorBootstrapIdentity {
        SupervisorBootstrapIdentity {
            driver: "kubernetes".to_string(),
            instance_name: "openshell-sandbox-a".to_string(),
            instance_id: "uid-a".to_string(),
            owner_name: "sandbox-owner-a".to_string(),
            owner_uid: "cr-uid-a".to_string(),
            binding,
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
    fn pod_sandbox_id_is_optional_for_warm_registration() {
        assert_eq!(
            pod_sandbox_id(&pod_with_sandbox_id(Some("sandbox-id-a"))).as_deref(),
            Some("sandbox-id-a")
        );
        assert!(pod_sandbox_id(&pod_with_sandbox_id(None)).is_none());
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
    fn validate_sandbox_owner_reference_requires_matching_cr_uid() {
        let owner = SandboxOwnerReference {
            api_version: SANDBOX_API_VERSION_FULL_V1BETA1.to_string(),
            name: "sandbox-a".to_string(),
            uid: "cr-uid-a".to_string(),
        };
        let cr = sandbox_cr("sandbox-a", "cr-uid-a", "sandbox-id-a");
        validate_sandbox_owner_reference(&owner, &cr).expect("matching CR should be accepted");

        let wrong_uid = sandbox_cr("sandbox-a", "cr-uid-b", "sandbox-id-a");
        let err = validate_sandbox_owner_reference(&owner, &wrong_uid)
            .expect_err("wrong CR UID must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn validate_sandbox_owner_binding_requires_matching_label() {
        let owner = SandboxOwnerReference {
            api_version: SANDBOX_API_VERSION_FULL_V1BETA1.to_string(),
            name: "sandbox-a".to_string(),
            uid: "cr-uid-a".to_string(),
        };
        let cr = sandbox_cr("sandbox-a", "cr-uid-a", "sandbox-id-a");
        validate_sandbox_owner_binding(&owner, "sandbox-id-a", &cr)
            .expect("matching label should be accepted");
        let wrong_label = sandbox_cr("sandbox-a", "cr-uid-a", "sandbox-id-b");
        let err = validate_sandbox_owner_binding(&owner, "sandbox-id-a", &wrong_label)
            .expect_err("wrong sandbox-id label must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn provider_delegates_to_resolver() {
        let resolved = bootstrap_identity(SupervisorBootstrapBinding::BoundSandbox {
            sandbox_id: "sandbox-a".to_string(),
        });
        let fake = Arc::new(FakeResolver::returning(Ok(Some(resolved.clone()))));
        let provider = KubernetesSupervisorBootstrapIdentityProvider::new(fake.clone());

        let result = provider
            .authenticate_registration("sa-jwt")
            .await
            .unwrap()
            .expect("expected identity");

        assert_eq!(result, resolved);
        assert_eq!(fake.seen_tokens.lock().unwrap().as_slice(), ["sa-jwt"]);
    }

    #[tokio::test]
    async fn provider_allows_none_to_fall_through() {
        let fake = Arc::new(FakeResolver::returning(Ok(None)));
        let provider = KubernetesSupervisorBootstrapIdentityProvider::new(fake);
        let result = provider.authenticate_registration("unknown").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn provider_accepts_warm_pending_identity() {
        let resolved = bootstrap_identity(SupervisorBootstrapBinding::WarmPending);
        let fake = Arc::new(FakeResolver::returning(Ok(Some(resolved.clone()))));
        let provider = KubernetesSupervisorBootstrapIdentityProvider::new(fake);
        let identity = provider
            .authenticate_registration("sa-jwt")
            .await
            .unwrap()
            .expect("expected identity");

        assert_eq!(identity.binding, SupervisorBootstrapBinding::WarmPending);
        assert_eq!(identity.owner_uid, "cr-uid-a");
    }

    #[tokio::test]
    async fn resolver_error_propagates() {
        let fake = Arc::new(FakeResolver::returning(Err(Status::unavailable(
            "apiserver down",
        ))));
        let provider = KubernetesSupervisorBootstrapIdentityProvider::new(fake);
        let err = provider
            .authenticate_registration("sa-jwt")
            .await
            .expect_err("resolver error must propagate");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
