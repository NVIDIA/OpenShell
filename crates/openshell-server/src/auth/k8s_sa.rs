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
// agent-sandbox CRD identity. Single source of truth in `openshell-core`; the
// re-anchor checks below must stay byte-identical with what the Kubernetes
// driver writes, so they are derived from the same constants the driver uses.
pub const SANDBOX_ID_ANNOTATION: &str = openshell_core::driver_utils::SANDBOX_ID_ANNOTATION;
const SANDBOX_API_GROUP: &str = openshell_core::driver_utils::SANDBOX_CRD_GROUP;
const SANDBOX_API_VERSION: &str = openshell_core::driver_utils::SANDBOX_CRD_VERSION;
const SANDBOX_API_VERSION_FULL: &str = openshell_core::driver_utils::SANDBOX_CRD_API_VERSION;
const SANDBOX_KIND: &str = openshell_core::driver_utils::SANDBOX_CRD_KIND;
const SANDBOX_ID_LABEL: &str = openshell_core::driver_utils::LABEL_SANDBOX_ID;
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";

// Warm-pool extension CRDs. A warm sandbox's owning `Sandbox` CR is created
// generically by the pool controller — it carries no `openshell.ai/sandbox-id`
// label and is instead controlled by a `SandboxClaim` (+ the controller's
// `agents.x-k8s.io/claim-uid` label). Identity must re-anchor to the
// gateway-created `SandboxClaim` and the durable claim mapping.
const SANDBOX_CLAIM_GROUP: &str = openshell_core::driver_utils::SANDBOX_EXT_GROUP;
const SANDBOX_CLAIM_VERSION: &str = openshell_core::driver_utils::SANDBOX_CRD_VERSION;
const SANDBOX_CLAIM_API_VERSION_FULL: &str = openshell_core::driver_utils::SANDBOX_EXT_API_VERSION;
const SANDBOX_CLAIM_KIND: &str = openshell_core::driver_utils::SANDBOX_CLAIM_KIND;
const CLAIM_UID_LABEL: &str = openshell_core::driver_utils::CLAIM_UID_LABEL;

/// Resolved identity extracted from a validated SA token + pod lookup.
#[derive(Debug, Clone)]
pub struct ResolvedK8sIdentity {
    pub sandbox_id: String,
    pub pod_name: String,
    pub pod_uid: String,
}

/// Looks up the durable warm-pool claim mapping the gateway recorded at
/// `CreateSandbox` time. Backed by the shared gateway Store (HA-safe: any
/// replica can serve the bootstrap). Split out so tests can fake it.
#[async_trait]
pub trait ClaimMappingLookup: Send + Sync + 'static {
    /// Resolve the sandbox-id the gateway bound to `(namespace, claim_name,
    /// claim_uid)`. `Ok(None)` (including a `claim_uid` that matches no record)
    /// means the caller fails closed.
    async fn lookup_sandbox_id(
        &self,
        namespace: &str,
        claim_name: &str,
        claim_uid: &str,
    ) -> Result<Option<String>, Status>;
}

#[async_trait]
impl ClaimMappingLookup for crate::persistence::Store {
    async fn lookup_sandbox_id(
        &self,
        namespace: &str,
        claim_name: &str,
        claim_uid: &str,
    ) -> Result<Option<String>, Status> {
        self.get_claim_mapping(namespace, claim_name, claim_uid)
            .await
            .map(|opt| opt.map(|mapping| mapping.sandbox_id))
            .map_err(|e| Status::internal(format!("claim mapping lookup failed: {e}")))
    }
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
    sandbox_claims_api: Api<DynamicObject>,
    claim_mapping: Arc<dyn ClaimMappingLookup>,
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
        claim_mapping: Arc<dyn ClaimMappingLookup>,
    ) -> Self {
        let token_reviews_api: Api<TokenReview> = Api::all(client.clone());
        let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let sandbox_gvk =
            GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let sandbox_resource = ApiResource::from_gvk(&sandbox_gvk);
        let sandboxes_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), namespace, &sandbox_resource);
        let claim_gvk = GroupVersionKind::gvk(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION,
            SANDBOX_CLAIM_KIND,
        );
        let claim_resource = ApiResource::from_gvk(&claim_gvk);
        let sandbox_claims_api: Api<DynamicObject> =
            Api::namespaced_with(client, namespace, &claim_resource);
        Self {
            token_reviews_api,
            pods_api,
            sandboxes_api,
            sandbox_claims_api,
            claim_mapping,
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

        // Warm vs cold is decided by the owning Sandbox CR's *ownerReference*,
        // never by a label a cold pod could carry. A warm Sandbox is controlled
        // by a SandboxClaim; identity then re-anchors to the gateway-created
        // claim mapping. A cold Sandbox keeps the original label cross-check.
        match sandbox_claim_owner_reference(&sandbox_cr)? {
            Some(claim_owner) => {
                let live_claim = self
                    .sandbox_claims_api
                    .get_opt(&claim_owner.name)
                    .await
                    .map_err(|e| {
                        warn!(
                            pod = %identity.pod_name,
                            claim = %claim_owner.name,
                            error = %e,
                            "failed to fetch SandboxClaim for warm pod identity validation"
                        );
                        Status::internal(format!("sandboxclaim GET failed: {e}"))
                    })?;
                let Some(live_claim) = live_claim else {
                    warn!(
                        pod = %identity.pod_name,
                        claim = %claim_owner.name,
                        "owning Sandbox references a SandboxClaim that does not exist"
                    );
                    return Err(Status::permission_denied("sandbox claim not found"));
                };
                // Cross-namespace pinning: the mapping is keyed and looked up in
                // the resolver's fixed sandbox namespace only.
                let store_sandbox_id = self
                    .claim_mapping
                    .lookup_sandbox_id(&self.sandbox_namespace, &claim_owner.name, &claim_owner.uid)
                    .await?;
                validate_warm_claim(
                    &owner,
                    &sandbox_cr,
                    &claim_owner,
                    &live_claim,
                    store_sandbox_id.as_deref(),
                    &sandbox_id,
                )?;
            }
            None => {
                validate_sandbox_owner_reference(&owner, &sandbox_id, &sandbox_cr)?;
            }
        }

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

/// Controlling `SandboxClaim` ownerReference extracted from an owning warm
/// `Sandbox` CR.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxClaimOwnerReference {
    name: String,
    uid: String,
}

/// Extract the controlling `SandboxClaim` ownerReference from an owning
/// `Sandbox` CR, if any.
///
/// `Ok(None)` => the owning Sandbox is a cold `OpenShell` Sandbox (no
/// `SandboxClaim` owner) and the caller uses the original label cross-check.
/// `Ok(Some(_))` => warm path. `Err` => a malformed/ambiguous claim
/// ownerReference rejects (fail closed).
#[allow(clippy::result_large_err)]
fn sandbox_claim_owner_reference(
    sandbox_cr: &DynamicObject,
) -> Result<Option<SandboxClaimOwnerReference>, Status> {
    let owner_refs = sandbox_cr
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default();
    let mut claim_refs = owner_refs.iter().filter(|owner| {
        owner.api_version == SANDBOX_CLAIM_API_VERSION_FULL && owner.kind == SANDBOX_CLAIM_KIND
    });
    let Some(owner) = claim_refs.next() else {
        return Ok(None);
    };
    if claim_refs.next().is_some() {
        return Err(Status::permission_denied(
            "sandbox has multiple SandboxClaim owners",
        ));
    }
    if owner.controller != Some(true) {
        return Err(Status::permission_denied(
            "sandbox SandboxClaim ownerReference is not controlling",
        ));
    }
    if owner.name.is_empty() || owner.uid.is_empty() {
        return Err(Status::permission_denied(
            "sandbox SandboxClaim ownerReference is incomplete",
        ));
    }
    Ok(Some(SandboxClaimOwnerReference {
        name: owner.name.clone(),
        uid: owner.uid.clone(),
    }))
}

/// The bound `Sandbox` name a `SandboxClaim` reports in `status.sandbox.name`,
/// or empty when the claim is not yet bound.
fn claim_bound_sandbox_name(claim: &DynamicObject) -> String {
    claim
        .data
        .get("status")
        .and_then(|status| status.get("sandbox"))
        .and_then(|sandbox| sandbox.get("name"))
        .and_then(|name| name.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Fail-closed validation of the warm-pool identity chain. Every leg must
/// agree or the bootstrap is rejected. This preserves the cold-path invariant —
/// *the sandbox-id a pod can obtain equals a value only the gateway wrote, on an
/// object the sandbox workload cannot mutate* — re-anchored to the
/// gateway-created `SandboxClaim` and the durable claim mapping.
///
/// Arguments:
/// - `sandbox_owner`: the pod's controlling `Sandbox` ownerRef (name + uid).
/// - `sandbox_cr`: the live owning `Sandbox` CR.
/// - `claim_owner`: the `SandboxClaim` controlling ownerRef on `sandbox_cr`.
/// - `live_claim`: the live `SandboxClaim` fetched by name.
/// - `store_sandbox_id`: the sandbox-id the gateway Store recorded for
///   `(namespace, claim_owner.name, claim_owner.uid)`, if any.
/// - `pod_sandbox_id`: the pod's `openshell.io/sandbox-id` annotation.
#[allow(clippy::result_large_err)]
fn validate_warm_claim(
    sandbox_owner: &SandboxOwnerReference,
    sandbox_cr: &DynamicObject,
    claim_owner: &SandboxClaimOwnerReference,
    live_claim: &DynamicObject,
    store_sandbox_id: Option<&str>,
    pod_sandbox_id: &str,
) -> Result<(), Status> {
    // 1. The owning Sandbox CR's UID matches the pod's ownerReference UID.
    let cr_uid = sandbox_cr.metadata.uid.as_deref().unwrap_or_default();
    if cr_uid != sandbox_owner.uid {
        warn!(
            sandbox_owner = %sandbox_owner.name,
            owner_uid = %sandbox_owner.uid,
            actual_uid = %cr_uid,
            "warm pod Sandbox ownerReference UID does not match live Sandbox CR"
        );
        return Err(Status::permission_denied("sandbox owner UID mismatch"));
    }

    // 2. The controller's claim-uid label agrees with the SandboxClaim ownerRef.
    let label_uid = sandbox_cr
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(CLAIM_UID_LABEL))
        .map(String::as_str)
        .unwrap_or_default();
    if label_uid != claim_owner.uid {
        warn!(
            sandbox_owner = %sandbox_owner.name,
            claim = %claim_owner.name,
            claim_owner_uid = %claim_owner.uid,
            label_uid = %label_uid,
            "warm Sandbox claim-uid label disagrees with SandboxClaim ownerReference"
        );
        return Err(Status::permission_denied(
            "sandbox claim-uid label mismatch",
        ));
    }

    // 3. The live SandboxClaim's UID matches the ownerReference UID.
    let live_uid = live_claim.metadata.uid.as_deref().unwrap_or_default();
    if live_uid != claim_owner.uid {
        warn!(
            claim = %claim_owner.name,
            claim_owner_uid = %claim_owner.uid,
            live_uid = %live_uid,
            "live SandboxClaim UID does not match ownerReference"
        );
        return Err(Status::permission_denied("sandbox claim UID mismatch"));
    }

    // 4. The claim is bound to this exact owning Sandbox.
    let bound = claim_bound_sandbox_name(live_claim);
    if bound.is_empty() || bound != sandbox_owner.name {
        warn!(
            claim = %claim_owner.name,
            bound_sandbox = %bound,
            owning_sandbox = %sandbox_owner.name,
            "SandboxClaim is not bound to the owning Sandbox"
        );
        return Err(Status::permission_denied(
            "sandbox claim is not bound to the owning sandbox",
        ));
    }

    // 5. The gateway-created Store mapping resolves the same sandbox-id as the
    //    pod annotation. A missing record (never created, or a uid that matches
    //    no record) fails closed.
    let Some(store_sandbox_id) = store_sandbox_id else {
        warn!(
            claim = %claim_owner.name,
            claim_owner_uid = %claim_owner.uid,
            "no gateway claim mapping for SandboxClaim; rejecting"
        );
        return Err(Status::permission_denied(
            "no gateway mapping for sandbox claim",
        ));
    };
    if store_sandbox_id != pod_sandbox_id {
        warn!(
            claim = %claim_owner.name,
            pod_sandbox_id = %pod_sandbox_id,
            mapped_sandbox_id = %store_sandbox_id,
            "warm pod sandbox annotation does not match gateway claim mapping"
        );
        return Err(Status::permission_denied("sandbox claim mapping mismatch"));
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

#[cfg(test)]
mod warm_claim_tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    use std::collections::BTreeMap;

    fn claim_owner_ref(name: &str, uid: &str, controller: bool) -> OwnerReference {
        OwnerReference {
            api_version: SANDBOX_CLAIM_API_VERSION_FULL.to_string(),
            block_owner_deletion: None,
            controller: Some(controller),
            kind: SANDBOX_CLAIM_KIND.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
        }
    }

    /// Owning Sandbox CR for a warm pod: claim-uid label + controlling
    /// `SandboxClaim` ownerReference.
    fn warm_sandbox_cr(
        name: &str,
        cr_uid: &str,
        claim_name: &str,
        claim_uid: &str,
    ) -> DynamicObject {
        let gvk = GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut cr = DynamicObject::new(name, &resource);
        cr.metadata.uid = Some(cr_uid.to_string());
        cr.metadata.labels = Some(BTreeMap::from([(
            CLAIM_UID_LABEL.to_string(),
            claim_uid.to_string(),
        )]));
        cr.metadata.owner_references = Some(vec![claim_owner_ref(claim_name, claim_uid, true)]);
        cr
    }

    fn sandbox_claim(name: &str, uid: &str, bound_sandbox: &str) -> DynamicObject {
        let gvk = GroupVersionKind::gvk(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION,
            SANDBOX_CLAIM_KIND,
        );
        let resource = ApiResource::from_gvk(&gvk);
        let mut claim = DynamicObject::new(name, &resource);
        claim.metadata.uid = Some(uid.to_string());
        if !bound_sandbox.is_empty() {
            claim.data = serde_json::json!({
                "status": { "sandbox": { "name": bound_sandbox } }
            });
        }
        claim
    }

    fn owner(name: &str, uid: &str) -> SandboxOwnerReference {
        SandboxOwnerReference {
            name: name.to_string(),
            uid: uid.to_string(),
        }
    }

    fn claim_owner(name: &str, uid: &str) -> SandboxClaimOwnerReference {
        SandboxClaimOwnerReference {
            name: name.to_string(),
            uid: uid.to_string(),
        }
    }

    // A fully-consistent warm binding: pod sandbox-id "sb-1", owning Sandbox
    // "sandbox-a" (cr uid "cr-1"), bound by claim "claim-a" (uid "claim-1"),
    // store mapping (ns, claim-a, claim-1) -> "sb-1".
    struct Fixture {
        owner: SandboxOwnerReference,
        cr: DynamicObject,
        claim_owner: SandboxClaimOwnerReference,
        claim: DynamicObject,
    }

    fn fixture() -> Fixture {
        Fixture {
            owner: owner("sandbox-a", "cr-1"),
            cr: warm_sandbox_cr("sandbox-a", "cr-1", "claim-a", "claim-1"),
            claim_owner: claim_owner("claim-a", "claim-1"),
            claim: sandbox_claim("claim-a", "claim-1", "sandbox-a"),
        }
    }

    #[allow(clippy::result_large_err)]
    fn validate(f: &Fixture, store: Option<&str>, pod_id: &str) -> Result<(), Status> {
        validate_warm_claim(&f.owner, &f.cr, &f.claim_owner, &f.claim, store, pod_id)
    }

    #[test]
    fn warm_chain_accepts_consistent_binding() {
        let f = fixture();
        validate(&f, Some("sb-1"), "sb-1").expect("consistent warm binding is accepted");
    }

    #[test]
    fn warm_chain_rejects_cr_uid_mismatch() {
        let mut f = fixture();
        f.cr.metadata.uid = Some("cr-other".to_string());
        let err = validate(&f, Some("sb-1"), "sb-1").expect_err("cr uid mismatch must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn warm_chain_rejects_claim_uid_label_mismatch() {
        let mut f = fixture();
        f.cr.metadata.labels = Some(BTreeMap::from([(
            CLAIM_UID_LABEL.to_string(),
            "claim-spoof".to_string(),
        )]));
        let err = validate(&f, Some("sb-1"), "sb-1").expect_err("claim-uid label mismatch rejects");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn warm_chain_rejects_live_claim_uid_mismatch() {
        let mut f = fixture();
        f.claim.metadata.uid = Some("claim-different".to_string());
        let err = validate(&f, Some("sb-1"), "sb-1").expect_err("live claim uid mismatch rejects");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn warm_chain_rejects_unbound_claim() {
        let mut f = fixture();
        f.claim = sandbox_claim("claim-a", "claim-1", "");
        let err = validate(&f, Some("sb-1"), "sb-1").expect_err("unbound claim rejects");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn warm_chain_rejects_claim_bound_to_other_sandbox() {
        let mut f = fixture();
        f.claim = sandbox_claim("claim-a", "claim-1", "some-other-sandbox");
        let err =
            validate(&f, Some("sb-1"), "sb-1").expect_err("claim bound elsewhere must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn warm_chain_rejects_missing_store_mapping() {
        // Claim exists but the gateway never recorded (or a stale record was
        // deleted) the durable mapping -> fail closed.
        let f = fixture();
        let err = validate(&f, None, "sb-1").expect_err("missing store mapping must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn warm_chain_rejects_store_mapping_spoof() {
        // The pod annotation claims a victim sandbox-id, but the gateway mapping
        // for this claim resolves a different (correct) id -> reject.
        let f = fixture();
        let err = validate(&f, Some("sb-1"), "victim-sandbox")
            .expect_err("annotation/mapping mismatch must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn claim_owner_reference_detects_warm_sandbox() {
        let cr = warm_sandbox_cr("sandbox-a", "cr-1", "claim-a", "claim-1");
        let claim_owner = sandbox_claim_owner_reference(&cr)
            .expect("well-formed")
            .expect("warm Sandbox has a SandboxClaim owner");
        assert_eq!(claim_owner.name, "claim-a");
        assert_eq!(claim_owner.uid, "claim-1");
    }

    #[test]
    fn claim_owner_reference_cold_sandbox_with_spoofed_label_is_not_warm() {
        // A cold Sandbox CR carrying a user-style claim-uid label but NO
        // controlling SandboxClaim ownerReference must take the cold path:
        // detection is ownerReference-based, never label-based.
        let gvk = GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut cr = DynamicObject::new("sandbox-a", &resource);
        cr.metadata.uid = Some("cr-1".to_string());
        cr.metadata.labels = Some(BTreeMap::from([
            (CLAIM_UID_LABEL.to_string(), "spoof".to_string()),
            (SANDBOX_ID_LABEL.to_string(), "sb-1".to_string()),
        ]));
        // No owner_references.
        assert!(
            sandbox_claim_owner_reference(&cr).unwrap().is_none(),
            "a label alone must not trigger the warm path"
        );
    }

    #[test]
    fn claim_owner_reference_rejects_non_controlling_owner() {
        let gvk = GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut cr = DynamicObject::new("sandbox-a", &resource);
        cr.metadata.owner_references = Some(vec![claim_owner_ref("claim-a", "claim-1", false)]);
        let err =
            sandbox_claim_owner_reference(&cr).expect_err("non-controlling claim owner rejects");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn claim_owner_reference_rejects_multiple_claim_owners() {
        let gvk = GroupVersionKind::gvk(SANDBOX_API_GROUP, SANDBOX_API_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut cr = DynamicObject::new("sandbox-a", &resource);
        cr.metadata.owner_references = Some(vec![
            claim_owner_ref("claim-a", "claim-1", true),
            claim_owner_ref("claim-b", "claim-2", true),
        ]);
        let err = sandbox_claim_owner_reference(&cr).expect_err("multiple claim owners reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn claim_bound_sandbox_name_reads_status() {
        let claim = sandbox_claim("claim-a", "claim-1", "sandbox-a");
        assert_eq!(claim_bound_sandbox_name(&claim), "sandbox-a");
        let unbound = sandbox_claim("claim-a", "claim-1", "");
        assert_eq!(claim_bound_sandbox_name(&unbound), "");
    }
}
