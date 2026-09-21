// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lease-elected preparation of single-use pairs. Sandbox metadata is authoritative.
use super::{
    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT, ANNOTATION_SANDBOX_RUNTIME_GENERATION,
    ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID, ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID,
    KUBE_API_TIMEOUT, KubernetesComputeDriver, KubernetesDriverError, LABEL_GATEWAY_ID,
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_WORKSPACE, Sandbox, SandboxRuntimeBootstrapPhase, SandboxRuntimeNames,
    annotation_or_label, decode_launch_authentication, gateway_verification_keys,
    random_sandbox_runtime_token, sandbox_runtime_bootstrap_phase,
    validate_kubernetes_dns1123_label,
};
use crate::isolation::{BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL};
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{Pod, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::Preconditions;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::core::{DynamicObject, ObjectMeta};
use kube::{Api, Error as KubeError};
use openshell_core::SandboxSessionId;
use openshell_core::jwt::{CredentialEpoch, SessionRotation, SessionVerificationKey};
use openshell_core::proto::compute::v1::{SyncWarmPoolsRequest, WarmPoolTarget};
use openshell_core::sandbox_generation::SandboxGenerationId;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    sync::atomic::Ordering,
    time::Duration,
};
use tracing::warn;

pub(super) const POOL: &str = "openshell.ai/warm-pool";
pub(super) const SERVICE_UID: &str = "openshell.ai/boundary-service-uid";
const STATE: &str = "openshell.ai/warm-pool-state";
const FINGERPRINT: &str = "openshell.ai/warm-pool-fingerprint";
const PAIR: &str = "openshell.ai/warm-pair-id";
const AUTH: &str = "openshell.ai/warm-pair-preparation";
const REGISTERED: &str = "openshell.ai/warm-proxy-registered-at-ms";
const TEMPLATE_NAME: &str = "openshell.ai/template-name";
const TEMPLATE_ID: &str = "openshell.ai/template-id";
const LEASE_SECONDS: i32 = 30;

#[derive(Clone)]
pub(super) struct Snapshot {
    request: SyncWarmPoolsRequest,
    received: std::time::Instant,
}

/// Public trust and physical runtime identity, without any tenant credentials.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PreparationAuthentication {
    pub gateway_id: String,
    pub verification_keys: Vec<SessionVerificationKey>,
    pub runtime_generation: SandboxGenerationId,
    pub session_id: SandboxSessionId,
    pub session_rotation: SessionRotation,
    pub auth_epoch: CredentialEpoch,
}
impl PreparationAuthentication {
    pub(super) fn from_sandbox(sandbox: &Sandbox) -> Result<Self, KubernetesDriverError> {
        let encoded = sandbox
            .spec
            .as_ref()
            .map(|s| s.launch_authentication.as_slice())
            .unwrap_or_default();
        let auth = decode_launch_authentication(encoded)?;
        Ok(Self {
            gateway_id: auth.gateway_id,
            verification_keys: auth.verification_keys,
            runtime_generation: auth.supervisor.runtime_generation,
            session_id: auth.supervisor.session_id,
            session_rotation: auth.supervisor.session_rotation,
            auth_epoch: auth.supervisor.auth_epoch,
        })
    }
}

pub(super) struct Preparation {
    template_id: String,
    template_name: String,
    fingerprint: String,
    pair_id: String,
    pub authentication: PreparationAuthentication,
}
impl Preparation {
    pub(super) fn decorate(&self, object: &mut DynamicObject, auth: &PreparationAuthentication) {
        let labels = object.metadata.labels.get_or_insert_default();
        labels.remove(LABEL_SANDBOX_ID);
        labels.insert(POOL.into(), self.template_id.clone());
        labels.insert(TEMPLATE_ID.into(), self.template_id.clone());
        if !self.template_name.is_empty() {
            labels.insert(TEMPLATE_NAME.into(), self.template_name.clone());
        }
        labels.insert(STATE.into(), "preparing".into());
        let annotations = object.metadata.annotations.get_or_insert_default();
        annotations.remove(LABEL_SANDBOX_ID);
        annotations.insert(PAIR.into(), self.pair_id.clone());
        annotations.insert(FINGERPRINT.into(), self.fingerprint.clone());
        annotations.insert(
            AUTH.into(),
            serde_json::to_string(auth).expect("preparation serializes"),
        );
    }
}

pub(super) fn is_pool_pair(object: &DynamicObject) -> bool {
    object
        .metadata
        .labels
        .as_ref()
        .is_some_and(|labels| labels.contains_key(POOL))
        && annotation_or_label(object, LABEL_SANDBOX_ID).is_none_or(|id| id.is_empty())
}

impl KubernetesComputeDriver {
    pub async fn select_warm_pair(
        &self,
        request: openshell_core::proto::compute::v1::SelectWarmPairRequest,
    ) -> Result<openshell_core::proto::compute::v1::SelectWarmPairResponse, tonic::Status> {
        use openshell_core::proto::compute::v1::{SelectWarmPairResponse, WarmPairCandidate};
        let mut response = SelectWarmPairResponse::default();
        let sandbox = request
            .sandbox
            .ok_or_else(|| tonic::Status::invalid_argument("missing sandbox"))?;
        let Some(snapshot) = self.pool_targets.read().await.clone() else {
            return Ok(response);
        };
        if !self.config.warm_pool.enabled || snapshot.received.elapsed() > Duration::from_mins(1) {
            return Ok(response);
        }
        let Some(target) = snapshot.request.pools.iter().find(|target| {
            target.template_id == request.template_id && target.workspace == sandbox.workspace
        }) else {
            return Ok(response);
        };
        if !self.pool_shape_matches(target, &sandbox) {
            return Ok(response);
        }
        let fingerprint = self
            .pool_fingerprint(target, &snapshot.request)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        let namespace = self
            .config
            .namespace_for_workspace(&sandbox.workspace, self.operator_allowlist.as_ref())
            .map_err(tonic::Status::invalid_argument)?;
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &namespace)
            .await
            .map_err(tonic::Status::unavailable)?;
        let selector = format!(
            "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_GATEWAY_ID}={},{POOL}={},{}=ready",
            self.config.gateway_id, request.template_id, STATE
        );
        let inventory = api
            .api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|_| tonic::Status::unavailable("warm inventory unavailable"))?;
        for object in inventory {
            if !is_pool_pair(&object)
                || object
                    .metadata
                    .uid
                    .as_ref()
                    .is_some_and(|uid| request.excluded_candidate_uids.contains(uid))
                || object.metadata.deletion_timestamp.is_some()
                || annotation_or_label(&object, LABEL_SANDBOX_WORKSPACE).as_deref()
                    != Some(&sandbox.workspace)
                || annotation_or_label(&object, FINGERPRINT).as_deref() != Some(&fingerprint)
                || !recent_registration(&object)
                || !within_idle_lifetime(&object, self.config.warm_pool.max_idle_seconds)
            {
                continue;
            }
            response.candidate = Some(WarmPairCandidate {
                namespace: namespace.clone(),
                name: object.metadata.name.clone().unwrap_or_default(),
                uid: object.metadata.uid.clone().unwrap_or_default(),
                template_id: request.template_id.clone(),
                fingerprint: fingerprint.clone(),
                runtime_generation: annotation_or_label(
                    &object,
                    ANNOTATION_SANDBOX_RUNTIME_GENERATION,
                )
                .unwrap_or_default(),
            });
            break;
        }
        Ok(response)
    }

    fn pool_shape_matches(&self, target: &WarmPoolTarget, sandbox: &Sandbox) -> bool {
        // Only command/TTY/attachment and gateway-managed policy are late-bound.
        // Image, resources and environment remain part of the immutable workload shape.
        let normalize = |spec: Option<openshell_core::proto::compute::v1::DriverSandboxSpec>| {
            spec.map(|mut spec| {
                spec.command.clear();
                spec.tty = false;
                spec.await_main_process_attachment = false;
                // Kubernetes pins UID/GID from driver configuration and namespace SCC.
                spec.workload_identity = None;
                spec.policy = None;
                spec.sandbox_token.clear();
                spec.launch_authentication.clear();
                if let Some(template) = spec.template.as_mut()
                    && template.image.trim().is_empty()
                {
                    template.image.clone_from(&self.config.default_image);
                }
                spec
            })
        };
        normalize(target.spec.clone()) == normalize(sandbox.spec.clone())
    }

    pub async fn claim_warm_pair(
        &self,
        sandbox: &Sandbox,
        candidate: &openshell_core::proto::compute::v1::WarmPairCandidate,
    ) -> Result<(), tonic::Status> {
        let namespace = self
            .config
            .namespace_for_workspace(&sandbox.workspace, self.operator_allowlist.as_ref())
            .map_err(tonic::Status::invalid_argument)?;
        if namespace != candidate.namespace {
            return Err(tonic::Status::aborted("warm pair namespace changed"));
        }
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &namespace)
            .await
            .map_err(tonic::Status::unavailable)?;
        for _ in 0..4 {
            let object = api
                .api
                .get_opt(&candidate.name)
                .await
                .map_err(|_| tonic::Status::unavailable("warm claim observation unavailable"))?
                .ok_or_else(|| tonic::Status::aborted("warm pair disappeared"))?;
            if object.metadata.uid.as_deref() != Some(&candidate.uid)
                || object.metadata.deletion_timestamp.is_some()
            {
                return Err(tonic::Status::aborted("warm pair was replaced or retired"));
            }
            if annotation_or_label(&object, LABEL_SANDBOX_ID).as_deref() == Some(&sandbox.id) {
                self.schedule_pair_metadata(object);
                return Ok(());
            }
            if !is_pool_pair(&object)
                || annotation_or_label(&object, STATE).as_deref() != Some("ready")
                || annotation_or_label(&object, POOL).as_deref() != Some(&candidate.template_id)
                || annotation_or_label(&object, FINGERPRINT).as_deref()
                    != Some(&candidate.fingerprint)
                || annotation_or_label(&object, ANNOTATION_SANDBOX_RUNTIME_GENERATION).as_deref()
                    != Some(&candidate.runtime_generation)
                || annotation_or_label(&object, LABEL_SANDBOX_WORKSPACE).as_deref()
                    != Some(&sandbox.workspace)
                || annotation_or_label(&object, LABEL_GATEWAY_ID).as_deref()
                    != Some(&self.config.gateway_id)
                || !recent_registration(&object)
                || !within_idle_lifetime(&object, self.config.warm_pool.max_idle_seconds)
            {
                return Err(tonic::Status::aborted("warm pair is no longer eligible"));
            }
            let snapshot = self
                .pool_targets
                .read()
                .await
                .clone()
                .ok_or_else(|| tonic::Status::unavailable("pool targets unavailable"))?;
            if snapshot.received.elapsed() > Duration::from_mins(1) {
                return Err(tonic::Status::unavailable("pool targets stale"));
            }
            let target = snapshot.request.pools.iter().find(|t| {
                t.template_id == candidate.template_id && t.workspace == sandbox.workspace
            });
            if !self.config.warm_pool.enabled
                || target.is_none_or(|target| {
                    !self.pool_shape_matches(target, sandbox)
                        || self
                            .pool_fingerprint(target, &snapshot.request)
                            .ok()
                            .as_deref()
                            != Some(&candidate.fingerprint)
                })
            {
                return Err(tonic::Status::aborted("warm pool revision changed"));
            }
            let main = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
                sandbox.spec.as_ref(),
            )
            .map_err(|_| tonic::Status::invalid_argument("invalid main process configuration"))?;
            let patch = serde_json::json!({"metadata": {"resourceVersion": object.metadata.resource_version,
                "labels": {STATE: null, POOL: null, LABEL_SANDBOX_ID: sandbox.id, LABEL_SANDBOX_NAME: sandbox.name},
                "annotations": {LABEL_SANDBOX_ID: sandbox.id, LABEL_SANDBOX_NAME: sandbox.name,
                    super::ANNOTATION_SANDBOX_RUNTIME_MAIN_PROCESS_SPEC: main,
                    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: openshell_core::time::now_ms().to_string()}}});
            match api
                .api
                .patch(
                    &candidate.name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await
            {
                Ok(claimed) => {
                    self.schedule_pair_metadata(claimed);
                    return Ok(());
                }
                Err(KubeError::Api(e)) if e.code == 409 => {}
                Err(_) => {
                    return Err(tonic::Status::unavailable(
                        "warm claim outcome is uncertain",
                    ));
                }
            }
        }
        Err(tonic::Status::unavailable("warm claim remains contended"))
    }

    fn schedule_pair_metadata(&self, object: DynamicObject) {
        let driver = self.clone();
        tokio::spawn(async move {
            driver.reconcile_pair_metadata(&object).await;
        });
    }

    /// Derive logical labels and the SPIFFE sandbox-ID annotation from the parent.
    /// Physical pair selectors and registration resource bindings remain unchanged.
    /// Repair metadata after claims and during lifecycle reconciliation.
    pub(super) async fn reconcile_pair_metadata(&self, object: &DynamicObject) {
        let mut labels = BTreeMap::new();
        let mut annotations = BTreeMap::new();
        for key in [TEMPLATE_ID, TEMPLATE_NAME] {
            if let Some(value) = annotation_or_label(object, key).filter(|s| !s.is_empty()) {
                labels.insert(key.to_string(), value);
            }
        }
        if !is_pool_pair(object) {
            for key in [LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME] {
                if let Some(value) = annotation_or_label(object, key).filter(|s| !s.is_empty()) {
                    if key == LABEL_SANDBOX_ID {
                        annotations.insert(key.to_string(), value.clone());
                    }
                    labels.insert(key.to_string(), value);
                }
            }
        }
        if labels.is_empty() {
            return;
        }
        if object.metadata.deletion_timestamp.is_some() {
            return;
        }
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let id = resource_id(object);
        let update = async {
            let inventory = pods
                .list(
                    &ListParams::default()
                        .labels(&format!("{BOUNDARY_PAIR_LABEL}={}", resource_id(object))),
                )
                .await?;
            for pod in inventory.items {
                let role = pod
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(BOUNDARY_ROLE_LABEL))
                    .map(String::as_str);
                let expected_uid = match role {
                    Some("workload") => {
                        annotation_or_label(object, ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID)
                    }
                    Some("supervisor") => {
                        annotation_or_label(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
                    }
                    _ => None,
                };
                if expected_uid.is_none()
                    || pod.metadata.uid != expected_uid
                    || pod.metadata.deletion_timestamp.is_some()
                    || (pod.metadata.labels.as_ref().is_some_and(|current| {
                        labels.iter().all(|(k, v)| current.get(k) == Some(v))
                    }) && annotations.iter().all(|(k, v)| {
                        pod.metadata.annotations.as_ref().and_then(|a| a.get(k)) == Some(v)
                    }))
                {
                    continue;
                }
                if let Some(pod_name) = &pod.metadata.name {
                    let mut patch = serde_json::json!({"metadata": {
                        "uid": pod.metadata.uid,
                        "resourceVersion": pod.metadata.resource_version,
                        "labels": labels
                    }});
                    if !annotations.is_empty() {
                        patch["metadata"]["annotations"] = serde_json::json!(annotations);
                    }
                    pods.patch(pod_name, &PatchParams::default(), &Patch::Merge(&patch))
                        .await?;
                }
            }
            Ok::<_, KubeError>(())
        };
        match tokio::time::timeout(KUBE_API_TIMEOUT, update).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(sandbox_id = %id, %error, "could not reconcile sandbox metadata on pair Pods; will retry");
            }
            Err(_) => {
                warn!(sandbox_id = %id, "timed out reconciling sandbox metadata on pair Pods; will retry");
            }
        }
    }

    pub async fn cancel_warm_pair(
        &self,
        sandbox_id: &str,
        candidate: &openshell_core::proto::compute::v1::WarmPairCandidate,
        only_unassigned: bool,
    ) -> Result<(), tonic::Status> {
        if !self.accepts_auth_namespace(&candidate.namespace) {
            return Err(tonic::Status::permission_denied("invalid pair namespace"));
        }
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &candidate.namespace)
            .await
            .map_err(tonic::Status::unavailable)?;
        for _ in 0..4 {
            let Some(object) = api
                .api
                .get_opt(&candidate.name)
                .await
                .map_err(|_| tonic::Status::unavailable("pair cancellation unavailable"))?
            else {
                return Ok(());
            };
            if object.metadata.uid.as_deref() != Some(&candidate.uid) {
                return Ok(());
            }
            if annotation_or_label(&object, LABEL_GATEWAY_ID).as_deref()
                != Some(&self.config.gateway_id)
            {
                return Err(tonic::Status::permission_denied("pair gateway mismatch"));
            }
            let assigned = annotation_or_label(&object, LABEL_SANDBOX_ID).unwrap_or_default();
            if !assigned.is_empty() && assigned != sandbox_id {
                return Ok(());
            }
            if assigned == sandbox_id && only_unassigned {
                return Err(tonic::Status::failed_precondition(
                    "candidate already claimed; recover the assignment",
                ));
            }
            // The same CAS used by claim fences any in-flight allocation before deletion.
            let patch = serde_json::json!({"metadata":{"resourceVersion": object.metadata.resource_version,"labels":{STATE:"retiring"}}});
            let retiring = match api
                .api
                .patch(
                    &candidate.name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await
            {
                Ok(object) => object,
                Err(KubeError::Api(e)) if e.code == 409 => continue,
                Err(KubeError::Api(e)) if e.code == 404 => return Ok(()),
                Err(_) => return Err(tonic::Status::unavailable("pair cancellation uncertain")),
            };
            match api
                .api
                .delete(
                    &candidate.name,
                    &DeleteParams {
                        preconditions: Some(Preconditions {
                            uid: retiring.metadata.uid,
                            resource_version: retiring.metadata.resource_version,
                        }),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(KubeError::Api(e)) if e.code == 404 => return Ok(()),
                Err(KubeError::Api(e)) if e.code == 409 => {}
                Err(_) => return Err(tonic::Status::unavailable("pair deletion uncertain")),
            }
        }
        Err(tonic::Status::unavailable("pair cancellation contended"))
    }

    pub async fn sync_warm_pools(
        &self,
        mut request: SyncWarmPoolsRequest,
    ) -> Result<(), tonic::Status> {
        if request.gateway_id != self.config.gateway_id {
            return Err(tonic::Status::invalid_argument("pool gateway mismatch"));
        }
        let keys: Vec<SessionVerificationKey> = serde_json::from_slice(&request.verification_keys)
            .map_err(|_| tonic::Status::invalid_argument("invalid pool verification keys"))?;
        gateway_verification_keys(&keys)
            .map_err(|_| tonic::Status::invalid_argument("invalid pool trust"))?;
        if keys.is_empty() {
            return Err(tonic::Status::invalid_argument("missing pool trust"));
        }
        if !self.config.warm_pool.enabled {
            request.pools.clear();
        }
        let mut seen = HashSet::new();
        for pool in &request.pools {
            validate_kubernetes_dns1123_label(&pool.template_id, "pool template ID")
                .map_err(tonic::Status::invalid_argument)?;
            if !pool.template_name.is_empty() {
                validate_kubernetes_dns1123_label(&pool.template_name, "pool template name")
                    .map_err(tonic::Status::invalid_argument)?;
            }
            if pool.spec.is_none() || !seen.insert((&pool.workspace, &pool.template_id)) {
                return Err(tonic::Status::invalid_argument(
                    "invalid or duplicate pool target",
                ));
            }
        }
        // Namespace eligibility can change independently of stored templates.
        // Keep refreshing the other workspaces when one leaves the allowlist.
        request.pools.retain(|pool| {
            match self
                .config
                .namespace_for_workspace(&pool.workspace, self.operator_allowlist.as_ref())
            {
                Ok(_) => true,
                Err(error) => {
                    warn!(workspace = %pool.workspace, template_id = %pool.template_id, %error, "skipping unavailable warm pool workspace");
                    false
                }
            }
        });
        *self.pool_targets.write().await = Some(Snapshot {
            request,
            received: std::time::Instant::now(),
        });
        Ok(())
    }

    pub(super) fn spawn_pool_controller(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let driver = self.clone();
        tokio::spawn(async move {
            let holder = random_sandbox_runtime_token();
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! { _ = shutdown.changed() => break, _ = interval.tick() => {} }
                if *shutdown.borrow() {
                    break;
                }
                let Some(snapshot) = driver.pool_targets.read().await.clone() else {
                    continue;
                };
                if snapshot.received.elapsed() > Duration::from_mins(1) {
                    continue;
                }
                match driver.renew_pool_lease(&holder).await {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        warn!(%error, "warm pool election failed");
                        continue;
                    }
                }
                // Renew concurrently; cancel preparation immediately on election uncertainty.
                let reconcile = driver.reconcile_pools(&snapshot.request);
                tokio::pin!(reconcile);
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        result = &mut reconcile => {
                            if let Err(error) = result { warn!(%error, "warm pool reconciliation failed"); }
                            break;
                        }
                        _ = interval.tick() => {
                            let current = driver.pool_targets.read().await.clone();
                            if current.as_ref().is_none_or(|current| current.received.elapsed() > Duration::from_mins(1) || current.request != snapshot.request)
                                || !matches!(driver.renew_pool_lease(&holder).await, Ok(true)) { break; }
                        }
                    }
                }
            }
        });
    }

    async fn renew_pool_lease(&self, holder: &str) -> Result<bool, KubernetesDriverError> {
        let leases: Api<Lease> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let name = format!(
            "os-pools-{:x}",
            Sha256::digest(self.config.gateway_id.as_bytes())
        )[..48]
            .to_string();
        let current = leases
            .get_opt(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let now = k8s_openapi::chrono::Utc::now();
        // Use the API timestamp type's elapsed time rather than lexical comparison.
        let now_ms = openshell_core::time::now_ms();
        if let Some(spec) = current.as_ref().and_then(|l| l.spec.as_ref()) {
            let expires = spec
                .renew_time
                .as_ref()
                .map_or(0, |time| time.0.timestamp_millis())
                + i64::from(spec.lease_duration_seconds.unwrap_or(LEASE_SECONDS)) * 1000;
            if spec.holder_identity.as_deref() != Some(holder) && expires > now_ms {
                return Ok(false);
            }
        }
        let lease = Lease {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                resource_version: current
                    .as_ref()
                    .and_then(|l| l.metadata.resource_version.clone()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some(holder.into()),
                lease_duration_seconds: Some(LEASE_SECONDS),
                renew_time: Some(MicroTime(now)),
                ..Default::default()
            }),
        };
        let result = if current.is_some() {
            leases.replace(&name, &PostParams::default(), &lease).await
        } else {
            leases.create(&PostParams::default(), &lease).await
        };
        match result {
            Ok(_) => Ok(true),
            Err(KubeError::Api(e)) if e.code == 409 => Ok(false),
            Err(e) => Err(KubernetesDriverError::from_kube(e)),
        }
    }

    async fn reconcile_pools(
        &self,
        request: &SyncWarmPoolsRequest,
    ) -> Result<(), KubernetesDriverError> {
        let lookup = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;
        // Spare pairs intentionally lack LABEL_SANDBOX_ID. The ordinary sandbox
        // selector requires that label and would hide every unassigned pair.
        let inventory = lookup
            .api
            .list(&ListParams::default().labels(&format!(
                "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_GATEWAY_ID}={},{POOL}",
                self.config.gateway_id
            )))
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let mut counts = BTreeMap::<(String, String), u32>::new();
        let mut total = 0;
        let targets = self.ordered_pool_targets(request);
        for object in inventory {
            if !is_pool_pair(&object) {
                continue;
            }
            if object.metadata.deletion_timestamp.is_some() {
                total += 1;
                continue;
            }
            let namespace = object
                .metadata
                .namespace
                .as_deref()
                .unwrap_or(&self.config.namespace);
            if !self.accepts_auth_namespace(namespace) {
                continue;
            }
            let workspace =
                annotation_or_label(&object, LABEL_SANDBOX_WORKSPACE).unwrap_or_default();
            let template = annotation_or_label(&object, POOL).unwrap_or_default();
            let key = (workspace.clone(), template.clone());
            let target = targets
                .iter()
                .find(|p| p.workspace == workspace && p.template_id == template);
            let age = openshell_core::time::now_ms()
                - annotation_or_label(&object, ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT)
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
            let state = annotation_or_label(&object, STATE).unwrap_or_default();
            let obsolete = !self.config.warm_pool.enabled
                || target.is_none_or(|p| {
                    self.pool_fingerprint(p, request).ok().as_ref()
                        != annotation_or_label(&object, FINGERPRINT).as_ref()
                });
            let expired = age
                > i64::try_from(self.config.warm_pool.max_idle_seconds.saturating_mul(1000))
                    .unwrap_or(i64::MAX);
            let timed_out = state != "ready"
                && age
                    > i64::try_from(
                        self.config
                            .warm_pool
                            .preparation_timeout_seconds
                            .saturating_mul(1000),
                    )
                    .unwrap_or(i64::MAX);
            let excess = total >= self.config.warm_pool.max_pairs
                || counts.get(&key).copied().unwrap_or(0) >= target.map_or(0, |p| p.target);
            if obsolete || expired || timed_out || excess || state == "retiring" {
                total += 1;
                if let Err(error) = self.retire_pair(&object).await {
                    warn!(pair = ?object.metadata.name, %error, "warm pair retirement will retry");
                }
                continue;
            }
            total += 1;
            *counts.entry(key).or_default() += 1;
            if let Some(target) = target {
                let remaining_ms = self
                    .config
                    .warm_pool
                    .preparation_timeout_seconds
                    .saturating_mul(1000)
                    .saturating_sub(u64::try_from(age).unwrap_or(0));
                let timeout = if state == "ready" {
                    KUBE_API_TIMEOUT
                } else {
                    Duration::from_millis(remaining_ms.max(1))
                };
                match tokio::time::timeout(timeout, Box::pin(self.reconcile_pair(&object, target)))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        warn!(pair = ?object.metadata.name, %error, "warm pair preparation will retry");
                    }
                    Err(_) => {
                        warn!(pair = ?object.metadata.name, "warm pair reconciliation timed out");
                    }
                }
            }
        }
        if !self.config.warm_pool.enabled {
            return Ok(());
        }
        // At most one successful pair per pass bounds handover overshoot. Failed
        // attempts reserve a capacity slot because the parent CR may have been
        // committed before the error became observable. Rotating target order
        // prevents that conservative accounting from starving later targets.
        for target in targets {
            if total >= self.config.warm_pool.max_pairs {
                break;
            }
            if counts
                .get(&(target.workspace.clone(), target.template_id.clone()))
                .copied()
                .unwrap_or(0)
                >= target.target
            {
                continue;
            }
            let verification_keys: Vec<SessionVerificationKey> =
                serde_json::from_slice(&request.verification_keys)
                    .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
            let pair_id = random_sandbox_runtime_token()[..24].to_string();
            let preparation = match self.pool_preparation(
                target,
                request,
                &pair_id,
                &verification_keys,
            ) {
                Ok(preparation) => preparation,
                Err(error) => {
                    warn!(workspace = %target.workspace, template_id = %target.template_id, %error, "warm pool target preparation rejected");
                    continue;
                }
            };
            let sandbox = Sandbox {
                id: pair_id.clone(),
                name: format!("warm-{pair_id}"),
                workspace: target.workspace.clone(),
                spec: target.spec.clone(),
                ..Default::default()
            };
            let result = tokio::time::timeout(
                Duration::from_secs(self.config.warm_pool.preparation_timeout_seconds),
                Box::pin(self.create_sandbox_inner(&sandbox, Some(&preparation))),
            )
            .await;
            match result {
                Ok(Ok(())) => break,
                Ok(Err(error)) => {
                    warn!(workspace = %target.workspace, template_id = %target.template_id, %error, "warm pair creation will retry");
                }
                Err(_) => {
                    warn!(workspace = %target.workspace, template_id = %target.template_id, "warm pair creation timed out and will retry");
                }
            }
            total += 1;
        }
        Ok(())
    }

    fn ordered_pool_targets<'a>(
        &self,
        request: &'a SyncWarmPoolsRequest,
    ) -> Vec<&'a WarmPoolTarget> {
        let mut targets = request.pools.iter().collect::<Vec<_>>();
        targets.sort_by_key(|target| (&target.workspace, &target.template_id));
        if !targets.is_empty() {
            let start = self.pool_reconcile_cursor.fetch_add(1, Ordering::Relaxed) % targets.len();
            targets.rotate_left(start);
        }
        targets
    }

    fn pool_preparation(
        &self,
        target: &WarmPoolTarget,
        request: &SyncWarmPoolsRequest,
        pair_id: &str,
        verification_keys: &[SessionVerificationKey],
    ) -> Result<Preparation, KubernetesDriverError> {
        Ok(Preparation {
            template_id: target.template_id.clone(),
            template_name: target.template_name.clone(),
            fingerprint: self.pool_fingerprint(target, request)?,
            pair_id: pair_id.to_string(),
            authentication: PreparationAuthentication {
                gateway_id: request.gateway_id.clone(),
                verification_keys: verification_keys.to_vec(),
                runtime_generation: SandboxGenerationId::parse(random_sandbox_runtime_token())
                    .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
                session_id: SandboxSessionId::new(),
                session_rotation: SessionRotation::new(1).expect("nonzero"),
                auth_epoch: CredentialEpoch::new(1).expect("nonzero"),
            },
        })
    }

    fn pool_fingerprint(
        &self,
        target: &WarmPoolTarget,
        request: &SyncWarmPoolsRequest,
    ) -> Result<String, KubernetesDriverError> {
        // Canonical JSON avoids map iteration order changing a preparation revision.
        use prost::Message;
        let mut spec = target.spec.clone().unwrap_or_default();
        let environment = std::mem::take(&mut spec.environment)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let template_environment = spec.template.as_mut().map(|t| {
            std::mem::take(&mut t.environment)
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        });
        let template_labels = spec.template.as_mut().map(|t| {
            std::mem::take(&mut t.labels)
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        });
        let mut config = serde_json::to_value(&self.config)
            .map_err(|e| KubernetesDriverError::Message(e.to_string()))?;
        config
            .as_object_mut()
            .expect("config object")
            .remove("warm_pool");
        let encoded = serde_json::to_vec(&(
            "pair-v1",
            spec.encode_to_vec(),
            environment,
            template_environment,
            template_labels,
            config,
            &request.gateway_id,
            &request.verification_keys,
        ))
        .map_err(|e| KubernetesDriverError::Message(e.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(encoded)))
    }

    async fn retire_pair(&self, object: &DynamicObject) -> Result<(), KubernetesDriverError> {
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let name = object.metadata.name.as_deref().unwrap_or_default();
        // CAS competes with future allocation; never retry using a newer claimed object.
        let patch = serde_json::json!({"metadata":{"resourceVersion":object.metadata.resource_version,"labels":{STATE:"retiring"}}});
        let retiring = match api
            .api
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(object) => object,
            Err(KubeError::Api(e)) if e.code == 409 || e.code == 404 => return Ok(()),
            Err(e) => return Err(KubernetesDriverError::from_kube(e)),
        };
        api.api
            .delete(
                name,
                &DeleteParams {
                    preconditions: Some(Preconditions {
                        uid: retiring.metadata.uid,
                        resource_version: retiring.metadata.resource_version,
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        Ok(())
    }

    async fn reconcile_pair(
        &self,
        object: &DynamicObject,
        target: &WarmPoolTarget,
    ) -> Result<(), KubernetesDriverError> {
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let name = object.metadata.name.as_deref().unwrap_or_default();
        let pair_id = annotation_or_label(object, PAIR).ok_or_else(|| {
            KubernetesDriverError::Message("pool pair lacks physical identity".into())
        })?;
        let generation =
            annotation_or_label(object, ANNOTATION_SANDBOX_RUNTIME_GENERATION).unwrap_or_default();
        let names = SandboxRuntimeNames::for_generation(&pair_id, &generation);
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        // Backfill display metadata on existing idle pairs without changing
        // preparation fingerprints or replacing the prepared runtime.
        let mut display_labels = BTreeMap::from([(TEMPLATE_ID, target.template_id.clone())]);
        if !target.template_name.is_empty() {
            display_labels.insert(TEMPLATE_NAME, target.template_name.clone());
        }
        let updated;
        let object = if display_labels
            .iter()
            .any(|(key, value)| annotation_or_label(object, key).as_ref() != Some(value))
        {
            let patch = serde_json::json!({
                "metadata": {"resourceVersion": object.metadata.resource_version, "labels": display_labels}
            });
            updated = api
                .api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
                .map_err(KubernetesDriverError::from_kube)?;
            &updated
        } else {
            object
        };
        if sandbox_runtime_bootstrap_phase(object) == Some(SandboxRuntimeBootstrapPhase::Preparing)
        {
            let auth: PreparationAuthentication =
                serde_json::from_str(&annotation_or_label(object, AUTH).unwrap_or_default())
                    .map_err(|e| KubernetesDriverError::Message(e.to_string()))?;
            let sandbox = Sandbox {
                id: pair_id.clone(),
                name: annotation_or_label(object, LABEL_SANDBOX_NAME).unwrap_or_default(),
                workspace: target.workspace.clone(),
                spec: target.spec.clone(),
                ..Default::default()
            };
            let (uid, gid, _) = self.resolve_sandbox_identity_in_namespace(namespace).await;
            let main = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
                sandbox.spec.as_ref(),
            )
            .map_err(|e| KubernetesDriverError::Message(e.to_string()))?;
            Box::pin(self.create_sandbox_runtime_companions(
                &sandbox,
                namespace,
                name,
                &api,
                object,
                &names,
                &generation,
                uid,
                gid,
                &main,
                "info",
                &auth,
            ))
            .await?;
            return Ok(());
        }
        self.reconcile_pair_metadata(object).await;
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let workloads = pods
            .list(&ListParams::default().labels(&format!("{BOUNDARY_ROLE_LABEL}=workload")))
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let uid = annotation_or_label(object, ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID);
        let workload_ready = workloads.items.iter().any(|pod| {
            pod.metadata.uid == uid
                && pod.metadata.deletion_timestamp.is_none()
                && pod
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .is_some_and(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c.type_ == "Ready" && c.status == "True")
                    })
        });
        let registered = annotation_or_label(object, REGISTERED)
            .and_then(|v| v.parse::<i64>().ok())
            .is_some_and(|time| openshell_core::time::now_ms() - time < 45_000);
        let proxy = pods
            .get_opt(&names.supervisor_pod)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let proxy_live = proxy.is_some_and(|pod| {
            pod.metadata.deletion_timestamp.is_none()
                && pod.metadata.uid
                    == annotation_or_label(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
                && pod.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running")
        });
        let service = Api::<Service>::namespaced(self.client.clone(), namespace)
            .get_opt(&names.boundary_service)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let service_ready = service
            .filter(|service| service.metadata.uid == annotation_or_label(object, SERVICE_UID))
            .and_then(|service| service.spec)
            .is_some_and(|spec| {
                spec.cluster_ip
                    .as_deref()
                    .is_some_and(|ip| !ip.is_empty() && ip != "None")
                    && spec
                        .selector
                        .as_ref()
                        .and_then(|selector| selector.get(BOUNDARY_PAIR_LABEL))
                        == Some(&pair_id)
            });
        let fence_ready = self
            .create_sandbox_runtime_fence(namespace, &names)
            .await
            .is_ok()
            && Api::<k8s_openapi::api::networking::v1::NetworkPolicy>::namespaced(
                self.client.clone(),
                namespace,
            )
            .get(&names.workload_policy)
            .await
            .is_ok_and(|fence| {
                super::sandbox_runtime_namespace_fence_generation_matches(&fence, object)
            });
        let ready = workload_ready && registered && proxy_live && service_ready && fence_ready;
        let state = if ready { "ready" } else { "preparing" };
        if annotation_or_label(object, STATE).as_deref() != Some(state) {
            let patch = serde_json::json!({"metadata":{"resourceVersion":object.metadata.resource_version,"labels":{STATE:state}}});
            match api
                .api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
            {
                Ok(_) => {}
                Err(KubeError::Api(e)) if e.code == 409 => {}
                Err(e) => return Err(KubernetesDriverError::from_kube(e)),
            }
        }
        Ok(())
    }

    pub(super) async fn record_pool_registration(
        &self,
        api: &Api<DynamicObject>,
        object: &DynamicObject,
    ) -> Result<(), tonic::Status> {
        if !is_pool_pair(object) {
            return Ok(());
        }
        if annotation_or_label(object, STATE).as_deref() == Some("retiring") {
            return Err(tonic::Status::permission_denied("pair is retiring"));
        }
        let now = openshell_core::time::now_ms();
        if annotation_or_label(object, REGISTERED)
            .and_then(|s| s.parse::<i64>().ok())
            .is_some_and(|time| now - time < 10_000)
        {
            return Ok(());
        }
        let patch = serde_json::json!({"metadata":{"resourceVersion":object.metadata.resource_version,"annotations":{REGISTERED:now.to_string()}}});
        api.patch(
            object.metadata.name.as_deref().unwrap_or_default(),
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|_| tonic::Status::unavailable("pool registration changed; retry"))?;
        Ok(())
    }
}

/// Reuse only dependents of this exact Sandbox/Pod incarnation.
pub(super) async fn create_owned<K>(api: &Api<K>, desired: &K) -> Result<K, KubernetesDriverError>
where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Serialize
        + Send
        + Sync,
{
    let name = desired
        .meta()
        .name
        .as_deref()
        .ok_or_else(|| KubernetesDriverError::Message("dependent has no name".into()))?;
    match api
        .get_opt(name)
        .await
        .map_err(KubernetesDriverError::from_kube)?
    {
        Some(existing) => {
            if existing.meta().deletion_timestamp.is_some()
                || existing.meta().owner_references != desired.meta().owner_references
            {
                return Err(KubernetesDriverError::Precondition(
                    "pair dependent has conflicting ownership".into(),
                ));
            }
            Ok(existing)
        }
        None => api
            .create(&PostParams::default(), desired)
            .await
            .map_err(KubernetesDriverError::from_kube),
    }
}

fn within_idle_lifetime(object: &DynamicObject, max_idle_seconds: u64) -> bool {
    annotation_or_label(object, ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT)
        .and_then(|value| value.parse::<i64>().ok())
        .is_some_and(|started| {
            let age = openshell_core::time::now_ms().saturating_sub(started);
            u64::try_from(age).is_ok_and(|age| age <= max_idle_seconds.saturating_mul(1000))
        })
}

fn recent_registration(object: &DynamicObject) -> bool {
    annotation_or_label(object, REGISTERED)
        .and_then(|v| v.parse::<i64>().ok())
        .is_some_and(|time| (0..45_000).contains(&(openshell_core::time::now_ms() - time)))
}

pub(super) fn resource_id(object: &DynamicObject) -> String {
    annotation_or_label(object, PAIR)
        .or_else(|| annotation_or_label(object, LABEL_SANDBOX_ID))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::{
        ApiResource, Client, GroupVersionKind, KubernetesComputeConfig, OwnerReference,
        SANDBOX_GROUP, SANDBOX_KIND, SANDBOX_VERSION_V1ALPHA1, Secret, sandbox_id_from_object,
    };
    use super::*;
    type Requests = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;
    use http_body_util::BodyExt as _;
    use openshell_core::proto::compute::v1::DriverSandboxSpec;
    use std::sync::{Arc, Mutex};

    fn api_driver(responses: Vec<(u16, serde_json::Value)>) -> (KubernetesComputeDriver, Requests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let responses = Arc::new(Mutex::new(std::collections::VecDeque::from(responses)));
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let captured = captured.clone();
            let responses = responses.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = body.collect().await.unwrap().to_bytes();
                captured.lock().unwrap().push((
                    parts.method.to_string(),
                    parts.uri.to_string(),
                    serde_json::from_slice(&bytes).unwrap_or_default(),
                ));
                let (status, value) = responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected API request");
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(http_body_util::Full::new(bytes::Bytes::from(
                            value.to_string(),
                        )))
                        .unwrap(),
                )
            }
        });
        let mut driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        driver.client = Client::new(service, "default");
        (driver, requests)
    }

    fn status(code: u16) -> (u16, serde_json::Value) {
        (
            code,
            serde_json::json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Conflict","message":"test","code":code}),
        )
    }

    #[tokio::test]
    async fn unavailable_workspace_does_not_block_pool_snapshot_refresh() {
        use super::super::{OperatorNamespaceAllowlist, WorkspaceMode};

        let (mut driver, requests) = api_driver(Vec::new());
        driver.config.workspace_mode = WorkspaceMode::Operator;
        driver.config.warm_pool.enabled = true;
        let allowlist = OperatorNamespaceAllowlist::new();
        allowlist.insert("available".into());
        allowlist.insert("removed".into());
        driver.operator_allowlist = Some(allowlist.clone());
        let request = SyncWarmPoolsRequest {
            gateway_id: driver.config.gateway_id.clone(),
            verification_keys: serde_json::to_vec(&[SessionVerificationKey {
                key_id: "test-key".into(),
                public_key_pem: rcgen::KeyPair::generate()
                    .unwrap()
                    .public_key_pem()
                    .into_bytes(),
            }])
            .unwrap(),
            pools: ["removed", "available"]
                .into_iter()
                .map(|workspace| WarmPoolTarget {
                    template_id: format!("template-{workspace}"),
                    workspace: workspace.into(),
                    target: 1,
                    spec: Some(DriverSandboxSpec::default()),
                    ..Default::default()
                })
                .collect(),
        };
        driver.sync_warm_pools(request.clone()).await.unwrap();
        allowlist.remove("removed");
        driver.pool_targets.write().await.as_mut().unwrap().received = std::time::Instant::now()
            .checked_sub(Duration::from_mins(2))
            .expect("two minutes fits in Instant");
        driver.sync_warm_pools(request.clone()).await.unwrap();
        {
            let snapshot = driver.pool_targets.read().await;
            let snapshot = snapshot.as_ref().unwrap();
            assert_eq!(snapshot.request.pools, vec![request.pools[1].clone()]);
            assert!(snapshot.received.elapsed() < Duration::from_mins(1));
        }
        // An empty eligible snapshot must also replace stale inventory.
        allowlist.remove("available");
        driver.sync_warm_pools(request.clone()).await.unwrap();
        assert!(
            driver
                .pool_targets
                .read()
                .await
                .as_ref()
                .unwrap()
                .request
                .pools
                .is_empty()
        );
        // Stored templates become eligible again when the namespace returns.
        allowlist.insert("removed".into());
        driver.sync_warm_pools(request.clone()).await.unwrap();
        assert_eq!(
            driver
                .pool_targets
                .read()
                .await
                .as_ref()
                .unwrap()
                .request
                .pools,
            vec![request.pools[0].clone()]
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pair_metadata_reconciles_only_bound_pods_and_retries_failures() {
        let parent: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "Sandbox",
            "metadata": {"name": "prepared", "namespace": "openshell", "annotations": {
                LABEL_SANDBOX_ID: "logical", LABEL_SANDBOX_NAME: "friendly-name",
                TEMPLATE_ID: "template-id", TEMPLATE_NAME: "example-template",
                PAIR: "physical", ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID: "workload-uid",
                ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: "supervisor-uid"
            }}
        }))
        .unwrap();
        let pod = |name: &str, uid: &str, role: &str| {
            serde_json::json!({
                "metadata": {"name": name, "uid": uid, "resourceVersion": "17",
                    "labels": {BOUNDARY_PAIR_LABEL: "physical", BOUNDARY_ROLE_LABEL: role},
                    "annotations": {LABEL_SANDBOX_ID: "physical"}}
            })
        };
        let workload = pod("workload", "workload-uid", "workload");
        let mut supervisor = pod("supervisor", "supervisor-uid", "supervisor");
        // Previously assigned Pods can already have correct labels while the
        // SPIFFE annotation still points at the physical pair.
        for (key, value) in [
            (LABEL_SANDBOX_ID, "logical"),
            (LABEL_SANDBOX_NAME, "friendly-name"),
            (TEMPLATE_ID, "template-id"),
            (TEMPLATE_NAME, "example-template"),
        ] {
            supervisor["metadata"]["labels"][key] = value.into();
        }
        let inventory = serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[
            workload.clone(), supervisor.clone(), pod("replacement", "wrong-uid", "workload")
        ]});
        let (driver, requests) = api_driver(vec![
            status(500), // Display metadata failures must be repairable.
            (200, inventory),
            (200, workload),
            (200, supervisor),
        ]);
        driver.reconcile_pair_metadata(&parent).await;
        driver.reconcile_pair_metadata(&parent).await;
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for (_, _, patch) in &requests[2..] {
            assert_eq!(
                patch["metadata"]["labels"],
                serde_json::json!({
                    LABEL_SANDBOX_ID: "logical", LABEL_SANDBOX_NAME: "friendly-name",
                    TEMPLATE_ID: "template-id", TEMPLATE_NAME: "example-template"
                })
            );
            assert_eq!(patch["metadata"]["resourceVersion"], "17");
            assert_eq!(
                patch["metadata"]["annotations"],
                serde_json::json!({LABEL_SANDBOX_ID: "logical"})
            );
            assert!(patch["spec"].is_null());
        }
        assert_eq!(requests[2].2["metadata"]["uid"], "workload-uid");
        assert_eq!(requests[3].2["metadata"]["uid"], "supervisor-uid");
    }

    #[tokio::test]
    async fn idle_pair_pods_get_template_labels_without_logical_sandbox_labels() {
        let parent: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "Sandbox",
            "metadata": {"name": "prepared", "namespace": "openshell",
                "labels": {POOL: "template-id", TEMPLATE_ID: "template-id", TEMPLATE_NAME: "example-template", LABEL_SANDBOX_NAME: "warm-physical"},
                "annotations": {PAIR: "physical", ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID: "workload-uid"}}
        })).unwrap();
        let pod = serde_json::json!({"metadata": {"name": "workload", "uid": "workload-uid", "resourceVersion": "3",
            "labels": {BOUNDARY_ROLE_LABEL: "workload", BOUNDARY_PAIR_LABEL: "physical"}}});
        let (driver, requests) = api_driver(vec![
            (
                200,
                serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[pod.clone()]}),
            ),
            (200, pod),
        ]);
        driver.reconcile_pair_metadata(&parent).await;
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests[1].2["metadata"]["labels"],
            serde_json::json!({
                TEMPLATE_ID: "template-id", TEMPLATE_NAME: "example-template"
            })
        );
        assert!(requests[1].2["metadata"]["annotations"].is_null());
    }

    #[tokio::test]
    async fn creation_uses_prepared_authentication_generation_for_metadata_and_secret_names() {
        let policy = serde_json::json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{}});
        let mut absent = status(404);
        absent.1["reason"] = "NotFound".into();
        let (mut driver, requests) = api_driver(vec![
            absent.clone(),
            (201, policy.clone()),
            absent.clone(),
            (201, policy),
            status(503),
        ]);
        driver.config.sandbox_uid = Some(10001);
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1ALPHA1)
            .unwrap();
        let preparation = Preparation {
            template_id: "template".into(),
            template_name: "example-template".into(),
            fingerprint: "revision".into(),
            pair_id: "physical".into(),
            authentication: PreparationAuthentication {
                gateway_id: "openshell".into(),
                verification_keys: Vec::new(),
                runtime_generation: SandboxGenerationId::parse("prepared-generation").unwrap(),
                session_id: SandboxSessionId::new(),
                session_rotation: SessionRotation::new(1).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
            },
        };
        let sandbox = Sandbox {
            id: "physical".into(),
            name: "warm-physical".into(),
            workspace: "default".into(),
            ..Default::default()
        };
        // Stop at the parent POST: inspect the real creation payload without provisioning Pods.
        let error = driver
            .create_sandbox_inner(&sandbox, Some(&preparation))
            .await
            .unwrap_err();
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            5,
            "creation failed before parent POST: {error}; requests: {requests:?}"
        );
        let (method, uri, object) = &requests[4];
        assert_eq!(method, "POST");
        assert!(uri.split('?').next().unwrap().ends_with("/sandboxes"));
        assert_eq!(
            object["metadata"]["labels"][TEMPLATE_NAME],
            "example-template"
        );
        assert_eq!(object["metadata"]["labels"][TEMPLATE_ID], "template");
        let auth: PreparationAuthentication =
            serde_json::from_str(object["metadata"]["annotations"][AUTH].as_str().unwrap())
                .unwrap();
        assert_eq!(
            object["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_GENERATION],
            auth.runtime_generation.as_str()
        );
        let names =
            SandboxRuntimeNames::for_generation(&sandbox.id, auth.runtime_generation.as_str());
        assert!(
            object["spec"]["podTemplate"]["spec"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|volume| volume["secret"]["secretName"] == names.sandbox_secret)
        );
    }

    async fn claim_fixture(
        responses: impl FnOnce(&serde_json::Value) -> Vec<(u16, serde_json::Value)>,
    ) -> (
        KubernetesComputeDriver,
        Requests,
        Sandbox,
        openshell_core::proto::compute::v1::WarmPairCandidate,
    ) {
        use openshell_core::proto::compute::v1::{DriverSandboxSpec, WarmPairCandidate};
        let target = WarmPoolTarget {
            template_id: "template".into(),
            template_name: "example-template".into(),
            workspace: "default".into(),
            target: 1,
            spec: Some(DriverSandboxSpec::default()),
        };
        let snapshot = SyncWarmPoolsRequest {
            pools: vec![target.clone()],
            gateway_id: "openshell".into(),
            verification_keys: b"[]".to_vec(),
        };
        let mut config = KubernetesComputeConfig::default();
        config.warm_pool.enabled = true;
        let fingerprint = KubernetesComputeDriver::new_for_test(config.clone())
            .pool_fingerprint(&target, &snapshot)
            .unwrap();
        let object = serde_json::json!({"apiVersion":"agents.x-k8s.io/v1alpha1","kind":"Sandbox","metadata":{
            "name":"warm-example","namespace":"openshell","uid":"pair-uid","resourceVersion":"17",
            "labels":{LABEL_MANAGED_BY:LABEL_MANAGED_BY_VALUE,LABEL_GATEWAY_ID:"openshell",LABEL_SANDBOX_WORKSPACE:"default",POOL:"template",STATE:"ready"},
            "annotations":{PAIR:"physical",FINGERPRINT:fingerprint, ANNOTATION_SANDBOX_RUNTIME_GENERATION:"generation",REGISTERED:openshell_core::time::now_ms().to_string(),ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT:openshell_core::time::now_ms().to_string()}
        }});
        let (mut driver, requests) = api_driver(responses(&object));
        driver.config = config;
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1ALPHA1)
            .unwrap();
        *driver.pool_targets.write().await = Some(Snapshot {
            request: snapshot,
            received: std::time::Instant::now(),
        });
        let sandbox = Sandbox {
            id: "logical".into(),
            name: "example".into(),
            workspace: "default".into(),
            spec: target.spec,
            ..Default::default()
        };
        let candidate = WarmPairCandidate {
            namespace: "openshell".into(),
            name: "warm-example".into(),
            uid: "pair-uid".into(),
            template_id: "template".into(),
            fingerprint,
            runtime_generation: "generation".into(),
        };
        (driver, requests, sandbox, candidate)
    }

    #[tokio::test]
    async fn selection_skips_targets_reserved_by_another_allocation() {
        let (driver, requests, sandbox, _) = claim_fixture(|object| {
            let mut second = object.clone();
            second["metadata"]["uid"] = "second-uid".into();
            second["metadata"]["name"] = "second-pair".into();
            vec![(
                200,
                serde_json::json!({
                    "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "SandboxList", "metadata": {},
                    "items": [object, second]
                }),
            )]
        })
        .await;
        let response = driver
            .select_warm_pair(openshell_core::proto::compute::v1::SelectWarmPairRequest {
                template_id: "template".into(),
                sandbox: Some(sandbox),
                excluded_candidate_uids: vec!["pair-uid".into()],
            })
            .await
            .unwrap();
        assert_eq!(response.candidate.unwrap().uid, "second-uid");
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "selection remains read-only"
        );
    }

    #[tokio::test]
    async fn claim_is_cas_and_adopts_its_own_committed_assignment() {
        let (driver, requests, sandbox, candidate) = claim_fixture(|object| {
            let mut assigned = object.clone();
            assigned["metadata"]["annotations"][LABEL_SANDBOX_ID] = "logical".into();
            vec![(200, object.clone()), status(409), (200, assigned)]
        })
        .await;
        driver.claim_warm_pair(&sandbox, &candidate).await.unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        let patch = &requests[1].2["metadata"];
        assert_eq!(patch["resourceVersion"], "17");
        assert_eq!(patch["annotations"][LABEL_SANDBOX_ID], "logical");
        assert!(patch["labels"][POOL].is_null());
        assert!(patch["labels"][STATE].is_null());
        assert!(
            patch["annotations"][PAIR].is_null(),
            "physical identity must not be overwritten"
        );
    }

    #[tokio::test]
    async fn claim_rejects_another_owner_and_replaced_uid_without_mutation() {
        for replaced in [false, true] {
            let (driver, requests, sandbox, candidate) = claim_fixture(|object| {
                let mut object = object.clone();
                if replaced {
                    object["metadata"]["uid"] = "replacement".into();
                } else {
                    object["metadata"]["annotations"][LABEL_SANDBOX_ID] = "other".into();
                }
                vec![(200, object)]
            })
            .await;
            assert_eq!(
                driver
                    .claim_warm_pair(&sandbox, &candidate)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Aborted
            );
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn retirement_winning_the_cas_fences_an_in_flight_claim() {
        let (driver, requests, sandbox, candidate) = claim_fixture(|object| {
            let mut retiring = object.clone();
            retiring["metadata"]["resourceVersion"] = "18".into();
            retiring["metadata"]["labels"][STATE] = "retiring".into();
            vec![(200, object.clone()), status(409), (200, retiring)]
        })
        .await;
        assert_eq!(
            driver
                .claim_warm_pair(&sandbox, &candidate)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].0, "PATCH");
        assert_eq!(requests[2].0, "GET");
    }

    #[tokio::test]
    async fn rejected_candidate_cancellation_cannot_delete_a_concurrent_successful_claim() {
        let (driver, requests, sandbox, candidate) = claim_fixture(|object| {
            let mut assigned = object.clone();
            assigned["metadata"]["annotations"][LABEL_SANDBOX_ID] = "logical".into();
            vec![(200, object.clone()), status(409), (200, assigned)]
        })
        .await;
        assert_eq!(
            driver
                .cancel_warm_pair(&sandbox.id, &candidate, true)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(requests.lock().unwrap().len(), 3);
        assert!(requests.lock().unwrap().iter().all(|r| r.0 != "DELETE"));
    }

    #[tokio::test]
    async fn deletion_fences_an_unassigned_candidate_before_deleting_exact_uid() {
        let (driver, requests, sandbox, candidate) = claim_fixture(|object| {
            let mut retiring = object.clone();
            retiring["metadata"]["resourceVersion"] = "18".into();
            retiring["metadata"]["labels"][STATE] = "retiring".into();
            vec![
                (200, object.clone()),
                (200, retiring.clone()),
                (200, retiring),
            ]
        })
        .await;
        driver
            .cancel_warm_pair(&sandbox.id, &candidate, false)
            .await
            .unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests[1].2["metadata"]["labels"][STATE], "retiring");
        assert_eq!(requests[2].2["preconditions"]["uid"], "pair-uid");
        assert_eq!(requests[2].2["preconditions"]["resourceVersion"], "18");
    }

    #[tokio::test]
    async fn pool_shape_allows_late_command_but_rejects_image_and_environment_changes() {
        let (driver, _, mut sandbox, _) = claim_fixture(|_| vec![]).await;
        let target = driver
            .pool_targets
            .read()
            .await
            .as_ref()
            .unwrap()
            .request
            .pools[0]
            .clone();
        sandbox.spec.as_mut().unwrap().command = vec!["custom-command".into()];
        assert!(driver.pool_shape_matches(&target, &sandbox));
        sandbox
            .spec
            .as_mut()
            .unwrap()
            .environment
            .insert("CHANGED".into(), "1".into());
        assert!(!driver.pool_shape_matches(&target, &sandbox));
        sandbox.spec.as_mut().unwrap().environment.clear();
        sandbox.spec.as_mut().unwrap().template =
            Some(openshell_core::proto::compute::v1::DriverSandboxTemplate {
                image: "different".into(),
                ..Default::default()
            });
        assert!(!driver.pool_shape_matches(&target, &sandbox));
    }

    #[tokio::test]
    async fn disabled_pool_discovers_and_retires_inventory_without_logical_ids() {
        let object = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "Sandbox",
            "metadata": {
                "name": "warm-example", "namespace": "openshell", "uid": "pair-uid",
                "resourceVersion": "17",
                "labels": {
                    LABEL_MANAGED_BY: LABEL_MANAGED_BY_VALUE,
                    LABEL_GATEWAY_ID: "openshell", POOL: "template", STATE: "preparing"
                }
            }
        });
        let mut retiring = object.clone();
        retiring["metadata"]["resourceVersion"] = serde_json::json!("18");
        retiring["metadata"]["labels"][STATE] = serde_json::json!("retiring");
        let (driver, requests) = api_driver(vec![
            (
                200,
                serde_json::json!({"apiVersion":"agents.x-k8s.io/v1alpha1", "kind":"SandboxList", "metadata":{}, "items":[object]}),
            ),
            (200, retiring.clone()),
            (200, retiring),
        ]);
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1ALPHA1)
            .unwrap();
        driver
            .reconcile_pools(&SyncWarmPoolsRequest::default())
            .await
            .unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        let (method, uri, _) = &requests[0];
        assert_eq!(method, "GET");
        assert!(uri.contains("labelSelector="));
        assert!(uri.contains("managed-by"));
        assert!(uri.contains("gateway-id"));
        assert!(uri.contains("warm-pool"));
        assert!(
            !uri.contains("sandbox-id"),
            "unassigned pairs have no logical ID label"
        );
        assert_eq!(requests[1].0, "PATCH");
        assert_eq!(requests[2].0, "DELETE");
        assert_eq!(requests[2].2["preconditions"]["uid"], "pair-uid");
        assert_eq!(requests[2].2["preconditions"]["resourceVersion"], "18");
    }

    #[tokio::test]
    async fn retirement_failure_does_not_block_remaining_inventory() {
        let object = |name: &str, uid: &str| {
            serde_json::json!({
                "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "Sandbox",
                "metadata": {
                    "name": name, "namespace": "openshell", "uid": uid,
                    "resourceVersion": "17",
                    "labels": {
                        LABEL_MANAGED_BY: LABEL_MANAGED_BY_VALUE,
                        LABEL_GATEWAY_ID: "openshell", POOL: "template", STATE: "preparing"
                    }
                }
            })
        };
        let first = object("warm-first", "first-uid");
        let second = object("warm-second", "second-uid");
        let mut retiring = second.clone();
        retiring["metadata"]["resourceVersion"] = serde_json::json!("18");
        retiring["metadata"]["labels"][STATE] = serde_json::json!("retiring");
        let (driver, requests) = api_driver(vec![
            (
                200,
                serde_json::json!({
                    "apiVersion":"agents.x-k8s.io/v1alpha1", "kind":"SandboxList",
                    "metadata":{}, "items":[first, second]
                }),
            ),
            status(500),
            (200, retiring.clone()),
            (200, retiring),
        ]);
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1ALPHA1)
            .unwrap();

        driver
            .reconcile_pools(&SyncWarmPoolsRequest::default())
            .await
            .expect("one failed retirement must not abort reconciliation");

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[1].1.contains("warm-first"));
        assert!(requests[2].1.contains("warm-second"));
        assert_eq!(requests[3].0, "DELETE");
        assert!(requests[3].1.contains("warm-second"));
    }

    #[tokio::test]
    async fn reconciliation_rotates_target_priority_between_passes() {
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let request = SyncWarmPoolsRequest {
            pools: ["a", "b", "c"]
                .into_iter()
                .map(|template_id| WarmPoolTarget {
                    template_id: template_id.to_string(),
                    workspace: "default".into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let order = || {
            driver
                .ordered_pool_targets(&request)
                .into_iter()
                .map(|target| target.template_id.as_str())
                .collect::<Vec<_>>()
        };

        assert_eq!(order(), ["a", "b", "c"]);
        assert_eq!(order(), ["b", "c", "a"]);
        assert_eq!(order(), ["c", "a", "b"]);
    }

    #[tokio::test]
    async fn target_creation_failure_does_not_block_later_target() {
        use openshell_core::proto::compute::v1::{
            DriverSandboxSpec, GpuResourceRequirements, ResourceRequirements,
        };

        let mut config = KubernetesComputeConfig::default();
        config.warm_pool.enabled = true;
        config.warm_pool.max_pairs = 2;
        let gateway_id = config.gateway_id.clone();
        let (mut driver, requests) = api_driver(vec![
            (
                200,
                serde_json::json!({
                    "apiVersion":"agents.x-k8s.io/v1alpha1", "kind":"SandboxList",
                    "metadata":{}, "items":[]
                }),
            ),
            (
                200,
                serde_json::json!({
                    "apiVersion":"v1", "kind":"Namespace",
                    "metadata":{"name":"openshell", "uid":"namespace-uid"}
                }),
            ),
            status(500),
        ]);
        driver.config = config;
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1ALPHA1)
            .unwrap();
        let invalid = WarmPoolTarget {
            template_id: "a-invalid".into(),
            workspace: "default".into(),
            target: 1,
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(ResourceRequirements {
                    gpu: Some(GpuResourceRequirements { count: Some(0) }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let healthy = WarmPoolTarget {
            template_id: "b-healthy".into(),
            workspace: "default".into(),
            target: 1,
            spec: Some(DriverSandboxSpec::default()),
            ..Default::default()
        };

        driver
            .reconcile_pools(&SyncWarmPoolsRequest {
                pools: vec![invalid, healthy],
                gateway_id,
                verification_keys: b"[]".to_vec(),
            })
            .await
            .expect("target failures must remain local to their target");

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].1.contains("/api/v1/namespaces/openshell"));
        assert!(requests[2].1.contains("networkpolicies"));
    }

    #[tokio::test]
    async fn election_respects_live_holder_and_cas_conflicts() {
        let lease = serde_json::json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"lease","resourceVersion":"17"},"spec":{"holderIdentity":"other","leaseDurationSeconds":30,"renewTime":k8s_openapi::chrono::Utc::now()}});
        let (driver, requests) = api_driver(vec![(200, lease.clone())]);
        assert!(!driver.renew_pool_lease("me").await.unwrap());
        assert_eq!(requests.lock().unwrap().len(), 1);
        let mut expired = lease;
        expired["spec"]["renewTime"] = serde_json::json!("2000-01-01T00:00:00Z");
        let (driver, requests) = api_driver(vec![(200, expired), status(409)]);
        assert!(!driver.renew_pool_lease("me").await.unwrap());
        let requests = requests.lock().unwrap();
        assert_eq!(requests[1].0, "PUT");
        assert_eq!(requests[1].2["metadata"]["resourceVersion"], "17");
    }

    #[tokio::test]
    async fn retirement_conflict_never_deletes_a_claimed_pair() {
        let (driver, requests) = api_driver(vec![status(409)]);
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1ALPHA1)
            .unwrap();
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1ALPHA1,
            SANDBOX_KIND,
        ));
        let mut object = DynamicObject::new("warm-example", &resource);
        object.metadata.resource_version = Some("17".into());
        object.metadata.uid = Some("pair-uid".into());
        driver.retire_pair(&object).await.unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "PATCH");
        assert_eq!(requests[0].2["metadata"]["resourceVersion"], "17");
    }

    #[tokio::test]
    async fn preparation_journal_reuses_existing_keys_and_rejects_new_owner() {
        let mut secret = Secret {
            metadata: ObjectMeta {
                name: Some("journal".into()),
                owner_references: Some(vec![OwnerReference {
                    api_version: "v1".into(),
                    kind: "Pod".into(),
                    name: "pod".into(),
                    uid: "original".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                "key".into(),
                k8s_openapi::ByteString(b"original material".to_vec()),
            )])),
            ..Default::default()
        };
        let (driver, requests) = api_driver(vec![
            (200, serde_json::to_value(&secret).unwrap()),
            (200, serde_json::to_value(&secret).unwrap()),
        ]);
        let api = Api::<Secret>::namespaced(driver.client, "default");
        secret.data = None; // retry generated different material; retain committed journal
        let reused = create_owned(&api, &secret).await.unwrap();
        assert_eq!(reused.data.unwrap()["key"].0, b"original material");
        secret.metadata.owner_references.as_mut().unwrap()[0].uid = "replacement".into();
        assert!(create_owned(&api, &secret).await.is_err());
        assert!(requests.lock().unwrap().iter().all(|r| r.0 == "GET"));
    }

    #[tokio::test]
    async fn preparation_revision_ignores_capacity_but_tracks_shape_and_trust() {
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let mut target = WarmPoolTarget {
            template_id: "template".into(),
            template_name: "example-template".into(),
            workspace: "default".into(),
            target: 1,
            spec: Some(DriverSandboxSpec::default()),
        };
        let mut request = SyncWarmPoolsRequest {
            gateway_id: "gateway".into(),
            verification_keys: b"public-key-a".to_vec(),
            ..Default::default()
        };
        let revision = driver.pool_fingerprint(&target, &request).unwrap();
        target.target = 20;
        target.template_name = "renamed-for-display".into();
        assert_eq!(
            revision,
            driver.pool_fingerprint(&target, &request).unwrap()
        );
        target
            .spec
            .as_mut()
            .unwrap()
            .environment
            .insert("MODEL".into(), "other".into());
        assert_ne!(
            revision,
            driver.pool_fingerprint(&target, &request).unwrap()
        );
        target.spec.as_mut().unwrap().environment.clear();
        request.verification_keys = b"public-key-b".to_vec();
        assert_ne!(
            revision,
            driver.pool_fingerprint(&target, &request).unwrap()
        );
    }

    #[test]
    fn inventory_never_has_a_logical_sandbox_identity() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1ALPHA1,
            SANDBOX_KIND,
        ));
        let mut object = DynamicObject::new("warm-example", &resource);
        object.metadata.labels = Some(BTreeMap::from([(POOL.into(), "template".into())]));
        assert!(is_pool_pair(&object));
        assert!(sandbox_id_from_object(&object).is_err());
        object.metadata.annotations = Some(BTreeMap::from([(
            LABEL_SANDBOX_ID.into(),
            "assigned".into(),
        )]));
        assert!(!is_pool_pair(&object));
        assert_eq!(sandbox_id_from_object(&object).unwrap(), "assigned");
    }
}
