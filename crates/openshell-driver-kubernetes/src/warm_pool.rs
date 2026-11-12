// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell-owned physical warm runtimes, using the Agent Sandbox core controller.
//!
//! The Sandbox CR is the provisioning journal. Its name and bootstrap identity
//! are chosen once, before any API request, and must never be reused. Pool policy
//! supplies the desired inventory; the gateway's preparation records remain the
//! authority for supervisor capacity and claims.

use super::*;
use crate::prepared_runtime::PreparedRuntimeBootstrap;
use openshell_core::SandboxSessionId;
#[cfg(test)]
use openshell_core::jwt::{CredentialEpoch, SessionRotation, SessionVerificationKey};
use openshell_supervisor_control::{
    PreparationRelease, PreparationRetirement, PreparedRuntimeRegistration,
};
use serde::Serialize;

const POOL_LABEL: &str = "openshell.ai/warm-pool";
const RECORD: &str = "openshell.ai/warm-runtime";
const POD_UID: &str = "openshell.ai/warm-runtime-pod-uid";
const RELEASED: &str = "openshell.ai/warm-runtime-released";
const RELEASE_AUTHORIZED: &str = "openshell.ai/warm-runtime-release-authorized";
const RETIRING: &str = "openshell.ai/warm-runtime-retiring";
const MAX_RECORD_BYTES: usize = 128 * 1024;

pub use openshell_supervisor_control::warm_pool::WarmRuntimeTrust;

fn validate_trust(trust: &WarmRuntimeTrust) -> Result<(), KubernetesDriverError> {
    openshell_core::jwt::SessionJwtVerifier::new(
        &trust.gateway_id,
        openshell_core::jwt::SessionTokenProfile::Sandbox,
        trust.verification_keys.clone(),
        Arc::new(openshell_core::jwt::SystemJwtClock),
    )
    .map(|_| ())
    .map_err(|_| invalid("invalid warm runtime gateway verification bundle"))
}

#[path = "warm_pool/reconciler.rs"]
mod reconciler;
pub use reconciler::WarmPoolReport;
#[path = "warm_pool/claim.rs"]
mod claim;
#[path = "warm_pool/dedicated.rs"]
mod dedicated;
pub(super) use claim::{claim_pending, physical_resource_id};
pub(super) use dedicated::{
    claimed_supervisor_pair, configure_dedicated_pod, validate_claimed_supervisor,
    validate_dedicated_pod,
};

/// One single-use physical runtime. Retrying this request reuses its CR and TLS
/// identity. A replacement gets a fresh `session_id`, including after retirement.
#[derive(Clone)]
pub struct WarmRuntimeRequest {
    pub workspace: String,
    pub pool_id: String,
    pub session_id: SandboxSessionId,
    pub spec: SandboxSpec,
    pub trust: WarmRuntimeTrust,
}

/// Durable public coordinates, also returned by inventory after a lost response.
#[derive(Clone, Debug, PartialEq, Eq)]
// Independent observations: a claimed CR may also be deleting or gate-released.
#[allow(clippy::struct_excessive_bools)]
pub struct WarmRuntimeResource {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub workspace: String,
    pub pool_id: String,
    pub session_id: SandboxSessionId,
    pub pod_uid: Option<String>,
    /// Gate release is not authenticated runtime readiness or claim eligibility.
    pub released: bool,
    pub deleting: bool,
    pub retiring: bool,
    pub claimed: bool,
}

/// Retirement is resumable until Kubernetes garbage collection has completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WarmRuntimeRetirement {
    /// Deletion was accepted, with a durable fence against late preparation.
    Deleting,
    /// This physical CR no longer exists. No other resource was changed.
    Absent,
    /// A claim or replacement won. No physical resources were deleted.
    Changed,
}

/// Result of preparing and releasing a physical runtime. No workload has started.
#[derive(Clone, Debug)]
pub struct WarmRuntimePreparation {
    pub resource: WarmRuntimeResource,
    pub registration: PreparedRuntimeRegistration,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    session_id: SandboxSessionId,
    workspace: String,
    pool_id: String,
    trust: WarmRuntimeTrust,
    uid: u32,
    gid: u32,
    /// Requested shape, including the unique Secret reference. Kubernetes may
    /// default omitted fields, but may not change fields we explicitly supplied.
    shape: serde_json::Value,
    child_env: BTreeMap<String, String>,
}

impl Record {
    fn physical_id(&self) -> String {
        self.session_id.to_string()
    }

    fn route(&self) -> String {
        format!("rt-{}", self.session_id)
    }

    fn names(&self) -> SandboxRuntimeNames {
        SandboxRuntimeNames::for_generation(&self.physical_id(), &self.physical_id())
    }

    fn encoded(&self) -> Result<String, KubernetesDriverError> {
        let encoded = serde_json::to_string(self).map_err(record_error)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(invalid("warm runtime record exceeds its size limit"));
        }
        Ok(encoded)
    }
}

impl KubernetesComputeDriver {
    fn warm_supervision(&self) -> Result<&SharedSupervision, KubernetesDriverError> {
        self.warm_supervision
            .as_ref()
            .or_else(|| {
                self.shared_supervisor
                    .as_ref()
                    .map(SharedSupervisor::supervision)
            })
            .ok_or_else(|| invalid("warm pool gateway coordination is missing"))
    }

    /// Create an OpenShell-owned spare using the Agent Sandbox core API. The
    /// unique bootstrap Secret reference is rendered before the Pod exists; no
    /// admission hook, extension template or runtime bootstrap exchange is used.
    ///
    /// Callers retain the request identity across ambiguous failures. A successful
    /// return means the runtime may connect to its reserved supervisor, not that
    /// it has connected or is eligible for a claim. Capacity failure keeps it gated.
    pub async fn prepare_warm_runtime(
        &self,
        request: &WarmRuntimeRequest,
    ) -> Result<WarmRuntimePreparation, KubernetesDriverError> {
        Box::pin(self.prepare_warm_runtime_inner(request)).await
    }

    async fn prepare_warm_runtime_inner(
        &self,
        request: &WarmRuntimeRequest,
    ) -> Result<WarmRuntimePreparation, KubernetesDriverError> {
        self.check_warm_runtime_support()?;
        validate_request(request, &self.config.gateway_id)?;
        validate_gpu_request(driver_gpu_requirements(
            request.spec.resource_requirements.as_ref(),
        ))
        .map_err(|status| KubernetesDriverError::InvalidArgument(status.message().into()))?;
        let namespace = self.warm_runtime_namespace(&request.workspace).await?;
        let sandbox = Sandbox {
            workspace: request.workspace.clone(),
            spec: Some(request.spec.clone()),
            ..Default::default()
        };
        self.validate_pod_metadata_for_sandbox(&sandbox)
            .map_err(KubernetesDriverError::InvalidArgument)?;
        let identities = self
            .admit_requested_resources(&sandbox)
            .await
            .map_err(admission_error)?;
        let (uid, gid, _) = self.resolve_sandbox_identity_in_namespace(&namespace).await;
        let physical_id = request.session_id.to_string();
        let names = SandboxRuntimeNames::for_generation(&physical_id, &physical_id);
        let mut data = sandbox_to_k8s_spec(
            Some(&request.spec),
            &SandboxPodParams {
                default_image: &self.config.default_image,
                image_pull_policy: self.config.image_pull_policy,
                // Shared/operator namespaces already contain these operator-managed
                // references. Managed mode needs a separate bootstrap journal.
                image_pull_secrets: &self.config.image_pull_secrets,
                sandbox_runtime_image: &self.config.sandbox_runtime_image,
                sandbox_runtime_image_pull_policy: self.config.sandbox_runtime_image_pull_policy,
                service_account_name: &self.config.service_account_name,
                sandbox_id: &physical_id,
                enable_user_namespaces: self.config.enable_user_namespaces,
                workspace_default_storage_size: &self.config.workspace_default_storage_size,
                workspace_storage_class: &self.config.workspace_storage_class,
                default_runtime_class_name: &self.config.default_runtime_class_name,
                sandbox_uid: uid,
                sandbox_gid: gid,
                boundary_port: self.config.sandbox_runtime.boundary_port,
                sandbox_secret_name: &names.sandbox_secret,
            },
        )
        .map_err(KubernetesDriverError::InvalidArgument)?;
        canonicalize_environment(&mut data);
        let mut child_env = request
            .spec
            .template
            .as_ref()
            .map_or_else(BTreeMap::new, |template| {
                template.environment.clone().into_iter().collect()
            });
        child_env.extend(request.spec.environment.clone());
        child_env.retain(|key, _| !key.starts_with("OPENSHELL_"));
        let record = Record {
            session_id: request.session_id,
            workspace: request.workspace.clone(),
            pool_id: request.pool_id.clone(),
            trust: request.trust.clone(),
            uid,
            gid,
            shape: data.clone(),
            child_env,
        };
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let name = format!("warm-{}", request.session_id);
        let mut candidate = DynamicObject::new(&name, &api.resource);
        candidate.metadata.namespace = Some(namespace.clone());
        candidate.metadata.labels = Some(BTreeMap::from([
            (LABEL_MANAGED_BY.into(), LABEL_MANAGED_BY_VALUE.into()),
            (LABEL_GATEWAY_ID.into(), self.config.gateway_id.clone()),
            (LABEL_SANDBOX_WORKSPACE.into(), request.workspace.clone()),
            (POOL_LABEL.into(), request.pool_id.clone()),
        ]));
        candidate.metadata.annotations = Some(BTreeMap::from([
            (RECORD.into(), record.encoded()?),
            (
                crate::resource_admission::IDENTITIES.into(),
                serde_json::to_string(&identities).map_err(record_error)?,
            ),
            (
                crate::resource_admission::CONFIG_USED.into(),
                request
                    .spec
                    .template
                    .as_ref()
                    .and_then(|template| template.driver_config.as_ref())
                    .is_some_and(|config| !config.fields.is_empty())
                    .to_string(),
            ),
        ]));
        candidate.data = data;
        // Create the Pod only after recording the identity. It is independently
        // blocked by the scheduling gate and its missing bootstrap Secret.
        set_operating(&mut candidate, &api.resource.version, false);
        let object = match api.api.create(&PostParams::default(), &candidate).await {
            Ok(object) => object,
            Err(KubeError::Api(error)) if error.code == 409 => api
                .api
                .get(&name)
                .await
                .map_err(KubernetesDriverError::from_kube)?,
            Err(error) => return Err(KubernetesDriverError::from_kube(error)),
        };
        let stored = read_record(&object, &self.config.gateway_id)?;
        if stored.encoded()? != record.encoded()? {
            return Err(invalid(
                "warm runtime request changed; use a new physical identity",
            ));
        }
        Box::pin(self.resume_warm_runtime_object(&api, object, stored)).await
    }

    /// Resume from the immutable CR journal without regenerating identity or
    /// trusting the current pool template. The caller must still decide whether
    /// that template/trust revision is desired, or retire it instead.
    pub async fn resume_warm_runtime(
        &self,
        resource: &WarmRuntimeResource,
    ) -> Result<WarmRuntimePreparation, KubernetesDriverError> {
        self.check_warm_runtime_support()?;
        let namespace = self.warm_runtime_namespace(&resource.workspace).await?;
        if namespace != resource.namespace {
            return Err(invalid("warm runtime namespace changed"));
        }
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let object = api
            .api
            .get(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let record = read_record(&object, &self.config.gateway_id)?;
        let current = resource_from_object(&object, &record)?;
        if !same_resource(&current, resource) {
            return Err(invalid("warm Sandbox resource identity changed"));
        }
        Box::pin(self.resume_warm_runtime_object(&api, object, record)).await
    }

    /// List physical inventory, including preparing and deleting resources. An
    /// unreadable or invalid journal is an error, never evidence of free capacity.
    pub async fn warm_runtime_inventory(
        &self,
        workspace: &str,
    ) -> Result<Vec<WarmRuntimeResource>, KubernetesDriverError> {
        self.check_warm_runtime_support()?;
        let namespace = self.warm_runtime_namespace(workspace).await?;
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let selector = format!(
            "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_GATEWAY_ID}={},{}={workspace},{POOL_LABEL}",
            self.config.gateway_id, LABEL_SANDBOX_WORKSPACE
        );
        let objects = api
            .api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        objects
            .into_iter()
            .map(|object| {
                let record = read_record(&object, &self.config.gateway_id)?;
                resource_from_object(&object, &record)
            })
            .collect()
    }

    /// Journal retirement, permanently fence preparation/activation, then delete
    /// only this CR by UID and version. Its Pod, Pod-owned bootstrap Secret and
    /// CR-owned control policy follow through Kubernetes garbage collection.
    /// Namespace-wide network fences are retained. All steps are retryable.
    pub async fn retire_warm_runtime(
        &self,
        resource: &WarmRuntimeResource,
    ) -> Result<WarmRuntimeRetirement, KubernetesDriverError> {
        self.check_warm_runtime_support()?;
        let namespace = self.warm_runtime_namespace(&resource.workspace).await?;
        if namespace != resource.namespace {
            return Err(invalid("warm runtime namespace changed"));
        }
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let Some(mut object) = api
            .api
            .get_opt(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
        else {
            return Ok(WarmRuntimeRetirement::Absent);
        };
        let record = read_record(&object, &self.config.gateway_id)?;
        let current = resource_from_object(&object, &record)?;
        if !same_resource(&current, resource)
            || annotation_or_label(&object, LABEL_SANDBOX_ID).is_some()
        {
            return Ok(WarmRuntimeRetirement::Changed);
        }
        if !current.retiring && !current.deleting {
            object =
                patch_annotations(&api.api, &object, serde_json::json!({RETIRING: "true"})).await?;
        }
        let outcome = self
            .warm_supervision()?
            .retire_preparation(PreparationRetirement {
                workspace: record.workspace.clone(),
                route: record.route(),
                generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    record.physical_id(),
                )
                .map_err(|_| invalid("invalid warm runtime generation"))?,
                auth_epoch: record.trust.auth_epoch,
            })
            .await
            .map_err(KubernetesDriverError::Message)?;
        if outcome != PreparationRelease::Released {
            return Ok(WarmRuntimeRetirement::Changed);
        }
        // Re-read after the durable operation. Status may have advanced, but a
        // concurrent claim, journal edit or object replacement is not ours to delete.
        let Some(latest) = api
            .api
            .get_opt(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
        else {
            return Ok(WarmRuntimeRetirement::Absent);
        };
        if latest.metadata.uid != object.metadata.uid
            || latest.metadata.annotations != object.metadata.annotations
            || latest.metadata.labels != object.metadata.labels
            || latest.metadata.owner_references != object.metadata.owner_references
            || latest.data.get("spec") != object.data.get("spec")
        {
            return Ok(WarmRuntimeRetirement::Changed);
        }
        match api
            .api
            .delete(
                &resource.name,
                &DeleteParams {
                    propagation_policy: Some(kube::api::PropagationPolicy::Foreground),
                    preconditions: Some(Preconditions {
                        uid: Some(resource.uid.clone()),
                        resource_version: Some(required_version(&latest)?.into()),
                    }),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => Ok(WarmRuntimeRetirement::Deleting),
            Err(KubeError::Api(error)) if error.code == 404 => Ok(WarmRuntimeRetirement::Absent),
            Err(KubeError::Api(error)) if error.code == 409 => Ok(WarmRuntimeRetirement::Changed),
            Err(error) => Err(KubernetesDriverError::from_kube(error)),
        }
    }

    fn check_warm_runtime_support(&self) -> Result<(), KubernetesDriverError> {
        if self.warm_supervision().is_err() {
            return Err(invalid(
                "warm runtime preparation requires gateway coordination",
            ));
        }
        if self.config.workspace_mode == WorkspaceMode::Managed {
            // Do not widen the managed namespace's create-only Secret permission.
            return Err(invalid(
                "managed workspace warm runtimes require a gateway-namespace bootstrap journal",
            ));
        }
        Ok(())
    }

    async fn warm_runtime_namespace(
        &self,
        workspace: &str,
    ) -> Result<String, KubernetesDriverError> {
        self.validate_workspace_namespace(workspace)?;
        self.wait_for_operator_allowlist()
            .await
            .map_err(admission_error)?;
        self.config
            .namespace_for_workspace(workspace, self.operator_allowlist.as_ref())
            .map_err(KubernetesDriverError::Precondition)
    }

    async fn resume_warm_runtime_object(
        &self,
        api: &AgentSandboxApi,
        mut object: DynamicObject,
        record: Record,
    ) -> Result<WarmRuntimePreparation, KubernetesDriverError> {
        let resource = resource_from_object(&object, &record)?;
        let names = record.names();
        ensure_unclaimed(&object)?;
        self.admit_warm_runtime(&object).await?;
        self.create_sandbox_runtime_fence(&resource.namespace, &names)
            .await?;
        let target = self.warm_target(api, &mut object, &record).await?;
        if !resource.released {
            let patch = sandbox_operating_state_patch(
                &api.resource.version,
                required_version(&object)?,
                true,
            );
            object = patch_object(&api.api, &object, patch).await?;
        }
        let pods = Api::<Pod>::namespaced(self.client.clone(), &resource.namespace);
        let pod = self
            .wait_for_bootstrap_workload_pod(&pods, &resource.name, &resource.uid)
            .await?;
        validate_pod(&pod, &object, &record)?;
        let pod_uid = pod
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| invalid("warm Pod has no UID"))?;
        // Journal the first Pod UID before either its Secret or reservation can
        // exist. A replacement Pod must never inherit this generation's identity.
        if annotation(&object, POD_UID).is_none() {
            object =
                patch_annotations(&api.api, &object, serde_json::json!({POD_UID: pod_uid})).await?;
        }
        let namespace = Api::<Namespace>::all(self.client.clone())
            .get(&resource.namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let namespace_uid = namespace
            .metadata
            .uid
            .ok_or_else(|| invalid("warm namespace has no UID"))?;
        let fence = Api::<NetworkPolicy>::namespaced(self.client.clone(), &resource.namespace)
            .get(&names.workload_policy)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let fence_coordinates = VerifiedControlPolicy::from_policy(&fence)?;
        let control_policy = &target.control_policy;
        let route = record.route();
        let bootstrap = PreparedRuntimeBootstrap {
            workspace: record.workspace.clone(),
            namespace: resource.namespace.clone(),
            pod_name: resource.name.clone(),
            pod_uid: pod_uid.into(),
            secret_name: names.sandbox_secret.clone(),
            session_id: record.session_id,
        };
        let verification_keys = gateway_verification_keys(&record.trust.verification_keys)?;
        let workload_identity = ResolvedWorkloadIdentity::new(
            record.uid,
            record.gid,
            Vec::new(),
            "kubernetes-config".into(),
            format!("sandbox:{}", resource.uid),
        )
        .map_err(|error| invalid(&error.to_string()))?;
        let registration = bootstrap
            .prepare(self.client.clone(), self.warm_supervision()?, |tls| {
                KubernetesSandboxRuntimeBoundarySpec {
                    boundary_id: String::new(),
                    generation: record.physical_id(),
                    session_id: record.session_id,
                    session_rotation: record.trust.session_rotation,
                    auth_epoch: record.trust.auth_epoch,
                    gateway_id: record.trust.gateway_id.clone(),
                    verification_keys: verification_keys.clone(),
                    namespace_uid: namespace_uid.clone(),
                    sandbox_resource_uid: resource.uid.clone(),
                    workload_pod_uid: pod_uid.into(),
                    workload_pod_uid_path: SANDBOX_POD_UID_PATH.into(),
                    supervisor: target.supervisor.clone(),
                    egress_policy_uid: fence_coordinates.uid.clone(),
                    egress_policy_resource_version: fence_coordinates.resource_version.clone(),
                    control_path: KubernetesControlPath::RuntimeInitiatedShared {
                        control_authority: target.authority.clone(),
                        supervisor_address: target.address,
                        supervisor_namespace: target.namespace.clone(),
                        route: route.clone(),
                        control_policy_uid: control_policy.uid.clone(),
                        control_policy_resource_version: control_policy.resource_version.clone(),
                    },
                    sandbox_tls: SandboxTlsServerConfig {
                        certificate_chain_path: BOUNDARY_CERTIFICATE_PATH.into(),
                        private_key_path: BOUNDARY_PRIVATE_KEY_PATH.into(),
                    },
                    supervisor_tls: tls,
                    host_gateway_ip: self.config.host_gateway_ip.parse().ok(),
                    workload_identity: workload_identity.clone(),
                    child_env: record.child_env.clone().into_iter().collect(),
                }
                .provision_prepared()
            })
            .await?;

        // Capacity is now durably reserved. Re-read the live resources after that
        // await; never release a replacement or an altered admission/fence.
        let mut current = api
            .api
            .get(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if current.metadata.uid != object.metadata.uid
            || read_record(&current, &self.config.gateway_id)?.encoded()? != record.encoded()?
        {
            return Err(invalid("warm Sandbox changed during preparation"));
        }
        ensure_unclaimed(&current)?;
        self.admit_warm_runtime(&current).await?;
        self.create_sandbox_runtime_fence(&resource.namespace, &names)
            .await?;
        let current_fence =
            Api::<NetworkPolicy>::namespaced(self.client.clone(), &resource.namespace)
                .get(&names.workload_policy)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
        let current_target = self.warm_target(api, &mut current, &record).await?;
        let current_control = &current_target.control_policy;
        if current_fence.metadata.uid != fence.metadata.uid
            || current_fence.metadata.resource_version != fence.metadata.resource_version
            || current_control.uid != control_policy.uid
            || current_control.resource_version != control_policy.resource_version
        {
            return Err(invalid(
                "warm runtime network fence changed during preparation",
            ));
        }
        let current_namespace = Api::<Namespace>::all(self.client.clone())
            .get(&resource.namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if current_namespace.metadata.uid.as_deref() != Some(namespace_uid.as_str()) {
            return Err(invalid("warm namespace changed during preparation"));
        }
        let current_pod = pods
            .get(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        validate_pod(&current_pod, &current, &record)?;
        if current_pod.metadata.uid != pod.metadata.uid {
            return Err(invalid("warm Pod changed during preparation"));
        }
        // Persist the authorization before the Pod write. If its response is
        // lost, an ungated Pod is accepted only with this durable evidence that
        // bootstrap and reservation both completed before gate removal.
        if annotation(&current, RELEASE_AUTHORIZED) != Some("true") {
            current = patch_annotations(
                &api.api,
                &current,
                serde_json::json!({RELEASE_AUTHORIZED: "true"}),
            )
            .await?;
        }
        if self.shared_supervisor.is_none() {
            self.release_warm_dedicated(&current, &record, &registration)
                .await?;
        }
        release_gate(&pods, &current_pod).await?;
        let object =
            patch_annotations(&api.api, &current, serde_json::json!({RELEASED: "true"})).await?;
        Ok(WarmRuntimePreparation {
            resource: resource_from_object(&object, &record)?,
            registration,
        })
    }

    async fn admit_warm_runtime(
        &self,
        object: &DynamicObject,
    ) -> Result<(), KubernetesDriverError> {
        // The common resource admission check requires a logical Sandbox label.
        // Supply the physical ID only to that local validation, never to stored
        // metadata or the gateway's logical Sandbox watch stream.
        let record = read_record(object, &self.config.gateway_id)?;
        let mut admission = object.clone();
        admission
            .metadata
            .labels
            .get_or_insert_default()
            .insert(LABEL_SANDBOX_ID.into(), record.physical_id());
        self.admit_stored_resources(&admission)
            .await
            .map_err(admission_error)
    }
}

fn validate_request(
    request: &WarmRuntimeRequest,
    gateway_id: &str,
) -> Result<(), KubernetesDriverError> {
    validate_kubernetes_dns1123_label(&request.pool_id, "warm pool ID")
        .map_err(KubernetesDriverError::InvalidArgument)?;
    if request.trust.gateway_id != gateway_id || request.trust.verification_keys.is_empty() {
        return Err(invalid(
            "warm runtime requires this gateway's verification keys",
        ));
    }
    if !request.spec.launch_authentication.is_empty() || !request.spec.sandbox_token.is_empty() {
        return Err(invalid(
            "warm runtime must not contain Sandbox launch credentials",
        ));
    }
    validate_trust(&request.trust)?;
    Ok(())
}

fn read_record(object: &DynamicObject, gateway_id: &str) -> Result<Record, KubernetesDriverError> {
    let encoded = annotation(object, RECORD)
        .filter(|value| value.len() <= MAX_RECORD_BYTES)
        .ok_or_else(|| invalid("warm Sandbox lacks a bounded provisioning record"))?;
    let record: Record =
        serde_json::from_str(encoded).map_err(|_| invalid("invalid warm runtime record"))?;
    validate_trust(&record.trust)?;
    let labels = object
        .metadata
        .labels
        .as_ref()
        .ok_or_else(|| invalid("warm Sandbox lacks labels"))?;
    if labels.get(LABEL_GATEWAY_ID).map(String::as_str) != Some(gateway_id)
        || labels.get(LABEL_MANAGED_BY).map(String::as_str) != Some(LABEL_MANAGED_BY_VALUE)
        || labels.get(POOL_LABEL) != Some(&record.pool_id)
        || labels.get(LABEL_SANDBOX_WORKSPACE) != Some(&record.workspace)
        || record.trust.gateway_id != gateway_id
        || object.metadata.name.as_deref() != Some(&format!("warm-{}", record.session_id))
        || (annotation_or_label(object, LABEL_SANDBOX_ID).is_none()
            && !requested_shape_matches(&record.shape, &object.data))
    {
        return Err(invalid(
            "warm runtime record does not match its resource identity",
        ));
    }
    Ok(record)
}

fn resource_from_object(
    object: &DynamicObject,
    record: &Record,
) -> Result<WarmRuntimeResource, KubernetesDriverError> {
    let required = |value: &Option<String>| {
        value
            .clone()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("warm Sandbox lacks immutable resource coordinates"))
    };
    Ok(WarmRuntimeResource {
        namespace: required(&object.metadata.namespace)?,
        name: required(&object.metadata.name)?,
        uid: required(&object.metadata.uid)?,
        workspace: record.workspace.clone(),
        pool_id: record.pool_id.clone(),
        session_id: record.session_id,
        pod_uid: annotation(object, POD_UID).map(str::to_string),
        released: annotation(object, RELEASED) == Some("true"),
        deleting: object.metadata.deletion_timestamp.is_some(),
        retiring: annotation(object, RETIRING) == Some("true"),
        claimed: annotation_or_label(object, LABEL_SANDBOX_ID).is_some(),
    })
}

fn same_resource(left: &WarmRuntimeResource, right: &WarmRuntimeResource) -> bool {
    left.uid == right.uid
        && left.namespace == right.namespace
        && left.name == right.name
        && left.workspace == right.workspace
        && left.pool_id == right.pool_id
        && left.session_id == right.session_id
}

fn validate_pod(
    pod: &Pod,
    object: &DynamicObject,
    record: &Record,
) -> Result<(), KubernetesDriverError> {
    ensure_unclaimed(object)?;
    if pod.metadata.deletion_timestamp.is_some() {
        return Err(invalid("warm Pod is terminating"));
    }
    if annotation(object, RELEASE_AUTHORIZED) != Some("true")
        && pod
            .spec
            .as_ref()
            .is_some_and(|spec| spec.node_name.is_some())
    {
        return Err(invalid(
            "warm Pod was bound to a node before capacity reservation",
        ));
    }
    if let Some(expected) = annotation(object, POD_UID)
        && pod.metadata.uid.as_deref() != Some(expected)
    {
        return Err(invalid(
            "warm Pod was replaced; a new physical runtime is required",
        ));
    }
    let actual = serde_json::to_value(pod).map_err(record_error)?;
    for key in ["containers", "initContainers"] {
        if let Some(path) = shape_difference(
            &record.shape["spec"]["podTemplate"]["spec"][key],
            &actual["spec"][key],
        ) {
            return Err(invalid(&format!(
                "warm Pod containers changed after admission at {key}{path}"
            )));
        }
    }
    // On retry after gate removal, check all other isolation fields using the
    // same admission validator. The immutable Pod UID was recorded before release.
    let mut validation = pod.clone();
    if !has_gate(pod) && annotation(object, RELEASE_AUTHORIZED) == Some("true") {
        validation
            .spec
            .as_mut()
            .ok_or_else(|| invalid("warm Pod has no spec"))?
            .scheduling_gates
            .get_or_insert_default()
            .push(k8s_openapi::api::core::v1::PodSchedulingGate {
                name: SANDBOX_BOOTSTRAP_SCHEDULING_GATE.into(),
            });
    }
    KubernetesComputeDriver::validate_capability_free_workload_pod(
        &validation,
        object
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| invalid("warm Sandbox has no UID"))?,
        &record.physical_id(),
        record.uid,
        record.gid,
        &record.names().sandbox_secret,
    )
}

fn has_gate(pod: &Pod) -> bool {
    pod.spec
        .as_ref()
        .and_then(|spec| spec.scheduling_gates.as_ref())
        .is_some_and(|gates| {
            gates
                .iter()
                .any(|gate| gate.name == SANDBOX_BOOTSTRAP_SCHEDULING_GATE)
        })
}

async fn release_gate(pods: &Api<Pod>, pod: &Pod) -> Result<(), KubernetesDriverError> {
    if !has_gate(pod) {
        return Ok(());
    }
    let gates = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.scheduling_gates.as_ref())
        .into_iter()
        .flatten()
        .filter(|gate| gate.name != SANDBOX_BOOTSTRAP_SCHEDULING_GATE)
        .cloned()
        .collect::<Vec<_>>();
    let patch = serde_json::json!({
        "metadata": {"uid": pod.metadata.uid, "resourceVersion": pod.metadata.resource_version},
        "spec": {"schedulingGates": gates},
    });
    if pod.metadata.uid.is_none() || pod.metadata.resource_version.is_none() {
        return Err(invalid("warm Pod has no mutation preconditions"));
    }
    pods.patch(
        pod.metadata
            .name
            .as_deref()
            .ok_or_else(|| invalid("warm Pod has no name"))?,
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(KubernetesDriverError::from_kube)?;
    Ok(())
}

fn ensure_unclaimed(object: &DynamicObject) -> Result<(), KubernetesDriverError> {
    if object.metadata.deletion_timestamp.is_some()
        || annotation_or_label(object, LABEL_SANDBOX_ID).is_some()
        || annotation(object, RETIRING).is_some()
    {
        return Err(invalid("warm Sandbox is claimed, retiring or terminating"));
    }
    Ok(())
}

async fn patch_annotations(
    api: &Api<DynamicObject>,
    object: &DynamicObject,
    annotations: serde_json::Value,
) -> Result<DynamicObject, KubernetesDriverError> {
    patch_object(
        api,
        object,
        serde_json::json!({"metadata": {"annotations": annotations}}),
    )
    .await
}

async fn patch_object(
    api: &Api<DynamicObject>,
    object: &DynamicObject,
    mut patch: serde_json::Value,
) -> Result<DynamicObject, KubernetesDriverError> {
    let name = object
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| invalid("warm Sandbox has no name"))?;
    let mut current = object.clone();
    for _ in 0..4 {
        ensure_unclaimed(&current)?;
        patch["metadata"]["uid"] = serde_json::json!(current.metadata.uid);
        patch["metadata"]["resourceVersion"] = serde_json::json!(required_version(&current)?);
        match api
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(updated) => return Ok(updated),
            Err(KubeError::Api(error)) if error.code == 409 => {
                current = api
                    .get(name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                // Only status and bookkeeping changes may retry locally. A claim,
                // new Pod binding, changed admission record or shape must return
                // to reconciliation, never silently become the new precondition.
                if current.metadata.uid != object.metadata.uid
                    || current.metadata.labels != object.metadata.labels
                    || current.metadata.annotations != object.metadata.annotations
                    || current.metadata.owner_references != object.metadata.owner_references
                    || current.data.get("spec") != object.data.get("spec")
                {
                    return Err(invalid("warm Sandbox changed during a conditional update"));
                }
            }
            Err(error) => return Err(KubernetesDriverError::from_kube(error)),
        }
    }
    Err(invalid(
        "warm Sandbox remained busy during a conditional update",
    ))
}

fn annotation<'a>(object: &'a DynamicObject, key: &str) -> Option<&'a str> {
    object
        .metadata
        .annotations
        .as_ref()?
        .get(key)
        .map(String::as_str)
}

fn required_version(object: &DynamicObject) -> Result<&str, KubernetesDriverError> {
    object
        .metadata
        .resource_version
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid("warm Sandbox has no resourceVersion"))
}

fn set_operating(object: &mut DynamicObject, version: &str, running: bool) {
    if version == SANDBOX_VERSION_V1ALPHA1 {
        object.data["spec"]["replicas"] = serde_json::json!(i32::from(running));
    } else {
        object.data["spec"]["operatingMode"] =
            serde_json::json!(if running { "Running" } else { "Suspended" });
    }
}

fn canonicalize_environment(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(env) = map.get_mut("env").and_then(serde_json::Value::as_array_mut) {
                env.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
            }
            for value in map.values_mut() {
                canonicalize_environment(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                canonicalize_environment(value);
            }
        }
        _ => {}
    }
}

fn requested_shape_matches(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    shape_difference(expected, actual).is_none()
}

fn shape_difference(expected: &serde_json::Value, actual: &serde_json::Value) -> Option<String> {
    match (expected, actual) {
        (serde_json::Value::Object(expected), serde_json::Value::Object(actual)) => {
            expected.iter().find_map(|(key, value)| {
                let difference = actual.get(key).map_or_else(
                    || {
                        // Kubernetes omits empty optional collections and empty
                        // EnvVar values. An omitted EnvVar value is the empty string.
                        let omitted = value.is_null()
                            || value.as_array().is_some_and(Vec::is_empty)
                            || value.as_object().is_some_and(serde_json::Map::is_empty)
                            || (key == "value" && value.as_str() == Some(""));
                        (!omitted).then(String::new)
                    },
                    |actual| shape_difference(value, actual),
                );
                difference.map(|suffix| format!("/{key}{suffix}"))
            })
        }
        (serde_json::Value::Array(expected), serde_json::Value::Array(actual)) => {
            if expected.len() != actual.len() {
                return Some(String::new());
            }
            expected
                .iter()
                .zip(actual)
                .enumerate()
                .find_map(|(index, (expected, actual))| {
                    shape_difference(expected, actual).map(|suffix| format!("/{index}{suffix}"))
                })
        }
        _ => (expected != actual).then(String::new),
    }
}

fn record_error(_: serde_json::Error) -> KubernetesDriverError {
    invalid("invalid warm runtime provisioning record")
}

fn invalid(message: &str) -> KubernetesDriverError {
    KubernetesDriverError::Precondition(message.into())
}

#[cfg(test)]
#[path = "warm_pool/tests.rs"]
mod tests;
