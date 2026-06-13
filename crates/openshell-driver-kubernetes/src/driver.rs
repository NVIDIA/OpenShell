// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes compute driver.

use crate::config::{
    AppArmorProfile, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_WORKSPACE_STORAGE_SIZE,
    KubernetesComputeConfig, SharedVolumeSpec, SupervisorSideloadMethod, WarmPoolSpec,
};
use futures::{Stream, StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Event as KubeEventObj, Node};
use kube::api::{Api, ApiResource, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, SUPERVISOR_IMAGE_BINARY_PATH,
};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    format_bytes, mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    DriverCondition as SandboxCondition, DriverPlatformEvent as PlatformEvent,
    DriverSandbox as Sandbox, DriverSandboxSpec as SandboxSpec,
    DriverSandboxStatus as SandboxStatus, DriverSandboxTemplate as SandboxTemplate,
    GetCapabilitiesResponse, WarmClaimBinding, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use openshell_core::proto_struct::{struct_to_json_object, value_to_json};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, KubernetesDriverError>> + Send>>;

#[derive(Debug, thiserror::Error)]
pub enum KubernetesDriverError {
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Message(String),
}

impl KubernetesDriverError {
    fn from_kube(err: KubeError) -> Self {
        match err {
            KubeError::Api(api) if api.code == 409 => Self::AlreadyExists,
            other => Self::Message(other.to_string()),
        }
    }
}

impl From<KubernetesDriverError> for openshell_core::ComputeDriverError {
    fn from(err: KubernetesDriverError) -> Self {
        match err {
            KubernetesDriverError::AlreadyExists => Self::AlreadyExists,
            KubernetesDriverError::InvalidArgument(m) => Self::InvalidArgument(m),
            KubernetesDriverError::Precondition(m) => Self::Precondition(m),
            KubernetesDriverError::Message(m) => Self::Message(m),
        }
    }
}

/// Timeout for individual Kubernetes API calls (create, delete, get).
/// This prevents gRPC handlers from blocking indefinitely when the k8s
/// API server is unreachable or slow.
const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);

// agent-sandbox CRD identity. Single source of truth in `openshell-core` so the
// gateway's auth re-anchor stays byte-identical with what this driver writes.
const SANDBOX_GROUP: &str = openshell_core::driver_utils::SANDBOX_CRD_GROUP;
const SANDBOX_VERSION: &str = openshell_core::driver_utils::SANDBOX_CRD_VERSION;
pub const SANDBOX_KIND: &str = openshell_core::driver_utils::SANDBOX_CRD_KIND;

// agent-sandbox warm-pool extension CRDs (extensions.agents.x-k8s.io/v1alpha1).
const EXT_GROUP: &str = openshell_core::driver_utils::SANDBOX_EXT_GROUP;
const EXT_VERSION: &str = openshell_core::driver_utils::SANDBOX_CRD_VERSION;
const SANDBOX_CLAIM_KIND: &str = openshell_core::driver_utils::SANDBOX_CLAIM_KIND;
const SANDBOX_TEMPLATE_KIND: &str = openshell_core::driver_utils::SANDBOX_TEMPLATE_KIND;
const SANDBOX_WARM_POOL_KIND: &str = openshell_core::driver_utils::SANDBOX_WARM_POOL_KIND;

/// Pod annotation carrying the per-sandbox identity. On the warm path it is
/// injected via `SandboxClaim.spec.additionalPodMetadata.annotations`; the
/// gateway resolves a pod's SA token back to this value during
/// `IssueSandboxToken`. Mirrors `auth::k8s_sa::SANDBOX_ID_ANNOTATION`.
const SANDBOX_ID_ANNOTATION: &str = openshell_core::driver_utils::SANDBOX_ID_ANNOTATION;
/// Label the upstream warm-pool controller stamps onto a bound `Sandbox` CR,
/// carrying the binding `SandboxClaim`'s UID. The driver distinguishes warm
/// Sandboxes from cold ones by the *absence* of `LABEL_SANDBOX_ID` (see
/// `is_cold_openshell_sandbox`), so this label is referenced only by tests that
/// construct representative bound-warm Sandboxes.
#[cfg(test)]
const CLAIM_UID_LABEL: &str = openshell_core::driver_utils::CLAIM_UID_LABEL;
/// Label the gateway stamps onto the `SandboxClaim`/`SandboxTemplate`/
/// `SandboxWarmPool` it owns, naming the originating pool.
const WARM_POOL_LABEL: &str = "openshell.ai/warm-pool";
/// Field manager used for server-side-apply of pool resources.
const WARM_POOL_FIELD_MANAGER: &str = "openshell-gateway-warmpool";

const GPU_RESOURCE_NAME: &str = "nvidia.com/gpu";
const GPU_RESOURCE_QUANTITY: &str = "1";
const SPIFFE_WORKLOAD_API_VOLUME_NAME: &str = "spiffe-workload-api";

// This POC treats the selected Struct as a driver-local typed schema. Once the
// Kubernetes shape stabilizes, these serde structs may move to driver-local
// protobuf definitions, but the typed decode should stay inside this driver.
// Do not promote Kubernetes config messages into the public API or gateway
// translation layer; the RFC boundary is Struct at the gateway, typed config in
// the selected driver.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesSandboxDriverConfig {
    pod: KubernetesPodDriverConfig,
    containers: KubernetesDriverContainersConfig,
}

impl KubernetesSandboxDriverConfig {
    fn from_sandbox(sandbox: &Sandbox) -> Result<Self, String> {
        let Some(template) = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
        else {
            return Ok(Self::default());
        };

        Self::from_template(template)
    }

    fn from_template(template: &SandboxTemplate) -> Result<Self, String> {
        let Some(config) = template.driver_config.as_ref() else {
            return Ok(Self::default());
        };

        let json = serde_json::Value::Object(struct_to_json_object(config));
        serde_json::from_value(json)
            .map_err(|err| format!("invalid kubernetes driver_config: {err}"))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesPodDriverConfig {
    node_selector: BTreeMap<String, String>,
    runtime_class_name: String,
    tolerations: Vec<serde_json::Value>,
    priority_class_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesDriverContainersConfig {
    agent: KubernetesContainerDriverConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesContainerDriverConfig {
    resources: KubernetesContainerResourceConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesContainerResourceConfig {
    requests: BTreeMap<String, String>,
    limits: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Default workspace persistence (temporary — will be replaced by snapshotting)
// ---------------------------------------------------------------------------
// Every sandbox pod gets a PVC-backed `/sandbox` directory so that user data
// (installed packages, files, dotfiles) survives pod rescheduling across
// gateway stop/start cycles.  An init container seeds the PVC with the
// image's original `/sandbox` contents on first use so that the Python venv,
// skills, and shell config are not lost when the empty PVC is mounted.
//
// NOTE: This PVC + init-container approach is a stopgap.  It has known
// limitations: image upgrades don't propagate into existing PVCs, the init
// copy adds first-start latency, and the full /sandbox directory is
// duplicated on disk.  The plan is to replace this with proper container
// snapshotting so that only the diff from the base image is persisted.

/// Volume name used for the workspace PVC in the pod spec.
const WORKSPACE_VOLUME_NAME: &str = "workspace";

/// Mount path for the workspace PVC in the **agent** container.  This shadows
/// the image's `/sandbox` directory — the init container copies the image
/// contents into the PVC before the agent starts.
const WORKSPACE_MOUNT_PATH: &str = "/sandbox";

/// Mount path for the workspace PVC in the **init** container.  A temporary
/// path so the init container can see the image's original `/sandbox` and
/// copy it into the PVC.
const WORKSPACE_INIT_MOUNT_PATH: &str = "/workspace-pvc";

/// Name of the init container that seeds the workspace PVC.
const WORKSPACE_INIT_CONTAINER_NAME: &str = "workspace-init";

/// Sentinel file written by the init container after copying the image's
/// `/sandbox` contents.  Subsequent pod starts skip the copy.
const WORKSPACE_SENTINEL: &str = ".workspace-initialized";

#[derive(Clone)]
pub struct KubernetesComputeDriver {
    client: Client,
    watch_client: Client,
    config: KubernetesComputeConfig,
}

impl std::fmt::Debug for KubernetesComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesComputeDriver")
            .field("namespace", &self.config.namespace)
            .field("default_image", &self.config.default_image)
            .field("grpc_endpoint", &self.config.grpc_endpoint)
            .finish()
    }
}

impl KubernetesComputeDriver {
    pub async fn new(config: KubernetesComputeConfig) -> Result<Self, KubernetesDriverError> {
        config
            .validate_provider_spiffe_workload_api_socket_path()
            .map_err(KubernetesDriverError::Precondition)?;
        let base_config = match kube::Config::incluster() {
            Ok(c) => c,
            Err(_) => kube::Config::infer()
                .await
                .map_err(kube::Error::InferConfig)
                .map_err(KubernetesDriverError::from_kube)?,
        };

        let mut kube_config = base_config.clone();
        kube_config.connect_timeout = Some(Duration::from_secs(10));
        kube_config.read_timeout = Some(Duration::from_secs(30));
        kube_config.write_timeout = Some(Duration::from_secs(30));
        let client = Client::try_from(kube_config).map_err(KubernetesDriverError::from_kube)?;

        let mut watch_kube_config = base_config;
        watch_kube_config.connect_timeout = Some(Duration::from_secs(10));
        watch_kube_config.read_timeout = None;
        watch_kube_config.write_timeout = Some(Duration::from_secs(30));
        let watch_client =
            Client::try_from(watch_kube_config).map_err(KubernetesDriverError::from_kube)?;

        Ok(Self {
            client,
            watch_client,
            config,
        })
    }

    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, String> {
        Ok(openshell_core::driver_utils::build_capabilities_response(
            "kubernetes",
            openshell_core::VERSION,
            &self.config.default_image,
        ))
    }

    pub fn default_image(&self) -> &str {
        &self.config.default_image
    }

    pub fn namespace(&self) -> &str {
        &self.config.namespace
    }

    pub fn ssh_socket_path(&self) -> &str {
        &self.config.ssh_socket_path
    }

    fn watch_api(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, SANDBOX_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        Api::namespaced_with(self.watch_client.clone(), &self.config.namespace, &resource)
    }

    fn api(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, SANDBOX_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        Api::namespaced_with(self.client.clone(), &self.config.namespace, &resource)
    }

    fn ext_api(&self, client: &Client, kind: &str) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(EXT_GROUP, EXT_VERSION, kind);
        let resource = ApiResource::from_gvk(&gvk);
        Api::namespaced_with(client.clone(), &self.config.namespace, &resource)
    }

    fn claims_api(&self) -> Api<DynamicObject> {
        self.ext_api(&self.client, SANDBOX_CLAIM_KIND)
    }

    fn watch_claims_api(&self) -> Api<DynamicObject> {
        self.ext_api(&self.watch_client, SANDBOX_CLAIM_KIND)
    }

    /// Whether warm pooling is enabled in driver config.
    fn warm_pool_enabled(&self) -> bool {
        self.config.warm_pool.enabled
    }

    /// Resolve the warm pool that a `CreateSandbox` request maps to, if any.
    ///
    /// Only the gateway's trusted `default_image` with no per-request template
    /// or env overrides is warm-pooled (issue #1879, remediation #7); anything
    /// else falls back to the cold path. Pools are matched by GPU shape.
    fn matching_warm_pool(&self, sandbox: &Sandbox) -> Option<&WarmPoolSpec> {
        if !self.warm_pool_enabled() {
            return None;
        }
        let spec = sandbox.spec.as_ref()?;
        if !warm_eligible(spec, &self.config.default_image) {
            return None;
        }
        self.config
            .warm_pool
            .pools
            .iter()
            .find(|pool| pool.gpu == spec.gpu)
    }

    /// Reconcile the operator-declared warm pools: server-side-apply one
    /// `SandboxTemplate` + one `SandboxWarmPool` per configured pool. Idempotent
    /// and safe to call on every startup. Non-fatal on individual failures —
    /// the cold path stays available regardless.
    pub async fn reconcile_warm_pools(&self) -> Result<(), KubernetesDriverError> {
        if !self.warm_pool_enabled() {
            return Ok(());
        }
        for pool in &self.config.warm_pool.pools {
            self.apply_warm_pool(pool).await?;
        }
        Ok(())
    }

    async fn apply_warm_pool(&self, pool: &WarmPoolSpec) -> Result<(), KubernetesDriverError> {
        let resource_name = warm_resource_name(&pool.name);
        let labels = warm_pool_labels(&pool.name);

        // SandboxTemplate: the shared, identity-free pod blueprint.
        let template_spec = build_warm_sandbox_template_spec(&self.config, pool);
        self.apply_ext_object(
            SANDBOX_TEMPLATE_KIND,
            &resource_name,
            &labels,
            serde_json::json!({ "spec": template_spec }),
        )
        .await?;

        // SandboxWarmPool: keeps `replicas` pods warm against that template.
        self.apply_ext_object(
            SANDBOX_WARM_POOL_KIND,
            &resource_name,
            &labels,
            serde_json::json!({
                "spec": {
                    "replicas": pool.replicas,
                    "sandboxTemplateRef": { "name": resource_name },
                }
            }),
        )
        .await?;

        info!(
            pool = %pool.name,
            replicas = pool.replicas,
            gpu = pool.gpu,
            "Reconciled warm pool"
        );
        Ok(())
    }

    async fn apply_ext_object(
        &self,
        kind: &str,
        name: &str,
        labels: &BTreeMap<String, String>,
        spec: serde_json::Value,
    ) -> Result<(), KubernetesDriverError> {
        let gvk = GroupVersionKind::gvk(EXT_GROUP, EXT_VERSION, kind);
        let resource = ApiResource::from_gvk(&gvk);
        let mut obj = DynamicObject::new(name, &resource);
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(self.config.namespace.clone()),
            labels: Some(labels.clone()),
            ..Default::default()
        };
        obj.data = spec;
        let api = self.ext_api(&self.client, kind);
        let params = PatchParams::apply(WARM_POOL_FIELD_MANAGER).force();
        tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.patch(name, &params, &Patch::Apply(&obj)),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out applying {kind}/{name} after {}s",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
        .map_err(KubernetesDriverError::from_kube)?;
        Ok(())
    }

    /// Bind a pre-warmed pod by creating a `SandboxClaim`. Returns the claim
    /// identity so the gateway can record the durable claim->sandbox-id mapping.
    async fn create_warm_claim(
        &self,
        sandbox: &Sandbox,
        pool: &WarmPoolSpec,
    ) -> Result<WarmClaimBinding, KubernetesDriverError> {
        let name = sandbox.name.as_str();
        let resource_name = warm_resource_name(&pool.name);

        let mut labels = warm_pool_labels(&pool.name);
        labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());

        let gvk = GroupVersionKind::gvk(EXT_GROUP, EXT_VERSION, SANDBOX_CLAIM_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut obj = DynamicObject::new(name, &resource);
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(self.config.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        };
        obj.data = warm_claim_spec(&resource_name, &sandbox.id);

        let created = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            self.claims_api().create(&PostParams::default(), &obj),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out creating SandboxClaim after {}s",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
        .map_err(KubernetesDriverError::from_kube)?;

        let claim_uid = created.metadata.uid.unwrap_or_default();
        if claim_uid.is_empty() {
            return Err(KubernetesDriverError::Message(
                "created SandboxClaim has no UID".to_string(),
            ));
        }
        info!(
            sandbox_id = %sandbox.id,
            claim = %name,
            claim_uid = %claim_uid,
            pool = %pool.name,
            "Bound warm sandbox via SandboxClaim"
        );
        Ok(WarmClaimBinding {
            namespace: self.config.namespace.clone(),
            claim_name: name.to_string(),
            claim_uid,
        })
    }

    async fn get_warm_sandbox(&self, name: &str) -> Result<Option<Sandbox>, String> {
        let api = self.claims_api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.get_opt(name)).await {
            Ok(Ok(Some(obj))) => sandbox_from_claim_object(&self.config.namespace, obj).map(Some),
            Ok(Ok(None)) => Ok(None),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    async fn list_warm_sandboxes(&self) -> Result<Vec<Sandbox>, String> {
        let selector = format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}");
        let params = ListParams::default().labels(&selector);
        let api = self.claims_api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.list(&params)).await {
            Ok(Ok(list)) => list
                .items
                .into_iter()
                .filter(|obj| {
                    obj.metadata
                        .labels
                        .as_ref()
                        .is_some_and(|labels| labels.contains_key(LABEL_SANDBOX_ID))
                })
                .map(|obj| sandbox_from_claim_object(&self.config.namespace, obj))
                .collect::<Result<Vec<_>, _>>(),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    /// Delete a warm-pool `SandboxClaim` by name. `shutdownPolicy: Delete`
    /// cascades teardown to the bound `Sandbox` + Pod. Returns `Ok(true)` when a
    /// claim was deleted; `Ok(false)` when warm pooling is disabled or no such
    /// claim exists (the caller then falls through to the cold `Sandbox` path —
    /// e.g. a cold sandbox created while warm pooling was on).
    async fn delete_warm_claim(&self, name: &str) -> Result<bool, String> {
        if !self.warm_pool_enabled() {
            return Ok(false);
        }
        let api = self.claims_api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.delete(name, &DeleteParams::default()))
            .await
        {
            Ok(Ok(_)) => {
                info!(claim = %name, "Deleted warm SandboxClaim");
                Ok(true)
            }
            Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(false),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    async fn has_gpu_capacity(&self) -> Result<bool, KubeError> {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let node_list = nodes.list(&ListParams::default()).await?;
        Ok(node_list.items.into_iter().any(|node| {
            node.status
                .and_then(|status| status.allocatable)
                .and_then(|allocatable| allocatable.get(GPU_RESOURCE_NAME).cloned())
                .is_some_and(|quantity| quantity.0 != "0")
        }))
    }

    pub async fn validate_sandbox_create(&self, sandbox: &Sandbox) -> Result<(), tonic::Status> {
        let _ = KubernetesSandboxDriverConfig::from_sandbox(sandbox)
            .map_err(tonic::Status::invalid_argument)?;
        let gpu_requested = sandbox.spec.as_ref().is_some_and(|spec| spec.gpu);
        if gpu_requested
            && !self.has_gpu_capacity().await.map_err(|err| {
                tonic::Status::internal(format!("check GPU node capacity failed: {err}"))
            })?
        {
            return Err(tonic::Status::failed_precondition(
                "GPU sandbox requested, but the active gateway has no allocatable GPUs. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration.",
            ));
        }
        Ok(())
    }

    pub async fn get_sandbox(&self, name: &str) -> Result<Option<Sandbox>, String> {
        info!(
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Fetching sandbox from Kubernetes"
        );

        let api = self.api();
        let cold = match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(name)).await {
            Ok(Ok(obj)) => Some(obj),
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                debug!(sandbox_name = %name, "Sandbox not found in Kubernetes");
                None
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_name = %name,
                    error = %err,
                    "Failed to fetch sandbox from Kubernetes"
                );
                return Err(err.to_string());
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out fetching sandbox from Kubernetes"
                );
                return Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ));
            }
        };

        // A cold Sandbox CR named `name` resolves directly; warm-pool Sandbox
        // CRs (pooled or claim-bound) lack the openshell sandbox-id label and
        // are addressed via their SandboxClaim instead, so fall through to the
        // warm lookup for those.
        if let Some(obj) = cold
            && is_cold_openshell_sandbox(&obj)
        {
            return sandbox_from_object(&self.config.namespace, obj).map(Some);
        }
        if self.warm_pool_enabled() {
            return self.get_warm_sandbox(name).await;
        }
        Ok(None)
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<Sandbox>, String> {
        info!(
            namespace = %self.config.namespace,
            "Listing sandboxes from Kubernetes"
        );

        let api = self.api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.list(&ListParams::default())).await {
            Ok(Ok(list)) => {
                // Cold Sandbox CRs only; warm-pool Sandboxes (pooled or bound)
                // are surfaced via their SandboxClaim below — their generic
                // names carry no openshell sandbox-id and would otherwise fail
                // to map.
                let mut sandboxes = list
                    .items
                    .into_iter()
                    .filter(is_cold_openshell_sandbox)
                    .map(|obj| sandbox_from_object(&self.config.namespace, obj))
                    .collect::<Result<Vec<_>, _>>()?;
                if self.warm_pool_enabled() {
                    sandboxes.extend(self.list_warm_sandboxes().await?);
                }
                sandboxes.sort_by(|left, right| {
                    left.name
                        .cmp(&right.name)
                        .then_with(|| left.id.cmp(&right.id))
                });
                Ok(sandboxes)
            }
            Ok(Err(err)) => {
                warn!(
                    namespace = %self.config.namespace,
                    error = %err,
                    "Failed to list sandboxes from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    namespace = %self.config.namespace,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out listing sandboxes from Kubernetes"
                );
                Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ))
            }
        }
    }

    pub async fn create_sandbox(
        &self,
        sandbox: &Sandbox,
    ) -> Result<Option<WarmClaimBinding>, KubernetesDriverError> {
        let _ = KubernetesSandboxDriverConfig::from_sandbox(sandbox)
            .map_err(KubernetesDriverError::InvalidArgument)?;
        let name = sandbox.name.as_str();

        // Warm path: when the request matches an operator-declared pool, bind a
        // pre-warmed pod via a SandboxClaim instead of cold-creating a Sandbox.
        if let Some(pool) = self.matching_warm_pool(sandbox) {
            let pool = pool.clone();
            return self.create_warm_claim(sandbox, &pool).await.map(Some);
        }

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Creating sandbox in Kubernetes"
        );

        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, SANDBOX_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut obj = DynamicObject::new(name, &resource);
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(self.config.namespace.clone()),
            labels: Some(sandbox_labels(sandbox)),
            ..Default::default()
        };
        let params = SandboxPodParams {
            default_image: &self.config.default_image,
            image_pull_policy: &self.config.image_pull_policy,
            image_pull_secrets: &self.config.image_pull_secrets,
            supervisor_image: &self.config.supervisor_image,
            supervisor_image_pull_policy: &self.config.supervisor_image_pull_policy,
            supervisor_sideload_method: self.config.supervisor_sideload_method,
            service_account_name: &self.config.service_account_name,
            sandbox_id: &sandbox.id,
            sandbox_name: &sandbox.name,
            grpc_endpoint: &self.config.grpc_endpoint,
            ssh_socket_path: self.ssh_socket_path(),
            client_tls_secret_name: &self.config.client_tls_secret_name,
            host_gateway_ip: &self.config.host_gateway_ip,
            enable_user_namespaces: self.config.enable_user_namespaces,
            app_armor_profile: self.config.app_armor_profile.as_ref(),
            workspace_default_storage_size: &self.config.workspace_default_storage_size,
            default_runtime_class_name: &self.config.default_runtime_class_name,
            sa_token_ttl_secs: self.config.effective_sa_token_ttl_secs(),
            provider_spiffe_enabled: self.config.provider_spiffe_enabled(),
            provider_spiffe_workload_api_socket_path: &self
                .config
                .provider_spiffe_workload_api_socket_path,
        };
        obj.data = sandbox_to_k8s_spec(sandbox.spec.as_ref(), &params);
        let api = self.api();

        match tokio::time::timeout(KUBE_API_TIMEOUT, api.create(&PostParams::default(), &obj)).await
        {
            Ok(Ok(_result)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "Sandbox created in Kubernetes successfully"
                );
                Ok(None)
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    error = %err,
                    "Failed to create sandbox in Kubernetes"
                );
                Err(KubernetesDriverError::from_kube(err))
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out creating sandbox in Kubernetes"
                );
                Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                )))
            }
        }
    }

    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, String> {
        info!(
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Deleting sandbox from Kubernetes"
        );

        // Warm path: a matching SandboxClaim is single-use; deleting it
        // cascades teardown to the bound Sandbox + Pod (shutdownPolicy: Delete),
        // so a claimed pod/Sandbox is never returned to the pool. A miss falls
        // through to the cold Sandbox delete below.
        if self.delete_warm_claim(name).await? {
            return Ok(true);
        }

        let api = self.api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.delete(name, &DeleteParams::default()))
            .await
        {
            Ok(Ok(_response)) => {
                info!(sandbox_name = %name, "Sandbox deleted from Kubernetes");
                Ok(true)
            }
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                debug!(sandbox_name = %name, "Sandbox not found in Kubernetes (already deleted)");
                Ok(false)
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_name = %name,
                    error = %err,
                    "Failed to delete sandbox from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out deleting sandbox from Kubernetes"
                );
                Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ))
            }
        }
    }

    pub async fn sandbox_exists(&self, name: &str) -> Result<bool, String> {
        let api = self.api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(name)).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(false),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    // Kept `async` to match the gRPC handler signature in `grpc.rs`, which awaits this method.
    #[allow(clippy::unused_async)]
    pub async fn watch_sandboxes(&self) -> Result<WatchStream, String> {
        let namespace = self.config.namespace.clone();
        let sandbox_api = self.watch_api();
        let event_api: Api<KubeEventObj> = Api::namespaced(self.watch_client.clone(), &namespace);
        let mut sandbox_stream = watcher::watcher(sandbox_api, watcher::Config::default()).boxed();
        let mut event_stream = watcher::watcher(event_api, watcher::Config::default()).boxed();
        // Watch warm-pool SandboxClaims only when warm pooling is enabled; the
        // extension CRDs may not be installed otherwise. A `pending` stream
        // keeps the select arm inert when disabled.
        let mut claim_stream = if self.warm_pool_enabled() {
            watcher::watcher(self.watch_claims_api(), watcher::Config::default()).boxed()
        } else {
            futures::stream::pending().boxed()
        };
        let (tx, rx) = mpsc::channel(256);

        tokio::spawn(async move {
            let mut sandbox_name_to_id = std::collections::HashMap::<String, String>::new();
            let mut agent_pod_to_id = std::collections::HashMap::<String, String>::new();

            loop {
                tokio::select! {
                    result = sandbox_stream.try_next() => match result {
                        // Only cold OpenShell Sandbox CRs are mapped here; warm-
                        // pool Sandboxes (pooled or claim-bound) lack the
                        // openshell sandbox-id label and are surfaced via the
                        // SandboxClaim watcher below, so skip them to avoid
                        // failing on their identity-free generic names.
                        Ok(Some(Event::Applied(obj))) => {
                            if !is_cold_openshell_sandbox(&obj) { continue; }
                            match sandbox_from_object(&namespace, obj) {
                                Ok(sandbox) => {
                                    update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox);
                                    let event = WatchSandboxesEvent {
                                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                            WatchSandboxesSandboxEvent { sandbox: Some(sandbox) }
                                        )),
                                    };
                                    if tx.send(Ok(event)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(err) => {
                                    if tx.send(Err(KubernetesDriverError::Message(err))).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(Some(Event::Deleted(obj))) => {
                            if !is_cold_openshell_sandbox(&obj) { continue; }
                            match sandbox_id_from_object(&obj) {
                                Ok(sandbox_id) => {
                                    remove_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox_id);
                                    let event = WatchSandboxesEvent {
                                        payload: Some(watch_sandboxes_event::Payload::Deleted(
                                            WatchSandboxesDeletedEvent { sandbox_id }
                                        )),
                                    };
                                    if tx.send(Ok(event)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(err) => {
                                    if tx.send(Err(KubernetesDriverError::Message(err))).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(Some(Event::Restarted(objs))) => {
                            for obj in objs {
                                if !is_cold_openshell_sandbox(&obj) { continue; }
                                match sandbox_from_object(&namespace, obj) {
                                    Ok(sandbox) => {
                                        update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox);
                                        let event = WatchSandboxesEvent {
                                            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                                WatchSandboxesSandboxEvent { sandbox: Some(sandbox) }
                                            )),
                                        };
                                        if tx.send(Ok(event)).await.is_err() {
                                            return;
                                        }
                                    }
                                    Err(err) => {
                                        if tx.send(Err(KubernetesDriverError::Message(err))).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "sandbox watcher stream ended unexpectedly".to_string()
                            ))).await;
                            break;
                        }
                        Err(err) => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(err.to_string()))).await;
                            break;
                        }
                    },
                    result = claim_stream.try_next() => match result {
                        Ok(Some(Event::Applied(obj))) => {
                            if let Some(sandbox) = managed_claim_sandbox(&namespace, &obj) {
                                update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox);
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent { sandbox: Some(sandbox) }
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Some(Event::Deleted(obj))) => {
                            if let Some(sandbox_id) = sandbox_id_from_claim_object(&obj) {
                                remove_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox_id);
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Deleted(
                                        WatchSandboxesDeletedEvent { sandbox_id }
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Some(Event::Restarted(objs))) => {
                            for obj in objs {
                                if let Some(sandbox) = managed_claim_sandbox(&namespace, &obj) {
                                    update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox);
                                    let event = WatchSandboxesEvent {
                                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                            WatchSandboxesSandboxEvent { sandbox: Some(sandbox) }
                                        )),
                                    };
                                    if tx.send(Ok(event)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "sandbox claim watcher stream ended".to_string()
                            ))).await;
                            break;
                        }
                        Err(err) => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(err.to_string()))).await;
                            break;
                        }
                    },
                    result = event_stream.try_next() => match result {
                        Ok(Some(Event::Applied(obj))) => {
                            if let Some((sandbox_id, event)) = map_kube_event_to_platform(
                                &sandbox_name_to_id,
                                &agent_pod_to_id,
                                &obj,
                            ) {
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
                                        WatchSandboxesPlatformEvent { sandbox_id, event: Some(event) }
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Some(Event::Deleted(_))) => {}
                        Ok(Some(Event::Restarted(_))) => {
                            debug!(namespace = %namespace, "Kubernetes event watcher restarted");
                        }
                        Ok(None) => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "kubernetes event watcher stream ended".to_string()
                            ))).await;
                            break;
                        }
                        Err(err) => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(err.to_string()))).await;
                            break;
                        }
                    }
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

fn sandbox_labels(sandbox: &Sandbox) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels
}

fn sandbox_id_from_object(obj: &DynamicObject) -> Result<String, String> {
    if let Some(labels) = obj.metadata.labels.as_ref()
        && let Some(id) = labels.get(LABEL_SANDBOX_ID)
    {
        return Ok(id.clone());
    }

    let name = obj.metadata.name.clone().unwrap_or_default();
    if let Some(id) = name.strip_prefix("sandbox-") {
        return Ok(id.to_string());
    }

    Err("sandbox id not found on object".to_string())
}

fn sandbox_from_object(namespace: &str, obj: DynamicObject) -> Result<Sandbox, String> {
    let id = sandbox_id_from_object(&obj)?;
    let name = obj.metadata.name.clone().unwrap_or_default();
    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let status = status_from_object(&obj);

    Ok(Sandbox {
        id,
        name,
        namespace,
        spec: None,
        status,
    })
}

// ---------------------------------------------------------------------------
// Warm-pool helpers
// ---------------------------------------------------------------------------

/// True when a `Sandbox` CR is a cold `OpenShell`-created sandbox — it carries
/// the `openshell.ai/sandbox-id` label set by `sandbox_labels`. Warm-pool
/// Sandbox CRs (created by the `SandboxWarmPool`) never carry it: while still
/// pooled they have neither identity label, and once bound they carry only the
/// upstream `agents.x-k8s.io/claim-uid` label. Both are surfaced to the gateway
/// via the `SandboxClaim` watcher instead, so the cold Sandbox watcher/list
/// must skip everything that is not a cold sandbox — otherwise it fails to map
/// their identity-free generic names ("sandbox id not found on object").
fn is_cold_openshell_sandbox(obj: &DynamicObject) -> bool {
    obj.metadata
        .labels
        .as_ref()
        .is_some_and(|labels| labels.contains_key(LABEL_SANDBOX_ID))
}

/// Name shared by a pool's `SandboxTemplate` and `SandboxWarmPool`.
fn warm_resource_name(pool_name: &str) -> String {
    format!("openshell-warmpool-{pool_name}")
}

/// Labels stamped onto gateway-owned warm-pool resources.
fn warm_pool_labels(pool_name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels.insert(WARM_POOL_LABEL.to_string(), pool_name.to_string());
    labels
}

/// Whether a `CreateSandbox` request is eligible for warm pooling. Only the
/// gateway's trusted `default_image` with no per-request template or env
/// overrides qualifies (issue #1879, remediation #7); anything else falls back
/// to the cold path (where per-sandbox env/identity can be injected freely).
///
/// Fail-closed *by construction*: both the spec and its template are
/// destructured exhaustively, so adding a field to `DriverSandboxSpec` or
/// `DriverSandboxTemplate` will not compile here until the new field is
/// explicitly classified as warm-safe or cold-only. This forecloses the
/// silent-drop class of bug where a per-request field is honored on the cold
/// path but ignored by the pooled template (issue #1879, PR #1813 review #1).
fn warm_eligible(spec: &SandboxSpec, default_image: &str) -> bool {
    let SandboxSpec {
        // The gateway forbids warm-pooling requests carrying a custom policy: a
        // warm pod boots on the pool's baseline policy and cannot late-bind a
        // per-sandbox policy (Landlock is applied once at process start), so
        // warm-pooling such a request would silently downgrade its policy.
        disallow_warm_pool,
        // Warm-safe. `gpu` selects the matching pool shape (see
        // `matching_warm_pool`); `sandbox_token` is ignored by the Kubernetes
        // driver (identity comes from the projected ServiceAccount token), so
        // neither forces the cold path.
        gpu: _,
        sandbox_token: _,
        // Cold-only. The pooled pod's env/log level are fixed at warm-up time
        // (the cold path threads these into the pod env via `spec_pod_env`).
        // (A specific GPU device now rides in the template's `driver_config`,
        // which the template check below rejects, so it also forces cold.)
        log_level,
        environment,
        // Per-request runtime overrides — validated field-by-field below.
        template,
    } = spec;

    if *disallow_warm_pool || !log_level.is_empty() || !environment.is_empty() {
        return false;
    }

    let Some(template) = template.as_ref() else {
        return true;
    };
    let SandboxTemplate {
        // Warm-safe only when empty or equal to the pool's default image.
        image,
        // Cold-only: consumed cold-side as the Sandbox spec's `agentSocket`;
        // the pooled template uses the default, so a per-request value would be
        // silently ignored.
        agent_socket_path,
        // Cold-only: the pooled pod's labels/env/resources are fixed at warm-up
        // and platform/driver config is baked into the `SandboxTemplate`.
        labels,
        environment,
        resources,
        platform_config,
        driver_config,
    } = template;

    (image.is_empty() || image.as_str() == default_image)
        && agent_socket_path.is_empty()
        && labels.is_empty()
        && environment.is_empty()
        && resources.is_none()
        && platform_config
            .as_ref()
            .is_none_or(|pc| pc.fields.is_empty())
        && driver_config.as_ref().is_none_or(|dc| dc.fields.is_empty())
}

/// Build the `SandboxTemplate.spec` for a warm pool: the shared pod blueprint
/// with **no** per-sandbox identity (no `openshell.io/sandbox-id` annotation, no
/// per-sandbox env). The writable `/sandbox` workspace is an ephemeral
/// `emptyDir` seeded from the image (single-use, nothing to orphan); an optional
/// shared volume is mounted read-only.
fn build_warm_sandbox_template_spec(
    config: &KubernetesComputeConfig,
    pool: &WarmPoolSpec,
) -> serde_json::Value {
    let runtime_class = if pool.runtime_class_name.is_empty() {
        config.default_runtime_class_name.clone()
    } else {
        pool.runtime_class_name.clone()
    };
    let params = SandboxPodParams {
        default_image: &config.default_image,
        image_pull_policy: &config.image_pull_policy,
        image_pull_secrets: &config.image_pull_secrets,
        supervisor_image: &config.supervisor_image,
        supervisor_image_pull_policy: &config.supervisor_image_pull_policy,
        supervisor_sideload_method: config.supervisor_sideload_method,
        service_account_name: &config.service_account_name,
        // Pooled pods are identity-free; the per-sandbox id is late-bound via
        // the SandboxClaim annotation + the IssueSandboxToken exchange.
        sandbox_id: "",
        sandbox_name: "",
        grpc_endpoint: &config.grpc_endpoint,
        ssh_socket_path: &config.ssh_socket_path,
        client_tls_secret_name: &config.client_tls_secret_name,
        host_gateway_ip: &config.host_gateway_ip,
        enable_user_namespaces: config.enable_user_namespaces,
        app_armor_profile: config.app_armor_profile.as_ref(),
        workspace_default_storage_size: &config.workspace_default_storage_size,
        default_runtime_class_name: &runtime_class,
        sa_token_ttl_secs: config.effective_sa_token_ttl_secs(),
        // Pooled pods are identity-free and carry no per-sandbox providers, so
        // they never mount provider-token-grant SPIFFE material. If a claimed
        // warm sandbox needs providers that is late-bound (out of scope here).
        provider_spiffe_enabled: false,
        provider_spiffe_workload_api_socket_path: "",
    };

    let empty_env = std::collections::HashMap::new();
    // inject_workspace=false: suppress the cold-path PVC workspace; an ephemeral
    // emptyDir workspace is attached below instead.
    let mut pod_template = sandbox_template_to_k8s(
        &SandboxTemplate::default(),
        pool.gpu,
        &empty_env,
        false,
        &params,
    );
    apply_ephemeral_workspace(
        &mut pod_template,
        &config.default_image,
        &config.image_pull_policy,
    );
    if let Some(shared) = pool.shared_volume.as_ref() {
        apply_shared_readonly_volume(&mut pod_template, shared);
    }

    serde_json::json!({
        "podTemplate": pod_template,
        // Reject per-claim env injection on the warm path: pod env is immutable
        // once running and identity must never ride pod env.
        "envVarsInjectionPolicy": "Disallowed",
        // Do NOT let the warm-pool controller manage a NetworkPolicy for these
        // pods. With no rules a Managed (the upstream default) NetworkPolicy is
        // default-deny and blocks the pod's egress to the gateway, so the
        // supervisor can never reach `IssueSandboxToken` / open its relay
        // session. OpenShell enforces egress itself via the supervisor proxy +
        // Landlock, so cluster NetworkPolicy management is left off here, matching
        // the cold path (which has no NetworkPolicy at all).
        "networkPolicyManagement": "Unmanaged",
    })
}

/// Build the `SandboxClaim.spec` JSON that binds a pre-warmed pod: it references
/// the pool template/warmpool, injects only the per-sandbox identity annotation,
/// and forces single-use teardown (`shutdownPolicy: Delete`, never `Retain`).
fn warm_claim_spec(resource_name: &str, sandbox_id: &str) -> serde_json::Value {
    serde_json::json!({
        "spec": {
            "sandboxTemplateRef": { "name": resource_name },
            "warmpool": resource_name,
            "additionalPodMetadata": {
                "annotations": { SANDBOX_ID_ANNOTATION: sandbox_id }
            },
            // Single-use: claim deletion must destroy the bound Sandbox/Pod (and
            // any backing storage). Never `Retain` (orphans data).
            "lifecycle": { "shutdownPolicy": "Delete" }
        }
    })
}

/// Attach an ephemeral `emptyDir` writable workspace at `/sandbox`, seeded from
/// the image on first start. Single-use and fail-safe: the kubelet reclaims it
/// with the pod, so there is nothing to orphan (vs. the cold path's PVC).
fn apply_ephemeral_workspace(
    pod_template: &mut serde_json::Value,
    image: &str,
    image_pull_policy: &str,
) {
    // The cold path relies on the Sandbox CRD controller to materialise a PVC
    // volume from `volumeClaimTemplates`; warm pods have none, so add the
    // emptyDir volume here. The mount + seed init-container are shared.
    if let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut())
        && let Some(volumes) = spec
            .entry("volumes")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
    {
        volumes.push(serde_json::json!({
            "name": WORKSPACE_VOLUME_NAME,
            "emptyDir": {}
        }));
    }
    apply_workspace_persistence(pod_template, image, image_pull_policy);
}

/// Mount a pre-existing PVC read-only into the agent container (shared datasets
/// / models / caches). Safe to share precisely because it is read-only and
/// holds no per-agent state.
fn apply_shared_readonly_volume(pod_template: &mut serde_json::Value, shared: &SharedVolumeSpec) {
    const SHARED_VOLUME_NAME: &str = "openshell-shared-data";
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    if let Some(volumes) = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
    {
        volumes.push(serde_json::json!({
            "name": SHARED_VOLUME_NAME,
            "persistentVolumeClaim": {
                "claimName": shared.claim_name,
                "readOnly": true
            }
        }));
    }

    let Some(containers) = spec.get_mut("containers").and_then(|v| v.as_array_mut()) else {
        return;
    };
    let index = containers
        .iter()
        .position(|c| c.get("name").and_then(|v| v.as_str()) == Some("agent"))
        .unwrap_or(0);
    if let Some(container) = containers.get_mut(index).and_then(|v| v.as_object_mut()) {
        let mut mount = serde_json::json!({
            "name": SHARED_VOLUME_NAME,
            "mountPath": shared.mount_path,
            "readOnly": true
        });
        if !shared.sub_path.is_empty() {
            mount["subPath"] = serde_json::json!(shared.sub_path);
        }
        if let Some(mounts) = container
            .entry("volumeMounts")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
        {
            mounts.push(mount);
        }
    }
}

/// Extract the gateway sandbox-id stamped on a managed `SandboxClaim`.
fn sandbox_id_from_claim_object(obj: &DynamicObject) -> Option<String> {
    obj.metadata
        .labels
        .as_ref()?
        .get(LABEL_SANDBOX_ID)
        .filter(|v| !v.is_empty())
        .cloned()
}

/// Map a managed warm-pool `SandboxClaim` to a driver `Sandbox`, or `None` when
/// it is not one of ours (missing the gateway sandbox-id label).
fn managed_claim_sandbox(namespace: &str, obj: &DynamicObject) -> Option<Sandbox> {
    sandbox_id_from_claim_object(obj)?;
    sandbox_from_claim_object(namespace, obj.clone()).ok()
}

/// Build a driver `Sandbox` from a warm-pool `SandboxClaim`. The id comes from
/// the gateway-set `openshell.ai/sandbox-id` label; status is derived from the
/// claim binding.
fn sandbox_from_claim_object(namespace: &str, obj: DynamicObject) -> Result<Sandbox, String> {
    let id = sandbox_id_from_claim_object(&obj)
        .ok_or_else(|| "SandboxClaim missing openshell.ai/sandbox-id label".to_string())?;
    let name = obj.metadata.name.clone().unwrap_or_default();
    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let status = Some(claim_status_to_sandbox_status(&obj));
    Ok(Sandbox {
        id,
        name,
        namespace,
        spec: None,
        status,
    })
}

/// Derive a driver status from a `SandboxClaim`. The bound `Sandbox`'s name is
/// used as the instance id (best-effort event correlation) and the claim
/// identity is surfaced so the gateway can back-fill or GC the durable claim
/// mapping. Readiness is ultimately driven by the supervisor session.
fn claim_status_to_sandbox_status(obj: &DynamicObject) -> SandboxStatus {
    let claim_name = obj.metadata.name.clone().unwrap_or_default();
    let claim_uid = obj.metadata.uid.clone().unwrap_or_default();
    let status_obj = obj.data.get("status").and_then(|s| s.as_object());

    let bound_sandbox = status_obj
        .and_then(|s| s.get("sandbox"))
        .and_then(|s| s.as_object())
        .and_then(|s| s.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let conditions = status_obj
        .and_then(|s| s.get("conditions"))
        .and_then(|val| val.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(condition_from_value)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    SandboxStatus {
        sandbox_name: bound_sandbox.clone(),
        instance_id: bound_sandbox,
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions,
        deleting: obj.metadata.deletion_timestamp.is_some(),
        claim_name,
        claim_uid,
    }
}

fn update_indexes(
    sandbox_name_to_id: &mut std::collections::HashMap<String, String>,
    agent_pod_to_id: &mut std::collections::HashMap<String, String>,
    sandbox: &Sandbox,
) {
    if !sandbox.name.is_empty() {
        sandbox_name_to_id.insert(sandbox.name.clone(), sandbox.id.clone());
    }
    if let Some(status) = sandbox.status.as_ref()
        && !status.instance_id.is_empty()
    {
        agent_pod_to_id.insert(status.instance_id.clone(), sandbox.id.clone());
    }
}

fn remove_indexes(
    sandbox_name_to_id: &mut std::collections::HashMap<String, String>,
    agent_pod_to_id: &mut std::collections::HashMap<String, String>,
    sandbox_id: &str,
) {
    sandbox_name_to_id.retain(|_, value| value != sandbox_id);
    agent_pod_to_id.retain(|_, value| value != sandbox_id);
}

fn map_kube_event_to_platform(
    sandbox_name_to_id: &std::collections::HashMap<String, String>,
    agent_pod_to_id: &std::collections::HashMap<String, String>,
    obj: &KubeEventObj,
) -> Option<(String, PlatformEvent)> {
    let involved = obj.involved_object.clone();
    let involved_kind = involved.kind.unwrap_or_default();
    let involved_name = involved.name.unwrap_or_default();

    let sandbox_id = match involved_kind.as_str() {
        "Sandbox" => sandbox_name_to_id.get(&involved_name).cloned()?,
        "Pod" => sandbox_name_to_id
            .get(&involved_name)
            .cloned()
            .or_else(|| agent_pod_to_id.get(&involved_name).cloned())?,
        _ => return None,
    };

    let ts = obj
        .last_timestamp
        .as_ref()
        .or(obj.first_timestamp.as_ref())
        .map_or(0, |t| t.0.timestamp_millis());

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("involved_kind".to_string(), involved_kind);
    metadata.insert("involved_name".to_string(), involved_name);
    if let Some(ns) = &obj.involved_object.namespace {
        metadata.insert("namespace".to_string(), ns.clone());
    }
    if let Some(count) = obj.count {
        metadata.insert("count".to_string(), count.to_string());
    }
    attach_kube_progress_metadata(
        &mut metadata,
        obj.reason.as_deref().unwrap_or_default(),
        obj.message.as_deref().unwrap_or_default(),
    );

    Some((
        sandbox_id,
        PlatformEvent {
            timestamp_ms: ts,
            source: "kubernetes".to_string(),
            r#type: obj.type_.clone().unwrap_or_default(),
            reason: obj.reason.clone().unwrap_or_default(),
            message: obj.message.clone().unwrap_or_default(),
            metadata,
        },
    ))
}

fn attach_kube_progress_metadata(
    metadata: &mut std::collections::HashMap<String, String>,
    reason: &str,
    message: &str,
) {
    match reason {
        "Scheduled" => {
            mark_progress_complete(
                metadata,
                PROGRESS_STEP_REQUESTING_SANDBOX,
                "Sandbox allocated",
            );
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
        }
        "Pulling" => {
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(image) = pulling_image_from_kube_message(message) {
                mark_progress_detail(metadata, image);
            }
        }
        "Pulled" => {
            let label = pulled_image_label(message);
            mark_progress_complete(metadata, PROGRESS_STEP_PULLING_IMAGE, label);
            mark_progress_active(metadata, PROGRESS_STEP_STARTING_SANDBOX);
        }
        _ => {}
    }
}

fn pulling_image_from_kube_message(message: &str) -> Option<String> {
    let image = message
        .strip_prefix("Pulling image ")
        .map(str::trim)
        .map(|value| value.trim_matches('"'))?;
    (!image.is_empty()).then(|| image.to_string())
}

fn pulled_image_label(message: &str) -> String {
    extract_image_size(message).map_or_else(
        || "Image pulled".to_string(),
        |bytes| format!("Image pulled ({})", format_bytes(bytes)),
    )
}

fn extract_image_size(message: &str) -> Option<u64> {
    let size_prefix = "Image size: ";
    let start = message.find(size_prefix)? + size_prefix.len();
    let rest = &message[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

/// Path where the supervisor binary is mounted inside the agent container.
const SUPERVISOR_MOUNT_PATH: &str = openshell_core::driver_utils::SUPERVISOR_CONTAINER_DIR;

/// Name of the volume used to side-load the supervisor binary.
const SUPERVISOR_VOLUME_NAME: &str = "openshell-supervisor-bin";

/// Name of the init container that installs the supervisor binary.
const SUPERVISOR_INIT_CONTAINER_NAME: &str = "openshell-supervisor-install";

/// Build the emptyDir volume that holds the supervisor binary.
///
/// The init container writes the binary here; the agent container reads it.
fn supervisor_volume() -> serde_json::Value {
    serde_json::json!({
        "name": SUPERVISOR_VOLUME_NAME,
        "emptyDir": {}
    })
}

/// Build the read-only volume mount for the supervisor binary in the agent container.
fn supervisor_volume_mount() -> serde_json::Value {
    serde_json::json!({
        "name": SUPERVISOR_VOLUME_NAME,
        "mountPath": SUPERVISOR_MOUNT_PATH,
        "readOnly": true
    })
}

/// Build an image volume that mounts the supervisor OCI image directly.
///
/// Requires Kubernetes >= v1.33 (`ImageVolume` beta) or >= v1.36 (GA).
/// The entire image filesystem is mounted read-only, making the binary
/// available at `{SUPERVISOR_MOUNT_PATH}/openshell-sandbox`.
fn supervisor_image_volume(
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
) -> serde_json::Value {
    let mut image_spec = serde_json::json!({
        "reference": supervisor_image,
    });
    if !supervisor_image_pull_policy.is_empty() {
        image_spec["pullPolicy"] = serde_json::json!(supervisor_image_pull_policy);
    }
    serde_json::json!({
        "name": SUPERVISOR_VOLUME_NAME,
        "image": image_spec
    })
}

/// Build the init container that copies the supervisor binary into the emptyDir.
///
/// The supervisor image contains the supervisor binary at `/openshell-sandbox`.
/// We invoke that binary with the `copy-self` subcommand so it copies itself
/// into the shared emptyDir volume, where the agent container then executes it
/// from a fixed, writable path. This pattern (binary self-copy) avoids requiring
/// `sh`/`cp` in the supervisor image and mirrors the approach used by argoexec's
/// emissary executor.
fn supervisor_init_container(
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
) -> serde_json::Value {
    let installed_path = format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox");
    let mut spec = serde_json::json!({
        "name": SUPERVISOR_INIT_CONTAINER_NAME,
        "image": supervisor_image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "copy-self",
            installed_path,
        ],
        "securityContext": {"runAsUser": 0},
        "volumeMounts": [{
            "name": SUPERVISOR_VOLUME_NAME,
            "mountPath": SUPERVISOR_MOUNT_PATH,
            "readOnly": false
        }]
    });
    if !supervisor_image_pull_policy.is_empty() {
        spec["imagePullPolicy"] = serde_json::json!(supervisor_image_pull_policy);
    }
    spec
}

/// Apply supervisor side-load transforms to an already-built pod template JSON.
///
/// Depending on the sideload method:
/// - **`ImageVolume`**: mounts the supervisor OCI image directly as a read-only
///   volume (no init container needed, requires K8s >= v1.33).
/// - **`InitContainer`**: injects an emptyDir volume and an init container that
///   copies the supervisor binary from the supervisor image into that volume.
///
/// In both cases, the agent container gets a command override to run the
/// side-loaded binary and `runAsUser: 0` so it can create network namespaces,
/// set up the proxy, and configure Landlock/seccomp.
fn apply_supervisor_sideload(
    pod_template: &mut serde_json::Value,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
    method: SupervisorSideloadMethod,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // 1. Add the volume (image source or emptyDir depending on method)
    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        match method {
            SupervisorSideloadMethod::ImageVolume => {
                volumes.push(supervisor_image_volume(
                    supervisor_image,
                    supervisor_image_pull_policy,
                ));
            }
            SupervisorSideloadMethod::InitContainer => {
                volumes.push(supervisor_volume());
            }
        }
    }

    // 2. Add the init container only for the init-container method
    if method == SupervisorSideloadMethod::InitContainer {
        let init_containers = spec
            .entry("initContainers")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(init_containers) = init_containers {
            init_containers.push(supervisor_init_container(
                supervisor_image,
                supervisor_image_pull_policy,
            ));
        }
    }

    // 3. Find the agent container and add volume mount + command override
    let Some(containers) = spec.get_mut("containers").and_then(|v| v.as_array_mut()) else {
        return;
    };

    let mut target_index = None;
    for (i, c) in containers.iter().enumerate() {
        if c.get("name").and_then(|v| v.as_str()) == Some("agent") {
            target_index = Some(i);
            break;
        }
    }
    let index = target_index.unwrap_or(0);

    if let Some(container) = containers.get_mut(index).and_then(|v| v.as_object_mut()) {
        // Override command to use the side-loaded supervisor binary
        container.insert(
            "command".to_string(),
            serde_json::json!([format!("{}/openshell-sandbox", SUPERVISOR_MOUNT_PATH)]),
        );

        // Force the supervisor to run as root (UID 0). Sandbox images may set
        // a non-root USER directive (e.g. `USER sandbox`), but the supervisor
        // needs root to create network namespaces, set up the proxy, and
        // configure Landlock/seccomp. The supervisor itself drops privileges
        // for child processes via the policy's `run_as_user`/`run_as_group`.
        let security_context = container
            .entry("securityContext")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(sc) = security_context.as_object_mut() {
            sc.insert("runAsUser".to_string(), serde_json::json!(0));
        }

        // Add volume mount
        let volume_mounts = container
            .entry("volumeMounts")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(volume_mounts) = volume_mounts {
            volume_mounts.push(supervisor_volume_mount());
        }
    }
}

/// Apply workspace persistence transforms to an already-built pod template.
///
/// This injects:
///   1. A volume mount on the agent container at `/sandbox`.
///   2. An init container (same image) that seeds the PVC with the image's
///      original `/sandbox` contents on first use.
///
/// The PVC volume itself is **not** added here — the Sandbox CRD controller
/// automatically creates a volume for each entry in `volumeClaimTemplates`
/// (following the `StatefulSet` convention).  Adding one here would create a
/// duplicate volume name and fail pod validation.
///
/// The init container mounts the PVC at a temporary path so it can still see
/// the image's `/sandbox` directory.  It checks for a sentinel file and skips
/// the copy if the PVC was already initialised.
fn apply_workspace_persistence(
    pod_template: &mut serde_json::Value,
    image: &str,
    image_pull_policy: &str,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // 1. Add workspace volume mount to the agent container
    let containers = spec.get_mut("containers").and_then(|v| v.as_array_mut());
    if let Some(containers) = containers {
        let mut target_index = None;
        for (i, c) in containers.iter().enumerate() {
            if c.get("name").and_then(|v| v.as_str()) == Some("agent") {
                target_index = Some(i);
                break;
            }
        }
        let index = target_index.unwrap_or(0);

        if let Some(container) = containers.get_mut(index).and_then(|v| v.as_object_mut()) {
            let volume_mounts = container
                .entry("volumeMounts")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut();
            if let Some(volume_mounts) = volume_mounts {
                volume_mounts.push(serde_json::json!({
                    "name": WORKSPACE_VOLUME_NAME,
                    "mountPath": WORKSPACE_MOUNT_PATH
                }));
            }
        }
    }

    // 3. Add the init container that seeds the PVC from the image
    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(init_containers) = init_containers {
        // The init container mounts the PVC at a temp path so it can still
        // read the image's original /sandbox contents.  It copies them into
        // the PVC only when the sentinel file is absent.
        //
        // Prefer a tar stream over `cp -a`: some sandbox images contain
        // self-referential symlinks under `/sandbox/.uv`, and GNU cp can
        // fail while seeding the PVC even though preserving the symlink as-is
        // is valid. `tar` copies the tree without dereferencing those links.
        //
        // The inner `[ -d ... ]` guard handles custom images that don't have
        // a /sandbox directory — the copy is skipped but the sentinel is
        // still written so subsequent starts are instant.
        let copy_cmd = format!(
            "if [ ! -f {WORKSPACE_INIT_MOUNT_PATH}/{WORKSPACE_SENTINEL} ]; then \
               if [ -d {WORKSPACE_MOUNT_PATH} ]; then \
                 tar -C {WORKSPACE_MOUNT_PATH} -cf - . | tar -C {WORKSPACE_INIT_MOUNT_PATH} -xpf -; \
               fi && \
               touch {WORKSPACE_INIT_MOUNT_PATH}/{WORKSPACE_SENTINEL}; \
             fi"
        );

        let mut init_spec = serde_json::json!({
            "name": WORKSPACE_INIT_CONTAINER_NAME,
            "image": image,
            "command": ["sh", "-c", copy_cmd],
            "securityContext": { "runAsUser": 0 },
            "volumeMounts": [{
                "name": WORKSPACE_VOLUME_NAME,
                "mountPath": WORKSPACE_INIT_MOUNT_PATH
            }]
        });
        if !image_pull_policy.is_empty() {
            init_spec["imagePullPolicy"] = serde_json::json!(image_pull_policy);
        }
        init_containers.push(init_spec);
    }
}

/// Build the default `volumeClaimTemplates` array for sandbox pods.
///
/// Provides a single PVC named "workspace" that backs the `/sandbox`
/// directory.  The init container seeds it from the image on first use.
fn default_workspace_volume_claim_templates(storage_size: &str) -> serde_json::Value {
    let size = if storage_size.is_empty() {
        DEFAULT_WORKSPACE_STORAGE_SIZE
    } else {
        storage_size
    };
    serde_json::json!([{
        "metadata": {
            "name": WORKSPACE_VOLUME_NAME
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": size
                }
            }
        }
    }])
}

/// Parameters shared by `sandbox_to_k8s_spec` and `sandbox_template_to_k8s`.
struct SandboxPodParams<'a> {
    default_image: &'a str,
    image_pull_policy: &'a str,
    image_pull_secrets: &'a [String],
    supervisor_image: &'a str,
    supervisor_image_pull_policy: &'a str,
    supervisor_sideload_method: SupervisorSideloadMethod,
    service_account_name: &'a str,
    sandbox_id: &'a str,
    sandbox_name: &'a str,
    grpc_endpoint: &'a str,
    ssh_socket_path: &'a str,
    client_tls_secret_name: &'a str,
    host_gateway_ip: &'a str,
    enable_user_namespaces: bool,
    app_armor_profile: Option<&'a AppArmorProfile>,
    workspace_default_storage_size: &'a str,
    default_runtime_class_name: &'a str,
    /// Lifetime (seconds) of the projected `ServiceAccount` token used
    /// for the bootstrap `IssueSandboxToken` exchange.
    sa_token_ttl_secs: i64,
    provider_spiffe_enabled: bool,
    provider_spiffe_workload_api_socket_path: &'a str,
}

impl Default for SandboxPodParams<'_> {
    fn default() -> Self {
        Self {
            default_image: "",
            image_pull_policy: "",
            image_pull_secrets: &[],
            supervisor_image: "",
            supervisor_image_pull_policy: "",
            supervisor_sideload_method: SupervisorSideloadMethod::default(),
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
            sandbox_id: "",
            sandbox_name: "",
            grpc_endpoint: "",
            ssh_socket_path: "",
            client_tls_secret_name: "",
            host_gateway_ip: "",
            enable_user_namespaces: false,
            app_armor_profile: None,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE,
            default_runtime_class_name: "",
            sa_token_ttl_secs: 3600,
            provider_spiffe_enabled: false,
            provider_spiffe_workload_api_socket_path: "",
        }
    }
}

fn spec_pod_env(spec: Option<&SandboxSpec>) -> std::collections::HashMap<String, String> {
    let mut env = spec.map_or_else(Default::default, |s| s.environment.clone());
    if let Some(s) = spec.filter(|s| !s.log_level.is_empty()) {
        env.insert(
            openshell_core::sandbox_env::LOG_LEVEL.to_string(),
            s.log_level.clone(),
        );
    }
    env
}

fn kubernetes_driver_config(template: &SandboxTemplate) -> KubernetesSandboxDriverConfig {
    KubernetesSandboxDriverConfig::from_template(template)
        .expect("validated Kubernetes driver_config")
}

fn sandbox_to_k8s_spec(
    spec: Option<&SandboxSpec>,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    // Determine early whether the user provided custom volumeClaimTemplates.
    // When they haven't, we inject a default workspace VCT and corresponding
    // init container + volume mount so sandbox data persists.  We need this
    // flag before building the podTemplate because the workspace persistence
    // transforms are applied inside sandbox_template_to_k8s.
    let user_has_vct = spec
        .and_then(|s| s.template.as_ref())
        .and_then(|t| platform_config_struct(t, "volume_claim_templates"))
        .is_some();
    let inject_workspace = !user_has_vct;

    if let Some(spec) = spec {
        let pod_env = spec_pod_env(Some(spec));
        if let Some(template) = spec.template.as_ref() {
            root.insert(
                "podTemplate".to_string(),
                sandbox_template_to_k8s(template, spec.gpu, &pod_env, inject_workspace, params),
            );
            if !template.agent_socket_path.is_empty() {
                root.insert(
                    "agentSocket".to_string(),
                    serde_json::json!(template.agent_socket_path),
                );
            }
            if let Some(volume_templates) =
                platform_config_struct(template, "volume_claim_templates")
            {
                root.insert("volumeClaimTemplates".to_string(), volume_templates);
            }
        }
    }

    // Inject the default workspace volumeClaimTemplate when the user didn't
    // provide their own.
    if inject_workspace {
        root.insert(
            "volumeClaimTemplates".to_string(),
            default_workspace_volume_claim_templates(params.workspace_default_storage_size),
        );
    }

    // podTemplate is required by the Kubernetes CRD - ensure it's always present
    if !root.contains_key("podTemplate") {
        let pod_env = spec_pod_env(spec);
        root.insert(
            "podTemplate".to_string(),
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                spec.is_some_and(|s| s.gpu),
                &pod_env,
                inject_workspace,
                params,
            ),
        );
    }

    serde_json::Value::Object(
        std::iter::once(("spec".to_string(), serde_json::Value::Object(root))).collect(),
    )
}

fn sandbox_template_to_k8s(
    template: &SandboxTemplate,
    gpu: bool,
    spec_environment: &std::collections::HashMap<String, String>,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let driver_config = kubernetes_driver_config(template);

    let mut metadata = serde_json::Map::new();
    let mut pod_labels = template
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<String, serde_json::Value>>();
    if params.provider_spiffe_enabled {
        pod_labels.insert(
            LABEL_MANAGED_BY.to_string(),
            serde_json::Value::String(LABEL_MANAGED_BY_VALUE.to_string()),
        );
        if !params.sandbox_id.is_empty() {
            pod_labels.insert(
                LABEL_SANDBOX_ID.to_string(),
                serde_json::Value::String(params.sandbox_id.to_string()),
            );
        }
    }
    if !pod_labels.is_empty() {
        metadata.insert("labels".to_string(), serde_json::Value::Object(pod_labels));
    }
    // Carry the sandbox UUID as a pod annotation so the gateway can resolve
    // a projected SA token claim (pod name + uid) back to a sandbox identity
    // when the supervisor calls `IssueSandboxToken` at startup. The gateway
    // also verifies the pod's controlling Sandbox ownerReference against the
    // live CR before accepting this annotation. Its K8s Role does NOT grant
    // `patch pods`, so this annotation is effectively immutable post-create.
    let mut pod_annotations = platform_config_struct(template, "annotations")
        .and_then(|v| match v {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    if !params.sandbox_id.is_empty() {
        pod_annotations.insert(
            "openshell.io/sandbox-id".to_string(),
            serde_json::Value::String(params.sandbox_id.to_string()),
        );
    }
    if !pod_annotations.is_empty() {
        metadata.insert(
            "annotations".to_string(),
            serde_json::Value::Object(pod_annotations),
        );
    }

    let mut spec = serde_json::Map::new();
    let runtime_class_name = platform_config_string(template, "runtime_class_name")
        .or_else(|| {
            (!driver_config.pod.runtime_class_name.is_empty())
                .then(|| driver_config.pod.runtime_class_name.clone())
        })
        .or_else(|| {
            (!params.default_runtime_class_name.is_empty())
                .then(|| params.default_runtime_class_name.to_string())
        });
    if let Some(runtime_class) = runtime_class_name {
        spec.insert(
            "runtimeClassName".to_string(),
            serde_json::json!(runtime_class),
        );
    }
    if let Some(node_selector) = platform_config_struct(template, "node_selector") {
        spec.insert("nodeSelector".to_string(), node_selector);
    }
    if let Some(tolerations) = platform_config_struct(template, "tolerations") {
        spec.insert("tolerations".to_string(), tolerations);
    }
    apply_pod_driver_config(&mut spec, &driver_config.pod);

    // Per-sandbox platform_config.host_users overrides the cluster-wide default.
    let use_user_namespaces = platform_config_bool(template, "host_users")
        .map_or(params.enable_user_namespaces, |host_users| !host_users);

    if use_user_namespaces {
        spec.insert("hostUsers".to_string(), serde_json::json!(false));
        if gpu {
            warn!(
                "GPU sandbox with user namespaces enabled — \
                 NVIDIA device plugin compatibility is unverified"
            );
        }
    }

    if !params.service_account_name.is_empty() {
        spec.insert(
            "serviceAccountName".to_string(),
            serde_json::json!(params.service_account_name),
        );
    }

    let image_pull_secrets = image_pull_secret_refs(params.image_pull_secrets);
    if !image_pull_secrets.is_empty() {
        spec.insert(
            "imagePullSecrets".to_string(),
            serde_json::Value::Array(image_pull_secrets),
        );
    }

    // Disable service account token auto-mounting for security hardening.
    // Sandbox pods should not have access to the Kubernetes API by default.
    spec.insert(
        "automountServiceAccountToken".to_string(),
        serde_json::json!(false),
    );

    let mut container = serde_json::Map::new();
    container.insert("name".to_string(), serde_json::json!("agent"));
    // Use template image if provided, otherwise fall back to default
    let image = if template.image.is_empty() {
        params.default_image
    } else {
        &template.image
    };
    if !image.is_empty() {
        container.insert("image".to_string(), serde_json::json!(image));
        if !params.image_pull_policy.is_empty() {
            container.insert(
                "imagePullPolicy".to_string(),
                serde_json::json!(params.image_pull_policy),
            );
        }
    }

    // Build environment variables - start with OpenShell-required vars
    let env = build_env_list(
        None,
        &template.environment,
        spec_environment,
        params.sandbox_id,
        params.sandbox_name,
        params.grpc_endpoint,
        params.ssh_socket_path,
        !params.client_tls_secret_name.is_empty(),
        provider_spiffe_socket_path(params),
    );

    container.insert("env".to_string(), serde_json::Value::Array(env));

    let mut capabilities: Vec<&str> = vec!["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYSLOG"];
    if use_user_namespaces {
        // In a user namespace the bounding set is reset. SETUID/SETGID are
        // needed for the supervisor to drop privileges to the sandbox user.
        // DAC_READ_SEARCH is needed for cross-UID /proc/<pid>/fd/ access
        // for process identity resolution in network policy enforcement.
        capabilities.extend(["SETUID", "SETGID", "DAC_READ_SEARCH"]);
    }
    let mut security_context = serde_json::json!({
        "capabilities": {
            "add": capabilities
        }
    });
    if let Some(profile) = params.app_armor_profile {
        security_context["appArmorProfile"] = app_armor_profile_to_k8s(profile);
    }
    container.insert("securityContext".to_string(), security_context);

    // Mount client TLS secret for mTLS to the server. Gateway identity uses
    // the projected ServiceAccount bootstrap token. Provider token grants may
    // additionally mount the SPIFFE Workload API socket.
    let mut volume_mounts: Vec<serde_json::Value> = Vec::new();
    if !params.client_tls_secret_name.is_empty() {
        volume_mounts.push(serde_json::json!({
            "name": "openshell-client-tls",
            "mountPath": "/etc/openshell-tls/client",
            "readOnly": true
        }));
    }
    if params.provider_spiffe_enabled {
        volume_mounts.push(serde_json::json!({
            "name": SPIFFE_WORKLOAD_API_VOLUME_NAME,
            "mountPath": spiffe_socket_mount_path(params.provider_spiffe_workload_api_socket_path),
            "readOnly": true,
        }));
    }
    volume_mounts.push(serde_json::json!({
        "name": "openshell-sa-token",
        "mountPath": "/var/run/secrets/openshell",
        "readOnly": true,
    }));
    container.insert(
        "volumeMounts".to_string(),
        serde_json::Value::Array(volume_mounts),
    );

    if let Some(resources) = container_resources(template, gpu) {
        container.insert("resources".to_string(), resources);
    }
    apply_agent_driver_resources(&mut container, &driver_config.containers.agent.resources);
    spec.insert(
        "containers".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(container)]),
    );

    // Add TLS secret volume.  Mode 0400 (owner-read) prevents the
    // unprivileged sandbox user from reading the mTLS private key.
    let mut volumes: Vec<serde_json::Value> = Vec::new();
    if !params.client_tls_secret_name.is_empty() {
        volumes.push(serde_json::json!({
            "name": "openshell-client-tls",
            "secret": { "secretName": params.client_tls_secret_name, "defaultMode": 256 }
        }));
    }
    if params.provider_spiffe_enabled {
        volumes.push(serde_json::json!({
            "name": SPIFFE_WORKLOAD_API_VOLUME_NAME,
            "csi": {
                "driver": "csi.spiffe.io",
                "readOnly": true
            }
        }));
    }
    // Projected ServiceAccountToken volume — kubelet writes a short-lived
    // audience-bound JWT into /var/run/secrets/openshell/token and rotates
    // it automatically. The supervisor exchanges this for a gateway-minted
    // JWT via `IssueSandboxToken` once at startup.
    volumes.push(serde_json::json!({
        "name": "openshell-sa-token",
        "projected": {
            "sources": [{
                "serviceAccountToken": {
                    "audience": "openshell-gateway",
                    "expirationSeconds": params.sa_token_ttl_secs,
                    "path": "token"
                }
            }],
            "defaultMode": 256
        }
    }));
    spec.insert("volumes".to_string(), serde_json::Value::Array(volumes));

    // Add hostAliases so sandbox pods can reach the Docker host.
    if !params.host_gateway_ip.is_empty() {
        spec.insert(
            "hostAliases".to_string(),
            serde_json::json!([{
                "ip": params.host_gateway_ip,
                "hostnames": ["host.docker.internal", "host.openshell.internal"]
            }]),
        );
    }

    let mut template_value = serde_json::Map::new();
    if !metadata.is_empty() {
        template_value.insert("metadata".to_string(), serde_json::Value::Object(metadata));
    }
    template_value.insert("spec".to_string(), serde_json::Value::Object(spec));

    let mut result = serde_json::Value::Object(template_value);

    apply_supervisor_sideload(
        &mut result,
        params.supervisor_image,
        params.supervisor_image_pull_policy,
        params.supervisor_sideload_method,
    );

    // Inject workspace persistence (init container + PVC volume mount) so
    // that /sandbox data survives pod rescheduling.  Skipped when the user
    // provides custom volumeClaimTemplates to avoid conflicts.
    if inject_workspace {
        apply_workspace_persistence(&mut result, image, params.image_pull_policy);
    }

    result
}

fn apply_pod_driver_config(
    spec: &mut serde_json::Map<String, serde_json::Value>,
    config: &KubernetesPodDriverConfig,
) {
    if !config.node_selector.is_empty() {
        let node_selector = spec
            .entry("nodeSelector".to_string())
            .or_insert_with(|| serde_json::json!({}));
        merge_string_map(node_selector, &config.node_selector);
    }

    if !config.priority_class_name.is_empty() {
        spec.entry("priorityClassName".to_string())
            .or_insert_with(|| serde_json::json!(config.priority_class_name));
    }

    if !config.tolerations.is_empty() {
        let tolerations = spec
            .entry("tolerations".to_string())
            .or_insert_with(|| serde_json::json!([]));
        if let Some(existing) = tolerations.as_array_mut() {
            existing.extend(config.tolerations.iter().cloned());
        } else {
            *tolerations = serde_json::Value::Array(config.tolerations.clone());
        }
    }
}

fn apply_agent_driver_resources(
    container: &mut serde_json::Map<String, serde_json::Value>,
    resources: &KubernetesContainerResourceConfig,
) {
    if resources.requests.is_empty() && resources.limits.is_empty() {
        return;
    }

    let target = container
        .entry("resources".to_string())
        .or_insert_with(|| serde_json::json!({}));
    apply_resource_quantity_map(target, "requests", &resources.requests);
    apply_resource_quantity_map(target, "limits", &resources.limits);
}

fn merge_string_map(target: &mut serde_json::Value, values: &BTreeMap<String, String>) {
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    let target = target
        .as_object_mut()
        .expect("target was converted to object");
    for (key, value) in values {
        target
            .entry(key.clone())
            .or_insert_with(|| serde_json::json!(value));
    }
}

fn apply_resource_quantity_map(
    target: &mut serde_json::Value,
    section: &str,
    values: &BTreeMap<String, String>,
) {
    if values.is_empty() {
        return;
    }
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    let target = target
        .as_object_mut()
        .expect("target was converted to object");
    let section_value = target
        .entry(section.to_string())
        .or_insert_with(|| serde_json::json!({}));
    merge_string_map(section_value, values);
}

fn image_pull_secret_refs(secrets: &[String]) -> Vec<serde_json::Value> {
    secrets
        .iter()
        .map(|secret| secret.trim())
        .filter(|secret| !secret.is_empty())
        .map(|secret| serde_json::json!({ "name": secret }))
        .collect()
}

fn app_armor_profile_to_k8s(profile: &AppArmorProfile) -> serde_json::Value {
    let mut value = serde_json::json!({
        "type": profile.to_k8s_type()
    });
    if let Some(localhost_profile) = profile.localhost_profile() {
        value["localhostProfile"] = serde_json::json!(localhost_profile);
    }
    value
}

fn container_resources(template: &SandboxTemplate, gpu: bool) -> Option<serde_json::Value> {
    // Start from the raw resources passthrough in platform_config (preserves
    // custom resource types like GPU limits that users set via the public API
    // Struct), then overlay the typed DriverResourceRequirements on top.
    let mut resources =
        platform_config_struct(template, "resources_raw").unwrap_or_else(|| serde_json::json!({}));

    // Overlay typed CPU/memory from DriverResourceRequirements.
    if let Some(ref req) = template.resources {
        let obj = resources.as_object_mut().unwrap();
        let mut apply = |section: &str, key: &str, value: &str| {
            if !value.is_empty() {
                let sec = obj.entry(section).or_insert_with(|| serde_json::json!({}));
                sec[key] = serde_json::json!(value);
            }
        };
        apply("limits", "cpu", &req.cpu_limit);
        apply("limits", "memory", &req.memory_limit);

        let cpu_request = if req.cpu_request.is_empty() {
            &req.cpu_limit
        } else {
            &req.cpu_request
        };
        let memory_request = if req.memory_request.is_empty() {
            &req.memory_limit
        } else {
            &req.memory_request
        };
        apply("requests", "cpu", cpu_request);
        apply("requests", "memory", memory_request);
    }

    if gpu {
        apply_gpu_limit(&mut resources);
    }
    if resources.as_object().is_some_and(serde_json::Map::is_empty) {
        None
    } else {
        Some(resources)
    }
}

fn apply_gpu_limit(resources: &mut serde_json::Value) {
    let Some(resources_obj) = resources.as_object_mut() else {
        *resources = serde_json::json!({});
        return apply_gpu_limit(resources);
    };

    let limits = resources_obj
        .entry("limits")
        .or_insert_with(|| serde_json::json!({}));
    let Some(limits_obj) = limits.as_object_mut() else {
        *limits = serde_json::json!({});
        return apply_gpu_limit(resources);
    };

    limits_obj.insert(
        GPU_RESOURCE_NAME.to_string(),
        serde_json::json!(GPU_RESOURCE_QUANTITY),
    );
}

#[allow(clippy::too_many_arguments)]
fn build_env_list(
    existing_env: Option<&Vec<serde_json::Value>>,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_socket_path: &str,
    tls_enabled: bool,
    provider_spiffe_socket_path: Option<&str>,
) -> Vec<serde_json::Value> {
    let mut env = existing_env.cloned().unwrap_or_default();
    apply_env_map(&mut env, template_environment);
    apply_env_map(&mut env, spec_environment);
    let mut user_env = template_environment.clone();
    user_env.extend(spec_environment.clone());
    if !user_env.is_empty()
        && let Ok(json) = serde_json::to_string(&user_env)
    {
        upsert_env(
            &mut env,
            openshell_core::sandbox_env::USER_ENVIRONMENT,
            &json,
        );
    }
    apply_required_env(
        &mut env,
        sandbox_id,
        sandbox_name,
        grpc_endpoint,
        ssh_socket_path,
        tls_enabled,
        provider_spiffe_socket_path,
    );
    env
}

fn apply_env_map(
    env: &mut Vec<serde_json::Value>,
    values: &std::collections::HashMap<String, String>,
) {
    for (key, value) in values {
        upsert_env(env, key, value);
    }
}

// Required env vars are passed individually for clarity at call sites; grouping into a struct
// would not improve readability for this internal helper.
fn apply_required_env(
    env: &mut Vec<serde_json::Value>,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_socket_path: &str,
    tls_enabled: bool,
    provider_spiffe_socket_path: Option<&str>,
) {
    // Identity vars are set only when known at pod-create time. Warm-pool
    // template pods boot without an identity (assigned at claim time), so these
    // are omitted there — leaving `OPENSHELL_SANDBOX_ID`/`OPENSHELL_SANDBOX`
    // unset (clap sees `None`) so the supervisor cleanly skips identity-gated
    // startup (per-sandbox policy fetch, log push) and instead boots on the
    // baseline policy, then establishes identity over the relay after the claim.
    if !sandbox_id.is_empty() {
        upsert_env(env, openshell_core::sandbox_env::SANDBOX_ID, sandbox_id);
    }
    if !sandbox_name.is_empty() {
        upsert_env(env, openshell_core::sandbox_env::SANDBOX, sandbox_name);
    }
    upsert_env(env, openshell_core::sandbox_env::ENDPOINT, grpc_endpoint);
    upsert_env(
        env,
        openshell_core::sandbox_env::SANDBOX_COMMAND,
        "sleep infinity",
    );
    upsert_env(
        env,
        openshell_core::sandbox_env::TELEMETRY_ENABLED,
        openshell_core::telemetry::enabled_env_value(),
    );
    if !ssh_socket_path.is_empty() {
        upsert_env(
            env,
            openshell_core::sandbox_env::SSH_SOCKET_PATH,
            ssh_socket_path,
        );
    }
    // TLS cert paths for sandbox-to-server mTLS. Only set when TLS is enabled
    // and the client TLS secret is mounted into the sandbox pod.
    if tls_enabled {
        upsert_env(
            env,
            openshell_core::sandbox_env::TLS_CA,
            "/etc/openshell-tls/client/ca.crt",
        );
        upsert_env(
            env,
            openshell_core::sandbox_env::TLS_CERT,
            "/etc/openshell-tls/client/tls.crt",
        );
        upsert_env(
            env,
            openshell_core::sandbox_env::TLS_KEY,
            "/etc/openshell-tls/client/tls.key",
        );
    }
    // Projected ServiceAccount token written by kubelet (see the volume
    // definition in `sandbox_template_to_k8s`). The supervisor reads this
    // and exchanges it for a gateway-minted JWT via `IssueSandboxToken`.
    upsert_env(
        env,
        openshell_core::sandbox_env::K8S_SA_TOKEN_FILE,
        "/var/run/secrets/openshell/token",
    );
    if let Some(socket_path) = provider_spiffe_socket_path {
        upsert_env(
            env,
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
            socket_path,
        );
    }
}

fn provider_spiffe_socket_path<'a>(params: &'a SandboxPodParams<'a>) -> Option<&'a str> {
    params
        .provider_spiffe_enabled
        .then_some(params.provider_spiffe_workload_api_socket_path)
}

fn spiffe_socket_mount_path(socket_path: &str) -> String {
    std::path::Path::new(socket_path)
        .parent()
        .and_then(std::path::Path::to_str)
        .filter(|path| !path.is_empty() && *path != "/")
        .expect("provider SPIFFE socket path should be validated before pod rendering")
        .to_string()
}

fn upsert_env(env: &mut Vec<serde_json::Value>, name: &str, value: &str) {
    if let Some(existing) = env
        .iter_mut()
        .find(|item| item.get("name").and_then(|value| value.as_str()) == Some(name))
    {
        *existing = serde_json::json!({"name": name, "value": value});
        return;
    }

    env.push(serde_json::json!({"name": name, "value": value}));
}

/// Extract a string value from the template's `platform_config` Struct.
fn platform_config_string(template: &SandboxTemplate, key: &str) -> Option<String> {
    let config = template.platform_config.as_ref()?;
    let value = config.fields.get(key)?;
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::StringValue(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn platform_config_bool(template: &SandboxTemplate, key: &str) -> Option<bool> {
    let config = template.platform_config.as_ref()?;
    let value = config.fields.get(key)?;
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::BoolValue(b)) => Some(*b),
        _ => None,
    }
}

/// Extract a nested Struct value from the template's `platform_config`,
/// converting it to `serde_json::Value`.
fn platform_config_struct(template: &SandboxTemplate, key: &str) -> Option<serde_json::Value> {
    let config = template.platform_config.as_ref()?;
    let value = config.fields.get(key)?;
    let json = value_to_json(value);
    // Return None for null/empty objects so callers can distinguish
    // "field absent" from "field present but empty".
    match &json {
        serde_json::Value::Null => None,
        serde_json::Value::Object(m) if m.is_empty() => None,
        _ => Some(json),
    }
}

fn status_from_object(obj: &DynamicObject) -> Option<SandboxStatus> {
    let status = obj.data.get("status")?;
    let status_obj = status.as_object()?;

    let conditions = status_obj
        .get("conditions")
        .and_then(|val| val.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(condition_from_value)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(SandboxStatus {
        sandbox_name: status_obj
            .get("sandboxName")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        instance_id: status_obj
            .get("agentPod")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        agent_fd: status_obj
            .get("agentFd")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        sandbox_fd: status_obj
            .get("sandboxFd")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        conditions,
        deleting: obj.metadata.deletion_timestamp.is_some(),
        // Cold-path Sandbox CRs are not warm-pool claims.
        claim_name: String::new(),
        claim_uid: String::new(),
    })
}

fn condition_from_value(value: &serde_json::Value) -> Option<SandboxCondition> {
    let obj = value.as_object()?;
    Some(SandboxCondition {
        r#type: obj.get("type")?.as_str()?.to_string(),
        status: obj.get("status")?.as_str()?.to_string(),
        reason: obj
            .get("reason")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        message: obj
            .get("message")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        last_transition_time: obj
            .get("lastTransitionTime")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::progress::{
        PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
        PROGRESS_COMPLETE_STEP_KEY,
    };
    use prost_types::{Struct, Value, value::Kind};

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    fn json_struct(value: serde_json::Value) -> Struct {
        match json_value(value).kind {
            Some(Kind::StructValue(value)) => value,
            _ => panic!("expected JSON object"),
        }
    }

    fn json_value(value: serde_json::Value) -> Value {
        match value {
            serde_json::Value::Null => Value { kind: None },
            serde_json::Value::Bool(value) => Value {
                kind: Some(Kind::BoolValue(value)),
            },
            serde_json::Value::Number(value) => Value {
                kind: value.as_f64().map(Kind::NumberValue),
            },
            serde_json::Value::String(value) => Value {
                kind: Some(Kind::StringValue(value)),
            },
            serde_json::Value::Array(values) => Value {
                kind: Some(Kind::ListValue(prost_types::ListValue {
                    values: values.into_iter().map(json_value).collect(),
                })),
            },
            serde_json::Value::Object(values) => Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: values
                        .into_iter()
                        .map(|(key, value)| (key, json_value(value)))
                        .collect(),
                })),
            },
        }
    }

    #[test]
    fn driver_config_rejects_invalid_shape() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": "not-an-object"
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("invalid kubernetes driver_config"));
    }

    #[test]
    fn driver_config_rejects_unknown_fields() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "cdi_devices": ["nvidia.com/gpu=0"]
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("unknown field"));
    }

    #[test]
    fn driver_config_from_sandbox_rejects_unknown_fields() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                gpu: true,
                template: Some(SandboxTemplate {
                    driver_config: Some(json_struct(serde_json::json!({
                        "cdi_devices": ["nvidia.com/gpu=0"]
                    }))),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = KubernetesSandboxDriverConfig::from_sandbox(&sandbox).unwrap_err();
        assert!(err.contains("unknown field"));
    }

    #[test]
    fn kube_pulling_event_adds_image_progress_metadata() {
        let mut metadata = std::collections::HashMap::new();

        attach_kube_progress_metadata(
            &mut metadata,
            "Pulling",
            "Pulling image \"ghcr.io/acme/sandbox:latest\"",
        );

        assert_eq!(
            metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
            Some(PROGRESS_STEP_PULLING_IMAGE)
        );
        assert_eq!(
            metadata.get(PROGRESS_ACTIVE_DETAIL_KEY).map(String::as_str),
            Some("ghcr.io/acme/sandbox:latest")
        );
    }

    #[test]
    fn kube_pulled_event_adds_completed_image_progress_metadata() {
        let mut metadata = std::collections::HashMap::new();

        attach_kube_progress_metadata(
            &mut metadata,
            "Pulled",
            "Successfully pulled image \"ghcr.io/acme/sandbox:latest\". Image size: 44040192 bytes.",
        );

        assert_eq!(
            metadata.get(PROGRESS_COMPLETE_STEP_KEY).map(String::as_str),
            Some(PROGRESS_STEP_PULLING_IMAGE)
        );
        assert_eq!(
            metadata
                .get(PROGRESS_COMPLETE_LABEL_KEY)
                .map(String::as_str),
            Some("Image pulled (42 MB)")
        );
        assert_eq!(
            metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
            Some(PROGRESS_STEP_STARTING_SANDBOX)
        );
    }

    #[test]
    fn supervisor_sideload_injects_run_as_user_zero() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest",
                    "securityContext": {
                        "capabilities": {
                            "add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYSLOG"]
                        }
                    }
                }]
            }
        });

        apply_supervisor_sideload(
            &mut pod_template,
            "custom-image:latest",
            "IfNotPresent",
            SupervisorSideloadMethod::InitContainer,
        );

        let sc = &pod_template["spec"]["containers"][0]["securityContext"];
        assert_eq!(sc["runAsUser"], 0, "runAsUser must be 0 for supervisor");
        // Capabilities should be preserved
        assert!(
            sc["capabilities"]["add"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("SYS_ADMIN"))
        );
    }

    #[test]
    fn supervisor_sideload_adds_security_context_when_missing() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest"
                }]
            }
        });

        apply_supervisor_sideload(
            &mut pod_template,
            "supervisor-image:latest",
            "IfNotPresent",
            SupervisorSideloadMethod::InitContainer,
        );

        let sc = &pod_template["spec"]["containers"][0]["securityContext"];
        assert_eq!(
            sc["runAsUser"], 0,
            "runAsUser must be 0 even when no prior securityContext"
        );
    }

    #[test]
    fn supervisor_sideload_injects_emptydir_volume_init_container_and_mount() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest"
                }]
            }
        });

        apply_supervisor_sideload(
            &mut pod_template,
            "supervisor-image:latest",
            "IfNotPresent",
            SupervisorSideloadMethod::InitContainer,
        );

        // Volume should be an emptyDir
        let volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0]["name"], SUPERVISOR_VOLUME_NAME);
        assert!(
            volumes[0]["emptyDir"].is_object(),
            "volume should be emptyDir, not hostPath"
        );

        // Init container should use the supervisor image, not the sandbox image
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .expect("initContainers should exist");
        assert_eq!(init_containers.len(), 1);
        assert_eq!(init_containers[0]["name"], SUPERVISOR_INIT_CONTAINER_NAME);
        assert_eq!(init_containers[0]["image"], "supervisor-image:latest");
        assert_eq!(init_containers[0]["imagePullPolicy"], "IfNotPresent");

        // The init container must invoke the binary directly with
        // `copy-self <DEST>` rather than depending on shell utilities.
        let init_command = init_containers[0]["command"]
            .as_array()
            .expect("init container command should be set");
        assert_eq!(init_command.len(), 3, "expected [binary, copy-self, dest]");
        assert_eq!(init_command[0], SUPERVISOR_IMAGE_BINARY_PATH);
        assert_eq!(init_command[1], "copy-self");
        assert_eq!(
            init_command[2].as_str().unwrap(),
            format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox")
        );
        assert!(
            !init_command.iter().any(|v| v == "sh"),
            "init container must not depend on a shell"
        );

        // Agent container command should be overridden to the emptyDir path
        let command = pod_template["spec"]["containers"][0]["command"]
            .as_array()
            .expect("command should be set");
        assert_eq!(
            command[0].as_str().unwrap(),
            format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox")
        );

        // Agent volume mount should be read-only
        let mounts = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should exist");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0]["name"], SUPERVISOR_VOLUME_NAME);
        assert_eq!(mounts[0]["mountPath"], SUPERVISOR_MOUNT_PATH);
        assert_eq!(mounts[0]["readOnly"], true);
    }

    #[test]
    fn supervisor_sideload_image_volume_injects_image_source_without_init_container() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest"
                }]
            }
        });

        apply_supervisor_sideload(
            &mut pod_template,
            "supervisor-image:latest",
            "IfNotPresent",
            SupervisorSideloadMethod::ImageVolume,
        );

        let volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0]["name"], SUPERVISOR_VOLUME_NAME);
        assert_eq!(volumes[0]["image"]["reference"], "supervisor-image:latest");
        assert_eq!(volumes[0]["image"]["pullPolicy"], "IfNotPresent");
        assert!(
            volumes[0]["emptyDir"].is_null(),
            "image volume method must not use emptyDir"
        );

        assert!(
            pod_template["spec"]["initContainers"].is_null(),
            "image volume method must not inject init containers"
        );

        let command = pod_template["spec"]["containers"][0]["command"]
            .as_array()
            .expect("command should be set");
        assert_eq!(
            command[0].as_str().unwrap(),
            format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox")
        );

        let sc = &pod_template["spec"]["containers"][0]["securityContext"];
        assert_eq!(sc["runAsUser"], 0);

        let mounts = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should exist");
        assert_eq!(mounts[0]["name"], SUPERVISOR_VOLUME_NAME);
        assert_eq!(mounts[0]["mountPath"], SUPERVISOR_MOUNT_PATH);
        assert_eq!(mounts[0]["readOnly"], true);
    }

    #[test]
    fn supervisor_image_volume_omits_pull_policy_when_empty() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest"
                }]
            }
        });

        apply_supervisor_sideload(
            &mut pod_template,
            "supervisor-image:latest",
            "",
            SupervisorSideloadMethod::ImageVolume,
        );

        let volume = &pod_template["spec"]["volumes"][0];
        assert_eq!(volume["image"]["reference"], "supervisor-image:latest");
        assert!(
            volume["image"].get("pullPolicy").is_none(),
            "pullPolicy should be omitted when empty"
        );
    }

    /// Regression test: TLS mount path must match env var paths.
    /// The volume is mounted at a specific path and the env vars must point to
    /// files within that same path, otherwise the sandbox will fail to start
    /// with "No such file or directory" errors.
    #[test]
    fn tls_env_vars_match_volume_mount_path() {
        // The mount path used in pod template construction
        const TLS_MOUNT_PATH: &str = "/etc/openshell-tls/client";

        // Build env with TLS enabled
        let mut env = Vec::new();
        apply_required_env(
            &mut env,
            "sandbox-1",
            "my-sandbox",
            "https://endpoint:8080",
            "0.0.0.0:2222",
            true, // tls_enabled
            None,
        );

        // Extract the TLS-related env vars
        let get_env = |name: &str| -> Option<String> {
            env.iter()
                .find(|e| e.get("name").and_then(|v| v.as_str()) == Some(name))
                .and_then(|e| e.get("value").and_then(|v| v.as_str()).map(String::from))
        };

        let tls_ca = get_env("OPENSHELL_TLS_CA").expect("OPENSHELL_TLS_CA must be set");
        let tls_cert = get_env("OPENSHELL_TLS_CERT").expect("OPENSHELL_TLS_CERT must be set");
        let tls_key = get_env("OPENSHELL_TLS_KEY").expect("OPENSHELL_TLS_KEY must be set");

        // All TLS paths must be within the mount path
        assert!(
            tls_ca.starts_with(TLS_MOUNT_PATH),
            "OPENSHELL_TLS_CA path '{tls_ca}' must start with mount path '{TLS_MOUNT_PATH}'"
        );
        assert!(
            tls_cert.starts_with(TLS_MOUNT_PATH),
            "OPENSHELL_TLS_CERT path '{tls_cert}' must start with mount path '{TLS_MOUNT_PATH}'"
        );
        assert!(
            tls_key.starts_with(TLS_MOUNT_PATH),
            "OPENSHELL_TLS_KEY path '{tls_key}' must start with mount path '{TLS_MOUNT_PATH}'"
        );
    }

    #[test]
    fn gpu_sandbox_adds_runtime_class_and_gpu_limit() {
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                true,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::Value::Null
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"][GPU_RESOURCE_NAME],
            serde_json::json!(GPU_RESOURCE_QUANTITY)
        );
    }

    #[test]
    fn gpu_sandbox_uses_template_runtime_class_name_when_set() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("kata-containers".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                true,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn non_gpu_sandbox_uses_template_runtime_class_name_when_set() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("kata-containers".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn default_runtime_class_name_applied_when_template_omits_it() {
        let template = SandboxTemplate::default();
        let pod_template = {
            let params = SandboxPodParams {
                default_runtime_class_name: "kata-containers",
                ..SandboxPodParams::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn template_runtime_class_name_overrides_config_default() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("gvisor".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams {
                default_runtime_class_name: "kata-containers",
                ..SandboxPodParams::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("gvisor")
        );
    }

    #[test]
    fn driver_config_runtime_class_name_applies_to_pod_spec() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "runtime_class_name": "kata-containers"
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn driver_config_runtime_class_name_overrides_config_default() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "runtime_class_name": "kata-containers"
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams {
                default_runtime_class_name: "gvisor",
                ..SandboxPodParams::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn template_runtime_class_name_overrides_driver_config() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("gvisor".to_string())),
                    },
                ))
                .collect(),
            }),
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "runtime_class_name": "kata-containers"
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("gvisor")
        );
    }

    #[test]
    fn runtime_class_name_omitted_when_both_template_and_default_empty() {
        let template = SandboxTemplate::default();
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!(null)
        );
    }

    #[test]
    fn gpu_sandbox_preserves_existing_resource_limits() {
        use openshell_core::proto::compute::v1::DriverResourceRequirements;
        let template = SandboxTemplate {
            resources: Some(DriverResourceRequirements {
                cpu_limit: "2".to_string(),
                ..Default::default()
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                true,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        let limits = &pod_template["spec"]["containers"][0]["resources"]["limits"];
        assert_eq!(limits["cpu"], serde_json::json!("2"));
        assert_eq!(
            limits[GPU_RESOURCE_NAME],
            serde_json::json!(GPU_RESOURCE_QUANTITY)
        );
    }

    #[test]
    fn cpu_and_memory_limits_are_mirrored_to_requests() {
        use openshell_core::proto::compute::v1::DriverResourceRequirements;
        let template = SandboxTemplate {
            resources: Some(DriverResourceRequirements {
                cpu_limit: "500m".to_string(),
                memory_limit: "2Gi".to_string(),
                ..Default::default()
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        let resources = &pod_template["spec"]["containers"][0]["resources"];
        assert_eq!(resources["limits"]["cpu"], serde_json::json!("500m"));
        assert_eq!(resources["limits"]["memory"], serde_json::json!("2Gi"));
        assert_eq!(resources["requests"]["cpu"], serde_json::json!("500m"));
        assert_eq!(resources["requests"]["memory"], serde_json::json!("2Gi"));
    }

    #[test]
    fn host_aliases_injected_when_gateway_ip_set() {
        let pod_template = {
            let params = SandboxPodParams {
                host_gateway_ip: "172.17.0.1",
                ..Default::default()
            };
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        let host_aliases = pod_template["spec"]["hostAliases"]
            .as_array()
            .expect("hostAliases should exist");
        assert_eq!(host_aliases.len(), 1);
        assert_eq!(host_aliases[0]["ip"], "172.17.0.1");
        let hostnames = host_aliases[0]["hostnames"]
            .as_array()
            .expect("hostnames should exist");
        assert!(hostnames.contains(&serde_json::json!("host.docker.internal")));
        assert!(hostnames.contains(&serde_json::json!("host.openshell.internal")));
    }

    #[test]
    fn host_aliases_not_injected_when_gateway_ip_empty() {
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert!(
            pod_template["spec"]["hostAliases"].is_null(),
            "hostAliases should not be present when host_gateway_ip is empty"
        );
    }

    #[test]
    fn tls_secret_volume_uses_restrictive_default_mode() {
        let template = SandboxTemplate::default();
        let pod_template = {
            let params = SandboxPodParams {
                client_tls_secret_name: "my-tls-secret",
                ..Default::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        let volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist");
        let tls_vol = volumes
            .iter()
            .find(|v| v["name"] == "openshell-client-tls")
            .expect("TLS volume should exist");
        assert_eq!(
            tls_vol["secret"]["defaultMode"],
            256, // 0o400
            "TLS secret volume must use mode 0400 to prevent sandbox user from reading the private key"
        );
    }

    // -----------------------------------------------------------------------
    // Workspace persistence tests
    // -----------------------------------------------------------------------

    #[test]
    fn workspace_persistence_injects_init_container_volume_and_mount() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "openshell/sandbox:latest"
                }]
            }
        });

        apply_workspace_persistence(
            &mut pod_template,
            "openshell/sandbox:latest",
            "IfNotPresent",
        );

        // Init container
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .expect("initContainers should exist");
        assert_eq!(init_containers.len(), 1);
        assert_eq!(init_containers[0]["name"], WORKSPACE_INIT_CONTAINER_NAME);
        assert_eq!(init_containers[0]["image"], "openshell/sandbox:latest");
        assert_eq!(init_containers[0]["imagePullPolicy"], "IfNotPresent");
        assert_eq!(init_containers[0]["securityContext"]["runAsUser"], 0);

        // Init container mounts PVC at temp path, not /sandbox
        let init_mounts = init_containers[0]["volumeMounts"]
            .as_array()
            .expect("init volumeMounts should exist");
        assert_eq!(init_mounts.len(), 1);
        assert_eq!(init_mounts[0]["name"], WORKSPACE_VOLUME_NAME);
        assert_eq!(init_mounts[0]["mountPath"], WORKSPACE_INIT_MOUNT_PATH);

        // Agent container mounts PVC at /sandbox
        let agent_mounts = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("agent volumeMounts should exist");
        let workspace_mount = agent_mounts
            .iter()
            .find(|m| m["name"] == WORKSPACE_VOLUME_NAME)
            .expect("workspace mount should exist on agent container");
        assert_eq!(workspace_mount["mountPath"], WORKSPACE_MOUNT_PATH);

        // The PVC volume is NOT created by apply_workspace_persistence — the
        // Sandbox CRD controller adds it from the volumeClaimTemplates.
        // Verify we did not inject one (which would cause a duplicate).
        let has_pvc_vol = pod_template["spec"]["volumes"]
            .as_array()
            .is_some_and(|vols| vols.iter().any(|v| v["name"] == WORKSPACE_VOLUME_NAME));
        assert!(
            !has_pvc_vol,
            "apply_workspace_persistence must NOT add a PVC volume (the CRD controller does that)"
        );
    }

    #[test]
    fn workspace_persistence_uses_same_image_as_agent() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "my-custom-image:v2"
                }]
            }
        });

        apply_workspace_persistence(&mut pod_template, "my-custom-image:v2", "IfNotPresent");

        let init_image = pod_template["spec"]["initContainers"][0]["image"]
            .as_str()
            .expect("init container should have image");
        assert_eq!(
            init_image, "my-custom-image:v2",
            "init container must use the same image as the agent container"
        );
    }

    #[test]
    fn workspace_init_command_checks_sentinel() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "img:latest"
                }]
            }
        });

        apply_workspace_persistence(&mut pod_template, "img:latest", "Always");

        let cmd = pod_template["spec"]["initContainers"][0]["command"]
            .as_array()
            .expect("command should be an array");
        let script = cmd[2].as_str().expect("third element should be the script");
        assert!(
            script.contains(WORKSPACE_SENTINEL),
            "init script must check for sentinel file"
        );
        assert!(
            script.contains("tar -C"),
            "init script must seed image contents with a tar stream"
        );
    }

    #[test]
    fn workspace_persistence_skipped_when_inject_workspace_false() {
        let params = SandboxPodParams {
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            false, // user provided custom VCTs
            &params,
        );

        // Only the supervisor init container should be present — no workspace init container
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .expect("supervisor init container should always be present");
        assert!(
            !init_containers
                .iter()
                .any(|c| c["name"] == WORKSPACE_INIT_CONTAINER_NAME),
            "workspace init container must NOT be present when inject_workspace is false"
        );

        // No workspace volume mount on agent
        let has_workspace_mount = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .is_some_and(|mounts| mounts.iter().any(|m| m["name"] == WORKSPACE_VOLUME_NAME));
        assert!(
            !has_workspace_mount,
            "workspace mount must NOT be present when inject_workspace is false"
        );
    }

    // -----------------------------------------------------------------------
    // User namespace tests
    // -----------------------------------------------------------------------

    fn default_template_to_k8s(enable_user_namespaces: bool) -> serde_json::Value {
        let params = SandboxPodParams {
            enable_user_namespaces,
            ..Default::default()
        };
        sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        )
    }

    #[test]
    fn app_armor_profile_omitted_by_default() {
        let pod_template = default_template_to_k8s(false);
        assert!(
            pod_template["spec"]["containers"][0]["securityContext"]["appArmorProfile"].is_null(),
            "appArmorProfile must be omitted when no profile is configured"
        );
    }

    #[test]
    fn app_armor_profile_renders_unconfined() {
        let profile = AppArmorProfile::Unconfined;
        let params = SandboxPodParams {
            app_armor_profile: Some(&profile),
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["containers"][0]["securityContext"]["appArmorProfile"],
            serde_json::json!({ "type": "Unconfined" })
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["securityContext"]["capabilities"]["add"][0],
            serde_json::json!("SYS_ADMIN"),
            "AppArmor rendering must preserve required capabilities"
        );
    }

    #[test]
    fn app_armor_profile_renders_localhost_profile() {
        let profile = AppArmorProfile::Localhost("openshell-supervisor".to_string());
        let params = SandboxPodParams {
            app_armor_profile: Some(&profile),
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["containers"][0]["securityContext"]["appArmorProfile"],
            serde_json::json!({
                "type": "Localhost",
                "localhostProfile": "openshell-supervisor"
            })
        );
    }

    #[test]
    fn user_namespaces_disabled_by_default() {
        let pod_template = default_template_to_k8s(false);
        assert!(
            pod_template["spec"]["hostUsers"].is_null(),
            "hostUsers must not be set when user namespaces are disabled"
        );
        let caps = pod_template["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
            .as_array()
            .unwrap();
        assert_eq!(caps.len(), 4);
        assert!(!caps.contains(&serde_json::json!("SETUID")));
    }

    #[test]
    fn user_namespaces_enabled_by_cluster_default() {
        let pod_template = default_template_to_k8s(true);
        assert_eq!(
            pod_template["spec"]["hostUsers"],
            serde_json::json!(false),
            "hostUsers must be false when user namespaces are enabled"
        );
    }

    #[test]
    fn user_namespaces_adds_extra_capabilities() {
        let pod_template = default_template_to_k8s(true);
        let caps = pod_template["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
            .as_array()
            .unwrap();
        assert!(caps.contains(&serde_json::json!("SYS_ADMIN")));
        assert!(caps.contains(&serde_json::json!("NET_ADMIN")));
        assert!(caps.contains(&serde_json::json!("SYS_PTRACE")));
        assert!(caps.contains(&serde_json::json!("SYSLOG")));
        assert!(caps.contains(&serde_json::json!("SETUID")));
        assert!(caps.contains(&serde_json::json!("SETGID")));
        assert!(caps.contains(&serde_json::json!("DAC_READ_SEARCH")));
        assert_eq!(caps.len(), 7);
    }

    #[test]
    fn user_namespaces_per_sandbox_override_enables() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "host_users".to_string(),
                    Value {
                        kind: Some(Kind::BoolValue(false)),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let params = SandboxPodParams::default(); // cluster default is off
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["hostUsers"],
            serde_json::json!(false),
            "per-sandbox host_users: false must enable user namespaces"
        );
        let caps = pod_template["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
            .as_array()
            .unwrap();
        assert!(caps.contains(&serde_json::json!("SETUID")));
    }

    #[test]
    fn user_namespaces_per_sandbox_override_disables() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "host_users".to_string(),
                    Value {
                        kind: Some(Kind::BoolValue(true)),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let params = SandboxPodParams {
            enable_user_namespaces: true, // cluster default is on
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert!(
            pod_template["spec"]["hostUsers"].is_null(),
            "per-sandbox host_users: true must disable user namespaces even when cluster default is on"
        );
        let caps = pod_template["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
            .as_array()
            .unwrap();
        assert_eq!(
            caps.len(),
            4,
            "extra capabilities must not be added when user namespaces are disabled"
        );
    }

    #[test]
    fn automount_service_account_token_is_disabled() {
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["automountServiceAccountToken"],
            serde_json::json!(false),
            "service account token auto-mounting must be disabled for security hardening"
        );
    }

    #[test]
    fn sandbox_template_sets_configured_service_account_name() {
        let params = SandboxPodParams {
            service_account_name: "openshell-sandbox",
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["serviceAccountName"],
            serde_json::json!("openshell-sandbox"),
            "sandbox pods must run under the configured service account"
        );
        assert_eq!(
            pod_template["spec"]["automountServiceAccountToken"],
            serde_json::json!(false),
            "explicit service account selection must not re-enable default token automounting"
        );
    }

    #[test]
    fn sandbox_template_omits_empty_image_pull_secrets() {
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &SandboxPodParams::default(),
        );

        assert!(
            pod_template["spec"]["imagePullSecrets"].is_null(),
            "imagePullSecrets must be omitted when no secrets are configured"
        );
    }

    #[test]
    fn sandbox_template_renders_configured_image_pull_secrets() {
        let secrets = vec![
            "regcred".to_string(),
            " backup-regcred ".to_string(),
            String::new(),
        ];
        let params = SandboxPodParams {
            image_pull_secrets: &secrets,
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["imagePullSecrets"],
            serde_json::json!([
                { "name": "regcred" },
                { "name": "backup-regcred" }
            ])
        );
    }

    #[test]
    fn sandbox_template_renders_image_pull_secrets_for_template_image() {
        let secrets = vec!["regcred".to_string()];
        let params = SandboxPodParams {
            default_image: "default-image:latest",
            image_pull_secrets: &secrets,
            ..Default::default()
        };
        let template = SandboxTemplate {
            image: "private.example.com/team/sandbox:v1".to_string(),
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["containers"][0]["image"],
            serde_json::json!("private.example.com/team/sandbox:v1")
        );
        assert_eq!(
            pod_template["spec"]["imagePullSecrets"],
            serde_json::json!([{ "name": "regcred" }])
        );
    }

    #[test]
    fn provider_spiffe_mounts_csi_socket_and_keeps_sa_token_bootstrap() {
        let params = SandboxPodParams {
            sandbox_id: "sandbox-123",
            sandbox_name: "sandbox",
            provider_spiffe_enabled: true,
            provider_spiffe_workload_api_socket_path: "/spiffe-workload-api/spire-agent.sock",
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        let env = pod_template["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env");
        assert!(env.iter().any(|e| {
            e["name"] == openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
                && e["value"] == "/spiffe-workload-api/spire-agent.sock"
        }));
        assert!(env.iter().any(|e| {
            e["name"] == openshell_core::sandbox_env::K8S_SA_TOKEN_FILE
                && e["value"] == "/var/run/secrets/openshell/token"
        }));

        let volumes = pod_template["spec"]["volumes"].as_array().expect("volumes");
        assert!(volumes.iter().any(|volume| {
            volume["name"] == SPIFFE_WORKLOAD_API_VOLUME_NAME
                && volume["csi"]["driver"] == "csi.spiffe.io"
        }));
        assert!(volumes.iter().any(|volume| {
            volume["name"] == "openshell-sa-token"
                && volume["projected"]["sources"][0]["serviceAccountToken"]["path"] == "token"
        }));

        assert_eq!(
            pod_template["metadata"]["labels"][LABEL_MANAGED_BY],
            serde_json::json!(LABEL_MANAGED_BY_VALUE)
        );
    }

    #[test]
    fn platform_config_bool_extracts_value() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "my_bool".to_string(),
                    Value {
                        kind: Some(Kind::BoolValue(true)),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        assert_eq!(platform_config_bool(&template, "my_bool"), Some(true));
        assert_eq!(platform_config_bool(&template, "missing"), None);
    }

    #[test]
    fn platform_config_bool_returns_none_for_non_bool() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "a_string".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("hello".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        assert_eq!(platform_config_bool(&template, "a_string"), None);
    }

    #[test]
    fn log_level_propagates_as_env_var_to_sandbox_pod() {
        let spec = SandboxSpec {
            log_level: "debug".to_string(),
            ..SandboxSpec::default()
        };
        let cr = sandbox_to_k8s_spec(Some(&spec), &SandboxPodParams::default());
        let env = cr["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(
            env.iter()
                .any(|e| e["name"] == "OPENSHELL_LOG_LEVEL" && e["value"] == "debug")
        );
        assert!(cr["spec"].get("logLevel").is_none());
    }

    #[test]
    fn telemetry_toggle_propagates_from_driver_env_to_sandbox_pod() {
        let _guard = ENV_LOCK.lock().unwrap();
        temp_env::with_vars(
            [(
                openshell_core::sandbox_env::TELEMETRY_ENABLED,
                Some("false"),
            )],
            || {
                let spec = SandboxSpec {
                    environment: std::collections::HashMap::from([(
                        openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
                        "true".to_string(),
                    )]),
                    ..SandboxSpec::default()
                };
                let cr = sandbox_to_k8s_spec(Some(&spec), &SandboxPodParams::default());
                let env = cr["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
                    .as_array()
                    .unwrap();
                let telemetry_entries = env
                    .iter()
                    .filter(|entry| entry["name"] == openshell_core::sandbox_env::TELEMETRY_ENABLED)
                    .collect::<Vec<_>>();

                assert_eq!(telemetry_entries.len(), 1);
                assert_eq!(telemetry_entries[0]["value"], serde_json::json!("false"));
            },
        );
    }

    #[test]
    fn node_selector_from_platform_config() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "node_selector".to_string(),
                    Value {
                        kind: Some(Kind::StructValue(Struct {
                            fields: std::iter::once((
                                "gpu-pool".to_string(),
                                Value {
                                    kind: Some(Kind::StringValue("true".to_string())),
                                },
                            ))
                            .collect(),
                        })),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                false,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["nodeSelector"]["gpu-pool"],
            serde_json::json!("true")
        );
    }

    #[test]
    fn tolerations_from_platform_config() {
        let toleration = Struct {
            fields: [
                (
                    "key".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("nvidia.com/gpu".to_string())),
                    },
                ),
                (
                    "operator".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("Exists".to_string())),
                    },
                ),
                (
                    "effect".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("NoSchedule".to_string())),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "tolerations".to_string(),
                    Value {
                        kind: Some(Kind::ListValue(prost_types::ListValue {
                            values: vec![Value {
                                kind: Some(Kind::StructValue(toleration)),
                            }],
                        })),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                false,
                &params,
            )
        };

        let tolerations = pod_template["spec"]["tolerations"]
            .as_array()
            .expect("tolerations should be an array");
        assert_eq!(tolerations.len(), 1);
        assert_eq!(tolerations[0]["key"], "nvidia.com/gpu");
        assert_eq!(tolerations[0]["operator"], "Exists");
        assert_eq!(tolerations[0]["effect"], "NoSchedule");
    }

    #[test]
    fn driver_config_applies_pod_scheduling_and_agent_resources() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "node_selector": {
                        "accelerator": "nvidia"
                    },
                    "runtime_class_name": "kata-containers",
                    "priority_class_name": "gpu-workload",
                    "tolerations": [{
                        "key": "nvidia.com/gpu",
                        "operator": "Exists",
                        "effect": "NoSchedule"
                    }]
                },
                "containers": {
                    "agent": {
                        "resources": {
                            "requests": {
                                "vendor.example/gpu-memory": "8Gi"
                            },
                            "limits": {
                                "vendor.example/gpu-slices": "1"
                            }
                        }
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            false,
            &SandboxPodParams::default(),
        );

        assert_eq!(
            pod_template["spec"]["nodeSelector"]["accelerator"],
            serde_json::json!("nvidia")
        );
        assert_eq!(
            pod_template["spec"]["priorityClassName"],
            serde_json::json!("gpu-workload")
        );
        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
        assert_eq!(
            pod_template["spec"]["tolerations"][0]["key"],
            serde_json::json!("nvidia.com/gpu")
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["requests"]["vendor.example/gpu-memory"],
            serde_json::json!("8Gi")
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"]["vendor.example/gpu-slices"],
            serde_json::json!("1")
        );
    }

    #[test]
    fn default_workspace_vct_uses_provided_storage_size() {
        let vct = default_workspace_volume_claim_templates("5Gi");
        let storage = &vct[0]["spec"]["resources"]["requests"]["storage"];
        assert_eq!(storage, "5Gi");
    }

    #[test]
    fn default_workspace_vct_falls_back_to_const_when_empty() {
        let vct = default_workspace_volume_claim_templates("");
        let storage = &vct[0]["spec"]["resources"]["requests"]["storage"];
        assert_eq!(storage, DEFAULT_WORKSPACE_STORAGE_SIZE);
    }
}

#[cfg(test)]
mod warm_pool_tests {
    use super::*;
    use crate::config::{KubernetesWarmPoolConfig, SharedVolumeSpec, WarmPoolSpec};

    fn pool(name: &str, gpu: bool) -> WarmPoolSpec {
        WarmPoolSpec {
            name: name.to_string(),
            replicas: 2,
            runtime_class_name: String::new(),
            gpu,
            shared_volume: None,
        }
    }

    fn warm_config(pools: Vec<WarmPoolSpec>) -> KubernetesComputeConfig {
        KubernetesComputeConfig {
            default_image: "ghcr.io/openshell/sandbox:latest".to_string(),
            warm_pool: KubernetesWarmPoolConfig {
                enabled: true,
                pools,
            },
            ..KubernetesComputeConfig::default()
        }
    }

    fn claim_object(
        sandbox_id: Option<&str>,
        bound: Option<&str>,
        claim_uid: &str,
    ) -> DynamicObject {
        let gvk = GroupVersionKind::gvk(EXT_GROUP, EXT_VERSION, SANDBOX_CLAIM_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut obj = DynamicObject::new("sb-name", &resource);
        obj.metadata.uid = Some(claim_uid.to_string());
        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        );
        if let Some(id) = sandbox_id {
            labels.insert(LABEL_SANDBOX_ID.to_string(), id.to_string());
        }
        obj.metadata.labels = Some(labels);
        if let Some(name) = bound {
            obj.data = serde_json::json!({ "status": { "sandbox": { "name": name } } });
        }
        obj
    }

    #[test]
    fn warm_eligible_accepts_default_image_without_overrides() {
        let spec = SandboxSpec::default();
        assert!(warm_eligible(&spec, "img"));

        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                image: "img".to_string(),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };
        assert!(warm_eligible(&spec, "img"));
    }

    #[test]
    fn warm_eligible_rejects_overrides() {
        // Custom image.
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                image: "other/image:tag".to_string(),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));

        // Per-request env.
        let mut env = std::collections::HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        let spec = SandboxSpec {
            environment: env,
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));

        // Per-request driver config (e.g. a specific GPU device, which moved
        // into driver_config) must fall back to cold — the pooled template
        // bakes a fixed shape.
        let mut fields = BTreeMap::new();
        fields.insert(
            "gpu_device".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("0".to_string())),
            },
        );
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                driver_config: Some(prost_types::Struct { fields }),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));

        // Custom template labels.
        let mut labels = std::collections::HashMap::new();
        labels.insert("team".to_string(), "x".to_string());
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                labels,
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));

        // Custom policy (gateway-signalled): must fall back to cold so the
        // per-sandbox policy is not silently downgraded to the pool baseline.
        let spec = SandboxSpec {
            disallow_warm_pool: true,
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));

        // Per-request log level: cold-only (threaded into pod env); the warm
        // template is built from defaults, so it would be silently dropped.
        let spec = SandboxSpec {
            log_level: "debug".to_string(),
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));

        // Per-request agent socket: cold-only (Sandbox `agentSocket`).
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                agent_socket_path: "/run/agent.sock".to_string(),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };
        assert!(!warm_eligible(&spec, "img"));
    }

    #[test]
    fn matching_warm_pool_selects_by_gpu_shape() {
        let config = warm_config(vec![pool("default", false), pool("gpu", true)]);

        // Driver matching is config-only; mimic it without a live client.
        let pools = &config.warm_pool.pools;
        let cpu_spec = SandboxSpec::default();
        let selected = pools.iter().find(|p| p.gpu == cpu_spec.gpu).unwrap();
        assert_eq!(selected.name, "default");

        let gpu_spec = SandboxSpec {
            gpu: true,
            ..SandboxSpec::default()
        };
        let selected = pools.iter().find(|p| p.gpu == gpu_spec.gpu).unwrap();
        assert_eq!(selected.name, "gpu");
    }

    #[test]
    fn warm_claim_spec_is_single_use_and_identity_only() {
        let spec = warm_claim_spec("openshell-warmpool-default", "sandbox-123");
        let claim = &spec["spec"];
        assert_eq!(
            claim["sandboxTemplateRef"]["name"],
            "openshell-warmpool-default"
        );
        assert_eq!(claim["warmpool"], "openshell-warmpool-default");
        assert_eq!(
            claim["additionalPodMetadata"]["annotations"]["openshell.io/sandbox-id"],
            "sandbox-123"
        );
        // Single-use teardown is mandatory; Retain would orphan workspace data.
        assert_eq!(claim["lifecycle"]["shutdownPolicy"], "Delete");
        // Per-claim env must never be set on the warm path.
        assert!(claim.get("env").is_none());
    }

    #[test]
    fn warm_template_uses_ephemeral_workspace_and_no_identity() {
        let config = warm_config(vec![pool("default", false)]);
        let spec = build_warm_sandbox_template_spec(&config, &config.warm_pool.pools[0]);

        // Disallow per-claim env injection.
        assert_eq!(spec["envVarsInjectionPolicy"], "Disallowed");
        // SandboxTemplate.spec carries no PVC volumeClaimTemplates (the orphan
        // risk); the writable workspace is an emptyDir instead.
        assert!(spec.get("volumeClaimTemplates").is_none());

        let pod_spec = &spec["podTemplate"]["spec"];
        let volumes = pod_spec["volumes"].as_array().expect("volumes");
        let workspace = volumes
            .iter()
            .find(|v| v["name"] == WORKSPACE_VOLUME_NAME)
            .expect("workspace volume present");
        assert!(
            workspace.get("emptyDir").is_some(),
            "warm workspace must be an emptyDir, got {workspace}"
        );
        assert!(
            workspace.get("persistentVolumeClaim").is_none(),
            "warm workspace must not be PVC-backed"
        );

        // The pooled template must not bake any per-sandbox identity annotation.
        let annotations = spec["podTemplate"]["metadata"].get("annotations");
        let has_sandbox_id = annotations
            .and_then(|a| a.get("openshell.io/sandbox-id"))
            .is_some();
        assert!(!has_sandbox_id, "pooled template must be identity-free");
    }

    #[test]
    fn warm_template_mounts_shared_volume_read_only() {
        let mut config = warm_config(vec![pool("data", false)]);
        config.warm_pool.pools[0].shared_volume = Some(SharedVolumeSpec {
            claim_name: "models".to_string(),
            mount_path: "/models".to_string(),
            sub_path: "llama".to_string(),
        });
        let spec = build_warm_sandbox_template_spec(&config, &config.warm_pool.pools[0]);
        let pod_spec = &spec["podTemplate"]["spec"];

        let shared_vol = pod_spec["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["persistentVolumeClaim"]["claimName"] == "models")
            .expect("shared volume present");
        assert_eq!(shared_vol["persistentVolumeClaim"]["readOnly"], true);

        let agent = pod_spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "agent")
            .expect("agent container");
        let mount = agent["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["mountPath"] == "/models")
            .expect("shared mount present");
        assert_eq!(mount["readOnly"], true);
        assert_eq!(mount["subPath"], "llama");
    }

    #[test]
    fn is_cold_openshell_sandbox_requires_sandbox_id_label() {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, SANDBOX_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);

        // Cold OpenShell sandbox: carries openshell.ai/sandbox-id.
        let mut cold = DynamicObject::new("cold-sb", &resource);
        cold.metadata.labels = Some(BTreeMap::from([(
            LABEL_SANDBOX_ID.to_string(),
            "sandbox-1".to_string(),
        )]));
        assert!(is_cold_openshell_sandbox(&cold));

        // Bound warm Sandbox: only the upstream claim-uid label.
        let mut bound_warm = DynamicObject::new("bound-sb", &resource);
        bound_warm.metadata.labels = Some(BTreeMap::from([(
            CLAIM_UID_LABEL.to_string(),
            "claim-uid".to_string(),
        )]));
        assert!(!is_cold_openshell_sandbox(&bound_warm));

        // Unbound pooled warm Sandbox: neither identity label — this is the
        // case that previously slipped through and broke the watch loop.
        let mut pooled_warm = DynamicObject::new("openshell-warmpool-default-abc", &resource);
        pooled_warm.metadata.labels = Some(BTreeMap::from([(
            WARM_POOL_LABEL.to_string(),
            "default".to_string(),
        )]));
        assert!(!is_cold_openshell_sandbox(&pooled_warm));
    }

    #[test]
    fn sandbox_from_claim_object_maps_id_and_bound_status() {
        let obj = claim_object(Some("sandbox-9"), Some("bound-sandbox-xyz"), "claim-uid-9");
        let sandbox = sandbox_from_claim_object("openshell", obj).unwrap();
        assert_eq!(sandbox.id, "sandbox-9");
        assert_eq!(sandbox.name, "sb-name");
        let status = sandbox.status.expect("status");
        assert_eq!(status.sandbox_name, "bound-sandbox-xyz");
        assert_eq!(status.instance_id, "bound-sandbox-xyz");
        assert_eq!(status.claim_name, "sb-name");
        assert_eq!(status.claim_uid, "claim-uid-9");
    }

    #[test]
    fn sandbox_from_claim_object_requires_sandbox_id_label() {
        let obj = claim_object(None, None, "claim-uid-0");
        assert!(sandbox_from_claim_object("openshell", obj).is_err());
        let obj = claim_object(None, None, "claim-uid-0");
        assert!(managed_claim_sandbox("openshell", &obj).is_none());
    }

    #[test]
    fn warm_resource_name_is_prefixed() {
        assert_eq!(warm_resource_name("default"), "openshell-warmpool-default");
    }
}
