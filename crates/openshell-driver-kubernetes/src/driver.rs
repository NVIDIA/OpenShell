// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes compute driver.

use super::AppArmorProfile;
use crate::config::{
    DEFAULT_PROXY_UID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_SANDBOX_UID,
    DEFAULT_WORKSPACE_STORAGE_SIZE, KubernetesComputeConfig, SupervisorSideloadMethod,
    SupervisorTopology,
};
use futures::{Stream, StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Event as KubeEventObj, Namespace, Node};
use kube::api::{Api, ApiResource, DeleteParams, ListParams, PostParams};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, SUPERVISOR_IMAGE_BINARY_PATH,
};
use openshell_core::gpu::{driver_gpu_requirements, effective_driver_gpu_count};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    format_bytes, mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    DriverCondition as SandboxCondition, DriverPlatformEvent as PlatformEvent,
    DriverSandbox as Sandbox, DriverSandboxSpec as SandboxSpec,
    DriverSandboxStatus as SandboxStatus, DriverSandboxTemplate as SandboxTemplate,
    GetCapabilitiesResponse, GpuResourceRequirements, WatchSandboxesDeletedEvent,
    WatchSandboxesEvent, WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent,
    watch_sandboxes_event,
};
use openshell_core::proto_struct::{struct_to_json_object, value_to_json};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, mpsc};
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

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_VERSION_V1BETA1: &str = "v1beta1";
const SANDBOX_VERSION_V1ALPHA1: &str = "v1alpha1";
const SANDBOX_VERSIONS: &[&str] = &[SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1];
pub const SANDBOX_KIND: &str = "Sandbox";

const GPU_RESOURCE_NAME: &str = "nvidia.com/gpu";
const SPIFFE_WORKLOAD_API_VOLUME_NAME: &str = "spiffe-workload-api";

struct AgentSandboxApi {
    api: Api<DynamicObject>,
    resource: ApiResource,
}

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
    sandbox_api_version: Arc<OnceCell<&'static str>>,
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
        config
            .validate_sandbox_identity_config()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_proxy_uid()
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
            sandbox_api_version: Arc::new(OnceCell::new()),
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

    fn agent_sandbox_api(&self, client: Client, sandbox_api_version: &str) -> AgentSandboxApi {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, sandbox_api_version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let api = Api::namespaced_with(client, &self.config.namespace, &resource);
        AgentSandboxApi { api, resource }
    }

    async fn supported_agent_sandbox_api(&self, client: Client) -> Result<AgentSandboxApi, String> {
        let sandbox_api_version = self.supported_sandbox_api_version(client.clone()).await?;
        Ok(self.agent_sandbox_api(client, sandbox_api_version))
    }

    async fn supported_sandbox_api_version(&self, client: Client) -> Result<&'static str, String> {
        self.sandbox_api_version
            .get_or_try_init(
                || async move { self.detect_supported_sandbox_api_version(client).await },
            )
            .await
            .copied()
    }

    async fn detect_supported_sandbox_api_version(
        &self,
        client: Client,
    ) -> Result<&'static str, String> {
        for sandbox_api_version in SANDBOX_VERSIONS {
            let agent_sandbox_api = self.agent_sandbox_api(client.clone(), sandbox_api_version);
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                agent_sandbox_api.api.list(&ListParams::default().limit(1)),
            )
            .await
            {
                Ok(Ok(_)) => {
                    debug!(
                        namespace = %self.config.namespace,
                        sandbox_api_version = %sandbox_api_version,
                        "Selected Agent Sandbox API version"
                    );
                    return Ok(sandbox_api_version);
                }
                Ok(Err(err)) if should_try_next_sandbox_api_version(&err) => {
                    debug!(
                        namespace = %self.config.namespace,
                        sandbox_api_version = %sandbox_api_version,
                        error = %err,
                        "Sandbox API version is not available; trying next supported version"
                    );
                }
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_elapsed) => {
                    return Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        Err(format!(
            "no supported Agent Sandbox API version is available; tried {}",
            SANDBOX_VERSIONS.join(", ")
        ))
    }

    /// Resolve sandbox UID/GID from config or `OpenShift` SCC namespace annotations.
    ///
    /// Returns `(uid, gid, ns_annotations_map)`:
    /// - If `sandbox_uid` is set in config, returns that (with fallback GID)
    /// - Otherwise fetches the target namespace and checks for
    ///   `openshift.io/sa.scc.uid-range` / `openshift.io/sa.scc.supplemental-groups`
    ///   annotations.
    /// - If neither config nor `OpenShift` is found, returns `(1000, 1000, {})` as defaults.
    async fn resolve_sandbox_identity(&self) -> (u32, u32, BTreeMap<String, String>) {
        // Explicit config takes priority — skip namespace lookup entirely.
        if self.config.sandbox_uid.is_some() {
            let uid = self.config.resolve_sandbox_uid(None);
            let gid = self.config.resolve_sandbox_gid(uid, None);
            return (uid, gid, BTreeMap::new());
        }

        // Try to read namespace annotations for OpenShift SCC.
        // Namespace is namespaced so Api::all works (it's cluster-scoped but
        // can list all namespaces) and we filter by name, or use Api::namespaced.
        let ns_api: Api<Namespace> = Api::all(self.client.clone());
        match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(self.config.namespace.as_str()))
            .await
        {
            Ok(Ok(ns)) => {
                let anns = ns.metadata.annotations.unwrap_or_default();
                tracing::info!(
                    namespace = %self.config.namespace,
                    uid_range = ?anns.get(crate::config::ANNOTATION_SCC_UID_RANGE),
                    sup_groups = ?anns.get(crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS),
                    "Resolved namespace annotations for sandbox identity"
                );
                let uid = self.config.resolve_sandbox_uid(Some(&anns));
                // Explicit sandbox_gid config wins; SCC annotation only applies when not set.
                let baseline_gid = self.config.resolve_sandbox_gid(uid, None);
                let gid = self.config.sandbox_gid.map_or_else(
                    || {
                        anns.get(crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS)
                            .and_then(|sup_range| {
                                KubernetesComputeConfig::from_open_shift_supplemental_groups(
                                    sup_range,
                                )
                            })
                            .unwrap_or(baseline_gid)
                    },
                    |_| baseline_gid,
                );
                tracing::info!(uid, gid, "Resolved sandbox identity");
                (uid, gid, anns)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    namespace = %self.config.namespace,
                    error = %e,
                    "Failed to fetch namespace for SCC annotations, falling back to defaults"
                );
                let uid = DEFAULT_SANDBOX_UID;
                let gid = self.config.resolve_sandbox_gid(uid, None);
                (uid, gid, BTreeMap::new())
            }
            Err(_) => {
                tracing::warn!(
                    namespace = %self.config.namespace,
                    "Namespace fetch timed out, falling back to defaults"
                );
                let uid = DEFAULT_SANDBOX_UID;
                let gid = self.config.resolve_sandbox_gid(uid, None);
                (uid, gid, BTreeMap::new())
            }
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
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        validate_gpu_request(gpu_requirements)?;
        if gpu_requirements.is_some()
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

        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone())
            .await?;
        match tokio::time::timeout(KUBE_API_TIMEOUT, agent_sandbox_api.api.get(name)).await {
            Ok(Ok(obj)) => sandbox_from_object(&self.config.namespace, obj).map(Some),
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                debug!(sandbox_name = %name, "Sandbox not found in Kubernetes");
                Ok(None)
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_name = %name,
                    error = %err,
                    "Failed to fetch sandbox from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out fetching sandbox from Kubernetes"
                );
                Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ))
            }
        }
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<Sandbox>, String> {
        info!(
            namespace = %self.config.namespace,
            "Listing sandboxes from Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone())
            .await?;
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api.api.list(&ListParams::default()),
        )
        .await
        {
            Ok(Ok(list)) => {
                let mut sandboxes = list
                    .items
                    .into_iter()
                    .map(|obj| sandbox_from_object(&self.config.namespace, obj))
                    .collect::<Result<Vec<_>, _>>()?;
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

    #[allow(clippy::similar_names)]
    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<(), KubernetesDriverError> {
        let _ = KubernetesSandboxDriverConfig::from_sandbox(sandbox)
            .map_err(KubernetesDriverError::InvalidArgument)?;
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        validate_gpu_request(gpu_requirements).map_err(|status| {
            KubernetesDriverError::InvalidArgument(status.message().to_string())
        })?;
        let name = sandbox.name.as_str();
        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Creating sandbox in Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;

        // Resolve sandbox UID/GID from config or OpenShift SCC namespace annotations.
        let (resolved_user_id, resolved_group_id, ns_annotations) =
            self.resolve_sandbox_identity().await;

        let params = SandboxPodParams {
            default_image: &self.config.default_image,
            image_pull_policy: &self.config.image_pull_policy,
            image_pull_secrets: &self.config.image_pull_secrets,
            supervisor_image: &self.config.supervisor_image,
            supervisor_image_pull_policy: &self.config.supervisor_image_pull_policy,
            supervisor_sideload_method: self.config.supervisor_sideload_method,
            supervisor_topology: self.config.topology,
            proxy_uid: self.config.sidecar.proxy_uid,
            process_binary_aware_network_policy: self
                .config
                .sidecar
                .process_binary_aware_network_policy,
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
            sandbox_uid: resolved_user_id,
            sandbox_gid: resolved_group_id,
        };
        validate_sidecar_proxy_identity(&params)?;

        let mut obj = DynamicObject::new(name, &agent_sandbox_api.resource);
        // Copy only the SCC-related annotations onto the Sandbox CR for
        // traceability. Copying the full namespace annotation map exposes
        // unrelated cluster metadata and can fail with oversized annotations.
        let scc_annotations: BTreeMap<String, String> = [
            crate::config::ANNOTATION_SCC_UID_RANGE,
            crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
        ]
        .iter()
        .filter_map(|key| {
            ns_annotations
                .get(*key)
                .map(|v| ((*key).to_string(), v.clone()))
        })
        .collect();
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(self.config.namespace.clone()),
            labels: Some(sandbox_labels(sandbox)),
            annotations: if scc_annotations.is_empty() {
                None
            } else {
                Some(scc_annotations)
            },
            ..Default::default()
        };

        obj.data = sandbox_to_k8s_spec(sandbox.spec.as_ref(), &params);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api.api.create(&PostParams::default(), &obj),
        )
        .await
        {
            Ok(Ok(_result)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "Sandbox created in Kubernetes successfully"
                );
                Ok(())
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

        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone())
            .await?;
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api.api.delete(name, &DeleteParams::default()),
        )
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
        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone())
            .await?;
        match tokio::time::timeout(KUBE_API_TIMEOUT, agent_sandbox_api.api.get(name)).await {
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
        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.watch_client.clone())
            .await?;
        let event_api: Api<KubeEventObj> = Api::namespaced(self.watch_client.clone(), &namespace);
        let mut sandbox_stream =
            watcher::watcher(agent_sandbox_api.api, watcher::Config::default()).boxed();
        let mut event_stream = watcher::watcher(event_api, watcher::Config::default()).boxed();
        let (tx, rx) = mpsc::channel(256);

        tokio::spawn(async move {
            let mut sandbox_name_to_id = std::collections::HashMap::<String, String>::new();
            let mut agent_pod_to_id = std::collections::HashMap::<String, String>::new();

            loop {
                tokio::select! {
                    result = sandbox_stream.try_next() => match result {
                        Ok(Some(Event::Applied(obj))) => {
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

fn should_try_next_sandbox_api_version(err: &KubeError) -> bool {
    // Kubernetes returns a structured 404 for some missing API resources and a
    // raw "404 page not found" body for others. Both mean the probed
    // group/version is unavailable and the next supported Sandbox API version
    // should be tried.
    matches!(err, KubeError::Api(api) if api.code == 404)
}

fn validate_gpu_request(
    gpu_requirements: Option<&GpuResourceRequirements>,
) -> Result<(), tonic::Status> {
    let _ =
        effective_driver_gpu_count(gpu_requirements).map_err(tonic::Status::invalid_argument)?;
    Ok(())
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

/// Name of the init container that prepares pod-level sidecar networking.
const SUPERVISOR_NETWORK_INIT_CONTAINER_NAME: &str = "openshell-network-init";

/// Container name for the network-only supervisor sidecar.
const SUPERVISOR_NETWORK_SIDECAR_NAME: &str = "openshell-supervisor-network";

/// Shared volume used by the network sidecar and process-only supervisor for
/// local coordination in sidecar topology.
const SIDECAR_STATE_VOLUME_NAME: &str = "openshell-sidecar-state";
const SIDECAR_STATE_MOUNT_PATH: &str = "/run/openshell-sidecar";
const SIDECAR_CONTROL_SOCKET: &str = "/run/openshell-sidecar/control.sock";
const SIDECAR_SSH_SOCKET_FILE: &str = "/run/openshell-sidecar/ssh.sock";

/// Shared TLS work directory. The network sidecar writes the proxy CA bundle
/// here, while the agent container consumes it after sidecar bootstrap.
const SIDECAR_TLS_VOLUME_NAME: &str = "openshell-supervisor-tls";
const SIDECAR_TLS_MOUNT_PATH: &str = "/etc/openshell-tls/proxy";
const SIDECAR_CLIENT_TLS_MOUNT_PATH: &str = "/etc/openshell-tls/proxy/client";

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

fn apply_supervisor_binary_source(
    spec: &mut serde_json::Map<String, serde_json::Value>,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
    method: SupervisorSideloadMethod,
) {
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
/// side-loaded binary as root so it can create network namespaces, set up the
/// proxy, and configure Landlock/seccomp.
#[allow(clippy::similar_names)]
fn apply_supervisor_sideload(
    pod_template: &mut serde_json::Value,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
    method: SupervisorSideloadMethod,
    sandbox_uid: u32,
    sandbox_gid: u32,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    apply_supervisor_binary_source(spec, supervisor_image, supervisor_image_pull_policy, method);

    // Find the agent container and add volume mount + command override
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

        // Inject resolved sandbox UID/GID as environment variables so the
        // supervisor can use them directly without /etc/passwd lookups.
        let env = container
            .entry("env")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(env) = env {
            env.push(serde_json::json!({
                "name": openshell_core::sandbox_env::SANDBOX_UID.to_string(),
                "value": sandbox_uid.to_string(),
            }));
            env.push(serde_json::json!({
                "name": openshell_core::sandbox_env::SANDBOX_GID.to_string(),
                "value": sandbox_gid.to_string(),
            }));
        }
    }
}

fn sidecar_state_volume_mount() -> serde_json::Value {
    serde_json::json!({
        "name": SIDECAR_STATE_VOLUME_NAME,
        "mountPath": SIDECAR_STATE_MOUNT_PATH,
    })
}

fn sidecar_tls_volume_mount() -> serde_json::Value {
    serde_json::json!({
        "name": SIDECAR_TLS_VOLUME_NAME,
        "mountPath": SIDECAR_TLS_MOUNT_PATH,
    })
}

fn copy_log_level_env(
    env: &mut Vec<serde_json::Value>,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
) {
    if let Some(value) = spec_environment
        .get(openshell_core::sandbox_env::LOG_LEVEL)
        .or_else(|| template_environment.get(openshell_core::sandbox_env::LOG_LEVEL))
    {
        upsert_env(env, openshell_core::sandbox_env::LOG_LEVEL, value);
    }
}

fn supervisor_sidecar_env(
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    params: &SandboxPodParams<'_>,
) -> Vec<serde_json::Value> {
    let mut env = Vec::new();
    apply_required_env(
        &mut env,
        params.sandbox_id,
        params.sandbox_name,
        params.grpc_endpoint,
        "",
        !params.client_tls_secret_name.is_empty(),
        provider_spiffe_socket_path(params),
    );
    if !params.client_tls_secret_name.is_empty() {
        upsert_env(
            &mut env,
            openshell_core::sandbox_env::TLS_CA,
            &format!("{SIDECAR_CLIENT_TLS_MOUNT_PATH}/ca.crt"),
        );
        upsert_env(
            &mut env,
            openshell_core::sandbox_env::TLS_CERT,
            &format!("{SIDECAR_CLIENT_TLS_MOUNT_PATH}/tls.crt"),
        );
        upsert_env(
            &mut env,
            openshell_core::sandbox_env::TLS_KEY,
            &format!("{SIDECAR_CLIENT_TLS_MOUNT_PATH}/tls.key"),
        );
    }
    copy_log_level_env(&mut env, template_environment, spec_environment);
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::SUPERVISOR_TOPOLOGY,
        "sidecar",
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::NETWORK_ENFORCEMENT_MODE,
        "sidecar-nftables",
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET,
        SIDECAR_CONTROL_SOCKET,
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::SSH_SOCKET_PATH,
        SIDECAR_SSH_SOCKET_FILE,
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::PROXY_TLS_DIR,
        SIDECAR_TLS_MOUNT_PATH,
    );
    if !params.process_binary_aware_network_policy {
        upsert_env(
            &mut env,
            openshell_core::sandbox_env::NETWORK_BINARY_IDENTITY,
            "relaxed",
        );
    }
    env
}

fn supervisor_sidecar_container(
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let capabilities = if params.process_binary_aware_network_policy {
        serde_json::json!({
            "drop": ["ALL"],
            "add": ["SYS_PTRACE"]
        })
    } else {
        serde_json::json!({
            "drop": ["ALL"]
        })
    };
    let mut container = serde_json::json!({
        "name": SUPERVISOR_NETWORK_SIDECAR_NAME,
        "image": params.supervisor_image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "--mode=network",
        ],
        "env": supervisor_sidecar_env(template_environment, spec_environment, params),
        "securityContext": {
            "runAsUser": params.proxy_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "capabilities": capabilities
        },
        "volumeMounts": [
            sidecar_state_volume_mount(),
            sidecar_tls_volume_mount(),
            {
                "name": "openshell-sa-token",
                "mountPath": "/var/run/secrets/openshell",
                "readOnly": true
            }
        ]
    });
    if !params.supervisor_image_pull_policy.is_empty() {
        container["imagePullPolicy"] = serde_json::json!(params.supervisor_image_pull_policy);
    }
    if params.provider_spiffe_enabled {
        container["volumeMounts"]
            .as_array_mut()
            .expect("volumeMounts is an array")
            .push(serde_json::json!({
                "name": SPIFFE_WORKLOAD_API_VOLUME_NAME,
                "mountPath": spiffe_socket_mount_path(params.provider_spiffe_workload_api_socket_path),
                "readOnly": true,
            }));
    }
    if let Some(profile) = params.app_armor_profile {
        container["securityContext"]["appArmorProfile"] = app_armor_profile_to_k8s(profile);
    }
    container
}

fn supervisor_network_init_container(params: &SandboxPodParams<'_>) -> serde_json::Value {
    let mut container = serde_json::json!({
        "name": SUPERVISOR_NETWORK_INIT_CONTAINER_NAME,
        "image": params.supervisor_image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "--mode=network-init",
            "--proxy-uid",
            params.proxy_uid.to_string(),
            "--proxy-gid",
            params.sandbox_gid.to_string(),
            "--sidecar-state-dir",
            SIDECAR_STATE_MOUNT_PATH,
            "--sidecar-tls-dir",
            SIDECAR_TLS_MOUNT_PATH,
        ],
        "securityContext": {
            "runAsUser": 0,
            "allowPrivilegeEscalation": false,
            "capabilities": {
                "drop": ["ALL"],
                "add": ["NET_ADMIN", "NET_RAW", "CHOWN", "FOWNER"]
            }
        },
        "volumeMounts": [
            sidecar_state_volume_mount(),
            sidecar_tls_volume_mount(),
        ]
    });
    if !params.supervisor_image_pull_policy.is_empty() {
        container["imagePullPolicy"] = serde_json::json!(params.supervisor_image_pull_policy);
    }
    if !params.client_tls_secret_name.is_empty() {
        container["volumeMounts"]
            .as_array_mut()
            .expect("volumeMounts is an array")
            .push(serde_json::json!({
                "name": "openshell-client-tls",
                "mountPath": "/etc/openshell-tls/client",
                "readOnly": true
            }));
    }
    if let Some(profile) = params.app_armor_profile {
        container["securityContext"]["appArmorProfile"] = app_armor_profile_to_k8s(profile);
    }
    container
}

fn apply_supervisor_sidecar_topology(
    pod_template: &mut serde_json::Value,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    params: &SandboxPodParams<'_>,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    let pod_security_context = spec
        .entry("securityContext")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(sc) = pod_security_context.as_object_mut() {
        sc.insert("fsGroup".to_string(), serde_json::json!(params.sandbox_gid));
    }

    spec.insert("shareProcessNamespace".to_string(), serde_json::json!(true));

    apply_supervisor_binary_source(
        spec,
        params.supervisor_image,
        params.supervisor_image_pull_policy,
        params.supervisor_sideload_method,
    );

    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        volumes.push(serde_json::json!({
            "name": SIDECAR_STATE_VOLUME_NAME,
            "emptyDir": {}
        }));
        volumes.push(serde_json::json!({
            "name": SIDECAR_TLS_VOLUME_NAME,
            "emptyDir": {}
        }));
    }

    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(init_containers) = init_containers {
        init_containers.push(supervisor_network_init_container(params));
    }

    let Some(containers) = spec.get_mut("containers").and_then(|v| v.as_array_mut()) else {
        return;
    };

    let target_index = containers
        .iter()
        .position(|c| c.get("name").and_then(|v| v.as_str()) == Some("agent"))
        .unwrap_or(0);

    if let Some(container) = containers
        .get_mut(target_index)
        .and_then(|v| v.as_object_mut())
    {
        container.insert(
            "command".to_string(),
            serde_json::json!([
                format!("{}/openshell-sandbox", SUPERVISOR_MOUNT_PATH),
                "--mode=process"
            ]),
        );

        let security_context = container
            .entry("securityContext")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(sc) = security_context.as_object_mut() {
            sc.insert(
                "runAsUser".to_string(),
                serde_json::json!(params.sandbox_uid),
            );
            sc.insert(
                "runAsGroup".to_string(),
                serde_json::json!(params.sandbox_gid),
            );
            sc.insert("runAsNonRoot".to_string(), serde_json::json!(true));
            sc.insert(
                "allowPrivilegeEscalation".to_string(),
                serde_json::json!(false),
            );
            sc.insert(
                "capabilities".to_string(),
                serde_json::json!({
                    "drop": ["ALL"]
                }),
            );
        }

        let volume_mounts = container
            .entry("volumeMounts")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(volume_mounts) = volume_mounts {
            remove_volume_mount(volume_mounts, "openshell-sa-token");
            remove_volume_mount(volume_mounts, "openshell-client-tls");
            remove_volume_mount(volume_mounts, SPIFFE_WORKLOAD_API_VOLUME_NAME);
            volume_mounts.push(supervisor_volume_mount());
            volume_mounts.push(sidecar_state_volume_mount());
            volume_mounts.push(sidecar_tls_volume_mount());
        }

        let env = container
            .entry("env")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(env) = env {
            remove_env(env, openshell_core::sandbox_env::ENDPOINT);
            remove_env(env, openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME);
            remove_env(env, openshell_core::sandbox_env::TLS_CA);
            remove_env(env, openshell_core::sandbox_env::TLS_CERT);
            remove_env(env, openshell_core::sandbox_env::TLS_KEY);
            remove_env(env, openshell_core::sandbox_env::SANDBOX_TOKEN);
            remove_env(env, openshell_core::sandbox_env::SANDBOX_TOKEN_FILE);
            remove_env(env, openshell_core::sandbox_env::K8S_SA_TOKEN_FILE);
            remove_env(
                env,
                openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::SUPERVISOR_TOPOLOGY,
                "sidecar",
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::NETWORK_ENFORCEMENT_MODE,
                "sidecar-nftables",
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::SSH_SOCKET_PATH,
                SIDECAR_SSH_SOCKET_FILE,
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET,
                SIDECAR_CONTROL_SOCKET,
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::PROXY_TLS_DIR,
                SIDECAR_TLS_MOUNT_PATH,
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::SANDBOX_UID,
                &params.sandbox_uid.to_string(),
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::SANDBOX_GID,
                &params.sandbox_gid.to_string(),
            );
        }
    }

    containers.push(supervisor_sidecar_container(
        template_environment,
        spec_environment,
        params,
    ));
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
#[allow(clippy::similar_names)]
fn apply_workspace_persistence(
    pod_template: &mut serde_json::Value,
    image: &str,
    image_pull_policy: &str,
    sandbox_gid: u32,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // fsGroup is a pod-level field — it instructs kubelet to chown mounted
    // volumes to this GID. It is invalid at the container securityContext level.
    let pod_sc = spec
        .entry("securityContext")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(pod_sc_obj) = pod_sc.as_object_mut() {
        pod_sc_obj.insert("fsGroup".to_string(), serde_json::json!(sandbox_gid));
    }

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
        // Archive only the contents, not the `/sandbox` directory entry
        // itself, so extraction never tries to chmod the PVC mount root.
        // Extract without restoring owner, mode, or timestamps so the
        // non-root init container can seed kubelet-owned PVCs.
        //
        // The inner `[ -d ... ]` guard handles custom images that don't have
        // a /sandbox directory — the copy is skipped but the sentinel is
        // still written so subsequent starts are instant.
        let copy_cmd = format!(
            "if [ ! -f {WORKSPACE_INIT_MOUNT_PATH}/{WORKSPACE_SENTINEL} ]; then \
               if [ -d {WORKSPACE_MOUNT_PATH} ]; then \
                 tmp=$(mktemp) && rm -f \"$tmp\" && \
                   (cd {WORKSPACE_MOUNT_PATH} && find . -mindepth 1 -maxdepth 1 -exec tar -cf \"$tmp\" {{}} +) && \
                   if [ -f \"$tmp\" ]; then \
                     tar -C {WORKSPACE_INIT_MOUNT_PATH} --no-same-owner --no-same-permissions --touch -xf \"$tmp\" && \
                     rm -f \"$tmp\"; \
                   fi; \
               fi && \
               touch {WORKSPACE_INIT_MOUNT_PATH}/{WORKSPACE_SENTINEL}; \
             fi"
        );

        let mut init_spec = serde_json::json!({
            "name": WORKSPACE_INIT_CONTAINER_NAME,
            "image": image,
            "command": ["sh", "-c", copy_cmd],
            "securityContext": {
                "runAsUser": 0,
            },
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
    supervisor_topology: SupervisorTopology,
    proxy_uid: u32,
    process_binary_aware_network_policy: bool,
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
    /// Resolved sandbox UID for supervisor `runAsUser` and env var.
    sandbox_uid: u32,
    /// Resolved sandbox GID for PVC init container operations.
    sandbox_gid: u32,
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
            supervisor_topology: SupervisorTopology::default(),
            proxy_uid: DEFAULT_PROXY_UID,
            process_binary_aware_network_policy: true,
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
            sandbox_uid: DEFAULT_SANDBOX_UID,
            sandbox_gid: DEFAULT_SANDBOX_UID,
        }
    }
}

fn validate_sidecar_proxy_identity(
    params: &SandboxPodParams<'_>,
) -> Result<(), KubernetesDriverError> {
    if params.supervisor_topology == SupervisorTopology::Sidecar
        && params.proxy_uid == params.sandbox_uid
    {
        return Err(KubernetesDriverError::Precondition(format!(
            "proxy_uid ({}) must not match sandbox_uid ({}) in sidecar topology",
            params.proxy_uid, params.sandbox_uid
        )));
    }
    Ok(())
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

    if let Some(spec) = spec {
        let pod_env = spec_pod_env(Some(spec));
        if let Some(template) = spec.template.as_ref() {
            root.insert(
                "podTemplate".to_string(),
                sandbox_template_to_k8s_with_gpu_requirements(
                    template,
                    driver_gpu_requirements(spec.resource_requirements.as_ref()),
                    &pod_env,
                    true,
                    params,
                ),
            );
            if !template.agent_socket_path.is_empty() {
                root.insert(
                    "agentSocket".to_string(),
                    serde_json::json!(template.agent_socket_path),
                );
            }
        }
    }

    root.insert(
        "volumeClaimTemplates".to_string(),
        default_workspace_volume_claim_templates(params.workspace_default_storage_size),
    );

    // podTemplate is required by the Kubernetes CRD - ensure it's always present
    if !root.contains_key("podTemplate") {
        let pod_env = spec_pod_env(spec);
        root.insert(
            "podTemplate".to_string(),
            sandbox_template_to_k8s_with_gpu_requirements(
                &SandboxTemplate::default(),
                driver_gpu_requirements(spec.and_then(|s| s.resource_requirements.as_ref())),
                &pod_env,
                true,
                params,
            ),
        );
    }

    serde_json::Value::Object(
        std::iter::once(("spec".to_string(), serde_json::Value::Object(root))).collect(),
    )
}

#[cfg(test)]
fn sandbox_template_to_k8s(
    template: &SandboxTemplate,
    gpu: bool,
    spec_environment: &std::collections::HashMap<String, String>,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let gpu_requirements = gpu.then_some(GpuResourceRequirements { count: None });
    sandbox_template_to_k8s_with_gpu_requirements(
        template,
        gpu_requirements.as_ref(),
        spec_environment,
        inject_workspace,
        params,
    )
}

fn sandbox_template_to_k8s_with_gpu_requirements(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
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
        if gpu_requirements.is_some() {
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

    if let Some(resources) = container_resources(template, gpu_requirements) {
        container.insert("resources".to_string(), resources);
    }
    apply_agent_driver_resources(&mut container, &driver_config.containers.agent.resources);
    spec.insert(
        "containers".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(container)]),
    );

    // Add TLS secret volume. Combined mode uses mode 0400 because the
    // supervisor starts as root and drops privileges before running workload
    // children. Sidecar mode keeps the process supervisor non-root, so it uses
    // pod fsGroup + 0440 to preserve gateway session and SSH control behavior.
    let mut volumes: Vec<serde_json::Value> = Vec::new();
    if !params.client_tls_secret_name.is_empty() {
        let client_tls_default_mode = match params.supervisor_topology {
            SupervisorTopology::Combined => 0o400,
            SupervisorTopology::Sidecar => 0o440,
        };
        volumes.push(serde_json::json!({
            "name": "openshell-client-tls",
            "secret": {
                "secretName": params.client_tls_secret_name,
                "defaultMode": client_tls_default_mode
            }
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
    // JWT via `IssueSandboxToken` once at startup. In sidecar topology both
    // supervisor containers run with the sandbox GID and need group-read access.
    let sa_token_default_mode = match params.supervisor_topology {
        SupervisorTopology::Combined => 0o400,
        SupervisorTopology::Sidecar => 0o440,
    };
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
            "defaultMode": sa_token_default_mode
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

    match params.supervisor_topology {
        SupervisorTopology::Combined => {
            apply_supervisor_sideload(
                &mut result,
                params.supervisor_image,
                params.supervisor_image_pull_policy,
                params.supervisor_sideload_method,
                params.sandbox_uid,
                params.sandbox_gid,
            );
        }
        SupervisorTopology::Sidecar => {
            apply_supervisor_sidecar_topology(
                &mut result,
                &template.environment,
                spec_environment,
                params,
            );
        }
    }

    // Inject workspace persistence (init container + PVC volume mount) so
    // that /sandbox data survives pod rescheduling.  Skipped when the user
    // provides custom volumeClaimTemplates to avoid conflicts.
    if inject_workspace {
        apply_workspace_persistence(
            &mut result,
            image,
            params.image_pull_policy,
            params.sandbox_gid,
        );
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

fn container_resources(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
) -> Option<serde_json::Value> {
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

    if let Some(gpu) = gpu_requirements {
        let quantity = gpu.count.unwrap_or(1).to_string();
        apply_gpu_limit(&mut resources, &quantity);
    }
    if resources.as_object().is_some_and(serde_json::Map::is_empty) {
        None
    } else {
        Some(resources)
    }
}

fn apply_gpu_limit(resources: &mut serde_json::Value, quantity: &str) {
    let Some(resources_obj) = resources.as_object_mut() else {
        *resources = serde_json::json!({});
        return apply_gpu_limit(resources, quantity);
    };

    let limits = resources_obj
        .entry("limits")
        .or_insert_with(|| serde_json::json!({}));
    let Some(limits_obj) = limits.as_object_mut() else {
        *limits = serde_json::json!({});
        return apply_gpu_limit(resources, quantity);
    };

    limits_obj.insert(GPU_RESOURCE_NAME.to_string(), serde_json::json!(quantity));
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
    upsert_env(env, openshell_core::sandbox_env::SANDBOX_ID, sandbox_id);
    upsert_env(env, openshell_core::sandbox_env::SANDBOX, sandbox_name);
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

fn remove_env(env: &mut Vec<serde_json::Value>, name: &str) {
    env.retain(|item| item.get("name").and_then(|value| value.as_str()) != Some(name));
}

fn remove_volume_mount(volume_mounts: &mut Vec<serde_json::Value>, name: &str) {
    volume_mounts.retain(|mount| mount.get("name").and_then(|value| value.as_str()) != Some(name));
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
    use openshell_core::proto::compute::v1::{GpuResourceRequirements, ResourceRequirements};
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

    fn rendered_env<'a>(container: &'a serde_json::Value, name: &str) -> Option<&'a str> {
        container["env"]
            .as_array()?
            .iter()
            .find(|item| item.get("name").and_then(|value| value.as_str()) == Some(name))?
            .get("value")?
            .as_str()
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
                template: Some(SandboxTemplate {
                    driver_config: Some(json_struct(serde_json::json!({
                        "gpu_device_ids": ["0000:2d:00.0"]
                    }))),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = KubernetesSandboxDriverConfig::from_sandbox(&sandbox).unwrap_err();
        assert!(err.contains("unknown field"));
        assert!(err.contains("gpu_device_ids"));
    }

    #[test]
    fn validate_rejects_zero_gpu_count() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                resource_requirements: Some(ResourceRequirements {
                    gpu: Some(GpuResourceRequirements { count: Some(0) }),
                }),
                ..SandboxSpec::default()
            }),
            ..Sandbox::default()
        };

        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        let err = validate_gpu_request(gpu_requirements).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("gpu count must be greater than 0"));
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
            1500, // sandbox_uid
            1500, // sandbox_gid
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
            1000, // sandbox_uid
            1000, // sandbox_gid
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
            1000, // sandbox_uid
            1000, // sandbox_gid
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
            1000, // sandbox_uid
            1000, // sandbox_gid
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
            1000, // sandbox_uid
            1000, // sandbox_gid
        );

        let volume = &pod_template["spec"]["volumes"][0];
        assert_eq!(volume["image"]["reference"], "supervisor-image:latest");
        assert!(
            volume["image"].get("pullPolicy").is_none(),
            "pullPolicy should be omitted when empty"
        );
    }

    #[test]
    fn sidecar_topology_renders_process_agent_and_network_sidecar() {
        let params = SandboxPodParams {
            supervisor_topology: SupervisorTopology::Sidecar,
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            supervisor_image: "supervisor-image:latest",
            supervisor_image_pull_policy: "IfNotPresent",
            grpc_endpoint: "https://openshell-gateway.openshell.svc:8080",
            client_tls_secret_name: "openshell-client-tls",
            proxy_uid: 2200,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate {
                image: "agent-image:latest".to_string(),
                ..SandboxTemplate::default()
            },
            false,
            &std::collections::HashMap::new(),
            false,
            &params,
        );

        assert_eq!(pod_template["spec"]["shareProcessNamespace"], true);
        assert_eq!(pod_template["spec"]["securityContext"]["fsGroup"], 1500);
        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 2);

        let agent = containers
            .iter()
            .find(|container| container["name"] == "agent")
            .unwrap();
        assert_eq!(
            agent["command"],
            serde_json::json!([
                format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox"),
                "--mode=process"
            ])
        );
        assert_eq!(agent["securityContext"]["runAsUser"], 1500);
        assert_eq!(agent["securityContext"]["runAsGroup"], 1500);
        assert_eq!(agent["securityContext"]["runAsNonRoot"], true);
        assert_eq!(agent["securityContext"]["allowPrivilegeEscalation"], false);
        assert_eq!(
            agent["securityContext"]["capabilities"],
            serde_json::json!({
                "drop": ["ALL"]
            })
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::ENDPOINT),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::TLS_CA),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::K8S_SA_TOKEN_FILE),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SSH_SOCKET_PATH),
            Some(SIDECAR_SSH_SOCKET_FILE)
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET),
            Some(SIDECAR_CONTROL_SOCKET)
        );
        assert_eq!(rendered_env(agent, "OPENSHELL_SUPERVISOR_READY_FILE"), None);
        assert_eq!(rendered_env(agent, "OPENSHELL_ENTRYPOINT_PID_FILE"), None);
        assert_eq!(
            rendered_env(agent, "OPENSHELL_SIDECAR_POLICY_SNAPSHOT_FILE"),
            None
        );
        assert_eq!(
            rendered_env(agent, "OPENSHELL_SIDECAR_PROVIDER_ENV_SNAPSHOT_FILE"),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::PROXY_TLS_DIR),
            Some(SIDECAR_TLS_MOUNT_PATH)
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SANDBOX_UID),
            Some("1500")
        );

        let sidecar = containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_SIDECAR_NAME)
            .unwrap();
        assert_eq!(sidecar["image"], "supervisor-image:latest");
        assert_eq!(sidecar["imagePullPolicy"], "IfNotPresent");
        assert_eq!(
            sidecar["command"],
            serde_json::json!([SUPERVISOR_IMAGE_BINARY_PATH, "--mode=network"])
        );
        assert_eq!(sidecar["securityContext"]["runAsUser"], 2200);
        assert_eq!(sidecar["securityContext"]["runAsGroup"], 1500);
        assert_eq!(sidecar["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            sidecar["securityContext"]["capabilities"],
            serde_json::json!({
                "drop": ["ALL"],
                "add": ["SYS_PTRACE"]
            })
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::ENDPOINT),
            Some("https://openshell-gateway.openshell.svc:8080")
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::SSH_SOCKET_PATH),
            Some(SIDECAR_SSH_SOCKET_FILE)
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET),
            Some(SIDECAR_CONTROL_SOCKET)
        );
        assert_eq!(
            rendered_env(sidecar, "OPENSHELL_SIDECAR_POLICY_SNAPSHOT_FILE"),
            None
        );
        assert_eq!(
            rendered_env(sidecar, "OPENSHELL_SIDECAR_PROVIDER_ENV_SNAPSHOT_FILE"),
            None
        );
        assert_eq!(
            rendered_env(
                sidecar,
                openshell_core::sandbox_env::NETWORK_BINARY_IDENTITY
            ),
            None
        );
        assert_eq!(rendered_env(sidecar, "OPENSHELL_ENTRYPOINT_PID_FILE"), None);
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::PROXY_TLS_DIR),
            Some(SIDECAR_TLS_MOUNT_PATH)
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::TLS_CA),
            Some("/etc/openshell-tls/proxy/client/ca.crt")
        );
        let sidecar_mounts = sidecar["volumeMounts"].as_array().unwrap();
        assert!(
            !sidecar_mounts
                .iter()
                .any(|mount| mount["name"] == "openshell-client-tls"),
            "runtime sidecar should use the init-copied TLS files, not the root-owned Secret mount"
        );
        let agent_mounts = agent["volumeMounts"].as_array().unwrap();
        assert!(
            !agent_mounts
                .iter()
                .any(|mount| mount["name"] == "openshell-sa-token"),
            "agent container must not mount gateway bootstrap token in sidecar topology"
        );
        assert!(
            !agent_mounts
                .iter()
                .any(|mount| mount["name"] == "openshell-client-tls"),
            "agent container must not mount gateway client TLS secret in sidecar topology"
        );
        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        let sa_token = volumes
            .iter()
            .find(|volume| volume["name"] == "openshell-sa-token")
            .unwrap();
        assert_eq!(sa_token["projected"]["defaultMode"], 0o440);
        let client_tls = volumes
            .iter()
            .find(|volume| volume["name"] == "openshell-client-tls")
            .unwrap();
        assert_eq!(client_tls["secret"]["defaultMode"], 0o440);

        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        let network_init = init_containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_INIT_CONTAINER_NAME)
            .unwrap();
        assert_eq!(network_init["image"], "supervisor-image:latest");
        assert_eq!(network_init["imagePullPolicy"], "IfNotPresent");
        assert_eq!(
            network_init["command"],
            serde_json::json!([
                SUPERVISOR_IMAGE_BINARY_PATH,
                "--mode=network-init",
                "--proxy-uid",
                "2200",
                "--proxy-gid",
                "1500",
                "--sidecar-state-dir",
                SIDECAR_STATE_MOUNT_PATH,
                "--sidecar-tls-dir",
                SIDECAR_TLS_MOUNT_PATH
            ])
        );
        assert_eq!(
            network_init["securityContext"]["capabilities"],
            serde_json::json!({
                "drop": ["ALL"],
                "add": ["NET_ADMIN", "NET_RAW", "CHOWN", "FOWNER"]
            })
        );
        let network_init_mounts = network_init["volumeMounts"].as_array().unwrap();
        assert!(network_init_mounts.iter().any(|mount| {
            mount["name"] == "openshell-client-tls"
                && mount["mountPath"] == "/etc/openshell-tls/client"
        }));
    }

    #[test]
    fn sidecar_topology_can_relax_process_binary_aware_network_policy() {
        let params = SandboxPodParams {
            supervisor_topology: SupervisorTopology::Sidecar,
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            supervisor_image: "supervisor-image:latest",
            proxy_uid: 2200,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            process_binary_aware_network_policy: false,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate {
                image: "agent-image:latest".to_string(),
                ..SandboxTemplate::default()
            },
            false,
            &std::collections::HashMap::new(),
            false,
            &params,
        );

        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        let sidecar = containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_SIDECAR_NAME)
            .unwrap();
        assert_eq!(
            sidecar["securityContext"]["capabilities"],
            serde_json::json!({
                "drop": ["ALL"]
            })
        );
        assert_eq!(
            rendered_env(
                sidecar,
                openshell_core::sandbox_env::NETWORK_BINARY_IDENTITY
            ),
            Some("relaxed")
        );
    }

    #[test]
    fn sidecar_topology_adds_shared_state_and_tls_volumes() {
        let params = SandboxPodParams {
            supervisor_topology: SupervisorTopology::Sidecar,
            supervisor_sideload_method: SupervisorSideloadMethod::ImageVolume,
            supervisor_image: "supervisor-image:latest",
            grpc_endpoint: "http://openshell-gateway.openshell.svc:8080",
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            false,
            &params,
        );

        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        assert!(
            volumes
                .iter()
                .any(|volume| volume["name"] == SIDECAR_STATE_VOLUME_NAME)
        );
        assert!(
            volumes
                .iter()
                .any(|volume| volume["name"] == SIDECAR_TLS_VOLUME_NAME)
        );
        assert!(volumes.iter().any(|volume| {
            volume["name"] == SUPERVISOR_VOLUME_NAME && volume["image"].is_object()
        }));

        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        for container_name in ["agent", SUPERVISOR_NETWORK_SIDECAR_NAME] {
            let container = containers
                .iter()
                .find(|container| container["name"] == container_name)
                .unwrap();
            let mounts = container["volumeMounts"].as_array().unwrap();
            assert!(mounts.iter().any(|mount| {
                mount["name"] == SIDECAR_STATE_VOLUME_NAME
                    && mount["mountPath"] == SIDECAR_STATE_MOUNT_PATH
            }));
            assert!(mounts.iter().any(|mount| {
                mount["name"] == SIDECAR_TLS_VOLUME_NAME
                    && mount["mountPath"] == SIDECAR_TLS_MOUNT_PATH
            }));
        }
    }

    #[test]
    fn sidecar_topology_rejects_proxy_uid_matching_sandbox_uid() {
        let params = SandboxPodParams {
            supervisor_topology: SupervisorTopology::Sidecar,
            proxy_uid: 1500,
            sandbox_uid: 1500,
            ..SandboxPodParams::default()
        };

        let err = validate_sidecar_proxy_identity(&params).unwrap_err();
        assert!(matches!(err, KubernetesDriverError::Precondition(_)));
        assert!(err.to_string().contains("proxy_uid"));
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
            serde_json::json!("1")
        );
    }

    #[test]
    fn gpu_count_sandbox_adds_requested_gpu_limit() {
        let pod_template = {
            let params = SandboxPodParams::default();
            let gpu_requirements = GpuResourceRequirements { count: Some(2) };
            sandbox_template_to_k8s_with_gpu_requirements(
                &SandboxTemplate::default(),
                Some(&gpu_requirements),
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"][GPU_RESOURCE_NAME],
            serde_json::json!("2")
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
        assert_eq!(limits[GPU_RESOURCE_NAME], serde_json::json!("1"));
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
            1000, // sandbox_gid
        );

        // Init container
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .expect("initContainers should exist");
        assert_eq!(init_containers.len(), 1);
        assert_eq!(init_containers[0]["name"], WORKSPACE_INIT_CONTAINER_NAME);
        assert_eq!(init_containers[0]["image"], "openshell/sandbox:latest");
        assert_eq!(init_containers[0]["imagePullPolicy"], "IfNotPresent");
        // init container always runs as root to handle PVC root directory permissions
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

        apply_workspace_persistence(
            &mut pod_template,
            "my-custom-image:v2",
            "IfNotPresent",
            1000,
        );

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

        apply_workspace_persistence(&mut pod_template, "img:latest", "Always", 1000);

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
        assert!(
            script.contains("find . -mindepth 1 -maxdepth 1"),
            "init script must archive sandbox contents without the mount root entry"
        );
        assert!(
            script.contains("--no-same-owner")
                && script.contains("--no-same-permissions")
                && script.contains("--touch"),
            "init script must avoid restoring metadata onto the PVC root"
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
