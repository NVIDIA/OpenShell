// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes compute driver.

use crate::config::{
    DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_SANDBOX_UID, DEFAULT_WORKSPACE_STORAGE_SIZE,
    KubernetesComputeConfig, OperatorNamespaceAllowlist, WorkspaceMode, is_dns_1123_label,
    managed_namespace, managed_namespace_prefix, validate_managed_namespace_name,
};
use crate::isolation::{BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, KubernetesProxyPodBoundarySpec};
use crate::proxy_pod::{
    BOUNDARY_CERTIFICATE_PATH, BOUNDARY_CLIENT_CA_PATH, BOUNDARY_CONFIG_PATH,
    BOUNDARY_PRIVATE_KEY_PATH, ProxyPodNames, boundary_service, control_deployment,
    control_egress_policy, generate_proxy_ca_material, sandbox_bootstrap_secret,
    sandbox_owner_reference as proxy_pod_sandbox_owner_reference, supervisor_bootstrap_secret,
    workload_fence,
};
use futures::{Stream, StreamExt, TryStreamExt};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::authentication::v1::{
    TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo,
};
use k8s_openapi::api::core::v1::{
    Event as KubeEventObj, Namespace, Node, PersistentVolumeClaimVolumeSource, Pod, Secret,
    Service, ServiceAccount, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{
    Api, ApiResource, DeleteParams, ListParams, Patch, PatchParams, PostParams, Preconditions,
};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::WatchStreamExt;
use kube::runtime::wait::await_condition;
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_mounts;
use openshell_core::driver_utils::{
    LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAME, LABEL_SANDBOX_WORKSPACE, openshell_sandbox_label_selector,
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
use openshell_isolation_interface::boundary_protocol::{
    BoundaryClientTls, BoundaryServerTls, generate_boundary_mutual_tls_material,
};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use rand::RngCore as _;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{OnceCell, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, KubernetesDriverError>> + Send>>;

const MANAGED_SSH_NETWORK_POLICY_NAME: &str = "openshell-sandbox-ssh";
const AGENT_SANDBOX_TRACE_CONTEXT_ANNOTATION: &str = "opentelemetry.io/trace-context";
const ANNOTATION_PROXY_POD_BOOTSTRAPPING: &str = "openshell.ai/proxy-pod-bootstrapping";
const ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT: &str =
    "openshell.ai/proxy-pod-bootstrap-started-at-ms";
const ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION: &str = "openshell.ai/proxy-pod-bootstrap-operation";
const ANNOTATION_PROXY_POD_GENERATION: &str = "openshell.ai/proxy-pod-generation";
const ANNOTATION_PROXY_POD_READINESS: &str = "openshell.ai/proxy-pod-readiness";
const ANNOTATION_PROXY_POD_WORKLOAD_UID: &str = "openshell.ai/proxy-pod-workload-uid";

#[derive(Debug, thiserror::Error)]
pub enum KubernetesDriverError {
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("sandbox not found")]
    NotFound,
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
            KubeError::Api(api) if api.code == 409 && api.reason == "AlreadyExists" => {
                Self::AlreadyExists
            }
            KubeError::Api(api) if api.code == 404 => Self::NotFound,
            other => Self::Message(other.to_string()),
        }
    }
}

fn is_kube_resource_version_conflict(error: &KubeError) -> bool {
    matches!(error, KubeError::Api(api) if api.code == 409 && api.reason == "Conflict")
}

async fn patch_dynamic_object_with_resource_version_retry(
    api: &Api<DynamicObject>,
    name: &str,
    mut patch_for_resource_version: impl FnMut(&str) -> serde_json::Value,
) -> Result<DynamicObject, KubernetesDriverError> {
    let operation = async {
        loop {
            let current = api.get(name).await?;
            let resource_version = current
                .metadata
                .resource_version
                .as_deref()
                .unwrap_or_default();
            let patch = patch_for_resource_version(resource_version);
            match api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
            {
                Ok(updated) => return Ok(updated),
                Err(error) if is_kube_resource_version_conflict(&error) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
    };
    tokio::time::timeout(KUBE_API_TIMEOUT, operation)
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out after {}s updating Kubernetes resource {name}",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
        .map_err(KubernetesDriverError::from_kube)
}

impl From<KubernetesDriverError> for openshell_core::ComputeDriverError {
    fn from(err: KubernetesDriverError) -> Self {
        match err {
            KubernetesDriverError::AlreadyExists => Self::AlreadyExists,
            KubernetesDriverError::NotFound => Self::NotFound,
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
const PROXY_POD_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const PROXY_POD_FENCE_QUIESCE_WINDOW: Duration = Duration::from_secs(6);
const PROXY_POD_FENCE_QUIESCE_INTERVAL: Duration = Duration::from_secs(2);
/// A pre-created fence may legitimately have no Sandbox CR while create is in flight.
const PROXY_POD_ORPHAN_FENCE_MIN_AGE: Duration = Duration::from_secs(5 * 60);
/// Bound how long a crash-interrupted, fail-closed bootstrap may remain stranded.
const PROXY_POD_BOOTSTRAP_GRACE: Duration = Duration::from_secs(5 * 60);

fn random_proxy_pod_token() -> String {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(token, "{byte:02x}").expect("writing to String cannot fail");
    }
    token
}

/// Kubernetes defaults pod termination to 30 seconds when the pod template
/// omits `terminationGracePeriodSeconds`.
const DEFAULT_POD_TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(30);
const STOP_INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const STOP_MAX_POLL_INTERVAL: Duration = Duration::from_secs(2);

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_VERSION_V1BETA1: &str = "v1beta1";
const SANDBOX_VERSION_V1ALPHA1: &str = "v1alpha1";
const SANDBOX_VERSIONS: &[&str] = &[SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1];
pub const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_POD_NAME_ANNOTATION: &str = "agents.x-k8s.io/pod-name";
const SANDBOX_SUSPENDED_CONDITION: &str = "Suspended";
const SANDBOX_SUSPENDED_POD_NOT_OWNED_REASON: &str = "PodNotOwned";
const SANDBOX_TOKEN_AUDIENCE: &str = "openshell-gateway";
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";

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
    volumes: Vec<KubernetesDriverVolumeConfig>,
}

impl KubernetesSandboxDriverConfig {
    fn from_template(template: &SandboxTemplate) -> Result<Self, String> {
        let Some(config) = template.driver_config.as_ref() else {
            return Ok(Self::default());
        };

        let json = serde_json::Value::Object(struct_to_json_object(config));
        let config: Self = serde_json::from_value(json)
            .map_err(|err| format!("invalid kubernetes driver_config: {err}"))?;
        config
            .validate()
            .map_err(|err| format!("invalid kubernetes driver_config: {err}"))?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        validate_kubernetes_driver_volumes(&self.volumes)?;
        validate_kubernetes_driver_volume_mounts(
            &self.volumes,
            &self.containers.agent.volume_mounts,
        )
    }

    fn has_explicit_sandbox_data_mount(&self) -> bool {
        self.containers.agent.volume_mounts.iter().any(|mount| {
            driver_mounts::path_is_or_under(
                Path::new(&mount.mount_path),
                Path::new(WORKSPACE_MOUNT_PATH),
            )
        })
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
    volume_mounts: Vec<KubernetesDriverVolumeMountConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesContainerResourceConfig {
    requests: BTreeMap<String, String>,
    limits: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesDriverVolumeConfig {
    name: String,
    persistent_volume_claim: KubernetesPersistentVolumeClaimConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesPersistentVolumeClaimConfig {
    claim_name: String,
    read_only: bool,
}

impl Default for KubernetesPersistentVolumeClaimConfig {
    fn default() -> Self {
        Self {
            claim_name: String::new(),
            read_only: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesDriverVolumeMountConfig {
    name: String,
    mount_path: String,
    sub_path: Option<String>,
    read_only: bool,
}

impl Default for KubernetesDriverVolumeMountConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            mount_path: String::new(),
            sub_path: None,
            read_only: true,
        }
    }
}

impl From<&KubernetesDriverVolumeConfig> for Volume {
    fn from(volume: &KubernetesDriverVolumeConfig) -> Self {
        Self {
            name: volume.name.clone(),
            persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                claim_name: volume.persistent_volume_claim.claim_name.clone(),
                read_only: Some(volume.persistent_volume_claim.read_only),
            }),
            ..Default::default()
        }
    }
}

impl From<&KubernetesDriverVolumeMountConfig> for VolumeMount {
    fn from(mount: &KubernetesDriverVolumeMountConfig) -> Self {
        Self {
            name: mount.name.clone(),
            mount_path: mount.mount_path.clone(),
            read_only: Some(mount.read_only),
            sub_path: mount.sub_path.clone(),
            ..Default::default()
        }
    }
}

const CLIENT_TLS_VOLUME_NAME: &str = "openshell-client-tls";
const UPSTREAM_PROXY_AUTH_VOLUME_NAME: &str = "openshell-upstream-proxy-auth";
const SERVICE_ACCOUNT_TOKEN_VOLUME_NAME: &str = "openshell-sa-token";
const SERVICE_ACCOUNT_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/openshell";

const KUBERNETES_DRIVER_RESERVED_VOLUME_NAMES: &[&str] = &[
    CLIENT_TLS_VOLUME_NAME,
    UPSTREAM_PROXY_AUTH_VOLUME_NAME,
    SERVICE_ACCOUNT_TOKEN_VOLUME_NAME,
    SPIFFE_WORKLOAD_API_VOLUME_NAME,
    SANDBOX_RUNTIME_VOLUME_NAME,
    SANDBOX_STATE_VOLUME_NAME,
    SANDBOX_BOOTSTRAP_VOLUME_NAME,
    SANDBOX_POD_IDENTITY_VOLUME_NAME,
    SANDBOX_PROXY_CA_VOLUME_NAME,
    WORKSPACE_VOLUME_NAME,
];

const KUBERNETES_DRIVER_PROTECTED_MOUNT_PATHS: &[&str] = &[SERVICE_ACCOUNT_TOKEN_MOUNT_PATH];

fn validate_kubernetes_driver_volumes(
    volumes: &[KubernetesDriverVolumeConfig],
) -> Result<(), String> {
    let mut names = HashSet::new();
    for volume in volumes {
        validate_kubernetes_dns1123_label(&volume.name, "volumes[].name")?;
        let name = volume.name.as_str();
        if KUBERNETES_DRIVER_RESERVED_VOLUME_NAMES.contains(&name) {
            return Err(format!(
                "volume name '{name}' is reserved for OpenShell-managed volumes"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "duplicate kubernetes driver_config volume '{name}'"
            ));
        }
        validate_kubernetes_dns1123_subdomain(
            &volume.persistent_volume_claim.claim_name,
            "volumes[].persistent_volume_claim.claim_name",
        )?;
    }
    Ok(())
}

fn validate_kubernetes_driver_volume_mounts(
    volumes: &[KubernetesDriverVolumeConfig],
    volume_mounts: &[KubernetesDriverVolumeMountConfig],
) -> Result<(), String> {
    let mut volume_read_only = BTreeMap::new();
    for volume in volumes {
        volume_read_only.insert(
            volume.name.as_str(),
            volume.persistent_volume_claim.read_only,
        );
    }

    let mut mount_paths = HashSet::new();
    for mount in volume_mounts {
        validate_kubernetes_dns1123_label(&mount.name, "containers.agent.volume_mounts[].name")?;
        let volume_name = mount.name.as_str();
        let Some(volume_is_read_only) = volume_read_only.get(volume_name) else {
            return Err(format!(
                "volume mount references unknown kubernetes driver_config volume '{volume_name}'"
            ));
        };
        if *volume_is_read_only && !mount.read_only {
            return Err(format!(
                "volume mount '{volume_name}' cannot set read_only=false because the PVC volume is read_only=true"
            ));
        }

        driver_mounts::validate_container_mount_target(&mount.mount_path)?;
        driver_mounts::validate_workspace_mount_target(
            &mount.mount_path,
            driver_mounts::DEFAULT_WORKSPACE_ROOT,
        )?;
        let normalized_mount_path = driver_mounts::normalize_mount_target(&mount.mount_path);
        if !mount_paths.insert(normalized_mount_path.clone()) {
            return Err(format!(
                "duplicate kubernetes driver_config mount target '{normalized_mount_path}'"
            ));
        }

        if let Some(sub_path) = mount.sub_path.as_ref() {
            driver_mounts::validate_mount_subpath(sub_path)?;
        }
    }
    Ok(())
}

// TODO: replace with an openshell_core Kubernetes-name helper once available.
fn is_dns_subdomain(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(is_dns_1123_label)
}

fn validate_kubernetes_dns1123_label(value: &str, field: &str) -> Result<(), String> {
    if !is_dns_1123_label(value) {
        return Err(format!(
            "{field} must be a DNS-1123 label: use lowercase alphanumeric characters or '-', start and end with an alphanumeric character, and use at most 63 characters"
        ));
    }
    Ok(())
}

fn validate_kubernetes_dns1123_subdomain(value: &str, field: &str) -> Result<(), String> {
    if !is_dns_subdomain(value) {
        return Err(format!(
            "{field} must be a DNS-1123 subdomain: use lowercase alphanumeric characters, '-' or '.', start and end with an alphanumeric character, and use at most 253 characters"
        ));
    }
    Ok(())
}

fn mount_path_conflicts_with_protected_path(mount_path: &str, protected_path: &str) -> bool {
    driver_mounts::path_is_or_under(Path::new(mount_path), Path::new(protected_path))
        || driver_mounts::path_is_or_under(Path::new(protected_path), Path::new(mount_path))
}

fn validate_kubernetes_protected_path_conflicts(
    volume_mounts: &[KubernetesDriverVolumeMountConfig],
    protected_paths: &[&str],
) -> Result<(), String> {
    for mount in volume_mounts {
        let mount_path = mount.mount_path.as_str();
        for protected_path in protected_paths {
            if mount_path_conflicts_with_protected_path(mount_path, protected_path) {
                return Err(format!(
                    "mount path '{mount_path}' conflicts with reserved OpenShell path '{protected_path}'"
                ));
            }
        }
    }
    Ok(())
}

fn kubernetes_driver_volume_to_k8s(volume: &KubernetesDriverVolumeConfig) -> serde_json::Value {
    serde_json::to_value(Volume::from(volume)).expect("Volume serializes to JSON")
}

fn kubernetes_driver_volume_mount_to_k8s(
    mount: &KubernetesDriverVolumeMountConfig,
) -> serde_json::Value {
    serde_json::to_value(VolumeMount::from(mount)).expect("VolumeMount serializes to JSON")
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
const WORKSPACE_INIT_MOUNT_PATH: &str = "/mnt/openshell-workspace";

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
    operator_allowlist: Option<OperatorNamespaceAllowlist>,
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
    #[cfg(test)]
    pub(crate) fn new_for_test(config: KubernetesComputeConfig) -> Self {
        let service = tower::service_fn(|_request: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Empty::<
                bytes::Bytes,
            >::new()))
        });
        let client = Client::new(service, "default");
        Self {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config,
            operator_allowlist: None,
        }
    }

    pub async fn new(
        config: KubernetesComputeConfig,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self, KubernetesDriverError> {
        config
            .validate_workspace_mode()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_provider_spiffe_workload_api_socket_path()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_sandbox_identity_config()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_proxy_uid()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_upstream_proxy_config()
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

        let operator_allowlist = if matches!(config.workspace_mode, WorkspaceMode::Operator) {
            let allowlist = OperatorNamespaceAllowlist::new();

            if let Some(ref label) = config.operator_namespace_label {
                spawn_namespace_label_watcher(
                    watch_client.clone(),
                    label.clone(),
                    allowlist.clone(),
                    shutdown_rx.clone(),
                );
            }

            if let Some(ref path) = config.operator_namespace_file {
                spawn_namespace_file_watcher(path.into(), allowlist.clone(), shutdown_rx.clone());
            }

            Some(allowlist)
        } else {
            None
        };

        let driver = Self {
            client,
            watch_client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config,
            operator_allowlist,
        };

        if driver.workspace_mode() == WorkspaceMode::Shared {
            driver.backfill_gateway_id_labels().await?;
        }

        Ok(driver)
    }

    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, String> {
        Ok(GetCapabilitiesResponse {
            driver_name: "kubernetes".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            gateway_manages_lifecycle: false,
            supports_sandbox_authentication: true,
            driver_reports_runtime_readiness: false,
        })
    }

    /// Authenticate the projected `ServiceAccount` token used by a sandbox pod.
    pub async fn authenticate_sandbox(&self, credential: &str) -> Result<String, tonic::Status> {
        let reviews: Api<TokenReview> = Api::all(self.client.clone());
        let review = TokenReview {
            metadata: ObjectMeta::default(),
            spec: TokenReviewSpec {
                audiences: Some(vec![SANDBOX_TOKEN_AUDIENCE.to_string()]),
                token: Some(credential.to_string()),
            },
            status: None,
        };
        let review = reviews
            .create(&PostParams::default(), &review)
            .await
            .map_err(|error| {
                warn!(%error, "Kubernetes TokenReview failed");
                tonic::Status::internal("Kubernetes TokenReview failed")
            })?;
        let status = review
            .status
            .ok_or_else(|| tonic::Status::internal("TokenReview response missing status"))?;
        let identity = token_review_identity(&status, &self.config.service_account_name)?
            .ok_or_else(|| tonic::Status::unauthenticated("sandbox credential was not accepted"))?;
        if !self.accepts_auth_namespace(&identity.namespace) {
            return Err(tonic::Status::permission_denied(
                "sandbox credential namespace is not accepted by the driver",
            ));
        }

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &identity.namespace);
        let pod = pods
            .get_opt(&identity.pod_name)
            .await
            .map_err(|error| {
                warn!(pod = %identity.pod_name, %error, "failed to read authenticated sandbox pod");
                tonic::Status::internal("failed to read authenticated sandbox pod")
            })?
            .ok_or_else(|| {
                tonic::Status::permission_denied("authenticated sandbox pod not found")
            })?;
        validate_pod_uid(&pod, &identity.pod_uid)?;
        let sandbox_id = pod_sandbox_id(&pod)?;
        let (owner, via_proxy_control) = self
            .resolve_sandbox_owner(&pod, &identity.namespace, &sandbox_id)
            .await?;
        let sandboxes = self
            .supported_agent_sandbox_api(self.client.clone(), &identity.namespace)
            .await
            .map_err(|error| {
                tonic::Status::internal(format!("failed to select Sandbox API: {error}"))
            })?;
        let sandbox = sandboxes.api.get_opt(&owner.name).await.map_err(|error| {
            warn!(sandbox = %owner.name, %error, "failed to read authenticated Sandbox resource");
            tonic::Status::internal("failed to read authenticated Sandbox resource")
        })?.ok_or_else(|| tonic::Status::permission_denied("sandbox owner not found"))?;
        validate_sandbox_owner_identity(&owner, &sandbox_id, &sandbox)?;
        require_proxy_control_authentication(via_proxy_control)?;
        Ok(sandbox_id)
    }

    #[allow(clippy::result_large_err)]
    async fn resolve_sandbox_owner(
        &self,
        pod: &Pod,
        namespace: &str,
        sandbox_id: &str,
    ) -> Result<(OwnerReference, bool), tonic::Status> {
        if let Ok(owner) = sandbox_owner_reference(pod) {
            return Ok((owner.clone(), false));
        }
        validate_proxy_control_labels(pod, sandbox_id)?;
        let names = ProxyPodNames::new(sandbox_id);
        let replica_set_owner = controller_owner_reference(
            pod.metadata.owner_references.as_deref().unwrap_or_default(),
        )
        .filter(|owner| owner.api_version == "apps/v1" && owner.kind == "ReplicaSet")
        .ok_or_else(|| tonic::Status::permission_denied("pod is not controlled by a Sandbox"))?;
        let replica_set = Api::<ReplicaSet>::namespaced(self.client.clone(), namespace)
            .get(&replica_set_owner.name)
            .await
            .map_err(|error| {
                tonic::Status::internal(format!("ReplicaSet lookup failed: {error}"))
            })?;
        validate_owner_uid(&replica_set.metadata.uid, replica_set_owner)?;
        let deployment_owner = controller_owner_reference(
            replica_set
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default(),
        )
        .filter(|owner| owner.api_version == "apps/v1" && owner.kind == "Deployment")
        .ok_or_else(|| {
            tonic::Status::permission_denied("ReplicaSet is not controlled by a Deployment")
        })?;
        if deployment_owner.name != names.control_deployment {
            return Err(tonic::Status::permission_denied(
                "control pod is not owned by the expected proxy-pod Deployment",
            ));
        }
        let deployment = Api::<Deployment>::namespaced(self.client.clone(), namespace)
            .get(&deployment_owner.name)
            .await
            .map_err(|error| {
                tonic::Status::internal(format!("Deployment lookup failed: {error}"))
            })?;
        validate_owner_uid(&deployment.metadata.uid, deployment_owner)?;
        validate_proxy_control_labels_from_metadata(&deployment.metadata, sandbox_id)?;
        let owner = deployment
            .metadata
            .owner_references
            .as_deref()
            .and_then(|owners| {
                owners
                    .iter()
                    .find(|owner| owner.controller == Some(true) && owner.kind == SANDBOX_KIND)
            })
            .filter(|owner| {
                matches!(
                    owner.api_version.as_str(),
                    "agents.x-k8s.io/v1beta1" | "agents.x-k8s.io/v1alpha1"
                )
            })
            .cloned()
            .ok_or_else(|| {
                tonic::Status::permission_denied("Deployment is not controlled by a Sandbox")
            })?;
        Ok((owner, true))
    }

    fn accepts_auth_namespace(&self, namespace: &str) -> bool {
        accepts_auth_namespace(&self.config, self.operator_allowlist.as_ref(), namespace)
    }

    pub fn operator_allowlist(&self) -> Option<&OperatorNamespaceAllowlist> {
        self.operator_allowlist.as_ref()
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

    pub fn workspace_mode(&self) -> WorkspaceMode {
        self.config.workspace_mode
    }

    pub(crate) fn validate_workspace_namespace(
        &self,
        workspace: &str,
    ) -> Result<(), KubernetesDriverError> {
        if self.config.workspace_mode == WorkspaceMode::Managed {
            validate_managed_namespace_name(&self.config.gateway_id, workspace)
                .map_err(KubernetesDriverError::InvalidArgument)?;
        }
        Ok(())
    }

    /// Backfill the `openshell.ai/gateway-id` label on Sandbox CRs that
    /// predate its introduction. Runs once at startup in shared mode so that
    /// label-selector based lookups continue to find legacy resources.
    async fn backfill_gateway_id_labels(&self) -> Result<(), KubernetesDriverError> {
        let sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;

        let selector = openshell_sandbox_label_selector();
        let list = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            sandbox_api
                .api
                .list(&ListParams::default().labels(&selector)),
        )
        .await
        {
            Ok(Ok(list)) => list,
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(
                    "timeout listing Sandbox resources for gateway-id label backfill".to_string(),
                ));
            }
        };

        let gateway_id = &self.config.gateway_id;
        for obj in &list {
            if !gateway_id_label_needs_backfill(obj.metadata.labels.as_ref(), gateway_id) {
                continue;
            }
            let Some(name) = obj.metadata.name.as_deref() else {
                continue;
            };
            let patch = serde_json::json!({
                "metadata": {
                    "labels": {
                        LABEL_GATEWAY_ID: gateway_id
                    }
                }
            });
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                sandbox_api
                    .api
                    .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
            )
            .await
            {
                Ok(Ok(_)) => {
                    info!(sandbox = %name, gateway_id, "backfilled gateway-id label");
                }
                Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
                Err(_) => {
                    return Err(KubernetesDriverError::Message(format!(
                        "timeout backfilling gateway-id label on Sandbox {name}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Ensure the K8s namespace for a workspace exists (managed mode only).
    ///
    /// Idempotent: returns the namespace name whether it was just created or
    /// already existed. Also creates the sandbox `ServiceAccount` in the
    /// namespace.
    ///
    pub async fn ensure_namespace(&self, workspace: &str) -> Result<String, KubernetesDriverError> {
        let ns_name = managed_namespace(&self.config.gateway_id, workspace);
        let ns_api: Api<Namespace> = Api::all(self.client.clone());

        let gateway_ns_annotations = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            ns_api.get(&self.config.namespace),
        )
        .await
        {
            Ok(Ok(ns)) => ns.metadata.annotations.unwrap_or_default(),
            Ok(Err(error)) => return Err(KubernetesDriverError::from_kube(error)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout getting gateway namespace {} for SCC annotations",
                    self.config.namespace
                )));
            }
        };

        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        );
        labels.insert(LABEL_GATEWAY_ID.to_string(), self.config.gateway_id.clone());
        labels.insert(LABEL_SANDBOX_WORKSPACE.to_string(), workspace.to_string());

        let mut annotations = BTreeMap::new();
        for key in [
            crate::config::ANNOTATION_SCC_UID_RANGE,
            crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
        ] {
            if let Some(val) = gateway_ns_annotations.get(key) {
                annotations.insert(key.to_string(), val.clone());
            }
        }

        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(ns_name.clone()),
                labels: Some(labels),
                annotations: if annotations.is_empty() {
                    None
                } else {
                    Some(annotations)
                },
                ..Default::default()
            },
            ..Default::default()
        };

        match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.create(&PostParams::default(), &ns))
            .await
        {
            Ok(Ok(_)) => {
                info!(namespace = %ns_name, workspace = %workspace, "created managed namespace");
            }
            Ok(Err(KubeError::Api(api))) if api.code == 409 => {
                let existing =
                    match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(&ns_name)).await {
                        Ok(Ok(ns)) => ns,
                        Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
                        Err(_) => {
                            return Err(KubernetesDriverError::Message(format!(
                                "timeout reading namespace {ns_name}"
                            )));
                        }
                    };
                if !is_namespace_owned_by_gateway(
                    existing.metadata.labels.as_ref(),
                    &self.config.gateway_id,
                ) {
                    return Err(KubernetesDriverError::Precondition(format!(
                        "namespace {ns_name} exists but is not owned by this gateway"
                    )));
                }
                debug!(namespace = %ns_name, "managed namespace already exists");
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout creating namespace {ns_name}"
                )));
            }
        }

        self.ensure_service_account(&ns_name).await?;
        self.ensure_managed_ssh_network_policy(&ns_name).await?;

        Ok(ns_name)
    }

    async fn ensure_managed_ssh_network_policy(
        &self,
        namespace: &str,
    ) -> Result<(), KubernetesDriverError> {
        if !self.config.managed_ssh_ingress.enabled {
            return Ok(());
        }

        let policy = managed_ssh_network_policy(namespace, &self.config);
        let policy_api: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            policy_api.patch(
                MANAGED_SSH_NETWORK_POLICY_NAME,
                &PatchParams::apply("openshell"),
                &Patch::Apply(&policy),
            ),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(namespace, "applied managed sandbox SSH NetworkPolicy");
                Ok(())
            }
            Ok(Err(error)) => Err(KubernetesDriverError::from_kube(error)),
            Err(_) => Err(KubernetesDriverError::Message(format!(
                "timeout applying SSH NetworkPolicy in {namespace}"
            ))),
        }
    }

    async fn ensure_service_account(&self, namespace: &str) -> Result<(), KubernetesDriverError> {
        let sa_api: Api<ServiceAccount> = Api::namespaced(self.client.clone(), namespace);
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some(self.config.service_account_name.clone()),
                labels: Some(BTreeMap::from([(
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_VALUE.to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        match tokio::time::timeout(KUBE_API_TIMEOUT, sa_api.create(&PostParams::default(), &sa))
            .await
        {
            Ok(Ok(_)) => {
                info!(namespace = %namespace, sa = %self.config.service_account_name, "created service account");
            }
            Ok(Err(KubeError::Api(api))) if api.code == 409 => {}
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout creating service account in {namespace}"
                )));
            }
        }

        Ok(())
    }

    /// Ensure the client TLS Secret exists in `namespace` by copying it from
    /// the gateway's Helm release namespace. Idempotent: creates the Secret on
    /// first call, updates it on subsequent calls to pick up cert rotations.
    /// No-op when `client_tls_secret_name` is empty (TLS disabled).
    async fn ensure_tls_secret(&self, namespace: &str) -> Result<(), KubernetesDriverError> {
        if self.config.client_tls_secret_name.is_empty() {
            return Ok(());
        }

        let source_api: Api<Secret> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let source = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            source_api.get(&self.config.client_tls_secret_name),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!(
                    secret = %self.config.client_tls_secret_name,
                    source_namespace = %self.config.namespace,
                    error = %e,
                    "failed to read source TLS secret"
                );
                return Err(KubernetesDriverError::from_kube(e));
            }
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout reading TLS secret {} from {}",
                    self.config.client_tls_secret_name, self.config.namespace
                )));
            }
        };

        let target_api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let copy = Secret {
            metadata: ObjectMeta {
                name: Some(self.config.client_tls_secret_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(BTreeMap::from([(
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_VALUE.to_string(),
                )])),
                ..Default::default()
            },
            data: source.data,
            type_: source.type_,
            ..Default::default()
        };

        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            target_api.patch(
                &self.config.client_tls_secret_name,
                &PatchParams::apply("openshell"),
                &Patch::Apply(&copy),
            ),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(
                    namespace = %namespace,
                    secret = %self.config.client_tls_secret_name,
                    "applied TLS secret copy"
                );
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout applying TLS secret in {namespace}"
                )));
            }
        }

        Ok(())
    }

    /// Copy the explicitly configured image-pull Secrets into a managed
    /// workspace namespace. Server-side apply refreshes rotated credentials
    /// without forcibly taking fields owned by another manager.
    async fn ensure_image_pull_secrets(
        &self,
        namespace: &str,
    ) -> Result<(), KubernetesDriverError> {
        let source_api: Api<Secret> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let target_api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);

        for secret_name in &self.config.image_pull_secrets {
            let source = match tokio::time::timeout(KUBE_API_TIMEOUT, source_api.get(secret_name))
                .await
            {
                Ok(Ok(secret)) => secret,
                Ok(Err(KubeError::Api(error))) if error.code == 404 => {
                    return Err(KubernetesDriverError::Precondition(format!(
                        "configured image-pull Secret {secret_name} does not exist in source namespace {}",
                        self.config.namespace
                    )));
                }
                Ok(Err(error)) => return Err(KubernetesDriverError::from_kube(error)),
                Err(_) => {
                    return Err(KubernetesDriverError::Message(format!(
                        "timeout reading image-pull Secret {secret_name} from {}",
                        self.config.namespace
                    )));
                }
            };

            let copy = image_pull_secret_copy(secret_name, namespace, source);
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                target_api.patch(
                    secret_name,
                    &PatchParams::apply("openshell"),
                    &Patch::Apply(&copy),
                ),
            )
            .await
            {
                Ok(Ok(_)) => {
                    info!(namespace, secret = %secret_name, "applied image-pull Secret copy");
                }
                Ok(Err(error)) => return Err(KubernetesDriverError::from_kube(error)),
                Err(_) => {
                    return Err(KubernetesDriverError::Message(format!(
                        "timeout applying image-pull Secret {secret_name} in {namespace}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Delete the managed namespace and all its contents (managed mode only).
    /// Called via the `DeleteWorkspace` RPC after workspace deletion.
    /// Kubernetes cascades namespace deletion to all resources within it.
    pub async fn delete_namespace(&self, workspace: &str) -> Result<(), KubernetesDriverError> {
        let ns_name = managed_namespace(&self.config.gateway_id, workspace);
        let ns_api: Api<Namespace> = Api::all(self.client.clone());

        let ns = match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(&ns_name)).await {
            Ok(Ok(ns)) => ns,
            Ok(Err(KubeError::Api(api))) if api.code == 404 => {
                debug!(namespace = %ns_name, "managed namespace already deleted");
                return Ok(());
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout getting namespace {ns_name}"
                )));
            }
        };

        if !is_namespace_owned_by_gateway(ns.metadata.labels.as_ref(), &self.config.gateway_id) {
            debug!(
                namespace = %ns_name,
                "namespace not owned by this gateway, skipping delete"
            );
            return Ok(());
        }

        let namespace_uid = ns.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message(format!(
                "namespace {ns_name} has no UID; refusing an unguarded delete"
            ))
        })?;
        let delete_params = namespace_delete_params(namespace_uid);

        match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.delete(&ns_name, &delete_params)).await
        {
            Ok(Ok(_)) => {
                info!(namespace = %ns_name, workspace = %workspace, "deleted managed namespace");
            }
            Ok(Err(KubeError::Api(api))) if api.code == 404 => {
                debug!(namespace = %ns_name, "managed namespace already deleted");
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout deleting namespace {ns_name}"
                )));
            }
        }

        Ok(())
    }

    fn validate_driver_config_for_sandbox(
        sandbox: &Sandbox,
    ) -> Result<KubernetesSandboxDriverConfig, String> {
        kubernetes_driver_config_for_spec(sandbox.spec.as_ref())
    }

    fn agent_sandbox_api(
        client: Client,
        sandbox_api_version: &str,
        namespace: &str,
    ) -> AgentSandboxApi {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, sandbox_api_version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let api = Api::namespaced_with(client, namespace, &resource);
        AgentSandboxApi { api, resource }
    }

    fn cluster_wide_sandbox_api(client: Client, sandbox_api_version: &str) -> AgentSandboxApi {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, sandbox_api_version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let api = Api::all_with(client, &resource);
        AgentSandboxApi { api, resource }
    }

    async fn supported_agent_sandbox_api(
        &self,
        client: Client,
        namespace: &str,
    ) -> Result<AgentSandboxApi, String> {
        let sandbox_api_version = self.supported_sandbox_api_version(client.clone()).await?;
        Ok(Self::agent_sandbox_api(
            client,
            sandbox_api_version,
            namespace,
        ))
    }

    async fn supported_sandbox_api_for_lookup(
        &self,
        client: Client,
    ) -> Result<AgentSandboxApi, String> {
        let sandbox_api_version = self.supported_sandbox_api_version(client.clone()).await?;
        if self.config.is_multi_namespace() {
            Ok(Self::cluster_wide_sandbox_api(client, sandbox_api_version))
        } else {
            Ok(Self::agent_sandbox_api(
                client,
                sandbox_api_version,
                &self.config.namespace,
            ))
        }
    }

    fn sandbox_lookup_selector(&self, sandbox_id: &str) -> String {
        sandbox_lookup_selector_for(sandbox_id, &self.config.gateway_id)
    }

    fn openshell_sandbox_selector(&self) -> String {
        openshell_sandbox_selector_for(&self.config.gateway_id)
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
            let agent_sandbox_api = Self::agent_sandbox_api(
                client.clone(),
                sandbox_api_version,
                &self.config.namespace,
            );
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

    async fn resolve_sandbox_identity_in_namespace(
        &self,
        namespace: &str,
    ) -> (u32, u32, BTreeMap<String, String>) {
        if self.config.sandbox_uid.is_some() {
            let uid = self.config.resolve_sandbox_uid(None);
            let gid = self.config.resolve_sandbox_gid(uid, None);
            return (uid, gid, BTreeMap::new());
        }

        let ns_api: Api<Namespace> = Api::all(self.client.clone());
        match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(namespace)).await {
            Ok(Ok(ns)) => {
                let anns = ns.metadata.annotations.unwrap_or_default();
                tracing::info!(
                    namespace = %namespace,
                    uid_range = ?anns.get(crate::config::ANNOTATION_SCC_UID_RANGE),
                    sup_groups = ?anns.get(crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS),
                    "Resolved namespace annotations for sandbox identity"
                );
                let uid = self.config.resolve_sandbox_uid(Some(&anns));
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
                    namespace = %namespace,
                    error = %e,
                    "Failed to fetch namespace for SCC annotations, falling back to defaults"
                );
                let uid = DEFAULT_SANDBOX_UID;
                let gid = self.config.resolve_sandbox_gid(uid, None);
                (uid, gid, BTreeMap::new())
            }
            Err(_) => {
                tracing::warn!(
                    namespace = %namespace,
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
        let _ = Self::validate_driver_config_for_sandbox(sandbox)
            .map_err(tonic::Status::invalid_argument)?;
        match self.config.workspace_mode {
            WorkspaceMode::Shared => {
                validate_kube_resource_name_length(&sandbox.workspace, &sandbox.name)?;
            }
            WorkspaceMode::Managed | WorkspaceMode::Operator => {
                validate_kubernetes_dns1123_label(&sandbox.name, "sandbox name")
                    .map_err(tonic::Status::invalid_argument)?;
            }
        }
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

    pub async fn get_sandbox(&self, sandbox_id: &str) -> Result<Option<Sandbox>, String> {
        info!(
            sandbox_id = %sandbox_id,
            workspace_mode = %self.config.workspace_mode,
            "Fetching sandbox from Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let lp = ListParams::default().labels(&selector);
        match tokio::time::timeout(KUBE_API_TIMEOUT, agent_sandbox_api.api.list(&lp)).await {
            Ok(Ok(list)) => {
                let Some(obj) = list.items.into_iter().next() else {
                    debug!(sandbox_id = %sandbox_id, "Sandbox not found in Kubernetes");
                    return Ok(None);
                };
                let ns = obj
                    .metadata
                    .namespace
                    .clone()
                    .unwrap_or_else(|| self.config.namespace.clone());
                Ok(
                    sandbox_from_object_with_proxy_pod_readiness(&self.client, &ns, obj)
                        .await
                        .ok()
                        .map(|(_, sandbox)| sandbox),
                )
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "Failed to fetch sandbox from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox_id,
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
            workspace_mode = %self.config.workspace_mode,
            "Listing sandboxes from Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.openshell_sandbox_selector();
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api
                .api
                .list(&ListParams::default().labels(&selector)),
        )
        .await
        {
            Ok(Ok(list)) => {
                let mut sandboxes = Vec::new();
                for obj in list.items {
                    let name = obj.metadata.name.clone().unwrap_or_default();
                    let ns = obj
                        .metadata
                        .namespace
                        .clone()
                        .unwrap_or_else(|| self.config.namespace.clone());
                    match sandbox_from_object_with_proxy_pod_readiness(&self.client, &ns, obj).await
                    {
                        Ok((_, sandbox)) => sandboxes.push(sandbox),
                        Err(err) => {
                            warn!(object_name = %name, error = %err, "skipping unrecognized Sandbox in list");
                        }
                    }
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
                    error = %err,
                    "Failed to list sandboxes from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
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
    #[tracing::instrument(
        name = "kubernetes.provision",
        skip(self, sandbox),
        fields(
            otel.name = "kubernetes.provision",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            sandbox.name = %sandbox.name,
        )
    )]
    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<(), KubernetesDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = self.create_sandbox_inner(sandbox).await;
        span_status.finish(result)
    }

    #[allow(clippy::similar_names)]
    async fn create_sandbox_inner(&self, sandbox: &Sandbox) -> Result<(), KubernetesDriverError> {
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        validate_gpu_request(gpu_requirements).map_err(|status| {
            KubernetesDriverError::InvalidArgument(status.message().to_string())
        })?;

        // Validate sandbox name against Kubernetes naming requirements
        validate_kubernetes_dns1123_label(&sandbox.name, "sandbox name")
            .map_err(KubernetesDriverError::InvalidArgument)?;

        let name = sandbox.name.as_str();
        let workspace = sandbox.workspace.as_str();
        self.validate_workspace_namespace(workspace)?;

        let target_namespace = match self.config.workspace_mode {
            WorkspaceMode::Shared => self.config.namespace.clone(),
            WorkspaceMode::Managed => {
                let namespace = self.ensure_namespace(workspace).await?;
                self.ensure_image_pull_secrets(&namespace).await?;
                namespace
            }
            WorkspaceMode::Operator => {
                if let Some(ref allowlist) = self.operator_allowlist
                    && !allowlist.contains(workspace)
                {
                    return Err(KubernetesDriverError::Precondition(format!(
                        "workspace '{workspace}' is not in the operator namespace allowlist"
                    )));
                }
                workspace.to_string()
            }
        };

        if self.config.is_multi_namespace() {
            self.ensure_tls_secret(&target_namespace).await?;
        }

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %name,
            namespace = %target_namespace,
            workspace = %workspace,
            workspace_mode = %self.config.workspace_mode,
            "Creating sandbox in Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone(), &target_namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;

        // Resolve sandbox UID/GID from config or OpenShift SCC namespace annotations.
        let (resolved_user_id, resolved_group_id, ns_annotations) = self
            .resolve_sandbox_identity_in_namespace(&target_namespace)
            .await;

        let generation = random_proxy_pod_token();
        let proxy_names = ProxyPodNames::for_generation(&sandbox.id, &generation);
        let params = SandboxPodParams {
            default_image: &self.config.default_image,
            image_pull_policy: &self.config.image_pull_policy,
            image_pull_secrets: &self.config.image_pull_secrets,
            supervisor_image: &self.config.supervisor_image,
            supervisor_image_pull_policy: &self.config.supervisor_image_pull_policy,
            service_account_name: &self.config.service_account_name,
            sandbox_id: &sandbox.id,
            enable_user_namespaces: self.config.enable_user_namespaces,
            workspace_default_storage_size: &self.config.workspace_default_storage_size,
            workspace_storage_class: &self.config.workspace_storage_class,
            default_runtime_class_name: &self.config.default_runtime_class_name,
            sandbox_uid: resolved_user_id,
            sandbox_gid: resolved_group_id,
            boundary_port: self.config.proxy_pod.boundary_port,
            sandbox_secret_name: &proxy_names.sandbox_secret,
        };
        let kube_name = self.config.kube_resource_name(workspace, name);
        let mut data = sandbox_to_k8s_spec(sandbox.spec.as_ref(), &params)
            .map_err(KubernetesDriverError::InvalidArgument)?;
        self.create_proxy_pod_fence(&target_namespace, &proxy_names, sandbox, &kube_name)
            .await?;
        // A missing bootstrap Secret keeps both pods inert as defense in
        // depth, but the CR is also created suspended so the controller
        // never races an unfenced workload into execution.
        if agent_sandbox_api.resource.version == SANDBOX_VERSION_V1ALPHA1 {
            data["spec"]["replicas"] = serde_json::json!(0);
        } else {
            data["spec"]["operatingMode"] = serde_json::json!("Suspended");
        }
        let mut obj = DynamicObject::new(&kube_name, &agent_sandbox_api.resource);
        let mut annotations = sandbox_annotations(sandbox);
        add_trace_context_annotation(&mut annotations);
        annotations.insert(
            ANNOTATION_PROXY_POD_BOOTSTRAPPING.to_string(),
            "true".to_string(),
        );
        annotations.insert(
            ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT.to_string(),
            openshell_core::time::now_ms().to_string(),
        );
        annotations.insert(
            ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION.to_string(),
            "create".to_string(),
        );
        annotations.insert(
            ANNOTATION_PROXY_POD_GENERATION.to_string(),
            generation.clone(),
        );
        for key in [
            crate::config::ANNOTATION_SCC_UID_RANGE,
            crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
        ] {
            if let Some(v) = ns_annotations.get(key) {
                annotations.insert(key.to_string(), v.clone());
            }
        }
        obj.metadata = ObjectMeta {
            name: Some(kube_name.clone()),
            namespace: Some(target_namespace.clone()),
            labels: Some(sandbox_labels(sandbox, Some(&self.config.gateway_id))),
            annotations: Some(annotations),
            ..Default::default()
        };

        obj.data = data;
        let created = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api.api.create(&PostParams::default(), &obj),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "Sandbox created in Kubernetes successfully"
                );
                result
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    error = %err,
                    "Failed to create sandbox in Kubernetes"
                );
                return Err(KubernetesDriverError::from_kube(err));
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out creating sandbox in Kubernetes"
                );
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                )));
            }
        };
        if let Err(error) = self
            .create_proxy_pod_companions(
                sandbox,
                &target_namespace,
                &kube_name,
                &agent_sandbox_api,
                &created,
                &proxy_names,
                &generation,
                resolved_user_id,
                resolved_group_id,
            )
            .await
        {
            warn!(sandbox_id = %sandbox.id, %error, "proxy-pod provisioning failed; rolling back Sandbox CR");
            let _ = agent_sandbox_api
                .api
                .delete(&kube_name, &DeleteParams::default())
                .await;
            return Err(error);
        }
        Ok(())
    }

    async fn create_proxy_pod_fence(
        &self,
        namespace: &str,
        names: &ProxyPodNames,
        sandbox: &Sandbox,
        workload_pod_name: &str,
    ) -> Result<(), KubernetesDriverError> {
        let mut policy = workload_fence(
            namespace,
            names,
            &sandbox.id,
            self.config.proxy_pod.boundary_port,
        )
        .workload_policy;
        let labels = policy.metadata.labels.get_or_insert_default();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        );
        labels.insert(LABEL_GATEWAY_ID.to_string(), self.config.gateway_id.clone());
        labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
        labels.insert(
            "openshell.ai/component".to_string(),
            "boundary-workload-fence".to_string(),
        );
        policy.metadata.annotations.get_or_insert_default().insert(
            "openshell.ai/workload-pod-name".to_string(),
            workload_pod_name.to_string(),
        );
        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        create_or_validate_proxy_pod_fence(&policies, &policy).await
    }

    async fn wait_for_bootstrap_workload_pod(
        &self,
        pods: &Api<Pod>,
        pod_name: &str,
        sandbox_uid: &str,
    ) -> Result<Pod, KubernetesDriverError> {
        let deadline = tokio::time::Instant::now() + KUBE_API_TIMEOUT;
        loop {
            match pods.get_opt(pod_name).await {
                Ok(Some(pod)) => {
                    let owned = pod
                        .metadata
                        .owner_references
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .any(|owner| {
                            owner.controller == Some(true)
                                && owner.kind == SANDBOX_KIND
                                && owner.uid == sandbox_uid
                        });
                    if !owned {
                        return Err(KubernetesDriverError::Precondition(format!(
                            "workload Pod {pod_name} is not controlled by the created Sandbox UID"
                        )));
                    }
                    return Ok(pod);
                }
                Ok(None) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(None) => {
                    return Err(KubernetesDriverError::Message(format!(
                        "timed out waiting for gated workload Pod {pod_name}"
                    )));
                }
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_capability_free_workload_pod(
        pod: &Pod,
        sandbox_resource_uid: &str,
        sandbox_id: &str,
        uid: u32,
        gid: u32,
        sandbox_secret_name: &str,
    ) -> Result<(), KubernetesDriverError> {
        let fail = |message: &str| {
            KubernetesDriverError::Precondition(format!(
                "admitted workload Pod does not preserve capability-free isolation: {message}"
            ))
        };
        if pod.metadata.uid.as_deref().is_none() {
            return Err(fail("missing Pod UID"));
        }
        let owner_matches = pod
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|owner| {
                owner.controller == Some(true)
                    && owner.kind == SANDBOX_KIND
                    && owner.uid == sandbox_resource_uid
            });
        if !owner_matches {
            return Err(fail("Sandbox owner UID changed"));
        }
        let labels = pod
            .metadata
            .labels
            .as_ref()
            .ok_or_else(|| fail("missing labels"))?;
        let expected_pair = crate::proxy_pod::pair_label_value(sandbox_id);
        if labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str) != Some("workload")
            || labels.get(BOUNDARY_PAIR_LABEL).map(String::as_str) != Some(expected_pair.as_str())
        {
            return Err(fail("pair labels changed"));
        }
        let spec = pod.spec.as_ref().ok_or_else(|| fail("missing Pod spec"))?;
        if spec.host_network == Some(true)
            || spec.host_pid == Some(true)
            || spec.host_ipc == Some(true)
            || spec.share_process_namespace == Some(true)
            || spec.automount_service_account_token != Some(false)
        {
            return Err(fail("host namespaces or ServiceAccount token enabled"));
        }
        let projected_service_account_token = spec
            .volumes
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|volume| volume.projected.as_ref())
            .flat_map(|projected| projected.sources.as_deref().unwrap_or_default())
            .any(|source| source.service_account_token.is_some());
        if projected_service_account_token {
            return Err(fail(
                "workload Pod must not receive a projected ServiceAccount token",
            ));
        }
        if spec.restart_policy.as_deref() != Some("Never")
            || spec.dns_policy.as_deref() != Some("None")
            || spec
                .dns_config
                .as_ref()
                .is_none_or(|dns| dns.nameservers.as_deref() != Some(&["127.0.0.53".to_string()]))
        {
            return Err(fail("restart or DNS posture changed"));
        }
        if !spec
            .scheduling_gates
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|gate| gate.name == SANDBOX_BOOTSTRAP_SCHEDULING_GATE)
        {
            return Err(fail("bootstrap scheduling gate missing"));
        }
        let security = spec
            .security_context
            .as_ref()
            .ok_or_else(|| fail("missing Pod security context"))?;
        if security.run_as_user != Some(i64::from(uid))
            || security.run_as_group != Some(i64::from(gid))
            || security.run_as_non_root != Some(true)
            || security.fs_group != Some(i64::from(gid))
            || security
                .supplemental_groups
                .as_deref()
                .is_some_and(|groups| !groups.is_empty())
            || security
                .seccomp_profile
                .as_ref()
                .is_none_or(|profile| profile.type_ != "RuntimeDefault")
        {
            return Err(fail("numeric identity, groups, or seccomp profile changed"));
        }
        let pod_json = serde_json::to_value(pod)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        if let Some(policy) = pod_json.pointer("/spec/securityContext/supplementalGroupsPolicy")
            && policy != &serde_json::json!("Strict")
        {
            return Err(fail("supplementalGroupsPolicy is not Strict"));
        }
        if pod_json
            .pointer("/spec/securityContext/supplementalGroupsPolicy")
            .is_none()
        {
            tracing::warn!(
                pod = pod.metadata.name.as_deref().unwrap_or("<unknown>"),
                "Kubernetes omitted supplementalGroupsPolicy; exact runtime groups remain enforced by boundary confirmation"
            );
        }
        let unprivileged_port_sysctl = pod_json
            .pointer("/spec/securityContext/sysctls")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|sysctls| {
                sysctls.iter().any(|sysctl| {
                    sysctl.get("name").and_then(serde_json::Value::as_str)
                        == Some("net.ipv4.ip_unprivileged_port_start")
                        && sysctl.get("value").and_then(serde_json::Value::as_str) == Some("0")
                })
            });
        if !unprivileged_port_sysctl {
            return Err(fail("safe unprivileged-port sysctl changed"));
        }
        let check_container = |container: &k8s_openapi::api::core::v1::Container,
                               name: &str|
         -> Result<(), KubernetesDriverError> {
            let context = container
                .security_context
                .as_ref()
                .ok_or_else(|| fail(&format!("{name} has no security context")))?;
            let drops_all = context
                .capabilities
                .as_ref()
                .and_then(|capabilities| capabilities.drop.as_deref())
                .is_some_and(|drops| drops.iter().any(|capability| capability == "ALL"));
            let adds_none = context
                .capabilities
                .as_ref()
                .and_then(|capabilities| capabilities.add.as_deref())
                .is_none_or(<[String]>::is_empty);
            if context.run_as_user != Some(i64::from(uid))
                || context.run_as_group != Some(i64::from(gid))
                || context.run_as_non_root != Some(true)
                || context.allow_privilege_escalation != Some(false)
                || !drops_all
                || !adds_none
            {
                return Err(fail(&format!("{name} security context changed")));
            }
            Ok(())
        };
        let agent = spec
            .containers
            .iter()
            .find(|container| container.name == "agent")
            .ok_or_else(|| fail("agent container missing"))?;
        check_container(agent, "agent")?;
        let bootstrap = spec
            .init_containers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|container| container.name == "openshell-sandbox-bootstrap")
            .ok_or_else(|| fail("trusted bootstrap init container missing"))?;
        check_container(bootstrap, "bootstrap init container")?;
        let mounts_volume = |container: &k8s_openapi::api::core::v1::Container,
                             volume_name: &str| {
            container
                .volume_mounts
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|mount| mount.name == volume_name)
        };
        if mounts_volume(agent, SANDBOX_BOOTSTRAP_VOLUME_NAME)
            || !mounts_volume(bootstrap, SANDBOX_BOOTSTRAP_VOLUME_NAME)
        {
            return Err(fail(
                "bootstrap Secret must be mounted only by the trusted init container",
            ));
        }
        let secret_matches = spec
            .volumes
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|volume| {
                volume.name == SANDBOX_BOOTSTRAP_VOLUME_NAME
                    && volume
                        .secret
                        .as_ref()
                        .and_then(|secret| secret.secret_name.as_deref())
                        == Some(sandbox_secret_name)
            });
        if !secret_matches {
            return Err(fail("generation-specific sandbox Secret changed"));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    async fn create_proxy_pod_companions(
        &self,
        sandbox: &Sandbox,
        namespace: &str,
        cr_name: &str,
        sandbox_api: &AgentSandboxApi,
        sandbox_cr: &DynamicObject,
        names: &ProxyPodNames,
        generation: &str,
        agent_uid: u32,
        agent_gid: u32,
    ) -> Result<(), KubernetesDriverError> {
        let cr_uid = sandbox_cr.metadata.uid.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("created Sandbox CR has no UID".to_string())
        })?;
        let namespace_uid = Api::<Namespace>::all(self.client.clone())
            .get(namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .metadata
            .uid
            .ok_or_else(|| {
                KubernetesDriverError::Message("sandbox namespace has no UID".to_string())
            })?;
        let dependent_owner = proxy_pod_sandbox_owner_reference(
            cr_name,
            cr_uid,
            &sandbox_api.resource.api_version,
            false,
        );
        let controller_owner = proxy_pod_sandbox_owner_reference(
            cr_name,
            cr_uid,
            &sandbox_api.resource.api_version,
            true,
        );

        let services: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let service = services
            .create(
                &PostParams::default(),
                &boundary_service(
                    namespace,
                    names,
                    &sandbox.id,
                    self.config.proxy_pod.boundary_port,
                    dependent_owner.clone(),
                ),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let service_ip: std::net::IpAddr = service
            .spec
            .and_then(|spec| spec.cluster_ip)
            .filter(|ip| ip != "None")
            .ok_or_else(|| {
                KubernetesDriverError::Message("boundary Service has no ClusterIP".to_string())
            })?
            .parse()
            .map_err(|error| {
                KubernetesDriverError::Message(format!(
                    "invalid boundary Service ClusterIP: {error}"
                ))
            })?;

        let main_process_spec = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
            sandbox.spec.as_ref(),
        )
        .map_err(|error| {
            KubernetesDriverError::InvalidArgument(format!("encode main process spec: {error}"))
        })?;
        let log_level = openshell_core::driver_utils::sandbox_log_level(sandbox, "info");
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let deployment = deployments
            .create(
                &PostParams::default(),
                &control_deployment(
                    namespace,
                    names,
                    &sandbox.id,
                    &sandbox.name,
                    &self.config.gateway_id,
                    &self.config.supervisor_image,
                    &self.config.supervisor_image_pull_policy,
                    &self.config.service_account_name,
                    agent_uid,
                    agent_gid,
                    &self.config.image_pull_secrets,
                    &self.config.grpc_endpoint,
                    &self.config.client_tls_secret_name,
                    &main_process_spec,
                    &log_level,
                    self.config.effective_sa_token_ttl_secs(),
                    self.config.https_proxy.as_deref(),
                    self.config.no_proxy.as_deref(),
                    self.config
                        .proxy_auth_secret_name
                        .as_deref()
                        .zip(self.config.proxy_auth_secret_key.as_deref()),
                    self.config.proxy_auth_allow_insecure == Some(true),
                    self.config.proxy_connect_by_hostname == Some(true),
                    self.config.provider_spiffe_enabled().then_some(
                        self.config
                            .provider_spiffe_workload_api_socket_path
                            .as_str(),
                    ),
                    controller_owner,
                ),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let deployment_uid = deployment.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("control Deployment has no UID".to_string())
        })?;

        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        policies
            .create(
                &PostParams::default(),
                &control_egress_policy(namespace, names, &sandbox.id, dependent_owner.clone()),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let fence = policies
            .get(&names.workload_policy)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let fence_uid = fence.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("workload NetworkPolicy has no UID".to_string())
        })?;
        let fence_resource_version = fence.metadata.resource_version.ok_or_else(|| {
            KubernetesDriverError::Message(
                "workload NetworkPolicy has no resourceVersion".to_string(),
            )
        })?;

        // Release the Sandbox CR only far enough for the controller to create
        // the workload Pod. The Pod remains unschedulable because its template
        // carries the OpenShell scheduling gate and references a Secret that
        // does not exist yet.
        patch_dynamic_object_with_resource_version_retry(&sandbox_api.api, cr_name, |version| {
            sandbox_operating_state_patch(&sandbox_api.resource.version, version, true)
        })
        .await?;

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let workload_pod = self
            .wait_for_bootstrap_workload_pod(&pods, cr_name, cr_uid)
            .await?;
        Self::validate_capability_free_workload_pod(
            &workload_pod,
            cr_uid,
            &sandbox.id,
            agent_uid,
            agent_gid,
            &names.sandbox_secret,
        )?;
        let workload_pod_uid =
            workload_pod.metadata.uid.clone().ok_or_else(|| {
                KubernetesDriverError::Message("workload Pod has no UID".to_string())
            })?;
        let workload_pod_name = workload_pod.metadata.name.clone().ok_or_else(|| {
            KubernetesDriverError::Message("workload Pod has no name".to_string())
        })?;
        patch_dynamic_object_with_resource_version_retry(&sandbox_api.api, cr_name, |version| {
            serde_json::json!({
                "metadata": {
                    "resourceVersion": version,
                    "annotations": {
                        ANNOTATION_PROXY_POD_WORKLOAD_UID: workload_pod_uid.clone(),
                    }
                }
            })
        })
        .await?;

        let bootstrap_token = random_proxy_pod_token();
        let mut child_env = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .map_or_else(std::collections::HashMap::new, |template| {
                template.environment.clone()
            });
        if let Some(spec) = sandbox.spec.as_ref() {
            child_env.extend(spec.environment.clone());
        }
        child_env.retain(|name, _| !name.starts_with("OPENSHELL_"));
        let host_gateway_ip = self.config.host_gateway_ip.parse().ok();
        let tls = generate_boundary_mutual_tls_material()
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let proxy_ca = generate_proxy_ca_material().map_err(KubernetesDriverError::Message)?;
        let workload_identity = ResolvedWorkloadIdentity::new(
            agent_uid,
            agent_gid,
            Vec::new(),
            "kubernetes-config".to_string(),
            format!("sandbox:{cr_uid}"),
        )
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let provisioned = KubernetesProxyPodBoundarySpec {
            boundary_id: sandbox.id.clone(),
            bootstrap_token,
            generation: generation.to_string(),
            session_epoch: random_proxy_pod_token(),
            namespace_uid,
            sandbox_resource_uid: cr_uid.to_string(),
            workload_pod_uid: workload_pod_uid.clone(),
            workload_pod_uid_path: PathBuf::from(SANDBOX_POD_UID_PATH),
            control_deployment_uid: deployment_uid.clone(),
            egress_policy_uid: fence_uid,
            egress_policy_resource_version: fence_resource_version,
            boundary_listener: std::net::SocketAddr::new(
                if service_ip.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                },
                self.config.proxy_pod.boundary_port,
            ),
            control_address: std::net::SocketAddr::new(
                service_ip,
                self.config.proxy_pod.boundary_port,
            ),
            sandbox_tls: BoundaryServerTls {
                certificate_chain_path: PathBuf::from(BOUNDARY_CERTIFICATE_PATH),
                private_key_path: PathBuf::from(BOUNDARY_PRIVATE_KEY_PATH),
                client_ca_certificate_path: PathBuf::from(BOUNDARY_CLIENT_CA_PATH),
            },
            supervisor_tls: BoundaryClientTls {
                server_name: tls.server_name.clone(),
                ca_certificate_pem: tls.ca_certificate_pem.clone(),
                certificate_chain_pem: tls.supervisor_certificate_pem.clone(),
                private_key_pem: tls.supervisor_private_key_pem.clone(),
            },
            host_gateway_ip,
            workload_identity,
            child_env,
        }
        .provision();
        let descriptor = provisioned
            .topology
            .descriptor(crate::isolation::BACKEND_NAME)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let sandbox_secret = sandbox_bootstrap_secret(
            namespace,
            names,
            &sandbox.id,
            provisioned
                .boundary_config
                .encode()
                .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
            tls.sandbox_certificate_pem.into_bytes(),
            tls.sandbox_private_key_pem.into_bytes(),
            tls.ca_certificate_pem.into_bytes(),
            OwnerReference {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
                name: workload_pod_name.clone(),
                uid: workload_pod_uid,
                controller: Some(false),
                block_owner_deletion: Some(false),
            },
        );
        let supervisor_secret = supervisor_bootstrap_secret(
            namespace,
            names,
            &sandbox.id,
            descriptor.payload,
            proxy_ca.certificate_pem.into_bytes(),
            proxy_ca.private_key_pem.into_bytes(),
            OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: names.control_deployment.clone(),
                uid: deployment_uid,
                controller: Some(false),
                block_owner_deletion: Some(false),
            },
        );
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        secrets
            .create(&PostParams::default(), &sandbox_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        secrets
            .create(&PostParams::default(), &supervisor_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;

        deployments
            .patch(
                &names.control_deployment,
                &PatchParams::default(),
                &Patch::Merge(&serde_json::json!({"spec": {"replicas": 1}})),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        pods.patch(
            &workload_pod_name,
            &PatchParams::default(),
            &Patch::Merge(&serde_json::json!({"spec": {"schedulingGates": []}})),
        )
        .await
        .map_err(KubernetesDriverError::from_kube)?;
        spawn_proxy_pod_bootstrap_completion(
            deployments.clone(),
            sandbox_api.api.clone(),
            names.control_deployment.clone(),
            cr_name.to_string(),
            Some(cr_uid.to_string()),
        );
        // Return while the CR remains explicitly bootstrapping. The gateway
        // can now commit the sandbox configuration required by a policy-less
        // control process without deadlocking behind this driver call. Only
        // boundary PID 1 is running at this point; the agent process cannot
        // start until control attaches and confirms enforcement. Reconcile
        // removes the marker after the control Deployment becomes Available.
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    async fn install_proxy_pod_generation(
        &self,
        namespace: &str,
        cr_name: &str,
        sandbox_api: &AgentSandboxApi,
        sandbox_id: &str,
        cr_uid: &str,
        names: &ProxyPodNames,
        generation: &str,
        deployment_uid: &str,
        agent_uid: u32,
        agent_gid: u32,
        child_env: std::collections::HashMap<String, String>,
    ) -> Result<(), KubernetesDriverError> {
        let namespace_uid = Api::<Namespace>::all(self.client.clone())
            .get(namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .metadata
            .uid
            .ok_or_else(|| {
                KubernetesDriverError::Message("sandbox namespace has no UID".to_string())
            })?;
        let services = Api::<Service>::namespaced(self.client.clone(), namespace);
        let service_ip: std::net::IpAddr = services
            .get(&names.boundary_service)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .spec
            .and_then(|spec| spec.cluster_ip)
            .filter(|ip| ip != "None")
            .ok_or_else(|| {
                KubernetesDriverError::Message("boundary Service has no ClusterIP".to_string())
            })?
            .parse()
            .map_err(|error| {
                KubernetesDriverError::Message(format!(
                    "invalid boundary Service ClusterIP: {error}"
                ))
            })?;
        let policies = Api::<NetworkPolicy>::namespaced(self.client.clone(), namespace);
        let fence = policies
            .get(&names.workload_policy)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let fence_uid = fence.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("workload NetworkPolicy has no UID".to_string())
        })?;
        let fence_resource_version = fence.metadata.resource_version.ok_or_else(|| {
            KubernetesDriverError::Message(
                "workload NetworkPolicy has no resourceVersion".to_string(),
            )
        })?;

        let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let workload_pod = self
            .wait_for_bootstrap_workload_pod(&pods, cr_name, cr_uid)
            .await?;
        Self::validate_capability_free_workload_pod(
            &workload_pod,
            cr_uid,
            sandbox_id,
            agent_uid,
            agent_gid,
            &names.sandbox_secret,
        )?;
        let workload_pod_uid =
            workload_pod.metadata.uid.clone().ok_or_else(|| {
                KubernetesDriverError::Message("workload Pod has no UID".to_string())
            })?;
        let workload_pod_name = workload_pod.metadata.name.clone().ok_or_else(|| {
            KubernetesDriverError::Message("workload Pod has no name".to_string())
        })?;
        patch_dynamic_object_with_resource_version_retry(&sandbox_api.api, cr_name, |version| {
            serde_json::json!({
                "metadata": {
                    "resourceVersion": version,
                    "annotations": {
                        ANNOTATION_PROXY_POD_WORKLOAD_UID: workload_pod_uid.clone(),
                    }
                }
            })
        })
        .await?;

        let tls = generate_boundary_mutual_tls_material()
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let proxy_ca = generate_proxy_ca_material().map_err(KubernetesDriverError::Message)?;
        let workload_identity = ResolvedWorkloadIdentity::new(
            agent_uid,
            agent_gid,
            Vec::new(),
            "kubernetes-config".to_string(),
            format!("sandbox:{cr_uid}"),
        )
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let provisioned = KubernetesProxyPodBoundarySpec {
            boundary_id: sandbox_id.to_string(),
            bootstrap_token: random_proxy_pod_token(),
            generation: generation.to_string(),
            session_epoch: random_proxy_pod_token(),
            namespace_uid,
            sandbox_resource_uid: cr_uid.to_string(),
            workload_pod_uid: workload_pod_uid.clone(),
            workload_pod_uid_path: PathBuf::from(SANDBOX_POD_UID_PATH),
            control_deployment_uid: deployment_uid.to_string(),
            egress_policy_uid: fence_uid,
            egress_policy_resource_version: fence_resource_version,
            boundary_listener: std::net::SocketAddr::new(
                if service_ip.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                },
                self.config.proxy_pod.boundary_port,
            ),
            control_address: std::net::SocketAddr::new(
                service_ip,
                self.config.proxy_pod.boundary_port,
            ),
            sandbox_tls: BoundaryServerTls {
                certificate_chain_path: PathBuf::from(BOUNDARY_CERTIFICATE_PATH),
                private_key_path: PathBuf::from(BOUNDARY_PRIVATE_KEY_PATH),
                client_ca_certificate_path: PathBuf::from(BOUNDARY_CLIENT_CA_PATH),
            },
            supervisor_tls: BoundaryClientTls {
                server_name: tls.server_name.clone(),
                ca_certificate_pem: tls.ca_certificate_pem.clone(),
                certificate_chain_pem: tls.supervisor_certificate_pem.clone(),
                private_key_pem: tls.supervisor_private_key_pem.clone(),
            },
            host_gateway_ip: self.config.host_gateway_ip.parse().ok(),
            workload_identity,
            child_env,
        }
        .provision();
        let descriptor = provisioned
            .topology
            .descriptor(crate::isolation::BACKEND_NAME)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let sandbox_secret = sandbox_bootstrap_secret(
            namespace,
            names,
            sandbox_id,
            provisioned
                .boundary_config
                .encode()
                .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
            tls.sandbox_certificate_pem.into_bytes(),
            tls.sandbox_private_key_pem.into_bytes(),
            tls.ca_certificate_pem.into_bytes(),
            OwnerReference {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
                name: workload_pod_name.clone(),
                uid: workload_pod_uid,
                controller: Some(false),
                block_owner_deletion: Some(false),
            },
        );
        let supervisor_secret = supervisor_bootstrap_secret(
            namespace,
            names,
            sandbox_id,
            descriptor.payload,
            proxy_ca.certificate_pem.into_bytes(),
            proxy_ca.private_key_pem.into_bytes(),
            OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: names.control_deployment.clone(),
                uid: deployment_uid.to_string(),
                controller: Some(false),
                block_owner_deletion: Some(false),
            },
        );
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        secrets
            .create(&PostParams::default(), &sandbox_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        secrets
            .create(&PostParams::default(), &supervisor_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;

        let deployments = Api::<Deployment>::namespaced(self.client.clone(), namespace);
        deployments
            .patch(
                &names.control_deployment,
                &PatchParams::default(),
                &Patch::Merge(&serde_json::json!({"spec": {"replicas": 1}})),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        pods.patch(
            &workload_pod_name,
            &PatchParams::default(),
            &Patch::Merge(&serde_json::json!({"spec": {"schedulingGates": []}})),
        )
        .await
        .map_err(KubernetesDriverError::from_kube)?;
        spawn_proxy_pod_bootstrap_completion(
            deployments,
            sandbox_api.api.clone(),
            names.control_deployment.clone(),
            cr_name.to_string(),
            Some(cr_uid.to_string()),
        );
        Ok(())
    }

    #[tracing::instrument(
        name = "kubernetes.stop_sandbox",
        skip(self),
        fields(
            otel.name = "kubernetes.stop_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn stop_sandbox(&self, sandbox_id: &str) -> Result<(), KubernetesDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = self.stop_sandbox_inner(sandbox_id).await;
        span_status.finish(result)
    }

    async fn stop_sandbox_inner(&self, sandbox_id: &str) -> Result<(), KubernetesDriverError> {
        let (agent_sandbox_api, kube_name, pod_name, namespace, stop_timeout) = self
            .patch_sandbox_operating_state(sandbox_id, false)
            .await?;
        let pod_api = Api::<Pod>::namespaced(self.client.clone(), &namespace);

        let deadline = tokio::time::Instant::now() + stop_timeout;
        let mut poll_interval = STOP_INITIAL_POLL_INTERVAL;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes sandbox to stop",
                    stop_timeout.as_secs()
                )));
            }
            let request_timeout = KUBE_API_TIMEOUT.min(deadline.saturating_duration_since(now));
            let object = tokio::time::timeout(
                request_timeout,
                agent_sandbox_api.api.get(&kube_name),
            )
            .await
            .map_err(|_| {
                KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes API while checking sandbox stop",
                    request_timeout.as_secs()
                ))
            })?
            .map_err(KubernetesDriverError::from_kube)?;
            if let Some(error) = kubernetes_sandbox_stop_failure(&object) {
                return Err(KubernetesDriverError::Message(error));
            }
            let pod_is_gone = kubernetes_sandbox_pod_is_gone(&pod_api, &pod_name, deadline)
                .await
                .map_err(KubernetesDriverError::Message)?;
            let stop_is_complete = kubernetes_sandbox_stop_is_complete(
                &agent_sandbox_api.resource.version,
                &object,
                pod_is_gone,
            );
            if stop_is_complete {
                if let Err(error) = self
                    .scale_proxy_pod_control(sandbox_id, &namespace, 0)
                    .await
                {
                    // The workload is already stopped. Treat a stranded
                    // control replica as resource drift and let periodic
                    // reconciliation retry rather than failing the stop.
                    warn!(sandbox_id, %error, "failed to scale stopped proxy-pod control Deployment to zero");
                }
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes sandbox to stop",
                    stop_timeout.as_secs()
                )));
            }
            tokio::time::sleep(poll_interval.min(deadline.saturating_duration_since(now))).await;
            poll_interval = next_stop_poll_interval(poll_interval);
        }
    }

    #[tracing::instrument(
        name = "kubernetes.start_sandbox",
        skip(self),
        fields(
            otel.name = "kubernetes.start_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn start_sandbox(&self, sandbox_id: &str) -> Result<(), KubernetesDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = Box::pin(self.start_proxy_pod_generation(sandbox_id)).await;
        span_status.finish(result)
    }

    #[allow(clippy::similar_names)]
    async fn start_proxy_pod_generation(
        &self,
        sandbox_id: &str,
    ) -> Result<(), KubernetesDriverError> {
        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let mut objects = lookup_api
            .api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .items;
        let object = objects.pop().ok_or(KubernetesDriverError::NotFound)?;
        if proxy_pod_bootstrap_in_progress(&object) {
            return Err(KubernetesDriverError::Precondition(
                "sandbox bootstrap has not completed; wait for reconciliation or recreate the sandbox"
                    .to_string(),
            ));
        }
        let namespace = object
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.config.namespace.clone());
        let cr_name = object.metadata.name.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no name".to_string())
        })?;
        let cr_uid = object.metadata.uid.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no UID".to_string())
        })?;
        let sandbox_api = Self::agent_sandbox_api(
            self.client.clone(),
            &lookup_api.resource.version,
            &namespace,
        );
        let pods = Api::<Pod>::namespaced(self.client.clone(), &namespace);
        if pods
            .get_opt(cr_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .is_some()
        {
            return Err(KubernetesDriverError::Precondition(
                "cannot rotate a running workload Pod; stop the sandbox first".to_string(),
            ));
        }

        let generation = random_proxy_pod_token();
        let names = ProxyPodNames::for_generation(sandbox_id, &generation);
        self.create_proxy_pod_fence(
            &namespace,
            &names,
            &Sandbox {
                id: sandbox_id.to_string(),
                ..Default::default()
            },
            cr_name,
        )
        .await?;
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &namespace);
        let old_deployment = deployments
            .get(&names.control_deployment)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let old_uid = old_deployment.metadata.uid.clone().ok_or_else(|| {
            KubernetesDriverError::Message("control Deployment has no UID".to_string())
        })?;
        let owner_references = old_deployment.metadata.owner_references.clone();
        let labels = old_deployment.metadata.labels.clone();
        let annotations = old_deployment.metadata.annotations.clone();
        let mut deployment_spec = old_deployment.spec.ok_or_else(|| {
            KubernetesDriverError::Message("control Deployment has no spec".to_string())
        })?;
        deployment_spec.replicas = Some(0);
        let bootstrap_volume = deployment_spec
            .template
            .spec
            .as_mut()
            .and_then(|spec| spec.volumes.as_mut())
            .and_then(|volumes| volumes.iter_mut().find(|volume| volume.name == "bootstrap"))
            .and_then(|volume| volume.secret.as_mut())
            .ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "control Deployment is missing its immutable bootstrap Secret volume"
                        .to_string(),
                )
            })?;
        bootstrap_volume.secret_name = Some(names.supervisor_secret.clone());
        deployments
            .delete(
                &names.control_deployment,
                // A stop only requests scale-to-zero; the old ReplicaSet and
                // Pod can still be terminating when start arrives. Foreground
                // deletion makes the Deployment disappear only after those
                // dependents are gone, so an old supervisor cannot reconnect
                // and supersede the replacement generation's session.
                &DeleteParams::foreground().preconditions(Preconditions {
                    uid: Some(old_uid),
                    resource_version: None,
                }),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let deadline = tokio::time::Instant::now() + KUBE_API_TIMEOUT;
        loop {
            if deployments
                .get_opt(&names.control_deployment)
                .await
                .map_err(KubernetesDriverError::from_kube)?
                .is_none()
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(KubernetesDriverError::Message(
                    "timed out waiting for old control Deployment deletion".to_string(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let replacement = Deployment {
            metadata: ObjectMeta {
                name: Some(names.control_deployment.clone()),
                namespace: Some(namespace.clone()),
                owner_references,
                labels,
                annotations,
                ..Default::default()
            },
            spec: Some(deployment_spec),
            status: None,
        };
        let replacement = deployments
            .create(&PostParams::default(), &replacement)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let deployment_uid = replacement.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("replacement control Deployment has no UID".to_string())
        })?;

        let mut volumes = object
            .data
            .pointer("/spec/podTemplate/spec/volumes")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "Sandbox pod template has no volume list".to_string(),
                )
            })?;
        let sandbox_secret = volumes
            .iter_mut()
            .find(|volume| {
                volume.get("name").and_then(serde_json::Value::as_str)
                    == Some(SANDBOX_BOOTSTRAP_VOLUME_NAME)
            })
            .and_then(|volume| volume.get_mut("secret"))
            .ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "Sandbox pod template is missing its bootstrap Secret volume".to_string(),
                )
            })?;
        sandbox_secret["secretName"] = serde_json::json!(names.sandbox_secret);
        patch_dynamic_object_with_resource_version_retry(&sandbox_api.api, cr_name, |version| {
            let mut running_patch =
                sandbox_operating_state_patch(&sandbox_api.resource.version, version, true);
            running_patch["metadata"]["annotations"] = serde_json::json!({
                ANNOTATION_PROXY_POD_BOOTSTRAPPING: "true",
                ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT: openshell_core::time::now_ms().to_string(),
                ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION: "restart",
                ANNOTATION_PROXY_POD_GENERATION: generation,
            });
            running_patch["spec"]["podTemplate"]["spec"]["volumes"] =
                serde_json::Value::Array(volumes.clone());
            running_patch
        })
        .await?;

        let (agent_uid, agent_gid, _) =
            self.resolve_sandbox_identity_in_namespace(&namespace).await;
        let child_env = child_environment_from_sandbox_object(&object);
        self.install_proxy_pod_generation(
            &namespace,
            cr_name,
            &sandbox_api,
            sandbox_id,
            cr_uid,
            &names,
            &generation,
            &deployment_uid,
            agent_uid,
            agent_gid,
            child_env,
        )
        .await
    }

    async fn patch_sandbox_operating_state(
        &self,
        sandbox_id: &str,
        running: bool,
    ) -> Result<(AgentSandboxApi, String, String, String, Duration), KubernetesDriverError> {
        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let list = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            lookup_api
                .api
                .list(&ListParams::default().labels(&selector)),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
        .map_err(KubernetesDriverError::from_kube)?;
        let object = list
            .items
            .into_iter()
            .next()
            .ok_or(KubernetesDriverError::NotFound)?;
        let namespace = object
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.config.namespace.clone());
        let agent_sandbox_api = Self::agent_sandbox_api(
            self.client.clone(),
            &lookup_api.resource.version,
            &namespace,
        );
        let stop_timeout = kubernetes_sandbox_stop_timeout(&object);
        let kube_name = object.metadata.name.clone().ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no name".to_string())
        })?;
        let pod_name = object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
            .cloned()
            .unwrap_or_else(|| kube_name.clone());
        if running {
            if proxy_pod_bootstrap_in_progress(&object) {
                return Err(KubernetesDriverError::Precondition(
                    "proxy-pod bootstrap has not completed; wait for reconciliation or recreate the sandbox"
                        .to_string(),
                ));
            }
            self.scale_proxy_pod_control(sandbox_id, &namespace, 1)
                .await?;
        }
        patch_dynamic_object_with_resource_version_retry(
            &agent_sandbox_api.api,
            &kube_name,
            |version| {
                sandbox_operating_state_patch(&agent_sandbox_api.resource.version, version, running)
            },
        )
        .await?;

        info!(
            sandbox_id,
            sandbox_api_version = %agent_sandbox_api.resource.version,
            running,
            "Updated Kubernetes sandbox operating state"
        );
        Ok((
            agent_sandbox_api,
            kube_name,
            pod_name,
            namespace,
            stop_timeout,
        ))
    }

    async fn scale_proxy_pod_control(
        &self,
        sandbox_id: &str,
        namespace: &str,
        replicas: i32,
    ) -> Result<(), KubernetesDriverError> {
        let names = ProxyPodNames::new(sandbox_id);
        Api::<Deployment>::namespaced(self.client.clone(), namespace)
            .patch(
                &names.control_deployment,
                &PatchParams::default(),
                &Patch::Merge(&serde_json::json!({"spec": {"replicas": replicas}})),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        Ok(())
    }

    #[tracing::instrument(
        name = "kubernetes.delete_sandbox",
        skip(self),
        fields(
            otel.name = "kubernetes.delete_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn delete_sandbox(&self, sandbox_id: &str) -> Result<bool, String> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = self.delete_sandbox_inner(sandbox_id).await;
        span_status.finish(result)
    }

    async fn delete_sandbox_inner(&self, sandbox_id: &str) -> Result<bool, String> {
        info!(
            sandbox_id = %sandbox_id,
            workspace_mode = %self.config.workspace_mode,
            "Deleting sandbox from Kubernetes"
        );

        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let lp = ListParams::default().labels(&selector);
        let (kube_name, obj_namespace, _workspace, preconditions, pod_name) =
            match tokio::time::timeout(KUBE_API_TIMEOUT, lookup_api.api.list(&lp)).await {
                Ok(Ok(list)) => {
                    if let Some(obj) = list.items.into_iter().next() {
                        match obj.metadata.name.clone() {
                            Some(name) => {
                                let ns = obj
                                    .metadata
                                    .namespace
                                    .clone()
                                    .unwrap_or_else(|| self.config.namespace.clone());
                                let ws = obj
                                    .metadata
                                    .labels
                                    .as_ref()
                                    .and_then(|l| l.get(LABEL_SANDBOX_WORKSPACE).cloned())
                                    .unwrap_or_default();
                                let pc = Preconditions {
                                    uid: obj.metadata.uid,
                                    resource_version: obj.metadata.resource_version,
                                };
                                let pod_name = obj
                                    .metadata
                                    .annotations
                                    .as_ref()
                                    .and_then(|annotations| {
                                        annotations.get(SANDBOX_POD_NAME_ANNOTATION)
                                    })
                                    .cloned()
                                    .unwrap_or_else(|| name.clone());
                                (name, ns, ws, pc, pod_name)
                            }
                            None => return Ok(false),
                        }
                    } else {
                        debug!(sandbox_id = %sandbox_id, "Sandbox not found in Kubernetes (already deleted)");
                        return Ok(false);
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "Failed to list sandbox for deletion from Kubernetes"
                    );
                    return Err(err.to_string());
                }
                Err(_elapsed) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                        "Timed out listing sandbox for deletion from Kubernetes"
                    );
                    return Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ));
                }
            };

        let delete_api = self
            .supported_agent_sandbox_api(self.client.clone(), &obj_namespace)
            .await?;
        let dp = DeleteParams::default().preconditions(preconditions);
        match tokio::time::timeout(KUBE_API_TIMEOUT, delete_api.api.delete(&kube_name, &dp)).await {
            Ok(Ok(_response)) => {
                info!(sandbox_id = %sandbox_id, namespace = %obj_namespace, "Sandbox deleted from Kubernetes");
                {
                    let pod_api = Api::<Pod>::namespaced(self.client.clone(), &obj_namespace);
                    let deadline = tokio::time::Instant::now()
                        + DEFAULT_POD_TERMINATION_GRACE_PERIOD
                        + KUBE_API_TIMEOUT;
                    loop {
                        match kubernetes_sandbox_pod_is_gone(&pod_api, &pod_name, deadline).await {
                            Ok(true) => break,
                            Ok(false) if tokio::time::Instant::now() < deadline => {
                                tokio::time::sleep(STOP_INITIAL_POLL_INTERVAL).await;
                            }
                            Ok(false) | Err(_) => {
                                warn!(
                                    sandbox_id,
                                    "retaining proxy-pod workload fence because workload Pod deletion was not confirmed"
                                );
                                return Ok(true);
                            }
                        }
                    }
                    // API acceptance of DELETE does not mean the CR is gone.
                    // Keep the unowned fence while finalizers can still leave
                    // the controller able to reconcile a workload Pod.
                    if !matches!(
                        tokio::time::timeout(KUBE_API_TIMEOUT, delete_api.api.get(&kube_name))
                            .await,
                        Ok(Err(KubeError::Api(kube::core::ErrorResponse {
                            code: 404,
                            ..
                        })))
                    ) {
                        warn!(
                            sandbox_id,
                            "retaining proxy-pod workload fence because Sandbox CR deletion was not confirmed"
                        );
                        return Ok(true);
                    }
                    let quiesce_deadline =
                        tokio::time::Instant::now() + PROXY_POD_FENCE_QUIESCE_WINDOW;
                    while tokio::time::Instant::now() < quiesce_deadline {
                        tokio::time::sleep(PROXY_POD_FENCE_QUIESCE_INTERVAL).await;
                        let cr_is_gone = matches!(
                            tokio::time::timeout(KUBE_API_TIMEOUT, delete_api.api.get(&kube_name))
                                .await,
                            Ok(Err(KubeError::Api(kube::core::ErrorResponse {
                                code: 404,
                                ..
                            })))
                        );
                        let pod_is_gone = kubernetes_sandbox_pod_is_gone(
                            &pod_api,
                            &pod_name,
                            tokio::time::Instant::now() + KUBE_API_TIMEOUT,
                        )
                        .await
                        .unwrap_or(false);
                        if !cr_is_gone || !pod_is_gone {
                            warn!(
                                sandbox_id,
                                "retaining proxy-pod workload fence because deletion did not remain quiescent"
                            );
                            return Ok(true);
                        }
                    }
                    let names = ProxyPodNames::new(sandbox_id);
                    let policies: Api<NetworkPolicy> =
                        Api::namespaced(self.client.clone(), &obj_namespace);
                    match policies
                        .delete(&names.workload_policy, &DeleteParams::default())
                        .await
                    {
                        Ok(_)
                        | Err(KubeError::Api(kube::core::ErrorResponse { code: 404, .. })) => {}
                        Err(error) => {
                            warn!(sandbox_id, %error, "failed to delete proxy-pod workload fence; reconciliation will retry");
                        }
                    }
                }
                Ok(true)
            }
            Ok(Err(KubeError::Api(err))) if err.code == 404 || err.code == 409 => {
                debug!(sandbox_id = %sandbox_id, "Sandbox not found in Kubernetes (already deleted or replaced)");
                Ok(false)
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "Failed to delete sandbox from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox_id,
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

    pub async fn sandbox_exists(&self, sandbox_id: &str) -> Result<bool, String> {
        let agent_sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let lp = ListParams::default().labels(&selector);
        match tokio::time::timeout(KUBE_API_TIMEOUT, agent_sandbox_api.api.list(&lp)).await {
            Ok(Ok(list)) => Ok(!list.items.is_empty()),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    /// Repair lifecycle drift and reap unowned workload fences while the
    /// gateway's sandbox watch is alive. Bootstrap material is immutable and
    /// intentionally not read by the gateway, so this pass only repairs state
    /// that can be proven from the Sandbox CR and named companion objects.
    async fn reconcile_proxy_pod_resources(&self) {
        let lookup_api = match self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
        {
            Ok(api) => api,
            Err(error) => {
                warn!(%error, "skipping proxy-pod reconciliation: Sandbox API unavailable");
                return;
            }
        };
        let list = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            lookup_api
                .api
                .list(&ListParams::default().labels(&self.openshell_sandbox_selector())),
        )
        .await
        {
            Ok(Ok(list)) => list,
            Ok(Err(error)) => {
                warn!(%error, "skipping proxy-pod reconciliation: Sandbox list failed");
                return;
            }
            Err(_) => {
                warn!("skipping proxy-pod reconciliation: Sandbox list timed out");
                return;
            }
        };

        let mut live_ids = HashSet::new();
        for object in list.items {
            let Ok(sandbox_id) = sandbox_id_from_object(&object) else {
                continue;
            };
            live_ids.insert(sandbox_id.clone());
            let namespace = object
                .metadata
                .namespace
                .as_deref()
                .unwrap_or(&self.config.namespace);
            let cr_name = object.metadata.name.as_deref().unwrap_or_default();
            let names = ProxyPodNames::new(&sandbox_id);
            let policies = Api::<NetworkPolicy>::namespaced(self.client.clone(), namespace);
            let fence_was_missing = matches!(
                tokio::time::timeout(KUBE_API_TIMEOUT, policies.get_opt(&names.workload_policy))
                    .await,
                Ok(Ok(None))
            );
            let sandbox = Sandbox {
                id: sandbox_id.clone(),
                ..Default::default()
            };
            match self
                .create_proxy_pod_fence(namespace, &names, &sandbox, cr_name)
                .await
            {
                Ok(()) => {}
                Err(KubernetesDriverError::Precondition(error)) => {
                    warn!(sandbox_id, %error, "proxy-pod workload fence is altered; suspending workload");
                    self.suspend_proxy_pod_after_dependency_failure(&lookup_api, &object)
                        .await;
                    continue;
                }
                Err(error) => {
                    warn!(sandbox_id, %error, "could not verify proxy-pod workload fence; reconciliation will retry");
                    continue;
                }
            }
            if fence_was_missing {
                // Recreating the deny-all fence closes direct egress first;
                // suspend next because the immutable boundary descriptor names
                // the prior policy UID/resourceVersion and can no longer be
                // re-confirmed after a control restart.
                warn!(
                    sandbox_id,
                    "recreated missing proxy-pod workload fence; suspending stale boundary"
                );
                self.suspend_proxy_pod_after_dependency_failure(&lookup_api, &object)
                    .await;
                continue;
            }
            if proxy_pod_bootstrap_in_progress(&object) {
                if proxy_pod_control_availability(&self.client, namespace, &sandbox_id).await
                    == ProxyPodControlAvailability::Available
                    && proxy_pod_runtime_is_ready(&object)
                {
                    self.complete_proxy_pod_bootstrap(&lookup_api, &object)
                        .await;
                } else {
                    self.reap_stale_proxy_pod_bootstrap(&lookup_api, &object)
                        .await;
                }
                continue;
            }
            let desired = desired_proxy_pod_control_replicas(&object);
            if desired > 0 {
                match proxy_pod_workload_generation_matches(
                    &self.client,
                    namespace,
                    cr_name,
                    &object,
                )
                .await
                {
                    ProxyPodControlAvailability::Available => {}
                    ProxyPodControlAvailability::Unavailable => {
                        warn!(
                            sandbox_id,
                            "proxy-pod workload generation changed; suspending stale boundary"
                        );
                        self.suspend_proxy_pod_after_dependency_failure(&lookup_api, &object)
                            .await;
                        continue;
                    }
                    ProxyPodControlAvailability::Unknown => {
                        warn!(
                            sandbox_id,
                            "could not verify proxy-pod workload generation; reconciliation will retry"
                        );
                        continue;
                    }
                }
            }
            match self
                .reconcile_proxy_pod_control_replicas(&sandbox_id, namespace, desired)
                .await
            {
                Ok(()) => {}
                Err(KubernetesDriverError::Precondition(error)) => {
                    warn!(sandbox_id, %error, "proxy-pod companion is missing; suspending workload");
                    self.suspend_proxy_pod_after_dependency_failure(&lookup_api, &object)
                        .await;
                }
                Err(error) => {
                    warn!(sandbox_id, %error, "failed to reconcile proxy-pod control Deployment");
                }
            }
            let availability =
                proxy_pod_control_availability(&self.client, namespace, &sandbox_id).await;
            self.publish_proxy_pod_readiness_transition(&lookup_api, &object, availability)
                .await;
        }

        self.reap_orphaned_proxy_pod_fences(&live_ids).await;
    }

    async fn publish_proxy_pod_readiness_transition(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
        availability: ProxyPodControlAvailability,
    ) {
        let state = match availability {
            ProxyPodControlAvailability::Available => "ready",
            ProxyPodControlAvailability::Unavailable => "unavailable",
            ProxyPodControlAvailability::Unknown => return,
        };
        if object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(ANNOTATION_PROXY_POD_READINESS))
            .is_some_and(|current| current == state)
        {
            return;
        }
        let (Some(name), Some(resource_version)) = (
            object.metadata.name.as_deref(),
            object.metadata.resource_version.as_deref(),
        ) else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = proxy_pod_readiness_transition_patch(resource_version, state);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(sandbox = name, %error, "proxy-pod readiness transition publication raced; reconciliation will retry");
            }
            Err(_) => {
                warn!(
                    sandbox = name,
                    "timed out publishing proxy-pod readiness transition"
                );
            }
        }
    }

    async fn suspend_proxy_pod_after_dependency_failure(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
    ) {
        let Some(name) = object.metadata.name.as_deref() else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = sandbox_operating_state_patch(
            &lookup_api.resource.version,
            object
                .metadata
                .resource_version
                .as_deref()
                .unwrap_or_default(),
            false,
        );
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                warn!(sandbox = name, %error, "failed to suspend proxy-pod after fence failure");
            }
            Err(error) => {
                warn!(sandbox = name, %error, "timed out suspending proxy-pod after fence failure");
            }
        }
    }

    async fn reap_stale_proxy_pod_bootstrap(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
    ) {
        if !proxy_pod_bootstrap_is_stale(object, SystemTime::now(), PROXY_POD_BOOTSTRAP_GRACE) {
            return;
        }
        if proxy_pod_bootstrap_operation(object) != Some("create") {
            warn!(
                sandbox = object.metadata.name.as_deref().unwrap_or("<unknown>"),
                "suspending stale proxy-pod restart bootstrap"
            );
            self.suspend_proxy_pod_after_dependency_failure(lookup_api, object)
                .await;
            return;
        }
        let (Some(name), Some(uid), Some(resource_version)) = (
            object.metadata.name.as_deref(),
            object.metadata.uid.clone(),
            object.metadata.resource_version.clone(),
        ) else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let params = DeleteParams::default().preconditions(Preconditions {
            uid: Some(uid),
            resource_version: Some(resource_version),
        });
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.api.delete(name, &params)).await {
            Ok(Ok(_)) => warn!(
                sandbox = name,
                "rolled back stale fail-closed proxy-pod bootstrap"
            ),
            Ok(Err(KubeError::Api(error))) if error.code == 404 || error.code == 409 => {}
            Ok(Err(error)) => {
                warn!(sandbox = name, %error, "failed to roll back stale proxy-pod bootstrap");
            }
            Err(_) => {
                warn!(
                    sandbox = name,
                    "timed out rolling back stale proxy-pod bootstrap"
                );
            }
        }
    }

    async fn complete_proxy_pod_bootstrap(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
    ) {
        let (Some(name), Some(resource_version)) = (
            object.metadata.name.as_deref(),
            object.metadata.resource_version.as_deref(),
        ) else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = proxy_pod_bootstrap_completion_patch(resource_version);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(sandbox = name, %error, "proxy-pod bootstrap completion raced; reconciliation will retry");
            }
            Err(_) => warn!(sandbox = name, "timed out completing proxy-pod bootstrap"),
        }
    }

    async fn reconcile_proxy_pod_control_replicas(
        &self,
        sandbox_id: &str,
        namespace: &str,
        desired: i32,
    ) -> Result<(), KubernetesDriverError> {
        let names = ProxyPodNames::new(sandbox_id);
        let services = Api::<Service>::namespaced(self.client.clone(), namespace);
        let service_exists =
            tokio::time::timeout(KUBE_API_TIMEOUT, services.get_opt(&names.boundary_service))
                .await
                .map_err(|_| {
                    KubernetesDriverError::Message(
                        "timed out reading proxy-pod boundary Service".to_string(),
                    )
                })?
                .map_err(KubernetesDriverError::from_kube)?
                .is_some();
        if !service_exists {
            return Err(KubernetesDriverError::Precondition(format!(
                "proxy-pod boundary Service {} is missing and its allocated address cannot be safely reconstructed",
                names.boundary_service
            )));
        }
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), namespace);
        let deployment = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            deployments.get_opt(&names.control_deployment),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(
                "timed out reading proxy-pod control Deployment".to_string(),
            )
        })?
        .map_err(KubernetesDriverError::from_kube)?
        .ok_or_else(|| {
            KubernetesDriverError::Precondition(format!(
                "proxy-pod control Deployment {} is missing and cannot be safely reconstructed from the Sandbox CR",
                names.control_deployment
            ))
        })?;
        if deployment.spec.as_ref().and_then(|spec| spec.replicas) == Some(desired) {
            return Ok(());
        }
        self.scale_proxy_pod_control(sandbox_id, namespace, desired)
            .await
    }

    async fn reap_orphaned_proxy_pod_fences(&self, live_ids: &HashSet<String>) {
        let policies: Api<NetworkPolicy> = if self.config.is_multi_namespace() {
            Api::all(self.client.clone())
        } else {
            Api::namespaced(self.client.clone(), &self.config.namespace)
        };
        let selector = format!(
            "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_GATEWAY_ID}={},openshell.ai/component=boundary-workload-fence",
            self.config.gateway_id
        );
        let list = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            policies.list(&ListParams::default().labels(&selector)),
        )
        .await
        {
            Ok(Ok(list)) => list,
            Ok(Err(error)) => {
                warn!(%error, "failed to list proxy-pod workload fences for orphan cleanup");
                return;
            }
            Err(_) => {
                warn!("timed out listing proxy-pod workload fences for orphan cleanup");
                return;
            }
        };
        for policy in list.items {
            let sandbox_id = policy
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
                .cloned()
                .unwrap_or_default();
            if sandbox_id.is_empty() || live_ids.contains(&sandbox_id) {
                continue;
            }
            if !proxy_pod_fence_is_old_enough(&policy, SystemTime::now()) {
                debug!(
                    sandbox_id,
                    "retaining young proxy-pod fence while Sandbox creation may be in flight"
                );
                continue;
            }
            // Reconfirm against the API after the two list snapshots. A sandbox
            // created between them must never lose the fence that precedes its CR.
            if self.sandbox_exists(&sandbox_id).await != Ok(false) {
                continue;
            }
            let Some(namespace) = policy.metadata.namespace.as_deref() else {
                continue;
            };
            let Some(pod_name) = policy
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get("openshell.ai/workload-pod-name"))
            else {
                warn!(
                    sandbox_id,
                    "retaining orphaned proxy-pod fence without workload Pod annotation"
                );
                continue;
            };
            let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
            if !matches!(
                tokio::time::timeout(KUBE_API_TIMEOUT, pods.get_opt(pod_name)).await,
                Ok(Ok(None))
            ) {
                debug!(
                    sandbox_id,
                    pod_name, "retaining proxy-pod fence until workload Pod absence is confirmed"
                );
                continue;
            }
            let quiesce_deadline = tokio::time::Instant::now() + PROXY_POD_FENCE_QUIESCE_WINDOW;
            let mut quiescent = true;
            while tokio::time::Instant::now() < quiesce_deadline {
                tokio::time::sleep(PROXY_POD_FENCE_QUIESCE_INTERVAL).await;
                if self.sandbox_exists(&sandbox_id).await != Ok(false)
                    || !matches!(
                        tokio::time::timeout(KUBE_API_TIMEOUT, pods.get_opt(pod_name)).await,
                        Ok(Ok(None))
                    )
                {
                    quiescent = false;
                    break;
                }
            }
            if !quiescent {
                debug!(
                    sandbox_id,
                    pod_name, "retaining orphaned proxy-pod fence after quiescence recheck"
                );
                continue;
            }
            let Some(name) = policy.metadata.name.as_deref() else {
                continue;
            };
            let scoped = Api::<NetworkPolicy>::namespaced(self.client.clone(), namespace);
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                scoped.delete(name, &DeleteParams::default()),
            )
            .await
            {
                Ok(Ok(_) | Err(KubeError::Api(kube::core::ErrorResponse { code: 404, .. }))) => {
                    info!(
                        sandbox_id,
                        policy = name,
                        "reaped orphaned proxy-pod workload fence"
                    );
                }
                Ok(Err(error)) => {
                    warn!(sandbox_id, policy = name, %error, "failed to reap orphaned proxy-pod workload fence");
                }
                Err(_) => warn!(
                    sandbox_id,
                    policy = name,
                    "timed out reaping orphaned proxy-pod workload fence"
                ),
            }
        }
    }

    fn spawn_proxy_pod_periodic_reconcile(
        &self,
        tx: mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
    ) {
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROXY_POD_RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        driver.reconcile_proxy_pod_resources().await;
                        if let Ok(sandboxes) = driver.list_sandboxes().await {
                            for sandbox in sandboxes {
                                if tx.send(Ok(WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent { sandbox: Some(sandbox) },
                                    )),
                                })).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    () = tx.closed() => return,
                }
            }
        });
    }

    // Kept `async` to match the gRPC handler signature in `grpc.rs`, which awaits this method.
    #[allow(clippy::unused_async)]
    pub async fn watch_sandboxes(&self) -> Result<WatchStream, String> {
        self.reconcile_proxy_pod_resources().await;
        if self.config.is_multi_namespace() {
            self.watch_sandboxes_cluster_wide().await
        } else {
            self.watch_sandboxes_single_namespace().await
        }
    }

    async fn watch_sandboxes_single_namespace(&self) -> Result<WatchStream, String> {
        let namespace = self.config.namespace.clone();
        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.watch_client.clone(), &self.config.namespace)
            .await?;
        let event_api: Api<KubeEventObj> = Api::namespaced(self.watch_client.clone(), &namespace);
        let watcher_config = watcher::Config::default().labels(&openshell_sandbox_label_selector());
        let mut sandbox_stream = recovering_watcher_stream(
            watcher::watcher(agent_sandbox_api.api, watcher_config),
            "sandbox-resource",
        )
        .boxed();
        let mut event_stream = recovering_watcher_stream(
            watcher::watcher(event_api, watcher::Config::default()),
            "kubernetes-event",
        )
        .boxed();
        let (tx, rx) = mpsc::channel(256);
        self.spawn_proxy_pod_periodic_reconcile(tx.clone());
        let readiness_client = self.watch_client.clone();

        tokio::spawn(async move {
            let mut sandbox_name_to_id = std::collections::HashMap::<String, String>::new();
            let mut agent_pod_to_id = std::collections::HashMap::<String, String>::new();

            loop {
                tokio::select! {
                    event = sandbox_stream.next() => match event {
                        Some(Event::Applied(obj)) => {
                            if let Ok((kube_name, sandbox)) = sandbox_from_object_with_proxy_pod_readiness(&readiness_client, &namespace, obj).await {
                                update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &kube_name, &sandbox);
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
                        Some(Event::Deleted(obj)) => {
                            if is_openshell_managed(&obj)
                                && let Ok(sandbox_id) = sandbox_id_from_object(&obj)
                            {
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
                        Some(Event::Restarted(objs)) => {
                            for obj in objs {
                                if let Ok((kube_name, sandbox)) = sandbox_from_object_with_proxy_pod_readiness(&readiness_client, &namespace, obj).await {
                                    update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &kube_name, &sandbox);
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
                        None => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "sandbox watcher stream ended unexpectedly".to_string()
                            ))).await;
                            break;
                        }
                    },
                    event = event_stream.next() => match event {
                        Some(Event::Applied(obj)) => {
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
                        Some(Event::Deleted(_)) => {}
                        Some(Event::Restarted(_)) => {
                            debug!(namespace = %namespace, "Kubernetes event watcher restarted");
                        }
                        None => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "kubernetes event watcher stream ended".to_string()
                            ))).await;
                            break;
                        }
                    },
                    () = tx.closed() => break,
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn watch_sandboxes_cluster_wide(&self) -> Result<WatchStream, String> {
        let sandbox_api_version = self
            .supported_sandbox_api_version(self.watch_client.clone())
            .await?;
        let cluster_api =
            Self::cluster_wide_sandbox_api(self.watch_client.clone(), sandbox_api_version);
        let selector = self.openshell_sandbox_selector();
        let watcher_config = watcher::Config::default().labels(&selector);
        let sandbox_stream = recovering_watcher_stream(
            watcher::watcher(cluster_api.api, watcher_config),
            "sandbox-resource",
        )
        .boxed();

        Ok(cluster_wide_watch_stream(
            sandbox_stream,
            self.config.namespace.clone(),
            self.watch_client.clone(),
            self.clone(),
        ))
    }
}

fn proxy_pod_bootstrap_completion_patch(resource_version: &str) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                ANNOTATION_PROXY_POD_BOOTSTRAPPING: serde_json::Value::Null,
                ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT: serde_json::Value::Null,
                ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION: serde_json::Value::Null,
                ANNOTATION_PROXY_POD_READINESS: "ready",
            }
        }
    })
}

fn spawn_proxy_pod_bootstrap_completion(
    deployments: Api<Deployment>,
    sandboxes: Api<DynamicObject>,
    deployment_name: String,
    sandbox_name: String,
    expected_sandbox_uid: Option<String>,
) {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + PROXY_POD_BOOTSTRAP_GRACE;
        let available = |deployment: Option<&Deployment>| {
            deployment.is_some_and(|deployment| {
                proxy_pod_control_availability_from_deployment(deployment)
                    == ProxyPodControlAvailability::Available
            })
        };
        match tokio::time::timeout_at(
            deadline,
            await_condition(deployments, &deployment_name, available),
        )
        .await
        {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(error)) => {
                debug!(%error, sandbox = sandbox_name, "proxy-pod bootstrap availability watch failed; reconciliation will retry");
                return;
            }
        }

        // A replacement control can become Available before the Agent
        // Sandbox controller has replaced the prior Suspended condition.
        // Clearing the bootstrap marker in that window publishes a terminal
        // Stopped event to the gateway. Wait for the controller's real Ready
        // condition so the marker removal and readiness annotation expose one
        // causally complete transition for both API versions.
        let runtime_ready = |object: Option<&DynamicObject>| {
            object.is_some_and(|object| {
                object.metadata.uid == expected_sandbox_uid
                    && proxy_pod_bootstrap_in_progress(object)
                    && proxy_pod_runtime_is_ready(object)
            })
        };
        let object = match tokio::time::timeout_at(
            deadline,
            await_condition(sandboxes.clone(), &sandbox_name, runtime_ready),
        )
        .await
        {
            Ok(Ok(Some(object))) => object,
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(error)) => {
                debug!(%error, sandbox = sandbox_name, "proxy-pod runtime readiness watch failed; reconciliation will retry");
                return;
            }
        };
        let Some(resource_version) = object.metadata.resource_version.as_deref() else {
            return;
        };
        let patch = proxy_pod_bootstrap_completion_patch(resource_version);
        if let Err(error) = sandboxes
            .patch(
                &sandbox_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
        {
            debug!(%error, sandbox = sandbox_name, "proxy-pod bootstrap completion raced; reconciliation will retry");
        }
    });
}

fn proxy_pod_runtime_is_ready(object: &DynamicObject) -> bool {
    object
        .data
        .pointer("/status/conditions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                    && condition.get("status").and_then(serde_json::Value::as_str) == Some("True")
            })
        })
}

fn proxy_pod_fence_is_old_enough(policy: &NetworkPolicy, now: SystemTime) -> bool {
    metadata_is_older_than(&policy.metadata, now, PROXY_POD_ORPHAN_FENCE_MIN_AGE)
}

fn proxy_pod_bootstrap_in_progress(object: &DynamicObject) -> bool {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_PROXY_POD_BOOTSTRAPPING))
        .is_some_and(|value| value == "true")
}

fn proxy_pod_bootstrap_operation(object: &DynamicObject) -> Option<&str> {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION))
        .map(String::as_str)
}

fn proxy_pod_bootstrap_is_stale(
    object: &DynamicObject,
    now: SystemTime,
    minimum_age: Duration,
) -> bool {
    let Some(started_at_ms) = object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT))
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return true;
    };
    now.duration_since(SystemTime::UNIX_EPOCH + Duration::from_millis(started_at_ms))
        .is_ok_and(|age| age >= minimum_age)
}

fn proxy_pod_readiness_transition_patch(resource_version: &str, state: &str) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": { ANNOTATION_PROXY_POD_READINESS: state },
        }
    })
}

fn metadata_is_older_than(metadata: &ObjectMeta, now: SystemTime, minimum_age: Duration) -> bool {
    let Some(created) = metadata.creation_timestamp.as_ref() else {
        return false;
    };
    let Ok(created_seconds) = u64::try_from(created.0.timestamp()) else {
        return false;
    };
    now.duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(created_seconds))
        .is_ok_and(|age| age >= minimum_age)
}

fn cluster_wide_watch_stream<S>(
    mut sandbox_stream: S,
    default_namespace: String,
    readiness_client: Client,
    driver: KubernetesComputeDriver,
) -> WatchStream
where
    S: Stream<Item = Event<DynamicObject>> + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::channel(256);
    driver.spawn_proxy_pod_periodic_reconcile(tx.clone());

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = sandbox_stream.next() => match event {
                    Some(Event::Applied(obj)) => {
                        let ns = obj.metadata.namespace.clone()
                            .unwrap_or_else(|| default_namespace.clone());
                        if let Ok((_kube_name, sandbox)) = sandbox_from_object_with_proxy_pod_readiness(&readiness_client, &ns, obj).await {
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
                    Some(Event::Deleted(obj)) => {
                        if is_openshell_managed(&obj)
                            && let Ok(sandbox_id) = sandbox_id_from_object(&obj)
                        {
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
                    Some(Event::Restarted(objs)) => {
                        for obj in objs {
                            let ns = obj.metadata.namespace.clone()
                                .unwrap_or_else(|| default_namespace.clone());
                            if let Ok((_kube_name, sandbox)) = sandbox_from_object_with_proxy_pod_readiness(&readiness_client, &ns, obj).await {
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
                    None => {
                        let _ = tx.send(Err(KubernetesDriverError::Message(
                            "sandbox watcher stream ended unexpectedly".to_string()
                        ))).await;
                        break;
                    }
                },
                () = tx.closed() => break,
            }
        }
    });

    Box::pin(ReceiverStream::new(rx))
}

fn recovering_watcher_stream<S, T, E>(
    stream: S,
    watcher: &'static str,
) -> impl Stream<Item = Event<T>>
where
    S: Stream<Item = Result<Event<T>, E>>,
    E: std::fmt::Display,
{
    continue_on_watcher_errors(stream.default_backoff(), watcher)
}

/// Drop kube-runtime watcher errors after logging them so continued polling can
/// drive its built-in relist and recovery state machine. The production adapter
/// above applies backoff first to avoid hot-looping on persistent API failures.
fn continue_on_watcher_errors<S, T, E>(
    stream: S,
    watcher: &'static str,
) -> impl Stream<Item = Event<T>>
where
    S: Stream<Item = Result<Event<T>, E>>,
    E: std::fmt::Display,
{
    stream.filter_map(move |result| {
        futures::future::ready(match result {
            Ok(event) => Some(event),
            Err(err) => {
                warn!(
                    watcher,
                    error = %err,
                    "Kubernetes watcher stream error; waiting for kube-runtime recovery"
                );
                None
            }
        })
    })
}

fn add_trace_context_annotation(annotations: &mut BTreeMap<String, String>) {
    let Some(carrier) = openshell_otel::current_trace_context_carrier() else {
        return;
    };
    if let Ok(value) = serde_json::to_string(&carrier) {
        annotations.insert(AGENT_SANDBOX_TRACE_CONTEXT_ANNOTATION.to_string(), value);
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

const MAX_KUBE_NAME_LEN: usize = 63;

fn validate_kube_resource_name_length(workspace: &str, name: &str) -> Result<(), tonic::Status> {
    let combined = workspace.len() + 2 + name.len(); // "--" separator
    if combined > MAX_KUBE_NAME_LEN {
        return Err(tonic::Status::invalid_argument(format!(
            "combined Kubernetes resource name '{workspace}--{name}' is {combined} characters, \
             exceeding the DNS-1123 limit of {MAX_KUBE_NAME_LEN}"
        )));
    }
    Ok(())
}

fn is_namespace_owned_by_gateway(
    labels: Option<&BTreeMap<String, String>>,
    gateway_id: &str,
) -> bool {
    labels
        .and_then(|l| l.get(LABEL_MANAGED_BY))
        .is_some_and(|v| v == LABEL_MANAGED_BY_VALUE)
        && labels
            .and_then(|l| l.get(LABEL_GATEWAY_ID))
            .is_some_and(|v| v == gateway_id)
}

fn gateway_id_label_needs_backfill(
    labels: Option<&BTreeMap<String, String>>,
    gateway_id: &str,
) -> bool {
    labels
        .and_then(|labels| labels.get(LABEL_GATEWAY_ID))
        .is_none_or(|value| value != gateway_id)
}

fn namespace_delete_params(uid: String) -> DeleteParams {
    DeleteParams::default().preconditions(Preconditions {
        uid: Some(uid),
        resource_version: None,
    })
}

fn sandbox_lookup_selector_for(sandbox_id: &str, gateway_id: &str) -> String {
    format!(
        "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_SANDBOX_ID}={sandbox_id},{LABEL_GATEWAY_ID}={gateway_id}"
    )
}

fn openshell_sandbox_selector_for(gateway_id: &str) -> String {
    use std::fmt::Write;
    let mut selector = openshell_sandbox_label_selector();
    write!(selector, ",{LABEL_GATEWAY_ID}={gateway_id}").unwrap();
    selector
}

fn sandbox_labels(sandbox: &Sandbox, gateway_id: Option<&str>) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    labels.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    labels.insert(
        LABEL_SANDBOX_WORKSPACE.to_string(),
        sandbox.workspace.clone(),
    );
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    if let Some(gw_id) = gateway_id {
        labels.insert(LABEL_GATEWAY_ID.to_string(), gw_id.to_string());
    }
    labels
}

fn managed_ssh_network_policy(namespace: &str, config: &KubernetesComputeConfig) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(MANAGED_SSH_NETWORK_POLICY_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(BTreeMap::from([(
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            )])),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_VALUE.to_string(),
                )])),
                ..Default::default()
            },
            policy_types: Some(vec!["Ingress".to_string()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([(
                            "kubernetes.io/metadata.name".to_string(),
                            config.managed_ssh_ingress.gateway_namespace.clone(),
                        )])),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(config.managed_ssh_ingress.gateway_pod_selector.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(2222)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }]),
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

fn image_pull_secret_copy(secret_name: &str, namespace: &str, source: Secret) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(BTreeMap::from([(
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            )])),
            ..Default::default()
        },
        data: source.data,
        type_: source.type_,
        ..Default::default()
    }
}

fn sandbox_annotations(sandbox: &Sandbox) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    annotations.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    annotations.insert(
        LABEL_SANDBOX_WORKSPACE.to_string(),
        sandbox.workspace.clone(),
    );
    annotations
}

fn sandbox_id_from_object(obj: &DynamicObject) -> Result<String, String> {
    if let Some(annotations) = obj.metadata.annotations.as_ref()
        && let Some(id) = annotations.get(LABEL_SANDBOX_ID)
    {
        return Ok(id.clone());
    }
    if let Some(labels) = obj.metadata.labels.as_ref()
        && let Some(id) = labels.get(LABEL_SANDBOX_ID)
    {
        return Ok(id.clone());
    }
    Err("sandbox id not found on object".to_string())
}

#[derive(Debug)]
struct TokenReviewIdentity {
    namespace: String,
    pod_name: String,
    pod_uid: String,
}

#[allow(clippy::result_large_err)]
fn token_review_identity(
    status: &TokenReviewStatus,
    expected_service_account: &str,
) -> Result<Option<TokenReviewIdentity>, tonic::Status> {
    if status.authenticated != Some(true) {
        return Ok(None);
    }
    if !status
        .audiences
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|audience| audience == SANDBOX_TOKEN_AUDIENCE)
    {
        return Err(tonic::Status::unauthenticated(
            "sandbox credential audience not accepted",
        ));
    }
    let user = status
        .user
        .as_ref()
        .ok_or_else(|| tonic::Status::permission_denied("TokenReview response missing user"))?;
    let rest = user
        .username
        .as_deref()
        .unwrap_or_default()
        .strip_prefix("system:serviceaccount:")
        .ok_or_else(|| tonic::Status::permission_denied("credential is not a service account"))?;
    let (namespace, service_account) = rest
        .split_once(':')
        .filter(|(namespace, service_account)| !namespace.is_empty() && !service_account.is_empty())
        .ok_or_else(|| tonic::Status::permission_denied("invalid service account identity"))?;
    if service_account != expected_service_account {
        return Err(tonic::Status::permission_denied(
            "credential is not from the configured sandbox service account",
        ));
    }
    Ok(Some(TokenReviewIdentity {
        namespace: namespace.to_string(),
        pod_name: user_extra_one(user, POD_NAME_EXTRA)?,
        pod_uid: user_extra_one(user, POD_UID_EXTRA)?,
    }))
}

#[allow(clippy::result_large_err)]
fn user_extra_one(user: &UserInfo, key: &str) -> Result<String, tonic::Status> {
    let values = user
        .extra
        .as_ref()
        .and_then(|extra| extra.get(key))
        .ok_or_else(|| tonic::Status::permission_denied("sandbox credential is not pod-bound"))?;
    if values.len() != 1 || values[0].is_empty() {
        return Err(tonic::Status::permission_denied(
            "sandbox credential has invalid pod binding",
        ));
    }
    Ok(values[0].clone())
}

#[allow(clippy::result_large_err)]
fn pod_sandbox_id(pod: &Pod) -> Result<String, tonic::Status> {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(LABEL_SANDBOX_ID))
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| tonic::Status::permission_denied("pod is not bound to a sandbox identity"))
}

#[allow(clippy::result_large_err)]
fn validate_pod_uid(pod: &Pod, expected_uid: &str) -> Result<(), tonic::Status> {
    if pod.metadata.uid.as_deref() == Some(expected_uid) {
        return Ok(());
    }
    Err(tonic::Status::permission_denied(
        "sandbox credential pod UID mismatch",
    ))
}

fn require_proxy_control_authentication(via_proxy_control: bool) -> Result<(), tonic::Status> {
    if via_proxy_control {
        Ok(())
    } else {
        Err(tonic::Status::permission_denied(
            "sandbox JWT authentication must originate from the paired supervisor Pod",
        ))
    }
}

#[allow(clippy::result_large_err)]
fn validate_proxy_control_labels(pod: &Pod, sandbox_id: &str) -> Result<(), tonic::Status> {
    validate_proxy_control_labels_from_metadata(&pod.metadata, sandbox_id)
}

#[allow(clippy::result_large_err)]
fn validate_proxy_control_labels_from_metadata(
    metadata: &ObjectMeta,
    sandbox_id: &str,
) -> Result<(), tonic::Status> {
    let labels = metadata.labels.as_ref().ok_or_else(|| {
        tonic::Status::permission_denied("control workload has no proxy-pod labels")
    })?;
    let expected_pair = crate::proxy_pod::pair_label_value(sandbox_id);
    let matches = labels
        .get(BOUNDARY_ROLE_LABEL)
        .is_some_and(|role| role == "supervisor")
        && labels
            .get(BOUNDARY_PAIR_LABEL)
            .is_some_and(|pair| pair == &expected_pair)
        && labels
            .get(LABEL_SANDBOX_ID)
            .is_some_and(|actual| actual == sandbox_id);
    if matches {
        Ok(())
    } else {
        Err(tonic::Status::permission_denied(
            "control workload proxy-pod labels do not match the sandbox identity",
        ))
    }
}

#[allow(clippy::result_large_err)]
fn sandbox_owner_reference(pod: &Pod) -> Result<&OwnerReference, tonic::Status> {
    let mut owners = pod
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|owner| {
            owner.kind == SANDBOX_KIND
                && matches!(
                    owner.api_version.as_str(),
                    "agents.x-k8s.io/v1beta1" | "agents.x-k8s.io/v1alpha1"
                )
        });
    let owner = owners
        .next()
        .ok_or_else(|| tonic::Status::permission_denied("pod is not controlled by a Sandbox"))?;
    if owners.next().is_some()
        || owner.controller != Some(true)
        || owner.name.is_empty()
        || owner.uid.is_empty()
    {
        return Err(tonic::Status::permission_denied(
            "pod has an invalid Sandbox owner",
        ));
    }
    Ok(owner)
}

fn controller_owner_reference(owners: &[OwnerReference]) -> Option<&OwnerReference> {
    owners.iter().find(|owner| owner.controller == Some(true))
}

#[allow(clippy::result_large_err)]
fn validate_owner_uid(
    actual_uid: &Option<String>,
    expected_owner: &OwnerReference,
) -> Result<(), tonic::Status> {
    if actual_uid.as_deref() == Some(expected_owner.uid.as_str()) {
        Ok(())
    } else {
        Err(tonic::Status::permission_denied(
            "Kubernetes controller owner UID mismatch",
        ))
    }
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_owner_identity(
    owner: &OwnerReference,
    sandbox_id: &str,
    sandbox: &DynamicObject,
) -> Result<(), tonic::Status> {
    let uid_matches = sandbox.metadata.uid.as_deref() == Some(owner.uid.as_str());
    let sandbox_id_matches = sandbox
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .is_some_and(|actual| actual == sandbox_id);
    if uid_matches && sandbox_id_matches {
        return Ok(());
    }
    Err(tonic::Status::permission_denied(
        "pod identity does not match its Sandbox owner",
    ))
}

fn accepts_auth_namespace(
    config: &KubernetesComputeConfig,
    operator_allowlist: Option<&OperatorNamespaceAllowlist>,
    namespace: &str,
) -> bool {
    match config.workspace_mode {
        WorkspaceMode::Shared => namespace == config.namespace,
        WorkspaceMode::Managed => {
            namespace.starts_with(&managed_namespace_prefix(&config.gateway_id))
        }
        WorkspaceMode::Operator => {
            operator_allowlist.is_some_and(|allowlist| allowlist.contains(namespace))
        }
    }
}

fn annotation_or_label(obj: &DynamicObject, key: &str) -> Option<String> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(key))
        .or_else(|| obj.metadata.labels.as_ref().and_then(|l| l.get(key)))
        .cloned()
}

fn is_openshell_managed(obj: &DynamicObject) -> bool {
    annotation_or_label(obj, LABEL_MANAGED_BY).as_deref() == Some(LABEL_MANAGED_BY_VALUE)
}

/// Returns `(kube_resource_name, DriverSandbox)`.
///
/// Returns `Err` in two cases (callers should skip, not fail):
/// - The object is not managed by `OpenShell` (missing/wrong `managed-by` label).
/// - The object is managed by `OpenShell` but missing required fields (orphan).
fn sandbox_from_object(namespace: &str, obj: DynamicObject) -> Result<(String, Sandbox), String> {
    let kube_name = obj.metadata.name.clone().unwrap_or_default();

    if !is_openshell_managed(&obj) {
        debug!(object = %kube_name, "skipping sandbox CR not managed by openshell");
        return Err(format!("object {kube_name} not managed by openshell"));
    }

    let Ok(id) = sandbox_id_from_object(&obj) else {
        warn!(object = %kube_name, "openshell-managed sandbox CR missing id");
        return Err(format!("object {kube_name} missing sandbox id"));
    };
    let Some(name) = annotation_or_label(&obj, LABEL_SANDBOX_NAME) else {
        warn!(object = %kube_name, "openshell-managed sandbox CR missing name");
        return Err(format!("object {kube_name} missing sandbox name"));
    };
    let Some(workspace) = annotation_or_label(&obj, LABEL_SANDBOX_WORKSPACE) else {
        warn!(object = %kube_name, "openshell-managed sandbox CR missing workspace");
        return Err(format!("object {kube_name} missing sandbox workspace"));
    };

    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let status = status_from_object(&obj);

    Ok((
        kube_name,
        Sandbox {
            id,
            name,
            namespace,
            spec: None,
            status,
            workspace,
        },
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyPodControlAvailability {
    Available,
    Unavailable,
    Unknown,
}

fn proxy_pod_control_availability_from_deployment(
    deployment: &Deployment,
) -> ProxyPodControlAvailability {
    if deployment
        .status
        .as_ref()
        .and_then(|status| status.available_replicas)
        .unwrap_or_default()
        > 0
    {
        ProxyPodControlAvailability::Available
    } else {
        ProxyPodControlAvailability::Unavailable
    }
}

async fn proxy_pod_control_availability(
    client: &Client,
    namespace: &str,
    sandbox_id: &str,
) -> ProxyPodControlAvailability {
    let names = ProxyPodNames::new(sandbox_id);
    let deployments = Api::<Deployment>::namespaced(client.clone(), namespace);
    let services = Api::<Service>::namespaced(client.clone(), namespace);
    let policies = Api::<NetworkPolicy>::namespaced(client.clone(), namespace);
    let deployment = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        deployments.get_opt(&names.control_deployment),
    ));
    let service = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        services.get_opt(&names.boundary_service),
    ));
    let fence = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        policies.get_opt(&names.workload_policy),
    ));
    let (deployment, service, fence) = tokio::join!(deployment, service, fence);
    let control = match deployment {
        Ok(Ok(Some(deployment))) => proxy_pod_control_availability_from_deployment(&deployment),
        Ok(Ok(None)) => ProxyPodControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine proxy-pod control availability");
            ProxyPodControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking proxy-pod control availability"
            );
            ProxyPodControlAvailability::Unknown
        }
    };
    let service = match service {
        Ok(Ok(Some(_))) => ProxyPodControlAvailability::Available,
        Ok(Ok(None)) => ProxyPodControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine proxy-pod boundary Service availability");
            ProxyPodControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking proxy-pod boundary Service availability"
            );
            ProxyPodControlAvailability::Unknown
        }
    };

    // Deployment availability alone is not sufficient: deletion of the
    // unowned fence would otherwise leave a live boundary with direct pod
    // egress while the driver continued to publish Ready.
    let fence = match fence {
        Ok(Ok(Some(_))) => ProxyPodControlAvailability::Available,
        Ok(Ok(None)) => ProxyPodControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine proxy-pod workload fence availability");
            ProxyPodControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking proxy-pod workload fence availability"
            );
            ProxyPodControlAvailability::Unknown
        }
    };
    if [control, service, fence].contains(&ProxyPodControlAvailability::Unavailable) {
        ProxyPodControlAvailability::Unavailable
    } else if [control, service, fence].contains(&ProxyPodControlAvailability::Unknown) {
        ProxyPodControlAvailability::Unknown
    } else {
        ProxyPodControlAvailability::Available
    }
}

async fn proxy_pod_workload_generation_matches(
    client: &Client,
    namespace: &str,
    pod_name: &str,
    sandbox: &DynamicObject,
) -> ProxyPodControlAvailability {
    let Some(expected_uid) = sandbox
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_PROXY_POD_WORKLOAD_UID))
    else {
        return ProxyPodControlAvailability::Unavailable;
    };
    let pods = Api::<Pod>::namespaced(client.clone(), namespace);
    match tokio::time::timeout(KUBE_API_TIMEOUT, pods.get_opt(pod_name)).await {
        Ok(Ok(Some(pod))) if pod.metadata.uid.as_deref() == Some(expected_uid.as_str()) => {
            ProxyPodControlAvailability::Available
        }
        Ok(Ok(_)) => ProxyPodControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(pod = pod_name, %error, "could not verify proxy-pod workload generation");
            ProxyPodControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                pod = pod_name,
                "timed out checking proxy-pod workload generation"
            );
            ProxyPodControlAvailability::Unknown
        }
    }
}

async fn sandbox_from_object_with_proxy_pod_readiness(
    client: &Client,
    namespace: &str,
    obj: DynamicObject,
) -> Result<(String, Sandbox), String> {
    let bootstrapping = proxy_pod_bootstrap_in_progress(&obj);
    let sandbox_id = sandbox_id_from_object(&obj).unwrap_or_default();
    let object_namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let (name, mut sandbox) = sandbox_from_object(namespace, obj.clone())?;
    if bootstrapping {
        mark_proxy_pod_bootstrapping(&mut sandbox);
    }
    if !sandbox_id.is_empty() {
        let dependencies = Box::pin(proxy_pod_control_availability(
            client,
            &object_namespace,
            &sandbox_id,
        ));
        let workload_generation = Box::pin(proxy_pod_workload_generation_matches(
            client,
            &object_namespace,
            &name,
            &obj,
        ));
        let (dependencies, workload_generation) = tokio::join!(dependencies, workload_generation);
        if dependencies != ProxyPodControlAvailability::Available
            || workload_generation != ProxyPodControlAvailability::Available
        {
            mark_proxy_pod_control_unavailable(&mut sandbox);
        }
    }
    Ok((name, sandbox))
}

fn mark_proxy_pod_bootstrapping(sandbox: &mut Sandbox) {
    if let Some(status) = sandbox.status.as_mut() {
        status
            .conditions
            .retain(|condition| condition.r#type != SANDBOX_SUSPENDED_CONDITION);
    }
    mark_proxy_pod_control_unavailable(sandbox);
}

fn mark_proxy_pod_control_unavailable(sandbox: &mut Sandbox) {
    const REASON: &str = "DependenciesNotReady";
    const MESSAGE: &str = "proxy-pod enforcement dependencies are not ready";
    let Some(status) = sandbox.status.as_mut() else {
        return;
    };
    if let Some(ready) = status
        .conditions
        .iter_mut()
        .find(|condition| condition.r#type == "Ready")
    {
        ready.status = "False".to_string();
        ready.reason = REASON.to_string();
        ready.message = MESSAGE.to_string();
    } else {
        status.conditions.push(SandboxCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: REASON.to_string(),
            message: MESSAGE.to_string(),
            last_transition_time: String::new(),
        });
    }
}

fn desired_proxy_pod_control_replicas(obj: &DynamicObject) -> i32 {
    if let Some(mode) = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("operatingMode"))
        .and_then(serde_json::Value::as_str)
    {
        return i32::from(!mode.eq_ignore_ascii_case("Suspended"));
    }
    obj.data
        .get("spec")
        .and_then(|spec| spec.get("replicas"))
        .and_then(serde_json::Value::as_i64)
        .map_or(1, |replicas| i32::from(replicas > 0))
}

fn update_indexes(
    sandbox_name_to_id: &mut std::collections::HashMap<String, String>,
    agent_pod_to_id: &mut std::collections::HashMap<String, String>,
    kube_name: &str,
    sandbox: &Sandbox,
) {
    if !kube_name.is_empty() {
        sandbox_name_to_id.insert(kube_name.to_string(), sandbox.id.clone());
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

const SANDBOX_RUNTIME_VOLUME_NAME: &str = "openshell-runtime";
const SANDBOX_STATE_VOLUME_NAME: &str = "openshell-runtime-state";
const SANDBOX_BOOTSTRAP_VOLUME_NAME: &str = "openshell-sandbox-bootstrap";
const SANDBOX_POD_IDENTITY_VOLUME_NAME: &str = "openshell-pod-identity";
const SANDBOX_RUNTIME_MOUNT_PATH: &str = "/.openshell/runtime";
const SANDBOX_STATE_MOUNT_PATH: &str = "/.openshell/state";
const SANDBOX_POD_IDENTITY_MOUNT_PATH: &str = "/.openshell/pod-identity";
const SANDBOX_POD_UID_PATH: &str = "/.openshell/pod-identity/uid";
const SANDBOX_PROXY_CA_VOLUME_NAME: &str = "openshell-run";
const SANDBOX_PROXY_CA_MOUNT_PATH: &str = "/run";
const SANDBOX_BOOTSTRAP_SCHEDULING_GATE: &str = "openshell.ai/bootstrap";

/// Render the workload pod half of the RFC 0012 proxy-pod topology.
///
/// The pod receives no gateway credential or endpoint. Its non-root sandbox
/// owns the workload process and seccomp listener; only the paired supervisor
/// Deployment can reach its TLS listener through `NetworkPolicy`.
fn apply_supervisor_proxy_pod_boundary(
    pod_template: &mut serde_json::Value,
    params: &SandboxPodParams<'_>,
) {
    let metadata = pod_template
        .as_object_mut()
        .expect("pod template must be an object")
        .entry("metadata")
        .or_insert_with(|| serde_json::json!({}));
    let labels = metadata
        .as_object_mut()
        .expect("pod metadata must be an object")
        .entry("labels")
        .or_insert_with(|| serde_json::json!({}));
    let labels = labels
        .as_object_mut()
        .expect("pod labels must be an object");
    labels.insert(
        BOUNDARY_PAIR_LABEL.to_string(),
        serde_json::json!(crate::proxy_pod::pair_label_value(params.sandbox_id)),
    );
    labels.insert(
        BOUNDARY_ROLE_LABEL.to_string(),
        serde_json::json!("workload"),
    );

    let Some(spec) = pod_template
        .get_mut("spec")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    spec.insert("hostNetwork".to_string(), serde_json::json!(false));
    spec.insert("hostPID".to_string(), serde_json::json!(false));
    spec.insert("hostIPC".to_string(), serde_json::json!(false));
    spec.insert(
        "shareProcessNamespace".to_string(),
        serde_json::json!(false),
    );
    spec.insert("dnsPolicy".to_string(), serde_json::json!("None"));
    spec.insert(
        "schedulingGates".to_string(),
        serde_json::json!([{"name": SANDBOX_BOOTSTRAP_SCHEDULING_GATE}]),
    );
    spec.insert(
        "dnsConfig".to_string(),
        serde_json::json!({
            "nameservers": ["127.0.0.53"],
            "options": [
                {"name": "ndots", "value": "5"},
                {"name": "timeout", "value": "2"},
                {"name": "attempts", "value": "2"}
            ]
        }),
    );
    spec.insert(
        "securityContext".to_string(),
        serde_json::json!({
            "runAsUser": params.sandbox_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "fsGroup": params.sandbox_gid,
            "fsGroupChangePolicy": "OnRootMismatch",
            "supplementalGroups": [],
            "supplementalGroupsPolicy": "Strict",
            "seccompProfile": {"type": "RuntimeDefault"},
            "sysctls": [{"name": "net.ipv4.ip_unprivileged_port_start", "value": "0"}]
        }),
    );
    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("pod volumes must be an array");
    volumes.retain(|volume| {
        !matches!(
            volume.get("name").and_then(serde_json::Value::as_str),
            Some(
                "openshell-sa-token"
                    | "openshell-client-tls"
                    | "spiffe-workload-api"
                    | SANDBOX_RUNTIME_VOLUME_NAME
                    | SANDBOX_STATE_VOLUME_NAME
                    | SANDBOX_BOOTSTRAP_VOLUME_NAME
                    | SANDBOX_POD_IDENTITY_VOLUME_NAME
                    | SANDBOX_PROXY_CA_VOLUME_NAME
            )
        )
    });
    volumes.extend([
        serde_json::json!({"name": SANDBOX_RUNTIME_VOLUME_NAME, "emptyDir": {"medium": "Memory"}}),
        serde_json::json!({"name": SANDBOX_STATE_VOLUME_NAME, "emptyDir": {"medium": "Memory"}}),
        serde_json::json!({
            "name": SANDBOX_BOOTSTRAP_VOLUME_NAME,
            "secret": {"secretName": params.sandbox_secret_name, "defaultMode": 0o440}
        }),
        serde_json::json!({
            "name": SANDBOX_POD_IDENTITY_VOLUME_NAME,
            "downwardAPI": {
                "items": [{"path": "uid", "fieldRef": {"fieldPath": "metadata.uid"}}]
            }
        }),
        serde_json::json!({
            "name": SANDBOX_PROXY_CA_VOLUME_NAME,
            "emptyDir": {"medium": "Memory"}
        }),
    ]);

    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("pod init containers must be an array");
    let mut bootstrap = serde_json::json!({
        "name": "openshell-sandbox-bootstrap",
        "image": params.supervisor_image,
        "command": ["/openshell-sandbox", "bootstrap"],
        "securityContext": {
            "runAsUser": params.sandbox_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "readOnlyRootFilesystem": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}
        },
        "volumeMounts": [
            {"name": SANDBOX_BOOTSTRAP_VOLUME_NAME, "mountPath": crate::proxy_pod::SANDBOX_BOOTSTRAP_INPUT_PATH, "readOnly": true},
            {"name": SANDBOX_RUNTIME_VOLUME_NAME, "mountPath": SANDBOX_RUNTIME_MOUNT_PATH},
            {"name": SANDBOX_STATE_VOLUME_NAME, "mountPath": SANDBOX_STATE_MOUNT_PATH}
        ]
    });
    if !params.supervisor_image_pull_policy.is_empty() {
        bootstrap["imagePullPolicy"] = serde_json::json!(params.supervisor_image_pull_policy);
    }
    init_containers.push(bootstrap);

    let containers = spec
        .get_mut("containers")
        .and_then(serde_json::Value::as_array_mut)
        .expect("pod containers must be an array");
    let index = containers
        .iter()
        .position(|container| {
            container.get("name").and_then(serde_json::Value::as_str) == Some("agent")
        })
        .unwrap_or(0);
    let container = containers[index]
        .as_object_mut()
        .expect("agent container must be an object");
    container.insert(
        "command".to_string(),
        serde_json::json!([
            format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
            "--bootstrap",
            BOUNDARY_CONFIG_PATH,
        ]),
    );
    container.insert(
        "securityContext".to_string(),
        serde_json::json!({
            "runAsUser": params.sandbox_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}
        }),
    );
    container.insert(
        "ports".to_string(),
        serde_json::json!([{
            "name": "sandbox-control",
            "containerPort": params.boundary_port,
            "protocol": "TCP"
        }]),
    );
    let mounts = container
        .entry("volumeMounts")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("agent volume mounts must be an array");
    mounts.retain(|mount| {
        !matches!(
            mount.get("name").and_then(serde_json::Value::as_str),
            Some(
                "openshell-sa-token"
                    | "openshell-client-tls"
                    | "spiffe-workload-api"
                    | SANDBOX_BOOTSTRAP_VOLUME_NAME
            )
        )
    });
    mounts.extend([
        serde_json::json!({"name": SANDBOX_RUNTIME_VOLUME_NAME, "mountPath": SANDBOX_RUNTIME_MOUNT_PATH, "readOnly": true}),
        serde_json::json!({"name": SANDBOX_STATE_VOLUME_NAME, "mountPath": SANDBOX_STATE_MOUNT_PATH}),
        serde_json::json!({"name": SANDBOX_POD_IDENTITY_VOLUME_NAME, "mountPath": SANDBOX_POD_IDENTITY_MOUNT_PATH, "readOnly": true}),
        serde_json::json!({"name": SANDBOX_PROXY_CA_VOLUME_NAME, "mountPath": SANDBOX_PROXY_CA_MOUNT_PATH}),
    ]);
    let env = container
        .entry("env")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("agent environment must be an array");
    for key in [
        openshell_core::sandbox_env::ENDPOINT,
        openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME,
        openshell_core::sandbox_env::TLS_CA,
        openshell_core::sandbox_env::TLS_CERT,
        openshell_core::sandbox_env::TLS_KEY,
        openshell_core::sandbox_env::SANDBOX_TOKEN,
        openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
        openshell_core::sandbox_env::K8S_SA_TOKEN_FILE,
        openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
    ] {
        remove_env(env, key);
    }
    apply_resolved_identity_env(env, params.sandbox_uid, params.sandbox_gid);
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
    sandbox_gid: Option<u32>,
    workspace_owner: Option<(u32, u32)>,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // fsGroup is a pod-level field — it instructs kubelet to chown mounted
    // volumes to this GID. It is invalid at the container securityContext level.
    if let Some(sandbox_gid) = sandbox_gid {
        let pod_sc = spec
            .entry("securityContext")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(pod_sc_obj) = pod_sc.as_object_mut() {
            pod_sc_obj.insert("fsGroup".to_string(), serde_json::json!(sandbox_gid));
        }
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

        let mut init_spec = if let Some((uid, gid)) = workspace_owner {
            serde_json::json!({
                "name": WORKSPACE_INIT_CONTAINER_NAME,
                "image": image,
                "command": [format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"), "seed-workspace"],
                "securityContext": {
                    "runAsUser": uid,
                    "runAsGroup": gid,
                    "runAsNonRoot": true,
                    "readOnlyRootFilesystem": true,
                    "allowPrivilegeEscalation": false,
                    "capabilities": {"drop": ["ALL"]}
                },
                "volumeMounts": [
                    {"name": WORKSPACE_VOLUME_NAME, "mountPath": WORKSPACE_INIT_MOUNT_PATH},
                    {"name": SANDBOX_RUNTIME_VOLUME_NAME, "mountPath": SANDBOX_RUNTIME_MOUNT_PATH, "readOnly": true}
                ]
            })
        } else {
            serde_json::json!({
                "name": WORKSPACE_INIT_CONTAINER_NAME,
                "image": image,
                "command": ["sh", "-c", copy_cmd],
                "securityContext": {"runAsUser": 0},
                "volumeMounts": [{
                    "name": WORKSPACE_VOLUME_NAME,
                    "mountPath": WORKSPACE_INIT_MOUNT_PATH
                }]
            })
        };
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
///
/// When `storage_class` is non-empty, it is written to the PVC's
/// `storageClassName`. An empty value omits the field so the cluster's
/// default `StorageClass` applies. Clusters with no default `StorageClass`
/// must set this to prevent the PVC from staying `Pending`.
fn default_workspace_volume_claim_templates(
    storage_size: &str,
    storage_class: &str,
) -> serde_json::Value {
    let size = if storage_size.is_empty() {
        DEFAULT_WORKSPACE_STORAGE_SIZE
    } else {
        storage_size
    };
    let mut spec = serde_json::json!({
        "accessModes": ["ReadWriteOnce"],
        "resources": {
            "requests": {
                "storage": size
            }
        }
    });
    if !storage_class.is_empty() {
        spec["storageClassName"] = serde_json::json!(storage_class);
    }
    serde_json::json!([{
        "metadata": {
            "name": WORKSPACE_VOLUME_NAME
        },
        "spec": spec
    }])
}

/// Parameters shared by `sandbox_to_k8s_spec` and `sandbox_template_to_k8s`.
#[allow(clippy::struct_excessive_bools)]
struct SandboxPodParams<'a> {
    default_image: &'a str,
    image_pull_policy: &'a str,
    image_pull_secrets: &'a [String],
    supervisor_image: &'a str,
    supervisor_image_pull_policy: &'a str,
    service_account_name: &'a str,
    sandbox_id: &'a str,
    enable_user_namespaces: bool,
    workspace_default_storage_size: &'a str,
    workspace_storage_class: &'a str,
    default_runtime_class_name: &'a str,
    /// Resolved sandbox UID for supervisor `runAsUser` and env var.
    sandbox_uid: u32,
    /// Resolved sandbox GID for PVC init container operations.
    sandbox_gid: u32,
    /// TLS listener port exposed only to the paired supervisor Pod.
    boundary_port: u16,
    /// Immutable Secret name for this workload Pod generation.
    sandbox_secret_name: &'a str,
}

impl Default for SandboxPodParams<'_> {
    fn default() -> Self {
        Self {
            default_image: "",
            image_pull_policy: "",
            image_pull_secrets: &[],
            supervisor_image: "",
            supervisor_image_pull_policy: "",
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
            sandbox_id: "",
            enable_user_namespaces: false,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE,
            workspace_storage_class: "",
            default_runtime_class_name: "",
            sandbox_uid: DEFAULT_SANDBOX_UID,
            sandbox_gid: DEFAULT_SANDBOX_UID,
            boundary_port: 5500,
            sandbox_secret_name: "os-sandbox-test-generation",
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

fn kubernetes_driver_config_for_spec(
    spec: Option<&SandboxSpec>,
) -> Result<KubernetesSandboxDriverConfig, String> {
    let config = spec
        .and_then(|spec| spec.template.as_ref())
        .map(KubernetesSandboxDriverConfig::from_template)
        .transpose()?
        .unwrap_or_default();
    validate_kubernetes_protected_path_conflicts(
        &config.containers.agent.volume_mounts,
        KUBERNETES_DRIVER_PROTECTED_MOUNT_PATHS,
    )?;
    Ok(config)
}

fn sandbox_to_k8s_spec(
    spec: Option<&SandboxSpec>,
    params: &SandboxPodParams<'_>,
) -> Result<serde_json::Value, String> {
    let driver_config = kubernetes_driver_config_for_spec(spec)?;
    let mut root = serde_json::Map::new();

    // Determine early whether OpenShell should inject its default workspace
    // PVC. Explicit Kubernetes driver-config mounts under /sandbox/ take
    // ownership of workspace persistence.
    // We need this flag before building the podTemplate because the workspace
    // persistence transforms are applied inside sandbox_template_to_k8s.
    let user_has_explicit_workspace_mount = driver_config.has_explicit_sandbox_data_mount();
    let inject_workspace = !user_has_explicit_workspace_mount;

    if let Some(spec) = spec {
        let pod_env = spec_pod_env(Some(spec));
        if let Some(template) = spec.template.as_ref() {
            root.insert(
                "podTemplate".to_string(),
                sandbox_template_to_k8s_with_validated_config(
                    template,
                    driver_gpu_requirements(spec.resource_requirements.as_ref()),
                    &pod_env,
                    &driver_config,
                    inject_workspace,
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

    if inject_workspace {
        root.insert(
            "volumeClaimTemplates".to_string(),
            default_workspace_volume_claim_templates(
                params.workspace_default_storage_size,
                params.workspace_storage_class,
            ),
        );
    }

    // podTemplate is required by the Kubernetes CRD - ensure it's always present
    if !root.contains_key("podTemplate") {
        let pod_env = spec_pod_env(spec);
        root.insert(
            "podTemplate".to_string(),
            sandbox_template_to_k8s_with_validated_config(
                &SandboxTemplate::default(),
                driver_gpu_requirements(spec.and_then(|s| s.resource_requirements.as_ref())),
                &pod_env,
                &driver_config,
                inject_workspace,
                params,
            ),
        );
    }

    Ok(serde_json::Value::Object(
        std::iter::once(("spec".to_string(), serde_json::Value::Object(root))).collect(),
    ))
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
    let driver_config = KubernetesSandboxDriverConfig::from_template(template)
        .expect("test Kubernetes driver_config should be valid");
    sandbox_template_to_k8s_with_validated_config(
        template,
        gpu_requirements.as_ref(),
        spec_environment,
        &driver_config,
        inject_workspace,
        params,
    )
}

#[cfg(test)]
fn sandbox_template_to_k8s_with_gpu_requirements(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
    spec_environment: &std::collections::HashMap<String, String>,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let driver_config = KubernetesSandboxDriverConfig::from_template(template)
        .expect("test Kubernetes driver_config should be valid");
    sandbox_template_to_k8s_with_validated_config(
        template,
        gpu_requirements,
        spec_environment,
        &driver_config,
        inject_workspace,
        params,
    )
}

fn sandbox_template_to_k8s_with_validated_config(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
    spec_environment: &std::collections::HashMap<String, String>,
    driver_config: &KubernetesSandboxDriverConfig,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    let pod_labels = template
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<String, serde_json::Value>>();
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
            LABEL_SANDBOX_ID.to_string(),
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

    // Per-sandbox portable intent overrides the cluster-wide default. This
    // driver owns the Kubernetes-specific `hostUsers` translation. Accept the
    // former platform_config encoding during rolling upgrades from gateways
    // that predate the typed field.
    let use_user_namespaces = template
        .user_namespaces
        .or_else(|| platform_config_bool(template, "host_users").map(|host_users| !host_users))
        .unwrap_or(params.enable_user_namespaces);

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
    // Do not let kubelet replace the canonical main-process generation after
    // the supervisor exits. The gateway records that exit as terminal Error.
    spec.insert("restartPolicy".to_string(), serde_json::json!("Never"));

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

    let env = build_sandbox_env(&template.environment, spec_environment);

    container.insert("env".to_string(), serde_json::Value::Array(env));

    let volume_mounts = driver_config
        .containers
        .agent
        .volume_mounts
        .iter()
        .map(kubernetes_driver_volume_mount_to_k8s)
        .collect::<Vec<_>>();
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

    let volumes = driver_config
        .volumes
        .iter()
        .map(kubernetes_driver_volume_to_k8s)
        .collect::<Vec<_>>();
    spec.insert("volumes".to_string(), serde_json::Value::Array(volumes));

    let mut template_value = serde_json::Map::new();
    if !metadata.is_empty() {
        template_value.insert("metadata".to_string(), serde_json::Value::Object(metadata));
    }
    template_value.insert("spec".to_string(), serde_json::Value::Object(spec));

    let mut result = serde_json::Value::Object(template_value);

    apply_supervisor_proxy_pod_boundary(&mut result, params);

    // Inject workspace persistence (init container + PVC volume mount) so
    // that /sandbox data survives pod rescheduling. Skipped when the user
    // provides custom storage through driver_config.
    if inject_workspace {
        apply_workspace_persistence(
            &mut result,
            image,
            params.image_pull_policy,
            None,
            Some((params.sandbox_uid, params.sandbox_gid)),
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

fn build_sandbox_env(
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
) -> Vec<serde_json::Value> {
    let mut env = Vec::new();
    for (name, value) in template_environment.iter().chain(spec_environment) {
        if !name.starts_with("OPENSHELL_") || name == openshell_core::sandbox_env::LOG_LEVEL {
            upsert_env(&mut env, name, value);
        }
    }
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::TELEMETRY_ENABLED,
        openshell_core::telemetry::enabled_env_value(),
    );
    env
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

fn apply_resolved_identity_env(env: &mut Vec<serde_json::Value>, uid: u32, gid: u32) {
    remove_env(env, openshell_core::sandbox_env::OCI_IMAGE_USER);
    remove_env(env, openshell_core::sandbox_env::SANDBOX_UID);
    remove_env(env, openshell_core::sandbox_env::SANDBOX_GID);
    upsert_env(env, openshell_core::sandbox_env::OCI_IMAGE_USER, "");
    upsert_env(
        env,
        openshell_core::sandbox_env::SANDBOX_UID,
        &uid.to_string(),
    );
    upsert_env(
        env,
        openshell_core::sandbox_env::SANDBOX_GID,
        &gid.to_string(),
    );
}

fn remove_env(env: &mut Vec<serde_json::Value>, name: &str) {
    env.retain(|item| item.get("name").and_then(|value| value.as_str()) != Some(name));
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
        Some(prost_types::value::Kind::BoolValue(value)) => Some(*value),
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

fn child_environment_from_sandbox_object(
    object: &DynamicObject,
) -> std::collections::HashMap<String, String> {
    object
        .data
        .pointer("/spec/podTemplate/spec/containers/0/env")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let value = entry.get("value")?.as_str()?;
            (!name.starts_with("OPENSHELL_")).then(|| (name.to_string(), value.to_string()))
        })
        .collect()
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
        ..Default::default()
    })
}

async fn create_or_validate_proxy_pod_fence(
    policies: &Api<NetworkPolicy>,
    expected: &NetworkPolicy,
) -> Result<(), KubernetesDriverError> {
    let name = expected.metadata.name.as_deref().unwrap_or_default();
    match tokio::time::timeout(KUBE_API_TIMEOUT, policies.get_opt(name)).await {
        Ok(Ok(Some(existing))) => {
            return validate_proxy_pod_fence(&existing, expected);
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => return Err(KubernetesDriverError::from_kube(error)),
        Err(_) => {
            return Err(KubernetesDriverError::Message(
                "timed out reading proxy-pod workload fence".to_string(),
            ));
        }
    }

    match tokio::time::timeout(
        KUBE_API_TIMEOUT,
        policies.create(&PostParams::default(), expected),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(KubeError::Api(error))) if error.code == 409 => {
            let existing = tokio::time::timeout(KUBE_API_TIMEOUT, policies.get(name))
                .await
                .map_err(|_| {
                    KubernetesDriverError::Message(
                        "timed out validating existing proxy-pod workload fence".to_string(),
                    )
                })?
                .map_err(KubernetesDriverError::from_kube)?;
            validate_proxy_pod_fence(&existing, expected)
        }
        Ok(Err(error)) => Err(KubernetesDriverError::from_kube(error)),
        Err(_) => Err(KubernetesDriverError::Message(
            "timed out creating proxy-pod workload fence".to_string(),
        )),
    }
}

fn validate_proxy_pod_fence(
    existing: &NetworkPolicy,
    expected: &NetworkPolicy,
) -> Result<(), KubernetesDriverError> {
    if proxy_pod_fence_matches(existing, expected) {
        Ok(())
    } else {
        let name = expected.metadata.name.as_deref().unwrap_or_default();
        Err(KubernetesDriverError::Precondition(format!(
            "proxy-pod workload fence {name} exists but does not match the intended enforcement"
        )))
    }
}

fn proxy_pod_fence_matches(existing: &NetworkPolicy, expected: &NetworkPolicy) -> bool {
    fn normalized_spec(mut spec: Option<NetworkPolicySpec>) -> Option<NetworkPolicySpec> {
        if let Some(spec) = spec.as_mut() {
            // The Kubernetes API server omits explicitly empty rule arrays when it
            // persists a NetworkPolicy. For a policy type named in `policyTypes`,
            // an omitted rule array and an empty rule array both deny all traffic.
            if spec.egress.as_ref().is_some_and(Vec::is_empty) {
                spec.egress = None;
            }
            if spec.ingress.as_ref().is_some_and(Vec::is_empty) {
                spec.ingress = None;
            }
        }
        spec
    }

    fn contains_required_metadata(
        actual: &Option<BTreeMap<String, String>>,
        required: &Option<BTreeMap<String, String>>,
    ) -> bool {
        required.as_ref().is_none_or(|required| {
            actual.as_ref().is_some_and(|actual| {
                required
                    .iter()
                    .all(|(key, value)| actual.get(key) == Some(value))
            })
        })
    }

    normalized_spec(existing.spec.clone()) == normalized_spec(expected.spec.clone())
        && contains_required_metadata(&existing.metadata.labels, &expected.metadata.labels)
        && contains_required_metadata(
            &existing.metadata.annotations,
            &expected.metadata.annotations,
        )
}

fn kubernetes_sandbox_has_stopped_condition(obj: &DynamicObject) -> bool {
    obj.data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.get("type").and_then(serde_json::Value::as_str)
                    == Some(SANDBOX_SUSPENDED_CONDITION)
                    && condition
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|status| status.eq_ignore_ascii_case("true"))
            })
        })
}

fn kubernetes_sandbox_stop_is_complete(
    api_version: &str,
    obj: &DynamicObject,
    pod_is_gone: bool,
) -> bool {
    if api_version == SANDBOX_VERSION_V1ALPHA1 {
        // v1alpha1 omits a usable stopped condition.
        pod_is_gone
    } else {
        kubernetes_sandbox_has_stopped_condition(obj) && pod_is_gone
    }
}

fn kubernetes_sandbox_stop_failure(obj: &DynamicObject) -> Option<String> {
    obj.data
        .get("status")?
        .get("conditions")?
        .as_array()?
        .iter()
        .find_map(|condition| {
            let is_terminal = condition.get("type").and_then(serde_json::Value::as_str)
                == Some(SANDBOX_SUSPENDED_CONDITION)
                && condition
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|status| status.eq_ignore_ascii_case("false"))
                && condition.get("reason").and_then(serde_json::Value::as_str)
                    == Some(SANDBOX_SUSPENDED_POD_NOT_OWNED_REASON);
            if !is_terminal {
                return None;
            }

            let message = condition
                .get("message")
                .and_then(serde_json::Value::as_str)
                .filter(|message| !message.is_empty())
                .unwrap_or("backing pod is not owned by this sandbox");
            Some(format!("Kubernetes sandbox stop rejected: {message}"))
        })
}

async fn kubernetes_sandbox_pod_is_gone(
    pod_api: &Api<Pod>,
    pod_name: &str,
    deadline: tokio::time::Instant,
) -> Result<bool, String> {
    let request_timeout =
        KUBE_API_TIMEOUT.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
    if request_timeout.is_zero() {
        return Ok(false);
    }

    match tokio::time::timeout(request_timeout, pod_api.get(pod_name)).await {
        Ok(Ok(_)) => Ok(false),
        Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(true),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!(
            "timed out after {}s waiting for Kubernetes API while checking sandbox pod termination",
            request_timeout.as_secs()
        )),
    }
}

fn kubernetes_sandbox_stop_timeout(obj: &DynamicObject) -> Duration {
    let termination_grace_period = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("podTemplate"))
        .and_then(|template| template.get("spec"))
        .and_then(|spec| spec.get("terminationGracePeriodSeconds"))
        .and_then(serde_json::Value::as_u64)
        .map_or(DEFAULT_POD_TERMINATION_GRACE_PERIOD, Duration::from_secs);

    // The controller must observe the desired state, wait for the pod grace
    // period and kubelet teardown, then reconcile the deleted pod into the
    // Sandbox status. Keep one API timeout of headroom around that grace.
    termination_grace_period.saturating_add(KUBE_API_TIMEOUT)
}

fn next_stop_poll_interval(current: Duration) -> Duration {
    current.saturating_mul(2).min(STOP_MAX_POLL_INTERVAL)
}

fn sandbox_operating_state_patch(
    api_version: &str,
    resource_version: &str,
    running: bool,
) -> serde_json::Value {
    if api_version == SANDBOX_VERSION_V1BETA1 {
        if running {
            serde_json::json!({
                "metadata": {"resourceVersion": resource_version},
                "spec": {"operatingMode": "Running"}
            })
        } else {
            serde_json::json!({
                "metadata": {
                    "resourceVersion": resource_version,
                    "annotations": {
                        ANNOTATION_PROXY_POD_BOOTSTRAPPING: serde_json::Value::Null,
                        ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT: serde_json::Value::Null,
                        ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION: serde_json::Value::Null,
                        ANNOTATION_PROXY_POD_WORKLOAD_UID: serde_json::Value::Null,
                    },
                },
                "spec": {"operatingMode": "Suspended"}
            })
        }
    } else {
        if running {
            serde_json::json!({
                "metadata": {"resourceVersion": resource_version},
                "spec": {"replicas": 1}
            })
        } else {
            serde_json::json!({
                "metadata": {
                    "resourceVersion": resource_version,
                    "annotations": {
                        ANNOTATION_PROXY_POD_BOOTSTRAPPING: serde_json::Value::Null,
                        ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT: serde_json::Value::Null,
                        ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION: serde_json::Value::Null,
                        ANNOTATION_PROXY_POD_WORKLOAD_UID: serde_json::Value::Null,
                    },
                },
                "spec": {"replicas": 0}
            })
        }
    }
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

fn spawn_namespace_label_watcher(
    client: Client,
    label_selector: String,
    allowlist: OperatorNamespaceAllowlist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let ns_api: Api<Namespace> = Api::all(client);
    let watcher_config = watcher::Config::default().labels(&label_selector);
    let jitter_seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_secs() ^ u64::from(duration.subsec_nanos())
        });

    tokio::spawn(async move {
        let mut retry_attempt = 0;
        loop {
            let mut stream = watcher::watcher(ns_api.clone(), watcher_config.clone()).boxed();

            loop {
                let event = tokio::select! {
                    result = stream.try_next() => result,
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                };
                match event {
                    Ok(Some(Event::Applied(ns))) => {
                        retry_attempt = 0;
                        if let Some(name) = ns.metadata.name.as_deref()
                            && allowlist.insert(name.to_string())
                        {
                            info!(namespace = name, "operator namespace added to allowlist");
                        }
                    }
                    Ok(Some(Event::Deleted(ns))) => {
                        retry_attempt = 0;
                        if let Some(name) = ns.metadata.name.as_deref()
                            && allowlist.remove(name)
                        {
                            info!(
                                namespace = name,
                                "operator namespace removed from allowlist"
                            );
                        }
                    }
                    Ok(Some(Event::Restarted(namespaces))) => {
                        retry_attempt = 0;
                        let names: std::collections::BTreeSet<String> = namespaces
                            .into_iter()
                            .filter_map(|ns| ns.metadata.name)
                            .collect();
                        let count = names.len();
                        allowlist.replace(names);
                        info!(
                            total = count,
                            "operator namespace allowlist replaced from full relist"
                        );
                    }
                    Ok(None) => {
                        warn!("operator namespace watcher stream ended unexpectedly");
                        break;
                    }
                    Err(err) => {
                        warn!(error = %err, "operator namespace watcher stream error");
                        break;
                    }
                }
            }

            let retry_delay = namespace_watcher_retry_delay(retry_attempt, jitter_seed);
            warn!(?retry_delay, "operator namespace watcher reconnecting");
            tokio::select! {
                () = tokio::time::sleep(retry_delay) => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                }
            }
            retry_attempt = retry_attempt.saturating_add(1);
        }
    });

    info!(
        label_selector = %label_selector,
        "operator namespace label watcher spawned"
    );
}

fn namespace_watcher_retry_delay(attempt: u32, jitter_seed: u64) -> Duration {
    let base_secs = 2_u64.saturating_mul(1_u64 << attempt.min(4)).min(24);
    let max_jitter_secs = base_secs / 4;
    let mixed_seed =
        jitter_seed.wrapping_add(u64::from(attempt).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let jitter_secs = mixed_seed % (max_jitter_secs + 1);
    Duration::from_secs(base_secs + jitter_secs)
}

fn load_namespace_file(path: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let names: Vec<String> = serde_json::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    Ok(names.into_iter().collect())
}

fn spawn_namespace_file_watcher(
    path: PathBuf,
    allowlist: OperatorNamespaceAllowlist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    match load_namespace_file(&path) {
        Ok(names) => {
            let count = names.len();
            allowlist.replace(names);
            info!(
                path = %path.display(),
                total = count,
                "operator namespace allowlist loaded from file"
            );
        }
        Err(err) => {
            warn!(
                error = %err,
                "failed to load initial operator namespace file, allowlist empty"
            );
        }
    }

    let watch_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let debounce = Duration::from_secs(1);

    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut watcher =
            match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res
                    && matches!(
                        event.kind,
                        notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                    )
                {
                    let _ = tx.send(());
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    warn!(
                        error = %e,
                        "failed to start operator namespace file watcher, hot-reload disabled"
                    );
                    return;
                }
            };

        if let Err(e) = notify::Watcher::watch(
            &mut watcher,
            &watch_dir,
            notify::RecursiveMode::NonRecursive,
        ) {
            warn!(
                error = %e,
                dir = %watch_dir.display(),
                "failed to watch operator namespace file directory, hot-reload disabled"
            );
            return;
        }

        info!(
            path = %path.display(),
            "operator namespace file watcher started"
        );

        loop {
            let got_event = tokio::select! {
                event = rx.recv() => event.is_some(),
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                    continue;
                }
            };
            if !got_event {
                warn!("operator namespace file watcher disconnected");
                break;
            }

            loop {
                tokio::select! {
                    () = tokio::time::sleep(debounce) => {
                        match load_namespace_file(&path) {
                            Ok(names) => {
                                let count = names.len();
                                allowlist.replace(names);
                                info!(
                                    total = count,
                                    "operator namespace allowlist reloaded from file"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    "failed to reload operator namespace file, keeping existing allowlist"
                                );
                            }
                        }
                        break;
                    }
                    r = rx.recv() => {
                        if r.is_some() {
                            continue;
                        }
                        warn!("operator namespace file watcher disconnected");
                        return;
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                    }
                }
            }
        }
    });
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
    use std::collections::BTreeSet;

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    #[tokio::test]
    async fn tracing_create_sandbox_failure_exports_a_kubernetes_operation_span() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());

        driver
            .create_sandbox(&Sandbox::default())
            .with_subscriber(subscriber)
            .await
            .expect_err("missing sandbox name should fail");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "kubernetes.provision")
            .expect("create operation span");
        assert!(matches!(
            span.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn sandbox_annotation_propagates_the_active_w3c_trace_context() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        let annotations = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("kubernetes.provision");
            let _entered = span.enter();
            let mut annotations = BTreeMap::new();
            add_trace_context_annotation(&mut annotations);
            annotations
        });

        let carrier: serde_json::Value = serde_json::from_str(
            annotations
                .get("opentelemetry.io/trace-context")
                .expect("agent-sandbox trace-context annotation"),
        )
        .expect("annotation should contain a JSON propagation carrier");
        let traceparent = carrier["traceparent"]
            .as_str()
            .expect("carrier should contain traceparent");
        assert!(traceparent.starts_with("00-"));
        assert_eq!(traceparent.len(), 55);

        provider.shutdown().unwrap();
    }

    fn json_struct(value: serde_json::Value) -> Struct {
        let serde_json::Value::Object(object) = value else {
            panic!("expected JSON object");
        };
        openshell_core::proto_struct::json_object_to_struct(object)
            .expect("test JSON must convert to a protobuf Struct")
    }

    fn sandbox_to_k8s_spec_for_test(
        spec: Option<&SandboxSpec>,
        params: &SandboxPodParams<'_>,
    ) -> serde_json::Value {
        sandbox_to_k8s_spec(spec, params).expect("test Kubernetes driver_config should be valid")
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
    fn resource_version_conflicts_are_not_reported_as_duplicate_sandboxes() {
        let conflict = KubeError::Api(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "the object has been modified".to_string(),
            reason: "Conflict".to_string(),
            code: 409,
        });
        assert!(is_kube_resource_version_conflict(&conflict));
        assert!(matches!(
            KubernetesDriverError::from_kube(conflict),
            KubernetesDriverError::Message(_)
        ));

        let duplicate = KubeError::Api(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "already exists".to_string(),
            reason: "AlreadyExists".to_string(),
            code: 409,
        });
        assert!(matches!(
            KubernetesDriverError::from_kube(duplicate),
            KubernetesDriverError::AlreadyExists
        ));
    }

    fn expired_watch_error() -> watcher::Error {
        watcher::Error::WatchError(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "too old resource version".to_string(),
            reason: "Expired".to_string(),
            code: 410,
        })
    }

    #[tokio::test]
    async fn sandbox_watcher_error_does_not_hide_restarted_recovery_event() {
        let recovered = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("recovered-sandbox".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let source = futures::stream::iter([
            Err(expired_watch_error()),
            Ok(Event::Restarted(vec![recovered])),
        ]);
        let mut stream = continue_on_watcher_errors(source, "sandbox-resource");

        let event = stream
            .next()
            .await
            .expect("410 Expired must not terminate the watcher stream");
        let Event::Restarted(objects) = event else {
            panic!("expected kube-runtime recovery to emit Restarted");
        };
        assert_eq!(objects.len(), 1);
        assert_eq!(
            objects[0].metadata.name.as_deref(),
            Some("recovered-sandbox")
        );
        assert!(
            stream.next().await.is_none(),
            "source closure must be preserved"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn outward_watch_stream_survives_expired_error_and_backoff_recovery() {
        let recovered = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("recovered-sandbox".to_string()),
                namespace: Some("recovered-namespace".to_string()),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "sandbox-id".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "sandbox-name".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "workspace".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let source = futures::stream::iter([
            Err(expired_watch_error()),
            Ok(Event::Restarted(vec![recovered])),
        ])
        .chain(futures::stream::pending());
        let sandbox_stream = recovering_watcher_stream(source, "sandbox-resource").boxed();
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let mut outward = cluster_wide_watch_stream(
            sandbox_stream,
            "default".to_string(),
            driver.watch_client.clone(),
            driver,
        );

        let event = outward
            .next()
            .await
            .expect("outward stream must stay open through recovery")
            .expect("recoverable watcher error must not reach the outward stream");
        let Some(watch_sandboxes_event::Payload::Sandbox(event)) = event.payload else {
            panic!("expected recovered sandbox event");
        };
        let sandbox = event.sandbox.expect("sandbox payload must be populated");
        assert_eq!(sandbox.id, "sandbox-id");
        assert_eq!(sandbox.namespace, "recovered-namespace");

        let next = outward.next();
        futures::pin_mut!(next);
        assert!(
            futures::poll!(next).is_pending(),
            "outward stream must remain open after the recovered event"
        );
    }

    #[tokio::test]
    async fn kubernetes_event_watcher_error_does_not_hide_restarted_recovery_event() {
        let source = futures::stream::iter([
            Err(expired_watch_error()),
            Ok(Event::Restarted(vec![KubeEventObj::default()])),
        ]);
        let mut stream = continue_on_watcher_errors(source, "kubernetes-event");

        let event = stream
            .next()
            .await
            .expect("410 Expired must not terminate the watcher stream");
        let Event::Restarted(events) = event else {
            panic!("expected kube-runtime recovery to emit Restarted");
        };
        assert_eq!(events.len(), 1);
        assert!(
            stream.next().await.is_none(),
            "source closure must be preserved"
        );
    }

    fn authenticated_token_review(username: &str) -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(true),
            audiences: Some(vec![SANDBOX_TOKEN_AUDIENCE.to_string()]),
            user: Some(UserInfo {
                username: Some(username.to_string()),
                extra: Some(BTreeMap::from([
                    (POD_NAME_EXTRA.to_string(), vec!["sandbox-pod".to_string()]),
                    (POD_UID_EXTRA.to_string(), vec!["pod-uid".to_string()]),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn token_review_uses_configured_service_account_and_pod_binding() {
        let status = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        let identity = token_review_identity(&status, "sandbox-sa")
            .unwrap()
            .expect("authenticated identity");
        assert_eq!(identity.namespace, "workspaces");
        assert_eq!(identity.pod_name, "sandbox-pod");
        assert_eq!(identity.pod_uid, "pod-uid");
    }

    #[test]
    fn token_review_rejects_a_different_service_account() {
        let status = authenticated_token_review("system:serviceaccount:workspaces:other");
        let error = token_review_identity(&status, "sandbox-sa").unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn token_review_rejects_wrong_audience_and_missing_pod_binding() {
        let mut wrong_audience =
            authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        wrong_audience.audiences = Some(vec!["kubernetes.default.svc".to_string()]);
        let error = token_review_identity(&wrong_audience, "sandbox-sa").unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);

        let mut missing_binding =
            authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        missing_binding.user.as_mut().unwrap().extra = None;
        let error = token_review_identity(&missing_binding, "sandbox-sa").unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn token_review_returns_none_when_not_authenticated() {
        let status = TokenReviewStatus {
            authenticated: Some(false),
            error: Some("token rejected".to_string()),
            ..Default::default()
        };

        assert!(
            token_review_identity(&status, "sandbox-sa")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn authentication_namespace_validation_covers_each_workspace_mode() {
        let mut config = KubernetesComputeConfig {
            namespace: "openshell".to_string(),
            ..Default::default()
        };
        assert!(accepts_auth_namespace(&config, None, "openshell"));
        assert!(!accepts_auth_namespace(&config, None, "other"));

        config.workspace_mode = WorkspaceMode::Managed;
        config.gateway_id = "gateway-a".to_string();
        assert!(accepts_auth_namespace(
            &config,
            None,
            "openshell-gateway-a-workspace-a"
        ));
        assert!(!accepts_auth_namespace(
            &config,
            None,
            "openshell-gateway-b-workspace-a"
        ));

        config.workspace_mode = WorkspaceMode::Operator;
        let allowlist = OperatorNamespaceAllowlist::from_set(BTreeSet::from([
            "team-a".to_string(),
            "team-b".to_string(),
        ]));
        assert!(accepts_auth_namespace(&config, Some(&allowlist), "team-a"));
        assert!(!accepts_auth_namespace(&config, Some(&allowlist), "team-c"));
        assert!(!accepts_auth_namespace(&config, None, "team-a"));
    }

    fn sandbox_owner_for_test(name: &str, uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: "agents.x-k8s.io/v1beta1".to_string(),
            block_owner_deletion: None,
            controller: Some(true),
            kind: SANDBOX_KIND.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
        }
    }

    fn sandbox_object_for_test(uid: &str, sandbox_id: &str) -> DynamicObject {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox-a", &resource);
        sandbox.metadata.uid = Some(uid.to_string());
        sandbox.metadata.labels = Some(BTreeMap::from([(
            LABEL_SANDBOX_ID.to_string(),
            sandbox_id.to_string(),
        )]));
        sandbox
    }

    #[test]
    fn pod_identity_requires_matching_uid_annotation_and_controlling_owner() {
        let owner = sandbox_owner_for_test("sandbox-a", "sandbox-uid-a");
        let pod = Pod {
            metadata: ObjectMeta {
                uid: Some("pod-uid-a".to_string()),
                annotations: Some(BTreeMap::from([(
                    LABEL_SANDBOX_ID.to_string(),
                    "sandbox-id-a".to_string(),
                )])),
                owner_references: Some(vec![owner.clone()]),
                ..Default::default()
            },
            ..Default::default()
        };

        validate_pod_uid(&pod, "pod-uid-a").expect("matching pod UID");
        assert_eq!(pod_sandbox_id(&pod).unwrap(), "sandbox-id-a");
        assert_eq!(sandbox_owner_reference(&pod).unwrap(), &owner);

        let error = validate_pod_uid(&pod, "other-pod-uid").unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let mut missing_annotation = pod.clone();
        missing_annotation.metadata.annotations = None;
        let error = pod_sandbox_id(&missing_annotation).unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let mut non_controlling = pod;
        non_controlling.metadata.owner_references.as_mut().unwrap()[0].controller = Some(false);
        let error = sandbox_owner_reference(&non_controlling).unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn proxy_control_identity_requires_exact_pair_and_role_labels() {
        let sandbox_id = "sandbox-id-a";
        let mut pod = Pod {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), sandbox_id.to_string()),
                    (
                        BOUNDARY_PAIR_LABEL.to_string(),
                        crate::proxy_pod::pair_label_value(sandbox_id),
                    ),
                    (BOUNDARY_ROLE_LABEL.to_string(), "supervisor".to_string()),
                ])),
                ..Default::default()
            },
            ..Default::default()
        };
        validate_proxy_control_labels(&pod, sandbox_id).unwrap();

        pod.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(BOUNDARY_ROLE_LABEL.to_string(), "workload".to_string());
        assert_eq!(
            validate_proxy_control_labels(&pod, sandbox_id)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn sandbox_authentication_requires_the_paired_supervisor() {
        require_proxy_control_authentication(true).expect("paired supervisor is trusted");
        assert_eq!(
            require_proxy_control_authentication(false)
                .expect_err("workload JWT must not authenticate directly")
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn orphan_fence_reaping_requires_a_creation_age_floor() {
        let policy: NetworkPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"creationTimestamp": "2026-01-01T00:00:00Z"},
            "spec": {"podSelector": {}}
        }))
        .unwrap();
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        assert!(!proxy_pod_fence_is_old_enough(
            &policy,
            created + PROXY_POD_ORPHAN_FENCE_MIN_AGE - Duration::from_secs(1)
        ));
        assert!(proxy_pod_fence_is_old_enough(
            &policy,
            created + PROXY_POD_ORPHAN_FENCE_MIN_AGE
        ));
        assert!(!proxy_pod_fence_is_old_enough(
            &NetworkPolicy::default(),
            created + PROXY_POD_ORPHAN_FENCE_MIN_AGE
        ));
    }

    #[test]
    fn proxy_pod_fence_validation_accepts_api_normalization_and_injected_metadata() {
        let names = ProxyPodNames::new("sandbox-id-a");
        let mut expected =
            workload_fence("namespace-a", &names, "sandbox-id-a", 5000).workload_policy;
        expected.metadata.labels = Some(BTreeMap::from([(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        )]));
        expected.metadata.annotations = Some(BTreeMap::from([(
            "openshell.ai/workload-pod-name".to_string(),
            "sandbox-a".to_string(),
        )]));

        let mut persisted = expected.clone();
        persisted.spec.as_mut().unwrap().egress = None;
        persisted
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert("admission.example/injected".to_string(), "true".to_string());
        assert!(proxy_pod_fence_matches(&persisted, &expected));
        assert!(validate_proxy_pod_fence(&persisted, &expected).is_ok());

        persisted.spec.as_mut().unwrap().policy_types = Some(vec!["Ingress".to_string()]);
        assert!(!proxy_pod_fence_matches(&persisted, &expected));
        assert!(matches!(
            validate_proxy_pod_fence(&persisted, &expected),
            Err(KubernetesDriverError::Precondition(_))
        ));
    }

    #[test]
    fn proxy_pod_bootstrap_marker_and_age_gate_rollback() {
        let started = Duration::from_secs(1_767_225_600);
        let mut object: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-a",
                "creationTimestamp": "2020-01-01T00:00:00Z",
                "annotations": {
                    ANNOTATION_PROXY_POD_BOOTSTRAPPING: "true",
                    ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT: started.as_millis().to_string(),
                    ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION: "restart",
                }
            }
        }))
        .unwrap();
        assert!(proxy_pod_bootstrap_in_progress(&object));
        assert_eq!(proxy_pod_bootstrap_operation(&object), Some("restart"));
        let started_at = SystemTime::UNIX_EPOCH + started;
        assert!(!proxy_pod_bootstrap_is_stale(
            &object,
            started_at + PROXY_POD_BOOTSTRAP_GRACE - Duration::from_secs(1),
            PROXY_POD_BOOTSTRAP_GRACE
        ));
        assert!(proxy_pod_bootstrap_is_stale(
            &object,
            started_at + PROXY_POD_BOOTSTRAP_GRACE,
            PROXY_POD_BOOTSTRAP_GRACE
        ));
        object
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .remove(ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT);
        assert!(proxy_pod_bootstrap_is_stale(
            &object,
            started_at,
            PROXY_POD_BOOTSTRAP_GRACE
        ));
        object
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .remove(ANNOTATION_PROXY_POD_BOOTSTRAPPING);
        assert!(!proxy_pod_bootstrap_in_progress(&object));
    }

    #[test]
    fn sandbox_owner_identity_requires_matching_uid_and_sandbox_id() {
        let owner = sandbox_owner_for_test("sandbox-a", "sandbox-uid-a");
        let sandbox = sandbox_object_for_test("sandbox-uid-a", "sandbox-id-a");
        validate_sandbox_owner_identity(&owner, "sandbox-id-a", &sandbox)
            .expect("matching owner identity");

        let mismatched_owner = sandbox_object_for_test("sandbox-uid-b", "sandbox-id-a");
        let error =
            validate_sandbox_owner_identity(&owner, "sandbox-id-a", &mismatched_owner).unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let mismatched_annotation = sandbox_object_for_test("sandbox-uid-a", "sandbox-id-b");
        let error = validate_sandbox_owner_identity(&owner, "sandbox-id-a", &mismatched_annotation)
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn sandbox_api_version_probe_retries_on_structured_and_raw_404() {
        let structured = kube_api_error(404, "could not find the requested resource");
        assert!(should_try_next_sandbox_api_version(&structured));

        let raw = kube_api_error(404, "404 page not found\n");
        assert!(should_try_next_sandbox_api_version(&raw));
    }

    #[test]
    fn lifecycle_patch_uses_version_specific_operating_state() {
        let beta_stop = sandbox_operating_state_patch(SANDBOX_VERSION_V1BETA1, "42", false);
        assert_eq!(beta_stop["metadata"]["resourceVersion"], "42");
        assert_eq!(
            beta_stop["metadata"]["annotations"][ANNOTATION_PROXY_POD_BOOTSTRAPPING],
            serde_json::Value::Null
        );
        assert_eq!(beta_stop["spec"]["operatingMode"], "Suspended");
        assert!(beta_stop["spec"].get("replicas").is_none());

        let alpha_start = sandbox_operating_state_patch(SANDBOX_VERSION_V1ALPHA1, "43", true);
        assert_eq!(alpha_start["metadata"]["resourceVersion"], "43");
        assert!(alpha_start["metadata"].get("annotations").is_none());
        assert_eq!(alpha_start["spec"]["replicas"], 1);
        assert!(alpha_start["spec"].get("operatingMode").is_none());
    }

    #[test]
    fn stop_timeout_includes_pod_grace_period_and_reconcile_headroom() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);

        assert_eq!(
            kubernetes_sandbox_stop_timeout(&sandbox),
            Duration::from_secs(60),
            "an omitted grace period uses the Kubernetes 30-second default"
        );

        sandbox.data = serde_json::json!({
            "spec": {
                "podTemplate": {
                    "spec": {"terminationGracePeriodSeconds": 45}
                }
            }
        });
        assert_eq!(
            kubernetes_sandbox_stop_timeout(&sandbox),
            Duration::from_secs(75)
        );
    }

    #[test]
    fn stop_poll_interval_backs_off_to_cap() {
        let mut interval = STOP_INITIAL_POLL_INTERVAL;
        let expected = [
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(2),
        ];

        for expected_interval in expected {
            interval = next_stop_poll_interval(interval);
            assert_eq!(interval, expected_interval);
        }
    }

    #[test]
    fn stopped_status_requires_published_condition() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1ALPHA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.data = serde_json::json!({"status": {"replicas": 0}});

        assert!(
            !kubernetes_sandbox_has_stopped_condition(&sandbox),
            "v1alpha1 omits a zero status replica count on the wire; it is not a usable completion signal"
        );

        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{"type": "Suspended", "status": "True"}]
            }
        });
        assert!(kubernetes_sandbox_has_stopped_condition(&sandbox));
    }

    #[test]
    fn beta_stop_requires_suspended_condition_and_deleted_pod() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);

        assert!(!kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1BETA1,
            &sandbox,
            true,
        ));

        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{"type": "Suspended", "status": "True"}]
            }
        });
        assert!(!kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1BETA1,
            &sandbox,
            false,
        ));
        assert!(kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1BETA1,
            &sandbox,
            true,
        ));
        assert!(kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1ALPHA1,
            &DynamicObject::new("sandbox", &resource),
            true,
        ));
    }

    #[test]
    fn stop_failure_only_rejects_terminal_suspension_condition() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{
                    "type": "Suspended",
                    "status": "False",
                    "reason": "PodNotOwned",
                    "message": "Refused to delete pod because it is not owned by this sandbox"
                }]
            }
        });

        assert_eq!(
            kubernetes_sandbox_stop_failure(&sandbox).as_deref(),
            Some(
                "Kubernetes sandbox stop rejected: Refused to delete pod because it is not owned by this sandbox"
            )
        );

        sandbox.data["status"]["conditions"][0]["status"] = serde_json::json!("Unknown");
        sandbox.data["status"]["conditions"][0]["reason"] = serde_json::json!("PodStateUnknown");
        assert!(
            kubernetes_sandbox_stop_failure(&sandbox).is_none(),
            "an unknown pod state can recover on a later controller reconciliation"
        );
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
    fn driver_config_for_spec_rejects_unknown_fields() {
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

        let err = kubernetes_driver_config_for_spec(sandbox.spec.as_ref()).unwrap_err();
        assert!(err.contains("unknown field"));
        assert!(err.contains("gpu_device_ids"));
    }

    #[test]
    fn driver_config_pvc_subpath_mounts_render_in_pod_template() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {
                        "claim_name": "pvc-user-data-123",
                        "read_only": false
                    }
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace",
                                "sub_path": "workspace",
                                "read_only": false
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/memory",
                                "sub_path": "memory"
                            }
                        ]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };
        let spec = SandboxSpec {
            template: Some(template),
            ..SandboxSpec::default()
        };

        let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
        let pod_template = &cr["spec"]["podTemplate"];

        let volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist");
        let user_volume = volumes
            .iter()
            .find(|volume| volume["name"] == "user-data")
            .expect("user PVC volume should be rendered");
        assert_eq!(
            user_volume["persistentVolumeClaim"]["claimName"],
            "pvc-user-data-123"
        );
        assert_eq!(user_volume["persistentVolumeClaim"]["readOnly"], false);

        let mounts = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should exist");
        let workspace_mount = mounts
            .iter()
            .find(|mount| mount["mountPath"] == "/sandbox/.openshell/workspace")
            .expect("workspace subPath mount should be rendered");
        assert_eq!(workspace_mount["name"], "user-data");
        assert_eq!(workspace_mount["subPath"], "workspace");
        assert_eq!(workspace_mount["readOnly"], false);

        let memory_mount = mounts
            .iter()
            .find(|mount| mount["mountPath"] == "/sandbox/.openshell/memory")
            .expect("memory subPath mount should be rendered");
        assert_eq!(memory_mount["name"], "user-data");
        assert_eq!(memory_mount["subPath"], "memory");
        assert_eq!(memory_mount["readOnly"], true);

        let spec_obj = cr["spec"].as_object().expect("spec should be an object");
        assert!(
            !spec_obj.contains_key("volumeClaimTemplates"),
            "explicit /sandbox driver_config mounts should skip the default workspace VCT"
        );
        let has_workspace_init = pod_template["spec"]["initContainers"]
            .as_array()
            .is_some_and(|containers| {
                containers
                    .iter()
                    .any(|container| container["name"] == WORKSPACE_INIT_CONTAINER_NAME)
            });
        assert!(
            !has_workspace_init,
            "explicit /sandbox driver_config mounts should skip the default workspace init container"
        );
    }

    #[test]
    fn driver_config_accepts_read_write_pvc_with_multiple_subpath_mounts() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {
                        "claim_name": "pvc-user-data",
                        "read_only": false
                    }
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace",
                                "sub_path": "workspace",
                                "read_only": false
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/memory",
                                "sub_path": "memory",
                                "read_only": false
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/sessions",
                                "sub_path": "sessions",
                                "read_only": false
                            }
                        ]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let config = KubernetesSandboxDriverConfig::from_template(&template)
            .expect("read-write PVC with multiple subPath mounts should validate");

        assert_eq!(config.volumes.len(), 1);
        assert_eq!(config.volumes[0].name, "user-data");
        assert_eq!(
            config.volumes[0].persistent_volume_claim.claim_name,
            "pvc-user-data"
        );
        assert!(!config.volumes[0].persistent_volume_claim.read_only);
        assert_eq!(config.containers.agent.volume_mounts.len(), 3);
        assert!(
            config
                .containers
                .agent
                .volume_mounts
                .iter()
                .all(|mount| !mount.read_only)
        );
        assert!(config.has_explicit_sandbox_data_mount());
    }

    #[test]
    fn driver_config_rejects_duplicate_pvc_volume_names() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [
                    {
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-a"}
                    },
                    {
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-b"}
                    }
                ]
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("duplicate kubernetes driver_config volume"));
    }

    #[test]
    fn driver_config_rejects_duplicate_pvc_volume_mount_targets() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace"
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace"
                            }
                        ]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("duplicate kubernetes driver_config mount target"));
    }

    #[test]
    fn driver_config_accepts_dns1123_subdomain_pvc_claim_name() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {"claim_name": "pvc.user-data.123"}
                }]
            }))),
            ..SandboxTemplate::default()
        };

        let config = KubernetesSandboxDriverConfig::from_template(&template)
            .expect("DNS-1123 subdomain PVC names should validate");

        assert_eq!(
            config.volumes[0].persistent_volume_claim.claim_name,
            "pvc.user-data.123"
        );
    }

    #[test]
    fn driver_config_rejects_invalid_volume_label_and_claim_name() {
        for (field, config) in [
            (
                "volumes[].name",
                serde_json::json!({
                    "volumes": [{
                        "name": "User_Data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }]
                }),
            ),
            (
                "volumes[].persistent_volume_claim.claim_name",
                serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "Pvc_User_Data"}
                    }]
                }),
            ),
        ] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(config)),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains(field) && err.contains("DNS-1123"),
                "expected invalid {field} to fail DNS-1123 validation, got {err}"
            );
        }
    }

    #[test]
    fn driver_config_rejects_mounts_referencing_unknown_volumes() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "known-data",
                    "persistent_volume_claim": {"claim_name": "pvc-known"}
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [{
                            "name": "missing-data",
                            "mount_path": "/sandbox/.openshell/workspace",
                            "sub_path": "workspace"
                        }]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("unknown kubernetes driver_config volume 'missing-data'"));
    }

    #[test]
    fn driver_config_rejects_shared_reserved_mount_targets() {
        for mount_path in [
            "/",
            "/sandbox",
            "/etc/openshell",
            "/etc/openshell-tls/client",
            "/opt/openshell/bin",
        ] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": mount_path
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains("mount path") || err.contains("mount target"),
                "expected protected mount target {mount_path:?} to be rejected, got {err}"
            );
        }
    }

    #[test]
    fn driver_config_rejects_kubernetes_static_protected_mount_targets() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": "/var/run/secrets/openshell"
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };

        let err = kubernetes_driver_config_for_spec(Some(&spec)).unwrap_err();

        assert!(err.contains("/var/run/secrets/openshell"));
    }

    #[test]
    fn driver_config_allows_spiffe_workload_path_without_provider_spiffe() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": "/spiffe-workload-api"
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };

        kubernetes_driver_config_for_spec(Some(&spec))
            .expect("SPIFFE workload path should only be protected when SPIFFE is enabled");
    }

    #[test]
    fn driver_config_rejects_invalid_kubernetes_sub_paths() {
        for sub_path in ["/workspace", "../workspace"] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace",
                                "sub_path": sub_path
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains("mount subpath must be relative"),
                "expected invalid sub_path {sub_path:?} to be rejected, got {err}"
            );
        }
    }

    #[test]
    fn driver_config_defaults_pvc_mounts_to_read_only() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [{
                            "name": "user-data",
                            "mount_path": "/sandbox/.openshell/workspace",
                            "sub_path": "workspace"
                        }]
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

        let volume = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist")
            .iter()
            .find(|volume| volume["name"] == "user-data")
            .expect("user volume should exist");
        assert_eq!(volume["persistentVolumeClaim"]["readOnly"], true);

        let mount = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should exist")
            .iter()
            .find(|mount| mount["mountPath"] == "/sandbox/.openshell/workspace")
            .expect("user mount should exist");
        assert_eq!(mount["readOnly"], true);
    }

    #[test]
    fn driver_config_rejects_read_write_mount_for_read_only_pvc_volume() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {
                        "claim_name": "pvc-user-data",
                        "read_only": true
                    }
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [{
                            "name": "user-data",
                            "mount_path": "/sandbox/.openshell/workspace",
                            "read_only": false
                        }]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("cannot set read_only=false"));
    }

    #[test]
    fn driver_config_rejects_reserved_kubernetes_volume_names() {
        for volume_name in [
            CLIENT_TLS_VOLUME_NAME,
            SERVICE_ACCOUNT_TOKEN_VOLUME_NAME,
            SPIFFE_WORKLOAD_API_VOLUME_NAME,
            SANDBOX_RUNTIME_VOLUME_NAME,
            SANDBOX_STATE_VOLUME_NAME,
            SANDBOX_BOOTSTRAP_VOLUME_NAME,
            SANDBOX_POD_IDENTITY_VOLUME_NAME,
            SANDBOX_PROXY_CA_VOLUME_NAME,
            WORKSPACE_VOLUME_NAME,
        ] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": volume_name,
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }]
                }))),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains("reserved for OpenShell-managed volumes"),
                "expected reserved volume name {volume_name:?} to be rejected, got {err}"
            );
        }
    }

    #[test]
    fn reserved_kubernetes_volume_names_cover_managed_pod_volumes() {
        let params = SandboxPodParams::default();
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );
        let volume_names = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist")
            .iter()
            .filter_map(|volume| volume["name"].as_str())
            .collect::<Vec<_>>();

        for volume_name in volume_names {
            assert!(
                KUBERNETES_DRIVER_RESERVED_VOLUME_NAMES.contains(&volume_name),
                "managed volume {volume_name:?} should be reserved"
            );
        }
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
    fn proxy_pod_topology_renders_credential_free_boundary_workload() {
        let params = SandboxPodParams {
            supervisor_image: "supervisor-image:latest",
            sandbox_id: "sandbox-123",
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );
        let agent = &pod_template["spec"]["containers"][0];

        assert_eq!(
            agent["command"],
            serde_json::json!([
                format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
                "--bootstrap",
                BOUNDARY_CONFIG_PATH
            ])
        );
        assert_eq!(agent["securityContext"]["runAsUser"], 1500);
        assert_eq!(agent["securityContext"]["runAsGroup"], 1500);
        assert_eq!(agent["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            agent["securityContext"]["capabilities"],
            serde_json::json!({"drop": ["ALL"]})
        );
        assert!(agent["securityContext"]["capabilities"]["add"].is_null());
        assert_eq!(pod_template["spec"]["securityContext"]["fsGroup"], 1500);
        assert_eq!(
            pod_template["spec"]["securityContext"]["seccompProfile"]["type"],
            "RuntimeDefault"
        );
        assert_eq!(pod_template["spec"]["dnsPolicy"], "None");
        assert_eq!(
            pod_template["spec"]["dnsConfig"]["nameservers"],
            serde_json::json!(["127.0.0.53"])
        );
        assert_eq!(
            pod_template["spec"]["schedulingGates"],
            serde_json::json!([{"name": SANDBOX_BOOTSTRAP_SCHEDULING_GATE}])
        );
        let workspace_init = pod_template["spec"]["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == WORKSPACE_INIT_CONTAINER_NAME)
            .unwrap();
        assert_eq!(
            workspace_init["command"],
            serde_json::json!([
                format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
                "seed-workspace"
            ])
        );
        assert_eq!(workspace_init["securityContext"]["runAsUser"], 1500);
        assert_eq!(
            workspace_init["securityContext"]["capabilities"],
            serde_json::json!({"drop": ["ALL"]})
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::ENDPOINT),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::K8S_SA_TOKEN_FILE),
            None
        );
        assert_eq!(
            pod_template["metadata"]["labels"][BOUNDARY_ROLE_LABEL],
            "workload"
        );

        let mounts = agent["volumeMounts"].as_array().unwrap();
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_RUNTIME_VOLUME_NAME && mount["readOnly"] == true
        }));
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_STATE_VOLUME_NAME && mount["readOnly"].is_null()
        }));
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_POD_IDENTITY_VOLUME_NAME
                && mount["mountPath"] == SANDBOX_POD_IDENTITY_MOUNT_PATH
                && mount["readOnly"] == true
        }));
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_PROXY_CA_VOLUME_NAME
                && mount["mountPath"] == SANDBOX_PROXY_CA_MOUNT_PATH
                && mount["readOnly"].is_null()
        }));
        assert!(
            !mounts
                .iter()
                .any(|mount| mount["name"] == SANDBOX_BOOTSTRAP_VOLUME_NAME)
        );
        assert!(
            !mounts
                .iter()
                .any(|mount| mount["name"] == CLIENT_TLS_VOLUME_NAME)
        );
        assert!(
            !mounts
                .iter()
                .any(|mount| mount["name"] == SERVICE_ACCOUNT_TOKEN_VOLUME_NAME)
        );

        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        let pod_identity = volumes
            .iter()
            .find(|volume| volume["name"] == SANDBOX_POD_IDENTITY_VOLUME_NAME)
            .unwrap();
        assert_eq!(
            pod_identity["downwardAPI"]["items"],
            serde_json::json!([{"path": "uid", "fieldRef": {"fieldPath": "metadata.uid"}}])
        );
    }

    /// Regression test: TLS mount path must match env var paths.
    /// The volume is mounted at a specific path and the env vars must point to
    /// files within that same path, otherwise the sandbox will fail to start
    /// with "No such file or directory" errors.

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
            Some(1000), // sandbox_gid
            None,
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
            Some(1000),
            None,
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

        apply_workspace_persistence(&mut pod_template, "img:latest", "Always", Some(1000), None);

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
        let params = SandboxPodParams::default();
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
    fn user_namespaces_disabled_by_default() {
        let pod_template = default_template_to_k8s(false);
        assert!(
            pod_template["spec"]["hostUsers"].is_null(),
            "hostUsers must not be set when user namespaces are disabled"
        );
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
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
    fn user_namespaces_preserve_capability_free_posture() {
        let pod_template = default_template_to_k8s(true);
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn user_namespaces_per_sandbox_override_enables() {
        let template = SandboxTemplate {
            user_namespaces: Some(true),
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
            "per-sandbox user namespace intent must set hostUsers: false"
        );
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn user_namespaces_per_sandbox_override_disables() {
        let template = SandboxTemplate {
            user_namespaces: Some(false),
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
            "per-sandbox user namespace intent must override the cluster default"
        );
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn user_namespaces_accepts_legacy_host_users_encoding() {
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

        let params = SandboxPodParams::default();
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
            "legacy host_users: false must still enable user namespaces"
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
    fn sandbox_template_annotation_is_accepted_by_bootstrap_authentication() {
        let params = SandboxPodParams {
            sandbox_id: "sandbox-a",
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );
        let pod: Pod = serde_json::from_value(pod_template).expect("valid pod template");

        assert_eq!(pod_sandbox_id(&pod).unwrap(), "sandbox-a");
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
    fn log_level_propagates_as_env_var_to_sandbox_pod() {
        let spec = SandboxSpec {
            log_level: "debug".to_string(),
            ..SandboxSpec::default()
        };
        let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
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
                let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
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
    fn sandbox_pod_drops_legacy_network_capability_environment() {
        let spec = SandboxSpec {
            environment: std::collections::HashMap::from([(
                openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES.to_string(),
                openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY.to_string(),
            )]),
            ..SandboxSpec::default()
        };
        let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
        let env = cr["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(!env.iter().any(|entry| {
            entry["name"] == openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES
        }));
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
        let vct = default_workspace_volume_claim_templates("5Gi", "");
        let storage = &vct[0]["spec"]["resources"]["requests"]["storage"];
        assert_eq!(storage, "5Gi");
    }

    #[test]
    fn default_workspace_vct_falls_back_to_const_when_empty() {
        let vct = default_workspace_volume_claim_templates("", "");
        let storage = &vct[0]["spec"]["resources"]["requests"]["storage"];
        assert_eq!(storage, DEFAULT_WORKSPACE_STORAGE_SIZE);
    }

    #[test]
    fn sandbox_name_validation_accepts_valid_dns_labels() {
        assert!(validate_kubernetes_dns1123_label("my-sandbox", "sandbox name").is_ok());
        assert!(validate_kubernetes_dns1123_label("test123", "sandbox name").is_ok());
        assert!(validate_kubernetes_dns1123_label("123abc", "sandbox name").is_ok());
    }

    #[test]
    fn sandbox_name_validation_rejects_invalid_dns_labels() {
        assert!(validate_kubernetes_dns1123_label("my_sandbox", "sandbox name").is_err());
        assert!(validate_kubernetes_dns1123_label("MySandbox", "sandbox name").is_err());
        assert!(validate_kubernetes_dns1123_label("dotted.name", "sandbox name").is_err());
    }

    #[test]
    fn kube_resource_name_length_validation_accepts_short_names() {
        validate_kube_resource_name_length("default", "my-sandbox").unwrap();
    }

    #[test]
    fn kube_resource_name_length_validation_rejects_oversized_names() {
        let long_ws = "a".repeat(40);
        let long_name = "b".repeat(25);
        let err = validate_kube_resource_name_length(&long_ws, &long_name).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("67"));
    }

    #[test]
    fn sandbox_from_object_reads_annotations() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("alpha--work".to_string()),
                namespace: Some("default".to_string()),
                annotations: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-123".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
                ])),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-123".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let (kube_name, sandbox) = sandbox_from_object("default", obj).unwrap();
        assert_eq!(kube_name, "alpha--work");
        assert_eq!(sandbox.name, "work");
        assert_eq!(sandbox.workspace, "alpha");
        assert_eq!(sandbox.id, "uuid-123");
    }

    #[test]
    fn sandbox_from_object_falls_back_to_labels() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("alpha--work".to_string()),
                namespace: Some("default".to_string()),
                annotations: None,
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-456".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let (_, sandbox) = sandbox_from_object("default", obj).unwrap();
        assert_eq!(sandbox.name, "work");
        assert_eq!(sandbox.workspace, "alpha");
        assert_eq!(sandbox.id, "uuid-456");
    }

    #[test]
    fn sandbox_from_object_skips_unmanaged_cr() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("foreign-sandbox".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(BTreeMap::from([(
                    "some-other-label".to_string(),
                    "value".to_string(),
                )])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let result = sandbox_from_object("default", obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not managed by openshell"));
    }

    #[test]
    fn sandbox_from_object_uses_object_namespace_over_fallback() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("work".to_string()),
                namespace: Some("openshell-gw1-team-a".to_string()),
                annotations: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-cross".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "team-a".to_string()),
                ])),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-cross".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "team-a".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let (_, sandbox) = sandbox_from_object("openshell", obj).unwrap();
        assert_eq!(sandbox.namespace, "openshell-gw1-team-a");
        assert_eq!(sandbox.workspace, "team-a");
    }

    #[test]
    fn sandbox_from_object_warns_on_managed_cr_missing_workspace() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("work".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-789".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let result = sandbox_from_object("default", obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing sandbox workspace"));
    }

    #[test]
    fn sandbox_labels_includes_workspace_and_name() {
        let sandbox = Sandbox {
            id: "uuid-1".to_string(),
            name: "work".to_string(),
            workspace: "alpha".to_string(),
            ..Default::default()
        };
        let labels = sandbox_labels(&sandbox, None);
        assert_eq!(labels.get(LABEL_SANDBOX_ID).unwrap(), "uuid-1");
        assert_eq!(labels.get(LABEL_SANDBOX_NAME).unwrap(), "work");
        assert_eq!(labels.get(LABEL_SANDBOX_WORKSPACE).unwrap(), "alpha");
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).unwrap(),
            LABEL_MANAGED_BY_VALUE
        );
        assert!(!labels.contains_key(LABEL_GATEWAY_ID));
    }

    #[test]
    fn sandbox_labels_includes_gateway_id_when_provided() {
        let sandbox = Sandbox {
            id: "uuid-1".to_string(),
            name: "work".to_string(),
            workspace: "alpha".to_string(),
            ..Default::default()
        };
        let labels = sandbox_labels(&sandbox, Some("gw-42"));
        assert_eq!(labels.get(LABEL_GATEWAY_ID).unwrap(), "gw-42");
    }

    #[test]
    fn sandbox_annotations_stores_authoritative_values() {
        let sandbox = Sandbox {
            id: "uuid-2".to_string(),
            name: "dev".to_string(),
            workspace: "beta".to_string(),
            ..Default::default()
        };
        let annotations = sandbox_annotations(&sandbox);
        assert_eq!(annotations.get(LABEL_SANDBOX_ID).unwrap(), "uuid-2");
        assert_eq!(annotations.get(LABEL_SANDBOX_NAME).unwrap(), "dev");
        assert_eq!(annotations.get(LABEL_SANDBOX_WORKSPACE).unwrap(), "beta");
    }

    #[test]
    fn sandbox_id_from_object_errors_without_label() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("some-name".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert!(sandbox_id_from_object(&obj).is_err());
    }

    #[test]
    fn default_workspace_vct_sets_storage_class_when_provided() {
        let vct = default_workspace_volume_claim_templates("5Gi", "fast-ssd");
        assert_eq!(vct[0]["spec"]["storageClassName"], "fast-ssd");
    }

    #[test]
    fn default_workspace_vct_omits_storage_class_when_empty() {
        let vct = default_workspace_volume_claim_templates("5Gi", "");
        assert!(vct[0]["spec"].get("storageClassName").is_none());
    }

    #[test]
    fn workspace_storage_class_propagates_to_generated_cr_spec() {
        let params = SandboxPodParams {
            workspace_storage_class: "fast-ssd",
            ..SandboxPodParams::default()
        };
        let cr = sandbox_to_k8s_spec_for_test(Some(&SandboxSpec::default()), &params);
        assert_eq!(
            cr["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"],
            "fast-ssd"
        );
    }

    #[test]
    fn workspace_storage_class_omitted_from_cr_spec_when_empty() {
        let cr = sandbox_to_k8s_spec_for_test(
            Some(&SandboxSpec::default()),
            &SandboxPodParams::default(),
        );
        assert!(
            cr["spec"]["volumeClaimTemplates"][0]["spec"]
                .get("storageClassName")
                .is_none()
        );
    }

    #[test]
    fn sandbox_lookup_selector_always_includes_gateway_id() {
        let sel = sandbox_lookup_selector_for("sb-123", "gw-42");
        assert!(
            sel.contains(&format!("{LABEL_GATEWAY_ID}=gw-42")),
            "selector must include gateway ID: {sel}"
        );
        assert!(
            sel.contains(&format!("{LABEL_SANDBOX_ID}=sb-123")),
            "selector must include sandbox ID: {sel}"
        );
        assert!(
            sel.contains(&format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}")),
            "selector must include managed-by: {sel}"
        );
    }

    #[test]
    fn openshell_sandbox_selector_always_includes_gateway_id() {
        let sel = openshell_sandbox_selector_for("gw-99");
        assert!(
            sel.contains(&format!("{LABEL_GATEWAY_ID}=gw-99")),
            "selector must include gateway ID: {sel}"
        );
        assert!(
            sel.contains(&format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}")),
            "selector must include managed-by: {sel}"
        );
    }

    #[test]
    fn gateway_id_backfill_adopts_unlabelled_sandbox() {
        let labels = BTreeMap::from([(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        )]);
        assert!(gateway_id_label_needs_backfill(Some(&labels), "gw-1"));
    }

    #[test]
    fn gateway_id_backfill_adopts_sandbox_from_previous_gateway() {
        let labels = BTreeMap::from([(LABEL_GATEWAY_ID.to_string(), "gw-old".to_string())]);
        assert!(gateway_id_label_needs_backfill(Some(&labels), "gw-1"));
    }

    #[test]
    fn gateway_id_backfill_skips_sandbox_already_owned_by_gateway() {
        let labels = BTreeMap::from([(LABEL_GATEWAY_ID.to_string(), "gw-1".to_string())]);
        assert!(!gateway_id_label_needs_backfill(Some(&labels), "gw-1"));
    }

    #[test]
    fn managed_ssh_policy_allows_only_gateway_peer_on_port_2222() {
        let config = KubernetesComputeConfig {
            managed_ssh_ingress: crate::config::ManagedSshIngressConfig {
                enabled: true,
                gateway_namespace: "gateway-ns".to_string(),
                gateway_pod_selector: BTreeMap::from([(
                    "app.kubernetes.io/name".to_string(),
                    "openshell".to_string(),
                )]),
            },
            ..KubernetesComputeConfig::default()
        };
        let policy = managed_ssh_network_policy("workspace-ns", &config);
        let spec = policy.spec.unwrap();
        assert_eq!(
            spec.policy_types.as_deref(),
            Some(["Ingress".to_string()].as_slice())
        );
        let ingress = &spec.ingress.unwrap()[0];
        assert_eq!(
            ingress.ports.as_ref().unwrap()[0].port,
            Some(IntOrString::Int(2222))
        );
        let peer = &ingress.from.as_ref().unwrap()[0];
        assert_eq!(
            peer.namespace_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()
                .get("kubernetes.io/metadata.name")
                .map(String::as_str),
            Some("gateway-ns")
        );
        assert_eq!(
            peer.pod_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()
                .get("app.kubernetes.io/name")
                .map(String::as_str),
            Some("openshell")
        );
    }

    #[test]
    fn image_pull_secret_copy_keeps_only_portable_secret_fields() {
        let source: Secret = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "regcred",
                "namespace": "gateway",
                "uid": "source-uid",
                "resourceVersion": "42",
                "labels": { "source-only": "true" },
                "annotations": { "source-only": "true" },
                "finalizers": ["example.test/finalizer"]
            },
            "type": "kubernetes.io/dockerconfigjson",
            "data": { ".dockerconfigjson": "e30=" }
        }))
        .unwrap();

        let copy = image_pull_secret_copy("regcred", "workspace", source);
        assert_eq!(copy.metadata.name.as_deref(), Some("regcred"));
        assert_eq!(copy.metadata.namespace.as_deref(), Some("workspace"));
        assert_eq!(
            copy.type_.as_deref(),
            Some("kubernetes.io/dockerconfigjson")
        );
        assert!(
            copy.data
                .as_ref()
                .unwrap()
                .contains_key(".dockerconfigjson")
        );
        assert_eq!(
            copy.metadata
                .labels
                .as_ref()
                .unwrap()
                .get(LABEL_MANAGED_BY)
                .map(String::as_str),
            Some(LABEL_MANAGED_BY_VALUE)
        );
        assert!(copy.metadata.uid.is_none());
        assert!(copy.metadata.resource_version.is_none());
        assert!(copy.metadata.annotations.is_none());
        assert!(copy.metadata.finalizers.is_none());
    }

    #[test]
    fn namespace_owned_with_correct_labels() {
        let labels = BTreeMap::from([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_GATEWAY_ID.to_string(), "gw-1".to_string()),
        ]);
        assert!(is_namespace_owned_by_gateway(Some(&labels), "gw-1"));
    }

    #[test]
    fn namespace_not_owned_missing_managed_by() {
        let labels = BTreeMap::from([(LABEL_GATEWAY_ID.to_string(), "gw-1".to_string())]);
        assert!(!is_namespace_owned_by_gateway(Some(&labels), "gw-1"));
    }

    #[test]
    fn namespace_not_owned_wrong_gateway_id() {
        let labels = BTreeMap::from([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_GATEWAY_ID.to_string(), "gw-other".to_string()),
        ]);
        assert!(!is_namespace_owned_by_gateway(Some(&labels), "gw-1"));
    }

    #[test]
    fn namespace_not_owned_no_labels() {
        assert!(!is_namespace_owned_by_gateway(None, "gw-1"));
    }

    #[test]
    fn namespace_delete_is_guarded_by_fetched_uid() {
        let params = namespace_delete_params("namespace-uid".to_string());
        assert_eq!(
            params
                .preconditions
                .and_then(|preconditions| preconditions.uid),
            Some("namespace-uid".to_string())
        );
    }

    #[test]
    fn namespace_watcher_retry_delay_is_bounded_exponential_with_jitter() {
        let seed = 42;
        let expected_ranges = [(2, 2), (4, 5), (8, 10), (16, 20), (24, 30), (24, 30)];

        for (attempt, (minimum, maximum)) in expected_ranges.into_iter().enumerate() {
            let attempt = u32::try_from(attempt).unwrap();
            let delay = namespace_watcher_retry_delay(attempt, seed).as_secs();
            assert!(
                (minimum..=maximum).contains(&delay),
                "attempt {attempt} produced {delay}s"
            );
        }
    }

    #[test]
    fn namespace_watcher_retry_delay_uses_seeded_jitter() {
        assert_ne!(
            namespace_watcher_retry_delay(3, 1),
            namespace_watcher_retry_delay(3, 2)
        );
    }

    #[test]
    fn proxy_pod_control_availability_requires_an_available_replica() {
        let mut deployment = Deployment::default();
        assert_eq!(
            proxy_pod_control_availability_from_deployment(&deployment),
            ProxyPodControlAvailability::Unavailable
        );
        deployment.status = Some(k8s_openapi::api::apps::v1::DeploymentStatus {
            available_replicas: Some(1),
            ..Default::default()
        });
        assert_eq!(
            proxy_pod_control_availability_from_deployment(&deployment),
            ProxyPodControlAvailability::Available
        );
    }

    #[test]
    fn proxy_pod_readiness_transitions_bump_the_watched_cr() {
        let unavailable = proxy_pod_readiness_transition_patch("42", "unavailable");
        let ready = proxy_pod_readiness_transition_patch("42", "ready");

        assert_eq!(unavailable["metadata"]["resourceVersion"], "42");
        assert_eq!(ready["metadata"]["resourceVersion"], "42");
        assert_eq!(
            unavailable["metadata"]["annotations"][ANNOTATION_PROXY_POD_READINESS],
            "unavailable"
        );
        assert_eq!(
            ready["metadata"]["annotations"][ANNOTATION_PROXY_POD_READINESS],
            "ready"
        );
        assert_ne!(unavailable, ready);
    }

    #[test]
    fn proxy_pod_bootstrap_completion_is_resource_version_guarded_and_publishes_ready() {
        let patch = proxy_pod_bootstrap_completion_patch("42");

        assert_eq!(patch["metadata"]["resourceVersion"], "42");
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_PROXY_POD_BOOTSTRAPPING],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_PROXY_POD_BOOTSTRAP_STARTED_AT],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_PROXY_POD_BOOTSTRAP_OPERATION],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_PROXY_POD_READINESS],
            "ready"
        );
    }

    #[test]
    fn proxy_pod_bootstrap_completion_waits_for_runtime_ready() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{"type": "Suspended", "status": "True"}]
            }
        });
        assert!(!proxy_pod_runtime_is_ready(&sandbox));

        sandbox.data["status"]["conditions"] = serde_json::json!([
            {"type": "Suspended", "status": "False"},
            {"type": "Ready", "status": "True"}
        ]);
        assert!(proxy_pod_runtime_is_ready(&sandbox));
    }

    #[test]
    fn proxy_pod_readiness_is_downgraded_with_a_transient_reason() {
        let mut sandbox = Sandbox {
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        mark_proxy_pod_control_unavailable(&mut sandbox);
        let ready = &sandbox.status.unwrap().conditions[0];
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, "DependenciesNotReady");
    }

    #[test]
    fn proxy_pod_bootstrap_does_not_publish_a_terminal_suspension() {
        let mut sandbox = Sandbox {
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: SANDBOX_SUSPENDED_CONDITION.to_string(),
                    status: "True".to_string(),
                    reason: "PodTerminated".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        mark_proxy_pod_bootstrapping(&mut sandbox);

        let conditions = &sandbox.status.unwrap().conditions;
        assert!(
            !conditions
                .iter()
                .any(|condition| condition.r#type == SANDBOX_SUSPENDED_CONDITION)
        );
        assert!(conditions.iter().any(|condition| {
            condition.r#type == "Ready"
                && condition.status == "False"
                && condition.reason == "DependenciesNotReady"
        }));
    }

    #[test]
    fn completed_proxy_pod_bootstrap_preserves_real_suspension() {
        let sandbox = Sandbox {
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: SANDBOX_SUSPENDED_CONDITION.to_string(),
                    status: "True".to_string(),
                    reason: "PodTerminated".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(sandbox.status.unwrap().conditions.iter().any(|condition| {
            condition.r#type == SANDBOX_SUSPENDED_CONDITION && condition.status == "True"
        }));
    }

    #[test]
    fn desired_proxy_pod_control_replicas_tracks_both_sandbox_apis() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut beta = DynamicObject::new("beta", &resource);
        beta.data = serde_json::json!({"spec": {"operatingMode": "Suspended"}});
        assert_eq!(desired_proxy_pod_control_replicas(&beta), 0);
        beta.data = serde_json::json!({"spec": {"operatingMode": "Running"}});
        assert_eq!(desired_proxy_pod_control_replicas(&beta), 1);

        let mut alpha = DynamicObject::new("alpha", &resource);
        alpha.data = serde_json::json!({"spec": {"replicas": 0}});
        assert_eq!(desired_proxy_pod_control_replicas(&alpha), 0);
        alpha.data = serde_json::json!({"spec": {"replicas": 1}});
        assert_eq!(desired_proxy_pod_control_replicas(&alpha), 1);
    }
}
