// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes compute driver.

use super::AppArmorProfile;
use crate::config::{
    DEFAULT_PROXY_UID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_SANDBOX_UID,
    DEFAULT_WORKSPACE_STORAGE_SIZE, KubernetesComputeConfig, OperatorNamespaceAllowlist,
    ProxyPodAffinity, ProxyPodDnsPeer, SupervisorSideloadMethod, SupervisorTopology, WorkspaceMode,
    is_dns_1123_label, managed_namespace, managed_namespace_prefix,
    validate_managed_namespace_name,
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
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_mounts;
use openshell_core::driver_utils::{
    LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAME, LABEL_SANDBOX_WORKSPACE, SUPERVISOR_IMAGE_BINARY_PATH,
    openshell_sandbox_label_selector,
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
    GetCapabilitiesResponse, GpuResourceRequirements, SupervisorSessionModel,
    WatchSandboxesDeletedEvent, WatchSandboxesEvent, WatchSandboxesPlatformEvent,
    WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use openshell_core::proto_struct::{struct_to_json_object, value_to_json};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use serde::Deserialize;
use serde::de::DeserializeOwned;
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
            KubeError::Api(api) if api.code == 409 => Self::AlreadyExists,
            other => Self::Message(other.to_string()),
        }
    }
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

/// Interval at which a proxy-pod gateway re-runs companion reconciliation while
/// its sandbox watch is established. `reconcile_proxy_pod_companions` otherwise
/// runs only at watch establishment, so a stop-time supervisor scale-down that
/// failed transiently (or an egress fence orphaned by a crash) would persist
/// until the next re-establishment. The periodic sweep bounds that window
/// without depending on the watch dropping.
const PROXY_POD_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Kubernetes defaults pod termination to 30 seconds when the pod template
/// omits `terminationGracePeriodSeconds`.
const DEFAULT_POD_TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(30);
const STOP_INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const STOP_MAX_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// After confirming the Sandbox CR is gone, the fence teardown waits out this
/// quiescence window (re-checking pod absence each interval) before deleting the
/// egress fence. It lets an in-flight controller reconciliation that read the CR
/// before deletion settle: if such a reconcile creates a dangling-ownerReference
/// workload Pod, the recheck sees it and retains the fence. A healthy controller
/// converges within its informer resync well inside this window.
const FENCE_QUIESCE_WINDOW: Duration = Duration::from_secs(6);
const FENCE_QUIESCE_INTERVAL: Duration = Duration::from_secs(2);

/// Backoff before re-establishing a supervisor Deployment watch that ended, so a
/// rare stream end does not silently drop fast readiness for the remainder of a
/// sandbox watch's lifetime.
const DEPLOYMENT_WATCH_REESTABLISH_BACKOFF: Duration = Duration::from_secs(2);

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_VERSION_V1BETA1: &str = "v1beta1";
const SANDBOX_VERSION_V1ALPHA1: &str = "v1alpha1";
const SANDBOX_VERSIONS: &[&str] = &[SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1];
pub const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_POD_NAME_ANNOTATION: &str = "agents.x-k8s.io/pod-name";
/// Records the supervisor topology a Sandbox CR was created under. The gateway's
/// configured topology can change (e.g. a Helm value edit + restart), so
/// interpreting an existing CR with the current global topology would
/// misclassify its supervisor-session model and mis-target its companion
/// Deployment. Reading this annotation keeps status and lifecycle behavior tied
/// to the topology the sandbox was actually created with.
const ANNOTATION_SUPERVISOR_TOPOLOGY: &str = "openshell.ai/supervisor-topology";
/// Records the name of the workload (agent) pod a proxy-pod egress fence guards.
/// The fence has no owner reference, so on delete/reap the gateway must confirm
/// that specific pod is gone before removing the fence — addressing it by name
/// (a scoped `get`) rather than enumerating pods cluster-wide.
const ANNOTATION_AGENT_POD_NAME: &str = "openshell.ai/agent-pod-name";
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
    /// Entrypoint override for the workload container.
    ///
    /// Only meaningful in `proxy-pod` topology, where the sandbox image runs
    /// directly. `combined` and `sidecar` replace the container command with
    /// the supervisor binary, so an override there would be silently ignored
    /// and is rejected instead.
    command: Vec<String>,
    /// Arguments for `command`, or for the image entrypoint when `command` is
    /// not set.
    args: Vec<String>,
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
    SUPERVISOR_VOLUME_NAME,
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
        // Validate DNS peers whenever this gateway may build proxy-pod
        // companions: the configured topology is proxy-pod, or a migration is
        // retaining companion management for pre-existing proxy-pod sandboxes
        // (whose supervisor could be reconstructed with these peers).
        if config.topology == SupervisorTopology::ProxyPod
            || config.proxy_pod.retain_companion_management
        {
            config
                .proxy_pod
                .validate_dns_peers()
                .map_err(KubernetesDriverError::Precondition)?;
            config
                .proxy_pod
                .validate_gateway_peers()
                .map_err(KubernetesDriverError::Precondition)?;
        }
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
    pub async fn authenticate_sandbox(
        &self,
        credential: &str,
    ) -> Result<(String, bool), tonic::Status> {
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
        // A proxy-pod agent pod carries the `agent` sandbox-role label. It is
        // authenticated as a process-scoped caller so the gateway mints a
        // narrowed `Process`-kind token that cannot read provider secrets or
        // inference routing. Every other pod is a full-authority caller.
        let scoped_process_caller = pod
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_ROLE))
            .map(String::as_str)
            == Some(SANDBOX_ROLE_AGENT);
        // Resolve the controlling Sandbox. An agent pod is directly owned by the
        // Sandbox CR; a proxy-pod supervisor pod is owned through the
        // Pod -> ReplicaSet -> Deployment -> Sandbox chain, which is walked and
        // UID-verified at each hop.
        let owner = self
            .resolve_sandbox_owner(&pod, &identity.namespace, &identity.pod_name)
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
        Ok((sandbox_id, scoped_process_caller))
    }

    /// Resolve the controlling `Sandbox` owner reference for an authenticated
    /// pod. Agent pods are owned directly by the Sandbox CR. Proxy-pod
    /// supervisor pods are owned through a `Pod -> ReplicaSet -> Deployment ->
    /// Sandbox` chain; each hop is fetched and UID-verified before trusting the
    /// next owner reference, so a pod cannot claim a Sandbox it does not belong
    /// to.
    #[allow(clippy::result_large_err)]
    async fn resolve_sandbox_owner(
        &self,
        pod: &Pod,
        namespace: &str,
        pod_name: &str,
    ) -> Result<OwnerReference, tonic::Status> {
        let pod_owners = pod.metadata.owner_references.as_deref().unwrap_or_default();
        if let Ok(owner) = sandbox_owner_reference(pod) {
            return Ok(owner.clone());
        }

        // Proxy-pod supervisor pod: walk to the controlling Deployment.
        let rs_owner = controller_owner_reference(pod_owners).ok_or_else(|| {
            tonic::Status::permission_denied("pod is not controlled by a Sandbox")
        })?;
        if rs_owner.api_version != APPS_API_VERSION_V1 || rs_owner.kind != REPLICA_SET_KIND {
            return Err(tonic::Status::permission_denied(
                "pod is not controlled by a Sandbox",
            ));
        }
        let replica_set = Api::<ReplicaSet>::namespaced(self.client.clone(), namespace)
            .get_opt(&rs_owner.name)
            .await
            .map_err(|error| {
                warn!(pod = %pod_name, replica_set = %rs_owner.name, %error, "failed to read pod controller ReplicaSet");
                tonic::Status::internal(format!("replicaset GET failed: {error}"))
            })?
            .ok_or_else(|| {
                tonic::Status::permission_denied("pod controller ReplicaSet not found")
            })?;
        validate_object_uid(
            replica_set.metadata.uid.as_deref().unwrap_or_default(),
            &rs_owner.uid,
            "pod controller ReplicaSet UID mismatch",
        )?;

        let deploy_owner = controller_owner_reference(
            replica_set
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default(),
        )
        .ok_or_else(|| {
            tonic::Status::permission_denied("ReplicaSet is not controlled by a Deployment")
        })?;
        if deploy_owner.api_version != APPS_API_VERSION_V1 || deploy_owner.kind != DEPLOYMENT_KIND {
            return Err(tonic::Status::permission_denied(
                "ReplicaSet is not controlled by a Deployment",
            ));
        }
        let deployment = Api::<Deployment>::namespaced(self.client.clone(), namespace)
            .get_opt(&deploy_owner.name)
            .await
            .map_err(|error| {
                warn!(pod = %pod_name, deployment = %deploy_owner.name, %error, "failed to read controller Deployment");
                tonic::Status::internal(format!("deployment GET failed: {error}"))
            })?
            .ok_or_else(|| {
                tonic::Status::permission_denied("ReplicaSet controller Deployment not found")
            })?;
        validate_object_uid(
            deployment.metadata.uid.as_deref().unwrap_or_default(),
            &deploy_owner.uid,
            "ReplicaSet controller Deployment UID mismatch",
        )?;

        let sandbox_owner = sandbox_owner_from_refs(
            deployment
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default(),
        )?;
        Ok(sandbox_owner.clone())
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
        &self,
        sandbox: &Sandbox,
    ) -> Result<KubernetesSandboxDriverConfig, String> {
        let config = kubernetes_driver_config_for_spec(
            sandbox.spec.as_ref(),
            self.config.provider_spiffe_enabled().then_some(
                self.config
                    .provider_spiffe_workload_api_socket_path
                    .as_str(),
            ),
        )?;
        validate_agent_command_for_topology(&config, self.config.topology)?;
        Ok(config)
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

    /// Live existence check for a Sandbox CR by sandbox id, scoped to this
    /// gateway. `Some(true)`/`Some(false)` when the answer is known; `None` when
    /// an API error or timeout makes it undeterminable (callers must treat that
    /// as "cannot confirm absent" and retain, never delete).
    async fn sandbox_cr_exists(&self, sandbox_id: &str) -> Option<bool> {
        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .ok()?;
        let lp = ListParams::default()
            .labels(&self.sandbox_lookup_selector(sandbox_id))
            .limit(1);
        match tokio::time::timeout(KUBE_API_TIMEOUT, lookup_api.api.list(&lp)).await {
            Ok(Ok(list)) => Some(!list.items.is_empty()),
            Ok(Err(err)) => {
                warn!(sandbox_id = %sandbox_id, error = %err, "Could not confirm Sandbox CR existence");
                None
            }
            Err(_elapsed) => {
                warn!(sandbox_id = %sandbox_id, "Timed out confirming Sandbox CR existence");
                None
            }
        }
    }

    fn openshell_sandbox_selector(&self) -> String {
        openshell_sandbox_selector_for(&self.config.gateway_id)
    }

    /// Label selector matching this gateway's proxy-pod supervisor Deployments.
    /// Scopes the supervisor Deployment watch to this gateway's supervisors so a
    /// Deployment availability change can be turned into a sandbox readiness
    /// refresh without observing unrelated Deployments.
    fn proxy_pod_supervisor_selector(&self) -> String {
        format!(
            "{},{LABEL_SANDBOX_ROLE}={SANDBOX_ROLE_SUPERVISOR}",
            self.openshell_sandbox_selector()
        )
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
        let _ = self
            .validate_driver_config_for_sandbox(sandbox)
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
        // No override: the fold checks live supervisor availability itself.
        self.lookup_sandbox_with_readiness(sandbox_id, None).await
    }

    /// Look up a Sandbox CR by id and build its `Sandbox`, folding proxy-pod
    /// supervisor readiness. `availability_override` supplies a supervisor
    /// availability already known to the caller (e.g. a Deployment watch event),
    /// avoiding a redundant Deployment GET that could otherwise fail open.
    async fn lookup_sandbox_with_readiness(
        &self,
        sandbox_id: &str,
        availability_override: Option<SupervisorAvailability>,
    ) -> Result<Option<Sandbox>, String> {
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
                // Capture identity before `sandbox_from_object` consumes the object.
                let cr_topology = topology_from_object(&obj, self.config.topology);
                let cr_name = obj.metadata.name.clone().unwrap_or_default();
                let cr_sandbox_id = sandbox_id_from_object(&obj).unwrap_or_default();
                let Ok((_, mut sandbox)) = sandbox_from_object(&ns, obj, self.config.topology)
                else {
                    return Ok(None);
                };
                self.apply_proxy_pod_supervisor_readiness(
                    &mut sandbox,
                    cr_topology,
                    &cr_name,
                    &cr_sandbox_id,
                    &ns,
                    availability_override,
                )
                .await;
                Ok(Some(sandbox))
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
                let mut sandboxes: Vec<Sandbox> = Vec::with_capacity(list.items.len());
                for obj in list.items {
                    let name = obj.metadata.name.clone().unwrap_or_default();
                    let ns = obj
                        .metadata
                        .namespace
                        .clone()
                        .unwrap_or_else(|| self.config.namespace.clone());
                    // Capture identity before `sandbox_from_object` consumes the
                    // object so a proxy-pod sandbox's readiness can be checked
                    // against its live supervisor Deployment.
                    let cr_topology = topology_from_object(&obj, self.config.topology);
                    let cr_name = obj.metadata.name.clone().unwrap_or_default();
                    let sandbox_id = sandbox_id_from_object(&obj).unwrap_or_default();
                    match sandbox_from_object(&ns, obj, self.config.topology) {
                        Ok((_, mut sandbox)) => {
                            // The agent pod's Ready condition does not reflect the
                            // separate supervisor Deployment. Without this, a
                            // sandbox whose supervisor died after startup would
                            // stay Ready while policy-enforced egress is dead.
                            self.apply_proxy_pod_supervisor_readiness(
                                &mut sandbox,
                                cr_topology,
                                &cr_name,
                                &sandbox_id,
                                &ns,
                                None,
                            )
                            .await;
                            sandboxes.push(sandbox);
                        }
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
        name = "kubernetes.create_sandbox",
        skip(self, sandbox),
        fields(
            otel.name = "kubernetes.create_sandbox",
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

        let cr_name = self.config.kube_resource_name(workspace, name);
        let params = self.build_sandbox_pod_params(
            sandbox,
            &target_namespace,
            &cr_name,
            resolved_user_id,
            resolved_group_id,
            self.config.topology,
        );
        validate_proxy_identity(&params)?;

        let data = sandbox_to_k8s_spec(sandbox.spec.as_ref(), &params)
            .map_err(KubernetesDriverError::InvalidArgument)?;
        let kube_name = cr_name.clone();
        let mut obj = DynamicObject::new(&kube_name, &agent_sandbox_api.resource);
        let mut annotations = sandbox_annotations(sandbox);
        add_trace_context_annotation(&mut annotations);
        for key in [
            crate::config::ANNOTATION_SCC_UID_RANGE,
            crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
        ] {
            if let Some(v) = ns_annotations.get(key) {
                annotations.insert(key.to_string(), v.clone());
            }
        }
        // Persist the creation-time topology so watch/list and start/stop derive
        // status and companion behavior from it rather than the gateway's
        // current global config, which may have changed since creation.
        annotations.insert(
            ANNOTATION_SUPERVISOR_TOPOLOGY.to_string(),
            self.config.topology.to_string(),
        );
        obj.metadata = ObjectMeta {
            name: Some(kube_name),
            // Clone: `params` borrows `target_namespace` for later companion
            // creation.
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

        if self.config.topology == SupervisorTopology::ProxyPod
            && let Err(err) = self
                .create_proxy_pod_resources(
                    sandbox,
                    sandbox.spec.as_ref(),
                    &params,
                    &created,
                    &agent_sandbox_api.resource.api_version,
                )
                .await
        {
            warn!(
                sandbox_id = %sandbox.id,
                sandbox_name = %name,
                error = %err,
                "Failed to create proxy-pod resources; deleting Sandbox CR"
            );
            // Delete the CR we actually created, addressed by its returned name
            // (the workspace-scoped CR name, not the bare sandbox name) and
            // guarded by its UID so we never remove a same-named successor.
            // Owner-referenced companions are garbage-collected with the CR.
            let created_name = created.metadata.name.as_deref().unwrap_or(params.cr_name);
            let mut delete_params = DeleteParams::default();
            if let Some(uid) = created.metadata.uid.clone() {
                delete_params = delete_params.preconditions(Preconditions {
                    uid: Some(uid),
                    resource_version: None,
                });
            }
            let cr_deleted = match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                agent_sandbox_api.api.delete(created_name, &delete_params),
            )
            .await
            {
                Ok(Ok(_)) => true,
                Ok(Err(KubeError::Api(err))) if err.code == 404 => true,
                _ => false,
            };
            // The agent egress NetworkPolicy carries no owner reference, so GC
            // will not collect it. Only tear the fence down once the CR is
            // confirmed gone AND the workload pod is gone: if the CR delete
            // failed (never reached Kubernetes, timed out, precondition
            // conflict), the surviving CR could still create an unfenced
            // workload, so the fence must stay. A retained fence is reaped by
            // reconciliation once its CR is truly absent.
            if cr_deleted {
                self.teardown_proxy_pod_fence(
                    params.namespace,
                    params.cr_name,
                    created.metadata.uid.as_deref(),
                    &sandbox.id,
                    DEFAULT_POD_TERMINATION_GRACE_PERIOD.saturating_add(KUBE_API_TIMEOUT),
                )
                .await;
            } else {
                warn!(
                    sandbox_id = %sandbox.id,
                    "Sandbox CR deletion unconfirmed on rollback; retaining egress fence"
                );
            }
            return Err(err);
        }

        Ok(())
    }

    /// Assemble the `SandboxPodParams` from gateway config for a sandbox. Shared
    /// by the create path and the proxy-pod companion reconciliation path so both
    /// render identical companions.
    #[allow(clippy::similar_names)]
    fn build_sandbox_pod_params<'a>(
        &'a self,
        sandbox: &'a Sandbox,
        target_namespace: &'a str,
        cr_name: &'a str,
        sandbox_uid: u32,
        sandbox_gid: u32,
        // The topology to render for. Normally the gateway's configured topology,
        // but companion reconstruction passes the CR's *persisted* topology so a
        // proxy-pod sandbox is rebuilt with proxy-pod parameters (its supervisor
        // UID, not the sidecar UID) even after the gateway's configured topology
        // has been migrated away from proxy-pod.
        topology: SupervisorTopology,
    ) -> SandboxPodParams<'a> {
        SandboxPodParams {
            default_image: &self.config.default_image,
            image_pull_policy: &self.config.image_pull_policy,
            image_pull_secrets: &self.config.image_pull_secrets,
            supervisor_image: &self.config.supervisor_image,
            supervisor_image_pull_policy: &self.config.supervisor_image_pull_policy,
            supervisor_sideload_method: self.config.supervisor_sideload_method,
            topology,
            proxy_uid: match topology {
                SupervisorTopology::ProxyPod => self.config.proxy_pod.proxy_uid,
                SupervisorTopology::Combined | SupervisorTopology::Sidecar => {
                    self.config.sidecar.proxy_uid
                }
            },
            process_binary_aware_network_policy: self
                .config
                .sidecar
                .process_binary_aware_network_policy,
            https_proxy: self.config.https_proxy.as_deref(),
            no_proxy: self.config.no_proxy.as_deref(),
            proxy_auth_secret_name: self.config.proxy_auth_secret_name.as_deref(),
            proxy_auth_secret_key: self.config.proxy_auth_secret_key.as_deref(),
            proxy_auth_allow_insecure: self.config.proxy_auth_allow_insecure == Some(true),
            proxy_connect_by_hostname: self.config.proxy_connect_by_hostname == Some(true),
            proxy_pod_affinity: self.config.proxy_pod.affinity,
            proxy_pod_dns_peers: &self.config.proxy_pod.dns_peers,
            proxy_pod_gateway_peers: &self.config.proxy_pod.gateway_peers,
            namespace: target_namespace,
            service_account_name: &self.config.service_account_name,
            sandbox_id: &sandbox.id,
            sandbox_name: &sandbox.name,
            gateway_id: &self.config.gateway_id,
            cr_name,
            grpc_endpoint: &self.config.grpc_endpoint,
            ssh_socket_path: self.ssh_socket_path(),
            client_tls_secret_name: &self.config.client_tls_secret_name,
            host_gateway_ip: &self.config.host_gateway_ip,
            enable_user_namespaces: self.config.enable_user_namespaces,
            app_armor_profile: self.config.app_armor_profile.as_ref(),
            workspace_default_storage_size: &self.config.workspace_default_storage_size,
            workspace_storage_class: &self.config.workspace_storage_class,
            default_runtime_class_name: &self.config.default_runtime_class_name,
            sa_token_ttl_secs: self.config.effective_sa_token_ttl_secs(),
            provider_spiffe_enabled: self.config.provider_spiffe_enabled(),
            provider_spiffe_workload_api_socket_path: &self
                .config
                .provider_spiffe_workload_api_socket_path,
            sandbox_uid,
            sandbox_gid,
        }
    }

    async fn create_proxy_pod_resources(
        &self,
        sandbox: &Sandbox,
        spec: Option<&SandboxSpec>,
        params: &SandboxPodParams<'_>,
        sandbox_cr: &DynamicObject,
        sandbox_api_version: &str,
    ) -> Result<(), KubernetesDriverError> {
        // Companion names derive from the Sandbox CR name, which is unique per
        // sandbox in every workspace mode. The bare sandbox name collides in
        // shared mode, where `workspace-a/dev` and `workspace-b/dev` both have
        // sandbox name `dev`.
        let cr_name = sandbox_cr
            .metadata
            .name
            .as_deref()
            .unwrap_or(sandbox.name.as_str());
        let names = proxy_pod_resource_names(cr_name, &sandbox.id);
        let template_environment = spec
            .and_then(|spec| spec.template.as_ref())
            .map(|template| template.environment.clone())
            .unwrap_or_default();
        let spec_environment = spec_pod_env(spec);
        let deployment_owner_ref =
            proxy_pod_owner_reference(sandbox_cr, sandbox_api_version, true)?;
        let dependent_owner_ref =
            proxy_pod_owner_reference(sandbox_cr, sandbox_api_version, false)?;
        let (ca_cert_pem, ca_key_pem) = generate_proxy_pod_ca()?;

        // Give the supervisor the workload's node placement so same-node
        // affinity resolves to a node the workload can also use. Both the
        // driver_config.pod placement and the public platform_config placement
        // (runtime class, node selector, tolerations) the workload honors must
        // be mirrored here.
        let pod_driver_config = spec
            .and_then(|spec| spec.template.as_ref())
            .and_then(|template| KubernetesSandboxDriverConfig::from_template(template).ok())
            .map(|config| config.pod)
            .unwrap_or_default();
        let placement =
            ProxyPodPlacement::from_template(spec.and_then(|spec| spec.template.as_ref()));
        let companions = build_proxy_pod_companions(
            &names,
            params,
            &template_environment,
            &spec_environment,
            &pod_driver_config,
            &placement,
            // A newly created sandbox starts running.
            1,
            deployment_owner_ref,
            dependent_owner_ref,
            &ca_cert_pem,
            &ca_key_pem,
        );
        self.apply_proxy_pod_companions(params.namespace, &companions)
            .await?;

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            supervisor_deployment = %names.supervisor_deployment,
            service = %names.service,
            "Created proxy-pod supervisor resources"
        );
        Ok(())
    }

    /// Idempotently apply a proxy-pod companion set. Each object is created only
    /// if absent (an `AlreadyExists` conflict is treated as success), so this is
    /// safe to run from both the create path and the restart reconciliation
    /// path. Purely additive: an existing CA Secret keeps its key material (no
    /// rotation) and an existing supervisor Deployment keeps its replica count
    /// (a stopped sandbox is not restarted).
    async fn apply_proxy_pod_companions(
        &self,
        namespace: &str,
        companions: &ProxyPodCompanions,
    ) -> Result<(), KubernetesDriverError> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let services: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);

        // The CA Secret skips ownership verification: the gateway holds no
        // Secret read permission, and the UUID-keyed name already implies the
        // object is this sandbox's own.
        create_companion_if_absent(&secrets, &companions.secret, "proxy-pod CA secret", false)
            .await?;
        create_companion_if_absent(&services, &companions.service, "proxy-pod service", true)
            .await?;
        // The egress fence carries no owner reference (it is gateway-managed), so
        // owner-based verification cannot vouch for it. Validate its enforcement
        // fields instead: an existing same-name policy must fence exactly this
        // agent, or a stale/altered one would be silently accepted.
        create_or_validate_egress_fence(&policies, &companions.agent_egress).await?;
        create_companion_if_absent(
            &policies,
            &companions.supervisor_ingress,
            "proxy-pod supervisor ingress NetworkPolicy",
            true,
        )
        .await?;
        create_companion_if_absent(
            &deployments,
            &companions.supervisor_deployment,
            "proxy-pod supervisor deployment",
            true,
        )
        .await?;
        Ok(())
    }

    /// Downgrade a proxy-pod sandbox's readiness to `NotReady` when its
    /// supervisor Deployment has no available replica. Shared by `get_sandbox`
    /// and `list_sandboxes` so both the reconcile loop's status refresh and
    /// direct queries reflect supervisor liveness. A no-op for other topologies.
    async fn apply_proxy_pod_supervisor_readiness(
        &self,
        sandbox: &mut Sandbox,
        topology: SupervisorTopology,
        cr_name: &str,
        sandbox_id: &str,
        namespace: &str,
        availability_override: Option<SupervisorAvailability>,
    ) {
        if topology != SupervisorTopology::ProxyPod || sandbox_id.is_empty() {
            return;
        }
        // Prefer a caller-supplied availability (e.g. taken directly from a
        // Deployment watch event) over a fresh GET: it reflects the exact state
        // that triggered the refresh and cannot fail open on a transient error.
        let availability = if let Some(availability) = availability_override {
            availability
        } else {
            let names = proxy_pod_resource_names(cr_name, sandbox_id);
            self.proxy_pod_supervisor_availability(namespace, &names.supervisor_deployment)
                .await
        };
        // Fail closed: readiness is only `Ready` when the supervisor is
        // *confirmed* available. The CR's own `Ready=True` reflects the agent
        // pod, not the separate supervisor, so leaving it intact on `Unknown`
        // (a GET error/timeout) would republish a possibly-dead-egress sandbox
        // as Ready and could overwrite a prior `DependenciesNotReady`. Only a
        // confirmed `Available` keeps `Ready`.
        if availability != SupervisorAvailability::Available {
            mark_supervisor_unavailable(sandbox);
        }
    }

    /// Tri-state availability of a proxy-pod sandbox's supervisor Deployment. A
    /// missing Deployment is `Unavailable`; a transient API error is `Unknown`.
    /// Callers fail closed (treat non-`Available` as not ready), so `Unknown` is
    /// kept distinct only so a definite absence and an undeterminable check read
    /// the same to readiness without conflating them in logs.
    async fn proxy_pod_supervisor_availability(
        &self,
        namespace: &str,
        deployment_name: &str,
    ) -> SupervisorAvailability {
        proxy_pod_supervisor_availability(&self.client, namespace, deployment_name).await
    }

    /// Spawn a periodic proxy-pod companion reconciliation bound to a sandbox
    /// watch's lifetime. `reconcile_proxy_pod_companions` otherwise runs only at
    /// watch establishment, which leaves a transiently-failed supervisor
    /// scale-down (or a crash-orphaned egress fence) uncorrected until the watch
    /// re-establishes. The periodic sweep bounds that window to
    /// `PROXY_POD_RECONCILE_INTERVAL`.
    ///
    /// Scheduled only when this gateway manages proxy-pod sandboxes (`enabled`):
    /// either its configured topology is proxy-pod, or a `retainCompanionRbac`
    /// migration left proxy-pod sandboxes it still owns. The task exits when the
    /// watch stream consumer drops its receiver (observed through `tx.closed()`),
    /// so each new watch establishment replaces the previous reconcile task
    /// rather than accumulating one.
    fn spawn_proxy_pod_periodic_reconcile(
        &self,
        tx: mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
        enabled: bool,
    ) {
        if !enabled {
            return;
        }
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROXY_POD_RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; discard it because
            // `watch_sandboxes` already reconciled before establishing the watch.
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => { driver.reconcile_proxy_pod_companions().await; },
                    () = tx.closed() => break,
                }
            }
        });
    }

    /// Repair proxy-pod companions for every existing Sandbox CR. A gateway
    /// crash between the CR create and its companion creates leaves a persisted
    /// CR with a partial topology that ordinary reconciliation never repairs,
    /// because the CR already exists. Runs on each `watch_sandboxes` call
    /// (gateway start and watch re-establishment) and periodically thereafter
    /// via `spawn_proxy_pod_periodic_reconcile`. Best-effort: failures are
    /// logged, not fatal.
    ///
    /// Whether background upkeep (periodic reconcile, readiness watch) stays
    /// scheduled is decided from configuration in `watch_sandboxes`, not from
    /// this pass — a transient discovery failure here must never disable it.
    async fn reconcile_proxy_pod_companions(&self) {
        // Driven by each CR's persisted creation-time topology, not the
        // gateway's current config: a gateway whose Helm topology was changed to
        // `combined` must still reconcile sandboxes that were created as
        // `proxy-pod` (whose companions and lifecycle it still owns). The
        // per-CR filter below selects those.
        let lookup_api = match self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
        {
            Ok(api) => api,
            Err(err) => {
                warn!(error = %err, "Skipping proxy-pod companion reconciliation: sandbox API unavailable");
                return;
            }
        };
        let api_version = format!("{SANDBOX_GROUP}/{}", lookup_api.resource.version);
        // Gateway-scoped selector: never touch another gateway's sandboxes,
        // whose companions carry that gateway's image, endpoint, and config.
        let lp = ListParams::default().labels(&self.openshell_sandbox_selector());
        let list = match tokio::time::timeout(KUBE_API_TIMEOUT, lookup_api.api.list(&lp)).await {
            Ok(Ok(list)) => list,
            Ok(Err(err)) => {
                warn!(error = %err, "Skipping proxy-pod companion reconciliation: list failed");
                return;
            }
            Err(_elapsed) => {
                warn!("Skipping proxy-pod companion reconciliation: list timed out");
                return;
            }
        };

        let mut checked = 0usize;
        let mut failed = 0usize;
        let mut live_sandbox_ids = HashSet::new();
        for obj in list.items {
            if !is_openshell_managed(&obj)
                || topology_from_object(&obj, self.config.topology) != SupervisorTopology::ProxyPod
            {
                continue;
            }
            if let Ok(id) = sandbox_id_from_object(&obj) {
                live_sandbox_ids.insert(id);
            }
            checked += 1;
            if let Err(err) = self
                .ensure_proxy_pod_companions_for_cr(&obj, &api_version)
                .await
            {
                failed += 1;
                warn!(
                    cr_name = ?obj.metadata.name,
                    error = %err,
                    "Failed to reconcile proxy-pod companions"
                );
            }
        }
        if checked > 0 {
            info!(
                checked,
                failed, "Reconciled proxy-pod companions for existing sandboxes"
            );
        }

        // Reap orphaned egress fences: the agent egress NetworkPolicy has no
        // owner reference (so it can outlive its workload pod on delete), which
        // means a gateway crash between CR deletion and fence teardown leaves it
        // behind. Delete any whose sandbox CR no longer exists.
        self.reap_orphaned_egress_fences(&live_sandbox_ids).await;
    }

    /// Delete agent egress `NetworkPolicy` objects whose Sandbox CR is gone.
    /// Their CRs having been reaped means the workload pods were torn down with
    /// them, so removing the now-purposeless fence is safe.
    async fn reap_orphaned_egress_fences(&self, live_sandbox_ids: &HashSet<String>) {
        let policies: Api<NetworkPolicy> = if self.config.is_multi_namespace() {
            Api::all(self.client.clone())
        } else {
            Api::namespaced(self.client.clone(), &self.config.namespace)
        };
        // Gateway-scoped, agent-role egress policies only.
        let selector = format!(
            "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_GATEWAY_ID}={},{LABEL_SANDBOX_ROLE}={SANDBOX_ROLE_AGENT}",
            self.config.gateway_id
        );
        let list = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            policies.list(&ListParams::default().labels(&selector)),
        )
        .await
        {
            Ok(Ok(list)) => list,
            Ok(Err(err)) => {
                warn!(error = %err, "Skipping orphaned egress fence reap: list failed");
                return;
            }
            Err(_elapsed) => {
                warn!("Skipping orphaned egress fence reap: list timed out");
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
            if sandbox_id.is_empty() || live_sandbox_ids.contains(&sandbox_id) {
                continue;
            }
            let Some(name) = policy.metadata.name.as_deref() else {
                continue;
            };
            let ns = policy
                .metadata
                .namespace
                .as_deref()
                .unwrap_or(&self.config.namespace)
                .to_string();
            // The guarded workload pod's name, recorded on the fence at creation.
            let Some(pod_name) = policy
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(ANNOTATION_AGENT_POD_NAME))
                .filter(|value| !value.is_empty())
            else {
                debug!(policy = %name, "Retaining orphaned egress fence: no recorded workload pod name");
                continue;
            };
            // `live_sandbox_ids` was snapshotted before this policy list, so a
            // sandbox created in that window (CR then fence, in that order) is
            // absent from it and would look orphaned. Re-confirm the CR is gone
            // immediately before deleting; retain on "exists" or "unknown" so a
            // freshly created sandbox never loses its egress fence to the reaper.
            if self.sandbox_cr_exists(&sandbox_id).await != Some(false) {
                debug!(sandbox_id = %sandbox_id, policy = %name, "Retaining egress fence: Sandbox CR not confirmed absent");
                continue;
            }
            // The CR is gone, but background garbage collection may still be
            // terminating the workload pod. Only drop the fence once that pod is
            // confirmed absent; retain it (this sweep or a later one reaps it)
            // when absence cannot be confirmed, so a SIGTERM-ignoring workload
            // never regains direct egress.
            if self.workload_pod_absent(&ns, pod_name).await != Some(true) {
                debug!(sandbox_id = %sandbox_id, policy = %name, "Retaining orphaned egress fence: workload pod not confirmed absent");
                continue;
            }
            let scoped: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), &ns);
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                scoped.delete(name, &DeleteParams::default()),
            )
            .await
            {
                Ok(Ok(_)) => {
                    info!(sandbox_id = %sandbox_id, policy = %name, "Reaped orphaned proxy-pod egress fence");
                }
                Ok(Err(KubeError::Api(_))) => {}
                Ok(Err(err)) => {
                    warn!(policy = %name, error = %err, "Failed to reap orphaned egress fence");
                }
                Err(_elapsed) => {
                    warn!(policy = %name, "Timed out reaping orphaned egress fence");
                }
            }
        }
    }

    /// Ensure the companions for a single Sandbox CR exist, reconstructing the
    /// render inputs from the CR itself. Placement (node selector, tolerations,
    /// runtime class) and the log level are read back from the CR's rendered
    /// agent pod so a repaired supervisor lands where the workload can pair with
    /// it. Application is idempotent, so present companions are left untouched.
    #[allow(clippy::similar_names)]
    async fn ensure_proxy_pod_companions_for_cr(
        &self,
        obj: &DynamicObject,
        sandbox_api_version: &str,
    ) -> Result<(), KubernetesDriverError> {
        let cr_name =
            obj.metadata.name.clone().ok_or_else(|| {
                KubernetesDriverError::Message("sandbox CR has no name".to_string())
            })?;
        let namespace = obj
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.config.namespace.clone());
        let sandbox = Sandbox {
            id: sandbox_id_from_object(obj).unwrap_or_default(),
            name: annotation_or_label(obj, LABEL_SANDBOX_NAME).unwrap_or_default(),
            namespace: namespace.clone(),
            spec: None,
            status: None,
            workspace: annotation_or_label(obj, LABEL_SANDBOX_WORKSPACE).unwrap_or_default(),
        };
        if sandbox.id.is_empty() {
            return Err(KubernetesDriverError::Message(format!(
                "sandbox CR {cr_name} has no sandbox id; cannot derive companion names"
            )));
        }
        let (sandbox_uid, sandbox_gid, _annotations) =
            self.resolve_sandbox_identity_in_namespace(&namespace).await;
        // This path only reconstructs proxy-pod companions (the caller filters to
        // proxy-pod CRs), so render with proxy-pod parameters regardless of the
        // gateway's currently-configured topology — otherwise a migrated
        // combined/sidecar gateway would rebuild the supervisor with the sidecar
        // UID instead of the proxy-pod supervisor UID.
        let params = self.build_sandbox_pod_params(
            &sandbox,
            &namespace,
            &cr_name,
            sandbox_uid,
            sandbox_gid,
            SupervisorTopology::ProxyPod,
        );
        let names = proxy_pod_resource_names(&cr_name, &sandbox.id);
        let deployment_owner_ref = proxy_pod_owner_reference(obj, sandbox_api_version, true)?;
        let dependent_owner_ref = proxy_pod_owner_reference(obj, sandbox_api_version, false)?;
        // A fresh CA is generated but only used if the Secret is missing;
        // create-if-absent keeps an existing CA rather than rotating it.
        let (ca_cert_pem, ca_key_pem) = generate_proxy_pod_ca()?;
        let placement = proxy_pod_placement_from_cr(obj);
        let spec_environment = proxy_pod_log_level_env_from_cr(obj);
        // Derive the desired supervisor replica count from the CR's operating
        // state so a missing Deployment is recreated with the right count.
        let replicas = desired_supervisor_replicas(obj);
        let companions = build_proxy_pod_companions(
            &names,
            &params,
            &std::collections::HashMap::new(),
            &spec_environment,
            &KubernetesPodDriverConfig::default(),
            &placement,
            replicas,
            deployment_owner_ref,
            dependent_owner_ref,
            &ca_cert_pem,
            &ca_key_pem,
        );
        self.apply_proxy_pod_companions(&namespace, &companions)
            .await?;
        // Reconcile replica drift on an already-existing Deployment (create is
        // idempotent and does not touch it): a crash between the CR operating-
        // state patch and the scale could otherwise leave a running workload
        // with zero supervisors, or a stopped sandbox with a live one.
        self.scale_proxy_pod_supervisor(
            &cr_name,
            &sandbox.id,
            &namespace,
            SupervisorTopology::ProxyPod,
            replicas,
        )
        .await
    }

    /// Scale a sandbox's paired supervisor `Deployment`.
    ///
    /// The supervisor runs in its own `Deployment`, so it does not stop when
    /// the agent pod does. Without this, a stopped sandbox keeps consuming a
    /// pod slot, CPU, and memory indefinitely.
    ///
    /// Failures are logged and swallowed. A supervisor that fails to scale down
    /// wastes resources but does not break the stop; a supervisor that fails to
    /// scale up is retried by the agent pod's connection attempts and surfaces
    /// as a normal readiness failure. Neither should fail the caller's
    /// start/stop RPC.
    /// Scale a proxy-pod sandbox's supervisor Deployment.
    ///
    /// `cr_name` is the Sandbox CR resource name (cosmetic in the companion
    /// names); `sandbox_id` is the immutable UUID the companion names are keyed
    /// on. `namespace` is the sandbox's resolved namespace.
    async fn scale_proxy_pod_supervisor(
        &self,
        cr_name: &str,
        sandbox_id: &str,
        namespace: &str,
        topology: SupervisorTopology,
        replicas: u32,
    ) -> Result<(), KubernetesDriverError> {
        if topology != SupervisorTopology::ProxyPod {
            return Ok(());
        }
        let names = proxy_pod_resource_names(cr_name, sandbox_id);
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let patch = serde_json::json!({"spec": {"replicas": replicas}});
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            deployments.patch(
                &names.supervisor_deployment,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            ),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(
                    cr_name = %cr_name,
                    deployment = %names.supervisor_deployment,
                    replicas,
                    "Scaled proxy-pod supervisor Deployment"
                );
                Ok(())
            }
            Ok(Err(err)) => Err(KubernetesDriverError::from_kube(err)),
            Err(_elapsed) => Err(KubernetesDriverError::Message(format!(
                "timed out after {}s scaling proxy-pod supervisor Deployment {}",
                KUBE_API_TIMEOUT.as_secs(),
                names.supervisor_deployment
            ))),
        }
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
        let (agent_sandbox_api, kube_name, pod_name, namespace, stop_timeout, topology) = self
            .patch_sandbox_operating_state(sandbox_id, false)
            .await?;
        let stopped = self
            .wait_for_sandbox_stopped(
                &agent_sandbox_api,
                &kube_name,
                &pod_name,
                &namespace,
                stop_timeout,
            )
            .await;
        // Scale the paired supervisor down only once the workload has actually
        // stopped, so a graceful shutdown that needs egress still has it. This
        // is best-effort: the workload is already stopped, so a failed
        // scale-down only wastes supervisor resources and must not fail the
        // stop. A later start or delete reconciles the replica count.
        if stopped.is_ok()
            && let Err(err) = self
                .scale_proxy_pod_supervisor(&kube_name, sandbox_id, &namespace, topology, 0)
                .await
        {
            warn!(
                sandbox_id = %sandbox_id,
                cr_name = %kube_name,
                error = %err,
                "Failed to scale proxy-pod supervisor down on stop"
            );
        }
        stopped
    }

    async fn wait_for_sandbox_stopped(
        &self,
        agent_sandbox_api: &AgentSandboxApi,
        kube_name: &str,
        pod_name: &str,
        namespace: &str,
        stop_timeout: Duration,
    ) -> Result<(), KubernetesDriverError> {
        let pod_api = Api::<Pod>::namespaced(self.client.clone(), namespace);

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
                agent_sandbox_api.api.get(kube_name),
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
            let pod_is_gone = kubernetes_sandbox_pod_is_gone(&pod_api, pod_name, deadline)
                .await
                .map_err(KubernetesDriverError::Message)?;
            if kubernetes_sandbox_stop_is_complete(
                &agent_sandbox_api.resource.version,
                &object,
                pod_is_gone,
            ) {
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
        let result = self.start_sandbox_inner(sandbox_id).await;
        span_status.finish(result)
    }

    async fn start_sandbox_inner(&self, sandbox_id: &str) -> Result<(), KubernetesDriverError> {
        let (_api, kube_name, _pod_name, namespace, _timeout, topology) =
            self.patch_sandbox_operating_state(sandbox_id, true).await?;
        // Propagate scale-up failure: the agent pod cannot itself retry a
        // Deployment scale, so a swallowed error would wedge the sandbox in
        // Starting with a supervisor stuck at zero replicas.
        self.scale_proxy_pod_supervisor(&kube_name, sandbox_id, &namespace, topology, 1)
            .await?;
        Ok(())
    }

    async fn patch_sandbox_operating_state(
        &self,
        sandbox_id: &str,
        running: bool,
    ) -> Result<
        (
            AgentSandboxApi,
            String,
            String,
            String,
            Duration,
            SupervisorTopology,
        ),
        KubernetesDriverError,
    > {
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
        // Resolve topology from the CR itself so start/stop scales the companion
        // Deployment based on how the sandbox was created, not the gateway's
        // current global topology.
        let topology = topology_from_object(&object, self.config.topology);
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
        let kube_name = object.metadata.name.ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no name".to_string())
        })?;
        let pod_name = object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
            .cloned()
            .unwrap_or_else(|| kube_name.clone());
        let resource_version = object.metadata.resource_version.unwrap_or_default();
        let desired = sandbox_operating_state_patch(
            &agent_sandbox_api.resource.version,
            &resource_version,
            running,
        );
        tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api.api.patch(
                &kube_name,
                &PatchParams::default(),
                &Patch::Merge(&desired),
            ),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
        .map_err(KubernetesDriverError::from_kube)?;

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
            topology,
        ))
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
        let (kube_name, obj_namespace, _workspace, preconditions, topology, stop_timeout) =
            match tokio::time::timeout(KUBE_API_TIMEOUT, lookup_api.api.list(&lp)).await {
                Ok(Ok(list)) => {
                    if let Some(obj) = list.items.into_iter().next() {
                        // Read fields that borrow the object before its `name` is moved.
                        let topology = topology_from_object(&obj, self.config.topology);
                        let stop_timeout = kubernetes_sandbox_stop_timeout(&obj);
                        match obj.metadata.name {
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
                                (name, ns, ws, pc, topology, stop_timeout)
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
        // Capture the UID before it is moved into the delete preconditions; the
        // post-delete fence teardown re-checks that this exact CR is gone.
        let cr_uid = preconditions.uid.clone();
        let dp = DeleteParams::default().preconditions(preconditions);
        // Delete the Sandbox CR. Owner-referenced companions (supervisor
        // Deployment, Service, CA Secret, supervisor-ingress NetworkPolicy) are
        // reaped by garbage collection. The agent egress NetworkPolicy — the
        // workload's fence — has no owner reference and is torn down explicitly
        // below, only after the workload pod is gone, so a pod that ignores
        // SIGTERM cannot regain direct egress during its termination grace
        // period. The UID precondition means a 409 (replacement) or 404 leaves a
        // successor untouched.
        let deleted = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            delete_api.api.delete(&kube_name, &dp),
        )
        .await
        {
            Ok(Ok(_response)) => {
                info!(sandbox_id = %sandbox_id, namespace = %obj_namespace, "Sandbox deleted from Kubernetes");
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
        };

        // Ordered fence teardown for proxy-pod: only after THIS CR was confirmed
        // deleted, wait for the workload pod to disappear, then delete its egress
        // NetworkPolicy. A 409/404 (`Ok(false)`) means a successor owns the name,
        // so we must not touch its fence.
        if matches!(deleted, Ok(true)) && topology == SupervisorTopology::ProxyPod {
            self.teardown_proxy_pod_fence(
                &obj_namespace,
                &kube_name,
                cr_uid.as_deref(),
                sandbox_id,
                stop_timeout,
            )
            .await;
        }
        deleted
    }

    /// Report whether the named workload (agent) pod is absent.
    ///
    /// Uses a name-scoped `get` (not a label `list`) so it needs only `pods:get`,
    /// never cluster-wide pod enumeration. The workload pod is named after its
    /// Sandbox CR, and that name is stamped on the fence so every path (delete,
    /// rollback, reaper) can address it exactly. `Some(true)` means the pod does
    /// not exist, `Some(false)` that it is still present, and `None` that the
    /// check could not be performed — callers must retain the fence on `None`.
    async fn workload_pod_absent(&self, namespace: &str, pod_name: &str) -> Option<bool> {
        if pod_name.is_empty() {
            return None;
        }
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        match tokio::time::timeout(KUBE_API_TIMEOUT, pods.get_opt(pod_name)).await {
            Ok(Ok(existing)) => Some(existing.is_none()),
            Ok(Err(err)) => {
                warn!(pod = %pod_name, error = %err, "Could not get workload pod");
                None
            }
            Err(_elapsed) => {
                warn!(pod = %pod_name, "Timed out getting workload pod");
                None
            }
        }
    }

    /// Whether the specific Sandbox CR we deleted — addressed by its Kubernetes
    /// UID — is actually gone, not merely marked for deletion. A DELETE the API
    /// server accepts only sets `deletionTimestamp`; finalizers or an in-flight
    /// controller can keep the CR (and recreate its workload pod) afterward, so
    /// pod-absence alone is not proof the fence is safe to drop.
    ///
    /// `Some(true)`: the CR is absent, or a *different*-UID object now holds the
    /// name (our CR is gone; a successor owns its own separately-named fence).
    /// `Some(false)`: the same-UID CR is still present (still terminating) — the
    /// workload can reappear, so keep the fence. `None`: undeterminable.
    async fn deleted_cr_is_gone(
        &self,
        namespace: &str,
        cr_name: &str,
        cr_uid: Option<&str>,
    ) -> Option<bool> {
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), namespace)
            .await
            .ok()?;
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.api.get_opt(cr_name)).await {
            Ok(Ok(None)) => Some(true),
            Ok(Ok(Some(obj))) => Some(obj.metadata.uid.as_deref() != cr_uid),
            Ok(Err(err)) => {
                warn!(cr = %cr_name, error = %err, "Could not confirm Sandbox CR deletion");
                None
            }
            Err(_elapsed) => {
                warn!(cr = %cr_name, "Timed out confirming Sandbox CR deletion");
                None
            }
        }
    }

    /// Delete a proxy-pod sandbox's egress `NetworkPolicy`, but only once its
    /// workload pod is confirmed gone, so the fence outlives a pod that ignores
    /// `SIGTERM`. Waits up to `stop_timeout` for the pod to disappear and RETAINS
    /// the fence if absence cannot be confirmed (leaving it for the reconciler to
    /// reap once the pod is truly gone). Best-effort deletion.
    async fn teardown_proxy_pod_fence(
        &self,
        namespace: &str,
        cr_name: &str,
        cr_uid: Option<&str>,
        sandbox_id: &str,
        stop_timeout: Duration,
    ) {
        // The workload pod is named after its Sandbox CR (see the pod-name
        // annotation the controller sets, which equals the CR name).
        let pod_name = cr_name;
        let deadline = tokio::time::Instant::now() + stop_timeout;
        let mut poll = STOP_INITIAL_POLL_INTERVAL;
        loop {
            match self.workload_pod_absent(namespace, pod_name).await {
                Some(true) => break,
                // Could not confirm, or pod still present: never drop the fence on
                // a guess. Retain it; reconciliation reaps it once the pod is gone.
                None => {
                    warn!(sandbox_id = %sandbox_id, "Leaving egress fence: workload pod absence unconfirmed");
                    return;
                }
                Some(false) => {}
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                warn!(sandbox_id = %sandbox_id, "Workload pod still present at deadline; leaving egress fence for reconciliation");
                return;
            }
            tokio::time::sleep(poll.min(deadline.saturating_duration_since(now))).await;
            poll = next_stop_poll_interval(poll);
        }

        // The accepted DELETE only set `deletionTimestamp`; a finalizer or an
        // in-flight controller reconciliation can still recreate the workload
        // after the pod-absence check above. Confirm THIS CR (by UID) is actually
        // gone immediately before removing the fence; retain it otherwise so a
        // reappearing workload never gets default-allow egress (reconciliation
        // reaps the fence once the CR is truly absent).
        match self.deleted_cr_is_gone(namespace, cr_name, cr_uid).await {
            Some(true) => {}
            Some(false) => {
                warn!(sandbox_id = %sandbox_id, "Leaving egress fence: Sandbox CR still terminating (deletionTimestamp set, finalizers pending)");
                return;
            }
            None => {
                warn!(sandbox_id = %sandbox_id, "Leaving egress fence: Sandbox CR deletion unconfirmed");
                return;
            }
        }

        // Even with the CR gone, a controller reconcile that read the CR before
        // its deletion could still create a dangling-ownerReference workload Pod
        // (Kubernetes permits references to a missing owner; GC orphan-collects it
        // later). Wait out a short quiescence window, re-confirming pod absence,
        // so such a stale Pod is observed and the fence retained rather than
        // deleted out from under it. A healthy controller converges well within
        // this window; anything still lingering is left for the reconciler.
        let quiesce_deadline = tokio::time::Instant::now() + FENCE_QUIESCE_WINDOW;
        while tokio::time::Instant::now() < quiesce_deadline {
            tokio::time::sleep(FENCE_QUIESCE_INTERVAL).await;
            if self.workload_pod_absent(namespace, pod_name).await != Some(true) {
                warn!(sandbox_id = %sandbox_id, "Leaving egress fence: workload pod reappeared during quiescence (stale controller reconcile)");
                return;
            }
        }

        let names = proxy_pod_resource_names(cr_name, sandbox_id);
        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            policies.delete(&names.agent_egress_network_policy, &DeleteParams::default()),
        )
        .await
        {
            Ok(Ok(_) | Err(KubeError::Api(_))) => {}
            Ok(Err(err)) => {
                warn!(sandbox_id = %sandbox_id, error = %err, "Failed to delete proxy-pod egress fence");
            }
            Err(_elapsed) => {
                warn!(sandbox_id = %sandbox_id, "Timed out deleting proxy-pod egress fence");
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

    pub async fn watch_sandboxes(&self) -> Result<WatchStream, String> {
        // Repair any proxy-pod companions left partial by a gateway crash
        // between the CR create and its companion creates. Runs on gateway start
        // and on every watch re-establishment.
        self.reconcile_proxy_pod_companions().await;
        // Whether to keep periodic repair and the shared-mode supervisor
        // Deployment readiness watch running. Determined from configuration —
        // never from a runtime sandbox list — so a transient discovery failure
        // cannot disable upkeep for a whole watch session. During a migration
        // away from proxy-pod, `retain_companion_management` (rendered from Helm
        // `retainCompanionRbac`) keeps it on until the last proxy-pod sandbox is
        // deleted.
        let manages_proxy_pod = self.config.topology == SupervisorTopology::ProxyPod
            || self.config.proxy_pod.retain_companion_management;
        if self.config.is_multi_namespace() {
            self.watch_sandboxes_cluster_wide(manages_proxy_pod).await
        } else {
            self.watch_sandboxes_single_namespace(manages_proxy_pod)
                .await
        }
    }

    async fn watch_sandboxes_single_namespace(
        &self,
        manages_proxy_pod: bool,
    ) -> Result<WatchStream, String> {
        let namespace = self.config.namespace.clone();
        let topology = self.config.topology;
        // Plain client for supervisor Deployment readiness checks inside the task.
        let client = self.client.clone();
        // Owned driver handle for CR lookups triggered by supervisor Deployment
        // changes (proxy-pod readiness refresh).
        let driver = self.clone();
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
        // Watch supervisor Deployments so proxy-pod readiness reflects supervisor
        // availability within seconds. Enabled whenever this gateway manages
        // proxy-pod sandboxes (config topology or a retainCompanionRbac
        // migration); otherwise it holds a stream that never yields. This is the
        // single-namespace (shared workspace) path, so the watch is namespaced
        // and needs no cluster-wide Deployment enumeration.
        // Keep the watch inputs so the task can re-establish the Deployment watch
        // after a recoverable end, rather than losing fast readiness for the rest
        // of the sandbox watch's lifetime.
        let deployment_watch: Option<(Api<Deployment>, String)> = manages_proxy_pod.then(|| {
            (
                Api::namespaced(self.watch_client.clone(), &namespace),
                self.proxy_pod_supervisor_selector(),
            )
        });
        let mut deployment_stream = match &deployment_watch {
            Some((api, selector)) => {
                proxy_pod_supervisor_deployment_stream(true, api.clone(), selector.clone())
            }
            None => futures::stream::pending().boxed(),
        };
        let (tx, rx) = mpsc::channel(256);
        self.spawn_proxy_pod_periodic_reconcile(tx.clone(), manages_proxy_pod);

        tokio::spawn(async move {
            let mut sandbox_name_to_id = std::collections::HashMap::<String, String>::new();
            let mut agent_pod_to_id = std::collections::HashMap::<String, String>::new();

            loop {
                tokio::select! {
                    event = sandbox_stream.next() => match event {
                        Some(Event::Applied(obj)) => {
                            if let Ok((kube_name, sandbox)) = sandbox_from_object_with_supervisor_readiness(&client, &namespace, obj, topology).await {
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
                                if let Ok((kube_name, sandbox)) = sandbox_from_object_with_supervisor_readiness(&client, &namespace, obj, topology).await {
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
                    result = deployment_stream.try_next() => match result {
                        Ok(Some(event)) => {
                            if !handle_supervisor_deployment_event(&driver, &tx, event).await {
                                break;
                            }
                        }
                        // kube's watcher self-heals transient errors and keeps
                        // yielding (it re-lists and re-watches with backoff), so
                        // keep polling the same stream instead of disabling the
                        // watch. The watch is only an optimization anyway —
                        // get/list and the periodic reconcile still fold in
                        // supervisor availability — so a persistent error (e.g. a
                        // migration without the Deployment RBAC) just backs off and
                        // logs; it never tears down the sandbox watch.
                        Err(err) => {
                            warn!(error = %err, "Supervisor Deployment watch error; retrying");
                        }
                        // A watcher stream should not end; if it does, re-establish
                        // it after a short backoff so fast readiness is not lost for
                        // the rest of this sandbox watch's lifetime.
                        Ok(None) => {
                            if let Some((api, selector)) = &deployment_watch {
                                warn!("Supervisor Deployment watch ended; re-establishing");
                                tokio::time::sleep(DEPLOYMENT_WATCH_REESTABLISH_BACKOFF).await;
                                deployment_stream = proxy_pod_supervisor_deployment_stream(
                                    true, api.clone(), selector.clone(),
                                );
                            } else {
                                deployment_stream = futures::stream::pending().boxed();
                            }
                        }
                    },
                    () = tx.closed() => break,
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn watch_sandboxes_cluster_wide(
        &self,
        manages_proxy_pod: bool,
    ) -> Result<WatchStream, String> {
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

        // Multi-namespace (managed/operator) workspace modes deliberately do NOT
        // watch supervisor Deployments: a cluster-wide Deployment informer would
        // require cluster-scoped list/watch on Deployments, which is broad
        // enumeration a compromised gateway could abuse. Proxy-pod supervisor
        // readiness folds in via get/list and the periodic reconcile instead.
        let (tx, rx) = mpsc::channel(256);
        self.spawn_proxy_pod_periodic_reconcile(tx.clone(), manages_proxy_pod);
        Ok(cluster_wide_watch_stream(
            sandbox_stream,
            self.config.namespace.clone(),
            self.config.topology,
            tx,
            rx,
        ))
    }
}

fn cluster_wide_watch_stream<S>(
    mut sandbox_stream: S,
    default_namespace: String,
    topology: SupervisorTopology,
    tx: mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
    rx: mpsc::Receiver<Result<WatchSandboxesEvent, KubernetesDriverError>>,
) -> WatchStream
where
    S: Stream<Item = Event<DynamicObject>> + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = sandbox_stream.next() => match event {
                    Some(Event::Applied(obj)) => {
                        let ns = obj.metadata.namespace.clone()
                            .unwrap_or_else(|| default_namespace.clone());
                        if let Ok((_kube_name, sandbox)) = sandbox_from_object(&ns, obj, topology) {
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
                            if let Ok((_kube_name, sandbox)) = sandbox_from_object(&ns, obj, topology) {
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

/// A supervisor Deployment watch scoped to `selector` when `enabled`, or a
/// stream that never yields otherwise (gateways that manage no supervisor
/// Deployments, or multi-namespace modes that avoid cluster-wide enumeration).
/// Boxing both arms to one type lets the watch loop poll a single branch
/// unconditionally.
fn proxy_pod_supervisor_deployment_stream(
    enabled: bool,
    deployments: Api<Deployment>,
    selector: String,
) -> Pin<Box<dyn Stream<Item = Result<Event<Deployment>, watcher::Error>> + Send>> {
    if enabled {
        let config = watcher::Config::default().labels(&selector);
        watcher::watcher(deployments, config).boxed()
    } else {
        futures::stream::pending().boxed()
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

#[allow(clippy::result_large_err)]
fn sandbox_owner_reference(pod: &Pod) -> Result<&OwnerReference, tonic::Status> {
    sandbox_owner_from_refs(pod.metadata.owner_references.as_deref().unwrap_or_default())
}

/// Extract the single controlling `Sandbox` owner reference from an owner list.
/// Shared by direct-owner (agent pod) and controller-chain (proxy-pod supervisor
/// Deployment) resolution.
fn sandbox_owner_from_refs(owners: &[OwnerReference]) -> Result<&OwnerReference, tonic::Status> {
    let mut matching = owners.iter().filter(|owner| {
        owner.kind == SANDBOX_KIND
            && matches!(
                owner.api_version.as_str(),
                "agents.x-k8s.io/v1beta1" | "agents.x-k8s.io/v1alpha1"
            )
    });
    let owner = matching
        .next()
        .ok_or_else(|| tonic::Status::permission_denied("not controlled by a Sandbox"))?;
    if matching.next().is_some()
        || owner.controller != Some(true)
        || owner.name.is_empty()
        || owner.uid.is_empty()
    {
        return Err(tonic::Status::permission_denied("invalid Sandbox owner"));
    }
    Ok(owner)
}

const REPLICA_SET_KIND: &str = "ReplicaSet";
const DEPLOYMENT_KIND: &str = "Deployment";
const APPS_API_VERSION_V1: &str = "apps/v1";

/// The single controlling (`controller: true`) owner reference, if any.
fn controller_owner_reference(owners: &[OwnerReference]) -> Option<&OwnerReference> {
    owners.iter().find(|owner| owner.controller == Some(true))
}

#[allow(clippy::result_large_err)]
fn validate_object_uid(actual: &str, expected: &str, message: &str) -> Result<(), tonic::Status> {
    if actual.is_empty() || actual != expected {
        return Err(tonic::Status::permission_denied(message.to_string()));
    }
    Ok(())
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

/// Resolve the supervisor topology a Sandbox CR was created under.
///
/// Falls back to `fallback` (the gateway's current configured topology) for CRs
/// created before this annotation existed, preserving their prior behavior.
fn topology_from_object(obj: &DynamicObject, fallback: SupervisorTopology) -> SupervisorTopology {
    if let Some(topology) = annotation_or_label(obj, ANNOTATION_SUPERVISOR_TOPOLOGY)
        .and_then(|value| value.parse::<SupervisorTopology>().ok())
    {
        return topology;
    }
    // No annotation: this CR predates the topology annotation, which every
    // sandbox created by this code stamps — including all proxy-pod sandboxes.
    // Such a CR therefore was NEVER proxy-pod, so it must not be classified as
    // proxy-pod even when the gateway is now configured that way (which would
    // wrongly report it sessionless and hunt for companions it never had).
    // Combined and sidecar share the session model and have no companions, so
    // collapsing an unknown fallback to combined is safe.
    if fallback == SupervisorTopology::ProxyPod {
        SupervisorTopology::Combined
    } else {
        fallback
    }
}

/// Returns `(kube_resource_name, DriverSandbox)`.
///
/// Returns `Err` in two cases (callers should skip, not fail):
/// - The object is not managed by `OpenShell` (missing/wrong `managed-by` label).
/// - The object is managed by `OpenShell` but missing required fields (orphan).
fn sandbox_from_object(
    namespace: &str,
    obj: DynamicObject,
    topology: SupervisorTopology,
) -> Result<(String, Sandbox), String> {
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
    // Derive the session model from the CR's creation-time topology, falling
    // back to the gateway's current topology for CRs predating the annotation.
    let resolved_topology = topology_from_object(&obj, topology);
    let status = status_from_object(&obj, resolved_topology);

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

/// UID used by strict process/binary-aware sidecars so Kubernetes grants the
/// requested capability set into the effective set without privilege escalation.
const BINARY_AWARE_SIDECAR_PROXY_UID: u32 = 0;

/// Shared volume used by the network sidecar and process-only supervisor for
/// local coordination in sidecar topology.
const SIDECAR_STATE_VOLUME_NAME: &str = "openshell-sidecar-state";
const SIDECAR_STATE_MOUNT_PATH: &str = openshell_core::container_paths::SIDECAR_RUN_ROOT;
const SIDECAR_CONTROL_SOCKET: &str = openshell_core::container_paths::SIDECAR_CONTROL_SOCKET;
// Linux abstract socket names are scoped to the pod's shared network namespace.
// Unlike a filesystem socket in the shared state volume, the workload cannot
// unlink and replace this relay endpoint after the trusted supervisor binds it.
const SIDECAR_SSH_SOCKET_FILE: &str = "@openshell-sidecar-ssh";

// Abstract socket for the proxy-pod agent's in-pod process supervisor. The agent
// pod runs non-root, so it cannot create a filesystem socket under `/run`; an
// abstract socket needs no writable directory and is scoped to the agent pod's
// own network namespace. The gateway relay and SSH server share this process.
const PROXY_POD_SSH_SOCKET_FILE: &str = "@openshell-proxy-pod-ssh";

/// Shared TLS work directory. The network sidecar writes the proxy CA bundle
/// here, while the agent container consumes it after sidecar bootstrap.
const SIDECAR_TLS_VOLUME_NAME: &str = "openshell-supervisor-tls";
const SIDECAR_TLS_MOUNT_PATH: &str = openshell_core::container_paths::SIDECAR_TLS_DIR;
const SIDECAR_CLIENT_TLS_MOUNT_PATH: &str = openshell_core::container_paths::SIDECAR_CLIENT_TLS_DIR;

const LABEL_SANDBOX_ROLE: &str = "openshell.ai/sandbox-role";
const SANDBOX_ROLE_AGENT: &str = "agent";
const SANDBOX_ROLE_SUPERVISOR: &str = "supervisor";
const PROXY_POD_PROXY_PORT: u16 = 3128;
const PROXY_POD_WAIT_INIT_CONTAINER_NAME: &str = "openshell-wait-for-proxy";
/// Upper bound on how long the agent pod waits for its paired supervisor.
/// Exceeding it fails the init container, which surfaces as a pod-level error
/// rather than a workload that silently has no egress.
const PROXY_POD_WAIT_TIMEOUT_SECS: u64 = 180;
const PROXY_POD_NETWORK_ENFORCEMENT_MODE: &str = "proxy-pod";
const PROXY_POD_CA_SECRET_MOUNT_PATH: &str = "/var/run/openshell-proxy-ca";
const PROXY_POD_CA_CERT_FILE: &str = "openshell-ca.pem";
const PROXY_POD_CA_KEY_FILE: &str = "openshell-ca-key.pem";

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
    run_as: Option<(u32, u32)>,
) -> serde_json::Value {
    let installed_path = format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox");
    // The copy-self init only writes the binary into the shared emptyDir. In
    // root-capable topologies (combined/sidecar) it runs as UID 0. In the
    // proxy-pod topology the pod runs under a non-root SCC (e.g. OpenShift
    // nonroot-v2), so it must run as the sandbox uid/gid; the emptyDir is
    // group-writable via the pod's fsGroup, so the non-root copy succeeds.
    let security_context = match run_as {
        None => serde_json::json!({ "runAsUser": 0 }),
        Some((uid, gid)) => serde_json::json!({
            "runAsUser": uid,
            "runAsGroup": gid,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "capabilities": { "drop": ["ALL"] }
        }),
    };
    let mut spec = serde_json::json!({
        "name": SUPERVISOR_INIT_CONTAINER_NAME,
        "image": supervisor_image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "copy-self",
            installed_path,
        ],
        "securityContext": security_context,
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
    init_run_as: Option<(u32, u32)>,
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
                init_run_as,
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
fn apply_supervisor_sideload_with_params(
    pod_template: &mut serde_json::Value,
    params: &SandboxPodParams<'_>,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    apply_supervisor_binary_source(
        spec,
        params.supervisor_image,
        params.supervisor_image_pull_policy,
        params.supervisor_sideload_method,
        None,
    );

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
        let mut command = vec![
            format!("{}/openshell-sandbox", SUPERVISOR_MOUNT_PATH),
            "--workdir".to_string(),
            driver_mounts::DEFAULT_WORKSPACE_ROOT.to_string(),
        ];
        command.extend(upstream_proxy_cli_args(params, true));
        container.insert("command".to_string(), serde_json::json!(command));

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

        // Inject the protected resolved identity contract. Clearing the OCI
        // input prevents image or user environment from selecting a
        // conflicting identity path.
        let env = container
            .entry("env")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(env) = env {
            apply_resolved_identity_env(env, params.sandbox_uid, params.sandbox_gid);
        }
        if has_upstream_proxy_credentials(params) {
            let volume_mounts = container
                .entry("volumeMounts")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut();
            if let Some(volume_mounts) = volume_mounts {
                volume_mounts.push(upstream_proxy_auth_volume_mount());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)]
fn apply_supervisor_sideload(
    pod_template: &mut serde_json::Value,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
    method: SupervisorSideloadMethod,
    sandbox_uid: u32,
    sandbox_gid: u32,
) {
    let params = SandboxPodParams {
        supervisor_image,
        supervisor_image_pull_policy,
        supervisor_sideload_method: method,
        sandbox_uid,
        sandbox_gid,
        ..SandboxPodParams::default()
    };
    apply_supervisor_sideload_with_params(pod_template, &params);
}

/// Build the `--upstream-proxy*` CLI arguments for a network supervisor.
///
/// `include_credentials` gates the arguments that depend on the mounted proxy
/// credential file. Sidecar topology mounts that Secret and passes `true`;
/// proxy-pod topology does not mount it (yet) and passes `false`, so it still
/// routes egress through the operator's corporate proxy (URL, `no_proxy`, CONNECT
/// mode) without referencing an auth file that would not exist in the
/// supervisor pod.
fn upstream_proxy_cli_args(
    params: &SandboxPodParams<'_>,
    include_credentials: bool,
) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(url) = params.https_proxy {
        args.extend(["--upstream-proxy".to_string(), url.to_string()]);
    }
    if let Some(list) = params.no_proxy {
        args.extend(["--upstream-no-proxy".to_string(), list.to_string()]);
    }
    if include_credentials && has_upstream_proxy_credentials(params) {
        args.extend([
            "--upstream-proxy-auth-file".to_string(),
            openshell_core::container_paths::UPSTREAM_PROXY_AUTH_MOUNT_PATH.to_string(),
        ]);
        if params.proxy_auth_allow_insecure {
            args.push("--upstream-proxy-auth-allow-insecure".to_string());
        }
    }
    if params.proxy_connect_by_hostname {
        args.push("--upstream-proxy-connect-by-hostname".to_string());
    }
    args
}

fn upstream_proxy_auth_volume_mount() -> serde_json::Value {
    serde_json::json!({
        "name": UPSTREAM_PROXY_AUTH_VOLUME_NAME,
        "mountPath": upstream_proxy_auth_volume_mount_path(),
        "readOnly": true,
    })
}

fn upstream_proxy_auth_volume_mount_path() -> &'static str {
    Path::new(openshell_core::container_paths::UPSTREAM_PROXY_AUTH_MOUNT_PATH)
        .parent()
        .and_then(Path::to_str)
        .expect("upstream proxy auth path has a parent directory")
}

fn upstream_proxy_auth_file_name() -> &'static str {
    Path::new(openshell_core::container_paths::UPSTREAM_PROXY_AUTH_MOUNT_PATH)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("upstream proxy auth path has a UTF-8 file name")
}

fn has_upstream_proxy_credentials(params: &SandboxPodParams<'_>) -> bool {
    params.proxy_auth_secret_name.is_some() && params.proxy_auth_secret_key.is_some()
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

#[derive(Debug, Clone)]
struct ProxyPodResourceNames {
    supervisor_deployment: String,
    service: String,
    proxy_ca_secret: String,
    agent_egress_network_policy: String,
    supervisor_ingress_network_policy: String,
}

/// Derive the companion resource names for a sandbox.
///
/// `cr_name` is cosmetic (readability in `kubectl get`); uniqueness comes from
/// `sandbox_id`, the immutable per-instance UUID. Keying the suffix on the UUID
/// (not the truncatable CR name) means two distinct sandbox instances never
/// collide, and a new sandbox that reuses a name while an old instance's
/// dependents are still being garbage-collected gets its own distinct names
/// rather than binding to the stale objects.
fn proxy_pod_resource_names(cr_name: &str, sandbox_id: &str) -> ProxyPodResourceNames {
    ProxyPodResourceNames {
        supervisor_deployment: dns_label_name("os-sup", cr_name, sandbox_id),
        service: dns_label_name("os-svc", cr_name, sandbox_id),
        proxy_ca_secret: dns_label_name("os-ca", cr_name, sandbox_id),
        agent_egress_network_policy: dns_label_name("os-eg", cr_name, sandbox_id),
        supervisor_ingress_network_policy: dns_label_name("os-ing", cr_name, sandbox_id),
    }
}

fn dns_label_name(prefix: &str, readable: &str, unique_key: &str) -> String {
    // FNV-1a over the immutable unique key (sandbox UUID) rather than the
    // readable name. A 64-bit suffix makes collisions between distinct sandbox
    // instances negligible, where the previous 32-bit hash of a truncatable
    // name had a deterministic collision path. Fall back to the readable name
    // only when no unique key is available.
    let key = if unique_key.is_empty() {
        readable
    } else {
        unique_key
    };
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let suffix = format!("{hash:016x}");
    let mut sanitized = readable
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized = sanitized
        .trim_matches('-')
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if sanitized.is_empty() {
        sanitized = "sandbox".to_string();
    }
    let max_base_len = 63usize.saturating_sub(prefix.len() + suffix.len() + 2);
    if sanitized.len() > max_base_len {
        sanitized.truncate(max_base_len);
        sanitized = sanitized.trim_matches('-').to_string();
    }
    format!("{prefix}-{sanitized}-{suffix}")
}

fn proxy_pod_service_dns(service_name: &str, namespace: &str) -> String {
    // Search-domain-relative rather than a hardcoded `.svc.cluster.local` FQDN:
    // clusters can run a custom cluster domain, and the pod resolver's search
    // list (`<ns>.svc.<domain>`, `svc.<domain>`, `<domain>`) resolves this form
    // on any domain. Hardcoding `cluster.local` would leave the workload's
    // wait-for-proxy init container unable to resolve its supervisor there.
    format!("{service_name}.{namespace}.svc")
}

fn proxy_pod_proxy_url(service_dns: &str) -> String {
    format!("http://{service_dns}:{PROXY_POD_PROXY_PORT}")
}

fn apply_host_gateway_aliases(
    spec: &mut serde_json::Map<String, serde_json::Value>,
    host_gateway_ip: &str,
) {
    if host_gateway_ip.is_empty() {
        return;
    }
    spec.insert(
        "hostAliases".to_string(),
        serde_json::json!([{
            "ip": host_gateway_ip,
            "hostnames": ["host.docker.internal", "host.openshell.internal"]
        }]),
    );
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
    apply_resolved_identity_env(&mut env, params.sandbox_uid, params.sandbox_gid);
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
    let proxy_uid = effective_sidecar_proxy_uid(params);
    let capabilities = if params.process_binary_aware_network_policy {
        serde_json::json!({
            "drop": ["ALL"],
            "add": ["SYS_PTRACE", "DAC_READ_SEARCH"]
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
            "runAsUser": proxy_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": proxy_uid != 0,
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
    container["command"]
        .as_array_mut()
        .expect("network supervisor command is an array")
        .extend(
            upstream_proxy_cli_args(params, true)
                .into_iter()
                .map(serde_json::Value::String),
        );
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
    if has_upstream_proxy_credentials(params) {
        container["volumeMounts"]
            .as_array_mut()
            .expect("volumeMounts is an array")
            .push(upstream_proxy_auth_volume_mount());
    }
    if let Some(profile) = params.app_armor_profile {
        container["securityContext"]["appArmorProfile"] = app_armor_profile_to_k8s(profile);
    }
    container
}

fn effective_sidecar_proxy_uid(params: &SandboxPodParams<'_>) -> u32 {
    if params.process_binary_aware_network_policy {
        BINARY_AWARE_SIDECAR_PROXY_UID
    } else {
        params.proxy_uid
    }
}

fn supervisor_network_init_container(params: &SandboxPodParams<'_>) -> serde_json::Value {
    let proxy_uid = effective_sidecar_proxy_uid(params);
    let mut container = serde_json::json!({
        "name": SUPERVISOR_NETWORK_INIT_CONTAINER_NAME,
        "image": params.supervisor_image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "--mode=network-init",
            "--proxy-uid",
            proxy_uid.to_string(),
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
                "mountPath": openshell_core::container_paths::CLIENT_TLS_DIR,
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
        None,
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
                "--mode=process",
                "--workdir",
                driver_mounts::DEFAULT_WORKSPACE_ROOT
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
            apply_resolved_identity_env(env, params.sandbox_uid, params.sandbox_gid);
        }
    }

    containers.push(supervisor_sidecar_container(
        template_environment,
        spec_environment,
        params,
    ));
}

fn proxy_pod_ca_source_volume_mount() -> serde_json::Value {
    serde_json::json!({
        "name": "openshell-proxy-pod-ca-source",
        "mountPath": PROXY_POD_CA_SECRET_MOUNT_PATH,
        "readOnly": true
    })
}

fn proxy_pod_ca_tls_volume_mount(read_only: bool) -> serde_json::Value {
    serde_json::json!({
        "name": "openshell-proxy-pod-tls",
        "mountPath": SIDECAR_TLS_MOUNT_PATH,
        "readOnly": read_only,
    })
}

fn proxy_pod_ca_init_container(
    image: &str,
    image_pull_policy: &str,
    run_as_user: u32,
    run_as_group: u32,
) -> serde_json::Value {
    let copy_cmd = format!(
        "set -eu; \
         mkdir -p {SIDECAR_TLS_MOUNT_PATH}; \
         cp {PROXY_POD_CA_SECRET_MOUNT_PATH}/{PROXY_POD_CA_CERT_FILE} {SIDECAR_TLS_MOUNT_PATH}/{PROXY_POD_CA_CERT_FILE}; \
         bundle={SIDECAR_TLS_MOUNT_PATH}/ca-bundle.pem; \
         found=0; \
         for path in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do \
           if [ -f \"$path\" ]; then cat \"$path\" > \"$bundle\"; found=1; break; fi; \
         done; \
         if [ \"$found\" = 0 ]; then : > \"$bundle\"; fi; \
         printf '\\n' >> \"$bundle\"; \
         cat {PROXY_POD_CA_SECRET_MOUNT_PATH}/{PROXY_POD_CA_CERT_FILE} >> \"$bundle\""
    );
    let mut init_spec = serde_json::json!({
        "name": "openshell-proxy-ca-install",
        "image": image,
        "command": ["sh", "-c", copy_cmd],
        "securityContext": {
            "runAsUser": run_as_user,
            "runAsGroup": run_as_group,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": {
                "drop": ["ALL"]
            }
        },
        "volumeMounts": [
            proxy_pod_ca_source_volume_mount(),
            proxy_pod_ca_tls_volume_mount(false),
        ]
    });
    if !image_pull_policy.is_empty() {
        init_spec["imagePullPolicy"] = serde_json::json!(image_pull_policy);
    }
    init_spec
}

fn proxy_pod_wait_for_proxy_init_container(
    image: &str,
    image_pull_policy: &str,
    run_as_user: u32,
    run_as_group: u32,
    service_dns: &str,
) -> serde_json::Value {
    let mut init_spec = serde_json::json!({
        "name": PROXY_POD_WAIT_INIT_CONTAINER_NAME,
        "image": image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "wait-for-tcp",
            format!("{service_dns}:{PROXY_POD_PROXY_PORT}"),
            PROXY_POD_WAIT_TIMEOUT_SECS.to_string(),
        ],
        "securityContext": {
            "runAsUser": run_as_user,
            "runAsGroup": run_as_group,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": {
                "drop": ["ALL"]
            }
        }
    });
    if !image_pull_policy.is_empty() {
        init_spec["imagePullPolicy"] = serde_json::json!(image_pull_policy);
    }
    init_spec
}

fn apply_proxy_pod_affinity(
    spec: &mut serde_json::Map<String, serde_json::Value>,
    sandbox_id: &str,
    mode: ProxyPodAffinity,
) {
    if sandbox_id.is_empty() || mode == ProxyPodAffinity::Disabled {
        return;
    }

    let term = serde_json::json!({
        "labelSelector": {
            "matchLabels": proxy_pod_match_labels(sandbox_id, SANDBOX_ROLE_SUPERVISOR)
        },
        "topologyKey": "kubernetes.io/hostname"
    });

    let affinity = spec
        .entry("affinity".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !affinity.is_object() {
        *affinity = serde_json::json!({});
    }
    let affinity = affinity
        .as_object_mut()
        .expect("affinity was converted to object");
    let pod_affinity = affinity
        .entry("podAffinity".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !pod_affinity.is_object() {
        *pod_affinity = serde_json::json!({});
    }
    let pod_affinity = pod_affinity
        .as_object_mut()
        .expect("podAffinity was converted to object");
    match mode {
        ProxyPodAffinity::Disabled => {}
        ProxyPodAffinity::Preferred => {
            let preferred = pod_affinity
                .entry("preferredDuringSchedulingIgnoredDuringExecution".to_string())
                .or_insert_with(|| serde_json::json!([]));
            if !preferred.is_array() {
                *preferred = serde_json::json!([]);
            }
            if let Some(preferred) = preferred.as_array_mut() {
                preferred.push(serde_json::json!({
                    "weight": 100,
                    "podAffinityTerm": term,
                }));
            }
        }
        ProxyPodAffinity::Required => {
            let required = pod_affinity
                .entry("requiredDuringSchedulingIgnoredDuringExecution".to_string())
                .or_insert_with(|| serde_json::json!([]));
            if !required.is_array() {
                *required = serde_json::json!([]);
            }
            if let Some(required) = required.as_array_mut() {
                required.push(term);
            }
        }
    }
}

fn apply_supervisor_proxy_pod_topology(
    pod_template: &mut serde_json::Value,
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

    apply_proxy_pod_affinity(spec, params.sandbox_id, params.proxy_pod_affinity);

    let names = proxy_pod_resource_names(params.cr_name, params.sandbox_id);
    let service_dns = proxy_pod_service_dns(&names.service, params.namespace);

    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        // The provider SPIFFE Workload API socket belongs only in the supervisor
        // (proxy) pod, which mints provider credentials. The agent pod holds a
        // scoped process-kind credential that cannot access provider secrets, so
        // it must not carry an SVID: drop the CSI volume entirely (no container
        // in the agent pod mounts it after the cleanup below).
        volumes.retain(|v| {
            v.get("name").and_then(serde_json::Value::as_str)
                != Some(SPIFFE_WORKLOAD_API_VOLUME_NAME)
        });
        volumes.push(serde_json::json!({
            "name": "openshell-proxy-pod-ca-source",
            "secret": {
                "secretName": names.proxy_ca_secret,
                "defaultMode": 0o444,
                "items": [{
                    "key": PROXY_POD_CA_CERT_FILE,
                    "path": PROXY_POD_CA_CERT_FILE,
                }]
            }
        }));
        volumes.push(serde_json::json!({
            "name": "openshell-proxy-pod-tls",
            "emptyDir": {}
        }));
    }

    // The agent pod runs the process supervisor (`--mode=process`), so it needs
    // the supervisor binary mounted just like combined/sidecar. Unlike those
    // root-capable topologies, the proxy-pod agent pod runs under a non-root
    // SCC, so the copy-self init container must run as the sandbox uid/gid.
    apply_supervisor_binary_source(
        spec,
        params.supervisor_image,
        params.supervisor_image_pull_policy,
        params.supervisor_sideload_method,
        Some((params.sandbox_uid, params.sandbox_gid)),
    );

    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(init_containers) = init_containers {
        init_containers.push(proxy_pod_ca_init_container(
            params.supervisor_image,
            params.supervisor_image_pull_policy,
            params.sandbox_uid,
            params.sandbox_gid,
        ));
        // Hold the workload until the paired supervisor is accepting proxy
        // connections, so the process supervisor's children never race ahead of
        // a working egress path.
        init_containers.push(proxy_pod_wait_for_proxy_init_container(
            params.supervisor_image,
            params.supervisor_image_pull_policy,
            params.sandbox_uid,
            params.sandbox_gid,
            &service_dns,
        ));
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
        // Run the process supervisor as the agent container's entrypoint; it
        // launches the workload (from MAIN_PROCESS_SPEC) and serves relays
        // locally. Network enforcement is external (the paired proxy pod), so
        // there is no `--mode=network` and no in-pod netns/nftables.
        container.insert(
            "command".to_string(),
            serde_json::json!([
                format!("{}/openshell-sandbox", SUPERVISOR_MOUNT_PATH),
                "--mode=process",
                "--workdir",
                driver_mounts::DEFAULT_WORKSPACE_ROOT
            ]),
        );

        let security_context = container
            .entry("securityContext")
            .or_insert_with(|| serde_json::json!({}));
        if !security_context.is_object() {
            *security_context = serde_json::json!({});
        }
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
                serde_json::json!({ "drop": ["ALL"] }),
            );
        }

        // Retain the gateway credentials: unlike the network-only design, the
        // in-pod process supervisor holds its own (scoped, process-kind) gateway
        // session for relays, policy, and log push. Add the supervisor binary
        // mount and the proxy CA trust dir.
        let volume_mounts = container
            .entry("volumeMounts")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(volume_mounts) = volume_mounts {
            // Drop the provider SPIFFE Workload API mount from the agent
            // container; it belongs only in the supervisor (proxy) pod.
            remove_volume_mount(volume_mounts, SPIFFE_WORKLOAD_API_VOLUME_NAME);
            volume_mounts.push(supervisor_volume_mount());
            volume_mounts.push(proxy_pod_ca_tls_volume_mount(true));
        }

        let env = container
            .entry("env")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut();
        if let Some(env) = env {
            // The provider SPIFFE Workload API socket lives only in the proxy
            // pod; strip its env so the agent never advertises a socket it no
            // longer mounts.
            remove_env(
                env,
                openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
            );

            // Select the process-supervisor + remote-proxy runtime path: own
            // gateway session (no sidecar control socket), NetworkOnly
            // enforcement, and the proxy CA read from the mounted TLS dir.
            upsert_env(
                env,
                openshell_core::sandbox_env::SUPERVISOR_TOPOLOGY,
                "proxy-pod",
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::NETWORK_ENFORCEMENT_MODE,
                "proxy-pod",
            );
            upsert_env(
                env,
                openshell_core::sandbox_env::PROXY_TLS_DIR,
                SIDECAR_TLS_MOUNT_PATH,
            );

            // The default SSH relay socket lives under `/run`, whose parent the
            // non-root agent cannot create. Use an abstract socket instead: it
            // needs no writable directory and is scoped to this pod's netns.
            upsert_env(
                env,
                openshell_core::sandbox_env::SSH_SOCKET_PATH,
                PROXY_POD_SSH_SOCKET_FILE,
            );

            // The workload's children egress through the remote proxy via these
            // proxy variables; the supervisor's own gateway dial is a direct
            // gRPC channel that does not consult them.
            let proxy_url = proxy_pod_proxy_url(&service_dns);
            for name in [
                "ALL_PROXY",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "http_proxy",
                "https_proxy",
                "grpc_proxy",
            ] {
                upsert_env(env, name, &proxy_url);
            }
            for name in ["NO_PROXY", "no_proxy"] {
                upsert_env(env, name, "127.0.0.1,localhost,::1");
            }
            upsert_env(env, "NODE_USE_ENV_PROXY", "1");

            let ca_cert = format!("{SIDECAR_TLS_MOUNT_PATH}/{PROXY_POD_CA_CERT_FILE}");
            let ca_bundle = format!("{SIDECAR_TLS_MOUNT_PATH}/ca-bundle.pem");
            for name in ["NODE_EXTRA_CA_CERTS", "DENO_CERT"] {
                upsert_env(env, name, &ca_cert);
            }
            for name in [
                "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "GIT_SSL_CAINFO",
            ] {
                upsert_env(env, name, &ca_bundle);
            }
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
#[allow(clippy::similar_names)]
fn apply_workspace_persistence(
    pod_template: &mut serde_json::Value,
    image: &str,
    image_pull_policy: &str,
    sandbox_uid: u32,
    sandbox_gid: u32,
    topology: SupervisorTopology,
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

        let security_context = if topology == SupervisorTopology::ProxyPod {
            serde_json::json!({
                "runAsUser": sandbox_uid,
                "runAsGroup": sandbox_gid,
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "capabilities": {
                    "drop": ["ALL"]
                }
            })
        } else {
            serde_json::json!({
                "runAsUser": 0,
            })
        };
        let mut init_spec = serde_json::json!({
            "name": WORKSPACE_INIT_CONTAINER_NAME,
            "image": image,
            "command": ["sh", "-c", copy_cmd],
            "securityContext": security_context,
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
    supervisor_sideload_method: SupervisorSideloadMethod,
    topology: SupervisorTopology,
    proxy_uid: u32,
    process_binary_aware_network_policy: bool,
    https_proxy: Option<&'a str>,
    no_proxy: Option<&'a str>,
    proxy_auth_secret_name: Option<&'a str>,
    proxy_auth_secret_key: Option<&'a str>,
    proxy_auth_allow_insecure: bool,
    proxy_connect_by_hostname: bool,
    proxy_pod_affinity: ProxyPodAffinity,
    proxy_pod_dns_peers: &'a [ProxyPodDnsPeer],
    proxy_pod_gateway_peers: &'a [ProxyPodDnsPeer],
    namespace: &'a str,
    service_account_name: &'a str,
    sandbox_id: &'a str,
    sandbox_name: &'a str,
    /// Gateway that owns this sandbox. Stamped as a label on proxy-pod
    /// companions so reconciliation can list and reap only this gateway's
    /// resources, never another gateway's.
    gateway_id: &'a str,
    /// Sandbox CR resource name (`kube_resource_name`), unique per sandbox in
    /// every workspace mode. Companion resource names derive from this so they
    /// match across the workload pod template and the companion objects.
    cr_name: &'a str,
    grpc_endpoint: &'a str,
    ssh_socket_path: &'a str,
    client_tls_secret_name: &'a str,
    host_gateway_ip: &'a str,
    enable_user_namespaces: bool,
    app_armor_profile: Option<&'a AppArmorProfile>,
    workspace_default_storage_size: &'a str,
    workspace_storage_class: &'a str,
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
            topology: SupervisorTopology::default(),
            proxy_uid: DEFAULT_PROXY_UID,
            process_binary_aware_network_policy: true,
            https_proxy: None,
            no_proxy: None,
            proxy_auth_secret_name: None,
            proxy_auth_secret_key: None,
            proxy_auth_allow_insecure: false,
            proxy_connect_by_hostname: false,
            proxy_pod_affinity: ProxyPodAffinity::Disabled,
            proxy_pod_dns_peers: &[],
            proxy_pod_gateway_peers: &[],
            namespace: "default",
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
            sandbox_id: "",
            sandbox_name: "",
            gateway_id: "",
            cr_name: "",
            grpc_endpoint: "",
            ssh_socket_path: "",
            client_tls_secret_name: "",
            host_gateway_ip: "",
            enable_user_namespaces: false,
            app_armor_profile: None,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE,
            workspace_storage_class: "",
            default_runtime_class_name: "",
            sa_token_ttl_secs: 3600,
            provider_spiffe_enabled: false,
            provider_spiffe_workload_api_socket_path: "",
            sandbox_uid: DEFAULT_SANDBOX_UID,
            sandbox_gid: DEFAULT_SANDBOX_UID,
        }
    }
}

fn validate_proxy_identity(params: &SandboxPodParams<'_>) -> Result<(), KubernetesDriverError> {
    if matches!(
        params.topology,
        SupervisorTopology::Sidecar | SupervisorTopology::ProxyPod
    ) && params.proxy_uid == params.sandbox_uid
    {
        let topology = params.topology.to_string();
        return Err(KubernetesDriverError::Precondition(format!(
            "proxy_uid ({}) must not match sandbox_uid ({}) in {topology} topology",
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

/// Reject workload entrypoint overrides in topologies that ignore them.
///
/// `combined` and `sidecar` replace the agent container's command with the
/// supervisor binary, so an override there would be accepted and then silently
/// dropped. Failing at validation is better than a sandbox that quietly does
/// something other than what was asked.
fn validate_agent_command_for_topology(
    config: &KubernetesSandboxDriverConfig,
    topology: SupervisorTopology,
) -> Result<(), String> {
    let agent = &config.containers.agent;
    if agent.command.is_empty() && agent.args.is_empty() {
        return Ok(());
    }
    // Every topology now runs the OpenShell supervisor as the agent container's
    // entrypoint (proxy-pod included, since it keeps the process supervisor in
    // the pod), so a container command/args override would be ignored. The
    // initial workload command is delivered through the sandbox spec / session
    // (`openshell sandbox create -- <cmd>`).
    Err(format!(
        "containers.agent.command and containers.agent.args are not supported; {topology} \
         topology runs the OpenShell supervisor as the container entrypoint and would ignore \
         them — pass the workload command via `openshell sandbox create -- <cmd>`"
    ))
}

fn kubernetes_driver_config_for_spec(
    spec: Option<&SandboxSpec>,
    provider_spiffe_workload_api_socket_path: Option<&str>,
) -> Result<KubernetesSandboxDriverConfig, String> {
    let config = spec
        .and_then(|spec| spec.template.as_ref())
        .map(KubernetesSandboxDriverConfig::from_template)
        .transpose()?
        .unwrap_or_default();
    let mut protected_paths = KUBERNETES_DRIVER_PROTECTED_MOUNT_PATHS.to_vec();
    let provider_spiffe_mount_path;
    if let Some(socket_path) = provider_spiffe_workload_api_socket_path {
        provider_spiffe_mount_path = spiffe_socket_mount_path(socket_path);
        protected_paths.push(&provider_spiffe_mount_path);
    }
    validate_kubernetes_protected_path_conflicts(
        &config.containers.agent.volume_mounts,
        &protected_paths,
    )?;
    Ok(config)
}

fn sandbox_to_k8s_spec(
    spec: Option<&SandboxSpec>,
    params: &SandboxPodParams<'_>,
) -> Result<serde_json::Value, String> {
    let driver_config =
        kubernetes_driver_config_for_spec(spec, provider_spiffe_socket_path(params))?;
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
                    Some(spec),
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
                spec,
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
        None,
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
        None,
        &driver_config,
        inject_workspace,
        params,
    )
}

fn sandbox_template_to_k8s_with_validated_config(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
    spec_environment: &std::collections::HashMap<String, String>,
    sandbox_spec: Option<&openshell_core::proto::compute::v1::DriverSandboxSpec>,
    driver_config: &KubernetesSandboxDriverConfig,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    let mut pod_labels = template
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<String, serde_json::Value>>();
    let proxy_pod_topology = params.topology == SupervisorTopology::ProxyPod;
    if params.provider_spiffe_enabled || proxy_pod_topology {
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
    if proxy_pod_topology {
        pod_labels.insert(
            LABEL_SANDBOX_ROLE.to_string(),
            serde_json::Value::String(SANDBOX_ROLE_AGENT.to_string()),
        );
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

    // Build environment variables - start with OpenShell-required vars
    let env = build_env_list(
        None,
        &template.environment,
        spec_environment,
        sandbox_spec,
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
            "name": CLIENT_TLS_VOLUME_NAME,
            "mountPath": openshell_core::container_paths::CLIENT_TLS_DIR,
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
        "name": SERVICE_ACCOUNT_TOKEN_VOLUME_NAME,
        "mountPath": SERVICE_ACCOUNT_TOKEN_MOUNT_PATH,
        "readOnly": true,
    }));
    volume_mounts.extend(
        driver_config
            .containers
            .agent
            .volume_mounts
            .iter()
            .map(kubernetes_driver_volume_mount_to_k8s),
    );
    container.insert(
        "volumeMounts".to_string(),
        serde_json::Value::Array(volume_mounts),
    );

    if let Some(resources) = container_resources(template, gpu_requirements) {
        container.insert("resources".to_string(), resources);
    }
    apply_agent_driver_resources(&mut container, &driver_config.containers.agent.resources);
    if params.topology == SupervisorTopology::ProxyPod {
        let agent_config = &driver_config.containers.agent;
        if !agent_config.command.is_empty() {
            container.insert(
                "command".to_string(),
                serde_json::json!(agent_config.command),
            );
        }
        if !agent_config.args.is_empty() {
            container.insert("args".to_string(), serde_json::json!(agent_config.args));
        }
    }
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
        let client_tls_default_mode = match params.topology {
            SupervisorTopology::Combined => 0o400,
            SupervisorTopology::Sidecar | SupervisorTopology::ProxyPod => 0o440,
        };
        volumes.push(serde_json::json!({
            "name": CLIENT_TLS_VOLUME_NAME,
            "secret": {
                "secretName": params.client_tls_secret_name,
                "defaultMode": client_tls_default_mode
            }
        }));
    }
    if has_upstream_proxy_credentials(params) {
        let secret_name = params
            .proxy_auth_secret_name
            .expect("complete proxy credential reference has a Secret name");
        let secret_key = params
            .proxy_auth_secret_key
            .expect("complete proxy credential reference has a Secret key");
        // The credential volume is mounted only into the container that runs
        // network supervision. Sidecar mode uses the pod fsGroup already
        // required for its non-root network supervisor.
        let default_mode = match params.topology {
            // `combined` and `proxy-pod` are rejected by
            // `validate_upstream_proxy_config`; use the most restrictive mode.
            SupervisorTopology::Combined | SupervisorTopology::ProxyPod => 0o400,
            SupervisorTopology::Sidecar => 0o440,
        };
        volumes.push(serde_json::json!({
            "name": UPSTREAM_PROXY_AUTH_VOLUME_NAME,
            "secret": {
                "secretName": secret_name,
                "defaultMode": default_mode,
                "items": [{
                    "key": secret_key,
                    "path": upstream_proxy_auth_file_name(),
                }]
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
    let sa_token_default_mode = match params.topology {
        SupervisorTopology::Combined => 0o400,
        SupervisorTopology::Sidecar | SupervisorTopology::ProxyPod => 0o440,
    };
    volumes.push(serde_json::json!({
        "name": SERVICE_ACCOUNT_TOKEN_VOLUME_NAME,
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
    volumes.extend(
        driver_config
            .volumes
            .iter()
            .map(kubernetes_driver_volume_to_k8s),
    );
    spec.insert("volumes".to_string(), serde_json::Value::Array(volumes));

    // Add hostAliases so sandbox pods can reach the Docker host.
    apply_host_gateway_aliases(&mut spec, params.host_gateway_ip);

    let mut template_value = serde_json::Map::new();
    if !metadata.is_empty() {
        template_value.insert("metadata".to_string(), serde_json::Value::Object(metadata));
    }
    template_value.insert("spec".to_string(), serde_json::Value::Object(spec));

    let mut result = serde_json::Value::Object(template_value);

    match params.topology {
        SupervisorTopology::Combined => {
            apply_supervisor_sideload_with_params(&mut result, params);
        }
        SupervisorTopology::Sidecar => {
            apply_supervisor_sidecar_topology(
                &mut result,
                &template.environment,
                spec_environment,
                params,
            );
        }
        SupervisorTopology::ProxyPod => {
            apply_supervisor_proxy_pod_topology(&mut result, params);
        }
    }

    // Inject workspace persistence (init container + PVC volume mount) so
    // that /sandbox data survives pod rescheduling. Skipped when the user
    // provides custom storage through driver_config.
    if inject_workspace {
        apply_workspace_persistence(
            &mut result,
            image,
            params.image_pull_policy,
            params.sandbox_uid,
            params.sandbox_gid,
            params.topology,
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

fn k8s_object<T>(value: serde_json::Value) -> T
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).expect("driver rendered an invalid Kubernetes object")
}

fn generate_proxy_pod_ca() -> Result<(String, String), KubernetesDriverError> {
    let ca_key = KeyPair::generate().map_err(|err| {
        KubernetesDriverError::Message(format!("failed to generate CA key: {err}"))
    })?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell Proxy Pod Sandbox CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "OpenShell");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let ca_cert = params.self_signed(&ca_key).map_err(|err| {
        KubernetesDriverError::Message(format!("failed to generate CA certificate: {err}"))
    })?;
    Ok((ca_cert.pem(), ca_key.serialize_pem()))
}

fn proxy_pod_owner_reference(
    sandbox_cr: &DynamicObject,
    api_version: &str,
    controller: bool,
) -> Result<serde_json::Value, KubernetesDriverError> {
    let name =
        sandbox_cr.metadata.name.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("created Sandbox is missing name".into())
        })?;
    let uid =
        sandbox_cr.metadata.uid.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("created Sandbox is missing uid".into())
        })?;
    Ok(serde_json::json!({
        "apiVersion": sandbox_cr
            .types
            .as_ref()
            .map_or(api_version, |types| types.api_version.as_str()),
        "kind": SANDBOX_KIND,
        "name": name,
        "uid": uid,
        "controller": controller,
        "blockOwnerDeletion": false,
    }))
}

fn proxy_pod_labels(sandbox_id: &str, role: &str, gateway_id: &str) -> serde_json::Value {
    let mut labels = serde_json::Map::new();
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        serde_json::json!(LABEL_MANAGED_BY_VALUE),
    );
    labels.insert(LABEL_SANDBOX_ID.to_string(), serde_json::json!(sandbox_id));
    labels.insert(LABEL_SANDBOX_ROLE.to_string(), serde_json::json!(role));
    // Gateway ownership so reconciliation can scope list/reap to this gateway.
    if !gateway_id.is_empty() {
        labels.insert(LABEL_GATEWAY_ID.to_string(), serde_json::json!(gateway_id));
    }
    serde_json::Value::Object(labels)
}

fn proxy_pod_match_labels(sandbox_id: &str, role: &str) -> serde_json::Value {
    let mut labels = serde_json::Map::new();
    labels.insert(LABEL_SANDBOX_ID.to_string(), serde_json::json!(sandbox_id));
    labels.insert(LABEL_SANDBOX_ROLE.to_string(), serde_json::json!(role));
    serde_json::Value::Object(labels)
}

fn proxy_pod_object_meta(
    name: &str,
    namespace: &str,
    sandbox_id: &str,
    role: &str,
    gateway_id: &str,
    owner_ref: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "namespace": namespace,
        "labels": proxy_pod_labels(sandbox_id, role, gateway_id),
        "annotations": {
            "openshell.ai/sandbox-id": sandbox_id
        },
        "ownerReferences": [owner_ref]
    })
}

fn proxy_pod_supervisor_env(
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
        false,
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
        "proxy-pod",
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::NETWORK_ENFORCEMENT_MODE,
        PROXY_POD_NETWORK_ENFORCEMENT_MODE,
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::NETWORK_BINARY_IDENTITY,
        "relaxed",
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::PROXY_BIND_ADDR,
        &format!("0.0.0.0:{PROXY_POD_PROXY_PORT}"),
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::PROXY_TLS_DIR,
        SIDECAR_TLS_MOUNT_PATH,
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::PROXY_CA_CERT_PATH,
        &format!("{PROXY_POD_CA_SECRET_MOUNT_PATH}/{PROXY_POD_CA_CERT_FILE}"),
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::PROXY_CA_KEY_PATH,
        &format!("{PROXY_POD_CA_SECRET_MOUNT_PATH}/{PROXY_POD_CA_KEY_FILE}"),
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::SANDBOX_UID,
        &params.sandbox_uid.to_string(),
    );
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::SANDBOX_GID,
        &params.sandbox_gid.to_string(),
    );
    env
}

fn proxy_pod_ca_secret(
    names: &ProxyPodResourceNames,
    params: &SandboxPodParams<'_>,
    owner_ref: serde_json::Value,
    cert_pem: &str,
    key_pem: &str,
) -> Secret {
    let mut string_data = serde_json::Map::new();
    string_data.insert(
        PROXY_POD_CA_CERT_FILE.to_string(),
        serde_json::json!(cert_pem),
    );
    string_data.insert(
        PROXY_POD_CA_KEY_FILE.to_string(),
        serde_json::json!(key_pem),
    );
    k8s_object(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": names.proxy_ca_secret,
            "namespace": params.namespace,
            "labels": proxy_pod_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR, params.gateway_id),
            "ownerReferences": [owner_ref],
        },
        "type": "Opaque",
        "stringData": serde_json::Value::Object(string_data)
    }))
}

fn proxy_pod_supervisor_service(
    names: &ProxyPodResourceNames,
    params: &SandboxPodParams<'_>,
    owner_ref: serde_json::Value,
) -> Service {
    k8s_object(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": names.service,
            "namespace": params.namespace,
            "labels": proxy_pod_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR, params.gateway_id),
            "ownerReferences": [owner_ref],
        },
        "spec": {
            "clusterIP": "None",
            "publishNotReadyAddresses": true,
            "selector": proxy_pod_match_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR),
            "ports": [
                {
                    "name": "http-proxy",
                    "port": PROXY_POD_PROXY_PORT,
                    "targetPort": PROXY_POD_PROXY_PORT,
                    "protocol": "TCP"
                }
            ]
        }
    }))
}

/// The set of Kubernetes objects that back one proxy-pod sandbox alongside its
/// Sandbox CR. All are owner-referenced to the CR for garbage collection.
struct ProxyPodCompanions {
    secret: Secret,
    service: Service,
    agent_egress: NetworkPolicy,
    supervisor_ingress: NetworkPolicy,
    supervisor_deployment: Deployment,
}

/// Render the full companion set from already-resolved inputs. Shared by the
/// create path (inputs from the sandbox spec) and the reconciliation path
/// (inputs reconstructed from the CR) so both produce identical objects.
#[allow(clippy::too_many_arguments)]
fn build_proxy_pod_companions(
    names: &ProxyPodResourceNames,
    params: &SandboxPodParams<'_>,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    pod_driver_config: &KubernetesPodDriverConfig,
    placement: &ProxyPodPlacement,
    supervisor_replicas: u32,
    deployment_owner_ref: serde_json::Value,
    dependent_owner_ref: serde_json::Value,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> ProxyPodCompanions {
    ProxyPodCompanions {
        secret: proxy_pod_ca_secret(
            names,
            params,
            dependent_owner_ref.clone(),
            ca_cert_pem,
            ca_key_pem,
        ),
        service: proxy_pod_supervisor_service(names, params, dependent_owner_ref.clone()),
        // No owner reference: the gateway manages this fence's lifecycle so it
        // outlives the workload pod on deletion.
        agent_egress: proxy_pod_agent_egress_network_policy(names, params),
        supervisor_ingress: proxy_pod_supervisor_ingress_network_policy(
            names,
            params,
            dependent_owner_ref,
        ),
        supervisor_deployment: proxy_pod_supervisor_deployment(
            names,
            template_environment,
            spec_environment,
            params,
            pod_driver_config,
            placement,
            supervisor_replicas,
            deployment_owner_ref,
        ),
    }
}

/// Create a companion object, treating an `AlreadyExists` (409) conflict as
/// success. This makes companion provisioning idempotent so it is safe to run
/// repeatedly from the reconciliation path without clobbering existing objects.
///
/// `verify_ownership` controls whether a 409 triggers an ownership-verifying
/// GET. It is `false` for the CA Secret because the gateway deliberately holds
/// no Secret read permission (least privilege); the companion name is keyed on
/// the immutable sandbox UUID, so a 409 already implies the object is this
/// sandbox's own. Non-secret companions verify via a metadata GET.
/// Create the agent egress fence, or validate an existing same-name policy.
///
/// The fence carries no owner reference, so ownership verification cannot vouch
/// for it. On an `AlreadyExists` conflict, fetch the existing policy and confirm
/// its enforcement fields (`spec`) and `sandbox-id` label match what we intended
/// to create; fail closed on any mismatch so a stale or altered policy is never
/// treated as a valid fence. If the conflicting policy has vanished by the time
/// we read it (409 then 404), the fence is *absent* — never treat that as
/// provisioned; retry the create so the workload is never left at default-allow.
async fn create_or_validate_egress_fence(
    api: &Api<NetworkPolicy>,
    expected: &NetworkPolicy,
) -> Result<(), KubernetesDriverError> {
    const DESC: &str = "proxy-pod agent egress NetworkPolicy";
    const MAX_ATTEMPTS: usize = 4;
    for _ in 0..MAX_ATTEMPTS {
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.create(&PostParams::default(), expected),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(KubeError::Api(err))) if err.code == 409 => {
                let name = expected.metadata.name.clone().unwrap_or_default();
                let existing = match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(&name)).await {
                    Ok(Ok(existing)) => existing,
                    // Conflicting policy vanished after the 409: the fence is now
                    // absent. Loop back and re-create it rather than reporting a
                    // non-existent boundary as provisioned.
                    Ok(Err(KubeError::Api(err))) if err.code == 404 => continue,
                    Ok(Err(err)) => return Err(KubernetesDriverError::from_kube(err)),
                    Err(_elapsed) => {
                        return Err(KubernetesDriverError::Message(format!(
                            "timed out after {}s validating {DESC} {name}",
                            KUBE_API_TIMEOUT.as_secs()
                        )));
                    }
                };
                let expected_sandbox_id = expected
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(LABEL_SANDBOX_ID));
                let existing_sandbox_id = existing
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(LABEL_SANDBOX_ID));
                if existing.spec == expected.spec && existing_sandbox_id == expected_sandbox_id {
                    return Ok(());
                }
                return Err(KubernetesDriverError::Message(format!(
                    "{DESC} {name} already exists but its enforcement does not match the intended \
                     fence (selector, egress rules, or sandbox-id differ); refusing to treat it \
                     as provisioned"
                )));
            }
            Ok(Err(err)) => return Err(KubernetesDriverError::from_kube(err)),
            Err(_elapsed) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s creating {DESC}",
                    KUBE_API_TIMEOUT.as_secs()
                )));
            }
        }
    }
    // Exhausted retries always re-creating/re-reading a vanishing fence: fail
    // closed rather than proceed without a boundary.
    Err(KubernetesDriverError::Message(format!(
        "{DESC} could not be provisioned after {MAX_ATTEMPTS} attempts (create/verify kept racing \
         a vanishing policy)"
    )))
}

async fn create_companion_if_absent<K>(
    api: &Api<K>,
    obj: &K,
    description: &str,
    verify_ownership: bool,
) -> Result<(), KubernetesDriverError>
where
    K: kube::Resource + Clone + std::fmt::Debug + serde::Serialize + DeserializeOwned + Sync,
    <K as kube::Resource>::DynamicType: Default,
{
    match tokio::time::timeout(KUBE_API_TIMEOUT, api.create(&PostParams::default(), obj)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(KubeError::Api(err))) if err.code == 409 => {
            if verify_ownership {
                verify_companion_ownership(api, obj, description).await
            } else {
                Ok(())
            }
        }
        Ok(Err(err)) => Err(KubernetesDriverError::from_kube(err)),
        Err(_elapsed) => Err(KubernetesDriverError::Message(format!(
            "timed out after {}s creating {description}",
            KUBE_API_TIMEOUT.as_secs()
        ))),
    }
}

/// On an `AlreadyExists` conflict, confirm the existing object belongs to the
/// same sandbox instance before treating the create as idempotent. A companion
/// is owner-referenced to its Sandbox CR, whose UID is per-instance, so an
/// object owned by a different CR UID is a stale leftover from a prior instance
/// (or an unrelated object). Adopting it would give the new sandbox a
/// mis-selecting egress policy or an unreachable supervisor, so we fail closed.
async fn verify_companion_ownership<K>(
    api: &Api<K>,
    obj: &K,
    description: &str,
) -> Result<(), KubernetesDriverError>
where
    K: kube::Resource + Clone + std::fmt::Debug + serde::Serialize + DeserializeOwned + Sync,
    <K as kube::Resource>::DynamicType: Default,
{
    let name = obj.meta().name.clone().unwrap_or_default();
    let expected_uids: HashSet<&str> = obj
        .meta()
        .owner_references
        .iter()
        .flatten()
        .map(|owner| owner.uid.as_str())
        .collect();
    // Without an owner reference to compare against we cannot prove identity;
    // there is nothing to verify, so accept (companions always carry one).
    if expected_uids.is_empty() {
        return Ok(());
    }
    match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(&name)).await {
        Ok(Ok(existing)) => {
            let same_instance = existing
                .meta()
                .owner_references
                .iter()
                .flatten()
                .any(|owner| expected_uids.contains(owner.uid.as_str()));
            if same_instance {
                Ok(())
            } else {
                Err(KubernetesDriverError::Message(format!(
                    "{description} {name} already exists but is owned by a different sandbox \
                     instance; refusing to adopt a stale companion"
                )))
            }
        }
        // Raced with garbage collection: the conflicting object is already gone,
        // so a later reconcile pass will recreate it cleanly.
        Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(()),
        // Cannot read the object to verify (should not happen with the rendered
        // RBAC, which grants get on non-secret companions). Accept rather than
        // wedge reconciliation: the UUID-keyed name already implies it is ours.
        Ok(Err(KubeError::Api(err))) if err.code == 403 => {
            warn!(
                companion = %description,
                name = %name,
                "Cannot verify companion ownership (forbidden); accepting existing object by UUID-keyed name"
            );
            Ok(())
        }
        Ok(Err(err)) => Err(KubernetesDriverError::from_kube(err)),
        Err(_elapsed) => Err(KubernetesDriverError::Message(format!(
            "timed out after {}s verifying ownership of {description} {name}",
            KUBE_API_TIMEOUT.as_secs()
        ))),
    }
}

/// Reconstruct the supervisor's node placement from a Sandbox CR's rendered
/// agent pod, so a reconciled supervisor lands where the workload can pair with
/// it. The agent pod already carries the merged placement, so reading it back is
/// both accurate and cluster-domain-agnostic.
fn proxy_pod_placement_from_cr(obj: &DynamicObject) -> ProxyPodPlacement {
    let Some(pod_spec) = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("podTemplate"))
        .and_then(|template| template.get("spec"))
    else {
        return ProxyPodPlacement::default();
    };
    ProxyPodPlacement {
        runtime_class_name: pod_spec
            .get("runtimeClassName")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        node_selector: pod_spec
            .get("nodeSelector")
            .filter(|value| value.as_object().is_some_and(|map| !map.is_empty()))
            .cloned(),
        tolerations: pod_spec
            .get("tolerations")
            .filter(|value| value.as_array().is_some_and(|list| !list.is_empty()))
            .cloned(),
    }
}

/// Read the log-level env back from a Sandbox CR's rendered agent pod so a
/// reconciled supervisor keeps the same verbosity as the original.
fn proxy_pod_log_level_env_from_cr(
    obj: &DynamicObject,
) -> std::collections::HashMap<String, String> {
    let mut env = std::collections::HashMap::new();
    let containers = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("podTemplate"))
        .and_then(|template| template.get("spec"))
        .and_then(|spec| spec.get("containers"))
        .and_then(serde_json::Value::as_array);
    let Some(containers) = containers else {
        return env;
    };
    for container in containers {
        let Some(entries) = container.get("env").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for entry in entries {
            if entry.get("name").and_then(serde_json::Value::as_str)
                == Some(openshell_core::sandbox_env::LOG_LEVEL)
                && let Some(value) = entry.get("value").and_then(serde_json::Value::as_str)
            {
                env.insert(
                    openshell_core::sandbox_env::LOG_LEVEL.to_string(),
                    value.to_string(),
                );
            }
        }
    }
    env
}

#[allow(clippy::too_many_arguments)]
fn proxy_pod_supervisor_deployment(
    names: &ProxyPodResourceNames,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    params: &SandboxPodParams<'_>,
    pod_config: &KubernetesPodDriverConfig,
    placement: &ProxyPodPlacement,
    replicas: u32,
    owner_ref: serde_json::Value,
) -> Deployment {
    let mut container = serde_json::json!({
        "name": SUPERVISOR_NETWORK_SIDECAR_NAME,
        "image": params.supervisor_image,
        "command": [
            SUPERVISOR_IMAGE_BINARY_PATH,
            "--mode=network",
        ],
        "env": proxy_pod_supervisor_env(template_environment, spec_environment, params),
        "ports": [
            {"name": "http-proxy", "containerPort": PROXY_POD_PROXY_PORT, "protocol": "TCP"}
        ],
        "readinessProbe": {
            "tcpSocket": {"port": PROXY_POD_PROXY_PORT},
            "periodSeconds": 2,
            "failureThreshold": 30
        },
        "securityContext": {
            "runAsUser": params.proxy_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {
                "drop": ["ALL"]
            }
        },
        "volumeMounts": [
            {
                "name": "openshell-sa-token",
                "mountPath": "/var/run/secrets/openshell",
                "readOnly": true
            },
            {
                "name": "openshell-proxy-pod-ca-source",
                "mountPath": PROXY_POD_CA_SECRET_MOUNT_PATH,
                "readOnly": true
            },
            proxy_pod_ca_tls_volume_mount(false),
        ]
    });
    // Route egress through the operator's corporate upstream proxy, matching
    // sidecar topology. Credentials are excluded because the proxy-pod
    // supervisor does not mount the auth Secret.
    container["command"]
        .as_array_mut()
        .expect("network supervisor command is an array")
        .extend(
            upstream_proxy_cli_args(params, false)
                .into_iter()
                .map(serde_json::Value::String),
        );
    if !params.supervisor_image_pull_policy.is_empty() {
        container["imagePullPolicy"] = serde_json::json!(params.supervisor_image_pull_policy);
    }
    if !params.client_tls_secret_name.is_empty() {
        container["volumeMounts"]
            .as_array_mut()
            .expect("volumeMounts is an array")
            .push(serde_json::json!({
                "name": "openshell-client-tls",
                "mountPath": SIDECAR_CLIENT_TLS_MOUNT_PATH,
                "readOnly": true
            }));
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

    let mut spec = serde_json::json!({
        "serviceAccountName": params.service_account_name,
        "automountServiceAccountToken": false,
        "securityContext": {
            "fsGroup": params.sandbox_gid
        },
        "containers": [container],
        "volumes": [
            {
                "name": "openshell-sa-token",
                "projected": {
                    "sources": [{
                        "serviceAccountToken": {
                            "audience": "openshell-gateway",
                            "expirationSeconds": params.sa_token_ttl_secs,
                            "path": "token"
                        }
                    }],
                    "defaultMode": 0o440
                }
            },
            {
                "name": "openshell-proxy-pod-ca-source",
                "secret": {
                    "secretName": names.proxy_ca_secret,
                    "defaultMode": 0o440
                }
            },
            {
                "name": "openshell-proxy-pod-tls",
                "emptyDir": {}
            }
        ]
    });
    // Match the workload's runtime-class precedence: public platform_config,
    // then driver_config.pod, then the cluster default.
    let runtime_class_name = placement
        .runtime_class_name
        .clone()
        .or_else(|| {
            (!pod_config.runtime_class_name.is_empty())
                .then(|| pod_config.runtime_class_name.clone())
        })
        .or_else(|| {
            (!params.default_runtime_class_name.is_empty())
                .then(|| params.default_runtime_class_name.to_string())
        });
    if let Some(runtime_class) = runtime_class_name {
        spec["runtimeClassName"] = serde_json::json!(runtime_class);
    }
    if let Some(spec_obj) = spec.as_object_mut() {
        apply_host_gateway_aliases(spec_obj, params.host_gateway_ip);
    }
    let image_pull_secrets = image_pull_secret_refs(params.image_pull_secrets);
    if !image_pull_secrets.is_empty() {
        spec["imagePullSecrets"] = serde_json::Value::Array(image_pull_secrets);
    }
    if !params.client_tls_secret_name.is_empty() {
        spec["volumes"]
            .as_array_mut()
            .expect("volumes is an array")
            .push(serde_json::json!({
                "name": "openshell-client-tls",
                "secret": {
                    "secretName": params.client_tls_secret_name,
                    "defaultMode": 0o440
                }
            }));
    }
    if params.provider_spiffe_enabled {
        spec["volumes"]
            .as_array_mut()
            .expect("volumes is an array")
            .push(serde_json::json!({
                "name": SPIFFE_WORKLOAD_API_VOLUME_NAME,
                "csi": {
                    "driver": "csi.spiffe.io",
                    "readOnly": true
                }
            }));
    }
    if let Some(spec_obj) = spec.as_object_mut() {
        // Seed platform_config placement first so driver_config.pod merges on top
        // with the same precedence the workload uses (per-key node-selector
        // override, appended tolerations).
        if let Some(node_selector) = placement.node_selector.clone() {
            spec_obj.insert("nodeSelector".to_string(), node_selector);
        }
        if let Some(tolerations) = placement.tolerations.clone() {
            spec_obj.insert("tolerations".to_string(), tolerations);
        }
        apply_pod_driver_config(spec_obj, pod_config);
    }

    k8s_object(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": proxy_pod_object_meta(
            &names.supervisor_deployment,
            params.namespace,
            params.sandbox_id,
            SANDBOX_ROLE_SUPERVISOR,
            params.gateway_id,
            owner_ref
        ),
        "spec": {
            "replicas": replicas,
            "selector": {
                "matchLabels": proxy_pod_match_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR)
            },
            "template": {
                "metadata": {
                    "labels": proxy_pod_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR, params.gateway_id),
                    "annotations": {
                        "openshell.ai/sandbox-id": params.sandbox_id
                    }
                },
                "spec": spec
            }
        }
    }))
}

/// Build the DNS egress rules for the agent pod.
///
/// Emits one rule per configured peer, because peers may listen on different
/// ports and a `NetworkPolicy` rule applies its port list to every `to` entry
/// in that rule.
///
/// `peer.port` is the destination **pod** port. Egress rules with a
/// `podSelector` peer are evaluated after `Service` address translation, so a
/// cluster whose DNS `Service` maps 53 onto a different container port needs
/// that container port configured. Upstream `CoreDNS` listens on 53;
/// `OpenShift`'s `dns-default` listens on 5353 and maps 53 to it.
///
/// Returns an empty vector for an empty peer list. This is deliberately
/// fail-closed: a `NetworkPolicy` egress rule with an empty `to` array matches
/// *every* destination, so emitting one here would silently open DNS-port
/// egress to the whole cluster. Emitting no rule denies DNS instead, and
/// `validate_dns_peers` rejects an empty list at startup so a correctly
/// configured driver never reaches that state.
fn proxy_pod_dns_egress_rules(peers: &[ProxyPodDnsPeer]) -> Vec<serde_json::Value> {
    peers
        .iter()
        .map(|peer| {
            let mut entry = serde_json::Map::new();
            if !peer.namespace_labels.is_empty() {
                entry.insert(
                    "namespaceSelector".to_string(),
                    serde_json::json!({"matchLabels": peer.namespace_labels}),
                );
            }
            if !peer.pod_labels.is_empty() {
                entry.insert(
                    "podSelector".to_string(),
                    serde_json::json!({"matchLabels": peer.pod_labels}),
                );
            }
            serde_json::json!({
                "to": [serde_json::Value::Object(entry)],
                "ports": [
                    {"protocol": "UDP", "port": peer.port},
                    {"protocol": "TCP", "port": peer.port}
                ]
            })
        })
        .collect()
}

/// Egress rules permitting the in-pod process supervisor to reach the gateway
/// (TCP only). Same selector shape as DNS peers; the port is the gateway's.
fn proxy_pod_gateway_egress_rules(peers: &[ProxyPodDnsPeer]) -> Vec<serde_json::Value> {
    peers
        .iter()
        .map(|peer| {
            let mut entry = serde_json::Map::new();
            if !peer.namespace_labels.is_empty() {
                entry.insert(
                    "namespaceSelector".to_string(),
                    serde_json::json!({"matchLabels": peer.namespace_labels}),
                );
            }
            if !peer.pod_labels.is_empty() {
                entry.insert(
                    "podSelector".to_string(),
                    serde_json::json!({"matchLabels": peer.pod_labels}),
                );
            }
            serde_json::json!({
                "to": [serde_json::Value::Object(entry)],
                "ports": [{"protocol": "TCP", "port": peer.port}]
            })
        })
        .collect()
}

fn proxy_pod_agent_egress_network_policy(
    names: &ProxyPodResourceNames,
    params: &SandboxPodParams<'_>,
) -> NetworkPolicy {
    let mut egress = vec![serde_json::json!({
        "to": [{
            "podSelector": {
                "matchLabels": proxy_pod_match_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR)
            }
        }],
        "ports": [
            {"protocol": "TCP", "port": PROXY_POD_PROXY_PORT}
        ]
    })];
    egress.extend(proxy_pod_dns_egress_rules(params.proxy_pod_dns_peers));
    // Permit the in-pod process supervisor's own gateway session (relays, policy,
    // log push, token bootstrap). The workload's children still reach only the
    // proxy on 3128; this rule is for the supervisor, not the workload.
    egress.extend(proxy_pod_gateway_egress_rules(
        params.proxy_pod_gateway_peers,
    ));

    // Deliberately NO ownerReference: this egress policy is the workload's fence,
    // and it must outlive the workload pod during deletion. Owner-reference
    // garbage collection deletes it concurrently with the pod (siblings of the
    // Sandbox CR), which would reopen direct egress for a pod that ignores
    // SIGTERM during its termination grace period. The gateway instead deletes
    // it explicitly after the pod is gone (delete_sandbox) and reaps orphans in
    // reconciliation, so it is never collected while the workload can still run.
    k8s_object(serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": names.agent_egress_network_policy,
            "namespace": params.namespace,
            "labels": proxy_pod_labels(params.sandbox_id, SANDBOX_ROLE_AGENT, params.gateway_id),
            // Record the guarded workload pod's name so delete/reap can confirm
            // it is gone by a scoped `get`, never a cluster-wide pod list. The
            // agent pod is named after its Sandbox CR (== cr_name).
            "annotations": {
                ANNOTATION_AGENT_POD_NAME: params.cr_name,
            },
        },
        "spec": {
            "podSelector": {
                "matchLabels": proxy_pod_match_labels(params.sandbox_id, SANDBOX_ROLE_AGENT)
            },
            "policyTypes": ["Egress"],
            "egress": egress
        }
    }))
}

fn proxy_pod_supervisor_ingress_network_policy(
    names: &ProxyPodResourceNames,
    params: &SandboxPodParams<'_>,
    owner_ref: serde_json::Value,
) -> NetworkPolicy {
    k8s_object(serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": names.supervisor_ingress_network_policy,
            "namespace": params.namespace,
            "labels": proxy_pod_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR, params.gateway_id),
            "ownerReferences": [owner_ref],
        },
        "spec": {
            "podSelector": {
                "matchLabels": proxy_pod_match_labels(params.sandbox_id, SANDBOX_ROLE_SUPERVISOR)
            },
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{
                    "podSelector": {
                        "matchLabels": proxy_pod_match_labels(params.sandbox_id, SANDBOX_ROLE_AGENT)
                    }
                }],
                "ports": [
                    {"protocol": "TCP", "port": PROXY_POD_PROXY_PORT}
                ]
            }]
        }
    }))
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
    sandbox_spec: Option<&openshell_core::proto::compute::v1::DriverSandboxSpec>,
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
    let main_process =
        openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(sandbox_spec)
            .expect("main process config serialization cannot fail");
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
        &main_process,
    );
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
        openshell_core::sandbox_env::TELEMETRY_ENABLED,
        openshell_core::telemetry::enabled_env_value(),
    );
    // Runtime capabilities are driver-owned. Kubernetes topologies do not yet
    // provide the complete policy DNS and transparent TCP substrate.
    upsert_env(
        env,
        openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
        "",
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
    Path::new(socket_path)
        .parent()
        .and_then(Path::to_str)
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

fn remove_volume_mount(volume_mounts: &mut Vec<serde_json::Value>, name: &str) {
    volume_mounts.retain(|mount| mount.get("name").and_then(|value| value.as_str()) != Some(name));
}

/// Node-placement overrides sourced from a sandbox template's public
/// `platform_config` (the typed/legacy path the workload pod honors). The
/// proxy-pod supervisor must apply the same overrides so it lands on a node the
/// workload can also use; otherwise same-node affinity can be unschedulable and
/// runtime-class mismatches (e.g. Kata vs default) split the pair across
/// incompatible runtimes.
#[derive(Default)]
struct ProxyPodPlacement {
    runtime_class_name: Option<String>,
    node_selector: Option<serde_json::Value>,
    tolerations: Option<serde_json::Value>,
}

impl ProxyPodPlacement {
    fn from_template(template: Option<&SandboxTemplate>) -> Self {
        let Some(template) = template else {
            return Self::default();
        };
        Self {
            runtime_class_name: platform_config_string(template, "runtime_class_name"),
            node_selector: platform_config_struct(template, "node_selector"),
            tolerations: platform_config_struct(template, "tolerations"),
        }
    }
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

/// Convert a `Sandbox` CR's status into the driver contract's status.
///
/// `topology` decides the supervisor-session model reported to the gateway.
/// `proxy-pod` has no in-sandbox process supervisor, so no `ConnectSupervisor`
/// session will ever open; the gateway must derive readiness from the
/// conditions below instead of waiting forever. The agent pod's
/// `wait-for-proxy` init container is what makes that safe: the pod does not
/// become Ready until its paired supervisor is accepting connections.
/// Whether a proxy-pod sandbox's supervisor Deployment currently has no
/// available replica. A missing Deployment counts as unavailable; a transient
/// API error does not (returns `false`), so readiness never flaps on a blip.
/// Tri-state supervisor availability. `Unknown` (an API error or timeout on the
/// Deployment GET) is deliberately distinct from `Available`: callers must not
/// treat "could not determine" as "up", or a transient blip would republish a
/// dead-egress sandbox as `Ready`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupervisorAvailability {
    Available,
    Unavailable,
    Unknown,
}

/// Supervisor availability derived from a supervisor `Deployment` object already
/// in hand (e.g. from a watch event), so no GET is needed and the result is
/// never `Unknown`.
fn supervisor_availability_from_deployment(deployment: &Deployment) -> SupervisorAvailability {
    let available = deployment
        .status
        .as_ref()
        .and_then(|status| status.available_replicas)
        .unwrap_or(0)
        >= 1;
    if available {
        SupervisorAvailability::Available
    } else {
        SupervisorAvailability::Unavailable
    }
}

async fn proxy_pod_supervisor_availability(
    client: &Client,
    namespace: &str,
    deployment_name: &str,
) -> SupervisorAvailability {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    match tokio::time::timeout(KUBE_API_TIMEOUT, deployments.get_opt(deployment_name)).await {
        Ok(Ok(Some(deployment))) => supervisor_availability_from_deployment(&deployment),
        // A missing Deployment is a definite absence, not an error.
        Ok(Ok(None)) => SupervisorAvailability::Unavailable,
        Ok(Err(err)) => {
            warn!(
                deployment = %deployment_name,
                error = %err,
                "Could not determine proxy-pod supervisor availability; treating supervisor as not ready"
            );
            SupervisorAvailability::Unknown
        }
        Err(_elapsed) => {
            warn!(
                deployment = %deployment_name,
                "Timed out checking proxy-pod supervisor availability; treating supervisor as not ready"
            );
            SupervisorAvailability::Unknown
        }
    }
}

/// Map a Sandbox CR to a `DriverSandbox`, folding proxy-pod supervisor
/// availability into readiness. Used by the watch paths so a CR event never
/// republishes a sandbox as `Ready` while its supervisor Deployment is down —
/// matching what the get/list paths already report.
async fn sandbox_from_object_with_supervisor_readiness(
    client: &Client,
    namespace: &str,
    obj: DynamicObject,
    fallback_topology: SupervisorTopology,
) -> Result<(String, Sandbox), String> {
    let cr_topology = topology_from_object(&obj, fallback_topology);
    let cr_namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let cr_name = obj.metadata.name.clone().unwrap_or_default();
    let sandbox_id = sandbox_id_from_object(&obj).unwrap_or_default();
    let (kube_name, mut sandbox) = sandbox_from_object(namespace, obj, fallback_topology)?;
    if cr_topology == SupervisorTopology::ProxyPod && !sandbox_id.is_empty() {
        let names = proxy_pod_resource_names(&cr_name, &sandbox_id);
        // Fail closed: keep `Ready` only when the supervisor is confirmed
        // available. `Unavailable` and `Unknown` (a GET error/timeout) both
        // downgrade to `Provisioning`, so a watch event never republishes a
        // sandbox as `Ready` while its policy-enforced egress path may be down.
        if proxy_pod_supervisor_availability(client, &cr_namespace, &names.supervisor_deployment)
            .await
            != SupervisorAvailability::Available
        {
            mark_supervisor_unavailable(&mut sandbox);
        }
    }
    Ok((kube_name, sandbox))
}

/// The `openshell.ai/sandbox-id` a supervisor Deployment belongs to, or `None`
/// when the label is absent or empty (not an OpenShell-managed supervisor).
fn supervisor_deployment_sandbox_id(deployment: &Deployment) -> Option<String> {
    deployment
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .filter(|id| !id.is_empty())
        .cloned()
}

/// Push a refreshed sandbox status in response to a supervisor Deployment
/// change so proxy-pod readiness reflects supervisor availability within seconds
/// instead of waiting for the reconcile sweep. `availability` is taken from the
/// watch event object itself, so the CR re-read applies the exact observed state
/// rather than re-fetching the Deployment (which could fail open on a transient
/// error and republish a dead-egress sandbox as `Ready`). Returns `false` only
/// when the watch consumer has gone away, signalling the caller to stop.
async fn emit_supervisor_readiness_refresh(
    driver: &KubernetesComputeDriver,
    tx: &mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
    deployment: &Deployment,
    availability: SupervisorAvailability,
) -> bool {
    let Some(sandbox_id) = supervisor_deployment_sandbox_id(deployment) else {
        return true;
    };
    match driver
        .lookup_sandbox_with_readiness(&sandbox_id, Some(availability))
        .await
    {
        Ok(Some(sandbox)) => {
            let event = WatchSandboxesEvent {
                payload: Some(watch_sandboxes_event::Payload::Sandbox(
                    WatchSandboxesSandboxEvent {
                        sandbox: Some(sandbox),
                    },
                )),
            };
            tx.send(Ok(event)).await.is_ok()
        }
        // The CR is already gone; the sandbox watch emits its own Deleted event.
        Ok(None) => true,
        Err(err) => {
            warn!(
                sandbox_id = %sandbox_id,
                error = %err,
                "Failed to refresh sandbox status after supervisor Deployment change"
            );
            true
        }
    }
}

/// Turn one supervisor Deployment watch event into sandbox status refreshes.
/// Returns `false` when the watch consumer has gone away.
async fn handle_supervisor_deployment_event(
    driver: &KubernetesComputeDriver,
    tx: &mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
    event: Event<Deployment>,
) -> bool {
    match event {
        Event::Applied(deployment) => {
            let availability = supervisor_availability_from_deployment(&deployment);
            emit_supervisor_readiness_refresh(driver, tx, &deployment, availability).await
        }
        // A deleted supervisor Deployment is unambiguously unavailable; do not
        // re-fetch and risk reading nothing (or a stale replica) back.
        Event::Deleted(deployment) => {
            emit_supervisor_readiness_refresh(
                driver,
                tx,
                &deployment,
                SupervisorAvailability::Unavailable,
            )
            .await
        }
        Event::Restarted(deployments) => {
            for deployment in deployments {
                let availability = supervisor_availability_from_deployment(&deployment);
                if !emit_supervisor_readiness_refresh(driver, tx, &deployment, availability).await {
                    return false;
                }
            }
            true
        }
    }
}

/// Desired supervisor replica count from a Sandbox CR's operating state: `1`
/// while running, `0` while suspended. Defaults to `1` (a freshly created CR is
/// running) when no operating state is recorded. Lets reconciliation restore the
/// correct replica count after a crash between the operating-state patch and the
/// supervisor scale.
fn desired_supervisor_replicas(obj: &DynamicObject) -> u32 {
    let spec = obj.data.get("spec");
    // v1beta1 encodes desired state as spec.operatingMode.
    if let Some(mode) = spec
        .and_then(|spec| spec.get("operatingMode"))
        .and_then(serde_json::Value::as_str)
    {
        return u32::from(!mode.eq_ignore_ascii_case("Suspended"));
    }
    // v1alpha1 encodes it as spec.replicas (0 or 1).
    if let Some(replicas) = spec
        .and_then(|spec| spec.get("replicas"))
        .and_then(serde_json::Value::as_u64)
    {
        return u32::from(replicas > 0);
    }
    1
}

/// Force a proxy-pod sandbox's `Ready` condition to `False` because its
/// supervisor Deployment has no available replica. The agent pod's own Ready
/// condition (which the CR carries) cannot see the separate supervisor, so
/// without this the sandbox would report Ready while policy-enforced egress is
/// dead.
fn mark_supervisor_unavailable(sandbox: &mut Sandbox) {
    // `DependenciesNotReady` is on the gateway's transient-reason allowlist, so
    // the sandbox becomes `Provisioning` (recoverable) rather than terminal
    // `Error`: readiness returns to `Ready` once the supervisor Deployment does.
    const REASON: &str = "DependenciesNotReady";
    const MESSAGE: &str = "proxy-pod network supervisor Deployment has no available replica";
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

fn status_from_object(obj: &DynamicObject, topology: SupervisorTopology) -> Option<SandboxStatus> {
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
        // Every topology now runs an in-sandbox process supervisor that owns a
        // gateway session and serves relays, so all report `Required`. (The
        // proxy-pod variant keeps only the network proxy out of the pod.)
        supervisor_session_model: match topology {
            SupervisorTopology::Combined
            | SupervisorTopology::Sidecar
            | SupervisorTopology::ProxyPod => SupervisorSessionModel::Required as i32,
        },
    })
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
        serde_json::json!({
            "metadata": {"resourceVersion": resource_version},
            "spec": {"operatingMode": if running { "Running" } else { "Suspended" }}
        })
    } else {
        serde_json::json!({
            "metadata": {"resourceVersion": resource_version},
            "spec": {"replicas": i32::from(running)}
        })
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

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));
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
            .find(|span| span.name == "kubernetes.create_sandbox")
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

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));

        let annotations = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("kubernetes.create_sandbox");
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
        let (tx, rx) = mpsc::channel(256);
        let mut outward = cluster_wide_watch_stream(
            sandbox_stream,
            "default".to_string(),
            SupervisorTopology::Combined,
            tx,
            rx,
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
        assert_eq!(beta_stop["spec"]["operatingMode"], "Suspended");
        assert!(beta_stop["spec"].get("replicas").is_none());

        let alpha_start = sandbox_operating_state_patch(SANDBOX_VERSION_V1ALPHA1, "43", true);
        assert_eq!(alpha_start["metadata"]["resourceVersion"], "43");
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

        let err = kubernetes_driver_config_for_spec(sandbox.spec.as_ref(), None).unwrap_err();
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

        let err = kubernetes_driver_config_for_spec(Some(&spec), None).unwrap_err();

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

        kubernetes_driver_config_for_spec(Some(&spec), None)
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
            SUPERVISOR_VOLUME_NAME,
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
        let params = SandboxPodParams {
            client_tls_secret_name: "openshell-client-tls-secret",
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
    fn driver_config_rejects_runtime_provider_spiffe_mount_path() {
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
                                "mount_path": "/custom-spiffe"
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };

        let err =
            kubernetes_driver_config_for_spec(Some(&spec), Some("/custom-spiffe/spire-agent.sock"))
                .unwrap_err();

        assert!(err.contains("/custom-spiffe"));
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
    fn supervisor_sideload_replaces_spoofed_identity_environment() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest",
                    "env": [
                        {"name": openshell_core::sandbox_env::OCI_IMAGE_USER, "value": "spoofed"},
                        {"name": openshell_core::sandbox_env::SANDBOX_UID, "value": "9999"},
                        {"name": openshell_core::sandbox_env::SANDBOX_GID, "value": "9999"},
                        {"name": openshell_core::sandbox_env::OCI_IMAGE_USER, "value": "duplicate"}
                    ]
                }]
            }
        });

        apply_supervisor_sideload(
            &mut pod_template,
            "supervisor-image:latest",
            "IfNotPresent",
            SupervisorSideloadMethod::InitContainer,
            1500,
            1600,
        );

        let agent = &pod_template["spec"]["containers"][0];
        let env = agent["env"].as_array().unwrap();
        for name in [
            openshell_core::sandbox_env::OCI_IMAGE_USER,
            openshell_core::sandbox_env::SANDBOX_UID,
            openshell_core::sandbox_env::SANDBOX_GID,
        ] {
            assert_eq!(
                env.iter().filter(|item| item["name"] == name).count(),
                1,
                "{name} must have one driver-owned value"
            );
        }
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::OCI_IMAGE_USER),
            Some("")
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SANDBOX_UID),
            Some("1500")
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SANDBOX_GID),
            Some("1600")
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

        // `--workdir` is optional for standalone supervisor invocations and
        // has no implicit default, so Kubernetes must pass its fixed workspace.
        let command = pod_template["spec"]["containers"][0]["command"]
            .as_array()
            .expect("command should be set");
        assert_eq!(
            command[0].as_str().unwrap(),
            format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox")
        );
        assert_eq!(
            command,
            serde_json::json!([
                format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox"),
                "--workdir",
                driver_mounts::DEFAULT_WORKSPACE_ROOT
            ])
            .as_array()
            .unwrap()
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
            topology: SupervisorTopology::Sidecar,
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            supervisor_image: "supervisor-image:latest",
            supervisor_image_pull_policy: "IfNotPresent",
            grpc_endpoint: "https://openshell-gateway.openshell.svc:8080",
            client_tls_secret_name: "openshell-client-tls",
            proxy_uid: 2200,
            namespace: "default",
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate {
                image: "agent-image:latest".to_string(),
                environment: std::collections::HashMap::from([
                    (
                        openshell_core::sandbox_env::OCI_IMAGE_USER.to_string(),
                        "spoofed".to_string(),
                    ),
                    (
                        openshell_core::sandbox_env::SANDBOX_UID.to_string(),
                        "9999".to_string(),
                    ),
                    (
                        openshell_core::sandbox_env::SANDBOX_GID.to_string(),
                        "9999".to_string(),
                    ),
                ]),
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
                "--mode=process",
                "--workdir",
                driver_mounts::DEFAULT_WORKSPACE_ROOT
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
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::OCI_IMAGE_USER),
            Some("")
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
        assert_eq!(sidecar["securityContext"]["runAsUser"], 0);
        assert_eq!(sidecar["securityContext"]["runAsGroup"], 1500);
        assert_eq!(sidecar["securityContext"]["runAsNonRoot"], false);
        assert_eq!(
            sidecar["securityContext"]["allowPrivilegeEscalation"],
            false
        );
        assert_eq!(
            sidecar["securityContext"]["capabilities"],
            serde_json::json!({
                "drop": ["ALL"],
                "add": ["SYS_PTRACE", "DAC_READ_SEARCH"]
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
        assert!(
            SIDECAR_SSH_SOCKET_FILE.starts_with('@'),
            "sidecar SSH relay must use a Linux abstract socket"
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::SANDBOX_UID),
            Some("1500")
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::SANDBOX_GID),
            Some("1500")
        );
        assert_eq!(
            rendered_env(sidecar, openshell_core::sandbox_env::OCI_IMAGE_USER),
            Some("")
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
                "0",
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
            topology: SupervisorTopology::Sidecar,
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
        assert_eq!(sidecar["securityContext"]["runAsUser"], 2200);
        assert_eq!(sidecar["securityContext"]["runAsGroup"], 1500);
        assert_eq!(sidecar["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            sidecar["securityContext"]["allowPrivilegeEscalation"],
            false
        );
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
        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        let network_init = init_containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_INIT_CONTAINER_NAME)
            .unwrap();
        assert_eq!(network_init["command"][3], "2200");
    }

    #[test]
    fn sidecar_topology_adds_shared_state_and_tls_volumes() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::Sidecar,
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
        let sidecar = containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_SIDECAR_NAME)
            .unwrap();
        assert_eq!(
            sidecar["securityContext"]["capabilities"],
            serde_json::json!({
                "drop": ["ALL"],
                "add": ["SYS_PTRACE", "DAC_READ_SEARCH"]
            })
        );
        assert_eq!(sidecar["securityContext"]["runAsUser"], 0);
        assert_eq!(sidecar["securityContext"]["runAsGroup"], 1000);
        assert_eq!(sidecar["securityContext"]["runAsNonRoot"], false);
        assert_eq!(
            sidecar["securityContext"]["allowPrivilegeEscalation"],
            false
        );

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
        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        let network_init = init_containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_INIT_CONTAINER_NAME)
            .unwrap();
        assert_eq!(network_init["command"][3], "0");
    }

    #[test]
    fn sidecar_topology_rejects_proxy_uid_matching_sandbox_uid() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::Sidecar,
            proxy_uid: 1500,
            namespace: "default",
            sandbox_uid: 1500,
            ..SandboxPodParams::default()
        };

        let err = validate_proxy_identity(&params).unwrap_err();
        assert!(matches!(err, KubernetesDriverError::Precondition(_)));
        assert!(err.to_string().contains("proxy_uid"));
    }

    #[test]
    fn proxy_pod_topology_runs_process_supervisor_with_gateway_creds() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            supervisor_image: "supervisor-image:latest",
            namespace: "agents",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
            grpc_endpoint: "https://openshell-gateway.openshell.svc:8080",
            proxy_uid: 2200,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            host_gateway_ip: "172.17.0.1",
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

        let names = proxy_pod_resource_names(params.cr_name, params.sandbox_id);
        let service_dns = proxy_pod_service_dns(&names.service, "agents");
        let agent = &pod_template["spec"]["containers"][0];

        assert_eq!(
            pod_template["metadata"]["labels"][LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_AGENT
        );
        // The agent container runs the process supervisor, not the workload
        // directly, and it launches the workload from MAIN_PROCESS_SPEC.
        assert_eq!(
            agent["command"],
            serde_json::json!([
                format!("{SUPERVISOR_MOUNT_PATH}/openshell-sandbox"),
                "--mode=process",
                "--workdir",
                driver_mounts::DEFAULT_WORKSPACE_ROOT
            ])
        );
        // Gateway credentials are RETAINED (the in-pod supervisor owns its own
        // scoped session), unlike the superseded network-only design.
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::ENDPOINT),
            Some(params.grpc_endpoint)
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SUPERVISOR_TOPOLOGY),
            Some("proxy-pod")
        );
        // The non-root agent cannot create a filesystem SSH socket under `/run`,
        // so the relay must use a netns-scoped abstract socket.
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::SSH_SOCKET_PATH),
            Some(PROXY_POD_SSH_SOCKET_FILE)
        );
        assert!(PROXY_POD_SSH_SOCKET_FILE.starts_with('@'));
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::NETWORK_ENFORCEMENT_MODE),
            Some("proxy-pod")
        );
        // The workload's children still egress through the remote proxy Service.
        assert_eq!(
            rendered_env(agent, "HTTP_PROXY"),
            Some(format!("http://{service_dns}:3128").as_str())
        );
        assert_eq!(
            rendered_env(agent, "SSL_CERT_FILE"),
            Some("/etc/openshell-tls/proxy/ca-bundle.pem")
        );
        assert_eq!(
            agent["securityContext"]["capabilities"]["drop"],
            serde_json::json!(["ALL"])
        );
        let proxy_tls_mount = agent["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["name"] == "openshell-proxy-pod-tls")
            .unwrap();
        assert_eq!(proxy_tls_mount["readOnly"], true);

        // Single pod (workload runs inside it); the supervisor binary and the
        // retained credential volumes are all present.
        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        assert!(volumes.iter().any(|volume| {
            volume["name"] == "openshell-proxy-pod-ca-source"
                && volume["secret"]["secretName"] == names.proxy_ca_secret
        }));
        assert!(volumes.iter().any(|volume| {
            volume["name"] == "openshell-proxy-pod-tls" && volume["emptyDir"].is_object()
        }));
        assert!(
            volumes
                .iter()
                .any(|volume| volume["name"] == SUPERVISOR_VOLUME_NAME),
            "supervisor binary volume must be mounted"
        );
        assert!(
            volumes
                .iter()
                .any(|volume| volume["name"] == SERVICE_ACCOUNT_TOKEN_VOLUME_NAME),
            "SA token volume must be retained"
        );

        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        let ca_init = init_containers
            .iter()
            .find(|container| container["name"] == "openshell-proxy-ca-install")
            .unwrap();
        assert_eq!(ca_init["image"], "supervisor-image:latest");
        assert_eq!(ca_init["securityContext"]["runAsUser"], 1500);
        assert_eq!(ca_init["securityContext"]["readOnlyRootFilesystem"], true);
        // Supervisor binary sideload init present (InitContainer method).
        assert!(
            init_containers
                .iter()
                .any(|container| container["name"] == SUPERVISOR_INIT_CONTAINER_NAME)
        );

        assert!(pod_template["spec"].get("affinity").is_none());
    }

    #[test]
    fn proxy_pod_agent_pod_has_no_root_containers() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor-image:latest",
            namespace: "agents",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
            proxy_uid: 2200,
            sandbox_uid: 1500,
            sandbox_gid: 1600,
            // Force the init-container sideload so the supervisor copy-self init
            // is present; on OpenShift's nonroot SCC it must not run as root.
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate {
                image: "agent-image:latest".to_string(),
                ..SandboxTemplate::default()
            },
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        // Supervisor binary sideload, CA install, wait-for-proxy, workspace seed.
        assert_eq!(init_containers.len(), 4);
        for container in containers.iter().chain(init_containers) {
            let security_context = &container["securityContext"];
            assert_ne!(
                security_context["runAsUser"], 0,
                "{} must not run as root",
                container["name"]
            );
            assert_eq!(security_context["runAsNonRoot"], true);
            assert_eq!(security_context["allowPrivilegeEscalation"], false);
            assert_eq!(
                security_context["capabilities"]["drop"],
                serde_json::json!(["ALL"])
            );
        }
    }

    #[test]
    fn proxy_pod_topology_supports_preferred_affinity() {
        let mut spec = serde_json::Map::new();
        apply_proxy_pod_affinity(&mut spec, "sandbox-123", ProxyPodAffinity::Preferred);

        let preferred =
            &spec["affinity"]["podAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0];
        assert_eq!(preferred["weight"], 100);
        assert_eq!(
            preferred["podAffinityTerm"]["labelSelector"]["matchLabels"][LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_SUPERVISOR
        );
        assert_eq!(
            preferred["podAffinityTerm"]["topologyKey"],
            "kubernetes.io/hostname"
        );
    }

    #[test]
    fn proxy_pod_topology_supports_required_affinity_without_replacing_existing_terms() {
        let mut spec = serde_json::json!({
            "affinity": {
                "podAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": [{
                        "topologyKey": "topology.kubernetes.io/zone"
                    }]
                }
            }
        })
        .as_object()
        .unwrap()
        .clone();
        apply_proxy_pod_affinity(&mut spec, "sandbox-123", ProxyPodAffinity::Required);

        let required =
            spec["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                .as_array()
                .unwrap();
        assert_eq!(required.len(), 2);
        assert_eq!(required[0]["topologyKey"], "topology.kubernetes.io/zone");
        assert_eq!(required[1]["topologyKey"], "kubernetes.io/hostname");
    }

    #[test]
    fn proxy_pod_companion_resources_bind_one_agent_to_one_supervisor() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor-image:latest",
            namespace: "agents",
            service_account_name: "openshell-sandbox",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
            grpc_endpoint: "http://openshell-gateway.openshell.svc:8080",
            proxy_uid: 2200,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            host_gateway_ip: "172.17.0.1",
            ..SandboxPodParams::default()
        };
        let names = proxy_pod_resource_names(params.cr_name, params.sandbox_id);
        let owner_ref = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "name": params.sandbox_name,
            "uid": "sandbox-cr-uid",
            "controller": true,
            "blockOwnerDeletion": false
        });

        let supervisor = serde_json::to_value(proxy_pod_supervisor_deployment(
            &names,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &params,
            &KubernetesPodDriverConfig::default(),
            &ProxyPodPlacement::default(),
            1,
            owner_ref.clone(),
        ))
        .unwrap();
        assert_eq!(
            supervisor["metadata"]["ownerReferences"][0]["controller"],
            true
        );
        assert_eq!(
            supervisor["metadata"]["annotations"]["openshell.ai/sandbox-id"],
            "sandbox-123"
        );
        assert_eq!(
            supervisor["metadata"]["labels"][LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_SUPERVISOR
        );
        assert_eq!(supervisor["kind"], "Deployment");
        assert_eq!(supervisor["spec"]["replicas"], 1);
        assert_eq!(
            supervisor["spec"]["selector"]["matchLabels"][LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_SUPERVISOR
        );
        assert_eq!(
            supervisor["spec"]["template"]["metadata"]["labels"][LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_SUPERVISOR
        );
        assert_eq!(
            supervisor["spec"]["template"]["spec"]["hostAliases"][0]["ip"],
            params.host_gateway_ip
        );
        let hostnames = supervisor["spec"]["template"]["spec"]["hostAliases"][0]["hostnames"]
            .as_array()
            .unwrap();
        assert!(hostnames.contains(&serde_json::json!("host.openshell.internal")));
        let container = &supervisor["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(
            rendered_env(container, openshell_core::sandbox_env::PROXY_BIND_ADDR),
            Some("0.0.0.0:3128")
        );

        let agent_egress =
            serde_json::to_value(proxy_pod_agent_egress_network_policy(&names, &params)).unwrap();
        assert_eq!(
            agent_egress["spec"]["policyTypes"],
            serde_json::json!(["Egress"])
        );
        // The egress fence must carry NO owner reference: it is gateway-managed
        // so it outlives the workload pod during deletion rather than being
        // garbage-collected concurrently with it.
        assert!(
            agent_egress["metadata"].get("ownerReferences").is_none(),
            "agent egress NetworkPolicy must have no ownerReferences: {agent_egress}"
        );
        assert_eq!(
            agent_egress["spec"]["podSelector"]["matchLabels"][LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_AGENT
        );
        assert_eq!(
            agent_egress["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"]
                [LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_SUPERVISOR
        );

        let supervisor_ingress = serde_json::to_value(proxy_pod_supervisor_ingress_network_policy(
            &names, &params, owner_ref,
        ))
        .unwrap();
        assert_eq!(
            supervisor_ingress["spec"]["policyTypes"],
            serde_json::json!(["Ingress"])
        );
        assert_eq!(
            supervisor_ingress["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]
                [LABEL_SANDBOX_ROLE],
            SANDBOX_ROLE_AGENT
        );
    }

    #[test]
    fn proxy_pod_topology_rejects_proxy_uid_matching_sandbox_uid() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            proxy_uid: 1500,
            namespace: "default",
            sandbox_uid: 1500,
            ..SandboxPodParams::default()
        };

        let err = validate_proxy_identity(&params).unwrap_err();
        assert!(matches!(err, KubernetesDriverError::Precondition(_)));
        assert!(err.to_string().contains("proxy-pod"));
    }

    /// Every egress rule except the supervisor rule, which is the one carrying
    /// the proxy port.
    fn dns_egress_rules(policy: &NetworkPolicy) -> Vec<serde_json::Value> {
        let policy = serde_json::to_value(policy).unwrap();
        policy["spec"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| {
                !rule["ports"].as_array().is_some_and(|ports| {
                    ports
                        .iter()
                        .any(|port| port["port"] == i64::from(PROXY_POD_PROXY_PORT))
                })
            })
            .cloned()
            .collect()
    }

    fn proxy_pod_egress_policy_with_dns_peers(peers: &[ProxyPodDnsPeer]) -> NetworkPolicy {
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            namespace: "agents",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
            proxy_pod_dns_peers: peers,
            proxy_pod_gateway_peers: &[],
            ..SandboxPodParams::default()
        };
        proxy_pod_agent_egress_network_policy(
            &proxy_pod_resource_names(params.cr_name, params.sandbox_id),
            &params,
        )
    }

    fn sandbox_object_with_conditions(conditions: &[(&str, &str)]) -> DynamicObject {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut obj = DynamicObject::new("sandbox", &resource);
        let conditions: Vec<_> = conditions
            .iter()
            .map(|(kind, status)| serde_json::json!({"type": kind, "status": status}))
            .collect();
        obj.data = serde_json::json!({"status": {"conditions": conditions}});
        obj
    }

    #[test]
    fn agent_command_override_is_rejected_in_every_topology() {
        let config = KubernetesSandboxDriverConfig {
            containers: KubernetesDriverContainersConfig {
                agent: KubernetesContainerDriverConfig {
                    command: vec!["sleep".to_string(), "infinity".to_string()],
                    ..KubernetesContainerDriverConfig::default()
                },
            },
            ..KubernetesSandboxDriverConfig::default()
        };

        // proxy-pod now runs the process supervisor as the entrypoint too, so the
        // override is ignored (and rejected) in every topology.
        for topology in [
            SupervisorTopology::Combined,
            SupervisorTopology::Sidecar,
            SupervisorTopology::ProxyPod,
        ] {
            let err = validate_agent_command_for_topology(&config, topology).unwrap_err();
            assert!(err.contains("not supported"), "{topology}: {err}");
        }
    }

    /// Per-sandbox proxy-pod resources are named from the sandbox name, not
    /// the Sandbox CR name -- the CR is `<workspace>--<sandbox>`. Deriving them
    /// from the CR name silently targets objects that do not exist, which
    /// owner-reference GC then masks on delete but not on stop/start.
    #[test]
    fn proxy_pod_supervisor_inherits_workload_node_placement() {
        let names = proxy_pod_resource_names("ws--dev", "sandbox-1");
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor:latest",
            namespace: "agents",
            sandbox_id: "sandbox-1",
            sandbox_name: "dev",
            proxy_uid: 2000,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod_config = KubernetesPodDriverConfig {
            node_selector: std::iter::once(("pool".to_string(), "gpu".to_string())).collect(),
            tolerations: vec![serde_json::json!({"key": "gpu", "operator": "Exists"})],
            ..KubernetesPodDriverConfig::default()
        };
        let dep = serde_json::to_value(proxy_pod_supervisor_deployment(
            &names,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &params,
            &pod_config,
            &ProxyPodPlacement::default(),
            1,
            serde_json::json!({}),
        ))
        .unwrap();
        let pod_spec = &dep["spec"]["template"]["spec"];
        assert_eq!(pod_spec["nodeSelector"]["pool"], "gpu");
        assert_eq!(pod_spec["tolerations"][0]["key"], "gpu");
    }

    /// The proxy-pod supervisor must route egress through the operator's
    /// corporate upstream proxy, matching sidecar topology, or all permitted
    /// traffic fails (or bypasses the required monitoring route).
    #[test]
    fn proxy_pod_supervisor_forwards_to_upstream_proxy() {
        let names = proxy_pod_resource_names("ws--dev", "sandbox-1");
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor:latest",
            namespace: "agents",
            sandbox_id: "sandbox-1",
            sandbox_name: "dev",
            proxy_uid: 2000,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            https_proxy: Some("http://corp-proxy.example.com:3128"),
            no_proxy: Some("10.0.0.0/8,.svc"),
            ..SandboxPodParams::default()
        };
        let dep = serde_json::to_value(proxy_pod_supervisor_deployment(
            &names,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &params,
            &KubernetesPodDriverConfig::default(),
            &ProxyPodPlacement::default(),
            1,
            serde_json::json!({}),
        ))
        .unwrap();
        let command = dep["spec"]["template"]["spec"]["containers"][0]["command"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let joined = command.join(" ");
        assert!(
            joined.contains("--upstream-proxy http://corp-proxy.example.com:3128"),
            "supervisor command must forward to the upstream proxy: {joined}"
        );
        assert!(
            joined.contains("--upstream-no-proxy 10.0.0.0/8,.svc"),
            "supervisor command must carry no_proxy: {joined}"
        );
        // Credentials are not mounted into the supervisor pod, so no auth-file arg.
        assert!(
            !joined.contains("--upstream-proxy-auth-file"),
            "proxy-pod must not reference an unmounted auth file: {joined}"
        );
    }

    /// The provider SPIFFE Workload API socket must live only in the supervisor
    /// (proxy) pod, which mints provider credentials. The agent pod holds a
    /// scoped process-kind credential that cannot access provider secrets, so it
    /// must not carry an SVID: no CSI volume, no container mount, no env.
    #[test]
    fn proxy_pod_strips_provider_spiffe_from_agent_but_keeps_it_on_supervisor() {
        let names = proxy_pod_resource_names("example-sandbox", "sandbox-123");
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor-image:latest",
            namespace: "agents",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
            proxy_uid: 2200,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            provider_spiffe_enabled: true,
            provider_spiffe_workload_api_socket_path: "/spiffe-workload-api/spire-agent.sock",
            ..SandboxPodParams::default()
        };

        // Agent pod: SPIFFE stripped everywhere.
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
        let agent = &pod_template["spec"]["containers"][0];
        assert!(
            rendered_env(
                agent,
                openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
            )
            .is_none(),
            "agent must not advertise the provider SPIFFE socket"
        );
        let agent_mounts = agent["volumeMounts"]
            .as_array()
            .expect("agent volumeMounts");
        assert!(
            !agent_mounts
                .iter()
                .any(|m| m["name"] == SPIFFE_WORKLOAD_API_VOLUME_NAME),
            "agent container must not mount the SPIFFE workload API socket"
        );
        let pod_volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("pod volumes");
        assert!(
            !pod_volumes
                .iter()
                .any(|v| v["name"] == SPIFFE_WORKLOAD_API_VOLUME_NAME),
            "agent pod must not carry the SPIFFE CSI volume"
        );

        // Supervisor (proxy) pod: SPIFFE retained (it mints provider credentials).
        let dep = serde_json::to_value(proxy_pod_supervisor_deployment(
            &names,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &params,
            &KubernetesPodDriverConfig::default(),
            &ProxyPodPlacement::default(),
            1,
            serde_json::json!({}),
        ))
        .unwrap();
        let sup_spec = &dep["spec"]["template"]["spec"];
        let sup_mounts = sup_spec["containers"][0]["volumeMounts"]
            .as_array()
            .expect("supervisor volumeMounts");
        assert!(
            sup_mounts
                .iter()
                .any(|m| m["name"] == SPIFFE_WORKLOAD_API_VOLUME_NAME),
            "supervisor container must mount the SPIFFE workload API socket"
        );
        let sup_volumes = sup_spec["volumes"].as_array().expect("supervisor volumes");
        assert!(
            sup_volumes
                .iter()
                .any(|v| v["name"] == SPIFFE_WORKLOAD_API_VOLUME_NAME
                    && v["csi"]["driver"] == "csi.spiffe.io"),
            "supervisor pod must carry the SPIFFE CSI volume"
        );
    }

    /// The supervisor must also honor the public `platform_config` placement the
    /// workload pod reads (runtime class, node selector, tolerations). Otherwise
    /// the workload can land under Kata (or a required node) while the supervisor
    /// takes the cluster default, breaking same-node pairing.
    #[test]
    fn proxy_pod_supervisor_inherits_platform_config_placement() {
        let toleration = Struct {
            fields: std::iter::once((
                "key".to_string(),
                Value {
                    kind: Some(Kind::StringValue("dedicated".to_string())),
                },
            ))
            .collect(),
        };
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: [
                    (
                        "runtime_class_name".to_string(),
                        Value {
                            kind: Some(Kind::StringValue("kata-containers".to_string())),
                        },
                    ),
                    (
                        "node_selector".to_string(),
                        Value {
                            kind: Some(Kind::StructValue(Struct {
                                fields: std::iter::once((
                                    "disktype".to_string(),
                                    Value {
                                        kind: Some(Kind::StringValue("ssd".to_string())),
                                    },
                                ))
                                .collect(),
                            })),
                        },
                    ),
                    (
                        "tolerations".to_string(),
                        Value {
                            kind: Some(Kind::ListValue(prost_types::ListValue {
                                values: vec![Value {
                                    kind: Some(Kind::StructValue(toleration)),
                                }],
                            })),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            }),
            ..SandboxTemplate::default()
        };
        let placement = ProxyPodPlacement::from_template(Some(&template));

        let names = proxy_pod_resource_names("ws--dev", "sandbox-1");
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor:latest",
            namespace: "agents",
            sandbox_id: "sandbox-1",
            sandbox_name: "dev",
            proxy_uid: 2000,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            // Cluster default must lose to the platform_config runtime class.
            default_runtime_class_name: "gvisor",
            ..SandboxPodParams::default()
        };
        let dep = serde_json::to_value(proxy_pod_supervisor_deployment(
            &names,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &params,
            &KubernetesPodDriverConfig::default(),
            &placement,
            1,
            serde_json::json!({}),
        ))
        .unwrap();
        let pod_spec = &dep["spec"]["template"]["spec"];
        assert_eq!(pod_spec["runtimeClassName"], "kata-containers");
        assert_eq!(pod_spec["nodeSelector"]["disktype"], "ssd");
        assert_eq!(pod_spec["tolerations"][0]["key"], "dedicated");
    }

    /// Companion reconciliation rebuilds a repaired supervisor's placement and
    /// log level from the Sandbox CR's rendered agent pod, so it lands where the
    /// workload can pair with it even after a crash lost the original spec.
    #[test]
    fn proxy_pod_placement_and_log_level_recovered_from_cr() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut obj = DynamicObject::new("ws--dev", &resource);
        obj.data = serde_json::json!({
            "spec": {
                "podTemplate": {
                    "spec": {
                        "runtimeClassName": "kata-containers",
                        "nodeSelector": {"disktype": "ssd"},
                        "tolerations": [{"key": "dedicated", "operator": "Exists"}],
                        "containers": [{
                            "name": "agent",
                            "env": [{
                                "name": openshell_core::sandbox_env::LOG_LEVEL,
                                "value": "debug"
                            }]
                        }]
                    }
                }
            }
        });

        let placement = proxy_pod_placement_from_cr(&obj);
        assert_eq!(
            placement.runtime_class_name.as_deref(),
            Some("kata-containers")
        );
        assert_eq!(placement.node_selector.unwrap()["disktype"], "ssd");
        assert_eq!(placement.tolerations.unwrap()[0]["key"], "dedicated");

        let env = proxy_pod_log_level_env_from_cr(&obj);
        assert_eq!(
            env.get(openshell_core::sandbox_env::LOG_LEVEL)
                .map(String::as_str),
            Some("debug")
        );
    }

    /// An empty/absent pod template must not fabricate placement or env.
    #[test]
    fn proxy_pod_reconstruction_tolerates_missing_pod_template() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let obj = DynamicObject::new("ws--dev", &resource);
        let placement = proxy_pod_placement_from_cr(&obj);
        assert!(placement.runtime_class_name.is_none());
        assert!(placement.node_selector.is_none());
        assert!(placement.tolerations.is_none());
        assert!(proxy_pod_log_level_env_from_cr(&obj).is_empty());
    }

    #[test]
    fn proxy_pod_pod_template_references_companions_by_cr_name() {
        // Shared mode: CR name is `<workspace>--<name>`, distinct from the bare
        // sandbox name. The workload pod's CA secret mount and proxy URL must
        // use the CR-name-derived companion names, or the pod mounts a secret
        // that does not exist (and never becomes Ready).
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor:latest",
            namespace: "agents",
            sandbox_id: "sandbox-1",
            sandbox_name: "dev",
            cr_name: "team-a--dev",
            proxy_uid: 2000,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate {
                image: "agent:latest".to_string(),
                ..SandboxTemplate::default()
            },
            false,
            &std::collections::HashMap::new(),
            false,
            &params,
        );
        let names = proxy_pod_resource_names(params.cr_name, params.sandbox_id);
        let service_dns = proxy_pod_service_dns(&names.service, "agents");
        let agent = &pod_template["spec"]["containers"][0];
        assert_eq!(
            rendered_env(agent, "HTTP_PROXY"),
            Some(format!("http://{service_dns}:3128").as_str())
        );
        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        assert!(
            volumes.iter().any(|v| {
                v["name"] == "openshell-proxy-pod-ca-source"
                    && v["secret"]["secretName"] == serde_json::json!(names.proxy_ca_secret)
            }),
            "workload CA volume must reference the CR-name-derived secret {}",
            names.proxy_ca_secret
        );
    }

    #[test]
    fn proxy_pod_resource_names_disambiguate_by_sandbox_id() {
        // Distinct sandbox instances get distinct companion names even when
        // their CR names are identical, because uniqueness is keyed on the
        // immutable per-instance UUID rather than the CR name.
        let a =
            proxy_pod_resource_names("workspace-a--dev", "11111111-1111-1111-1111-111111111111");
        let b =
            proxy_pod_resource_names("workspace-a--dev", "22222222-2222-2222-2222-222222222222");
        assert_ne!(a.supervisor_deployment, b.supervisor_deployment);
        assert_ne!(a.service, b.service);
        assert_ne!(a.proxy_ca_secret, b.proxy_ca_secret);
        assert_ne!(a.agent_egress_network_policy, b.agent_egress_network_policy);
        assert_ne!(
            a.supervisor_ingress_network_policy,
            b.supervisor_ingress_network_policy
        );
    }

    #[test]
    fn proxy_pod_resource_names_are_stable_for_an_instance() {
        // The same sandbox id yields the same names across calls (create,
        // reconcile, scale all recompute them independently).
        let first = proxy_pod_resource_names("ws--dev", "abc-123");
        let second = proxy_pod_resource_names("ws--dev", "abc-123");
        assert_eq!(first.supervisor_deployment, second.supervisor_deployment);
    }

    #[test]
    fn proxy_pod_resource_names_avoid_truncation_collision() {
        // Two CR names that collided under the old 32-bit name hash — a shared
        // 48-char prefix that truncates identically — now differ because the
        // suffix is a 64-bit hash of the distinct sandbox UUIDs.
        let long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let a = proxy_pod_resource_names(
            &format!("{long}-955pct6t1ohlwg"),
            "11111111-1111-1111-1111-111111111111",
        );
        let b = proxy_pod_resource_names(
            &format!("{long}-uw6jys21qzazvy"),
            "22222222-2222-2222-2222-222222222222",
        );
        assert_ne!(a.supervisor_deployment, b.supervisor_deployment);
        assert!(a.supervisor_deployment.len() <= MAX_KUBE_NAME_LEN);
        assert!(b.supervisor_deployment.len() <= MAX_KUBE_NAME_LEN);
    }

    #[test]
    fn supervisor_topologies_require_a_supervisor_session() {
        let obj = sandbox_object_with_conditions(&[("Ready", "True")]);
        // proxy-pod now runs an in-pod process supervisor, so it too requires a
        // session (relays are available).
        for topology in [
            SupervisorTopology::Combined,
            SupervisorTopology::Sidecar,
            SupervisorTopology::ProxyPod,
        ] {
            let status = status_from_object(&obj, topology).unwrap();
            assert_eq!(
                status.supervisor_session_model,
                SupervisorSessionModel::Required as i32,
                "{topology}"
            );
        }
    }

    #[test]
    fn mark_supervisor_unavailable_forces_not_ready() {
        let mut sandbox = Sandbox {
            id: "id".to_string(),
            name: "dev".to_string(),
            namespace: "agents".to_string(),
            spec: None,
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: String::new(),
                    message: String::new(),
                    last_transition_time: String::new(),
                }],
                ..SandboxStatus::default()
            }),
            workspace: "default".to_string(),
        };
        mark_supervisor_unavailable(&mut sandbox);
        let ready = sandbox
            .status
            .unwrap()
            .conditions
            .into_iter()
            .find(|condition| condition.r#type == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        // Must be a transient reason so the gateway maps it to a recoverable
        // Provisioning phase rather than terminal Error.
        assert_eq!(ready.reason, "DependenciesNotReady");
    }

    #[test]
    fn mark_supervisor_unavailable_adds_condition_when_absent() {
        let mut sandbox = Sandbox {
            id: "id".to_string(),
            name: "dev".to_string(),
            namespace: "agents".to_string(),
            spec: None,
            status: Some(SandboxStatus::default()),
            workspace: "default".to_string(),
        };
        mark_supervisor_unavailable(&mut sandbox);
        let conditions = sandbox.status.unwrap().conditions;
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].r#type, "Ready");
        assert_eq!(conditions[0].status, "False");
    }

    #[test]
    fn topology_from_object_prefers_annotation_over_fallback() {
        let mut obj = sandbox_object_with_conditions(&[("Ready", "True")]);
        obj.metadata.annotations = Some(BTreeMap::from([(
            ANNOTATION_SUPERVISOR_TOPOLOGY.to_string(),
            "proxy-pod".to_string(),
        )]));
        // Even if the gateway is now configured for `combined`, a CR created
        // under `proxy-pod` must be interpreted as `proxy-pod`.
        assert_eq!(
            topology_from_object(&obj, SupervisorTopology::Combined),
            SupervisorTopology::ProxyPod
        );
    }

    #[test]
    fn topology_from_object_falls_back_without_annotation() {
        let obj = sandbox_object_with_conditions(&[("Ready", "True")]);
        // A CR predating the annotation keeps a non-proxy-pod fallback as-is.
        assert_eq!(
            topology_from_object(&obj, SupervisorTopology::Sidecar),
            SupervisorTopology::Sidecar
        );
    }

    #[test]
    fn desired_supervisor_replicas_follows_operating_state() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut running = DynamicObject::new("s", &resource);
        running.data = serde_json::json!({"spec": {"operatingMode": "Running"}});
        assert_eq!(desired_supervisor_replicas(&running), 1);

        let mut suspended = DynamicObject::new("s", &resource);
        suspended.data = serde_json::json!({"spec": {"operatingMode": "Suspended"}});
        assert_eq!(desired_supervisor_replicas(&suspended), 0);

        // v1alpha1 encodes it as spec.replicas.
        let mut alpha_stopped = DynamicObject::new("s", &resource);
        alpha_stopped.data = serde_json::json!({"spec": {"replicas": 0}});
        assert_eq!(desired_supervisor_replicas(&alpha_stopped), 0);

        // No operating state recorded defaults to running.
        let bare = DynamicObject::new("s", &resource);
        assert_eq!(desired_supervisor_replicas(&bare), 1);
    }

    #[test]
    fn topology_from_object_never_falls_back_to_proxy_pod() {
        // An un-annotated CR was created before this branch, so it was never
        // proxy-pod. Even when the gateway is now configured proxy-pod, it must
        // not be misclassified as such (which would report it sessionless and
        // hunt for companions it never had).
        let obj = sandbox_object_with_conditions(&[("Ready", "True")]);
        assert_eq!(
            topology_from_object(&obj, SupervisorTopology::ProxyPod),
            SupervisorTopology::Combined
        );
    }

    #[test]
    fn sandbox_from_object_derives_session_model_from_persisted_topology() {
        let mut obj = sandbox_object_with_conditions(&[("Ready", "True")]);
        obj.metadata.name = Some("alpha--work".to_string());
        obj.metadata.annotations = Some(BTreeMap::from([
            (LABEL_SANDBOX_ID.to_string(), "uuid-123".to_string()),
            (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
            (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (
                ANNOTATION_SUPERVISOR_TOPOLOGY.to_string(),
                "proxy-pod".to_string(),
            ),
        ]));

        // The persisted `proxy-pod` annotation is honored over the `combined`
        // fallback; every topology now requires a supervisor session.
        let (_, sandbox) =
            sandbox_from_object("default", obj, SupervisorTopology::Combined).unwrap();
        assert_eq!(
            sandbox.status.unwrap().supervisor_session_model,
            SupervisorSessionModel::Required as i32
        );
    }

    /// The agent pod must not report Ready before its paired supervisor is
    /// serving: the gateway derives readiness from the pod for this topology,
    /// so a pod that is up without a proxy would advertise egress it does not
    /// have.
    #[test]
    fn proxy_pod_agent_waits_for_its_paired_supervisor() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::ProxyPod,
            supervisor_image: "supervisor-image:latest",
            namespace: "agents",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
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
        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        let wait = init_containers
            .iter()
            .find(|c| c["name"] == PROXY_POD_WAIT_INIT_CONTAINER_NAME)
            .expect("proxy-pod agent pod waits for its supervisor");

        let command = wait["command"].as_array().unwrap();
        assert_eq!(command[1], "wait-for-tcp");
        let names = proxy_pod_resource_names(params.cr_name, params.sandbox_id);
        let service_dns = proxy_pod_service_dns(&names.service, "agents");
        assert_eq!(command[2], format!("{service_dns}:3128"));
        assert_eq!(wait["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            wait["securityContext"]["capabilities"]["drop"],
            serde_json::json!(["ALL"])
        );
    }

    #[test]
    fn other_topologies_have_no_wait_for_proxy_init_container() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::Sidecar,
            supervisor_image: "supervisor-image:latest",
            namespace: "agents",
            sandbox_id: "sandbox-123",
            sandbox_name: "example-sandbox",
            cr_name: "example-sandbox",
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
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !init_containers
                .iter()
                .any(|c| c["name"] == PROXY_POD_WAIT_INIT_CONTAINER_NAME)
        );
    }

    #[test]
    fn proxy_pod_dns_peers_default_to_upstream_kube_system_conventions() {
        let peers = crate::config::KubernetesProxyPodConfig::default().dns_peers;
        let rules = dns_egress_rules(&proxy_pod_egress_policy_with_dns_peers(&peers));

        assert_eq!(rules.len(), 2);
        let mut apps = Vec::new();
        for rule in &rules {
            let to = rule["to"].as_array().unwrap();
            assert_eq!(to.len(), 1);
            assert_eq!(
                to[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
                "kube-system"
            );
            for port in rule["ports"].as_array().unwrap() {
                assert_eq!(port["port"], 53);
            }
            apps.push(to[0]["podSelector"]["matchLabels"]["k8s-app"].clone());
        }
        assert!(apps.contains(&serde_json::json!("kube-dns")));
        assert!(apps.contains(&serde_json::json!("coredns")));
    }

    /// `OpenShift` hosts cluster DNS in `openshift-dns`, not `kube-system`, and
    /// labels the pods with `dns.operator.openshift.io/daemonset-dns=default`.
    /// The upstream default matches nothing there, leaving the agent pod unable
    /// to resolve even its own paired supervisor Service.
    #[test]
    fn proxy_pod_dns_peers_render_openshift_selectors() {
        let peers = vec![ProxyPodDnsPeer {
            namespace_labels: std::iter::once((
                "kubernetes.io/metadata.name".to_string(),
                "openshift-dns".to_string(),
            ))
            .collect(),
            pod_labels: std::iter::once((
                "dns.operator.openshift.io/daemonset-dns".to_string(),
                "default".to_string(),
            ))
            .collect(),
            port: 5353,
        }];
        let rule = dns_egress_rules(&proxy_pod_egress_policy_with_dns_peers(&peers))
            .pop()
            .unwrap();
        let to = rule["to"].as_array().unwrap();

        assert_eq!(to.len(), 1);
        assert_eq!(
            to[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "openshift-dns"
        );
        assert_eq!(
            to[0]["podSelector"]["matchLabels"]["dns.operator.openshift.io/daemonset-dns"],
            "default"
        );
        // OpenShift's dns-default Service maps 53 onto container port 5353.
        // Egress rules match the destination pod port, so the rule must carry
        // 5353 rather than the Service port.
        for port in rule["ports"].as_array().unwrap() {
            assert_eq!(port["port"], 5353);
        }
    }

    /// A `NetworkPolicy` egress rule with an empty `to` array matches every
    /// destination. Emitting one for an empty peer list would open DNS-port
    /// egress cluster-wide, so the rule is omitted entirely instead.
    #[test]
    fn proxy_pod_empty_dns_peers_omit_the_rule_rather_than_allowing_all() {
        let policy = proxy_pod_egress_policy_with_dns_peers(&[]);
        assert!(dns_egress_rules(&policy).is_empty());

        let policy = serde_json::to_value(&policy).unwrap();
        let egress = policy["spec"]["egress"].as_array().unwrap();
        assert_eq!(egress.len(), 1);
        assert!(
            !egress
                .iter()
                .any(|rule| rule["to"].as_array().is_some_and(Vec::is_empty))
        );
    }

    #[test]
    fn proxy_pod_dns_peers_allow_a_namespace_only_peer() {
        let peers = vec![ProxyPodDnsPeer {
            namespace_labels: std::iter::once((
                "kubernetes.io/metadata.name".to_string(),
                "openshift-dns".to_string(),
            ))
            .collect(),
            pod_labels: BTreeMap::new(),
            port: 5353,
        }];
        let rule = dns_egress_rules(&proxy_pod_egress_policy_with_dns_peers(&peers))
            .pop()
            .unwrap();
        let to = rule["to"].as_array().unwrap();

        assert_eq!(to.len(), 1);
        assert!(to[0].get("namespaceSelector").is_some());
        assert!(to[0].get("podSelector").is_none());
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
            .find(|v| v["name"] == CLIENT_TLS_VOLUME_NAME)
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
            1000, // sandbox_uid
            1000, // sandbox_gid
            SupervisorTopology::Combined,
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
            1000,
            SupervisorTopology::Combined,
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

        apply_workspace_persistence(
            &mut pod_template,
            "img:latest",
            "Always",
            1000,
            1000,
            SupervisorTopology::Combined,
        );

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
    fn workspace_persistence_uses_non_root_init_container_for_proxy_pod() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "img:latest"
                }]
            }
        });

        apply_workspace_persistence(
            &mut pod_template,
            "img:latest",
            "IfNotPresent",
            1500,
            1600,
            SupervisorTopology::ProxyPod,
        );

        let security_context = &pod_template["spec"]["initContainers"][0]["securityContext"];
        assert_eq!(security_context["runAsUser"], 1500);
        assert_eq!(security_context["runAsGroup"], 1600);
        assert_eq!(security_context["runAsNonRoot"], true);
        assert_eq!(security_context["allowPrivilegeEscalation"], false);
        assert_eq!(
            security_context["capabilities"]["drop"],
            serde_json::json!(["ALL"])
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
        let caps = pod_template["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
            .as_array()
            .unwrap();
        assert!(caps.contains(&serde_json::json!("SETUID")));
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
            volume["name"] == SERVICE_ACCOUNT_TOKEN_VOLUME_NAME
                && volume["projected"]["sources"][0]["serviceAccountToken"]["path"] == "token"
        }));

        assert_eq!(
            pod_template["metadata"]["labels"][LABEL_MANAGED_BY],
            serde_json::json!(LABEL_MANAGED_BY_VALUE)
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
    fn sandbox_pod_clears_unsupported_network_capabilities() {
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
        let entries = env
            .iter()
            .filter(|entry| {
                entry["name"] == openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["value"], serde_json::json!(""));
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

        let (kube_name, sandbox) =
            sandbox_from_object("default", obj, SupervisorTopology::Combined).unwrap();
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

        let (_, sandbox) =
            sandbox_from_object("default", obj, SupervisorTopology::Combined).unwrap();
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

        let result = sandbox_from_object("default", obj, SupervisorTopology::Combined);
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

        let (_, sandbox) =
            sandbox_from_object("openshell", obj, SupervisorTopology::Combined).unwrap();
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

        let result = sandbox_from_object("default", obj, SupervisorTopology::Combined);
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
    fn upstream_proxy_is_injected_only_into_network_supervisors() {
        let params = SandboxPodParams {
            topology: SupervisorTopology::Sidecar,
            supervisor_sideload_method: SupervisorSideloadMethod::InitContainer,
            supervisor_image: "supervisor-image:latest",
            https_proxy: Some("http://proxy.corp.example:8080"),
            no_proxy: Some(".svc.cluster.local,10.96.0.0/12"),
            proxy_auth_secret_name: Some("corporate-proxy-auth"),
            proxy_auth_secret_key: Some("credentials"),
            proxy_auth_allow_insecure: true,
            proxy_connect_by_hostname: true,
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            false,
            &params,
        );
        let containers = pod["spec"]["containers"].as_array().unwrap();
        let network = containers
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_SIDECAR_NAME)
            .unwrap();
        let command = network["command"].as_array().unwrap();
        assert!(command.iter().any(|arg| arg == "--upstream-proxy"));
        assert!(command.iter().any(|arg| arg == "--upstream-no-proxy"));
        let auth_file_index = command
            .iter()
            .position(|arg| arg == "--upstream-proxy-auth-file")
            .unwrap();
        assert_eq!(
            command[auth_file_index + 1],
            openshell_core::container_paths::UPSTREAM_PROXY_AUTH_MOUNT_PATH
        );
        assert!(
            command
                .iter()
                .any(|arg| arg == "--upstream-proxy-auth-allow-insecure")
        );
        assert!(
            command
                .iter()
                .any(|arg| arg == "--upstream-proxy-connect-by-hostname")
        );
        assert!(
            network["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["name"] == UPSTREAM_PROXY_AUTH_VOLUME_NAME)
        );

        let init = pod["spec"]["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == SUPERVISOR_NETWORK_INIT_CONTAINER_NAME)
            .unwrap();
        assert!(!init["command"].as_array().unwrap().iter().any(|arg| {
            arg.as_str()
                .is_some_and(|arg| arg.starts_with("--upstream-"))
        }));
        let agent = containers
            .iter()
            .find(|container| container["name"] == "agent")
            .unwrap();
        assert!(
            !agent["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["name"] == UPSTREAM_PROXY_AUTH_VOLUME_NAME)
        );
        assert!(!agent["env"].as_array().unwrap().iter().any(|entry| {
            entry["value"] == "corporate-proxy-auth" || entry["value"] == "credentials"
        }));

        let volume = pod["spec"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == UPSTREAM_PROXY_AUTH_VOLUME_NAME)
            .unwrap();
        assert_eq!(volume["secret"]["secretName"], "corporate-proxy-auth");
        assert_eq!(volume["secret"]["items"][0]["key"], "credentials");
        assert_eq!(
            volume["secret"]["items"][0]["path"],
            upstream_proxy_auth_file_name()
        );
        assert_eq!(volume["secret"]["defaultMode"], 0o440);
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
    fn supervisor_availability_from_deployment_reads_available_replicas() {
        use k8s_openapi::api::apps::v1::DeploymentStatus;
        let ready = Deployment {
            status: Some(DeploymentStatus {
                available_replicas: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            supervisor_availability_from_deployment(&ready),
            SupervisorAvailability::Available
        );

        // Zero available replicas, and a status with no replica counts at all,
        // both mean unavailable — never Unknown (the object is in hand).
        let zero = Deployment {
            status: Some(DeploymentStatus {
                available_replicas: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            supervisor_availability_from_deployment(&zero),
            SupervisorAvailability::Unavailable
        );
        assert_eq!(
            supervisor_availability_from_deployment(&Deployment::default()),
            SupervisorAvailability::Unavailable
        );
    }

    #[test]
    fn supervisor_deployment_sandbox_id_reads_label() {
        let deployment = Deployment {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([(
                    LABEL_SANDBOX_ID.to_string(),
                    "sb-77".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            supervisor_deployment_sandbox_id(&deployment),
            Some("sb-77".to_string())
        );
    }

    #[test]
    fn supervisor_deployment_sandbox_id_none_when_missing_or_empty() {
        let no_labels = Deployment::default();
        assert_eq!(supervisor_deployment_sandbox_id(&no_labels), None);

        let empty = Deployment {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([(
                    LABEL_SANDBOX_ID.to_string(),
                    String::new(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(supervisor_deployment_sandbox_id(&empty), None);
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
}
