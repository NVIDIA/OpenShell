// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes compute driver.

use crate::config::KubernetesComputeConfig;
use futures::{Stream, StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Event as KubeEventObj, Node};
use kube::api::{Api, ApiResource, DeleteParams, ListParams, PostParams};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::proto::compute::v1::{
    DriverCondition as SandboxCondition, DriverPlatformEvent as PlatformEvent,
    DriverSandbox as Sandbox, DriverSandboxSpec as SandboxSpec,
    DriverSandboxStatus as SandboxStatus, DriverSandboxTemplate as SandboxTemplate,
    GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
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

/// Timeout for individual Kubernetes API calls (create, delete, get).
/// This prevents gRPC handlers from blocking indefinitely when the k8s
/// API server is unreachable or slow.
const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_VERSION: &str = "v1alpha1";
pub const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_ID_LABEL: &str = "openshell.ai/sandbox-id";
const SANDBOX_MANAGED_LABEL: &str = "openshell.ai/managed-by";
const SANDBOX_MANAGED_VALUE: &str = "openshell";
const GPU_RESOURCE_NAME: &str = "nvidia.com/gpu";
const GPU_RESOURCE_QUANTITY: &str = "1";

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

/// Default storage request for the workspace PVC.
const WORKSPACE_DEFAULT_STORAGE: &str = "2Gi";

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
    pub async fn new(config: KubernetesComputeConfig) -> Result<Self, KubeError> {
        let base_config = match kube::Config::incluster() {
            Ok(c) => c,
            Err(_) => kube::Config::infer()
                .await
                .map_err(kube::Error::InferConfig)?,
        };

        let mut kube_config = base_config.clone();
        kube_config.connect_timeout = Some(Duration::from_secs(10));
        kube_config.read_timeout = Some(Duration::from_secs(30));
        kube_config.write_timeout = Some(Duration::from_secs(30));
        let client = Client::try_from(kube_config)?;

        let mut watch_kube_config = base_config;
        watch_kube_config.connect_timeout = Some(Duration::from_secs(10));
        watch_kube_config.read_timeout = None;
        watch_kube_config.write_timeout = Some(Duration::from_secs(30));
        let watch_client = Client::try_from(watch_kube_config)?;

        Ok(Self {
            client,
            watch_client,
            config,
        })
    }

    pub async fn capabilities(&self) -> Result<GetCapabilitiesResponse, String> {
        Ok(GetCapabilitiesResponse {
            driver_name: "kubernetes".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            supports_gpu: self.has_gpu_capacity().await.unwrap_or(false),
            gpu_count: 0,
        })
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

    pub const fn ssh_handshake_skew_secs(&self) -> u64 {
        self.config.ssh_handshake_skew_secs
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
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(name)).await {
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

        let api = self.api();
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.list(&ListParams::default())).await {
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

    fn ssh_handshake_secret(&self) -> &str {
        &self.config.ssh_handshake_secret
    }

    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<(), KubernetesDriverError> {
        let name = sandbox.name.as_str();
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
        obj.data = sandbox_to_k8s_spec(
            sandbox.spec.as_ref(),
            &self.config.default_image,
            &self.config.image_pull_policy,
            &self.config.supervisor_image,
            &self.config.supervisor_image_pull_policy,
            &sandbox.id,
            &sandbox.name,
            &self.config.grpc_endpoint,
            self.ssh_socket_path(),
            self.ssh_handshake_secret(),
            self.ssh_handshake_skew_secs(),
            &self.config.client_tls_secret_name,
            &self.config.host_gateway_ip,
        );
        let api = self.api();

        match tokio::time::timeout(KUBE_API_TIMEOUT, api.create(&PostParams::default(), &obj)).await
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

fn sandbox_labels(sandbox: &Sandbox) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(SANDBOX_ID_LABEL.to_string(), sandbox.id.clone());
    labels.insert(
        SANDBOX_MANAGED_LABEL.to_string(),
        SANDBOX_MANAGED_VALUE.to_string(),
    );
    labels
}

fn sandbox_id_from_object(obj: &DynamicObject) -> Result<String, String> {
    if let Some(labels) = obj.metadata.labels.as_ref()
        && let Some(id) = labels.get(SANDBOX_ID_LABEL)
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

/// Path where the supervisor binary is mounted inside the agent container.
const SUPERVISOR_MOUNT_PATH: &str = "/opt/openshell/bin";

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

/// Path of the supervisor binary inside the supervisor image.
///
/// The supervisor image places the binary at the filesystem root and ships
/// nothing else. We invoke it directly — there is no shell, `cp`, or PATH
/// resolution available inside the image.
const SUPERVISOR_IMAGE_BINARY_PATH: &str = "/openshell-sandbox";

/// Build the init container that copies the supervisor binary into the emptyDir.
///
/// The supervisor image contains only the supervisor binary at
/// `/openshell-sandbox`. We invoke that binary with the `copy-self`
/// subcommand so it copies itself into the shared emptyDir volume, where the
/// agent container then executes it from a fixed, writable path. This pattern
/// (binary self-copy) avoids requiring `sh`/`cp` in the supervisor image and
/// mirrors the approach used by argoexec's emissary executor.
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
/// Injects an emptyDir volume, an init container that copies the supervisor
/// binary from the supervisor image into that volume, and a read-only volume
/// mount + command override on the agent container.
///
/// The `runAsUser: 0` override ensures the supervisor binary runs as root
/// regardless of the image's `USER` directive. The supervisor needs root for
/// network namespace creation, proxy setup, and Landlock/seccomp configuration.
/// It drops to the appropriate non-root user for child processes via the
/// policy's `run_as_user`/`run_as_group`.
fn apply_supervisor_sideload(
    pod_template: &mut serde_json::Value,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // 1. Add the emptyDir volume to spec.volumes
    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        volumes.push(supervisor_volume());
    }

    // 2. Add the init container that copies the binary into the emptyDir
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
fn default_workspace_volume_claim_templates() -> serde_json::Value {
    serde_json::json!([{
        "metadata": {
            "name": WORKSPACE_VOLUME_NAME
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": WORKSPACE_DEFAULT_STORAGE
                }
            }
        }
    }])
}

#[allow(clippy::too_many_arguments)]
fn sandbox_to_k8s_spec(
    spec: Option<&SandboxSpec>,
    default_image: &str,
    image_pull_policy: &str,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_socket_path: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    client_tls_secret_name: &str,
    host_gateway_ip: &str,
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
        if !spec.log_level.is_empty() {
            root.insert("logLevel".to_string(), serde_json::json!(spec.log_level));
        }
        if !spec.environment.is_empty() {
            root.insert(
                "environment".to_string(),
                serde_json::json!(spec.environment),
            );
        }
        if let Some(template) = spec.template.as_ref() {
            root.insert(
                "podTemplate".to_string(),
                sandbox_template_to_k8s(
                    template,
                    spec.gpu,
                    default_image,
                    image_pull_policy,
                    supervisor_image,
                    supervisor_image_pull_policy,
                    sandbox_id,
                    sandbox_name,
                    grpc_endpoint,
                    ssh_socket_path,
                    ssh_handshake_secret,
                    ssh_handshake_skew_secs,
                    &spec.environment,
                    client_tls_secret_name,
                    host_gateway_ip,
                    inject_workspace,
                ),
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
            default_workspace_volume_claim_templates(),
        );
    }

    // podTemplate is required by the Kubernetes CRD - ensure it's always present
    if !root.contains_key("podTemplate") {
        let empty_env = std::collections::HashMap::new();
        let spec_env = spec.as_ref().map_or(&empty_env, |s| &s.environment);
        root.insert(
            "podTemplate".to_string(),
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                spec.as_ref().is_some_and(|s| s.gpu),
                default_image,
                image_pull_policy,
                supervisor_image,
                supervisor_image_pull_policy,
                sandbox_id,
                sandbox_name,
                grpc_endpoint,
                ssh_socket_path,
                ssh_handshake_secret,
                ssh_handshake_skew_secs,
                spec_env,
                client_tls_secret_name,
                host_gateway_ip,
                inject_workspace,
            ),
        );
    }

    serde_json::Value::Object(
        std::iter::once(("spec".to_string(), serde_json::Value::Object(root))).collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn sandbox_template_to_k8s(
    template: &SandboxTemplate,
    gpu: bool,
    default_image: &str,
    image_pull_policy: &str,
    supervisor_image: &str,
    supervisor_image_pull_policy: &str,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_socket_path: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
    client_tls_secret_name: &str,
    host_gateway_ip: &str,
    inject_workspace: bool,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    if !template.labels.is_empty() {
        metadata.insert("labels".to_string(), serde_json::json!(template.labels));
    }
    if let Some(annotations) = platform_config_struct(template, "annotations") {
        metadata.insert("annotations".to_string(), annotations);
    }

    let mut spec = serde_json::Map::new();
    if let Some(runtime_class) = platform_config_string(template, "runtime_class_name") {
        spec.insert(
            "runtimeClassName".to_string(),
            serde_json::json!(runtime_class),
        );
    }

    let mut container = serde_json::Map::new();
    container.insert("name".to_string(), serde_json::json!("agent"));
    // Use template image if provided, otherwise fall back to default
    let image = if template.image.is_empty() {
        default_image
    } else {
        &template.image
    };
    if !image.is_empty() {
        container.insert("image".to_string(), serde_json::json!(image));
        if !image_pull_policy.is_empty() {
            container.insert(
                "imagePullPolicy".to_string(),
                serde_json::json!(image_pull_policy),
            );
        }
    }

    // Build environment variables - start with OpenShell-required vars
    let env = build_env_list(
        None,
        &template.environment,
        spec_environment,
        sandbox_id,
        sandbox_name,
        grpc_endpoint,
        ssh_socket_path,
        ssh_handshake_secret,
        ssh_handshake_skew_secs,
        !client_tls_secret_name.is_empty(),
    );

    container.insert("env".to_string(), serde_json::Value::Array(env));

    // The sandbox process needs SYS_ADMIN (for seccomp filter installation and
    // network namespace creation), NET_ADMIN (for network namespace veth setup),
    // SYS_PTRACE (for the CONNECT proxy to read /proc/<pid>/fd/ of sandbox-user
    // processes to resolve binary identity for network policy enforcement),
    // and SYSLOG (for reading /dev/kmsg to surface bypass detection diagnostics).
    // This mirrors the capabilities used by `mise run sandbox`.
    container.insert(
        "securityContext".to_string(),
        serde_json::json!({
            "capabilities": {
                "add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYSLOG"]
            }
        }),
    );

    // Mount client TLS secret for mTLS to the server.
    if !client_tls_secret_name.is_empty() {
        container.insert(
            "volumeMounts".to_string(),
            serde_json::json!([{
                "name": "openshell-client-tls",
                "mountPath": "/etc/openshell-tls/client",
                "readOnly": true
            }]),
        );
    }

    if let Some(resources) = container_resources(template, gpu) {
        container.insert("resources".to_string(), resources);
    }
    spec.insert(
        "containers".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(container)]),
    );

    // Add TLS secret volume.  Mode 0400 (owner-read) prevents the
    // unprivileged sandbox user from reading the mTLS private key.
    if !client_tls_secret_name.is_empty() {
        spec.insert(
            "volumes".to_string(),
            serde_json::json!([{
                "name": "openshell-client-tls",
                "secret": { "secretName": client_tls_secret_name, "defaultMode": 256 }
            }]),
        );
    }

    // Add hostAliases so sandbox pods can reach the Docker host.
    if !host_gateway_ip.is_empty() {
        spec.insert(
            "hostAliases".to_string(),
            serde_json::json!([{
                "ip": host_gateway_ip,
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

    // Side-load the supervisor binary via an init container that copies it
    // from the supervisor image into a shared emptyDir volume.
    apply_supervisor_sideload(&mut result, supervisor_image, supervisor_image_pull_policy);

    // Inject workspace persistence (init container + PVC volume mount) so
    // that /sandbox data survives pod rescheduling.  Skipped when the user
    // provides custom volumeClaimTemplates to avoid conflicts.
    if inject_workspace {
        apply_workspace_persistence(&mut result, image, image_pull_policy);
    }

    result
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
        apply("requests", "cpu", &req.cpu_request);
        apply("requests", "memory", &req.memory_request);
        apply("limits", "cpu", &req.cpu_limit);
        apply("limits", "memory", &req.memory_limit);
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
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    tls_enabled: bool,
) -> Vec<serde_json::Value> {
    let mut env = existing_env.cloned().unwrap_or_default();
    apply_env_map(&mut env, template_environment);
    apply_env_map(&mut env, spec_environment);
    apply_required_env(
        &mut env,
        sandbox_id,
        sandbox_name,
        grpc_endpoint,
        ssh_socket_path,
        ssh_handshake_secret,
        ssh_handshake_skew_secs,
        tls_enabled,
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
#[allow(clippy::too_many_arguments)]
fn apply_required_env(
    env: &mut Vec<serde_json::Value>,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_socket_path: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    tls_enabled: bool,
) {
    upsert_env(env, "OPENSHELL_SANDBOX_ID", sandbox_id);
    upsert_env(env, "OPENSHELL_SANDBOX", sandbox_name);
    upsert_env(env, "OPENSHELL_ENDPOINT", grpc_endpoint);
    upsert_env(env, "OPENSHELL_SANDBOX_COMMAND", "sleep infinity");
    if !ssh_socket_path.is_empty() {
        upsert_env(env, "OPENSHELL_SSH_SOCKET_PATH", ssh_socket_path);
    }
    upsert_env(env, "OPENSHELL_SSH_HANDSHAKE_SECRET", ssh_handshake_secret);
    upsert_env(
        env,
        "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS",
        &ssh_handshake_skew_secs.to_string(),
    );
    // TLS cert paths for sandbox-to-server mTLS. Only set when TLS is enabled
    // and the client TLS secret is mounted into the sandbox pod.
    if tls_enabled {
        upsert_env(env, "OPENSHELL_TLS_CA", "/etc/openshell-tls/client/ca.crt");
        upsert_env(
            env,
            "OPENSHELL_TLS_CERT",
            "/etc/openshell-tls/client/tls.crt",
        );
        upsert_env(
            env,
            "OPENSHELL_TLS_KEY",
            "/etc/openshell-tls/client/tls.key",
        );
    }
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

/// Extract a nested Struct value from the template's `platform_config`,
/// converting it to `serde_json::Value`.
fn platform_config_struct(template: &SandboxTemplate, key: &str) -> Option<serde_json::Value> {
    let config = template.platform_config.as_ref()?;
    let value = config.fields.get(key)?;
    let json = proto_value_to_json(value);
    // Return None for null/empty objects so callers can distinguish
    // "field absent" from "field present but empty".
    match &json {
        serde_json::Value::Null => None,
        serde_json::Value::Object(m) if m.is_empty() => None,
        _ => Some(json),
    }
}

fn proto_value_to_json(value: &prost_types::Value) -> serde_json::Value {
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NumberValue(num)) => serde_json::Number::from_f64(*num)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Some(prost_types::value::Kind::StringValue(val)) => serde_json::Value::String(val.clone()),
        Some(prost_types::value::Kind::BoolValue(val)) => serde_json::Value::Bool(*val),
        Some(prost_types::value::Kind::StructValue(val)) => {
            let mut map = serde_json::Map::new();
            for (key, value) in &val.fields {
                map.insert(key.clone(), proto_value_to_json(value));
            }
            serde_json::Value::Object(map)
        }
        Some(prost_types::value::Kind::ListValue(list)) => {
            let values = list.values.iter().map(proto_value_to_json).collect();
            serde_json::Value::Array(values)
        }
        Some(prost_types::value::Kind::NullValue(_)) | None => serde_json::Value::Null,
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
    use prost_types::{Struct, Value, value::Kind};

    #[test]
    fn apply_required_env_always_injects_ssh_handshake_secret() {
        let mut env = Vec::new();
        apply_required_env(
            &mut env,
            "sandbox-1",
            "my-sandbox",
            "https://endpoint:8080",
            "0.0.0.0:2222",
            "my-secret-value",
            300,
            true,
        );

        let secret_entry = env
            .iter()
            .find(|e| {
                e.get("name").and_then(|v| v.as_str()) == Some("OPENSHELL_SSH_HANDSHAKE_SECRET")
            })
            .expect("OPENSHELL_SSH_HANDSHAKE_SECRET must be present in env");
        assert_eq!(
            secret_entry.get("value").and_then(|v| v.as_str()),
            Some("my-secret-value")
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

        apply_supervisor_sideload(&mut pod_template, "custom-image:latest", "IfNotPresent");

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

        apply_supervisor_sideload(&mut pod_template, "supervisor-image:latest", "IfNotPresent");

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

        apply_supervisor_sideload(&mut pod_template, "supervisor-image:latest", "IfNotPresent");

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

        // The supervisor image ships only the binary (no shell). The init
        // container must invoke the binary directly with `copy-self <DEST>`.
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
            "init container must not depend on a shell (supervisor image ships only the binary)"
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
            "secret",
            300,
            true, // tls_enabled
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
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            true,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
            true,
        );

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

        let pod_template = sandbox_template_to_k8s(
            &template,
            true,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
            true,
        );

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

        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
            true,
        );

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
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

        let pod_template = sandbox_template_to_k8s(
            &template,
            true,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
            true,
        );

        let limits = &pod_template["spec"]["containers"][0]["resources"]["limits"];
        assert_eq!(limits["cpu"], serde_json::json!("2"));
        assert_eq!(
            limits[GPU_RESOURCE_NAME],
            serde_json::json!(GPU_RESOURCE_QUANTITY)
        );
    }

    #[test]
    fn host_aliases_injected_when_gateway_ip_set() {
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "172.17.0.1",
            true,
        );

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
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
            true,
        );

        assert!(
            pod_template["spec"]["hostAliases"].is_null(),
            "hostAliases should not be present when host_gateway_ip is empty"
        );
    }

    #[test]
    fn tls_secret_volume_uses_restrictive_default_mode() {
        let template = SandboxTemplate::default();
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "my-tls-secret",
            "",
            true,
        );

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
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            "openshell/sandbox:latest",
            "",
            "openshell/supervisor:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
            false, // user provided custom VCTs
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
}
