// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes sandbox integration.

use crate::persistence::{ObjectId, ObjectName, ObjectType, Store};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::{Api, ApiResource, DeleteParams, ListParams, PostParams};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::proto::{
    Sandbox, SandboxCondition, SandboxPhase, SandboxSpec, SandboxStatus, SandboxTemplate,
};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

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
const GPU_RUNTIME_CLASS_NAME: &str = "nvidia";
const GPU_RESOURCE_NAME: &str = "nvidia.com/gpu";
const GPU_RESOURCE_QUANTITY: &str = "1";

#[derive(Clone)]
pub struct SandboxClient {
    client: Client,
    namespace: String,
    default_image: String,
    /// Kubernetes `imagePullPolicy` for sandbox containers.  When empty the
    /// field is omitted from the pod spec and Kubernetes applies its default.
    image_pull_policy: String,
    grpc_endpoint: String,
    ssh_listen_addr: String,
    ssh_handshake_secret: String,
    ssh_handshake_skew_secs: u64,
    /// When non-empty, sandbox pods get this K8s secret mounted for mTLS to the server.
    client_tls_secret_name: String,
    /// When non-empty, sandbox pods get `hostAliases` entries mapping
    /// `host.docker.internal` and `host.openshell.internal` to this IP.
    host_gateway_ip: String,
}

impl std::fmt::Debug for SandboxClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxClient")
            .field("namespace", &self.namespace)
            .field("default_image", &self.default_image)
            .field("grpc_endpoint", &self.grpc_endpoint)
            .finish()
    }
}

impl SandboxClient {
    pub async fn new(
        namespace: String,
        default_image: String,
        image_pull_policy: String,
        grpc_endpoint: String,
        ssh_listen_addr: String,
        ssh_handshake_secret: String,
        ssh_handshake_skew_secs: u64,
        client_tls_secret_name: String,
        host_gateway_ip: String,
    ) -> Result<Self, KubeError> {
        let mut config = match kube::Config::incluster() {
            Ok(c) => c,
            Err(_) => kube::Config::infer()
                .await
                .map_err(kube::Error::InferConfig)?,
        };
        config.connect_timeout = Some(Duration::from_secs(10));
        config.read_timeout = Some(Duration::from_secs(30));
        config.write_timeout = Some(Duration::from_secs(30));
        let client = Client::try_from(config)?;
        Ok(Self {
            client,
            namespace,
            default_image,
            image_pull_policy,
            grpc_endpoint,
            ssh_listen_addr,
            ssh_handshake_secret,
            ssh_handshake_skew_secs,
            client_tls_secret_name,
            host_gateway_ip,
        })
    }

    pub fn default_image(&self) -> &str {
        &self.default_image
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn ssh_listen_addr(&self) -> &str {
        &self.ssh_listen_addr
    }

    pub fn ssh_handshake_secret(&self) -> &str {
        &self.ssh_handshake_secret
    }

    pub const fn ssh_handshake_skew_secs(&self) -> u64 {
        self.ssh_handshake_skew_secs
    }

    pub fn api(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, SANDBOX_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    pub async fn validate_gpu_support(&self) -> Result<(), tonic::Status> {
        let runtime_classes: Api<DynamicObject> = Api::all_with(
            self.client.clone(),
            &ApiResource::from_gvk(&GroupVersionKind::gvk("node.k8s.io", "v1", "RuntimeClass")),
        );

        let runtime_class_exists = runtime_classes
            .get_opt(GPU_RUNTIME_CLASS_NAME)
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("check GPU runtime class failed: {err}"))
            })?
            .is_some();

        if !runtime_class_exists {
            return Err(tonic::Status::failed_precondition(
                "GPU sandbox requested, but the active gateway is not GPU-enabled. To start a gateway with GPU support run: `openshell gateway start --gpu`",
            ));
        }

        let nodes: Api<Node> = Api::all(self.client.clone());
        let node_list = nodes.list(&ListParams::default()).await.map_err(|err| {
            tonic::Status::internal(format!("check GPU node capacity failed: {err}"))
        })?;

        let has_gpu_capacity = node_list.items.into_iter().any(|node| {
            node.status
                .and_then(|status| status.allocatable)
                .and_then(|allocatable| allocatable.get(GPU_RESOURCE_NAME).cloned())
                .is_some_and(|quantity| quantity.0 != "0")
        });

        if !has_gpu_capacity {
            return Err(tonic::Status::failed_precondition(
                "GPU sandbox requested, but the active gateway has no allocatable GPUs. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration.",
            ));
        }

        Ok(())
    }

    pub async fn agent_pod_ip(&self, pod_name: &str) -> Result<Option<IpAddr>, KubeError> {
        let api: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        match api.get(pod_name).await {
            Ok(pod) => {
                let ip = pod
                    .status
                    .and_then(|status| status.pod_ip)
                    .and_then(|ip| ip.parse().ok());
                Ok(ip)
            }
            Err(KubeError::Api(err)) if err.code == 404 => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn create(&self, sandbox: &Sandbox) -> Result<DynamicObject, KubeError> {
        let name = sandbox.name.as_str();
        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %name,
            namespace = %self.namespace,
            "Creating sandbox in Kubernetes"
        );

        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, SANDBOX_VERSION, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let mut obj = DynamicObject::new(name, &resource);
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(self.namespace.clone()),
            labels: Some(sandbox_labels(sandbox)),
            ..Default::default()
        };
        obj.data = sandbox_to_k8s_spec(
            sandbox.spec.as_ref(),
            &self.default_image,
            &self.image_pull_policy,
            &sandbox.id,
            &sandbox.name,
            &self.grpc_endpoint,
            self.ssh_listen_addr(),
            self.ssh_handshake_secret(),
            self.ssh_handshake_skew_secs(),
            &self.client_tls_secret_name,
            &self.host_gateway_ip,
        );
        let api = self.api();

        match tokio::time::timeout(KUBE_API_TIMEOUT, api.create(&PostParams::default(), &obj)).await
        {
            Ok(Ok(result)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "Sandbox created in Kubernetes successfully"
                );
                Ok(result)
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    error = %err,
                    "Failed to create sandbox in Kubernetes"
                );
                Err(err)
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out creating sandbox in Kubernetes"
                );
                Err(KubeError::Api(kube::core::ErrorResponse {
                    status: "Failure".to_string(),
                    message: format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ),
                    reason: "Timeout".to_string(),
                    code: 504,
                }))
            }
        }
    }

    pub async fn delete(&self, name: &str) -> Result<bool, KubeError> {
        info!(
            sandbox_name = %name,
            namespace = %self.namespace,
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
                Err(err)
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out deleting sandbox from Kubernetes"
                );
                Err(KubeError::Api(kube::core::ErrorResponse {
                    status: "Failure".to_string(),
                    message: format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ),
                    reason: "Timeout".to_string(),
                    code: 504,
                }))
            }
        }
    }
}

impl ObjectType for Sandbox {
    fn object_type() -> &'static str {
        "sandbox"
    }
}

impl ObjectId for Sandbox {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for Sandbox {
    fn object_name(&self) -> &str {
        &self.name
    }
}

pub fn spawn_sandbox_watcher(
    store: Arc<Store>,
    client: SandboxClient,
    index: crate::sandbox_index::SandboxIndex,
    watch_bus: crate::sandbox_watch::SandboxWatchBus,
    tracing_log_bus: crate::tracing_bus::TracingLogBus,
) {
    let namespace = client.namespace().to_string();
    info!(namespace = %namespace, "Starting sandbox watcher");

    tokio::spawn(async move {
        let api = client.api();
        let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();

        loop {
            match stream.try_next().await {
                Ok(Some(event)) => match event {
                    Event::Applied(obj) => {
                        let obj_name = obj.metadata.name.clone().unwrap_or_default();
                        debug!(sandbox_name = %obj_name, "Received Applied event from Kubernetes");
                        if let Err(err) =
                            handle_applied(&store, &client, &index, &watch_bus, obj).await
                        {
                            warn!(sandbox_name = %obj_name, error = %err, "Failed to apply sandbox update");
                        }
                    }
                    Event::Deleted(obj) => {
                        let obj_name = obj.metadata.name.clone().unwrap_or_default();
                        debug!(sandbox_name = %obj_name, "Received Deleted event from Kubernetes");
                        if let Err(err) =
                            handle_deleted(&store, &index, &watch_bus, &tracing_log_bus, obj).await
                        {
                            warn!(sandbox_name = %obj_name, error = %err, "Failed to delete sandbox record");
                        }
                    }
                    Event::Restarted(objs) => {
                        info!(
                            count = objs.len(),
                            "Sandbox watcher restarted, re-syncing sandboxes"
                        );
                        for obj in objs {
                            let obj_name = obj.metadata.name.clone().unwrap_or_default();
                            if let Err(err) =
                                handle_applied(&store, &client, &index, &watch_bus, obj).await
                            {
                                warn!(sandbox_name = %obj_name, error = %err, "Failed to apply sandbox update during resync");
                            }
                        }
                    }
                },
                Ok(None) => {
                    warn!("Sandbox watcher stream ended unexpectedly");
                    break;
                }
                Err(err) => {
                    warn!(error = %err, "Sandbox watcher error");
                }
            }
        }
    });
}

/// Interval between store-vs-k8s reconciliation sweeps.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How long a sandbox can stay in `Provisioning` in the store without a
/// corresponding Kubernetes resource before it is considered orphaned and
/// removed.
const ORPHAN_GRACE_PERIOD: Duration = Duration::from_secs(300);

/// Periodically reconcile the store against Kubernetes to clean up orphaned
/// sandbox records.  A record is orphaned when it exists in the store but
/// has no corresponding Kubernetes `Sandbox` CR — typically because the
/// k8s create timed out or the gRPC handler was cancelled.
pub fn spawn_store_reconciler(
    store: Arc<Store>,
    client: SandboxClient,
    index: crate::sandbox_index::SandboxIndex,
    watch_bus: crate::sandbox_watch::SandboxWatchBus,
    tracing_log_bus: crate::tracing_bus::TracingLogBus,
) {
    tokio::spawn(async move {
        // Wait for initial startup to settle before running the first sweep.
        tokio::time::sleep(RECONCILE_INTERVAL).await;

        loop {
            if let Err(e) =
                reconcile_orphaned_sandboxes(&store, &client, &index, &watch_bus, &tracing_log_bus)
                    .await
            {
                warn!(error = %e, "Store reconciliation sweep failed");
            }
            tokio::time::sleep(RECONCILE_INTERVAL).await;
        }
    });
}

/// Single reconciliation sweep: list all sandboxes in the store that are
/// still `Provisioning`, check if they have a corresponding k8s resource,
/// and remove any that have been orphaned beyond the grace period.
async fn reconcile_orphaned_sandboxes(
    store: &Store,
    client: &SandboxClient,
    index: &crate::sandbox_index::SandboxIndex,
    watch_bus: &crate::sandbox_watch::SandboxWatchBus,
    tracing_log_bus: &crate::tracing_bus::TracingLogBus,
) -> Result<(), String> {
    let records = store
        .list(Sandbox::object_type(), 500, 0)
        .await
        .map_err(|e| e.to_string())?;

    let api = client.api();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    for record in records {
        let sandbox: Sandbox = match prost::Message::decode(record.payload.as_slice()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to decode sandbox record during reconciliation");
                continue;
            }
        };

        // Only check sandboxes that are still provisioning — these are the
        // ones at risk of being orphaned.
        if sandbox.phase != SandboxPhase::Provisioning as i32 {
            continue;
        }

        // Check how old this record is using the store's created_at_ms.
        let age_ms = now_ms.saturating_sub(record.created_at_ms);
        if age_ms < ORPHAN_GRACE_PERIOD.as_millis() as i64 {
            continue;
        }

        // Check if a corresponding k8s resource exists.
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(&sandbox.name)).await {
            Ok(Ok(_)) => {
                // k8s resource exists — not orphaned.
                continue;
            }
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                // k8s resource does not exist — orphaned store entry.
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    age_secs = age_ms / 1000,
                    "Removing orphaned sandbox from store (no corresponding k8s resource)"
                );
                if let Err(e) = store.delete(Sandbox::object_type(), &sandbox.id).await {
                    warn!(sandbox_id = %sandbox.id, error = %e, "Failed to remove orphaned sandbox");
                }
                index.remove_sandbox(&sandbox.id);
                watch_bus.notify(&sandbox.id);
                tracing_log_bus.remove(&sandbox.id);
                tracing_log_bus.platform_event_bus.remove(&sandbox.id);
                watch_bus.remove(&sandbox.id);
            }
            Ok(Err(err)) => {
                // k8s API error — skip this record and try again next cycle.
                debug!(
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "Skipping orphan check due to k8s API error"
                );
            }
            Err(_elapsed) => {
                debug!(
                    sandbox_id = %sandbox.id,
                    "Skipping orphan check due to k8s API timeout"
                );
            }
        }
    }

    Ok(())
}

async fn handle_applied(
    store: &Store,
    client: &SandboxClient,
    index: &crate::sandbox_index::SandboxIndex,
    watch_bus: &crate::sandbox_watch::SandboxWatchBus,
    obj: DynamicObject,
) -> Result<(), String> {
    let id = sandbox_id_from_object(&obj)?;
    let name = obj.metadata.name.clone().unwrap_or_default();
    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| client.namespace().to_string());
    let deletion_timestamp = obj.metadata.deletion_timestamp.is_some();

    let existing = store
        .get_message::<Sandbox>(&id)
        .await
        .map_err(|e| e.to_string())?;

    let mut status = status_from_object(&obj);
    rewrite_user_facing_conditions(
        &mut status,
        existing.as_ref().and_then(|sandbox| sandbox.spec.as_ref()),
    );
    let phase = derive_phase(&status, deletion_timestamp);

    // If the record doesn't exist yet, the `create_sandbox` handler may
    // still be in-flight (it creates the k8s resource first, then writes
    // to the store).  Build a minimal placeholder but never overwrite an
    // existing record's `spec` — only the `create_sandbox` handler sets it.
    let mut sandbox = existing.unwrap_or_else(|| Sandbox {
        id: id.clone(),
        name: name.clone(),
        namespace,
        spec: None,
        status: None,
        phase: SandboxPhase::Unknown as i32,
        ..Default::default()
    });

    // Log phase transitions
    let old_phase = SandboxPhase::try_from(sandbox.phase).unwrap_or(SandboxPhase::Unknown);
    if old_phase != phase {
        info!(
            sandbox_id = %id,
            sandbox_name = %name,
            old_phase = ?old_phase,
            new_phase = ?phase,
            "Sandbox phase changed"
        );
    }

    // Log error conditions with details
    if phase == SandboxPhase::Error
        && let Some(ref status) = status
    {
        for condition in &status.conditions {
            if condition.r#type == "Ready"
                && condition.status.eq_ignore_ascii_case("false")
                && is_terminal_failure_condition(condition)
            {
                warn!(
                    sandbox_id = %id,
                    sandbox_name = %name,
                    reason = %condition.reason,
                    message = %condition.message,
                    "Sandbox failed to become ready"
                );
            }
        }
    }

    // Log when sandbox becomes ready
    if phase == SandboxPhase::Ready && old_phase != SandboxPhase::Ready {
        info!(
            sandbox_id = %id,
            sandbox_name = %name,
            "Sandbox is now ready"
        );
    }

    sandbox.status = status;
    sandbox.phase = phase as i32;

    index.update_from_sandbox(&sandbox);

    store
        .put_message(&sandbox)
        .await
        .map_err(|e| e.to_string())?;

    watch_bus.notify(&id);
    Ok(())
}

async fn handle_deleted(
    store: &Store,
    index: &crate::sandbox_index::SandboxIndex,
    watch_bus: &crate::sandbox_watch::SandboxWatchBus,
    tracing_log_bus: &crate::tracing_bus::TracingLogBus,
    obj: DynamicObject,
) -> Result<(), String> {
    let id = sandbox_id_from_object(&obj)?;
    let deleted = store
        .delete(Sandbox::object_type(), &id)
        .await
        .map_err(|e| e.to_string())?;
    debug!(sandbox_id = %id, deleted, "Deleted sandbox record");
    index.remove_sandbox(&id);
    watch_bus.notify(&id);

    // Clean up bus entries to prevent unbounded memory growth.
    tracing_log_bus.remove(&id);
    tracing_log_bus.platform_event_bus.remove(&id);
    watch_bus.remove(&id);

    Ok(())
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

/// Path where the supervisor binary is mounted inside the agent container.
/// The supervisor is always side-loaded from the k3s node filesystem via a
/// read-only hostPath volume — it is never baked into sandbox images.
const SUPERVISOR_MOUNT_PATH: &str = "/opt/openshell/bin";

/// Name of the volume used to side-load the supervisor binary.
const SUPERVISOR_VOLUME_NAME: &str = "openshell-supervisor-bin";

/// Path on the k3s node filesystem where the supervisor binary lives.
/// This is baked into the cluster image at build time and can be updated
/// via `docker cp` during local development.
const SUPERVISOR_HOST_PATH: &str = "/opt/openshell/bin";

/// Build the hostPath volume definition that exposes the supervisor binary
/// from the k3s node filesystem.
fn supervisor_volume() -> serde_json::Value {
    serde_json::json!({
        "name": SUPERVISOR_VOLUME_NAME,
        "hostPath": {
            "path": SUPERVISOR_HOST_PATH,
            "type": "DirectoryOrCreate"
        }
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

/// Apply supervisor side-load transforms to an already-built pod template JSON.
///
/// This injects the hostPath volume, volume mount, command override, and
/// `runAsUser: 0` into the pod template, targeting the `agent` container
/// (or the first container if no `agent` is found).
///
/// The supervisor binary is always side-loaded from the k3s node filesystem
/// via a read-only hostPath volume. No init container is needed.
///
/// The `runAsUser: 0` override ensures the supervisor binary runs as root
/// regardless of the image's `USER` directive. The supervisor needs root for
/// network namespace creation, proxy setup, and Landlock/seccomp configuration.
/// It drops to the appropriate non-root user for child processes via the
/// policy's `run_as_user`/`run_as_group`.
fn apply_supervisor_sideload(pod_template: &mut serde_json::Value) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // 1. Add the hostPath volume to spec.volumes
    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        volumes.push(supervisor_volume());
    }

    // 2. Find the agent container and add volume mount + command override
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

#[allow(clippy::too_many_arguments)]
fn sandbox_to_k8s_spec(
    spec: Option<&SandboxSpec>,
    default_image: &str,
    image_pull_policy: &str,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    client_tls_secret_name: &str,
    host_gateway_ip: &str,
) -> serde_json::Value {
    let mut root = serde_json::Map::new();
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
                    sandbox_id,
                    sandbox_name,
                    grpc_endpoint,
                    ssh_listen_addr,
                    ssh_handshake_secret,
                    ssh_handshake_skew_secs,
                    &spec.environment,
                    client_tls_secret_name,
                    host_gateway_ip,
                ),
            );
            if !template.agent_socket.is_empty() {
                root.insert(
                    "agentSocket".to_string(),
                    serde_json::json!(template.agent_socket),
                );
            }
            if let Some(volume_templates) = struct_to_json(&template.volume_claim_templates) {
                root.insert("volumeClaimTemplates".to_string(), volume_templates);
            }
        }
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
                sandbox_id,
                sandbox_name,
                grpc_endpoint,
                ssh_listen_addr,
                ssh_handshake_secret,
                ssh_handshake_skew_secs,
                spec_env,
                client_tls_secret_name,
                host_gateway_ip,
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
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
    client_tls_secret_name: &str,
    host_gateway_ip: &str,
) -> serde_json::Value {
    if let Some(pod_template) = struct_to_json(&template.pod_template) {
        return inject_pod_template(
            pod_template,
            template,
            gpu,
            default_image,
            image_pull_policy,
            sandbox_id,
            sandbox_name,
            grpc_endpoint,
            ssh_listen_addr,
            ssh_handshake_secret,
            ssh_handshake_skew_secs,
            spec_environment,
            client_tls_secret_name,
            host_gateway_ip,
        );
    }

    // The supervisor binary is always side-loaded from the node filesystem
    // via a hostPath volume, regardless of which sandbox image is used.

    let mut metadata = serde_json::Map::new();
    if !template.labels.is_empty() {
        metadata.insert("labels".to_string(), serde_json::json!(template.labels));
    }
    if !template.annotations.is_empty() {
        metadata.insert(
            "annotations".to_string(),
            serde_json::json!(template.annotations),
        );
    }

    let mut spec = serde_json::Map::new();
    if gpu {
        spec.insert(
            "runtimeClassName".to_string(),
            serde_json::json!(GPU_RUNTIME_CLASS_NAME),
        );
    } else if !template.runtime_class_name.is_empty() {
        spec.insert(
            "runtimeClassName".to_string(),
            serde_json::json!(template.runtime_class_name),
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
        ssh_listen_addr,
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

    // Add TLS secret volume.
    if !client_tls_secret_name.is_empty() {
        spec.insert(
            "volumes".to_string(),
            serde_json::json!([{
                "name": "openshell-client-tls",
                "secret": { "secretName": client_tls_secret_name }
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

    // Always side-load the supervisor binary from the node filesystem
    apply_supervisor_sideload(&mut result);

    result
}

#[allow(clippy::too_many_arguments)]
fn inject_pod_template(
    mut pod_template: serde_json::Value,
    template: &SandboxTemplate,
    gpu: bool,
    default_image: &str,
    image_pull_policy: &str,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
    client_tls_secret_name: &str,
    host_gateway_ip: &str,
) -> serde_json::Value {
    let Some(spec) = pod_template
        .get_mut("spec")
        .and_then(|value| value.as_object_mut())
    else {
        return pod_template;
    };

    if gpu {
        spec.insert(
            "runtimeClassName".to_string(),
            serde_json::json!(GPU_RUNTIME_CLASS_NAME),
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

    // Inject TLS volume at the pod spec level.
    if !client_tls_secret_name.is_empty() {
        let volumes = spec
            .entry("volumes")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(volumes_arr) = volumes.as_array_mut() {
            volumes_arr.push(serde_json::json!({
                "name": "openshell-client-tls",
                "secret": { "secretName": client_tls_secret_name }
            }));
        }
    }

    let Some(containers) = spec
        .get_mut("containers")
        .and_then(|value| value.as_array_mut())
    else {
        return pod_template;
    };
    if containers.is_empty() {
        return pod_template;
    }

    let mut target_index = None;
    for (index, container) in containers.iter().enumerate() {
        if container.get("name").and_then(|value| value.as_str()) == Some("agent") {
            target_index = Some(index);
            break;
        }
    }
    let index = target_index.unwrap_or(0);
    if let Some(container) = containers.get_mut(index) {
        update_container_env(
            container,
            template,
            sandbox_id,
            sandbox_name,
            grpc_endpoint,
            ssh_listen_addr,
            ssh_handshake_secret,
            ssh_handshake_skew_secs,
            spec_environment,
            !client_tls_secret_name.is_empty(),
        );

        // Inject imagePullPolicy on the agent container.
        if !image_pull_policy.is_empty() {
            if let Some(container_obj) = container.as_object_mut() {
                container_obj.insert(
                    "imagePullPolicy".to_string(),
                    serde_json::json!(image_pull_policy),
                );
            }
        }

        // Inject TLS volumeMount on the agent container.
        if !client_tls_secret_name.is_empty()
            && let Some(container_obj) = container.as_object_mut()
        {
            let mounts = container_obj
                .entry("volumeMounts")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(mounts_arr) = mounts.as_array_mut() {
                mounts_arr.push(serde_json::json!({
                    "name": "openshell-client-tls",
                    "mountPath": "/etc/openshell-tls/client",
                    "readOnly": true
                }));
            }
        }

        if gpu {
            apply_gpu_to_container(container);
        }
    }

    // Always side-load the supervisor binary from the node filesystem
    apply_supervisor_sideload(&mut pod_template);

    pod_template
}

fn container_resources(template: &SandboxTemplate, gpu: bool) -> Option<serde_json::Value> {
    let mut resources =
        struct_to_json(&template.resources).unwrap_or_else(|| serde_json::json!({}));
    if gpu {
        apply_gpu_limit(&mut resources);
    }
    if resources
        .as_object()
        .is_some_and(|object| object.is_empty())
    {
        None
    } else {
        Some(resources)
    }
}

fn apply_gpu_to_container(container: &mut serde_json::Value) {
    if let Some(container_obj) = container.as_object_mut() {
        let resources = container_obj
            .entry("resources")
            .or_insert_with(|| serde_json::json!({}));
        apply_gpu_limit(resources);
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
fn update_container_env(
    container: &mut serde_json::Value,
    template: &SandboxTemplate,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
    tls_enabled: bool,
) {
    let Some(container_obj) = container.as_object_mut() else {
        return;
    };
    let existing_env = container_obj
        .get("env")
        .and_then(|value| value.as_array())
        .cloned();
    let env = build_env_list(
        existing_env.as_ref(),
        &template.environment,
        spec_environment,
        sandbox_id,
        sandbox_name,
        grpc_endpoint,
        ssh_listen_addr,
        ssh_handshake_secret,
        ssh_handshake_skew_secs,
        tls_enabled,
    );
    container_obj.insert("env".to_string(), serde_json::Value::Array(env));
}

#[allow(clippy::too_many_arguments)]
fn build_env_list(
    existing_env: Option<&Vec<serde_json::Value>>,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
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
        ssh_listen_addr,
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

fn apply_required_env(
    env: &mut Vec<serde_json::Value>,
    sandbox_id: &str,
    sandbox_name: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    tls_enabled: bool,
) {
    upsert_env(env, "OPENSHELL_SANDBOX_ID", sandbox_id);
    upsert_env(env, "OPENSHELL_SANDBOX", sandbox_name);
    upsert_env(env, "OPENSHELL_ENDPOINT", grpc_endpoint);
    upsert_env(env, "OPENSHELL_SANDBOX_COMMAND", "sleep infinity");
    if !ssh_listen_addr.is_empty() {
        upsert_env(env, "OPENSHELL_SSH_LISTEN_ADDR", ssh_listen_addr);
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

fn struct_to_json(input: &Option<prost_types::Struct>) -> Option<serde_json::Value> {
    let input = input.as_ref()?;
    let mut map = serde_json::Map::new();
    for (key, value) in &input.fields {
        map.insert(key.clone(), proto_value_to_json(value));
    }
    Some(serde_json::Value::Object(map))
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
        agent_pod: status_obj
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

fn rewrite_user_facing_conditions(status: &mut Option<SandboxStatus>, spec: Option<&SandboxSpec>) {
    let gpu_requested = spec.is_some_and(|sandbox_spec| sandbox_spec.gpu);
    if !gpu_requested {
        return;
    }

    if let Some(status) = status {
        for condition in &mut status.conditions {
            if condition.r#type == "Ready"
                && condition.status.eq_ignore_ascii_case("false")
                && condition.reason.eq_ignore_ascii_case("Unschedulable")
            {
                condition.message = "GPU sandbox could not be scheduled on the active gateway. Another GPU sandbox may already be using the available GPU, or the gateway may not currently be able to satisfy GPU placement. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration.".to_string();
            }
        }
    }
}

fn derive_phase(status: &Option<SandboxStatus>, deleting: bool) -> SandboxPhase {
    if deleting {
        return SandboxPhase::Deleting;
    }

    if let Some(status) = status {
        for condition in &status.conditions {
            if condition.r#type == "Ready" {
                return if condition.status.eq_ignore_ascii_case("true") {
                    SandboxPhase::Ready
                } else if condition.status.eq_ignore_ascii_case("false") {
                    if is_terminal_failure_condition(condition) {
                        SandboxPhase::Error
                    } else {
                        SandboxPhase::Provisioning
                    }
                } else {
                    SandboxPhase::Provisioning
                };
            }
        }
        return SandboxPhase::Provisioning;
    }

    SandboxPhase::Unknown
}

fn is_terminal_failure_condition(condition: &SandboxCondition) -> bool {
    let reason = condition.reason.to_ascii_lowercase();

    // These are transient conditions from the sandbox controller that indicate
    // the sandbox is still being provisioned and may become ready:
    //
    // - ReconcilerError: Controller-level transient error, will be retried
    // - DependenciesNotReady: Pod/Service not ready yet, normal during provisioning
    //
    // Any other Ready=False condition is considered terminal (e.g., the controller
    // determined a permanent failure like ImagePullBackOff, Unschedulable, etc.)
    let transient_reasons = ["reconcilererror", "dependenciesnotready"];

    !transient_reasons.contains(&reason.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::{Struct, Value, value::Kind};

    fn make_condition(reason: &str, message: &str) -> SandboxCondition {
        SandboxCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: String::new(),
        }
    }

    #[test]
    fn terminal_failure_treats_unknown_reasons_as_terminal() {
        // Any Ready=False condition with an unknown reason is terminal.
        // We trust the sandbox controller's assessment.
        let terminal_cases = [
            ("Failed", "Something went wrong"),
            ("CrashLoopBackOff", "Container keeps crashing"),
            ("ImagePullBackOff", "Failed to pull image"),
            ("ErrImagePull", "Error pulling image"),
            ("Unschedulable", "No nodes match"),
            ("SomeOtherReason", "Any other reason is terminal"),
        ];

        for (reason, message) in terminal_cases {
            let condition = make_condition(reason, message);
            assert!(
                is_terminal_failure_condition(&condition),
                "Expected terminal failure for reason={reason}, message={message}"
            );
        }
    }

    #[test]
    fn terminal_failure_ignores_transient_reasons() {
        // These reasons are transient - the sandbox may still become ready:
        // - ReconcilerError: controller will retry
        // - DependenciesNotReady: pod/service still being created
        let transient_cases = [
            (
                "ReconcilerError",
                "Error seen: failed to update pod: Operation cannot be fulfilled",
            ),
            ("reconcilererror", "lowercase also works"),
            ("RECONCILERERROR", "uppercase also works"),
            (
                "DependenciesNotReady",
                "Pod exists with phase: Pending; Service Exists",
            ),
            ("dependenciesnotready", "lowercase also works"),
        ];

        for (reason, message) in transient_cases {
            let condition = make_condition(reason, message);
            assert!(
                !is_terminal_failure_condition(&condition),
                "Expected transient (non-terminal) for reason={reason}, message={message}"
            );
        }
    }

    #[test]
    fn derive_phase_returns_provisioning_for_transient_conditions() {
        // Transient conditions (ReconcilerError, DependenciesNotReady) should
        // result in Provisioning phase, not Error.
        let transient_conditions = [
            ("ReconcilerError", "Error seen: failed to update pod"),
            (
                "DependenciesNotReady",
                "Pod exists with phase: Pending; Service Exists",
            ),
        ];

        for (reason, message) in transient_conditions {
            let status = Some(SandboxStatus {
                sandbox_name: "test".to_string(),
                agent_pod: "test-pod".to_string(),
                agent_fd: String::new(),
                sandbox_fd: String::new(),
                conditions: vec![SandboxCondition {
                    r#type: "Ready".to_string(),
                    status: "False".to_string(),
                    reason: reason.to_string(),
                    message: message.to_string(),
                    last_transition_time: String::new(),
                }],
            });

            assert_eq!(
                derive_phase(&status, false),
                SandboxPhase::Provisioning,
                "Expected Provisioning for transient reason={reason}"
            );
        }
    }

    #[test]
    fn derive_phase_returns_error_for_terminal_ready_false() {
        let status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "ImagePullBackOff".to_string(),
                message: "Failed to pull image".to_string(),
                last_transition_time: String::new(),
            }],
        });

        assert_eq!(derive_phase(&status, false), SandboxPhase::Error);
    }

    #[test]
    fn rewrite_user_facing_conditions_rewrites_gpu_unschedulable_message() {
        let mut status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: "0/1 nodes are available: 1 Insufficient nvidia.com/gpu.".to_string(),
                last_transition_time: String::new(),
            }],
        });

        rewrite_user_facing_conditions(
            &mut status,
            Some(&SandboxSpec {
                gpu: true,
                ..Default::default()
            }),
        );

        let message = &status.unwrap().conditions[0].message;
        assert_eq!(
            message,
            "GPU sandbox could not be scheduled on the active gateway. Another GPU sandbox may already be using the available GPU, or the gateway may not currently be able to satisfy GPU placement. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration."
        );
    }

    #[test]
    fn rewrite_user_facing_conditions_leaves_non_gpu_unschedulable_message_unchanged() {
        let original = "0/1 nodes are available: 1 Insufficient cpu.";
        let mut status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: original.to_string(),
                last_transition_time: String::new(),
            }],
        });

        rewrite_user_facing_conditions(
            &mut status,
            Some(&SandboxSpec {
                gpu: false,
                ..Default::default()
            }),
        );

        assert_eq!(status.unwrap().conditions[0].message, original);
    }

    #[test]
    fn derive_phase_returns_ready_for_ready_true() {
        let status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "DependenciesReady".to_string(),
                message: "Pod is Ready; Service Exists".to_string(),
                last_transition_time: String::new(),
            }],
        });

        assert_eq!(derive_phase(&status, false), SandboxPhase::Ready);
    }

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

        apply_supervisor_sideload(&mut pod_template);

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

        apply_supervisor_sideload(&mut pod_template);

        let sc = &pod_template["spec"]["containers"][0]["securityContext"];
        assert_eq!(
            sc["runAsUser"], 0,
            "runAsUser must be 0 even when no prior securityContext"
        );
    }

    #[test]
    fn supervisor_sideload_injects_hostpath_volume_and_mount() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "custom-image:latest"
                }]
            }
        });

        apply_supervisor_sideload(&mut pod_template);

        // No init containers should be present (hostPath, not emptyDir+init)
        assert!(
            pod_template["spec"]["initContainers"].is_null(),
            "hostPath sideload should not create init containers"
        );

        // Volume should be a hostPath volume
        let volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0]["name"], SUPERVISOR_VOLUME_NAME);
        assert_eq!(volumes[0]["hostPath"]["path"], SUPERVISOR_HOST_PATH);
        assert_eq!(volumes[0]["hostPath"]["type"], "DirectoryOrCreate");

        // Agent container command should be overridden
        let command = pod_template["spec"]["containers"][0]["command"]
            .as_array()
            .expect("command should be set");
        assert_eq!(
            command[0].as_str().unwrap(),
            format!("{}/openshell-sandbox", SUPERVISOR_MOUNT_PATH)
        );

        // Volume mount should be read-only
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

    fn string_value(value: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(value.to_string())),
        }
    }

    #[test]
    fn gpu_sandbox_adds_runtime_class_and_gpu_limit() {
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            true,
            "openshell/sandbox:latest",
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
        );

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!(GPU_RUNTIME_CLASS_NAME)
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"][GPU_RESOURCE_NAME],
            serde_json::json!(GPU_RESOURCE_QUANTITY)
        );
    }

    #[test]
    fn gpu_sandbox_preserves_existing_resource_limits() {
        let template = SandboxTemplate {
            resources: Some(Struct {
                fields: [(
                    "limits".to_string(),
                    Value {
                        kind: Some(Kind::StructValue(Struct {
                            fields: [("cpu".to_string(), string_value("2"))]
                                .into_iter()
                                .collect(),
                        })),
                    },
                )]
                .into_iter()
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = sandbox_template_to_k8s(
            &template,
            true,
            "openshell/sandbox:latest",
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
        );

        let limits = &pod_template["spec"]["containers"][0]["resources"]["limits"];
        assert_eq!(limits["cpu"], serde_json::json!("2"));
        assert_eq!(
            limits[GPU_RESOURCE_NAME],
            serde_json::json!(GPU_RESOURCE_QUANTITY)
        );
    }

    #[test]
    fn gpu_sandbox_updates_custom_pod_template() {
        let template = SandboxTemplate {
            pod_template: Some(Struct {
                fields: [(
                    "spec".to_string(),
                    Value {
                        kind: Some(Kind::StructValue(Struct {
                            fields: [(
                                "containers".to_string(),
                                Value {
                                    kind: Some(Kind::ListValue(prost_types::ListValue {
                                        values: vec![Value {
                                            kind: Some(Kind::StructValue(Struct {
                                                fields: [(
                                                    "name".to_string(),
                                                    string_value("agent"),
                                                )]
                                                .into_iter()
                                                .collect(),
                                            })),
                                        }],
                                    })),
                                },
                            )]
                            .into_iter()
                            .collect(),
                        })),
                    },
                )]
                .into_iter()
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = sandbox_template_to_k8s(
            &template,
            true,
            "openshell/sandbox:latest",
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
        );

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!(GPU_RUNTIME_CLASS_NAME)
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"][GPU_RESOURCE_NAME],
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
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "172.17.0.1",
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
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "",
        );

        assert!(
            pod_template["spec"]["hostAliases"].is_null(),
            "hostAliases should not be present when host_gateway_ip is empty"
        );
    }

    #[test]
    fn host_aliases_injected_in_custom_pod_template() {
        let template = SandboxTemplate {
            pod_template: Some(Struct {
                fields: [(
                    "spec".to_string(),
                    Value {
                        kind: Some(Kind::StructValue(Struct {
                            fields: [(
                                "containers".to_string(),
                                Value {
                                    kind: Some(Kind::ListValue(prost_types::ListValue {
                                        values: vec![Value {
                                            kind: Some(Kind::StructValue(Struct {
                                                fields: [(
                                                    "name".to_string(),
                                                    string_value("agent"),
                                                )]
                                                .into_iter()
                                                .collect(),
                                            })),
                                        }],
                                    })),
                                },
                            )]
                            .into_iter()
                            .collect(),
                        })),
                    },
                )]
                .into_iter()
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            "openshell/sandbox:latest",
            "",
            "sandbox-id",
            "sandbox-name",
            "https://gateway.example.com",
            "0.0.0.0:2222",
            "secret",
            300,
            &std::collections::HashMap::new(),
            "",
            "192.168.65.2",
        );

        let host_aliases = pod_template["spec"]["hostAliases"]
            .as_array()
            .expect("hostAliases should exist in custom pod template");
        assert_eq!(host_aliases[0]["ip"], "192.168.65.2");
    }
}
