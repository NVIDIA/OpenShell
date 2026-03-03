// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes sandbox integration.

use crate::persistence::{ObjectId, ObjectName, ObjectType, Store};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ApiResource, DeleteParams, PostParams};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use navigator_core::proto::{
    Sandbox, SandboxCondition, SandboxPhase, SandboxSpec, SandboxStatus, SandboxTemplate,
};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_VERSION: &str = "v1alpha1";
pub const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_ID_LABEL: &str = "navigator.ai/sandbox-id";
const SANDBOX_MANAGED_LABEL: &str = "navigator.ai/managed-by";
const SANDBOX_MANAGED_VALUE: &str = "navigator";

#[derive(Clone)]
pub struct SandboxClient {
    client: Client,
    namespace: String,
    default_image: String,
    grpc_endpoint: String,
    ssh_listen_addr: String,
    ssh_handshake_secret: String,
    ssh_handshake_skew_secs: u64,
    /// When non-empty, sandbox pods get this K8s secret mounted for mTLS to the server.
    client_tls_secret_name: String,
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
        grpc_endpoint: String,
        ssh_listen_addr: String,
        ssh_handshake_secret: String,
        ssh_handshake_skew_secs: u64,
        client_tls_secret_name: String,
    ) -> Result<Self, KubeError> {
        let client = Client::try_default().await?;
        Ok(Self {
            client,
            namespace,
            default_image,
            grpc_endpoint,
            ssh_listen_addr,
            ssh_handshake_secret,
            ssh_handshake_skew_secs,
            client_tls_secret_name,
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
            &sandbox.id,
            &self.grpc_endpoint,
            self.ssh_listen_addr(),
            self.ssh_handshake_secret(),
            self.ssh_handshake_skew_secs(),
            &self.client_tls_secret_name,
        );
        let api = self.api();

        match api.create(&PostParams::default(), &obj).await {
            Ok(result) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "Sandbox created in Kubernetes successfully"
                );
                Ok(result)
            }
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    error = %err,
                    "Failed to create sandbox in Kubernetes"
                );
                Err(err)
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
        match api.delete(name, &DeleteParams::default()).await {
            Ok(_response) => {
                info!(sandbox_name = %name, "Sandbox deleted from Kubernetes");
                Ok(true)
            }
            Err(KubeError::Api(err)) if err.code == 404 => {
                debug!(sandbox_name = %name, "Sandbox not found in Kubernetes (already deleted)");
                Ok(false)
            }
            Err(err) => {
                warn!(
                    sandbox_name = %name,
                    error = %err,
                    "Failed to delete sandbox from Kubernetes"
                );
                Err(err)
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
                        if let Err(err) = handle_deleted(&store, &index, &watch_bus, obj).await {
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

    let status = status_from_object(&obj);
    let phase = derive_phase(&status, deletion_timestamp);

    let mut sandbox = store
        .get_message::<Sandbox>(&id)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| Sandbox {
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

/// Path where the supervisor binary is mounted inside the agent container
/// when using supervisor bootstrap mode (custom workload image).
const SUPERVISOR_MOUNT_PATH: &str = "/opt/navigator/bin";

/// Name of the shared volume used to side-load the supervisor binary.
const SUPERVISOR_VOLUME_NAME: &str = "navigator-supervisor-bin";

/// Source path of the supervisor binary inside the default sandbox image.
const SUPERVISOR_SRC_PATH: &str = "/usr/local/bin/navigator-sandbox";

/// Returns `true` when supervisor bootstrap mode is needed: the template
/// specifies a custom workload image that differs from the server's default
/// sandbox image.
fn needs_supervisor_bootstrap(template: &SandboxTemplate, default_image: &str) -> bool {
    !template.image.is_empty() && template.image != default_image
}

/// Build the init container JSON that copies the supervisor binary from the
/// default sandbox image into the shared volume.
fn supervisor_init_container(default_image: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "copy-supervisor",
        "image": default_image,
        "command": ["sh", "-c", format!(
            "cp {src} {dst}/navigator-sandbox && chmod 755 {dst}/navigator-sandbox",
            src = SUPERVISOR_SRC_PATH,
            dst = SUPERVISOR_MOUNT_PATH,
        )],
        "volumeMounts": [{
            "name": SUPERVISOR_VOLUME_NAME,
            "mountPath": SUPERVISOR_MOUNT_PATH
        }]
    })
}

/// Build the emptyDir volume definition for the supervisor binary.
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

/// Apply supervisor bootstrap transforms to an already-built pod template JSON.
///
/// This injects the init container, shared volume, volume mount, and command
/// override into the pod template, targeting the `agent` container (or the
/// first container if no `agent` is found).
fn apply_supervisor_bootstrap(pod_template: &mut serde_json::Value, default_image: &str) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // 1. Add the shared volume to spec.volumes
    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        volumes.push(supervisor_volume());
    }

    // 2. Add the init container to spec.initContainers
    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(init_containers) = init_containers {
        init_containers.push(supervisor_init_container(default_image));
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
            serde_json::json!([format!("{}/navigator-sandbox", SUPERVISOR_MOUNT_PATH)]),
        );

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
    sandbox_id: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    client_tls_secret_name: &str,
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
                    default_image,
                    sandbox_id,
                    grpc_endpoint,
                    ssh_listen_addr,
                    ssh_handshake_secret,
                    ssh_handshake_skew_secs,
                    &spec.environment,
                    client_tls_secret_name,
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
                default_image,
                sandbox_id,
                grpc_endpoint,
                ssh_listen_addr,
                ssh_handshake_secret,
                ssh_handshake_skew_secs,
                spec_env,
                client_tls_secret_name,
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
    default_image: &str,
    sandbox_id: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
    client_tls_secret_name: &str,
) -> serde_json::Value {
    if let Some(pod_template) = struct_to_json(&template.pod_template) {
        return inject_pod_template(
            pod_template,
            template,
            default_image,
            sandbox_id,
            grpc_endpoint,
            ssh_listen_addr,
            ssh_handshake_secret,
            ssh_handshake_skew_secs,
            spec_environment,
            client_tls_secret_name,
        );
    }

    let bootstrap = needs_supervisor_bootstrap(template, default_image);
    if bootstrap {
        info!(
            workload_image = %template.image,
            supervisor_image = %default_image,
            "Supervisor bootstrap mode active: side-loading supervisor from default image"
        );
    }

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
    if !template.runtime_class_name.is_empty() {
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
    }

    // Build environment variables - start with Navigator-required vars
    let env = build_env_list(
        None,
        &template.environment,
        spec_environment,
        sandbox_id,
        grpc_endpoint,
        ssh_listen_addr,
        ssh_handshake_secret,
        ssh_handshake_skew_secs,
    );

    container.insert("env".to_string(), serde_json::Value::Array(env));

    // The sandbox process needs SYS_ADMIN (for seccomp filter installation and
    // network namespace creation), NET_ADMIN (for network namespace veth setup),
    // and SYS_PTRACE (for the CONNECT proxy to read /proc/<pid>/fd/ of sandbox-user
    // processes to resolve binary identity for network policy enforcement).
    // This mirrors the capabilities used by `mise run sandbox`.
    container.insert(
        "securityContext".to_string(),
        serde_json::json!({
            "capabilities": {
                "add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
            }
        }),
    );

    // Mount client TLS secret for mTLS to the server.
    if !client_tls_secret_name.is_empty() {
        container.insert(
            "volumeMounts".to_string(),
            serde_json::json!([{
                "name": "navigator-client-tls",
                "mountPath": "/etc/navigator-tls/client",
                "readOnly": true
            }]),
        );
    }

    if let Some(resources) = struct_to_json(&template.resources) {
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
                "name": "navigator-client-tls",
                "secret": { "secretName": client_tls_secret_name }
            }]),
        );
    }

    let mut template_value = serde_json::Map::new();
    if !metadata.is_empty() {
        template_value.insert("metadata".to_string(), serde_json::Value::Object(metadata));
    }
    template_value.insert("spec".to_string(), serde_json::Value::Object(spec));

    let mut result = serde_json::Value::Object(template_value);

    // Apply supervisor bootstrap transforms when using a custom workload image
    if bootstrap {
        apply_supervisor_bootstrap(&mut result, default_image);
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn inject_pod_template(
    mut pod_template: serde_json::Value,
    template: &SandboxTemplate,
    default_image: &str,
    sandbox_id: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
    client_tls_secret_name: &str,
) -> serde_json::Value {
    let Some(spec) = pod_template
        .get_mut("spec")
        .and_then(|value| value.as_object_mut())
    else {
        return pod_template;
    };

    // Inject TLS volume at the pod spec level.
    if !client_tls_secret_name.is_empty() {
        let volumes = spec
            .entry("volumes")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(volumes_arr) = volumes.as_array_mut() {
            volumes_arr.push(serde_json::json!({
                "name": "navigator-client-tls",
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
            grpc_endpoint,
            ssh_listen_addr,
            ssh_handshake_secret,
            ssh_handshake_skew_secs,
            spec_environment,
        );

        // Inject TLS volumeMount on the agent container.
        if !client_tls_secret_name.is_empty()
            && let Some(container_obj) = container.as_object_mut()
        {
            let mounts = container_obj
                .entry("volumeMounts")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(mounts_arr) = mounts.as_array_mut() {
                mounts_arr.push(serde_json::json!({
                    "name": "navigator-client-tls",
                    "mountPath": "/etc/navigator-tls/client",
                    "readOnly": true
                }));
            }
        }
    }

    // Apply supervisor bootstrap transforms for custom workload images
    if needs_supervisor_bootstrap(template, default_image) {
        info!(
            workload_image = %template.image,
            supervisor_image = %default_image,
            "Supervisor bootstrap mode active for custom pod template"
        );
        apply_supervisor_bootstrap(&mut pod_template, default_image);
    }

    pod_template
}

#[allow(clippy::too_many_arguments)]
fn update_container_env(
    container: &mut serde_json::Value,
    template: &SandboxTemplate,
    sandbox_id: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
    spec_environment: &std::collections::HashMap<String, String>,
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
        grpc_endpoint,
        ssh_listen_addr,
        ssh_handshake_secret,
        ssh_handshake_skew_secs,
    );
    container_obj.insert("env".to_string(), serde_json::Value::Array(env));
}

#[allow(clippy::too_many_arguments)]
fn build_env_list(
    existing_env: Option<&Vec<serde_json::Value>>,
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
    sandbox_id: &str,
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
) -> Vec<serde_json::Value> {
    let mut env = existing_env.cloned().unwrap_or_default();
    apply_env_map(&mut env, template_environment);
    apply_env_map(&mut env, spec_environment);
    apply_required_env(
        &mut env,
        sandbox_id,
        grpc_endpoint,
        ssh_listen_addr,
        ssh_handshake_secret,
        ssh_handshake_skew_secs,
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
    grpc_endpoint: &str,
    ssh_listen_addr: &str,
    ssh_handshake_secret: &str,
    ssh_handshake_skew_secs: u64,
) {
    upsert_env(env, "NAVIGATOR_SANDBOX_ID", sandbox_id);
    upsert_env(env, "NAVIGATOR_ENDPOINT", grpc_endpoint);
    upsert_env(env, "NAVIGATOR_SANDBOX_COMMAND", "sleep infinity");
    if !ssh_listen_addr.is_empty() {
        upsert_env(env, "NAVIGATOR_SSH_LISTEN_ADDR", ssh_listen_addr);
    }
    if !ssh_handshake_secret.is_empty() {
        upsert_env(env, "NAVIGATOR_SSH_HANDSHAKE_SECRET", ssh_handshake_secret);
    }
    upsert_env(
        env,
        "NAVIGATOR_SSH_HANDSHAKE_SKEW_SECS",
        &ssh_handshake_skew_secs.to_string(),
    );
    // TLS cert paths for sandbox-to-server mTLS. The actual secret is mounted
    // as a volume; these env vars tell the sandbox gRPC client where to find
    // the certs.
    upsert_env(env, "NAVIGATOR_TLS_CA", "/etc/navigator-tls/client/ca.crt");
    upsert_env(
        env,
        "NAVIGATOR_TLS_CERT",
        "/etc/navigator-tls/client/tls.crt",
    );
    upsert_env(
        env,
        "NAVIGATOR_TLS_KEY",
        "/etc/navigator-tls/client/tls.key",
    );
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
}
