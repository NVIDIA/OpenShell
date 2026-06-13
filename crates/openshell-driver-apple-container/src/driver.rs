// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Apple Container compute-driver implementation.

use crate::cli::{
    AppleContainerCli, AppleContainerCliError, AppleContainerListEntry, AppleContainerNetworkEntry,
};
use crate::config::AppleContainerComputeConfig;
use futures::Stream;
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_NAMESPACE, TLS_CA_MOUNT_PATH, TLS_CERT_MOUNT_PATH, TLS_KEY_MOUNT_PATH,
};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverSandbox, DriverSandboxStatus, GetCapabilitiesResponse,
    WatchSandboxesDeletedEvent, WatchSandboxesEvent, WatchSandboxesSandboxEvent,
    watch_sandboxes_event,
};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::warn;

const CONTAINER_PREFIX: &str = "openshell-sandbox-";
const VOLUME_PREFIX: &str = "openshell-sandbox-";
const SUPERVISOR_DIR_MOUNT_PATH: &str = "/opt/openshell/bin";
const AUTH_DIR_MOUNT_PATH: &str = "/etc/openshell/auth";
const TLS_DIR_MOUNT_PATH: &str = "/etc/openshell/tls/client";
const TLS_CA_FILE: &str = "ca.crt";
const TLS_CERT_FILE: &str = "tls.crt";
const TLS_KEY_FILE: &str = "tls.key";
const SANDBOX_TOKEN_FILE: &str = "sandbox.jwt";
const SANDBOX_WORKDIR: &str = "/sandbox";
const SANDBOX_COMMAND: &str = "sleep infinity";
const SUPERVISOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const TRANSIENT_STOPPED_LAUNCH_GRACE_MS: i64 = 30_000;
const WATCH_BUFFER: usize = 64;

#[derive(Debug, Clone)]
struct AppleGuestTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Debug)]
struct AppleSecretStagingDirs {
    auth_mount_dir: Option<PathBuf>,
    tls_mount_dir: Option<PathBuf>,
}

/// Stream type returned by the Apple Container driver watch API.
pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, String>> + Send + 'static>>;

/// Queried by the driver to decide when a running sandbox is usable.
///
/// Apple Container can report that the container process has started before
/// the `OpenShell` supervisor has connected back to the gateway. The compute
/// plane treats the sandbox as Ready only after this signal flips true.
pub trait SupervisorReadiness: Send + Sync + 'static {
    /// Return true once the sandbox supervisor has an active gateway session.
    fn is_supervisor_connected(&self, sandbox_id: &str) -> bool;
}

/// Compute driver that manages sandboxes with Apple's container runtime.
#[derive(Clone)]
pub struct AppleContainerComputeDriver {
    cli: AppleContainerCli,
    config: AppleContainerComputeConfig,
    gateway_bind_addresses: Vec<SocketAddr>,
    supervisor_readiness: Arc<dyn SupervisorReadiness>,
    events: broadcast::Sender<WatchSandboxesEvent>,
}

impl std::fmt::Debug for AppleContainerComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleContainerComputeDriver")
            .field("cli", &self.cli)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AppleContainerComputeDriver {
    /// Create and validate a new Apple Container driver.
    ///
    /// # Errors
    /// Returns an error when the configured `container` CLI is unavailable or
    /// reports an unhealthy Apple Container service.
    pub async fn new(
        config: AppleContainerComputeConfig,
        supervisor_readiness: Arc<dyn SupervisorReadiness>,
    ) -> Result<Self, Status> {
        let _ = apple_guest_tls_paths(&config)?;
        let cli = AppleContainerCli::new(config.container_bin.clone());
        cli.health().await.map_err(status_from_cli)?;
        let gateway_bind_addresses = gateway_bind_addresses_from_networks(&cli, &config).await?;
        Ok(Self {
            cli,
            config,
            gateway_bind_addresses,
            supervisor_readiness,
            events: broadcast::channel(WATCH_BUFFER).0,
        })
    }

    /// Return driver capability metadata.
    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        openshell_core::driver_utils::build_capabilities_response(
            "apple-container",
            openshell_core::VERSION,
            &self.config.default_image,
        )
    }

    /// Return gateway listener addresses required by Apple container VMs.
    #[must_use]
    pub fn gateway_bind_addresses(&self) -> Vec<SocketAddr> {
        self.gateway_bind_addresses.clone()
    }

    /// Validate a sandbox before creation.
    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        if sandbox.name.trim().is_empty() {
            return Err(Status::failed_precondition("sandbox name is required"));
        }
        if sandbox.id.trim().is_empty() {
            return Err(Status::failed_precondition("sandbox id is required"));
        }
        if sandbox.spec.as_ref().is_some_and(|spec| spec.gpu) {
            return Err(Status::failed_precondition(
                "apple-container driver does not support GPU sandboxes",
            ));
        }
        validate_container_name(&container_name_for_sandbox(sandbox))?;
        validate_sandbox_template(sandbox)?;
        if sandbox_image(sandbox, &self.config).trim().is_empty() {
            return Err(Status::failed_precondition(
                "no sandbox image configured: set default_image in [openshell.drivers.apple-container] or provide a template image",
            ));
        }
        Ok(())
    }

    /// Create and start one sandbox.
    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        self.validate_sandbox_create(sandbox)?;
        validate_sandbox_auth(sandbox)?;
        if self
            .find_managed_entry(&sandbox.id, &sandbox.name)
            .await?
            .is_some()
        {
            return Err(Status::already_exists("sandbox already exists"));
        }
        let volume = volume_name(&sandbox.id);
        self.cli
            .create_volume(&volume, &managed_labels(sandbox, &self.config))
            .await
            .map_err(status_from_cli)?;
        let args = match self.create_args(sandbox).await {
            Ok(args) => args,
            Err(err) => {
                self.cleanup_volume_with_warning(&volume, &sandbox.id, "create-args-failed")
                    .await;
                cleanup_secret_staging_dir(&sandbox.id, &self.config);
                return Err(err);
            }
        };
        if let Err(err) = self.cli.run_detached(&args).await {
            self.cleanup_volume_with_warning(&volume, &sandbox.id, "container-run-failed")
                .await;
            cleanup_secret_staging_dir(&sandbox.id, &self.config);
            return Err(status_from_cli(err));
        }
        Ok(())
    }

    /// Stop a sandbox without deleting it.
    pub async fn stop_sandbox(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        require_sandbox_identifier(sandbox_id, sandbox_name)?;
        let entry = self
            .find_managed_entry(sandbox_id, sandbox_name)
            .await?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        self.cli
            .stop(&entry.id, self.config.stop_timeout_secs)
            .await
            .map_err(status_from_cli)
    }

    /// Start a managed sandbox that was stopped while the gateway was down.
    pub async fn resume_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, Status> {
        let Some(entry) = self.find_managed_entry(sandbox_id, sandbox_name).await? else {
            return Ok(false);
        };
        if !apple_container_state_needs_resume(&entry.status.state) {
            return Ok(true);
        }
        match self.cli.start(&entry.id).await {
            Ok(()) => Ok(true),
            Err(err) => {
                let status = status_from_cli(err);
                if status.code() == tonic::Code::NotFound {
                    Ok(false)
                } else {
                    Err(status)
                }
            }
        }
    }

    /// Stop all running OpenShell-managed Apple containers during gateway shutdown.
    pub async fn stop_managed_containers_on_shutdown(&self) -> Result<usize, Status> {
        let targets = self
            .list_entries()
            .await?
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .filter(|entry| apple_container_state_needs_shutdown_stop(&entry.status.state))
            .map(|entry| entry.id)
            .collect::<Vec<_>>();
        let target_count = targets.len();
        let mut stopped = 0usize;
        let mut failures = Vec::new();

        for target in targets {
            match self.cli.stop(&target, self.config.stop_timeout_secs).await {
                Ok(()) => stopped += 1,
                Err(err) => {
                    let status = status_from_cli(err);
                    if status.code() == tonic::Code::NotFound {
                        continue;
                    }
                    warn!(
                        container = %target,
                        error = %status,
                        "Failed to stop Apple sandbox container during shutdown"
                    );
                    failures.push(target);
                }
            }
        }

        if !failures.is_empty() {
            return Err(Status::internal(format!(
                "failed to stop {} of {target_count} Apple sandbox containers during shutdown",
                failures.len()
            )));
        }

        Ok(stopped)
    }

    /// Delete a sandbox and its driver-owned secret staging directory.
    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, Status> {
        require_sandbox_identifier(sandbox_id, sandbox_name)?;
        let Some(entry) = self.find_managed_entry(sandbox_id, sandbox_name).await? else {
            if !sandbox_id.is_empty() {
                self.cleanup_volume_with_warning(
                    &volume_name(sandbox_id),
                    sandbox_id,
                    "container-not-found",
                )
                .await;
                cleanup_secret_staging_dir(sandbox_id, &self.config);
            }
            return Ok(false);
        };
        let resolved_id = entry
            .configuration
            .labels
            .get(LABEL_SANDBOX_ID)
            .cloned()
            .unwrap_or_else(|| sandbox_id.to_string());
        let deleted = self.cli.delete(&entry.id).await.map_err(status_from_cli)?;
        if !resolved_id.is_empty() {
            self.cleanup_volume_with_warning(
                &volume_name(&resolved_id),
                &resolved_id,
                "container-deleted",
            )
            .await;
            cleanup_secret_staging_dir(&resolved_id, &self.config);
        }
        if deleted && !resolved_id.is_empty() {
            self.emit_deleted_event(&resolved_id);
        }
        Ok(deleted)
    }

    async fn find_managed_entry(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<AppleContainerListEntry>, Status> {
        Ok(self
            .list_entries()
            .await?
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .find(|entry| entry_matches(entry, sandbox_id, sandbox_name)))
    }

    /// Fetch one sandbox by name.
    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        let sandboxes = self.list_entries().await?;
        Ok(sandboxes
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .find(|entry| entry_matches(entry, sandbox_id, sandbox_name))
            .and_then(|entry| driver_sandbox_from_entry(entry, self.supervisor_readiness.as_ref())))
    }

    /// List all OpenShell-managed Apple containers.
    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, Status> {
        let mut sandboxes = self
            .list_entries()
            .await?
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .filter_map(|entry| {
                driver_sandbox_from_entry(entry, self.supervisor_readiness.as_ref())
            })
            .collect::<Vec<_>>();
        sandboxes.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(sandboxes)
    }

    /// Start a polling watch stream for sandbox snapshots.
    pub fn watch_sandboxes(&self) -> Result<WatchStream, Status> {
        let driver = self.clone();
        let mut events = self.events.subscribe();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            let mut previous: BTreeMap<String, DriverSandbox> = BTreeMap::new();
            let mut poll = tokio::time::interval(Duration::from_secs(2));
            poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = poll.tick() => {
                        match driver.list_sandboxes().await {
                            Ok(sandboxes) => {
                                let current = sandboxes
                                    .iter()
                                    .map(|sandbox| (sandbox.id.clone(), sandbox.clone()))
                                    .collect::<BTreeMap<_, _>>();
                                if !send_snapshot_delta(&tx, &previous, &current).await {
                                    return;
                                }
                                previous = current;
                            }
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    "Apple sandbox watch poll failed"
                                );
                            }
                        }
                    }
                    event = events.recv() => {
                        match event {
                            Ok(event) => {
                                apply_watch_event_to_cache(&mut previous, &event);
                                if tx.send(Ok(event)).await.is_err() {
                                    return;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    skipped,
                                    "Apple sandbox watch event receiver lagged; polling will resynchronize state"
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    fn emit_deleted_event(&self, sandbox_id: &str) {
        let _ = self
            .events
            .send(watch_deleted_event(sandbox_id.to_string()));
    }

    async fn cleanup_volume_with_warning(&self, volume: &str, sandbox_id: &str, reason: &str) {
        match self.cli.delete_volume(volume).await {
            Ok(_) => {}
            Err(err) => {
                let status = status_from_cli(err);
                warn!(
                    sandbox_id,
                    volume,
                    reason,
                    error = %status,
                    "Failed to delete Apple sandbox volume"
                );
            }
        }
    }

    async fn list_entries(&self) -> Result<Vec<AppleContainerListEntry>, Status> {
        self.cli.list().await.map_err(status_from_cli)
    }

    async fn create_args(&self, sandbox: &DriverSandbox) -> Result<Vec<String>, Status> {
        self.create_args_with_secret_staging_base(sandbox, None)
            .await
    }

    async fn create_args_with_secret_staging_base(
        &self,
        sandbox: &DriverSandbox,
        secret_staging_base: Option<&Path>,
    ) -> Result<Vec<String>, Status> {
        let container_name = container_name_for_sandbox(sandbox);
        let image = sandbox_image(sandbox, &self.config);
        if image.trim().is_empty() {
            return Err(Status::failed_precondition(
                "no sandbox image configured: set default_image in [openshell.drivers.apple-container] or provide a template image",
            ));
        }

        let supervisor_dir = supervisor_bin_dir(&self.config.supervisor_bin_dir)?;
        let guest_tls = apple_guest_tls_paths(&self.config)?;
        let staging_dirs = write_secret_staging_materials(
            sandbox,
            &self.config,
            guest_tls.as_ref(),
            secret_staging_base,
        )
        .await?;
        let mut args = vec!["--name".to_string(), container_name];
        for label in managed_labels(sandbox, &self.config) {
            args.push("--label".to_string());
            args.push(label);
        }
        args.extend([
            // Sandbox images may set USER sandbox for interactive shells. The
            // supervisor itself must start as root so it can create the network
            // namespace, prepare writable paths, and then drop to the policy user.
            "--user".to_string(),
            "0:0".to_string(),
            "--workdir".to_string(),
            SANDBOX_WORKDIR.to_string(),
            "--volume".to_string(),
            format!("{}:{SANDBOX_WORKDIR}", volume_name(&sandbox.id)),
            "--mount".to_string(),
            crate::cli::readonly_bind_mount(&supervisor_dir, SUPERVISOR_DIR_MOUNT_PATH),
            "--entrypoint".to_string(),
            format!("{SUPERVISOR_DIR_MOUNT_PATH}/openshell-sandbox"),
        ]);

        if let Some(auth_dir) = staging_dirs.auth_mount_dir {
            args.push("--mount".to_string());
            args.push(crate::cli::readonly_bind_mount(
                &auth_dir,
                AUTH_DIR_MOUNT_PATH,
            ));
        }

        if let Some(tls_dir) = staging_dirs.tls_mount_dir {
            args.push("--mount".to_string());
            args.push(crate::cli::readonly_bind_mount(
                &tls_dir,
                TLS_DIR_MOUNT_PATH,
            ));
        }

        for (key, value) in sandbox_environment(sandbox, &self.config) {
            args.push("--env".to_string());
            args.push(format!("{key}={value}"));
        }

        if let Some(memory) = sandbox_memory_limit(sandbox) {
            args.push("--memory".to_string());
            args.push(memory);
        }
        if let Some(cpus) = sandbox_cpu_limit(sandbox)? {
            args.push("--cpus".to_string());
            args.push(cpus);
        }

        for cap in ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYSLOG"] {
            args.push("--cap-add".to_string());
            args.push(cap.to_string());
        }
        args.push(image);
        // The Apple CLI does not expose a Docker-style empty-CMD override.
        // Pass the supervisor command explicitly after the image so image CMD
        // defaults cannot become accidental sandbox workload arguments.
        args.push("sleep".to_string());
        args.push("infinity".to_string());
        Ok(args)
    }
}

fn status_from_cli(err: AppleContainerCliError) -> Status {
    if matches!(&err, AppleContainerCliError::Unhealthy { .. }) {
        return Status::failed_precondition(err.to_string());
    }
    let message = err.to_string();
    if message.contains("already exists") || message.contains("exists") {
        Status::already_exists(message)
    } else if message.contains("not found") || message.contains("does not exist") {
        Status::not_found(message)
    } else {
        Status::internal(message)
    }
}

async fn send_snapshot_delta(
    tx: &mpsc::Sender<Result<WatchSandboxesEvent, String>>,
    previous: &BTreeMap<String, DriverSandbox>,
    current: &BTreeMap<String, DriverSandbox>,
) -> bool {
    for (sandbox_id, sandbox) in current {
        if previous.get(sandbox_id) == Some(sandbox) {
            continue;
        }
        if tx
            .send(Ok(watch_sandbox_event(sandbox.clone())))
            .await
            .is_err()
        {
            return false;
        }
    }
    for sandbox_id in previous.keys() {
        if current.contains_key(sandbox_id) {
            continue;
        }
        if tx
            .send(Ok(watch_deleted_event(sandbox_id.clone())))
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

fn watch_sandbox_event(sandbox: DriverSandbox) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(sandbox),
            },
        )),
    }
}

fn watch_deleted_event(sandbox_id: String) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Deleted(
            WatchSandboxesDeletedEvent { sandbox_id },
        )),
    }
}

fn apply_watch_event_to_cache(
    previous: &mut BTreeMap<String, DriverSandbox>,
    event: &WatchSandboxesEvent,
) {
    match event.payload.as_ref() {
        Some(watch_sandboxes_event::Payload::Sandbox(WatchSandboxesSandboxEvent {
            sandbox: Some(sandbox),
        })) => {
            previous.insert(sandbox.id.clone(), sandbox.clone());
        }
        Some(watch_sandboxes_event::Payload::Deleted(WatchSandboxesDeletedEvent {
            sandbox_id,
        })) => {
            previous.remove(sandbox_id);
        }
        _ => {}
    }
}

async fn gateway_bind_addresses_from_networks(
    cli: &AppleContainerCli,
    config: &AppleContainerComputeConfig,
) -> Result<Vec<SocketAddr>, Status> {
    if !config.grpc_endpoint.trim().is_empty() {
        return Ok(Vec::new());
    }
    let networks = cli.list_networks().await.map_err(status_from_cli)?;
    let Some(host_gateway) = apple_default_network_gateway(&networks) else {
        return Err(Status::failed_precondition(
            "apple-container driver could not find a default network ipv4Gateway; set grpc_endpoint to a reachable gateway URL",
        ));
    };
    Ok(vec![SocketAddr::new(host_gateway, config.gateway_port)])
}

fn apple_default_network_gateway(networks: &[AppleContainerNetworkEntry]) -> Option<IpAddr> {
    networks
        .iter()
        .find(|network| network.id == "default" || network.configuration.name == "default")
        .and_then(|network| network.status.ipv4_gateway)
        .or_else(|| {
            networks
                .iter()
                .find_map(|network| network.status.ipv4_gateway)
        })
}

fn apple_container_state_needs_resume(state: &str) -> bool {
    matches!(state, "created" | "stopped" | "exited")
}

fn apple_container_state_needs_shutdown_stop(state: &str) -> bool {
    matches!(state, "created" | "running")
}

const MAX_CONTAINER_NAME_LEN: usize = 64;

fn container_name_for_sandbox(sandbox: &DriverSandbox) -> String {
    let id_suffix = runtime_name_component(&sandbox.id);
    let friendly_name = runtime_name_component(&sandbox.name);
    if friendly_name.is_empty() {
        let mut base = format!("{CONTAINER_PREFIX}{id_suffix}");
        if base.len() > MAX_CONTAINER_NAME_LEN {
            base.truncate(MAX_CONTAINER_NAME_LEN);
        }
        return trim_runtime_name_tail(base);
    }

    // Apple container names are unique per runtime, not per OpenShell
    // namespace. Keep the id suffix even when the friendly name is long so two
    // sandboxes with the same display name cannot collide at the platform
    // layer.
    let reserved = CONTAINER_PREFIX.len() + 1 + id_suffix.len();
    if reserved >= MAX_CONTAINER_NAME_LEN {
        let mut base = format!("{CONTAINER_PREFIX}{id_suffix}");
        base.truncate(MAX_CONTAINER_NAME_LEN);
        return trim_runtime_name_tail(base);
    }

    let name_budget = MAX_CONTAINER_NAME_LEN - reserved;
    let truncated_name = if friendly_name.len() > name_budget {
        trim_runtime_name_tail(friendly_name[..name_budget].to_string())
    } else {
        friendly_name
    };
    format!("{CONTAINER_PREFIX}{truncated_name}-{id_suffix}")
}

fn volume_name(sandbox_id: &str) -> String {
    format!("{VOLUME_PREFIX}{}", sanitize_name(sandbox_id))
}

fn managed_labels(sandbox: &DriverSandbox, config: &AppleContainerComputeConfig) -> Vec<String> {
    let mut labels = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.labels.clone())
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    labels.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    labels.insert(
        LABEL_SANDBOX_NAMESPACE.to_string(),
        config.sandbox_namespace.clone(),
    );
    labels
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn sanitize_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "sandbox".to_string()
    } else {
        out
    }
}

fn runtime_name_component(value: &str) -> String {
    let trimmed = trim_runtime_name_tail(sanitize_name(value));
    if trimmed.is_empty() {
        "sandbox".to_string()
    } else {
        trimmed
    }
}

fn trim_runtime_name_tail(mut value: String) -> String {
    while value
        .chars()
        .last()
        .is_some_and(|ch| matches!(ch, '-' | '.' | '_'))
    {
        value.pop();
    }
    value
}

fn validate_container_name(name: &str) -> Result<(), Status> {
    if name.starts_with('-') || name.ends_with('-') {
        return Err(Status::failed_precondition(
            "apple-container sandbox name cannot start or end with '-'",
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(Status::failed_precondition(
            "apple-container sandbox name contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_sandbox_template(sandbox: &DriverSandbox) -> Result<(), Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;

    if !template.agent_socket_path.trim().is_empty() {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support template.agent_socket_path",
        ));
    }
    if template
        .platform_config
        .as_ref()
        .is_some_and(|config| !config.fields.is_empty())
    {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support template.platform_config",
        ));
    }
    if template
        .driver_config
        .as_ref()
        .is_some_and(|config| !config.fields.is_empty())
    {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support template.driver_config",
        ));
    }
    if let Some(resources) = template.resources.as_ref() {
        validate_resources(resources)?;
    }
    Ok(())
}

fn validate_sandbox_auth(sandbox: &DriverSandbox) -> Result<(), Status> {
    if sandbox
        .spec
        .as_ref()
        .is_some_and(|spec| !spec.sandbox_token.trim().is_empty())
    {
        return Ok(());
    }

    Err(Status::failed_precondition(
        "apple-container sandboxes require gateway JWT auth; configure [openshell.gateway.gateway_jwt]",
    ))
}

fn validate_resources(
    resources: &openshell_core::proto::compute::v1::DriverResourceRequirements,
) -> Result<(), Status> {
    if !resources.cpu_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support resources.requests.cpu",
        ));
    }
    if !resources.memory_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support resources.requests.memory",
        ));
    }
    let _ = normalize_cpu_for_apple(&resources.cpu_limit)?;
    Ok(())
}

fn sandbox_image(sandbox: &DriverSandbox, config: &AppleContainerComputeConfig) -> String {
    sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.as_str())
        .filter(|image| !image.trim().is_empty())
        .unwrap_or(&config.default_image)
        .to_string()
}

fn sandbox_environment(
    sandbox: &DriverSandbox,
    config: &AppleContainerComputeConfig,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if let Some(spec) = sandbox.spec.as_ref() {
        let mut user_env = BTreeMap::new();
        if let Some(template) = spec.template.as_ref() {
            user_env.extend(template.environment.clone());
        }
        user_env.extend(spec.environment.clone());
        for key in driver_owned_environment_keys() {
            user_env.remove(key);
        }
        user_env.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
        user_env.remove(openshell_core::sandbox_env::USER_ENVIRONMENT);
        if !user_env.is_empty() {
            if let Ok(json) = serde_json::to_string(&user_env) {
                env.insert(
                    openshell_core::sandbox_env::USER_ENVIRONMENT.to_string(),
                    json,
                );
            }
            env.extend(user_env);
        }
    }
    for key in driver_owned_environment_keys() {
        env.remove(key);
    }
    env.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
    env.extend([
        ("HOME".to_string(), "/root".to_string()),
        ("PATH".to_string(), SUPERVISOR_PATH.to_string()),
        ("TERM".to_string(), "xterm".to_string()),
        (
            openshell_core::sandbox_env::ENDPOINT.to_string(),
            config.effective_grpc_endpoint(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX_ID.to_string(),
            sandbox.id.clone(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX.to_string(),
            sandbox.name.clone(),
        ),
        (
            openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
            config.sandbox_ssh_socket_path.clone(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX_COMMAND.to_string(),
            SANDBOX_COMMAND.to_string(),
        ),
        (
            openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
            openshell_core::telemetry::enabled_env_value().to_string(),
        ),
        (
            openshell_core::sandbox_env::LOG_LEVEL.to_string(),
            openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level),
        ),
    ]);
    if config.tls_enabled() {
        env.insert(
            openshell_core::sandbox_env::TLS_CA.to_string(),
            TLS_CA_MOUNT_PATH.to_string(),
        );
        env.insert(
            openshell_core::sandbox_env::TLS_CERT.to_string(),
            TLS_CERT_MOUNT_PATH.to_string(),
        );
        env.insert(
            openshell_core::sandbox_env::TLS_KEY.to_string(),
            TLS_KEY_MOUNT_PATH.to_string(),
        );
    }
    if let Some(spec) = sandbox.spec.as_ref()
        && !spec.sandbox_token.is_empty()
    {
        env.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE.to_string(),
            format!("{AUTH_DIR_MOUNT_PATH}/{SANDBOX_TOKEN_FILE}"),
        );
    }
    env
}

fn driver_owned_environment_keys() -> [&'static str; 14] {
    [
        "HOME",
        "PATH",
        "TERM",
        openshell_core::sandbox_env::ENDPOINT,
        openshell_core::sandbox_env::SANDBOX_ID,
        openshell_core::sandbox_env::SANDBOX,
        openshell_core::sandbox_env::SSH_SOCKET_PATH,
        openshell_core::sandbox_env::SANDBOX_COMMAND,
        openshell_core::sandbox_env::TELEMETRY_ENABLED,
        openshell_core::sandbox_env::LOG_LEVEL,
        openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
        openshell_core::sandbox_env::TLS_CA,
        openshell_core::sandbox_env::TLS_CERT,
        openshell_core::sandbox_env::TLS_KEY,
    ]
}

fn apple_guest_tls_paths(
    config: &AppleContainerComputeConfig,
) -> Result<Option<AppleGuestTlsPaths>, Status> {
    let has_ca = config.guest_tls_ca.is_some();
    let has_cert = config.guest_tls_cert.is_some();
    let has_key = config.guest_tls_key.is_some();
    let any_tls = has_ca || has_cert || has_key;
    let all_tls = has_ca && has_cert && has_key;

    if any_tls && !all_tls {
        return Err(Status::failed_precondition(
            "apple-container compute driver requires guest_tls_ca, guest_tls_cert, and guest_tls_key when any guest TLS material is configured",
        ));
    }

    let endpoint = config.effective_grpc_endpoint();
    if !endpoint.starts_with("https://") {
        if any_tls {
            return Err(Status::failed_precondition(format!(
                "guest_tls_ca/guest_tls_cert/guest_tls_key were provided but grpc_endpoint is '{endpoint}'; TLS materials require an https:// endpoint",
            )));
        }
        return Ok(None);
    }

    if !all_tls {
        return Err(Status::failed_precondition(
            "apple-container compute driver requires guest_tls_ca, guest_tls_cert, and guest_tls_key when grpc_endpoint uses https://",
        ));
    }

    let ca = config
        .guest_tls_ca
        .as_deref()
        .ok_or_else(|| Status::failed_precondition("guest_tls_ca is required"))?;
    let cert = config
        .guest_tls_cert
        .as_deref()
        .ok_or_else(|| Status::failed_precondition("guest_tls_cert is required"))?;
    let key = config
        .guest_tls_key
        .as_deref()
        .ok_or_else(|| Status::failed_precondition("guest_tls_key is required"))?;

    Ok(Some(AppleGuestTlsPaths {
        ca: canonicalize_existing_file(ca, "apple-container TLS CA certificate")?,
        cert: canonicalize_existing_file(cert, "apple-container TLS client certificate")?,
        key: canonicalize_existing_file(key, "apple-container TLS client private key")?,
    }))
}

fn canonicalize_existing_file(path: &Path, description: &str) -> Result<PathBuf, Status> {
    if !path.is_file() {
        return Err(Status::failed_precondition(format!(
            "{description} '{}' does not exist or is not a file",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|err| {
        Status::failed_precondition(format!(
            "failed to resolve {description} '{}': {err}",
            path.display()
        ))
    })
}

async fn write_secret_staging_materials(
    sandbox: &DriverSandbox,
    config: &AppleContainerComputeConfig,
    tls: Option<&AppleGuestTlsPaths>,
    secret_staging_base: Option<&Path>,
) -> Result<AppleSecretStagingDirs, Status> {
    let token = sandbox
        .spec
        .as_ref()
        .and_then(|spec| (!spec.sandbox_token.is_empty()).then_some(spec.sandbox_token.as_str()));
    if token.is_none() && tls.is_none() {
        return Ok(AppleSecretStagingDirs {
            auth_mount_dir: None,
            tls_mount_dir: None,
        });
    }
    let dir = secret_staging_dir_with_base(
        &sandbox.id,
        Some(&config.sandbox_namespace),
        secret_staging_base,
    )?;
    openshell_core::paths::create_dir_restricted(&dir)
        .map_err(|err| Status::internal(format!("create secret staging dir failed: {err}")))?;
    let result = async {
        if let Some(token) = token {
            write_owner_only_file(&dir.join(SANDBOX_TOKEN_FILE), token).await?;
        }
        let tls_dir = if let Some(tls) = tls {
            // Apple Container's virtiofs bind mounts are directory-oriented.
            // Stage guest secrets under the per-sandbox secret directory so the
            // same lifecycle cleanup removes both the JWT and TLS material.
            let tls_dir = dir.join("tls");
            openshell_core::paths::create_dir_restricted(&tls_dir)
                .map_err(|err| Status::internal(format!("create TLS staging dir failed: {err}")))?;
            copy_file_restricted(&tls.ca, &tls_dir.join(TLS_CA_FILE), false).await?;
            copy_file_restricted(&tls.cert, &tls_dir.join(TLS_CERT_FILE), false).await?;
            copy_file_restricted(&tls.key, &tls_dir.join(TLS_KEY_FILE), true).await?;
            Some(tls_dir)
        } else {
            None
        };
        Ok::<Option<PathBuf>, Status>(tls_dir)
    }
    .await;
    let tls_dir = match result {
        Ok(tls_dir) => tls_dir,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(err);
        }
    };
    Ok(AppleSecretStagingDirs {
        auth_mount_dir: token.is_some().then(|| dir.clone()),
        tls_mount_dir: tls_dir,
    })
}

async fn copy_file_restricted(source: &Path, dest: &Path, owner_only: bool) -> Result<(), Status> {
    let source = source.to_path_buf();
    let dest = dest.to_path_buf();
    tokio::task::spawn_blocking(move || copy_file_restricted_blocking(&source, &dest, owner_only))
        .await
        .map_err(|err| Status::internal(format!("copy TLS file task failed: {err}")))?
}

fn copy_file_restricted_blocking(
    source: &Path,
    dest: &Path,
    owner_only: bool,
) -> Result<(), Status> {
    let bytes = std::fs::read(source)
        .map_err(|err| Status::internal(format!("read {} failed: {err}", source.display())))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        let mode = if owner_only { 0o600 } else { 0o644 };
        options.mode(mode);
    }
    let mut file = options
        .open(dest)
        .map_err(|err| Status::internal(format!("create {} failed: {err}", dest.display())))?;
    file.write_all(&bytes)
        .map_err(|err| Status::internal(format!("write {} failed: {err}", dest.display())))?;
    if owner_only {
        openshell_core::paths::set_file_owner_only(dest).map_err(|err| {
            Status::internal(format!("restrict {} failed: {err}", dest.display()))
        })?;
    }
    Ok(())
}

async fn write_owner_only_file(path: &Path, contents: &str) -> Result<(), Status> {
    let path = path.to_path_buf();
    let contents = format!("{contents}\n");
    tokio::task::spawn_blocking(move || write_owner_only_file_blocking(&path, &contents))
        .await
        .map_err(|err| Status::internal(format!("write auth file task failed: {err}")))?
}

fn write_owner_only_file_blocking(path: &Path, contents: &str) -> Result<(), Status> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        // Token files must never exist with default umask permissions. Create
        // them at owner-only mode, then re-apply the shared path helper so the
        // invariant stays consistent with the rest of OpenShell's secret files.
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| Status::internal(format!("create {} failed: {err}", path.display())))?;
    file.write_all(contents.as_bytes())
        .map_err(|err| Status::internal(format!("write {} failed: {err}", path.display())))?;
    openshell_core::paths::set_file_owner_only(path)
        .map_err(|err| Status::internal(format!("restrict {} failed: {err}", path.display())))
}

fn cleanup_secret_staging_dir(sandbox_id: &str, config: &AppleContainerComputeConfig) {
    let Ok(dir) = secret_staging_dir(sandbox_id, Some(&config.sandbox_namespace)) else {
        return;
    };
    if let Err(err) = std::fs::remove_dir_all(&dir)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %dir.display(), error = %err, "failed to remove Apple container secret staging dir");
    }
}

fn secret_staging_dir(sandbox_id: &str, namespace: Option<&str>) -> Result<PathBuf, Status> {
    secret_staging_dir_with_base(sandbox_id, namespace, None)
}

fn secret_staging_dir_with_base(
    sandbox_id: &str,
    namespace: Option<&str>,
    base: Option<&Path>,
) -> Result<PathBuf, Status> {
    let mut path = if let Some(base) = base {
        base.to_path_buf()
    } else {
        openshell_core::paths::xdg_state_dir()
            .map_err(|err| Status::internal(format!("resolve state dir failed: {err}")))?
            .join("openshell")
            .join("apple-container-secrets")
    };
    if let Some(namespace) = namespace {
        path = path.join(namespace.replace(['/', '\\'], "-"));
    }
    Ok(path.join(sandbox_id))
}

fn supervisor_bin_dir(configured: &Path) -> Result<PathBuf, Status> {
    let path = if configured.as_os_str().is_empty() {
        default_supervisor_bin_dir().ok_or_else(|| {
            Status::failed_precondition(
                "apple-container driver requires supervisor_bin_dir or OPENSHELL_APPLE_CONTAINER_SUPERVISOR_BIN_DIR",
            )
        })?
    } else {
        configured.to_path_buf()
    };
    let supervisor = path.join("openshell-sandbox");
    if !supervisor.is_file() {
        return Err(Status::failed_precondition(format!(
            "openshell-sandbox supervisor not found at {}",
            supervisor.display()
        )));
    }
    Ok(path)
}

fn default_supervisor_bin_dir() -> Option<PathBuf> {
    std::env::var_os("OPENSHELL_APPLE_CONTAINER_SUPERVISOR_BIN_DIR").map(PathBuf::from)
}

fn sandbox_memory_limit(sandbox: &DriverSandbox) -> Option<String> {
    let value = sandbox
        .spec
        .as_ref()?
        .template
        .as_ref()?
        .resources
        .as_ref()?
        .memory_limit
        .trim()
        .to_string();
    (!value.is_empty()).then(|| normalize_quantity_for_apple(&value))
}

fn sandbox_cpu_limit(sandbox: &DriverSandbox) -> Result<Option<String>, Status> {
    let Some(resources) = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .and_then(|template| template.resources.as_ref())
    else {
        return Ok(None);
    };
    normalize_cpu_for_apple(&resources.cpu_limit)
}

fn normalize_cpu_for_apple(value: &str) -> Result<Option<String>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if let Some(millicores) = value.strip_suffix('m') {
        let millicores = millicores.parse::<u64>().map_err(|_| {
            Status::failed_precondition(format!(
                "invalid apple-container cpu_limit '{value}'; expected a positive whole-core or whole-millicore quantity",
            ))
        })?;
        if millicores == 0 {
            return Err(Status::failed_precondition(
                "apple-container cpu_limit must be greater than zero",
            ));
        }
        if millicores % 1_000 != 0 {
            return Err(Status::failed_precondition(
                "apple-container cpu_limit must resolve to a whole CPU count because the Apple Container CLI expects an integer --cpus value",
            ));
        }
        return Ok(Some((millicores / 1_000).to_string()));
    }

    let cores = value.parse::<u64>().map_err(|_| {
        Status::failed_precondition(format!(
            "invalid apple-container cpu_limit '{value}'; expected a positive whole-core or whole-millicore quantity",
        ))
    })?;
    if cores == 0 {
        return Err(Status::failed_precondition(
            "apple-container cpu_limit must be greater than zero",
        ));
    }
    Ok(Some(value.to_string()))
}

fn normalize_quantity_for_apple(value: &str) -> String {
    value
        .strip_suffix("Ki")
        .map(|v| format!("{v}K"))
        .or_else(|| value.strip_suffix("Mi").map(|v| format!("{v}M")))
        .or_else(|| value.strip_suffix("Gi").map(|v| format!("{v}G")))
        .or_else(|| value.strip_suffix("Ti").map(|v| format!("{v}T")))
        .unwrap_or_else(|| value.to_string())
}

fn managed_entry(entry: &AppleContainerListEntry, config: &AppleContainerComputeConfig) -> bool {
    let labels = &entry.configuration.labels;
    labels
        .get(LABEL_MANAGED_BY)
        .is_some_and(|value| value == LABEL_MANAGED_BY_VALUE)
        && labels
            .get(LABEL_SANDBOX_NAMESPACE)
            .is_some_and(|value| value == &config.sandbox_namespace)
}

fn entry_matches(entry: &AppleContainerListEntry, sandbox_id: &str, sandbox_name: &str) -> bool {
    let labels = &entry.configuration.labels;
    let id_matches = sandbox_id.is_empty()
        || labels
            .get(LABEL_SANDBOX_ID)
            .is_some_and(|value| value == sandbox_id);
    let name_matches = sandbox_name.is_empty()
        || labels
            .get(LABEL_SANDBOX_NAME)
            .is_some_and(|value| value == sandbox_name);
    id_matches && name_matches
}

fn require_sandbox_identifier(sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
    if sandbox_id.is_empty() && sandbox_name.is_empty() {
        return Err(Status::invalid_argument(
            "sandbox_id or sandbox_name is required",
        ));
    }
    Ok(())
}

fn driver_sandbox_from_entry(
    entry: AppleContainerListEntry,
    readiness: &dyn SupervisorReadiness,
) -> Option<DriverSandbox> {
    let labels = &entry.configuration.labels;
    let id = labels.get(LABEL_SANDBOX_ID)?.clone();
    let name = labels.get(LABEL_SANDBOX_NAME)?.clone();
    let namespace = labels
        .get(LABEL_SANDBOX_NAMESPACE)
        .cloned()
        .unwrap_or_default();
    let image = entry
        .configuration
        .image
        .as_ref()
        .map(|image| image.reference.clone())
        .unwrap_or_default();
    let supervisor_connected = readiness.is_supervisor_connected(&id);
    Some(DriverSandbox {
        id,
        name: name.clone(),
        namespace,
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: name,
            instance_id: entry.id,
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition_from_state(
                &entry.status.state,
                &image,
                supervisor_connected,
                entry.configuration.creation_date.as_deref(),
            )],
            deleting: apple_container_is_deleting(&entry.status.state),
        }),
    })
}

fn condition_from_state(
    state: &str,
    image: &str,
    supervisor_connected: bool,
    creation_date: Option<&str>,
) -> DriverCondition {
    let launch_age_ms = creation_date.and_then(creation_age_ms);
    match state {
        "running" if supervisor_connected => DriverCondition {
            r#type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "SupervisorConnected".to_string(),
            message: "Supervisor relay is live".to_string(),
            last_transition_time: String::new(),
        },
        "running" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "DependenciesNotReady".to_string(),
            message: format!(
                "Apple container is running from {image}; waiting for supervisor relay"
            ),
            last_transition_time: String::new(),
        },
        "created" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "Starting".to_string(),
            message: "Apple container is created".to_string(),
            last_transition_time: String::new(),
        },
        "stopped"
            if launch_age_ms.is_some_and(|age_ms| age_ms <= TRANSIENT_STOPPED_LAUNCH_GRACE_MS) =>
        {
            DriverCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Starting".to_string(),
                message: "Apple container is starting".to_string(),
                last_transition_time: String::new(),
            }
        }
        "stopped" | "exited" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "ContainerStopped".to_string(),
            message: "Apple container is stopped".to_string(),
            last_transition_time: String::new(),
        },
        "deleting" | "removing" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "Deleting".to_string(),
            message: "Apple container is being removed".to_string(),
            last_transition_time: String::new(),
        },
        other => DriverCondition {
            r#type: "Ready".to_string(),
            status: "Unknown".to_string(),
            reason: "ContainerStateUnknown".to_string(),
            message: format!("Apple container state is {other}"),
            last_transition_time: String::new(),
        },
    }
}

fn creation_age_ms(creation_date: &str) -> Option<i64> {
    let created_at = chrono::DateTime::parse_from_rfc3339(creation_date).ok()?;
    Some(
        openshell_core::time::now_ms()
            .saturating_sub(created_at.timestamp_millis())
            .max(0),
    )
}

fn apple_container_is_deleting(state: &str) -> bool {
    matches!(state, "deleting" | "removing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{AppleContainerConfiguration, AppleContainerImage, AppleContainerStatus};
    use openshell_core::proto::compute::v1::{
        DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
    };

    struct AlwaysReady;

    impl SupervisorReadiness for AlwaysReady {
        fn is_supervisor_connected(&self, _sandbox_id: &str) -> bool {
            true
        }
    }

    struct NeverReady;

    impl SupervisorReadiness for NeverReady {
        fn is_supervisor_connected(&self, _sandbox_id: &str) -> bool {
            false
        }
    }

    fn test_supervisor_dir(test_name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openshell-apple-container-{test_name}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn container_name_sanitizes_unsupported_characters() {
        let sandbox = DriverSandbox {
            id: "sbx/id".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: None,
            status: None,
        };
        assert_eq!(
            container_name_for_sandbox(&sandbox),
            "openshell-sandbox-demo-sbx-id"
        );
    }

    #[test]
    fn container_name_preserves_id_suffix_with_apple_length_limit() {
        let sandbox = DriverSandbox {
            id: "d40fd9e4-39be-4182-b0bf-54c295292dca".to_string(),
            name: "hermes-apple-e2e-mainbase".to_string(),
            namespace: String::new(),
            spec: None,
            status: None,
        };

        let name = container_name_for_sandbox(&sandbox);

        assert_eq!(name.len(), MAX_CONTAINER_NAME_LEN);
        assert!(name.ends_with("d40fd9e4-39be-4182-b0bf-54c295292dca"));
    }

    #[test]
    fn volume_name_uses_sandbox_id() {
        assert_eq!(
            volume_name("sandbox/id"),
            "openshell-sandbox-sandbox-id".to_string()
        );
    }

    #[test]
    fn condition_maps_running_to_waiting_until_supervisor_connects() {
        let condition = condition_from_state("running", "example:latest", false, None);
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "DependenciesNotReady");
    }

    #[test]
    fn condition_maps_connected_supervisor_to_ready() {
        let condition = condition_from_state("running", "example:latest", true, None);
        assert_eq!(condition.status, "True");
        assert_eq!(condition.reason, "SupervisorConnected");
    }

    #[test]
    fn condition_maps_recent_stopped_container_to_starting() {
        let recent_creation_date = rfc3339_from_unix_ms(openshell_core::time::now_ms() - 1_000);

        let condition = condition_from_state(
            "stopped",
            "example:latest",
            false,
            Some(&recent_creation_date),
        );

        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "Starting");
    }

    #[test]
    fn condition_maps_old_stopped_container_to_terminal_error() {
        let old_creation_date = rfc3339_from_unix_ms(
            openshell_core::time::now_ms() - TRANSIENT_STOPPED_LAUNCH_GRACE_MS - 1_000,
        );

        let condition =
            condition_from_state("stopped", "example:latest", false, Some(&old_creation_date));

        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "ContainerStopped");
    }

    #[test]
    fn memory_quantity_maps_kubernetes_suffixes() {
        assert_eq!(normalize_quantity_for_apple("512Mi"), "512M");
        assert_eq!(normalize_quantity_for_apple("4Gi"), "4G");
    }

    #[test]
    fn cpu_limit_reads_typed_resources() {
        let sandbox = DriverSandbox {
            id: "id".to_string(),
            name: "name".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    resources: Some(DriverResourceRequirements {
                        cpu_limit: "2".to_string(),
                        ..DriverResourceRequirements::default()
                    }),
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };
        assert_eq!(sandbox_cpu_limit(&sandbox).unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn cpu_limit_accepts_whole_core_quantities_for_apple_cli() {
        assert_eq!(
            normalize_cpu_for_apple("2000m").unwrap().as_deref(),
            Some("2")
        );
        assert_eq!(normalize_cpu_for_apple("2").unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn cpu_limit_rejects_fractional_values_for_apple_cli() {
        let err = normalize_cpu_for_apple("500m").unwrap_err();
        assert_eq!(
            err.message(),
            "apple-container cpu_limit must resolve to a whole CPU count because the Apple Container CLI expects an integer --cpus value"
        );

        let err = normalize_cpu_for_apple("1.5").unwrap_err();
        assert!(
            err.message()
                .contains("expected a positive whole-core or whole-millicore quantity")
        );
    }

    #[test]
    fn cpu_limit_rejects_non_positive_values() {
        let err = normalize_cpu_for_apple("0").unwrap_err();
        assert_eq!(
            err.message(),
            "apple-container cpu_limit must be greater than zero"
        );

        let err = normalize_cpu_for_apple("0m").unwrap_err();
        assert_eq!(
            err.message(),
            "apple-container cpu_limit must be greater than zero"
        );
    }

    fn network_entry(id: &str, name: &str, gateway: Option<&str>) -> AppleContainerNetworkEntry {
        AppleContainerNetworkEntry {
            id: id.to_string(),
            configuration: crate::cli::AppleContainerNetworkConfiguration {
                name: name.to_string(),
            },
            status: crate::cli::AppleContainerNetworkStatus {
                ipv4_gateway: gateway.map(|value| value.parse().unwrap()),
            },
        }
    }

    #[test]
    fn apple_default_network_gateway_prefers_default_network() {
        let networks = vec![
            network_entry("other", "other", Some("192.168.100.1")),
            network_entry("default", "default", Some("192.168.64.1")),
        ];

        assert_eq!(
            apple_default_network_gateway(&networks).map(|ip| ip.to_string()),
            Some("192.168.64.1".to_string())
        );
    }

    #[test]
    fn apple_default_network_gateway_falls_back_to_first_gateway() {
        let networks = vec![
            network_entry("default", "default", None),
            network_entry("custom", "custom", Some("192.168.127.1")),
        ];

        assert_eq!(
            apple_default_network_gateway(&networks).map(|ip| ip.to_string()),
            Some("192.168.127.1".to_string())
        );
    }

    #[test]
    fn lifecycle_state_predicates_match_startable_and_stoppable_states() {
        for state in ["created", "stopped", "exited"] {
            assert!(
                apple_container_state_needs_resume(state),
                "{state} should be resumed"
            );
        }
        for state in ["running", "deleting", "removing", "unknown"] {
            assert!(
                !apple_container_state_needs_resume(state),
                "{state} should not be resumed"
            );
        }
        for state in ["created", "running"] {
            assert!(
                apple_container_state_needs_shutdown_stop(state),
                "{state} should be stopped on shutdown"
            );
        }
        for state in ["stopped", "exited", "deleting", "removing", "unknown"] {
            assert!(
                !apple_container_state_needs_shutdown_stop(state),
                "{state} should not be stopped on shutdown"
            );
        }
    }

    #[test]
    fn default_endpoint_uses_apple_host_dns_name() {
        let config = AppleContainerComputeConfig {
            gateway_port: 17686,
            ..AppleContainerComputeConfig::default()
        };

        assert_eq!(
            config.effective_grpc_endpoint(),
            "http://host.container.internal:17686"
        );
    }

    #[test]
    fn default_endpoint_uses_https_when_guest_tls_is_configured() {
        let config = AppleContainerComputeConfig {
            gateway_port: 17686,
            guest_tls_ca: Some(PathBuf::from("/host/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/host/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/host/tls.key")),
            ..AppleContainerComputeConfig::default()
        };

        assert_eq!(
            config.effective_grpc_endpoint(),
            "https://host.container.internal:17686"
        );
    }

    #[test]
    fn guest_tls_validation_rejects_partial_configuration() {
        let config = AppleContainerComputeConfig {
            guest_tls_ca: Some(PathBuf::from("/host/ca.crt")),
            ..AppleContainerComputeConfig::default()
        };

        let err = apple_guest_tls_paths(&config).unwrap_err();

        assert!(
            err.message()
                .contains("requires guest_tls_ca, guest_tls_cert, and guest_tls_key")
        );
    }

    #[test]
    fn guest_tls_validation_rejects_https_without_materials() {
        let config = AppleContainerComputeConfig {
            grpc_endpoint: "https://host.container.internal:17670".to_string(),
            ..AppleContainerComputeConfig::default()
        };

        let err = apple_guest_tls_paths(&config).unwrap_err();

        assert!(err.message().contains("when grpc_endpoint uses https://"));
    }

    #[test]
    fn sandbox_environment_preserves_driver_owned_values() {
        let mut spec_env = std::collections::HashMap::new();
        spec_env.insert(
            openshell_core::sandbox_env::ENDPOINT.to_string(),
            "http://attacker.invalid".to_string(),
        );
        spec_env.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE.to_string(),
            "/tmp/attacker-token".to_string(),
        );
        spec_env.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN.to_string(),
            "inline-secret".to_string(),
        );
        spec_env.insert(
            openshell_core::sandbox_env::TLS_CA.to_string(),
            "/tmp/user-ca.crt".to_string(),
        );
        spec_env.insert("VISIBLE".to_string(), "value".to_string());
        spec_env.insert(
            openshell_core::sandbox_env::USER_ENVIRONMENT.to_string(),
            "{\"ATTACK\":\"1\"}".to_string(),
        );
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                environment: spec_env,
                sandbox_token: "gateway-token".to_string(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let env = sandbox_environment(&sandbox, &AppleContainerComputeConfig::default());

        assert_eq!(
            env.get(openshell_core::sandbox_env::ENDPOINT)
                .map(String::as_str),
            Some("http://host.container.internal:17670")
        );
        assert_eq!(
            env.get(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE)
                .map(String::as_str),
            Some("/etc/openshell/auth/sandbox.jwt")
        );
        assert!(!env.contains_key(openshell_core::sandbox_env::SANDBOX_TOKEN));
        assert!(!env.contains_key(openshell_core::sandbox_env::TLS_CA));
        assert_eq!(env.get("VISIBLE").map(String::as_str), Some("value"));
        let user_env_json = env
            .get(openshell_core::sandbox_env::USER_ENVIRONMENT)
            .expect("user environment JSON should be set");
        let user_env: BTreeMap<String, String> = serde_json::from_str(user_env_json).unwrap();
        assert_eq!(user_env.get("VISIBLE").map(String::as_str), Some("value"));
        assert!(!user_env.contains_key(openshell_core::sandbox_env::ENDPOINT));
        assert!(!user_env.contains_key(openshell_core::sandbox_env::USER_ENVIRONMENT));
        assert!(!user_env.contains_key(openshell_core::sandbox_env::TLS_CA));
    }

    #[test]
    fn sandbox_environment_sets_tls_paths_when_configured() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec::default()),
            status: None,
        };
        let config = AppleContainerComputeConfig {
            guest_tls_ca: Some(PathBuf::from("/host/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/host/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/host/tls.key")),
            ..AppleContainerComputeConfig::default()
        };

        let env = sandbox_environment(&sandbox, &config);

        assert_eq!(
            env.get(openshell_core::sandbox_env::ENDPOINT)
                .map(String::as_str),
            Some("https://host.container.internal:17670")
        );
        assert_eq!(
            env.get(openshell_core::sandbox_env::TLS_CA)
                .map(String::as_str),
            Some(TLS_CA_MOUNT_PATH)
        );
        assert_eq!(
            env.get(openshell_core::sandbox_env::TLS_CERT)
                .map(String::as_str),
            Some(TLS_CERT_MOUNT_PATH)
        );
        assert_eq!(
            env.get(openshell_core::sandbox_env::TLS_KEY)
                .map(String::as_str),
            Some(TLS_KEY_MOUNT_PATH)
        );
    }

    #[test]
    fn require_sandbox_identifier_rejects_empty_target() {
        let err = require_sandbox_identifier("", "").unwrap_err();
        assert_eq!(err.message(), "sandbox_id or sandbox_name is required");
        assert!(require_sandbox_identifier("sbx-1", "").is_ok());
        assert!(require_sandbox_identifier("", "demo").is_ok());
    }

    #[tokio::test]
    async fn create_args_force_supervisor_to_run_as_root() {
        let tempdir = test_supervisor_dir("root-supervisor");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec::default()),
            status: None,
        };

        let args = driver.create_args(&sandbox).await.unwrap();

        assert_eq!(arg_value(&args, "--user"), Some("0:0"));
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[tokio::test]
    async fn create_args_merges_template_labels_with_managed_labels() {
        let tempdir = test_supervisor_dir("container-labels");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                sandbox_namespace: "team-a".to_string(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    labels: std::collections::HashMap::from([
                        ("custom.example/role".to_string(), "worker".to_string()),
                        (LABEL_SANDBOX_ID.to_string(), "spoofed".to_string()),
                    ]),
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let args = driver.create_args(&sandbox).await.unwrap();
        let labels = arg_values(&args, "--label");

        assert!(labels.contains(&"custom.example/role=worker"));
        assert!(labels.contains(&"openshell.ai/sandbox-id=sbx-1"));
        assert!(labels.contains(&"openshell.ai/sandbox-name=demo"));
        assert!(labels.contains(&"openshell.ai/sandbox-namespace=team-a"));
        assert!(!labels.contains(&"openshell.ai/sandbox-id=spoofed"));
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_owner_only_file_creates_token_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = test_supervisor_dir("owner-only-token");
        std::fs::create_dir_all(&tempdir).unwrap();
        let token = tempdir.join(SANDBOX_TOKEN_FILE);

        write_owner_only_file(&token, "secret-token").await.unwrap();

        let mode = std::fs::metadata(&token).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&token).unwrap(), "secret-token\n");

        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[tokio::test]
    async fn create_args_mounts_guest_tls_materials_without_sandbox_token() {
        let tempdir = test_supervisor_dir("tls-mounts");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let ca = tempdir.join("ca.crt");
        let cert = tempdir.join("tls.crt");
        let key = tempdir.join("tls.key");
        std::fs::write(&ca, b"ca").unwrap();
        std::fs::write(&cert, b"cert").unwrap();
        std::fs::write(&key, b"key").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                guest_tls_ca: Some(ca.clone()),
                guest_tls_cert: Some(cert.clone()),
                guest_tls_key: Some(key.clone()),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: None,
            status: None,
        };
        let secret_staging_base = tempdir.join("apple-container-secrets");

        let args = driver
            .create_args_with_secret_staging_base(&sandbox, Some(&secret_staging_base))
            .await
            .unwrap();

        let staged_tls_dir = secret_staging_dir_with_base(
            &sandbox.id,
            Some(&driver.config.sandbox_namespace),
            Some(&secret_staging_base),
        )
        .unwrap()
        .join("tls");
        assert!(args.contains(&crate::cli::readonly_bind_mount(
            &staged_tls_dir,
            TLS_DIR_MOUNT_PATH,
        )));
        assert_eq!(
            std::fs::read(staged_tls_dir.join(TLS_CA_FILE)).unwrap(),
            b"ca"
        );
        assert_eq!(
            std::fs::read(staged_tls_dir.join(TLS_CERT_FILE)).unwrap(),
            b"cert"
        );
        assert_eq!(
            std::fs::read(staged_tls_dir.join(TLS_KEY_FILE)).unwrap(),
            b"key"
        );
        assert!(args.contains(&format!(
            "{}={TLS_CA_MOUNT_PATH}",
            openshell_core::sandbox_env::TLS_CA
        )));
        assert!(args.contains(&format!(
            "{}={TLS_CERT_MOUNT_PATH}",
            openshell_core::sandbox_env::TLS_CERT
        )));
        assert!(args.contains(&format!(
            "{}={TLS_KEY_MOUNT_PATH}",
            openshell_core::sandbox_env::TLS_KEY
        )));
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[tokio::test]
    async fn create_args_overrides_image_cmd_with_supervisor_command() {
        let tempdir = test_supervisor_dir("supervisor-command");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                default_image: "example/image:latest".to_string(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec::default()),
            status: None,
        };

        let args = driver.create_args(&sandbox).await.unwrap();

        assert_eq!(
            args[args.len().saturating_sub(3)..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["example/image:latest", "sleep", "infinity"]
        );
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_create_accepts_sanitized_runtime_names() {
        let tempdir = test_supervisor_dir("validate-sanitized-name");
        std::fs::create_dir_all(&tempdir).unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo/name".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                sandbox_token: "token".to_string(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        driver.validate_sandbox_create(&sandbox).unwrap();
        assert_eq!(
            container_name_for_sandbox(&sandbox),
            "openshell-sandbox-demo-name-sbx-1"
        );
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_create_allows_missing_sandbox_token_for_preflight() {
        let tempdir = test_supervisor_dir("validate-auth-token");
        std::fs::create_dir_all(&tempdir).unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        driver.validate_sandbox_create(&sandbox).unwrap();
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_auth_rejects_missing_sandbox_token() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let err = validate_sandbox_auth(&sandbox).unwrap_err();

        assert_eq!(
            err.message(),
            "apple-container sandboxes require gateway JWT auth; configure [openshell.gateway.gateway_jwt]"
        );
    }

    #[test]
    fn validate_sandbox_create_rejects_missing_image_sources() {
        let tempdir = test_supervisor_dir("validate-image");
        std::fs::create_dir_all(&tempdir).unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                default_image: String::new(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let err = driver.validate_sandbox_create(&sandbox).unwrap_err();

        assert!(
            err.message()
                .contains("no sandbox image configured: set default_image")
        );
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_template_rejects_driver_config() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    driver_config: Some(prost_types::Struct {
                        fields: BTreeMap::from([(
                            "mounts".to_string(),
                            prost_types::Value {
                                kind: Some(prost_types::value::Kind::ListValue(
                                    prost_types::ListValue { values: Vec::new() },
                                )),
                            },
                        )]),
                    }),
                    ..DriverSandboxTemplate::default()
                }),
                sandbox_token: "token".to_string(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let err = validate_sandbox_template(&sandbox).unwrap_err();

        assert_eq!(
            err.message(),
            "apple-container compute driver does not support template.driver_config"
        );
    }

    #[test]
    fn watch_event_cache_applies_sandbox_and_delete_events() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: "default".to_string(),
            spec: None,
            status: None,
        };
        let mut cache = BTreeMap::new();

        apply_watch_event_to_cache(&mut cache, &watch_sandbox_event(sandbox.clone()));
        assert_eq!(cache.get("sbx-1"), Some(&sandbox));

        apply_watch_event_to_cache(&mut cache, &watch_deleted_event("sbx-1".to_string()));
        assert!(!cache.contains_key("sbx-1"));
    }

    #[test]
    fn managed_entry_requires_matching_namespace() {
        let config = AppleContainerComputeConfig {
            sandbox_namespace: "team-a".to_string(),
            ..AppleContainerComputeConfig::default()
        };
        let entry = list_entry("sbx-1", "demo", "team-a", "running");
        assert!(managed_entry(&entry, &config));

        let other = list_entry("sbx-1", "demo", "team-b", "running");
        assert!(!managed_entry(&other, &config));
    }

    #[test]
    fn entry_matches_accepts_id_or_name() {
        let entry = list_entry("sbx-1", "demo", "default", "running");
        assert!(entry_matches(&entry, "sbx-1", ""));
        assert!(entry_matches(&entry, "", "demo"));
        assert!(entry_matches(&entry, "sbx-1", "demo"));
        assert!(!entry_matches(&entry, "sbx-2", ""));
        assert!(!entry_matches(&entry, "", "other"));
    }

    #[test]
    fn driver_sandbox_uses_supervisor_readiness() {
        let waiting = driver_sandbox_from_entry(
            list_entry("sbx-1", "demo", "default", "running"),
            &NeverReady,
        )
        .unwrap();
        let waiting_condition = &waiting.status.unwrap().conditions[0];
        assert_eq!(waiting_condition.status, "False");
        assert_eq!(waiting_condition.reason, "DependenciesNotReady");

        let ready = driver_sandbox_from_entry(
            list_entry("sbx-1", "demo", "default", "running"),
            &AlwaysReady,
        )
        .unwrap();
        let ready_condition = &ready.status.unwrap().conditions[0];
        assert_eq!(ready_condition.status, "True");
        assert_eq!(ready_condition.reason, "SupervisorConnected");
    }

    fn list_entry(
        sandbox_id: &str,
        sandbox_name: &str,
        namespace: &str,
        state: &str,
    ) -> AppleContainerListEntry {
        let labels = BTreeMap::from([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_SANDBOX_ID.to_string(), sandbox_id.to_string()),
            (LABEL_SANDBOX_NAME.to_string(), sandbox_name.to_string()),
            (LABEL_SANDBOX_NAMESPACE.to_string(), namespace.to_string()),
        ]);
        AppleContainerListEntry {
            id: format!("runtime-{sandbox_id}"),
            configuration: AppleContainerConfiguration {
                creation_date: None,
                labels,
                image: Some(AppleContainerImage {
                    reference: "example:latest".to_string(),
                }),
            },
            status: AppleContainerStatus {
                state: state.to_string(),
            },
        }
    }

    fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.windows(2)
            .find(|window| window[0] == name)
            .map(|window| window[1].as_str())
    }

    fn arg_values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
        args.windows(2)
            .filter(|window| window[0] == name)
            .map(|window| window[1].as_str())
            .collect()
    }

    fn rfc3339_from_unix_ms(unix_ms: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
            .unwrap()
            .to_rfc3339()
    }
}
