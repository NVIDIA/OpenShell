// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI compute driver: orchestrates image pull, OCI spec generation,
//! networking, and direct low-level runtime invocation for each sandbox.
//!
//! # Who spawns the sandbox's process
//!
//! **This driver — not containerd — spawns the configured low-level OCI
//! runtime (`runc`/`crun`/...).** containerd is used only for image
//! pull/unpack and snapshot management, and only behind the
//! `openshell-rootfs` provider boundary
//! ([`openshell_rootfs::ContainerdRootfsProvider`], via containerd's
//! `Transfer`, `Images`, `Content`, `Snapshots`, and `Leases` services);
//! it never creates a containerd `Container` or `Task` object, and its
//! shim (`io.containerd.runc.v2`) is never involved. This driver sees
//! only provider-neutral [`openshell_rootfs::PreparedRootfs`] mounts.
//! `runtime.rs` builds a standard OCI bundle (`config.json` + a mounted
//! `rootfs/`) from those mounts and drives the configured runtime
//! directly through its `create`/`start`/`state`/`kill`/`delete` CLI
//! contract — the same integration pattern containerd's shim, CRI-O, and
//! Podman use internally, just invoked by this driver's own process
//! instead of containerd's.
//!
//! Because this driver never registers a containerd `Container`/`Task`,
//! the writable snapshot the provider prepares has nothing else
//! protecting it from containerd's background garbage collector. The
//! provider closes that gap internally: a containerd lease is created
//! alongside the snapshot and deleted by
//! [`openshell_rootfs::ContainerdRootfsProvider::release`] at sandbox
//! teardown.
//!
//! # What has been verified against a real system, and what has not
//!
//! Verified end to end during development against a real `containerd` 2.x
//! + `runc`/`crun` install on Linux (aarch64):
//! - Image pull + unpack via containerd's `Transfer` service, OCI chain-ID
//!   resolution, and writable snapshot `Prepare`.
//! - A snapshot with no containerd `Container`/`Task` referencing it *is*
//!   reaped by containerd's background GC within a sandbox's own
//!   lifetime; attaching it to a lease (`Leases.AddResource`) prevents
//!   that, confirmed by an otherwise-identical run without the lease
//!   failing at teardown with "snapshot ... does not exist".
//! - Mounting the prepared snapshot into a bundle directory ourselves,
//!   then `create` → `start` → `state` → `delete` against both `runc` and
//!   `crun` directly (not through containerd) — including confirming a
//!   bogus `runtime_binary` value surfaces a plain `fork/exec ...: no such
//!   file or directory` from the OS, not a containerd-side error, since
//!   containerd is no longer in this path at all.
//! - Joining a pre-created, driver-managed network namespace via the OCI
//!   spec's namespace `path` isolates the container to `lo` only.
//!
//! **Not yet verified in this initial cut** (called out here rather than
//! left implicit):
//! - GPU device passthrough (no GPU hardware in the development
//!   environment) — see `gpu.rs` for the scope limitation on CDI.
//! - SELinux-enforcing hosts.
//! - The supervisor binary bind-mount path end to end with a real
//!   `openshell-sandbox` binary (exercised structurally, not with the real
//!   supervisor).
//! - Sustained multi-sandbox concurrency / long-running soak behavior.
//! - `WatchSandboxes` is a polling loop (see below), not a push-based
//!   subscription to containerd's own event stream — functionally correct
//!   but higher-latency and more RPC-heavy than a real subscription would
//!   be. Tracked as follow-up.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use futures::Stream;
use openshell_core::ComputeDriverError;
use openshell_core::driver_utils::{
    SANDBOX_TOKEN_MOUNT_PATH, SUPERVISOR_CONTAINER_BINARY, build_capabilities_response,
    sandbox_log_level, sandbox_token_path,
};
use openshell_core::gpu::{CdiGpuDefaultSelector, effective_driver_gpu_count};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverSandbox, DriverSandboxStatus, GetCapabilitiesResponse,
};
use openshell_core::sandbox_env;
use openshell_rootfs::ContainerdRootfsProvider;
use tracing::warn;

use crate::config::OciComputeConfig;
use crate::gpu;
use crate::network::SandboxNetwork;
use crate::runtime::{self, RuntimeStatus};
use crate::spec::{ExtraMount, SpecInput, build_spec};

const DRIVER_NAME: &str = "oci";
/// Maximum length accepted for a sandbox name/ID used directly as a path
/// component (bundle directory) and as the low-level runtime's container
/// ID.
const MAX_SANDBOX_NAME_LEN: usize = 255;
/// Default CPU period for cgroup v2 `cpu.max` (100ms), matching the
/// Docker/Podman drivers' convention.
const DEFAULT_CPU_PERIOD_MICROS: u64 = 100_000;
const DEFAULT_CPU_QUOTA_MICROS: i64 = 200_000; // 2 cores
const DEFAULT_MEMORY_LIMIT_BYTES: i64 = 4 * 1024 * 1024 * 1024; // 4 GiB
const DEFAULT_PIDS_LIMIT: i64 = 4096;
/// Filename, inside a sandbox's bundle directory, holding the gateway's
/// stable sandbox ID. containerd container labels served this purpose in
/// an earlier revision of this driver; now that no containerd
/// `Container`/`Task` is created at all, this is the only place that
/// mapping is recorded.
const SANDBOX_ID_FILE: &str = "sandbox_id";
/// Filename, inside a sandbox's bundle directory, holding the sandbox's
/// workspace. Other drivers recover this from container/pod labels; this
/// driver has no equivalent runtime-side label store, so it persists the
/// value alongside [`SANDBOX_ID_FILE`] instead.
const SANDBOX_WORKSPACE_FILE: &str = "sandbox_workspace";

/// Map a rootfs-provider error into the compute-driver error space (an
/// `impl From` would violate the orphan rule: both types are foreign to
/// this crate).
fn rootfs_err(value: openshell_rootfs::RootfsError) -> ComputeDriverError {
    ComputeDriverError::Message(value.to_string())
}

impl From<crate::network::NetworkError> for ComputeDriverError {
    fn from(value: crate::network::NetworkError) -> Self {
        Self::Message(value.to_string())
    }
}

impl From<runtime::RuntimeError> for ComputeDriverError {
    fn from(value: runtime::RuntimeError) -> Self {
        Self::Message(value.to_string())
    }
}

#[derive(Clone)]
pub struct OciComputeDriver {
    config: OciComputeConfig,
    rootfs: ContainerdRootfsProvider,
    gpu_selector: std::sync::Arc<CdiGpuDefaultSelector>,
}

impl std::fmt::Debug for OciComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciComputeDriver")
            .field(
                "containerd_socket_path",
                &self.config.containerd_socket_path,
            )
            .field("containerd_namespace", &self.config.containerd_namespace)
            .field("runtime_binary", &self.config.runtime_binary)
            .finish()
    }
}

impl OciComputeDriver {
    /// Connect the rootfs provider to the system containerd (used for
    /// image pull/unpack and snapshot management only — see the module
    /// docs) and construct the driver.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid or the containerd
    /// socket cannot be reached.
    pub async fn new(config: OciComputeConfig) -> Result<Self, ComputeDriverError> {
        config
            .validate()
            .map_err(ComputeDriverError::InvalidArgument)?;
        let rootfs = ContainerdRootfsProvider::connect(
            &config.containerd_socket_path,
            config.containerd_namespace.clone(),
            config.snapshotter.clone(),
        )
        .await
        .map_err(rootfs_err)?;
        let inventory = gpu::local_cdi_gpu_inventory();
        let gpu_selector = std::sync::Arc::new(CdiGpuDefaultSelector::new(inventory, false));
        Ok(Self {
            config,
            rootfs,
            gpu_selector,
        })
    }

    /// Construct a driver around an already-built rootfs provider, without
    /// dialing containerd. Used by unit tests that only exercise request
    /// validation and never issue an RPC.
    #[cfg(test)]
    #[must_use]
    pub fn for_tests(config: OciComputeConfig, rootfs: ContainerdRootfsProvider) -> Self {
        let inventory = gpu::local_cdi_gpu_inventory();
        let gpu_selector = std::sync::Arc::new(CdiGpuDefaultSelector::new(inventory, false));
        Self {
            config,
            rootfs,
            gpu_selector,
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        build_capabilities_response(
            DRIVER_NAME,
            openshell_core::VERSION,
            self.config.default_image.clone(),
        )
    }

    /// Validate a sandbox request before any containerd calls are made.
    ///
    /// # Errors
    /// Returns [`ComputeDriverError::InvalidArgument`] when the request is
    /// structurally invalid, or [`ComputeDriverError::Precondition`] when it
    /// is well-formed but not satisfiable on this host (e.g. a GPU request
    /// with no discoverable devices).
    pub fn validate_sandbox_create(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<(), ComputeDriverError> {
        let image = resolve_image(sandbox, &self.config);
        if image.is_empty() {
            return Err(ComputeDriverError::InvalidArgument(
                "sandbox template has no image and no default_image is configured".to_string(),
            ));
        }
        let gpu = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|resources| resources.gpu.as_ref());
        if let Some(gpu) = gpu {
            let count = effective_driver_gpu_count(Some(gpu))
                .map_err(ComputeDriverError::InvalidArgument)?
                .unwrap_or(1);
            self.gpu_selector
                .peek_device_ids(count)
                .map_err(|err| ComputeDriverError::Precondition(err.to_string()))?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns [`ComputeDriverError::AlreadyExists`] if a bundle already
    /// exists for this sandbox name. Returns other errors if the rootfs
    /// provider or the low-level runtime invocation fails; on failure
    /// after resources have already been created, this best-effort tears
    /// down whatever was created before returning.
    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), ComputeDriverError> {
        validate_sandbox_name(&sandbox.name)?;
        let container_id = sandbox.name.clone();
        let image = resolve_image(sandbox, &self.config).to_string();
        let bundle_dir = runtime::bundle_dir(&self.config.state_dir, &container_id);

        if bundle_dir.exists() {
            return Err(ComputeDriverError::AlreadyExists);
        }

        // The provider owns every containerd-side resource (image pull,
        // snapshot, GC-protecting lease) and cleans up after itself when
        // preparation fails partway.
        let prepared = self
            .rootfs
            .prepare(&image, &container_id)
            .await
            .map_err(rootfs_err)?;

        let network = SandboxNetwork::allocate(
            &sandbox.id,
            &self.config.veth_subnet_base,
            &self.config.state_dir,
        )?;
        if let Err(err) = network.setup(self.config.gateway_port) {
            SandboxNetwork::release_slot(&sandbox.id, &self.config.state_dir);
            let _ = self.rootfs.release(&container_id).await;
            return Err(err.into());
        }

        let result = self.assemble_and_run_bundle(
            sandbox,
            &container_id,
            &bundle_dir,
            &network,
            prepared.root_mount(),
        );
        if let Err(err) = result {
            // Undo everything `assemble_and_run_bundle` may have partially
            // created, in the reverse order it was created: the rootfs
            // mount and bundle directory first (an error after
            // `mount_rootfs` would otherwise leave both behind, and a
            // still-mounted rootfs can then make the provider's snapshot
            // removal below fail, leaving a retry of `create_sandbox`
            // permanently stuck on `AlreadyExists`), then the network
            // namespace, then the provider's resources.
            runtime::unmount_rootfs(&bundle_dir);
            let _ = std::fs::remove_dir_all(&bundle_dir);
            let _ = network.teardown_best_effort();
            SandboxNetwork::release_slot(&sandbox.id, &self.config.state_dir);
            let _ = self.rootfs.release(&container_id).await;
            return Err(err);
        }

        Ok(())
    }

    fn assemble_and_run_bundle(
        &self,
        sandbox: &DriverSandbox,
        container_id: &str,
        bundle_dir: &std::path::Path,
        network: &SandboxNetwork,
        rootfs_mount: &openshell_rootfs::RootfsMount,
    ) -> Result<(), ComputeDriverError> {
        let resources = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .and_then(|template| template.resources.as_ref());
        let (cpu_quota, cpu_period) = resources.map_or(
            (Some(DEFAULT_CPU_QUOTA_MICROS), DEFAULT_CPU_PERIOD_MICROS),
            resource_cpu_quota,
        );
        let memory_limit = resources
            .and_then(resource_memory_limit)
            .or(Some(DEFAULT_MEMORY_LIMIT_BYTES));

        let gpu = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|resources| resources.gpu.as_ref());
        let mut extra_mounts = Vec::new();
        if let Some(binary_path) = &self.config.supervisor_binary_path {
            extra_mounts.push(ExtraMount {
                destination: SUPERVISOR_CONTAINER_BINARY.to_string(),
                source: binary_path.clone(),
                read_only: true,
            });
        }
        if let Some(gpu) = gpu {
            let count = effective_driver_gpu_count(Some(gpu))
                .map_err(ComputeDriverError::InvalidArgument)?
                .unwrap_or(1);
            let device_ids = self
                .gpu_selector
                .next_device_ids(count)
                .map_err(|err| ComputeDriverError::Precondition(err.to_string()))?;
            let device_paths = gpu::device_paths_for(&device_ids);
            for path in &device_paths {
                extra_mounts.push(ExtraMount {
                    destination: path.display().to_string(),
                    source: path.clone(),
                    read_only: false,
                });
            }
        }

        let token_mount = Self::write_sandbox_token(sandbox)?;
        if let Some(path) = &token_mount {
            extra_mounts.push(ExtraMount {
                destination: SANDBOX_TOKEN_MOUNT_PATH.to_string(),
                source: path.clone(),
                read_only: true,
            });
        }

        let spec = build_spec(SpecInput {
            config: &self.config,
            hostname: format!("sandbox-{}", sandbox.name),
            args: vec![SUPERVISOR_CONTAINER_BINARY.to_string()],
            env: build_env(sandbox, &self.config, container_id, network),
            netns_path: &network.netns_path,
            cpu_quota_micros: cpu_quota,
            cpu_period_micros: cpu_period,
            memory_limit_bytes: memory_limit,
            pids_limit: Some(DEFAULT_PIDS_LIMIT),
            extra_mounts,
            selinux_relabel_bind_mounts: is_selinux_enabled(),
        })
        .map_err(ComputeDriverError::Message)?;

        std::fs::create_dir_all(bundle_dir)
            .map_err(|err| ComputeDriverError::Message(format!("create bundle dir: {err}")))?;
        std::fs::write(bundle_dir.join(SANDBOX_ID_FILE), &sandbox.id)
            .map_err(|err| ComputeDriverError::Message(format!("write sandbox id: {err}")))?;
        std::fs::write(bundle_dir.join(SANDBOX_WORKSPACE_FILE), &sandbox.workspace).map_err(
            |err| ComputeDriverError::Message(format!("write sandbox workspace: {err}")),
        )?;
        runtime::mount_rootfs(bundle_dir, rootfs_mount)?;
        runtime::write_config(bundle_dir, &spec)?;
        let runtime_root = runtime::runtime_root(&self.config.state_dir);
        runtime::create(
            &self.config.runtime_binary,
            &runtime_root,
            bundle_dir,
            container_id,
        )?;

        if let Err(err) = runtime::start(&self.config.runtime_binary, &runtime_root, container_id) {
            let _ = runtime::delete(&self.config.runtime_binary, &runtime_root, container_id);
            return Err(err.into());
        }

        Ok(())
    }

    fn write_sandbox_token(sandbox: &DriverSandbox) -> Result<Option<PathBuf>, ComputeDriverError> {
        let Some(token) = sandbox
            .spec
            .as_ref()
            .map(|spec| spec.sandbox_token.trim())
            .filter(|token| !token.is_empty())
        else {
            return Ok(None);
        };
        let path = sandbox_token_path("oci-sandbox-tokens", None, &sandbox.id)
            .map_err(|err| ComputeDriverError::Message(err.to_string()))?;
        openshell_core::paths::ensure_parent_dir_restricted(&path)
            .map_err(|err| ComputeDriverError::Message(err.to_string()))?;
        std::fs::write(&path, format!("{token}\n"))
            .map_err(|err| ComputeDriverError::Message(err.to_string()))?;
        openshell_core::paths::set_file_owner_only(&path)
            .map_err(|err| ComputeDriverError::Message(err.to_string()))?;
        Ok(Some(path))
    }

    /// # Errors
    /// This does not perform any RPCs and does not currently fail; the
    /// `Result` return type matches the other drivers' `get_sandbox`
    /// signature for interchangeability. Returns `Ok(None)` if no bundle
    /// exists for this sandbox name.
    pub fn get_sandbox(
        &self,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, ComputeDriverError> {
        validate_sandbox_name(sandbox_name)?;
        let bundle_dir = runtime::bundle_dir(&self.config.state_dir, sandbox_name);
        if !bundle_dir.exists() {
            return Ok(None);
        }
        Ok(Some(
            self.driver_sandbox_from_bundle(sandbox_name, &bundle_dir),
        ))
    }

    /// # Errors
    /// This does not perform any RPCs and does not currently fail; the
    /// `Result` return type matches the other drivers' `list_sandboxes`
    /// signature for interchangeability.
    pub fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, ComputeDriverError> {
        let ids = runtime::list_sandbox_ids(&self.config.state_dir);
        Ok(ids
            .into_iter()
            .map(|id| {
                let bundle_dir = runtime::bundle_dir(&self.config.state_dir, &id);
                self.driver_sandbox_from_bundle(&id, &bundle_dir)
            })
            .collect())
    }

    fn driver_sandbox_from_bundle(
        &self,
        container_id: &str,
        bundle_dir: &std::path::Path,
    ) -> DriverSandbox {
        let sandbox_id = std::fs::read_to_string(bundle_dir.join(SANDBOX_ID_FILE))
            .unwrap_or_else(|_| container_id.to_string());
        let workspace =
            std::fs::read_to_string(bundle_dir.join(SANDBOX_WORKSPACE_FILE)).unwrap_or_default();
        let runtime_root = runtime::runtime_root(&self.config.state_dir);
        let state = runtime::state(&self.config.runtime_binary, &runtime_root, container_id).ok();
        let condition = condition_from_runtime_state(state.as_ref());

        DriverSandbox {
            id: sandbox_id,
            name: container_id.to_string(),
            namespace: String::new(),
            spec: None,
            status: Some(DriverSandboxStatus {
                sandbox_name: container_id.to_string(),
                instance_id: container_id.to_string(),
                agent_fd: String::new(),
                sandbox_fd: String::new(),
                conditions: vec![condition],
                deleting: false,
            }),
            workspace,
        }
    }

    /// # Errors
    /// This does not currently fail: an already-stopped or never-started
    /// sandbox is not an error, and the SIGKILL escalation is best-effort.
    pub async fn stop_sandbox(&self, sandbox_name: &str) -> Result<(), ComputeDriverError> {
        const SIGTERM: u32 = 15;
        const SIGKILL: u32 = 9;

        validate_sandbox_name(sandbox_name)?;
        let runtime_root = runtime::runtime_root(&self.config.state_dir);
        if runtime::kill(
            &self.config.runtime_binary,
            &runtime_root,
            sandbox_name,
            SIGTERM,
        )
        .is_err()
        {
            // Already stopped / never started — nothing to signal.
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(u64::from(
            self.config.stop_timeout_secs,
        )))
        .await;

        // Best-effort escalation; ignore errors (the process may have
        // already exited on its own after SIGTERM).
        let _ = runtime::kill(
            &self.config.runtime_binary,
            &runtime_root,
            sandbox_name,
            SIGKILL,
        );
        Ok(())
    }

    /// # Errors
    /// This does not currently fail: every teardown step is best-effort,
    /// matching the other drivers' teardown posture. Returns `Ok(false)`
    /// if no bundle existed for this sandbox name.
    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, ComputeDriverError> {
        validate_sandbox_name(sandbox_id)?;
        validate_sandbox_name(sandbox_name)?;
        let bundle_dir = runtime::bundle_dir(&self.config.state_dir, sandbox_name);
        let existed = bundle_dir.exists();
        let runtime_root = runtime::runtime_root(&self.config.state_dir);

        let _ = runtime::kill(&self.config.runtime_binary, &runtime_root, sandbox_name, 9);
        let _ = runtime::delete(&self.config.runtime_binary, &runtime_root, sandbox_name);
        runtime::unmount_rootfs(&bundle_dir);
        let _ = std::fs::remove_dir_all(&bundle_dir);

        let _ = self.rootfs.release(sandbox_name).await;

        let network = SandboxNetwork::plan(sandbox_id, &self.config.veth_subnet_base);
        let _ = network.teardown_best_effort();
        SandboxNetwork::release_slot(sandbox_id, &self.config.state_dir);

        Ok(existed)
    }

    /// Poll-based sandbox observation stream. See the module-level doc
    /// comment for why this is polling rather than a subscription to
    /// containerd's native event stream.
    ///
    /// # Errors
    /// This constructor itself does not perform any RPCs, so it does not
    /// currently fail; the `Result` return type matches the other drivers'
    /// `watch_sandboxes` signature for interchangeability.
    pub fn watch_sandboxes(&self) -> Result<WatchStream, ComputeDriverError> {
        use openshell_core::proto::compute::v1::{
            WatchSandboxesDeletedEvent, WatchSandboxesEvent, WatchSandboxesSandboxEvent,
            watch_sandboxes_event,
        };
        use tokio::sync::mpsc;
        use tokio_stream::wrappers::ReceiverStream;

        let (tx, rx) = mpsc::channel::<Result<WatchSandboxesEvent, ComputeDriverError>>(256);
        let driver = self.clone();
        tokio::spawn(async move {
            let mut known: BTreeMap<String, DriverSandbox> = BTreeMap::new();
            loop {
                match driver.list_sandboxes() {
                    Ok(current) => {
                        let mut seen = std::collections::BTreeSet::new();
                        for sandbox in current {
                            seen.insert(sandbox.id.clone());
                            let changed = known
                                .get(&sandbox.id)
                                .is_none_or(|previous| previous.status != sandbox.status);
                            if changed {
                                known.insert(sandbox.id.clone(), sandbox.clone());
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent {
                                            sandbox: Some(sandbox),
                                        },
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        let removed: Vec<String> = known
                            .keys()
                            .filter(|id| !seen.contains(*id))
                            .cloned()
                            .collect();
                        for id in removed {
                            known.remove(&id);
                            let event = WatchSandboxesEvent {
                                payload: Some(watch_sandboxes_event::Payload::Deleted(
                                    WatchSandboxesDeletedEvent { sandbox_id: id },
                                )),
                            };
                            if tx.send(Ok(event)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "oci driver watch poll failed");
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

pub type WatchStream = Pin<
    Box<
        dyn Stream<
                Item = Result<
                    openshell_core::proto::compute::v1::WatchSandboxesEvent,
                    ComputeDriverError,
                >,
            > + Send,
    >,
>;

/// Reject a sandbox name/ID that is unsafe to use directly as a path
/// component (bundle directory under `state_dir`) and as the low-level
/// runtime's container ID.
///
/// Without this, a name containing `/` or `..` could escape
/// `state_dir/bundles/` — e.g. `delete_sandbox`'s `remove_dir_all` would
/// then recursively delete whatever that path resolves to. Mirrors
/// `openshell-driver-podman`'s `validate_name`, which is tested against
/// the same class of input.
fn validate_sandbox_name(name: &str) -> Result<(), ComputeDriverError> {
    if name.is_empty() {
        return Err(ComputeDriverError::InvalidArgument(
            "sandbox name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_SANDBOX_NAME_LEN {
        return Err(ComputeDriverError::InvalidArgument(format!(
            "sandbox name exceeds maximum length of {MAX_SANDBOX_NAME_LEN} characters (got {})",
            name.len()
        )));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(ComputeDriverError::InvalidArgument(format!(
            "sandbox name must start with an alphanumeric character: {name:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(ComputeDriverError::InvalidArgument(format!(
            "sandbox name must only contain alphanumeric characters, '.', '_', or '-': {name:?}"
        )));
    }
    Ok(())
}

/// Resolve the OCI image reference for a sandbox, using the template image
/// if provided, otherwise the driver's default image.
#[must_use]
fn resolve_image<'a>(sandbox: &'a DriverSandbox, config: &'a OciComputeConfig) -> &'a str {
    sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.as_str())
        .filter(|image| !image.is_empty())
        .unwrap_or(&config.default_image)
}

fn resource_cpu_quota(
    resources: &openshell_core::proto::compute::v1::DriverResourceRequirements,
) -> (Option<i64>, u64) {
    let quota = if resources.cpu_limit.is_empty() {
        Some(DEFAULT_CPU_QUOTA_MICROS)
    } else {
        parse_cpu_to_quota_micros(&resources.cpu_limit)
    };
    (quota, DEFAULT_CPU_PERIOD_MICROS)
}

fn resource_memory_limit(
    resources: &openshell_core::proto::compute::v1::DriverResourceRequirements,
) -> Option<i64> {
    if resources.memory_limit.is_empty() {
        return None;
    }
    parse_memory_to_bytes(&resources.memory_limit).and_then(|bytes| i64::try_from(bytes).ok())
}

/// Parse a Kubernetes-style CPU quantity to cgroup quota microseconds for a
/// 100ms period, mirroring `openshell-driver-podman`'s
/// `parse_cpu_to_microseconds` (kept as a separate copy here since the two
/// crates do not currently share a resource-quantity-parsing crate — see
/// the plan's Risks section for this as a follow-up dedup opportunity).
fn parse_cpu_to_quota_micros(quantity: &str) -> Option<i64> {
    let micros: u64 = if let Some(millis_str) = quantity.strip_suffix('m') {
        let millis: u64 = millis_str.parse().ok()?;
        millis.checked_mul(100)?
    } else {
        let cores: f64 = quantity.parse().ok()?;
        if cores <= 0.0 || !cores.is_finite() {
            return None;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let val = (cores * 100_000.0) as u64;
        val
    };
    if micros == 0 {
        None
    } else {
        i64::try_from(micros).ok()
    }
}

fn parse_memory_to_bytes(quantity: &str) -> Option<u64> {
    let suffixes: &[(&str, u64)] = &[
        ("Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024),
        ("Pi", 1024 * 1024 * 1024 * 1024 * 1024),
        ("Ti", 1024 * 1024 * 1024 * 1024),
        ("Gi", 1024 * 1024 * 1024),
        ("Mi", 1024 * 1024),
        ("Ki", 1024),
        ("E", 1_000_000_000_000_000_000),
        ("P", 1_000_000_000_000_000),
        ("T", 1_000_000_000_000),
        ("G", 1_000_000_000),
        ("M", 1_000_000),
        ("K", 1_000),
        ("k", 1_000),
    ];
    for (suffix, multiplier) in suffixes {
        if let Some(num_str) = quantity.strip_suffix(suffix) {
            let num: u64 = num_str.parse().ok()?;
            return num.checked_mul(*multiplier);
        }
    }
    quantity.parse().ok()
}

fn build_env(
    sandbox: &DriverSandbox,
    config: &OciComputeConfig,
    container_id: &str,
    network: &SandboxNetwork,
) -> Vec<String> {
    let spec = sandbox.spec.as_ref();
    let template = spec.and_then(|s| s.template.as_ref());

    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut user_env: BTreeMap<String, String> = BTreeMap::new();
    if let Some(t) = template {
        for (k, v) in &t.environment {
            user_env.insert(k.clone(), v.clone());
        }
    }
    if let Some(s) = spec {
        for (k, v) in &s.environment {
            user_env.insert(k.clone(), v.clone());
        }
    }
    env.extend(user_env.clone());
    if !user_env.is_empty()
        && let Ok(json) = serde_json::to_string(&user_env)
    {
        env.insert(sandbox_env::USER_ENVIRONMENT.into(), json);
    }

    env.insert(sandbox_env::SANDBOX.into(), sandbox.name.clone());
    env.insert(sandbox_env::SANDBOX_ID.into(), sandbox.id.clone());
    env.insert(
        sandbox_env::ENDPOINT.into(),
        endpoint_reachable_from_sandbox(&config.grpc_endpoint, network.host_ip()),
    );
    env.insert(
        sandbox_env::SSH_SOCKET_PATH.into(),
        config.sandbox_ssh_socket_path.clone(),
    );
    env.insert(
        sandbox_env::LOG_LEVEL.into(),
        sandbox_log_level(sandbox, "info"),
    );
    env.insert("OPENSHELL_CONTAINER_IMAGE".into(), container_id.to_string());

    env.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// Rewrite a loopback host in `endpoint` to `host_ip`.
///
/// The sandbox runs inside its own network namespace (see `network.rs`),
/// joined to the host only via a veth pair — its `lo` is not the host's
/// loopback. `grpc_endpoint`'s default value (and, if left unchanged, a
/// user-supplied override) point at `127.0.0.1`/`localhost`, which
/// resolves inside the sandbox's own namespace and can never reach the
/// gateway; only `host_ip` (the veth peer address on the host side of
/// *this* sandbox's namespace) is reachable from inside it.
fn endpoint_reachable_from_sandbox(endpoint: &str, host_ip: &str) -> String {
    endpoint
        .replace("127.0.0.1", host_ip)
        .replace("localhost", host_ip)
}

fn condition_from_runtime_state(state: Option<&runtime::RuntimeState>) -> DriverCondition {
    let Some(state) = state else {
        return DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "TaskNotFound".to_string(),
            message: String::new(),
            last_transition_time: String::new(),
        };
    };
    let (status_str, reason) = match state.status {
        RuntimeStatus::Running => ("True", "TaskRunning"),
        RuntimeStatus::Creating | RuntimeStatus::Created => ("False", "TaskCreated"),
        RuntimeStatus::Stopped => ("False", "TaskStopped"),
        RuntimeStatus::Paused => ("False", "TaskPaused"),
        RuntimeStatus::Unknown => ("Unknown", "TaskStatusUnknown"),
    };
    DriverCondition {
        r#type: "Ready".to_string(),
        status: status_str.to_string(),
        reason: reason.to_string(),
        message: String::new(),
        last_transition_time: String::new(),
    }
}

fn is_selinux_enabled() -> bool {
    std::path::Path::new("/sys/fs/selinux").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::compute::v1::{
        DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
    };

    fn test_sandbox(id: &str, name: &str) -> DriverSandbox {
        DriverSandbox {
            id: id.to_string(),
            name: name.to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec::default()),
            status: None,
            workspace: String::new(),
        }
    }

    #[test]
    fn resolve_image_prefers_template_image() {
        let config = OciComputeConfig {
            default_image: "default:latest".to_string(),
            ..OciComputeConfig::default()
        };
        let mut sandbox = test_sandbox("id", "name");
        sandbox.spec.as_mut().unwrap().template = Some(DriverSandboxTemplate {
            image: "custom:1.0".to_string(),
            ..Default::default()
        });
        assert_eq!(resolve_image(&sandbox, &config), "custom:1.0");
    }

    #[test]
    fn resolve_image_falls_back_to_default() {
        let config = OciComputeConfig {
            default_image: "default:latest".to_string(),
            ..OciComputeConfig::default()
        };
        let sandbox = test_sandbox("id", "name");
        assert_eq!(resolve_image(&sandbox, &config), "default:latest");
    }

    #[test]
    fn parse_cpu_millicore() {
        assert_eq!(parse_cpu_to_quota_micros("500m"), Some(50_000));
        assert_eq!(parse_cpu_to_quota_micros("2"), Some(200_000));
    }

    #[test]
    fn parse_memory_binary_suffix() {
        assert_eq!(parse_memory_to_bytes("256Mi"), Some(256 * 1024 * 1024));
    }

    #[test]
    fn resource_cpu_quota_defaults_when_unset() {
        let resources = DriverResourceRequirements::default();
        assert_eq!(
            resource_cpu_quota(&resources),
            (Some(DEFAULT_CPU_QUOTA_MICROS), DEFAULT_CPU_PERIOD_MICROS)
        );
    }

    #[test]
    fn build_env_sets_required_vars_and_cannot_be_overridden() {
        let config = OciComputeConfig {
            grpc_endpoint: "http://127.0.0.1:17670".to_string(),
            ..OciComputeConfig::default()
        };
        let mut sandbox = test_sandbox("sandbox-id", "sandbox-name");
        sandbox
            .spec
            .as_mut()
            .unwrap()
            .environment
            .insert(sandbox_env::SANDBOX_ID.to_string(), "spoofed".to_string());

        let network = SandboxNetwork::plan("sandbox-id", &config.veth_subnet_base);
        let env = build_env(&sandbox, &config, "sandbox-name", &network);
        let endpoint_line = env
            .iter()
            .find(|line| line.starts_with(&format!("{}=", sandbox_env::SANDBOX_ID)))
            .expect("sandbox id var present");
        assert_eq!(
            endpoint_line,
            &format!("{}=sandbox-id", sandbox_env::SANDBOX_ID)
        );
    }

    #[test]
    fn build_env_rewrites_loopback_endpoint_to_the_sandbox_reachable_host_ip() {
        let config = OciComputeConfig {
            grpc_endpoint: "http://127.0.0.1:17670".to_string(),
            ..OciComputeConfig::default()
        };
        let sandbox = test_sandbox("sandbox-id", "sandbox-name");
        let network = SandboxNetwork::plan("sandbox-id", &config.veth_subnet_base);

        let env = build_env(&sandbox, &config, "sandbox-name", &network);
        let endpoint_line = env
            .iter()
            .find(|line| line.starts_with(&format!("{}=", sandbox_env::ENDPOINT)))
            .expect("endpoint var present");
        assert!(
            !endpoint_line.contains("127.0.0.1"),
            "endpoint must not point at loopback, which is unreachable from \
             the sandbox's own network namespace: {endpoint_line}"
        );
        assert!(endpoint_line.contains(network.host_ip()));
    }

    #[test]
    fn endpoint_reachable_from_sandbox_rewrites_loopback_forms() {
        assert_eq!(
            endpoint_reachable_from_sandbox("http://127.0.0.1:17670", "10.0.132.1"),
            "http://10.0.132.1:17670"
        );
        assert_eq!(
            endpoint_reachable_from_sandbox("https://localhost:443", "10.0.132.1"),
            "https://10.0.132.1:443"
        );
        assert_eq!(
            endpoint_reachable_from_sandbox("https://gateway.example.com:443", "10.0.132.1"),
            "https://gateway.example.com:443"
        );
    }

    #[test]
    fn validate_sandbox_name_rejects_path_traversal() {
        assert!(validate_sandbox_name("../etc").is_err());
        assert!(validate_sandbox_name("has/slash").is_err());
        assert!(validate_sandbox_name("").is_err());
    }

    #[test]
    fn validate_sandbox_name_accepts_normal_names() {
        assert!(validate_sandbox_name("my-sandbox_1.v2").is_ok());
    }

    #[test]
    fn condition_from_missing_runtime_state_is_not_ready() {
        let condition = condition_from_runtime_state(None);
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "TaskNotFound");
    }

    #[test]
    fn condition_from_running_state_is_ready() {
        let condition = condition_from_runtime_state(Some(&runtime::RuntimeState {
            status: RuntimeStatus::Running,
            pid: 123,
        }));
        assert_eq!(condition.status, "True");
        assert_eq!(condition.reason, "TaskRunning");
    }
}
