// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::gpu::{
    GpuInventory, SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name,
};
use crate::lifecycle::{
    BackendFeature, GuestInitDropin, LaunchAbortReason, LaunchPlan, LifecycleExtensionRegistry,
    RestoreContext, extension_state_dir,
};
use crate::rootfs::{
    clone_or_copy_sparse_file, create_ext4_image_from_dir_with_size, create_rootfs_image_from_dir,
    extract_rootfs_archive_to, prepare_sandbox_rootfs_from_image_root, sandbox_guest_init_path,
    set_rootfs_image_file_mode, write_rootfs_image_file,
};
use crate::runtime::VmBackend;
use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder};
use flate2::read::GzDecoder;
use futures::{Stream, StreamExt, TryStreamExt};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use oci_client::client::{Client as OciClient, ClientConfig};
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::manifest::{
    ImageIndexEntry, OCI_IMAGE_MEDIA_TYPE, OciDescriptor, OciImageManifest,
};
use oci_client::secrets::RegistryAuth;
use oci_client::{Reference, RegistryOperation};
use openshell_core::gpu::{
    driver_gpu_requirements, effective_driver_gpu_count, validate_specific_gpu_device_request,
};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    format_bytes, mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DeleteWorkspaceRequest, DeleteWorkspaceResponse, DriverCondition as SandboxCondition,
    DriverPlatformEvent as PlatformEvent, DriverSandbox as Sandbox,
    DriverSandboxStatus as SandboxStatus, DriverSandboxTemplate as SandboxTemplate,
    EnsureWorkspaceRequest, EnsureWorkspaceResponse, GetCapabilitiesRequest,
    GetCapabilitiesResponse, GetGatewayListenerRequirementsRequest,
    GetGatewayListenerRequirementsResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest, StartSandboxResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, watch_sandboxes_event,
};
use openshell_core::proto_struct::{
    deserialize_optional_non_empty_string_list, struct_to_json_value,
};
use openshell_vfio::SysfsRoot;
use opentelemetry::trace::TraceContextExt as _;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{Instrument as _, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use url::{Host, Url};

const DRIVER_NAME: &str = "openshell-driver-vm";
const WATCH_BUFFER: usize = 256;
const DEFAULT_VCPUS: u8 = 2;
const DEFAULT_MEM_MIB: u32 = 2048;
const DEFAULT_OVERLAY_DISK_MIB: u64 = 4096;
const DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY: usize = 4;
const MAX_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY: usize = 16;
const REGISTRY_REQUEST_MAX_ATTEMPTS: usize = 4;
const REGISTRY_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);
const REGISTRY_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmSandboxDriverConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_empty_string_list"
    )]
    gpu_device_ids: Option<Vec<String>>,
}

impl VmSandboxDriverConfig {
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

        serde_json::from_value(struct_to_json_value(config))
            .map_err(|err| format!("invalid vm driver_config: {err}"))
    }
}

/// gvproxy host-loopback IP — gvproxy's TCP/UDP/ICMP forwarder NAT-rewrites
/// this destination to the host's `127.0.0.1` and dials out from the host
/// process. This is the only address that transparently reaches host-bound
/// services without explicit `expose` rules.
///
/// See gvisor-tap-vsock `cmd/gvproxy/config.go` (default NAT entry
/// `HostIP -> 127.0.0.1`) and `pkg/services/forwarder/tcp.go` (NAT lookup
/// before `net.Dial`).
///
/// Code paths route via `GVPROXY_HOST_LOOPBACK_ALIAS` (DNS / /etc/hosts)
/// instead so logs stay readable; this constant is kept for documentation
/// and parity with the guest init script.
#[allow(dead_code)] // Documentation/parity anchor; all routing goes via the alias.
const GVPROXY_HOST_LOOPBACK_IP: &str = "192.168.127.254";
const OPENSHELL_HOST_GATEWAY_ALIAS: &str = "host.openshell.internal";
/// Hostname gvproxy resolves (via its embedded DNS) to the host-loopback IP.
///
/// We rewrite loopback URLs to this hostname rather than the bare IP because:
///   * the guest init script seeds /etc/hosts with the same mapping, so it
///     resolves even when gvproxy's DNS is not in resolv.conf;
///   * keeping a recognisable hostname makes log messages clearer than a bare
///     192.168.127.254 reference;
///   * package-managed gateway certificates include this SAN for guest mTLS.
///
/// Both names ultimately route through the gvproxy NAT path on
/// `GVPROXY_HOST_LOOPBACK_IP` — they do **not** go through the gateway IP.
const GVPROXY_HOST_LOOPBACK_ALIAS: &str = OPENSHELL_HOST_GATEWAY_ALIAS;
const GUEST_SSH_SOCKET_PATH: &str = openshell_core::container_paths::SSH_SOCKET_PATH;
const GUEST_TLS_CA_PATH: &str = openshell_core::container_paths::VM_GUEST_TLS_CA_PATH;
const GUEST_TLS_CERT_PATH: &str = openshell_core::container_paths::VM_GUEST_TLS_CERT_PATH;
const GUEST_TLS_KEY_PATH: &str = openshell_core::container_paths::VM_GUEST_TLS_KEY_PATH;
const GUEST_SANDBOX_TOKEN_PATH: &str = openshell_core::container_paths::VM_GUEST_SANDBOX_TOKEN_PATH;
const GUEST_INIT_DROPIN_DIR: &str = openshell_core::container_paths::VM_GUEST_INIT_DROPIN_DIR;
/// Guest path of the driver-authored manifest enumerating which
/// `init.d` drop-ins the guest init script is allowed to execute.
///
/// The guest runs *only* the entries listed here (fail-closed): anything
/// else found under `init.d` — e.g. files baked into a user-controlled
/// guest image — is ignored. The driver writes this file into the overlay
/// upperdir on every launch, so the image cannot forge or shadow it.
const GUEST_INIT_DROPIN_MANIFEST: &str =
    openshell_core::container_paths::VM_GUEST_INIT_DROPIN_MANIFEST;
/// Guest path of the root-only corporate proxy credential staged by the driver.
const GUEST_UPSTREAM_PROXY_AUTH_PATH: &str =
    openshell_core::container_paths::VM_GUEST_UPSTREAM_PROXY_AUTH_PATH;
/// Guest path of the corporate proxy CA bundle staged by the driver.
const GUEST_PROXY_CA_PATH: &str = openshell_core::container_paths::VM_GUEST_PROXY_CA_PATH;
/// Guest path of the driver-authored supervisor argument list.
///
/// The counterpart of [`GUEST_INIT_DROPIN_MANIFEST`] for the supervisor's own
/// command line: written into the overlay upperdir on every launch (empty
/// when there is nothing to pass) so the guest appends exactly the arguments
/// the driver chose and a sandbox image cannot forge or shadow them.
const GUEST_SUPERVISOR_ARGS_PATH: &str =
    openshell_core::container_paths::VM_GUEST_SUPERVISOR_ARGS_PATH;
const IMAGE_CACHE_ROOT_DIR: &str = "images";
const IMAGE_CACHE_ROOTFS_IMAGE: &str = "rootfs.ext4";
const OVERLAY_TEMPLATE_CACHE_DIR: &str = "overlay-templates";
const OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION: &str = "sandbox-overlay-ext4-v1";
const SANDBOX_OVERLAY_IMAGE: &str = "overlay.ext4";
const SANDBOX_REQUEST_FILE: &str = "sandbox.pb";
const SANDBOX_STOPPED_FILE: &str = "stopped";
/// Durable tombstone preventing driver restart from relaunching a sandbox
/// whose canonical main process already terminated.
const MAIN_PROCESS_EXITED_FILE: &str = "main-process-exited";
const GUEST_IMAGE_CONFIG_DIR: &str = "openshell-image";
const GUEST_IMAGE_OCI_LAYOUT_DIR: &str = "oci";
const GUEST_IMAGE_OCI_REF: &str = "openshell";
const IMAGE_EXPORT_ROOTFS_ARCHIVE: &str = "source-rootfs.tar";
const BOOTSTRAP_IMAGE_CACHE_LAYOUT_VERSION: &str = "sandbox-bootstrap-rootfs-ext4-v3";
const PREPARED_IMAGE_CACHE_LAYOUT_VERSION: &str = "sandbox-prepared-rootfs-ext4-umoci-v3";
const IMAGE_IDENTITY_FILE: &str = "image-identity";
const IMAGE_REFERENCE_FILE: &str = "image-reference";
const IMAGE_PREP_INIT_MODE: &str = "image-prep";
static IMAGE_CACHE_BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct VmDriverTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Debug, Clone)]
struct RuntimeImagePlan {
    root_disk: PathBuf,
    image_disk: Option<PathBuf>,
    image_identity: String,
    bootstrap_image_identity: String,
}

#[derive(Debug, Clone)]
struct PreparedImageDisk {
    image_identity: String,
    disk_path: PathBuf,
}

#[derive(Debug, Clone)]
struct GuestImagePayload {
    image_ref: String,
    image_identity: String,
    source: GuestImagePayloadSource,
}

#[derive(Debug, Clone)]
enum GuestImagePayloadSource {
    RegistryOciLayout { layout_dir: PathBuf },
    LocalDocker { rootfs_archive: PathBuf },
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct VmDriverConfig {
    pub openshell_endpoint: String,
    pub state_dir: PathBuf,
    pub launcher_bin: Option<PathBuf>,
    pub default_image: String,
    pub bootstrap_image: String,
    pub log_level: String,
    pub krun_log_level: u32,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub overlay_disk_mib: u64,
    pub guest_tls_ca: Option<PathBuf>,
    pub guest_tls_cert: Option<PathBuf>,
    pub guest_tls_key: Option<PathBuf>,
    pub gpu_enabled: bool,
    pub gpu_mem_mib: u32,
    pub gpu_vcpus: u8,
    /// Resolved sandbox UID for rootfs `/etc/passwd` entry.
    /// When empty, defaults to 10001 (the legacy hardcoded value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_uid: Option<u32>,
    /// Resolved sandbox GID for rootfs `/etc/passwd` and `/etc/group` entries.
    /// When empty, defaults to the resolved UID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_gid: Option<u32>,

    /// Corporate forward proxy URL (`http://host:port` or `https://host:port`)
    /// passed to the in-guest supervisor.
    ///
    /// The supervisor chains policy-approved TLS tunnels through this proxy
    /// with HTTP CONNECT instead of dialing destinations directly. This is an
    /// operator-owned egress boundary: it travels on the supervisor's argv,
    /// which sandbox spec/template environment and image `ENV` cannot
    /// influence. A proxy on the gateway host's loopback is reachable from the
    /// guest only through the gvproxy host alias
    /// (`host.openshell.internal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_proxy: Option<String>,

    /// Comma-separated `NO_PROXY` list passed alongside the proxy URL.
    ///
    /// Matching destinations are dialed directly instead of through the
    /// corporate proxy. This bypasses only the corporate proxy, never
    /// `OpenShell` policy evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,

    /// Path (on the gateway host) to a file containing the corporate proxy
    /// credential in `user:pass` form.
    ///
    /// The driver validates it at sandbox-create time and stages it into the
    /// per-sandbox overlay at [`GUEST_UPSTREAM_PROXY_AUTH_PATH`], root-only.
    /// Credentials are never embedded in the proxy URL and never reach the
    /// guest environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_auth_file: Option<String>,

    /// Explicit acknowledgement that proxy credentials are sent in cleartext.
    ///
    /// `Proxy-Authorization: Basic` over the plain-TCP connection to an
    /// `http://` proxy is recoverable by anyone on the network path, so
    /// [`Self::proxy_auth_file`] requires this acknowledgement. An `https://`
    /// proxy carries the credential inside the verified TLS session and does
    /// not need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_auth_allow_insecure: Option<bool>,

    /// Send the destination hostname in CONNECT requests instead of a
    /// validated IP.
    ///
    /// The default binds the tunnel to an address that passed the sandbox's
    /// SSRF and `allowed_ips` validation. Set this only when the proxy's ACLs
    /// filter on hostnames and reject IP CONNECT targets: the proxy then
    /// resolves the name itself and its own ACLs become the effective egress
    /// control for proxied TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_connect_by_hostname: Option<bool>,

    /// Path (on the gateway host) to a PEM CA bundle trusted for the
    /// corporate proxy.
    ///
    /// The driver stages it into the per-sandbox overlay at
    /// [`GUEST_PROXY_CA_PATH`] and passes that path via
    /// `--upstream-proxy-ca-bundle`. It is trusted both for the handshake
    /// with an `https://` proxy and for server certificates re-signed by a
    /// TLS-intercepting proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_ca_bundle: Option<String>,
}

/// Redacting `Debug` so a proxy URL or credential path never reaches a log.
///
/// A validated proxy URL cannot embed credentials, but `Debug` can be emitted
/// before validation runs, so presence is logged rather than the value.
impl std::fmt::Debug for VmDriverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmDriverConfig")
            .field("openshell_endpoint", &self.openshell_endpoint)
            .field("state_dir", &self.state_dir)
            .field("launcher_bin", &self.launcher_bin)
            .field("default_image", &self.default_image)
            .field("bootstrap_image", &self.bootstrap_image)
            .field("log_level", &self.log_level)
            .field("krun_log_level", &self.krun_log_level)
            .field("vcpus", &self.vcpus)
            .field("mem_mib", &self.mem_mib)
            .field("overlay_disk_mib", &self.overlay_disk_mib)
            .field("guest_tls_ca", &self.guest_tls_ca)
            .field("guest_tls_cert", &self.guest_tls_cert)
            .field("guest_tls_key", &self.guest_tls_key)
            .field("gpu_enabled", &self.gpu_enabled)
            .field("gpu_mem_mib", &self.gpu_mem_mib)
            .field("gpu_vcpus", &self.gpu_vcpus)
            .field("sandbox_uid", &self.sandbox_uid)
            .field("sandbox_gid", &self.sandbox_gid)
            .field("https_proxy", &self.https_proxy.is_some())
            .field("no_proxy", &self.no_proxy)
            .field("proxy_auth_file", &self.proxy_auth_file.is_some())
            .field("proxy_auth_allow_insecure", &self.proxy_auth_allow_insecure)
            .field("proxy_connect_by_hostname", &self.proxy_connect_by_hostname)
            .field("proxy_ca_bundle", &self.proxy_ca_bundle)
            .finish()
    }
}

/// Default sandbox UID used by the VM driver when no config value is set.
pub const DEFAULT_SANDBOX_UID: u32 = 10001;

impl Default for VmDriverConfig {
    fn default() -> Self {
        Self {
            openshell_endpoint: String::new(),
            state_dir: PathBuf::from("target/openshell-vm-driver"),
            launcher_bin: None,
            default_image: String::new(),
            bootstrap_image: String::new(),
            log_level: "info".to_string(),
            krun_log_level: 1,
            vcpus: DEFAULT_VCPUS,
            mem_mib: DEFAULT_MEM_MIB,
            overlay_disk_mib: DEFAULT_OVERLAY_DISK_MIB,
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            gpu_enabled: false,
            gpu_mem_mib: 8192,
            gpu_vcpus: 4,
            sandbox_uid: None,
            sandbox_gid: None,
            https_proxy: None,
            no_proxy: None,
            proxy_auth_file: None,
            proxy_auth_allow_insecure: None,
            proxy_connect_by_hostname: None,
            proxy_ca_bundle: None,
        }
    }
}

impl VmDriverConfig {
    /// Resolve the sandbox UID, falling back to `DEFAULT_SANDBOX_UID`.
    pub fn resolve_sandbox_uid(&self) -> u32 {
        self.sandbox_uid.unwrap_or(DEFAULT_SANDBOX_UID)
    }

    /// Resolve the sandbox GID, falling back to the resolved UID.
    pub fn resolve_sandbox_gid(&self, resolved_uid: u32) -> u32 {
        self.sandbox_gid.unwrap_or(resolved_uid)
    }

    pub fn validate_sandbox_identity(&self) -> Result<(), String> {
        let range = openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID;
        if let Some(uid) = self.sandbox_uid
            && !range.contains(&uid)
        {
            return Err(format!(
                "sandbox_uid {uid} is outside the allowed range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        if let Some(gid) = self.sandbox_gid
            && !range.contains(&gid)
        {
            return Err(format!(
                "sandbox_gid {gid} is outside the allowed range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        Ok(())
    }

    /// Validate the operator's corporate upstream-proxy settings, fail-closed.
    ///
    /// Delegates to the validator shared with the Podman and Kubernetes
    /// drivers and with the in-guest supervisor, so a value accepted here is
    /// never rejected inside the guest — and no misconfiguration can silently
    /// degrade to a direct dial.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending key.
    pub fn validate_proxy_config(&self) -> Result<(), String> {
        openshell_core::driver_utils::validate_upstream_proxy_settings(
            &openshell_core::driver_utils::UpstreamProxySettings {
                url: self.https_proxy.as_deref(),
                no_proxy: self.no_proxy.as_deref(),
                auth_file: self.proxy_auth_file.as_deref(),
                auth_allow_insecure: self.proxy_auth_allow_insecure,
                connect_by_hostname: self.proxy_connect_by_hostname,
                ca_bundle: self.proxy_ca_bundle.as_deref(),
            },
        )
    }

    fn requires_tls_materials(&self) -> bool {
        self.openshell_endpoint.starts_with("https://")
    }

    fn tls_paths(&self) -> Result<Option<VmDriverTlsPaths>, String> {
        let provided = [
            self.guest_tls_ca.as_ref(),
            self.guest_tls_cert.as_ref(),
            self.guest_tls_key.as_ref(),
        ];
        if provided.iter().all(Option::is_none) {
            return if self.requires_tls_materials() {
                Err(
                    "https:// openshell endpoint requires OPENSHELL_VM_TLS_CA, OPENSHELL_VM_TLS_CERT, and OPENSHELL_VM_TLS_KEY so sandbox VMs can authenticate to the gateway"
                        .to_string(),
                )
            } else {
                Ok(None)
            };
        }

        let Some(ca) = self.guest_tls_ca.clone() else {
            return Err(
                "OPENSHELL_VM_TLS_CA is required when TLS materials are configured".to_string(),
            );
        };
        let Some(cert) = self.guest_tls_cert.clone() else {
            return Err(
                "OPENSHELL_VM_TLS_CERT is required when TLS materials are configured".to_string(),
            );
        };
        let Some(key) = self.guest_tls_key.clone() else {
            return Err(
                "OPENSHELL_VM_TLS_KEY is required when TLS materials are configured".to_string(),
            );
        };

        for path in [&ca, &cert, &key] {
            if !path.is_file() {
                return Err(format!(
                    "TLS material '{}' does not exist or is not a file",
                    path.display()
                ));
            }
        }

        Ok(Some(VmDriverTlsPaths { ca, cert, key }))
    }
}

fn validate_openshell_endpoint(endpoint: &str) -> Result<(), String> {
    let url = Url::parse(endpoint)
        .map_err(|err| format!("invalid openshell endpoint '{endpoint}': {err}"))?;
    let Some(host) = url.host() else {
        return Err(format!("openshell endpoint '{endpoint}' is missing a host"));
    };

    let invalid_from_vm = match host {
        Host::Domain(_) => false,
        Host::Ipv4(ip) => ip.is_unspecified(),
        Host::Ipv6(ip) => ip.is_unspecified(),
    };

    if invalid_from_vm {
        return Err(format!(
            "openshell endpoint '{endpoint}' is not reachable from sandbox VMs; use a concrete host such as 127.0.0.1, {OPENSHELL_HOST_GATEWAY_ALIAS}, or another routable address"
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct VmProcess {
    child: Child,
    deleting: bool,
}

struct SandboxRecord {
    snapshot: Sandbox,
    state_dir: PathBuf,
    process: Option<Arc<Mutex<VmProcess>>>,
    provisioning_task: Option<JoinHandle<()>>,
    gpu_bdf: Option<String>,
    qemu_network_allocated: bool,
    deleting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayPreparation {
    Fresh,
    PreserveExisting,
}

fn provisioning_span(
    parent: &opentelemetry::Context,
    sandbox_id: &str,
    image_ref: &str,
) -> tracing::Span {
    let span = tracing::info_span!(
        parent: None,
        "vm.provision",
        otel.name = "vm.provision",
        otel.status_code = tracing::field::Empty,
        sandbox.id = %sandbox_id,
        image.ref = %image_ref,
    );
    let parent_span_context = parent.span().span_context().clone();
    if parent_span_context.is_valid() {
        let parent = opentelemetry::Context::new().with_remote_span_context(parent_span_context);
        let _ = span.set_parent(parent);
    }
    span
}

#[derive(Clone)]
pub struct VmDriver {
    config: VmDriverConfig,
    launcher_bin: PathBuf,
    registry: Arc<Mutex<HashMap<String, SandboxRecord>>>,
    image_cache_lock: Arc<Mutex<()>>,
    events: broadcast::Sender<WatchSandboxesEvent>,
    gpu_inventory: Option<Arc<std::sync::Mutex<GpuInventory>>>,
    subnet_allocator: Arc<std::sync::Mutex<SubnetAllocator>>,
    lifecycle_extensions: Arc<LifecycleExtensionRegistry>,
}

impl VmDriver {
    pub async fn new(config: VmDriverConfig) -> Result<Self, String> {
        Self::new_with_extensions(config, LifecycleExtensionRegistry::new()).await
    }

    pub async fn new_with_extensions(
        config: VmDriverConfig,
        lifecycle_extensions: LifecycleExtensionRegistry,
    ) -> Result<Self, String> {
        lifecycle_extensions
            .validate()
            .map_err(|err| err.message().to_string())?;
        config.validate_sandbox_identity()?;
        config.validate_proxy_config()?;
        if config.openshell_endpoint.trim().is_empty() {
            return Err("openshell endpoint is required".to_string());
        }
        validate_openshell_endpoint(&config.openshell_endpoint)?;
        let _ = config.tls_paths()?;

        #[cfg(target_os = "linux")]
        if config.gpu_enabled {
            check_gpu_privileges()?;
            tokio::task::spawn_blocking(crate::cleanup_stale_tap_interfaces)
                .await
                .map_err(|e| format!("cleanup stale TAP interfaces panicked: {e}"))?;
        }

        let state_root = sandboxes_root_dir(&config.state_dir);
        create_private_dir_all(&state_root).await.map_err(|err| {
            format!(
                "failed to create state dir '{}': {err}",
                state_root.display()
            )
        })?;
        let image_cache_root = image_cache_root_dir(&config.state_dir);
        tokio::fs::create_dir_all(&image_cache_root)
            .await
            .map_err(|err| {
                format!(
                    "failed to create state dir '{}': {err}",
                    image_cache_root.display()
                )
            })?;

        let launcher_bin = if let Some(path) = config.launcher_bin.clone() {
            path
        } else {
            std::env::current_exe()
                .map_err(|err| format!("failed to resolve vm driver executable: {err}"))?
        };

        let gpu_inventory = if config.gpu_enabled {
            let sysfs = SysfsRoot::system();
            let inventory = GpuInventory::new(sysfs, &config.state_dir);
            tracing::info!(
                gpu_count = inventory.gpu_count(),
                "GPU inventory initialized"
            );
            Some(Arc::new(std::sync::Mutex::new(inventory)))
        } else {
            None
        };

        let subnet_allocator = Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
            Ipv4Addr::new(10, 0, 128, 0),
            17,
        )));

        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = Self {
            config,
            launcher_bin,
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory,
            subnet_allocator,
            lifecycle_extensions: Arc::new(lifecycle_extensions),
        };
        driver.restore_persisted_sandboxes().await;
        Ok(driver)
    }

    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            gateway_manages_lifecycle: true,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: false,
        }
    }

    // `tonic::Status` is large but is the standard error type across the
    // gRPC API surface; boxing here would diverge from every other handler.
    #[allow(clippy::result_large_err)]
    pub fn validate_sandbox(&self, sandbox: &Sandbox) -> Result<(), Status> {
        validate_vm_sandbox(sandbox, self.config.gpu_enabled)?;
        if self.resolved_sandbox_image(sandbox).is_none() {
            return Err(Status::failed_precondition(
                "vm sandboxes require template.image or a configured default sandbox image",
            ));
        }
        Ok(())
    }

    // `tonic::Status` is large but is the standard error type across the
    // gRPC API surface; boxing here would diverge from every other handler.
    #[allow(clippy::result_large_err)]
    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<CreateSandboxResponse, Status> {
        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            "vm driver: create_sandbox received"
        );
        validate_vm_sandbox(sandbox, self.config.gpu_enabled)?;

        let state_dir = sandbox_state_dir(&self.config.state_dir, &sandbox.id)?;
        let image_ref = self.resolved_sandbox_image(sandbox).ok_or_else(|| {
            Status::failed_precondition(
                "vm sandboxes require template.image or a configured default sandbox image",
            )
        })?;
        info!(
            sandbox_id = %sandbox.id,
            image_ref = %image_ref,
            state_dir = %state_dir.display(),
            "vm driver: resolved image ref, preparing disks"
        );

        let snapshot = sandbox_snapshot(sandbox, provisioning_condition(), false);
        {
            let mut registry = self.registry.lock().await;
            if registry.contains_key(&sandbox.id) {
                return Err(Status::already_exists("sandbox already exists"));
            }
            registry.insert(
                sandbox.id.clone(),
                SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    qemu_network_allocated: false,
                    deleting: false,
                },
            );
        }

        let tls_paths = match self.config.tls_paths() {
            Ok(paths) => paths,
            Err(err) => {
                let mut registry = self.registry.lock().await;
                registry.remove(&sandbox.id);
                return Err(Status::failed_precondition(err));
            }
        };

        if let Err(err) = create_private_dir_all(&state_dir).await {
            let mut registry = self.registry.lock().await;
            registry.remove(&sandbox.id);
            return Err(Status::internal(format!("create state dir failed: {err}")));
        }

        if let Err(err) = self.ensure_extension_state_dirs(&state_dir).await {
            let mut registry = self.registry.lock().await;
            registry.remove(&sandbox.id);
            let _ = tokio::fs::remove_dir_all(&state_dir).await;
            return Err(err);
        }

        if let Err(err) = write_sandbox_request(&state_dir, sandbox).await {
            let mut registry = self.registry.lock().await;
            registry.remove(&sandbox.id);
            let _ = tokio::fs::remove_dir_all(&state_dir).await;
            return Err(Status::internal(format!(
                "write sandbox start metadata failed: {err}"
            )));
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "Scheduled",
                format!("Sandbox accepted by vm driver to image \"{image_ref}\""),
            ),
        );
        self.publish_snapshot(snapshot);

        let driver = self.clone();
        let sandbox_for_task = sandbox.clone();
        let sandbox_id = sandbox.id.clone();
        let image_ref_for_task = image_ref.clone();
        let state_dir_for_task = state_dir.clone();
        let parent = tracing::Span::current().context();
        let provisioning_span = provisioning_span(&parent, &sandbox_id, &image_ref);
        let task = tokio::spawn(
            async move {
                driver
                    .provision_sandbox(
                        sandbox_for_task,
                        image_ref_for_task,
                        state_dir_for_task,
                        tls_paths,
                        OverlayPreparation::Fresh,
                    )
                    .await;
            }
            .instrument(provisioning_span),
        );

        let mut registry = self.registry.lock().await;
        if let Some(record) = registry.get_mut(&sandbox_id) {
            if record.deleting {
                task.abort();
            } else {
                record.provisioning_task = Some(task);
            }
        } else {
            task.abort();
        }

        Ok(CreateSandboxResponse {})
    }

    async fn provision_sandbox(
        &self,
        sandbox: Sandbox,
        image_ref: String,
        state_dir: PathBuf,
        tls_paths: Option<VmDriverTlsPaths>,
        overlay_preparation: OverlayPreparation,
    ) {
        let sandbox_id = sandbox.id.clone();
        if let Err(err) = self
            .provision_sandbox_inner(
                sandbox,
                image_ref,
                state_dir.clone(),
                tls_paths,
                overlay_preparation,
            )
            .await
        {
            tracing::Span::current().record("otel.status_code", "ERROR");
            if err.code() == tonic::Code::Cancelled {
                if overlay_preparation == OverlayPreparation::Fresh {
                    let _ = tokio::fs::remove_dir_all(&state_dir).await;
                }
                return;
            }

            warn!(
                sandbox_id = %sandbox_id,
                error = %err.message(),
                "vm driver: sandbox provisioning failed"
            );
            self.fail_provisioning(
                &sandbox_id,
                &state_dir,
                "ProvisioningFailed",
                err.message(),
                overlay_preparation == OverlayPreparation::Fresh,
            )
            .await;
        }
    }

    #[allow(clippy::result_large_err)]
    async fn provision_sandbox_inner(
        &self,
        sandbox: Sandbox,
        image_ref: String,
        state_dir: PathBuf,
        tls_paths: Option<VmDriverTlsPaths>,
        overlay_preparation: OverlayPreparation,
    ) -> Result<(), Status> {
        self.ensure_provisioning_active(&sandbox.id).await?;
        let is_gpu = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|requirements| driver_gpu_requirements(Some(requirements)))
            .is_some();
        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "ResolvingImage",
                format!("Resolving VM sandbox image \"{image_ref}\""),
            ),
        );

        let image_plan = self.prepare_runtime_images(&sandbox.id, &image_ref).await?;
        let image_identity = image_plan.image_identity.clone();
        self.ensure_provisioning_active(&sandbox.id).await?;
        info!(
            sandbox_id = %sandbox.id,
            image_identity = %image_identity,
            bootstrap_image_identity = %image_plan.bootstrap_image_identity,
            image_disk = image_plan.image_disk.as_ref().map(|path| path.display().to_string()).unwrap_or_default(),
            "vm driver: sandbox root disk plan resolved"
        );
        let disk_paths = sandbox_runtime_disk_paths(&state_dir);
        let root_disk = image_plan.root_disk;
        let image_disk = image_plan.image_disk;
        let overlay_disk = disk_paths.overlay_disk;

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "PreparingOverlay",
                "Preparing writable VM overlay disk".to_string(),
            ),
        );
        if let Err(err) = self
            .prepare_runtime_overlay(
                &overlay_disk,
                tls_paths.as_ref(),
                sandbox
                    .spec
                    .as_ref()
                    .map(|spec| spec.sandbox_token.as_str())
                    .filter(|token| !token.is_empty()),
                overlay_preparation,
            )
            .await
        {
            return Err(Status::internal(format!(
                "prepare guest overlay disk failed: {err}"
            )));
        }
        self.ensure_provisioning_active(&sandbox.id).await?;

        if let Err(err) =
            write_sandbox_image_metadata(&state_dir, &image_ref, &image_identity).await
        {
            return Err(Status::internal(format!(
                "write sandbox image metadata failed: {err}"
            )));
        }

        let gpu_device_id = vm_gpu_device_id(&sandbox)?;
        let gpu_bdf = if let Some(gpu_device_id) = gpu_device_id.as_deref() {
            Some(
                self.assign_gpu_to_record(&sandbox.id, gpu_device_id)
                    .await?,
            )
        } else {
            None
        };

        let needs_qemu = is_gpu;

        let mut plan =
            match self.build_vm_launch_plan(&sandbox.id, needs_qemu, is_gpu, gpu_bdf.clone()) {
                Ok(plan) => plan,
                Err(err) => {
                    self.release_gpu_and_subnet(&sandbox.id);
                    return Err(err);
                }
            };

        // `build_vm_launch_plan` already allocated the QEMU subnet, so record
        // it as allocated now — before the cancellable `configure_launch` /
        // `before_launch` hooks run. If a delete aborts provisioning while
        // one of those hooks is awaiting, the aborted future never runs its
        // own release path, and the delete cleanup is gated on this flag; if
        // the flag were still unset the subnet would leak.
        if plan.backend == VmBackend::Qemu
            && let Err(err) = self.mark_qemu_network_allocated(&sandbox.id).await
        {
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(err);
        }

        if let Err(err) = self
            .lifecycle_extensions
            .configure_launch(&sandbox, &state_dir, &mut plan)
            .await
        {
            self.lifecycle_extensions
                .after_launch_failed(
                    &sandbox,
                    &state_dir,
                    LaunchAbortReason::BeforeLaunchHookFailed,
                )
                .await;
            self.release_gpu_and_subnet(&sandbox.id);
            let message = format!(
                "vm lifecycle extension rejected sandbox launch plan: {}",
                err.message()
            );
            return Err(if err.is_resource_exhausted() {
                Status::resource_exhausted(message)
            } else {
                Status::failed_precondition(message)
            });
        }

        // Resolve and validate the backend from the requirements that
        // `configure_launch` extensions contributed. After this point the
        // plan's backend, sizing, and host allocations (subnet, tap, vsock)
        // are final; the `before_launch` hook below may still mutate
        // `plan.env` and `plan.guest_init_dropins` and may abort the launch,
        // but it MUST NOT change `plan.backend`, `plan.required_backends`,
        // or `plan.required_backend_features` -- those are enforced as a
        // documented trait contract, not a runtime check.
        if let Err(err) =
            self.resolve_launch_plan_backend(&sandbox.id, is_gpu, gpu_bdf.clone(), &mut plan)
        {
            self.lifecycle_extensions
                .after_launch_failed(
                    &sandbox,
                    &state_dir,
                    LaunchAbortReason::BeforeLaunchHookFailed,
                )
                .await;
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(err);
        }

        if let Err(err) = Self::validate_launch_plan_backend(is_gpu, &plan) {
            self.lifecycle_extensions
                .after_launch_failed(
                    &sandbox,
                    &state_dir,
                    LaunchAbortReason::BeforeLaunchHookFailed,
                )
                .await;
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(err);
        }

        if let Err(err) = self
            .lifecycle_extensions
            .before_launch(&sandbox, &state_dir, &mut plan)
            .await
        {
            self.lifecycle_extensions
                .after_launch_failed(
                    &sandbox,
                    &state_dir,
                    LaunchAbortReason::BeforeLaunchHookFailed,
                )
                .await;
            self.release_gpu_and_subnet(&sandbox.id);
            let message = format!(
                "vm lifecycle extension rejected sandbox launch: {}",
                err.message()
            );
            return Err(if err.is_resource_exhausted() {
                Status::resource_exhausted(message)
            } else {
                Status::failed_precondition(message)
            });
        }

        if let Err(err) = inject_guest_init_dropins(&overlay_disk, &plan.guest_init_dropins) {
            self.lifecycle_extensions
                .after_launch_failed(&sandbox, &state_dir, LaunchAbortReason::GuestPrepareFailed)
                .await;
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(err);
        }

        // Staged on every launch, including a restart onto a preserved
        // overlay, so the driver's copy always shadows the image layer.
        if let Err(err) = inject_guest_upstream_proxy(&overlay_disk, &self.config).await {
            self.lifecycle_extensions
                .after_launch_failed(&sandbox, &state_dir, LaunchAbortReason::GuestPrepareFailed)
                .await;
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(err);
        }

        let endpoint_override = if plan.backend == VmBackend::Qemu {
            plan.host_ip.as_deref().map(|host_ip| {
                guest_visible_openshell_endpoint_for_tap(&self.config.openshell_endpoint, host_ip)
            })
        } else {
            None
        };

        let console_output = state_dir.join("rootfs-console.log");
        let mut command = Command::new(&self.launcher_bin);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--internal-run-vm");
        command.arg("--vm-root-disk").arg(&root_disk);
        command.arg("--vm-overlay-disk").arg(&overlay_disk);
        if let Some(image_disk) = &image_disk {
            command.arg("--vm-image-disk").arg(image_disk);
        }
        command.arg("--vm-exec").arg(sandbox_guest_init_path());
        command.arg("--vm-workdir").arg("/");
        command.arg("--vm-console-output").arg(&console_output);
        command.arg("--vm-vcpus").arg(plan.vcpus.to_string());
        command.arg("--vm-mem-mib").arg(plan.mem_mib.to_string());
        if let Some(kernel_image) = &plan.kernel_image {
            command.arg("--vm-kernel-image").arg(kernel_image);
        }

        if plan.backend == VmBackend::Qemu {
            command.arg("--vm-backend").arg("qemu");
            if let Some(bdf) = plan.gpu_bdf.as_deref() {
                command.arg("--vm-gpu-bdf").arg(bdf);
            }
            if let Some(tap) = plan.tap_device.as_deref() {
                command.arg("--vm-tap-device").arg(tap);
            }
            if let Some(guest_ip) = plan.guest_ip.as_deref() {
                command.arg("--vm-guest-ip").arg(guest_ip);
            }
            if let Some(host_ip) = plan.host_ip.as_deref() {
                command.arg("--vm-host-ip").arg(host_ip);
            }
            if let Some(vsock_cid) = plan.vsock_cid {
                command.arg("--vm-vsock-cid").arg(vsock_cid.to_string());
            }
            if let Some(guest_mac) = plan.guest_mac.as_deref() {
                command.arg("--vm-guest-mac").arg(guest_mac);
            }
            if let Some(port) = plan.gateway_port {
                command.arg("--vm-gateway-port").arg(port.to_string());
            }
        }

        self.ensure_provisioning_active(&sandbox.id).await?;

        command
            .arg("--vm-krun-log-level")
            .arg(self.config.krun_log_level.to_string());

        for env in build_guest_environment(&sandbox, &self.config, endpoint_override.as_deref()) {
            command.arg("--vm-env").arg(env);
        }
        for env in &plan.env {
            command.arg("--vm-env").arg(env);
        }

        info!(
            sandbox_id = %sandbox.id,
            launcher = %self.launcher_bin.display(),
            console_output = %console_output.display(),
            "vm driver: spawning VM launcher"
        );
        let child = match spawn_vm_launcher(&mut command, &sandbox.id, &plan.backend) {
            Ok(child) => child,
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "vm driver: launcher spawn failed"
                );
                self.lifecycle_extensions
                    .after_launch_failed(
                        &sandbox,
                        &state_dir,
                        LaunchAbortReason::LauncherSpawnFailed,
                    )
                    .await;
                self.release_gpu_and_subnet(&sandbox.id);
                return Err(Status::internal(format!(
                    "failed to launch vm helper '{}': {err}",
                    self.launcher_bin.display()
                )));
            }
        };
        info!(
            sandbox_id = %sandbox.id,
            launcher_pid = child.id().unwrap_or(0),
                "vm driver: launcher spawned"
        );
        let process = Arc::new(Mutex::new(VmProcess {
            child,
            deleting: false,
        }));

        let mut process_to_stop = None;
        let mut snapshot_to_publish = None;
        {
            let mut registry = self.registry.lock().await;
            match registry.get_mut(&sandbox.id) {
                Some(record) if !record.deleting => {
                    record.process = Some(process.clone());
                    record.gpu_bdf.clone_from(&gpu_bdf);
                    record.qemu_network_allocated = plan.backend == VmBackend::Qemu;
                    snapshot_to_publish = Some(record.snapshot.clone());
                }
                _ => {
                    process_to_stop = Some(process.clone());
                }
            }
        }

        if let Some(process) = process_to_stop {
            {
                let mut process = process.lock().await;
                process.deleting = true;
                terminate_vm_process(&mut process.child)
                    .await
                    .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
            }
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(Status::cancelled("sandbox provisioning cancelled"));
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event("vm", "Normal", "Started", "Started VM launcher".to_string()),
        );
        if let Some(snapshot) = snapshot_to_publish {
            self.publish_snapshot(snapshot);
        }
        if overlay_preparation == OverlayPreparation::PreserveExisting {
            let persisted = RestoreContext {
                sandbox: sandbox.clone(),
                state_dir: state_dir.clone(),
            };
            self.lifecycle_extensions.after_restore(&persisted).await;
        }
        tokio::spawn({
            let driver = self.clone();
            let sandbox_id = sandbox.id.clone();
            async move {
                driver.monitor_sandbox(sandbox_id).await;
            }
        });

        Ok(())
    }

    pub async fn stop_sandbox(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        if !sandbox_id.is_empty() {
            validate_sandbox_id(sandbox_id)?;
        }
        let record_id = {
            let registry = self.registry.lock().await;
            if registry.contains_key(sandbox_id) {
                Some(sandbox_id.to_string())
            } else {
                registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .map(|(id, _)| id.clone())
            }
        }
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

        let state_dir = {
            let registry = self.registry.lock().await;
            registry
                .get(&record_id)
                .ok_or_else(|| Status::not_found("sandbox not found"))?
                .state_dir
                .clone()
        };

        // Persist intent before detaching process handles or releasing host
        // allocations. If this write fails, the live record remains intact.
        tokio::fs::write(state_dir.join(SANDBOX_STOPPED_FILE), b"stopped\n")
            .await
            .map_err(|err| Status::internal(format!("persist stop marker failed: {err}")))?;

        let (process, provisioning_task, has_gpu, has_qemu_network, snapshot) = {
            let mut registry = self.registry.lock().await;
            let record = registry
                .get_mut(&record_id)
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            (
                record.process.take(),
                record.provisioning_task.take(),
                record.gpu_bdf.take().is_some(),
                std::mem::take(&mut record.qemu_network_allocated),
                record.snapshot.clone(),
            )
        };

        if let Some(task) = provisioning_task {
            task.abort();
        }
        if let Some(process) = process {
            let mut process = process.lock().await;
            process.deleting = true;
            terminate_vm_process(&mut process.child)
                .await
                .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
        }
        self.lifecycle_extensions
            .after_launch_failed(&snapshot, &state_dir, LaunchAbortReason::Stopped)
            .await;
        self.release_allocations(&record_id, has_gpu, has_qemu_network);

        if let Some(snapshot) = self
            .set_snapshot_condition(&record_id, stopped_condition(), false)
            .await
        {
            self.publish_snapshot(snapshot);
        }
        self.publish_platform_event(
            record_id,
            platform_event("vm", "Normal", "Stopped", "VM sandbox stopped".to_string()),
        );
        Ok(())
    }

    pub async fn start_sandbox(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        if !sandbox_id.is_empty() {
            validate_sandbox_id(sandbox_id)?;
        }
        let (record_id, state_dir, already_running) = {
            let registry = self.registry.lock().await;
            let (id, record) = if let Some(entry) = registry.get_key_value(sandbox_id) {
                entry
            } else {
                registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .ok_or_else(|| Status::not_found("sandbox not found"))?
            };
            (
                id.clone(),
                record.state_dir.clone(),
                record.process.is_some() || record.provisioning_task.is_some(),
            )
        };
        if already_running {
            return Ok(());
        }

        let sandbox = read_sandbox_request(&state_dir.join(SANDBOX_REQUEST_FILE))
            .await
            .map_err(|err| {
                Status::internal(format!("read sandbox start metadata failed: {err}"))
            })?;
        let stopped_record = self
            .registry
            .lock()
            .await
            .remove(&record_id)
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let restored = self
            .restore_persisted_sandbox(sandbox, state_dir, true, &tracing::Span::current())
            .await;
        if !restored {
            self.registry
                .lock()
                .await
                .entry(record_id)
                .or_insert(stopped_record);
            return Err(Status::internal("failed to start persisted VM sandbox"));
        }
        Ok(())
    }

    #[tracing::instrument(
        name = "vm.teardown",
        skip(self),
        fields(
            otel.name = "vm.teardown",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
            sandbox.name = %sandbox_name,
        )
    )]
    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<DeleteSandboxResponse, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        if !sandbox_id.is_empty() {
            validate_sandbox_id(sandbox_id)?;
        }

        let record_id = {
            let registry = self.registry.lock().await;
            if let Some((id, _record)) = registry.get_key_value(sandbox_id) {
                Some(id.clone())
            } else {
                registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .map(|(id, _)| id.clone())
            }
        };

        let Some(record_id) = record_id else {
            return span_status.finish(Ok(DeleteSandboxResponse { deleted: false }));
        };

        let (
            state_dir,
            process,
            gpu_bdf,
            qemu_network_allocated,
            provisioning_task,
            sandbox_snapshot,
        ) = {
            let mut registry = self.registry.lock().await;
            let Some(record) = registry.get_mut(&record_id) else {
                return span_status.finish(Ok(DeleteSandboxResponse { deleted: false }));
            };
            record.deleting = true;
            (
                record.state_dir.clone(),
                record.process.clone(),
                record.gpu_bdf.clone(),
                record.qemu_network_allocated,
                record.provisioning_task.take(),
                record.snapshot.clone(),
            )
        };

        if let Some(snapshot) = self
            .set_snapshot_condition(&record_id, deleting_condition(), true)
            .await
        {
            self.publish_snapshot(snapshot);
        }

        if let Some(task) = provisioning_task {
            task.abort();
        }

        if let Some(process) = process {
            let mut process = process.lock().await;
            process.deleting = true;
            terminate_vm_process(&mut process.child)
                .await
                .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
        }

        self.lifecycle_extensions
            .after_delete(&sandbox_snapshot, &state_dir)
            .await;

        self.release_allocations(&record_id, gpu_bdf.is_some(), qemu_network_allocated);

        remove_sandbox_state_dir(&self.config.state_dir, &state_dir).await?;

        {
            let mut registry = self.registry.lock().await;
            registry.remove(&record_id);
        }

        self.publish_deleted(record_id);
        span_status.finish(Ok(DeleteSandboxResponse { deleted: true }))
    }

    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<Sandbox>, Status> {
        if !sandbox_id.is_empty() {
            validate_sandbox_id(sandbox_id)?;
        }

        let registry = self.registry.lock().await;
        let sandbox = if sandbox_id.is_empty() {
            registry
                .values()
                .find(|record| record.snapshot.name == sandbox_name)
                .map(|record| record.snapshot.clone())
        } else {
            registry
                .get(sandbox_id)
                .map(|record| record.snapshot.clone())
        };
        Ok(sandbox)
    }

    pub async fn current_snapshots(&self) -> Vec<Sandbox> {
        let registry = self.registry.lock().await;
        let mut snapshots = registry
            .values()
            .map(|record| record.snapshot.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.name.cmp(&right.name));
        snapshots
    }

    #[tracing::instrument(
        name = "reconcile",
        skip_all,
        fields(
            otel.name = "reconcile.sandboxes",
            driver.name = "vm",
        )
    )]
    async fn restore_persisted_sandboxes(&self) {
        let state_root = sandboxes_root_dir(&self.config.state_dir);
        let mut entries = match tokio::fs::read_dir(&state_root).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(
                    state_root = %state_root.display(),
                    error = %err,
                    "vm driver: failed to scan persisted sandboxes"
                );
                return;
            }
        };

        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(err) => {
                    warn!(
                        state_root = %state_root.display(),
                        error = %err,
                        "vm driver: failed to continue scanning persisted sandboxes"
                    );
                    break;
                }
            };
            let state_dir = entry.path();
            let is_dir = match entry.file_type().await {
                Ok(file_type) => file_type.is_dir(),
                Err(err) => {
                    warn!(
                        state_dir = %state_dir.display(),
                        error = %err,
                        "vm driver: failed to inspect persisted sandbox state dir"
                    );
                    continue;
                }
            };
            if !is_dir {
                continue;
            }

            let request_path = state_dir.join(SANDBOX_REQUEST_FILE);
            let sandbox = match read_sandbox_request(&request_path).await {
                Ok(sandbox) => sandbox,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    warn!(
                        state_dir = %state_dir.display(),
                        error = %err,
                        "vm driver: failed to read persisted sandbox request"
                    );
                    continue;
                }
            };

            if let Err(status) =
                validate_restored_sandbox_state(&self.config.state_dir, &state_dir, &sandbox)
            {
                warn!(
                    sandbox_id = %sandbox.id,
                    state_dir = %state_dir.display(),
                    error = %status.message(),
                    "vm driver: ignoring invalid persisted sandbox state"
                );
                continue;
            }

            if tokio::fs::metadata(state_dir.join(SANDBOX_STOPPED_FILE))
                .await
                .is_ok()
            {
                let snapshot = sandbox_snapshot(&sandbox, stopped_condition(), false);
                let mut registry = self.registry.lock().await;
                registry.entry(sandbox.id.clone()).or_insert(SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    qemu_network_allocated: false,
                    deleting: false,
                });
                drop(registry);
                self.publish_snapshot(snapshot);
                info!(sandbox_id = %sandbox.id, "vm driver: restored stopped sandbox without launching compute");
                continue;
            }

            if tokio::fs::try_exists(state_dir.join(MAIN_PROCESS_EXITED_FILE))
                .await
                .unwrap_or(false)
            {
                let snapshot = sandbox_snapshot(
                    &sandbox,
                    error_condition(
                        "ProcessExited",
                        "Canonical main process exited before VM driver restart",
                    ),
                    false,
                );
                let mut registry = self.registry.lock().await;
                registry.entry(sandbox.id.clone()).or_insert(SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    qemu_network_allocated: false,
                    deleting: false,
                });
                drop(registry);
                self.publish_snapshot(snapshot);
                info!(
                    sandbox_id = %sandbox.id,
                    "vm driver: preserved terminal sandbox without restarting canonical process"
                );
                continue;
            }

            self.restore_persisted_sandbox(sandbox, state_dir, false, &tracing::Span::current())
                .await;
        }
    }

    /// Restore a persisted sandbox and report whether the driver accepted it.
    /// For explicit start, the stop marker is cleared only after all
    /// restore preflight checks pass and the replacement registry record is
    /// installed. A failed restore therefore remains durably stopped.
    async fn restore_persisted_sandbox(
        &self,
        sandbox: Sandbox,
        state_dir: PathBuf,
        clear_stop_marker: bool,
        reconciliation_span: &tracing::Span,
    ) -> bool {
        let Some(image_ref) = self.resolved_sandbox_image(&sandbox) else {
            warn!(
                sandbox_id = %sandbox.id,
                sandbox_name = %sandbox.name,
                "vm driver: cannot restore persisted sandbox without image"
            );
            return false;
        };
        let tls_paths = match self.config.tls_paths() {
            Ok(paths) => paths,
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    error = %err,
                    "vm driver: cannot restore persisted sandbox TLS configuration"
                );
                return false;
            }
        };

        if let Err(err) = self.ensure_extension_state_dirs(&state_dir).await {
            warn!(
                sandbox_id = %sandbox.id,
                sandbox_name = %sandbox.name,
                state_dir = %state_dir.display(),
                error = %err.message(),
                "vm driver: cannot restore persisted sandbox extension state"
            );
            return false;
        }

        let persisted = RestoreContext {
            sandbox: sandbox.clone(),
            state_dir: state_dir.clone(),
        };
        if let Err(err) = self.lifecycle_extensions.before_restore(&persisted).await {
            warn!(
                sandbox_id = %sandbox.id,
                sandbox_name = %sandbox.name,
                state_dir = %state_dir.display(),
                error = %err,
                "vm driver: lifecycle extension rejected persisted sandbox restore"
            );
            return false;
        }

        let snapshot = sandbox_snapshot(&sandbox, provisioning_condition(), false);
        {
            let mut registry = self.registry.lock().await;
            if registry.contains_key(&sandbox.id) {
                return false;
            }
            registry.insert(
                sandbox.id.clone(),
                SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    qemu_network_allocated: false,
                    deleting: false,
                },
            );
        }

        if clear_stop_marker {
            match tokio::fs::remove_file(state_dir.join(SANDBOX_STOPPED_FILE)).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    self.registry.lock().await.remove(&sandbox.id);
                    warn!(
                        sandbox_id = %sandbox.id,
                        state_dir = %state_dir.display(),
                        error = %err,
                        "vm driver: cannot clear stop marker for persisted sandbox restore"
                    );
                    return false;
                }
            }
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "Restoring",
                "Restoring persisted VM sandbox after driver restart".to_string(),
            ),
        );
        self.publish_snapshot(snapshot);

        let driver = self.clone();
        let sandbox_id = sandbox.id.clone();
        let restoration_span = tracing::info_span!(
            parent: reconciliation_span,
            "vm.restore",
            otel.name = "vm.restore",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        );
        let reconciliation_span = reconciliation_span.clone();
        let provisioning_span =
            provisioning_span(&restoration_span.context(), &sandbox_id, &image_ref);
        let task = tokio::spawn(
            async move {
                driver
                    .provision_sandbox(
                        sandbox,
                        image_ref,
                        state_dir,
                        tls_paths,
                        OverlayPreparation::PreserveExisting,
                    )
                    .await;
                drop(reconciliation_span);
            }
            .instrument(provisioning_span)
            .instrument(restoration_span),
        );

        let mut registry = self.registry.lock().await;
        if let Some(record) = registry.get_mut(&sandbox_id) {
            if record.deleting {
                task.abort();
            } else {
                record.provisioning_task = Some(task);
            }
        } else {
            task.abort();
        }
        true
    }

    fn release_gpu(&self, sandbox_id: &str) {
        if let Some(inventory) = self.gpu_inventory.as_ref()
            && let Ok(mut inv) = inventory.lock()
        {
            inv.release(sandbox_id);
        }
    }

    fn release_subnet(&self, sandbox_id: &str) {
        if let Ok(mut alloc) = self.subnet_allocator.lock() {
            alloc.release(sandbox_id);
        }
    }

    fn release_allocations(&self, sandbox_id: &str, has_gpu: bool, has_qemu_network: bool) {
        if has_gpu {
            self.release_gpu(sandbox_id);
        }
        if has_qemu_network {
            self.release_subnet(sandbox_id);
        }
    }

    fn release_gpu_and_subnet(&self, sandbox_id: &str) {
        self.release_gpu(sandbox_id);
        self.release_subnet(sandbox_id);
    }

    async fn ensure_extension_state_dirs(&self, state_dir: &Path) -> Result<(), Status> {
        for extension_name in self.lifecycle_extensions.names() {
            let extension_dir = extension_state_dir(state_dir, &extension_name).map_err(|err| {
                Status::failed_precondition(format!(
                    "invalid VM lifecycle extension '{}': {}",
                    extension_name,
                    err.message()
                ))
            })?;
            create_private_dir_all(&extension_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "create VM lifecycle extension state dir '{}' failed: {err}",
                        extension_dir.display()
                    ))
                })?;
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn resolve_launch_plan_backend(
        &self,
        sandbox_id: &str,
        is_gpu: bool,
        gpu_bdf: Option<String>,
        plan: &mut LaunchPlan,
    ) -> Result<(), Status> {
        if plan.kernel_image.is_some() {
            plan.require_backend_feature(BackendFeature::ExternalKernelImage);
        }
        if !plan.guest_init_dropins.is_empty() {
            plan.require_backend_feature(BackendFeature::GuestInitDropins);
        }

        if plan.required_backends.contains(&VmBackend::Qemu)
            || plan.backend == VmBackend::Qemu
            || plan
                .required_backend_features
                .iter()
                .any(|feature| feature.requires_qemu())
        {
            self.configure_qemu_launch_plan(sandbox_id, is_gpu, gpu_bdf, plan)?;
        }

        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn configure_qemu_launch_plan(
        &self,
        sandbox_id: &str,
        is_gpu: bool,
        gpu_bdf: Option<String>,
        plan: &mut LaunchPlan,
    ) -> Result<(), Status> {
        plan.backend = VmBackend::Qemu;
        if is_gpu {
            plan.vcpus = self.config.gpu_vcpus;
            plan.mem_mib = self.config.gpu_mem_mib;
        }
        if plan.gpu_bdf.is_none() {
            plan.gpu_bdf = gpu_bdf;
        }
        if !has_complete_qemu_network(plan) {
            let subnet = self
                .subnet_allocator
                .lock()
                .map_err(|e| Status::internal(format!("subnet allocator lock poisoned: {e}")))?
                .allocate(sandbox_id)
                .map_err(Status::failed_precondition)?;
            let mac = mac_from_sandbox_id(sandbox_id);
            plan.tap_device = Some(tap_device_name(sandbox_id));
            plan.guest_ip = Some(subnet.guest_ip.to_string());
            plan.host_ip = Some(subnet.host_ip.to_string());
            plan.vsock_cid = Some(allocate_vsock_cid());
            plan.guest_mac = Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ));
            plan.gateway_port = gateway_port_from_endpoint(&self.config.openshell_endpoint);
        }

        // The corporate-proxy host-loopback recipe is a libkrun/gvproxy
        // property and has no QEMU/TAP equivalent (see
        // `proxy_url_targets_gateway_host`). Run it here, after the subnet
        // allocation above has settled `plan.host_ip`, because the address to
        // compare against is this sandbox's own TAP host address. Fail the
        // create with the reason rather than boot a sandbox whose
        // policy-approved CONNECTs all time out against an unreachable proxy.
        if let Some(url) = self.config.https_proxy.as_deref()
            && proxy_url_targets_gateway_host(url, plan.host_ip.as_deref())
        {
            let tap_host = plan.host_ip.as_deref().unwrap_or("the TAP host address");
            return Err(Status::failed_precondition(format!(
                "https_proxy '{url}' addresses the gateway host, which a QEMU/TAP sandbox \
                 (GPU sandboxes) cannot reach: host.openshell.internal resolves to this \
                 sandbox's TAP host address {tap_host} and the driver's nftables rules allow \
                 only the gateway port from the guest. Configure a proxy address routable \
                 from the guest's masqueraded egress, or run this sandbox without a GPU"
            )));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_launch_plan_backend(is_gpu: bool, plan: &LaunchPlan) -> Result<(), Status> {
        // NOTE: this guard exists because the non-GPU QEMU launch path
        // (PCI device transport, VFIO root port wiring) has not landed
        // yet. Until then, even though the resolver will happily promote
        // a plan to QEMU when an extension requires `PciPassthrough` or
        // `ExternalKernelImage`, the launch itself is blocked here so we
        // don't spawn a QEMU instance with no concrete device backing.
        // Remove this guard once the non-GPU QEMU launch path supports
        // emitting `pcie-root-port` + `vfio-pci` for arbitrary device
        // descriptors.
        if plan.backend == VmBackend::Qemu && !is_gpu {
            let offending_feature = plan
                .required_backend_features
                .iter()
                .find(|feature| feature.requires_qemu())
                .map_or("(explicit QEMU backend requirement)", |feature| {
                    feature.as_str()
                });
            return Err(Status::failed_precondition(format!(
                "vm lifecycle extension required '{offending_feature}', which resolves to the QEMU backend, \
                 but non-GPU QEMU launch is not yet supported (pending PCI device transport)"
            )));
        }
        if plan.backend != VmBackend::Qemu && is_gpu {
            return Err(Status::failed_precondition(
                "GPU sandbox launch requires the QEMU backend",
            ));
        }
        if plan.required_backends.contains(&VmBackend::Libkrun)
            && plan.required_backends.contains(&VmBackend::Qemu)
        {
            return Err(Status::failed_precondition(
                "VM lifecycle extensions requested conflicting VM backends",
            ));
        }
        if plan.required_backends.contains(&VmBackend::Libkrun)
            && plan.backend != VmBackend::Libkrun
        {
            return Err(Status::failed_precondition(
                "VM lifecycle extension requires the libkrun backend",
            ));
        }
        if plan.required_backends.contains(&VmBackend::Qemu) && plan.backend != VmBackend::Qemu {
            return Err(Status::failed_precondition(
                "VM lifecycle extension requires the QEMU backend",
            ));
        }
        if plan.backend != VmBackend::Qemu
            && let Some(feature) = plan
                .required_backend_features
                .iter()
                .find(|feature| feature.requires_qemu())
        {
            return Err(Status::failed_precondition(format!(
                "VM backend feature '{}' requires a VM backend with PCI-style launch support",
                feature.as_str()
            )));
        }
        if plan.kernel_image.is_some() && plan.backend != VmBackend::Qemu {
            return Err(Status::failed_precondition(
                "selected kernel image requires a VM backend that supports external kernel images",
            ));
        }
        if let Some(kernel_image) = &plan.kernel_image
            && !kernel_image.is_file()
        {
            return Err(Status::failed_precondition(format!(
                "selected kernel image does not exist: {}",
                kernel_image.display()
            )));
        }
        Ok(())
    }

    async fn mark_qemu_network_allocated(&self, sandbox_id: &str) -> Result<(), Status> {
        let mut registry = self.registry.lock().await;
        match registry.get_mut(sandbox_id) {
            Some(record) if !record.deleting => {
                record.qemu_network_allocated = true;
                Ok(())
            }
            _ => Err(Status::cancelled("sandbox provisioning cancelled")),
        }
    }

    #[allow(clippy::result_large_err)]
    fn build_vm_launch_plan(
        &self,
        sandbox_id: &str,
        needs_qemu: bool,
        is_gpu: bool,
        gpu_bdf: Option<String>,
    ) -> Result<LaunchPlan, Status> {
        if !needs_qemu {
            return Ok(LaunchPlan {
                backend: VmBackend::Libkrun,
                vcpus: self.config.vcpus,
                mem_mib: self.config.mem_mib,
                required_backends: Vec::new(),
                required_backend_features: Vec::new(),
                kernel_profile: None,
                kernel_image: None,
                gpu_bdf: None,
                tap_device: None,
                guest_ip: None,
                host_ip: None,
                vsock_cid: None,
                guest_mac: None,
                gateway_port: None,
                guest_init_dropins: Vec::new(),
                env: Vec::new(),
            });
        }

        let subnet = self
            .subnet_allocator
            .lock()
            .map_err(|e| Status::internal(format!("subnet allocator lock poisoned: {e}")))?
            .allocate(sandbox_id)
            .map_err(Status::failed_precondition)?;
        let vsock_cid = allocate_vsock_cid();
        let mac = mac_from_sandbox_id(sandbox_id);
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let tap = tap_device_name(sandbox_id);
        let gateway_port = gateway_port_from_endpoint(&self.config.openshell_endpoint);

        let (vcpus, mem_mib) = if is_gpu {
            (self.config.gpu_vcpus, self.config.gpu_mem_mib)
        } else {
            (self.config.vcpus, self.config.mem_mib)
        };

        Ok(LaunchPlan {
            backend: VmBackend::Qemu,
            vcpus,
            mem_mib,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: None,
            gpu_bdf,
            tap_device: Some(tap),
            guest_ip: Some(subnet.guest_ip.to_string()),
            host_ip: Some(subnet.host_ip.to_string()),
            vsock_cid: Some(vsock_cid),
            guest_mac: Some(mac_str),
            gateway_port,
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
        })
    }

    async fn ensure_provisioning_active(&self, sandbox_id: &str) -> Result<(), Status> {
        let registry = self.registry.lock().await;
        match registry.get(sandbox_id) {
            Some(record) if !record.deleting => Ok(()),
            _ => Err(Status::cancelled("sandbox provisioning cancelled")),
        }
    }

    #[cfg(test)]
    async fn wait_for_provisioning_for_test(&self, sandbox_id: &str) {
        let task = self
            .registry
            .lock()
            .await
            .get_mut(sandbox_id)
            .and_then(|record| record.provisioning_task.take())
            .unwrap_or_else(|| panic!("provisioning task for {sandbox_id}"));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap_or_else(|_| panic!("provisioning task for {sandbox_id} timed out"))
            .unwrap_or_else(|err| panic!("provisioning task for {sandbox_id} failed: {err}"));
    }

    async fn assign_gpu_to_record(
        &self,
        sandbox_id: &str,
        gpu_device: &str,
    ) -> Result<String, Status> {
        let mut registry = self.registry.lock().await;
        match registry.get_mut(sandbox_id) {
            Some(record) if !record.deleting => {}
            _ => return Err(Status::cancelled("sandbox provisioning cancelled")),
        }

        let inventory = self
            .gpu_inventory
            .as_ref()
            .ok_or_else(|| Status::internal("GPU inventory not initialized"))?;
        let assignment = inventory
            .lock()
            .map_err(|e| Status::internal(format!("GPU inventory lock poisoned: {e}")))?
            .assign(sandbox_id, gpu_device)
            .map_err(Status::failed_precondition)?;

        let record = registry
            .get_mut(sandbox_id)
            .expect("sandbox record exists while registry lock is held");
        record.gpu_bdf = Some(assignment.bdf.clone());
        tracing::info!(
            sandbox_id = %sandbox_id,
            bdf = %assignment.bdf,
            gpu_name = %assignment.name,
            iommu_group = assignment.iommu_group,
            "assigned GPU to sandbox"
        );
        Ok(assignment.bdf)
    }

    async fn fail_provisioning(
        &self,
        sandbox_id: &str,
        state_dir: &Path,
        reason: &str,
        message: &str,
        remove_state: bool,
    ) {
        self.release_gpu_and_subnet(sandbox_id);
        let snapshot = {
            let mut registry = self.registry.lock().await;
            let Some(record) = registry.get_mut(sandbox_id) else {
                return;
            };
            if record.deleting {
                return;
            }
            record.process = None;
            record.gpu_bdf = None;
            record.qemu_network_allocated = false;
            record.snapshot.status = Some(status_with_condition(
                &record.snapshot,
                error_condition(reason, message),
                false,
            ));
            Some(record.snapshot.clone())
        };

        if remove_state {
            let _ = tokio::fs::remove_dir_all(state_dir).await;
        }
        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Warning",
                reason,
                format!("VM provisioning failed: {message}"),
            ),
        );
        if let Some(snapshot) = snapshot {
            self.publish_snapshot(snapshot);
        }
    }

    #[tracing::instrument(
        name = "vm.prepare_images",
        skip(self),
        fields(
            otel.name = "vm.prepare_images",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
            image.ref = %image_ref,
        )
    )]
    async fn prepare_runtime_images(
        &self,
        sandbox_id: &str,
        image_ref: &str,
    ) -> Result<RuntimeImagePlan, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let bootstrap_image_ref = self.bootstrap_image_ref(image_ref);
        let bootstrap_image_identity = self
            .ensure_cached_bootstrap_rootfs_image(sandbox_id, &bootstrap_image_ref)
            .await?;
        let root_disk = image_cache_rootfs_image(&self.config.state_dir, &bootstrap_image_identity);

        if image_ref.trim() == bootstrap_image_ref.trim() {
            return span_status.finish(Ok(RuntimeImagePlan {
                root_disk,
                image_disk: None,
                image_identity: bootstrap_image_identity.clone(),
                bootstrap_image_identity,
            }));
        }

        let prepared = self
            .ensure_prepared_image_disk(sandbox_id, image_ref, &root_disk)
            .await?;
        span_status.finish(Ok(RuntimeImagePlan {
            root_disk,
            image_disk: Some(prepared.disk_path),
            image_identity: prepared.image_identity,
            bootstrap_image_identity,
        }))
    }

    fn bootstrap_image_ref(&self, sandbox_image_ref: &str) -> String {
        let configured = self.config.bootstrap_image.trim();
        if !configured.is_empty() {
            return configured.to_string();
        }
        let default = self.config.default_image.trim();
        if !default.is_empty() {
            return default.to_string();
        }
        sandbox_image_ref.to_string()
    }

    #[tracing::instrument(
        name = "vm.prepare_overlay",
        skip_all,
        fields(
            otel.name = "vm.prepare_overlay",
            otel.status_code = tracing::field::Empty,
            overlay.path = %overlay_disk.display(),
            preparation = ?preparation,
        )
    )]
    async fn prepare_runtime_overlay(
        &self,
        overlay_disk: &Path,
        tls_paths: Option<&VmDriverTlsPaths>,
        sandbox_token: Option<&str>,
        preparation: OverlayPreparation,
    ) -> Result<(), String> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let tls_materials = match tls_paths {
            Some(paths) => Some(read_guest_tls_materials(paths).await?),
            None => None,
        };
        let sandbox_token = sandbox_token.map(str::to_string);
        let overlay_disk = overlay_disk.to_path_buf();
        let overlay_size_bytes = self
            .config
            .overlay_disk_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| {
                format!(
                    "overlay disk size {} MiB is too large",
                    self.config.overlay_disk_mib
                )
            })?;

        let template_path = overlay_template_image(&self.config.state_dir, overlay_size_bytes);
        if !overlay_template_image_ready(&template_path, overlay_size_bytes).await? {
            let _cache_guard = self.image_cache_lock.lock().await;
            let template_path = template_path.clone();
            tokio::task::spawn_blocking(move || {
                ensure_sandbox_overlay_template_image(&template_path, overlay_size_bytes)
            })
            .await
            .map_err(|err| format!("overlay template preparation panicked: {err}"))??;
        }

        let result = tokio::task::spawn_blocking(move || {
            prepare_sandbox_overlay_image(
                &template_path,
                &overlay_disk,
                tls_materials.as_ref(),
                sandbox_token.as_deref(),
                preparation,
                overlay_size_bytes,
            )
        })
        .await
        .map_err(|err| format!("overlay image preparation panicked: {err}"))?;
        span_status.finish(result)
    }

    fn resolved_sandbox_image(&self, sandbox: &Sandbox) -> Option<String> {
        requested_sandbox_image(sandbox)
            .map(ToOwned::to_owned)
            .or_else(|| {
                let image = self.config.default_image.trim();
                (!image.is_empty()).then(|| image.to_string())
            })
    }

    #[tracing::instrument(
        name = "vm.resolve_bootstrap_image",
        skip(self),
        fields(
            otel.name = "vm.resolve_bootstrap_image",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
            image.ref = %image_ref,
        )
    )]
    async fn ensure_cached_bootstrap_rootfs_image(
        &self,
        sandbox_id: &str,
        image_ref: &str,
    ) -> Result<String, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        if let Some((engine, image_identity)) =
            self.resolve_local_container_image(image_ref).await?
        {
            let result = self
                .ensure_cached_local_image_rootfs_image(
                    sandbox_id,
                    image_ref,
                    &engine,
                    &image_identity,
                )
                .await;
            return span_status.finish(result);
        }

        info!(image_ref = %image_ref, "vm driver: ensuring cached root disk image (registry)");
        let reference = parse_registry_reference(image_ref)?;
        let client = registry_client();
        let auth = registry_auth(image_ref)?;
        info!(image_ref = %image_ref, "vm driver: authenticating with registry");
        self.publish_vm_progress(
            sandbox_id,
            "AuthenticatingRegistry",
            format!("Authenticating registry access for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        retry_registry_request("authenticate with registry", || {
            client.auth(&reference, &auth, RegistryOperation::Pull)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
            ))
        })?;
        info!(image_ref = %image_ref, "vm driver: fetching manifest digest");
        self.publish_vm_progress(
            sandbox_id,
            "FetchingManifest",
            format!("Fetching manifest for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        let source_image_identity = retry_registry_request("fetch manifest digest", || {
            client.fetch_manifest_digest(&reference, &auth)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to resolve vm sandbox image '{image_ref}': {err}"
            ))
        })?;
        info!(
            image_ref = %image_ref,
            image_identity = %source_image_identity,
            "vm driver: manifest digest resolved"
        );
        let image_identity = bootstrap_image_cache_identity(&source_image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &image_identity);

        // Emit a driver progress hint for cache hits too and immediately
        // follow with `Pulled` so the image step still advances cleanly.
        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulling",
                format!("Pulling image \"{image_ref}\""),
            ),
        );

        if tokio::fs::metadata(&image_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                image_path = %image_path.display(),
                "vm driver: root disk image cache hit (no build needed)"
            );
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "registry".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), image_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return span_status.finish(Ok(image_identity));
        }

        info!(
            image_identity = %image_identity,
            "vm driver: root disk image cache miss, acquiring build lock"
        );
        self.publish_vm_progress(
            sandbox_id,
            "CacheMiss",
            format!("Preparing VM root disk cache for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
                ("cache_hit".to_string(), "false".to_string()),
                ("image_identity".to_string(), image_identity.clone()),
            ]),
        );
        self.publish_vm_progress(
            sandbox_id,
            "WaitingForImageCacheLock",
            "Waiting for VM image cache build lock".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_identity".to_string(), image_identity.clone()),
            ]),
        );
        let _cache_guard = self.image_cache_lock.lock().await;
        info!(
            image_identity = %image_identity,
            "vm driver: build lock acquired"
        );
        if tokio::fs::metadata(&image_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                "vm driver: root disk image cache hit after lock (built by another task)"
            );
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "registry".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), image_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return span_status.finish(Ok(image_identity));
        }

        self.build_cached_registry_image_rootfs_image(
            sandbox_id,
            &client,
            &reference,
            &auth,
            image_ref,
            &image_identity,
        )
        .await?;
        self.publish_pulled_event(sandbox_id, image_ref, &image_path)
            .await;
        span_status.finish(Ok(image_identity))
    }

    async fn resolve_local_container_image(
        &self,
        image_ref: &str,
    ) -> Result<Option<(Docker, String)>, Status> {
        let required_local_image = is_openshell_local_build_image_ref(image_ref);
        let engine = match connect_local_container_engine().await {
            Some(engine) => engine,
            None if required_local_image => {
                return Err(Status::failed_precondition(format!(
                    "no container engine (Docker/Podman) available for locally built sandbox image '{image_ref}'"
                )));
            }
            None => {
                warn!(
                    image_ref = %image_ref,
                    "vm driver: no local container engine available, falling back to registry"
                );
                return Ok(None);
            }
        };

        match engine.inspect_image(image_ref).await {
            Ok(inspect) => {
                if let Some(message) = local_image_platform_mismatch(
                    image_ref,
                    inspect.os.as_deref(),
                    inspect.architecture.as_deref(),
                ) {
                    if required_local_image {
                        return Err(Status::failed_precondition(message));
                    }
                    warn!(
                        image_ref = %image_ref,
                        %message,
                        "vm driver: local container image platform mismatch, falling back to registry"
                    );
                    return Ok(None);
                }

                let image_identity = inspect.id.filter(|id| !id.trim().is_empty()).ok_or_else(
                    || {
                        Status::failed_precondition(format!(
                            "local container image '{image_ref}' inspect response has no image ID"
                        ))
                    },
                )?;
                info!(
                    image_ref = %image_ref,
                    image_identity = %image_identity,
                    "vm driver: resolved image from local container engine"
                );
                Ok(Some((engine, image_identity)))
            }
            Err(err) if is_docker_not_found_error(&err) && required_local_image => {
                Err(Status::failed_precondition(format!(
                    "locally built sandbox image '{image_ref}' is not present in the local container engine"
                )))
            }
            Err(err) if is_docker_not_found_error(&err) => Ok(None),
            Err(err) if required_local_image => Err(Status::failed_precondition(format!(
                "failed to inspect locally built sandbox image '{image_ref}': {err}"
            ))),
            Err(err) => {
                warn!(
                    image_ref = %image_ref,
                    error = %err,
                    "vm driver: local container image inspection failed, falling back to registry"
                );
                Ok(None)
            }
        }
    }

    async fn ensure_cached_local_image_rootfs_image(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        docker: &Docker,
        image_identity: &str,
    ) -> Result<String, Status> {
        let cache_identity = bootstrap_image_cache_identity(image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &cache_identity);

        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulling",
                format!("Pulling image \"{image_ref}\""),
            ),
        );

        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for local image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "local_docker".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), cache_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return Ok(cache_identity);
        }

        self.publish_vm_progress(
            sandbox_id,
            "CacheMiss",
            format!("Preparing VM root disk cache for local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("cache_hit".to_string(), "false".to_string()),
                ("image_identity".to_string(), cache_identity.clone()),
            ]),
        );
        self.publish_vm_progress(
            sandbox_id,
            "WaitingForImageCacheLock",
            "Waiting for VM image cache build lock".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_identity".to_string(), cache_identity.clone()),
            ]),
        );
        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for local image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "local_docker".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), cache_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return Ok(cache_identity);
        }

        self.build_cached_local_image_rootfs_image(sandbox_id, docker, image_ref, &cache_identity)
            .await?;
        self.publish_pulled_event(sandbox_id, image_ref, &image_path)
            .await;
        Ok(cache_identity)
    }

    async fn ensure_prepared_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        bootstrap_root_disk: &Path,
    ) -> Result<PreparedImageDisk, Status> {
        if let Some((docker, image_identity)) =
            self.resolve_local_container_image(image_ref).await?
        {
            return self
                .ensure_prepared_local_image_disk(
                    sandbox_id,
                    image_ref,
                    &docker,
                    &image_identity,
                    bootstrap_root_disk,
                )
                .await;
        }

        self.ensure_prepared_registry_image_disk(sandbox_id, image_ref, bootstrap_root_disk)
            .await
    }

    async fn ensure_prepared_local_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        docker: &Docker,
        image_identity: &str,
        bootstrap_root_disk: &Path,
    ) -> Result<PreparedImageDisk, Status> {
        let cache_identity = prepared_image_cache_identity(image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &cache_identity);

        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "local_docker", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        self.publish_prepared_cache_miss(sandbox_id, image_ref, "local_docker", &cache_identity);
        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "local_docker", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        let staging_dir = image_cache_staging_dir(&self.config.state_dir, &cache_identity);
        let rootfs_archive = staging_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
        self.reset_image_staging_dir(&staging_dir).await?;

        self.publish_vm_progress(
            sandbox_id,
            "ExportingRootfs",
            format!("Exporting rootfs from local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), cache_identity.clone()),
            ]),
        );
        if let Err(err) =
            export_local_image_rootfs_to_path(docker, image_ref, &rootfs_archive).await
        {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(err);
        }

        let payload = GuestImagePayload {
            image_ref: image_ref.to_string(),
            image_identity: cache_identity.clone(),
            source: GuestImagePayloadSource::LocalDocker { rootfs_archive },
        };
        self.build_prepared_image_disk(
            sandbox_id,
            image_ref,
            "local_docker",
            &cache_identity,
            bootstrap_root_disk,
            &staging_dir,
            &payload,
        )
        .await?;

        Ok(PreparedImageDisk {
            image_identity: cache_identity,
            disk_path: image_path,
        })
    }

    async fn ensure_prepared_registry_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        bootstrap_root_disk: &Path,
    ) -> Result<PreparedImageDisk, Status> {
        let reference = parse_registry_reference(image_ref)?;
        let client = registry_client();
        let auth = registry_auth(image_ref)?;

        self.publish_vm_progress(
            sandbox_id,
            "AuthenticatingRegistry",
            format!("Authenticating registry access for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        retry_registry_request("authenticate with registry", || {
            client.auth(&reference, &auth, RegistryOperation::Pull)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
            ))
        })?;

        self.publish_vm_progress(
            sandbox_id,
            "FetchingManifest",
            format!("Fetching manifest for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        let source_image_identity = retry_registry_request("fetch manifest digest", || {
            client.fetch_manifest_digest(&reference, &auth)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to resolve vm sandbox image '{image_ref}': {err}"
            ))
        })?;
        let cache_identity = prepared_image_cache_identity(&source_image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &cache_identity);

        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "registry", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        self.publish_prepared_cache_miss(sandbox_id, image_ref, "registry", &cache_identity);
        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "registry", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        let staging_dir = image_cache_staging_dir(&self.config.state_dir, &cache_identity);
        self.reset_image_staging_dir(&staging_dir).await?;
        let layout_dir = staging_dir.join(GUEST_IMAGE_OCI_LAYOUT_DIR);

        let (manifest, _) = retry_registry_request("pull image manifest", || {
            client.pull_image_manifest(&reference, &auth)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to pull vm sandbox image manifest '{image_ref}': {err}"
            ))
        })?;
        tokio::fs::create_dir_all(oci_layout_blobs_dir(&layout_dir))
            .await
            .map_err(|err| Status::internal(format!("create guest OCI layout failed: {err}")))?;

        download_registry_descriptor_blob_file(
            &client,
            &reference,
            image_ref,
            &layout_dir,
            &manifest.config,
            "config",
        )
        .await?;

        let total_layers = manifest.layers.len();
        let total_bytes: i64 = manifest.layers.iter().map(|layer| layer.size.max(0)).sum();
        futures::stream::iter(manifest.layers.iter().cloned().enumerate())
            .map(|(index, layer)| {
                let client = client.clone();
                let reference = reference.clone();
                let layout_dir = layout_dir.clone();
                async move {
                    self.publish_registry_layer_progress(
                        sandbox_id,
                        image_ref,
                        &layer,
                        index,
                        total_layers,
                        total_bytes,
                    );
                    download_registry_descriptor_blob_file(
                        &client,
                        &reference,
                        image_ref,
                        &layout_dir,
                        &layer,
                        &format!("layer {}", index + 1),
                    )
                    .await
                }
            })
            .buffer_unordered(registry_layer_download_concurrency())
            .try_collect::<Vec<_>>()
            .await?;

        write_oci_layout_for_manifest(&layout_dir, GUEST_IMAGE_OCI_REF, &manifest)
            .map_err(|err| Status::internal(format!("write OCI layout failed: {err}")))?;

        let payload = GuestImagePayload {
            image_ref: image_ref.to_string(),
            image_identity: cache_identity.clone(),
            source: GuestImagePayloadSource::RegistryOciLayout { layout_dir },
        };
        self.build_prepared_image_disk(
            sandbox_id,
            image_ref,
            "registry",
            &cache_identity,
            bootstrap_root_disk,
            &staging_dir,
            &payload,
        )
        .await?;

        Ok(PreparedImageDisk {
            image_identity: cache_identity,
            disk_path: image_path,
        })
    }

    async fn reset_image_staging_dir(&self, staging_dir: &Path) -> Result<(), Status> {
        tokio::fs::create_dir_all(image_cache_root_dir(&self.config.state_dir))
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;
        if tokio::fs::metadata(staging_dir).await.is_ok() {
            tokio::fs::remove_dir_all(staging_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "remove stale image cache staging dir failed: {err}"
                    ))
                })?;
        }
        tokio::fs::create_dir_all(staging_dir).await.map_err(|err| {
            Status::internal(format!("create image cache staging dir failed: {err}"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_prepared_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        image_source: &str,
        image_identity: &str,
        bootstrap_root_disk: &Path,
        staging_dir: &Path,
        payload: &GuestImagePayload,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, image_identity);
        let prepared_image = staging_dir.join(IMAGE_CACHE_ROOTFS_IMAGE);
        tokio::fs::create_dir_all(&cache_dir).await.map_err(|err| {
            Status::internal(format!("create prepared image cache dir failed: {err}"))
        })?;

        let payload_for_size = payload.clone();
        let min_size = self
            .config
            .overlay_disk_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| Status::internal("prepared image disk size overflow"))?;
        let image_size = tokio::task::spawn_blocking(move || {
            prepared_image_disk_size_bytes(&payload_for_size, min_size)
        })
        .await
        .map_err(|err| {
            Status::internal(format!("prepared image size calculation panicked: {err}"))
        })?
        .map_err(Status::internal)?;

        let payload_for_disk = payload.clone();
        let prepared_image_for_disk = prepared_image.clone();
        self.publish_vm_progress(
            sandbox_id,
            "CreatingRootDisk",
            "Formatting prepared VM image disk".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        tokio::task::spawn_blocking(move || {
            create_image_prep_disk(&prepared_image_for_disk, image_size, &payload_for_disk)
        })
        .await
        .map_err(|err| Status::internal(format!("prepared image disk build panicked: {err}")))?
        .map_err(Status::failed_precondition)?;

        self.publish_vm_progress(
            sandbox_id,
            "PreparingRootfs",
            format!("Preparing VM image rootfs for \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        if let Err(err) = self
            .run_image_prep_vm(bootstrap_root_disk, &prepared_image, staging_dir)
            .await
        {
            let _ = tokio::fs::remove_dir_all(staging_dir).await;
            return Err(err);
        }

        if tokio::fs::metadata(&image_path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(staging_dir).await;
            return Ok(());
        }
        tokio::fs::rename(&prepared_image, &image_path)
            .await
            .map_err(|err| Status::internal(format!("store prepared image disk failed: {err}")))?;
        let _ = tokio::fs::remove_dir_all(staging_dir).await;
        Ok(())
    }

    async fn run_image_prep_vm(
        &self,
        bootstrap_root_disk: &Path,
        prep_disk: &Path,
        run_dir: &Path,
    ) -> Result<(), Status> {
        let console_output = run_dir.join("image-prep-console.log");
        let mut command = Command::new(&self.launcher_bin);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--internal-run-vm");
        command.arg("--vm-root-disk").arg(bootstrap_root_disk);
        command.arg("--vm-overlay-disk").arg(prep_disk);
        command.arg("--vm-exec").arg(sandbox_guest_init_path());
        command.arg("--vm-workdir").arg("/");
        command.arg("--vm-console-output").arg(&console_output);
        command.arg("--vm-vcpus").arg(self.config.vcpus.to_string());
        command
            .arg("--vm-mem-mib")
            .arg(self.config.mem_mib.to_string());
        command
            .arg("--vm-krun-log-level")
            .arg(self.config.krun_log_level.to_string());
        command
            .arg("--vm-env")
            .arg(format!("OPENSHELL_VM_INIT_MODE={IMAGE_PREP_INIT_MODE}"));

        let mut child = command
            .spawn()
            .map_err(|err| Status::internal(format!("failed to run image-prep vm: {err}")))?;
        let status = child
            .wait()
            .await
            .map_err(|err| Status::internal(format!("failed to wait for image-prep vm: {err}")))?;
        if status.success() {
            return Ok(());
        }
        let console = tokio::fs::read_to_string(&console_output)
            .await
            .unwrap_or_default();
        Err(Status::failed_precondition(format!(
            "image-prep vm exited with status {status}: {console}"
        )))
    }

    fn publish_prepared_cache_hit(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        image_source: &str,
        image_identity: &str,
    ) {
        self.publish_vm_progress(
            sandbox_id,
            "CacheHit",
            format!("Using cached prepared VM image disk for \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("cache_hit".to_string(), "true".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
    }

    fn publish_prepared_cache_miss(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        image_source: &str,
        image_identity: &str,
    ) {
        self.publish_vm_progress(
            sandbox_id,
            "CacheMiss",
            format!("Preparing VM image disk cache for \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("cache_hit".to_string(), "false".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
    }

    #[allow(clippy::similar_names)]
    async fn build_cached_local_image_rootfs_image(
        &self,
        sandbox_id: &str,
        docker: &Docker,
        image_ref: &str,
        image_identity: &str,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, image_identity);
        let staging_dir = image_cache_staging_dir(&self.config.state_dir, image_identity);
        let exported_rootfs = staging_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
        let prepared_rootfs = staging_dir.join("rootfs");
        let prepared_image = staging_dir.join(IMAGE_CACHE_ROOTFS_IMAGE);

        tokio::fs::create_dir_all(image_cache_root_dir(&self.config.state_dir))
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;

        if tokio::fs::metadata(&staging_dir).await.is_ok() {
            tokio::fs::remove_dir_all(&staging_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "remove stale image cache staging dir failed: {err}"
                    ))
                })?;
        }
        tokio::fs::create_dir_all(&staging_dir)
            .await
            .map_err(|err| {
                Status::internal(format!("create image cache staging dir failed: {err}"))
            })?;

        self.publish_vm_progress(
            sandbox_id,
            "ExportingRootfs",
            format!("Exporting rootfs from local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        if let Err(err) =
            export_local_image_rootfs_to_path(docker, image_ref, &exported_rootfs).await
        {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(err);
        }

        let image_ref_owned = image_ref.to_string();
        let image_identity_owned = image_identity.to_string();
        let exported_rootfs_for_build = exported_rootfs.clone();
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let sandbox_uid = self.config.resolve_sandbox_uid();
        let sandbox_gid = self.config.resolve_sandbox_gid(sandbox_uid);
        self.publish_vm_progress(
            sandbox_id,
            "PreparingRootfs",
            format!(
                "Preparing VM rootfs for local image \"{image_ref}\" (sandbox uid={sandbox_uid})"
            ),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
                ("sandbox_uid".to_string(), sandbox_uid.to_string()),
            ]),
        );
        let prepare_result = tokio::task::spawn_blocking(move || {
            extract_rootfs_archive_to(&exported_rootfs_for_build, &prepared_rootfs_for_build)?;
            prepare_sandbox_rootfs_from_image_root(
                &prepared_rootfs_for_build,
                &image_identity_owned,
                sandbox_uid,
                sandbox_gid,
            )
            .map_err(|err| {
                format!("vm sandbox image '{image_ref_owned}' is not base-compatible: {err}")
            })
        })
        .await
        .map_err(|err| Status::internal(format!("local image preparation panicked: {err}")))?;

        if let Err(err) = prepare_result {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        self.publish_vm_progress(
            sandbox_id,
            "CreatingRootDisk",
            "Formatting VM root disk image".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let prepared_image_for_build = prepared_image.clone();
        let build_result = tokio::task::spawn_blocking(move || {
            create_rootfs_image_from_dir(&prepared_rootfs_for_build, &prepared_image_for_build)
        })
        .await
        .map_err(|err| Status::internal(format!("rootfs image build panicked: {err}")))?;

        if let Err(err) = build_result {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        if tokio::fs::metadata(&image_path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Ok(());
        }

        tokio::fs::rename(&prepared_image, &image_path)
            .await
            .map_err(|err| Status::internal(format!("store cached rootfs image failed: {err}")))?;
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        Ok(())
    }

    #[allow(clippy::similar_names)]
    async fn build_cached_registry_image_rootfs_image(
        &self,
        sandbox_id: &str,
        client: &OciClient,
        reference: &Reference,
        auth: &RegistryAuth,
        image_ref: &str,
        image_identity: &str,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, image_identity);
        let staging_dir = image_cache_staging_dir(&self.config.state_dir, image_identity);
        let prepared_rootfs = staging_dir.join("rootfs");
        let prepared_image = staging_dir.join(IMAGE_CACHE_ROOTFS_IMAGE);

        tokio::fs::create_dir_all(image_cache_root_dir(&self.config.state_dir))
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;

        if tokio::fs::metadata(&staging_dir).await.is_ok() {
            tokio::fs::remove_dir_all(&staging_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "remove stale image cache staging dir failed: {err}"
                    ))
                })?;
        }
        tokio::fs::create_dir_all(&staging_dir)
            .await
            .map_err(|err| {
                Status::internal(format!("create image cache staging dir failed: {err}"))
            })?;

        info!(
            image_ref = %image_ref,
            staging_dir = %staging_dir.display(),
            "vm driver: pulling registry image layers"
        );
        if let Err(err) = self
            .pull_registry_image_rootfs(
                sandbox_id,
                client,
                reference,
                auth,
                image_ref,
                &staging_dir,
                &prepared_rootfs,
            )
            .await
        {
            warn!(
                image_ref = %image_ref,
                error = %err.message(),
                "vm driver: pull_registry_image_rootfs failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(err);
        }
        info!(
            image_ref = %image_ref,
            "vm driver: image layers pulled, preparing rootfs image"
        );

        let image_ref_owned = image_ref.to_string();
        let image_identity_owned = image_identity.to_string();
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let sandbox_uid = self.config.resolve_sandbox_uid();
        let sandbox_gid = self.config.resolve_sandbox_gid(sandbox_uid);
        self.publish_vm_progress(
            sandbox_id,
            "PreparingRootfs",
            format!("Preparing VM rootfs for image \"{image_ref}\" (sandbox uid={sandbox_uid})"),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
                ("sandbox_uid".to_string(), sandbox_uid.to_string()),
            ]),
        );
        let prepare_result = tokio::task::spawn_blocking(move || {
            prepare_sandbox_rootfs_from_image_root(
                &prepared_rootfs_for_build,
                &image_identity_owned,
                sandbox_uid,
                sandbox_gid,
            )
            .map_err(|err| {
                format!("vm sandbox image '{image_ref_owned}' is not base-compatible: {err}")
            })
        })
        .await
        .map_err(|err| Status::internal(format!("image rootfs preparation panicked: {err}")))?;

        if let Err(err) = prepare_result {
            warn!(
                image_ref = %image_ref,
                error = %err,
                "vm driver: rootfs preparation failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        self.publish_vm_progress(
            sandbox_id,
            "CreatingRootDisk",
            "Formatting VM root disk image".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let prepared_image_for_build = prepared_image.clone();
        let build_result = tokio::task::spawn_blocking(move || {
            create_rootfs_image_from_dir(&prepared_rootfs_for_build, &prepared_image_for_build)
        })
        .await
        .map_err(|err| Status::internal(format!("image rootfs build panicked: {err}")))?;

        if let Err(err) = build_result {
            warn!(
                image_ref = %image_ref,
                error = %err,
                "vm driver: rootfs image build failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        if tokio::fs::metadata(&image_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                "vm driver: another task wrote image while we were building, discarding ours"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Ok(());
        }

        tokio::fs::rename(&prepared_image, &image_path)
            .await
            .map_err(|err| Status::internal(format!("store cached rootfs image failed: {err}")))?;
        info!(
            image_identity = %image_identity,
            image_path = %image_path.display(),
            "vm driver: root disk image committed to cache"
        );
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        Ok(())
    }

    /// Watch the launcher child process and surface errors as driver
    /// conditions.
    ///
    /// The driver no longer owns the `Ready` transition — the gateway
    /// promotes a sandbox to `Ready` the moment its supervisor session
    /// lands (see `openshell-server/src/compute/mod.rs`). This loop only
    /// handles the sad paths: the child process failing to start, exiting
    /// abnormally, or becoming unpollable. Those still surface as driver
    /// `Error` conditions so the gateway can reason about a dead VM.
    async fn monitor_sandbox(&self, sandbox_id: String) {
        loop {
            let process = {
                let registry = self.registry.lock().await;
                let Some(record) = registry.get(&sandbox_id) else {
                    return;
                };
                let Some(process) = record.process.as_ref() else {
                    return;
                };
                process.clone()
            };

            let exit_status = {
                let mut process = process.lock().await;
                if process.deleting {
                    return;
                }
                match process.child.try_wait() {
                    Ok(status) => status,
                    Err(err) => {
                        if let Some(snapshot) = self
                            .set_snapshot_condition(
                                &sandbox_id,
                                error_condition("ProcessPollFailed", &err.to_string()),
                                false,
                            )
                            .await
                        {
                            self.publish_snapshot(snapshot);
                        }
                        self.publish_platform_event(
                            sandbox_id.clone(),
                            platform_event(
                                "vm",
                                "Warning",
                                "ProcessPollFailed",
                                format!("Failed to poll VM helper process: {err}"),
                            ),
                        );
                        return;
                    }
                }
            };

            if let Some(status) = exit_status {
                let state_dir = {
                    let registry = self.registry.lock().await;
                    registry
                        .get(&sandbox_id)
                        .map(|record| record.state_dir.clone())
                };
                if let Some(state_dir) = state_dir
                    && let Err(error) = write_private_file(
                        &state_dir.join(MAIN_PROCESS_EXITED_FILE),
                        b"terminal\n".to_vec(),
                    )
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        %error,
                        "vm driver: failed to persist canonical-process exit tombstone"
                    );
                }
                let message = status.code().map_or_else(
                    || "VM process exited".to_string(),
                    |code| format!("VM process exited with status {code}"),
                );
                if let Some(snapshot) = self
                    .set_snapshot_condition(
                        &sandbox_id,
                        error_condition("ProcessExited", &message),
                        false,
                    )
                    .await
                {
                    self.publish_snapshot(snapshot);
                }
                self.publish_platform_event(
                    sandbox_id.clone(),
                    platform_event("vm", "Warning", "ProcessExited", message),
                );
                let (has_gpu, has_qemu_network, cleanup_ctx) = {
                    let registry = self.registry.lock().await;
                    registry
                        .get(&sandbox_id)
                        .map_or((false, false, None), |record| {
                            (
                                record.gpu_bdf.is_some(),
                                record.qemu_network_allocated,
                                Some((record.snapshot.clone(), record.state_dir.clone())),
                            )
                        })
                };
                // Give lifecycle extensions a chance to release host
                // resources they allocated in `before_launch` (e.g. device
                // bindings, OVS flows). The driver releases its own
                // allocations just below; without this, extension-owned
                // resources would leak whenever a VM helper exits without an
                // explicit delete. Cleanup is best-effort and idempotent, so
                // a later delete that also fires `after_delete` is safe.
                if let Some((sandbox, state_dir)) = cleanup_ctx {
                    self.lifecycle_extensions
                        .after_launch_failed(&sandbox, &state_dir, LaunchAbortReason::ProcessExited)
                        .await;
                }
                self.release_allocations(&sandbox_id, has_gpu, has_qemu_network);
                return;
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn set_snapshot_condition(
        &self,
        sandbox_id: &str,
        condition: SandboxCondition,
        deleting: bool,
    ) -> Option<Sandbox> {
        let mut registry = self.registry.lock().await;
        let record = registry.get_mut(sandbox_id)?;
        record.snapshot.status = Some(status_with_condition(&record.snapshot, condition, deleting));
        Some(record.snapshot.clone())
    }

    fn publish_snapshot(&self, sandbox: Sandbox) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                WatchSandboxesSandboxEvent {
                    sandbox: Some(sandbox),
                },
            )),
        });
    }

    fn publish_deleted(&self, sandbox_id: String) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Deleted(
                WatchSandboxesDeletedEvent { sandbox_id },
            )),
        });
    }

    fn publish_platform_event(&self, sandbox_id: String, event: PlatformEvent) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
                WatchSandboxesPlatformEvent {
                    sandbox_id,
                    event: Some(event),
                },
            )),
        });
    }

    fn publish_vm_progress(
        &self,
        sandbox_id: &str,
        reason: &str,
        message: String,
        metadata: HashMap<String, String>,
    ) {
        let mut event = platform_event("vm", "Normal", reason, message);
        event.metadata = metadata;
        attach_vm_progress_metadata(&mut event);
        self.publish_platform_event(sandbox_id.to_string(), event);
    }
}

#[tonic::async_trait]
impl ComputeDriver for VmDriver {
    async fn authenticate_sandbox(
        &self,
        _request: Request<openshell_core::proto::compute::v1::AuthenticateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::compute::v1::AuthenticateSandboxResponse>, Status>
    {
        Err(Status::unimplemented(
            "VM driver does not authenticate sandbox credentials",
        ))
    }

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(self.capabilities()))
    }

    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements: Vec::new(),
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.validate_sandbox(&sandbox)?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        let response = self.create_sandbox(&sandbox).await?;
        Ok(Response::new(response))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() && request.sandbox_name.is_empty() {
            return Err(Status::invalid_argument(
                "sandbox_id or sandbox_name is required",
            ));
        }

        let sandbox = self
            .get_sandbox(&request.sandbox_id, &request.sandbox_name)
            .await?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        if !request.sandbox_id.is_empty() && request.sandbox_id != sandbox.id {
            return Err(Status::failed_precondition(
                "sandbox_id did not match the fetched sandbox",
            ));
        }

        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse {
            sandboxes: self.current_snapshots().await,
        }))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let request = request.into_inner();
        self.stop_sandbox(&request.sandbox_id, &request.sandbox_name)
            .await?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let request = request.into_inner();
        self.start_sandbox(&request.sandbox_id, &request.sandbox_name)
            .await?;
        Ok(Response::new(StartSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        let response = self
            .delete_sandbox(&request.sandbox_id, &request.sandbox_name)
            .await?;
        Ok(Response::new(response))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let initial = self.current_snapshots().await;
        let mut rx = self.events.subscribe();
        let (tx, out_rx) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            let mut sent = HashSet::new();
            for sandbox in initial {
                sent.insert(sandbox.id.clone());
                if tx
                    .send(Ok(WatchSandboxesEvent {
                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                            WatchSandboxesSandboxEvent {
                                sandbox: Some(sandbox),
                            },
                        )),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }

            loop {
                let event = tokio::select! {
                    () = tx.closed() => return,
                    event = rx.recv() => event,
                };
                match event {
                    Ok(event) => {
                        if let Some(watch_sandboxes_event::Payload::Sandbox(sandbox_event)) =
                            &event.payload
                            && let Some(sandbox) = &sandbox_event.sandbox
                            && !sent.insert(sandbox.id.clone())
                        {
                            // duplicate snapshots are still forwarded
                        }
                        if tx.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        let stream: Self::WatchSandboxesStream = Box::pin(ReceiverStream::new(out_rx));
        Ok(Response::new(stream))
    }

    async fn ensure_workspace(
        &self,
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Ok(Response::new(EnsureWorkspaceResponse {}))
    }

    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Ok(Response::new(DeleteWorkspaceResponse {}))
    }
}

#[cfg(target_os = "linux")]
fn check_gpu_privileges() -> Result<(), String> {
    if !rustix::process::geteuid().is_root() {
        return Err(
            "GPU support requires root privileges for VFIO bind/unbind and TAP networking. \
             Run with sudo or ensure CAP_SYS_ADMIN + CAP_NET_ADMIN capabilities are set."
                .to_string(),
        );
    }
    Ok(())
}

// `tonic::Status` is ~176 bytes; it's the standard error type across the
// gRPC API surface, so boxing here would diverge from every other handler.
#[allow(clippy::result_large_err)]
fn validate_vm_sandbox(sandbox: &Sandbox, gpu_enabled: bool) -> Result<(), Status> {
    validate_sandbox_id(&sandbox.id)?;

    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;

    if let Some(template) = spec.template.as_ref() {
        validate_vm_sandbox_template(template)?;
    }
    validate_gpu_request(sandbox, gpu_enabled)?;

    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_vm_sandbox_template(template: &SandboxTemplate) -> Result<(), Status> {
    if !template.agent_socket_path.is_empty() {
        return Err(Status::failed_precondition(
            "vm sandboxes do not support template.agent_socket_path",
        ));
    }
    if template.platform_config.is_some() {
        return Err(Status::failed_precondition(
            "vm sandboxes do not support template.platform_config",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_gpu_request(sandbox: &Sandbox, gpu_enabled: bool) -> Result<(), Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;

    let gpu_requirements = driver_gpu_requirements(spec.resource_requirements.as_ref());
    let gpu_count =
        effective_driver_gpu_count(gpu_requirements).map_err(Status::invalid_argument)?;

    if gpu_requirements.is_some() && !gpu_enabled {
        return Err(Status::failed_precondition(
            "GPU support is not enabled on this driver; start with --gpu",
        ));
    }

    let _ = vm_gpu_device_id(sandbox)?;

    if gpu_count.is_some_and(|count| count > 1) {
        return Err(Status::invalid_argument(
            "VM GPU sandboxes support only one GPU",
        ));
    }

    Ok(())
}

#[allow(clippy::result_large_err)]
fn vm_gpu_device_id(sandbox: &Sandbox) -> Result<Option<String>, Status> {
    let Some(spec) = sandbox.spec.as_ref() else {
        return Ok(None);
    };
    let gpu_device_ids = VmSandboxDriverConfig::from_sandbox(sandbox)
        .map_err(Status::invalid_argument)?
        .gpu_device_ids
        .unwrap_or_default();
    let gpu_requirements = driver_gpu_requirements(spec.resource_requirements.as_ref());
    validate_specific_gpu_device_request(
        gpu_requirements,
        &gpu_device_ids,
        "driver_config.gpu_device_ids",
    )
    .map_err(Status::invalid_argument)?;
    if gpu_device_ids.len() > 1 {
        return Err(Status::invalid_argument(
            "vm driver currently supports at most one gpu_device_ids entry",
        ));
    }

    Ok(gpu_requirements
        .is_some()
        .then(|| gpu_device_ids.into_iter().next().unwrap_or_default()))
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_id(sandbox_id: &str) -> Result<(), Status> {
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox id is required"));
    }
    if sandbox_id.len() > 128 {
        return Err(Status::invalid_argument(
            "sandbox id exceeds maximum length (128 bytes)",
        ));
    }
    if matches!(sandbox_id, "." | "..") {
        return Err(Status::invalid_argument(
            "sandbox id must match [A-Za-z0-9._-]{1,128}",
        ));
    }
    if !sandbox_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Status::invalid_argument(
            "sandbox id must match [A-Za-z0-9._-]{1,128}",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn parse_registry_reference(image_ref: &str) -> Result<Reference, Status> {
    Reference::try_from(image_ref).map_err(|err| {
        Status::failed_precondition(format!(
            "invalid vm sandbox image reference '{image_ref}': {err}"
        ))
    })
}

/// Try to connect to a local container engine (Docker or Podman).
///
/// Tries Docker first (`connect_with_local_defaults`, which respects
/// `DOCKER_HOST`). If Docker is unavailable, falls back to the Podman
/// socket, which exposes a Docker-compatible API.
async fn connect_local_container_engine() -> Option<Docker> {
    if let Ok(docker) = Docker::connect_with_local_defaults()
        && docker.ping().await.is_ok()
    {
        return Some(docker);
    }

    let podman_socket = detect_podman_socket()?;
    if let Ok(docker) =
        Docker::connect_with_unix(podman_socket.to_str()?, 120, bollard::API_DEFAULT_VERSION)
        && docker.ping().await.is_ok()
    {
        info!(
            socket = %podman_socket.display(),
            "vm driver: connected to Podman (Docker-compatible API)"
        );
        return Some(docker);
    }

    None
}

fn detect_podman_socket() -> Option<PathBuf> {
    openshell_driver_podman::driver::detect_socket()
}

fn is_openshell_local_build_image_ref(image_ref: &str) -> bool {
    image_ref.starts_with("openshell/sandbox-from:")
}

fn local_image_platform_mismatch(
    image_ref: &str,
    actual_os: Option<&str>,
    actual_arch: Option<&str>,
) -> Option<String> {
    let actual_os = actual_os.unwrap_or("unknown");
    let actual_arch = actual_arch.unwrap_or("unknown");
    let expected_os = "linux";
    let expected_arch = linux_oci_arch();

    (actual_os != expected_os || actual_arch != expected_arch).then(|| {
        format!(
            "local Docker image '{image_ref}' is {actual_os}/{actual_arch}, but VM sandboxes require {expected_os}/{expected_arch}"
        )
    })
}

fn is_docker_not_found_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

async fn export_local_image_rootfs_to_path(
    docker: &Docker,
    image_ref: &str,
    tar_path: &Path,
) -> Result<(), Status> {
    let container_name = format!(
        "openshell-vm-rootfs-export-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let create_options = CreateContainerOptionsBuilder::default()
        .name(container_name.as_str())
        .build();
    let container = docker
        .create_container(
            Some(create_options),
            ContainerCreateBody {
                image: Some(image_ref.to_string()),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to create temporary export container for local Docker image '{image_ref}': {err}"
            ))
        })?;
    let container_id = container.id;

    let export_result = async {
        if let Some(parent) = tar_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                Status::internal(format!(
                    "create export dir {} failed: {err}",
                    parent.display()
                ))
            })?;
        }
        let mut file = tokio::fs::File::create(tar_path).await.map_err(|err| {
            Status::internal(format!("create {} failed: {err}", tar_path.display()))
        })?;
        let mut stream = docker.export_container(&container_id);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to export local Docker image '{image_ref}': {err}"
                ))
            })?;
            file.write_all(&chunk).await.map_err(|err| {
                Status::internal(format!("write {} failed: {err}", tar_path.display()))
            })?;
        }
        file.flush()
            .await
            .map_err(|err| Status::internal(format!("flush {} failed: {err}", tar_path.display())))
    }
    .await;

    let cleanup_result = docker
        .remove_container(
            &container_id,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await;

    match (export_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(Status::internal(format!(
            "failed to remove temporary export container for local Docker image '{image_ref}': {err}"
        ))),
    }
}

fn registry_client() -> OciClient {
    OciClient::new(ClientConfig {
        platform_resolver: Some(Box::new(linux_platform_resolver)),
        ..Default::default()
    })
}

async fn retry_registry_request<T, F, Fut>(
    operation: &str,
    request: F,
) -> Result<T, OciDistributionError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OciDistributionError>>,
{
    retry_registry_request_with_delay(operation, REGISTRY_RETRY_INITIAL_DELAY, request).await
}

async fn retry_registry_request_with_delay<T, F, Fut>(
    operation: &str,
    initial_delay: Duration,
    mut request: F,
) -> Result<T, OciDistributionError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OciDistributionError>>,
{
    let mut delay = initial_delay;
    for attempt in 1..=REGISTRY_REQUEST_MAX_ATTEMPTS {
        match request().await {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt < REGISTRY_REQUEST_MAX_ATTEMPTS && registry_error_is_retryable(&err) =>
            {
                warn!(
                    operation,
                    attempt,
                    max_attempts = REGISTRY_REQUEST_MAX_ATTEMPTS,
                    retry_delay_ms = delay.as_millis(),
                    error = %err,
                    "vm driver: transient registry request failed; retrying"
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(REGISTRY_RETRY_MAX_DELAY);
            }
            Err(err) => return Err(err),
        }
    }

    unreachable!("registry request retry loop always returns")
}

fn registry_error_is_retryable(err: &OciDistributionError) -> bool {
    match err {
        OciDistributionError::AuthenticationFailure(message) => {
            registry_message_is_retryable(message)
        }
        OciDistributionError::RegistryError { envelope, .. } => {
            envelope.errors.iter().any(|error| {
                error.code == OciErrorCode::Toomanyrequests
                    || registry_message_is_retryable(&error.message)
            })
        }
        OciDistributionError::RequestError(err) => {
            err.is_connect()
                || err.is_timeout()
                || err
                    .status()
                    .is_some_and(|status| matches!(status.as_u16(), 408 | 425 | 429 | 500..=599))
        }
        OciDistributionError::ServerError { code, message, .. } => {
            matches!(code, 408 | 425 | 429 | 500..=599) || registry_message_is_retryable(message)
        }
        OciDistributionError::IoError(err) => matches!(
            err.kind(),
            std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::WouldBlock
        ),
        _ => false,
    }
}

fn registry_message_is_retryable(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("retry-after")
        || message.contains("too many requests")
        || message.contains("rate limit")
}

enum RegistryBlobPullError {
    CreateFile(std::io::Error),
    Registry(OciDistributionError),
}

async fn pull_registry_blob_file(
    operation: &str,
    client: &OciClient,
    reference: &Reference,
    descriptor: &OciDescriptor,
    blob_path: &Path,
) -> Result<tokio::fs::File, RegistryBlobPullError> {
    let mut delay = REGISTRY_RETRY_INITIAL_DELAY;
    for attempt in 1..=REGISTRY_REQUEST_MAX_ATTEMPTS {
        let mut file = tokio::fs::File::create(blob_path)
            .await
            .map_err(RegistryBlobPullError::CreateFile)?;
        match client.pull_blob(reference, descriptor, &mut file).await {
            Ok(()) => return Ok(file),
            Err(err)
                if attempt < REGISTRY_REQUEST_MAX_ATTEMPTS && registry_error_is_retryable(&err) =>
            {
                warn!(
                    operation,
                    attempt,
                    max_attempts = REGISTRY_REQUEST_MAX_ATTEMPTS,
                    retry_delay_ms = delay.as_millis(),
                    error = %err,
                    "vm driver: transient registry request failed; retrying"
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(REGISTRY_RETRY_MAX_DELAY);
            }
            Err(err) => return Err(RegistryBlobPullError::Registry(err)),
        }
    }

    unreachable!("registry blob retry loop always returns")
}

fn linux_platform_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    let expected_arch = linux_oci_arch();
    manifests
        .iter()
        .find_map(|entry| {
            let platform = entry.platform.as_ref()?;
            (platform.os.to_string() == "linux"
                && platform.architecture.to_string() == expected_arch)
                .then(|| entry.digest.clone())
        })
        .or_else(|| {
            manifests.iter().find_map(|entry| {
                let platform = entry.platform.as_ref()?;
                (platform.os.to_string() == "linux").then(|| entry.digest.clone())
            })
        })
}

fn linux_oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        other => other,
    }
}

#[allow(clippy::result_large_err)]
fn registry_auth(image_ref: &str) -> Result<RegistryAuth, Status> {
    let username = env_non_empty("OPENSHELL_REGISTRY_USERNAME");
    let token = env_non_empty("OPENSHELL_REGISTRY_TOKEN");

    match token {
        Some(token) => {
            let username = match username {
                Some(username) => username,
                None if image_reference_registry_host(image_ref)
                    .eq_ignore_ascii_case("ghcr.io") =>
                {
                    "__token__".to_string()
                }
                None => {
                    return Err(Status::failed_precondition(
                        "OPENSHELL_REGISTRY_USERNAME is required when OPENSHELL_REGISTRY_TOKEN is set for non-GHCR registries",
                    ));
                }
            };
            Ok(RegistryAuth::Basic(username, token))
        }
        None => Ok(RegistryAuth::Anonymous),
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn image_reference_registry_host(image_ref: &str) -> &str {
    let mut parts = image_ref.splitn(2, '/');
    let first = parts.next().unwrap_or(image_ref);
    let has_path = parts.next().is_some();
    if has_path
        && (first.contains('.') || first.contains(':') || first.eq_ignore_ascii_case("localhost"))
    {
        first
    } else {
        "docker.io"
    }
}

impl VmDriver {
    #[allow(clippy::too_many_arguments)]
    async fn pull_registry_image_rootfs(
        &self,
        sandbox_id: &str,
        client: &OciClient,
        reference: &Reference,
        auth: &RegistryAuth,
        image_ref: &str,
        staging_dir: &Path,
        rootfs: &Path,
    ) -> Result<(), Status> {
        retry_registry_request("authenticate with registry", || {
            client.auth(reference, auth, RegistryOperation::Pull)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
            ))
        })?;
        let (manifest, _) = retry_registry_request("pull image manifest", || {
            client.pull_image_manifest(reference, auth)
        })
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to pull vm sandbox image manifest '{image_ref}': {err}"
            ))
        })?;

        tokio::fs::create_dir_all(rootfs)
            .await
            .map_err(|err| Status::internal(format!("create rootfs dir failed: {err}")))?;
        tokio::fs::create_dir_all(staging_dir.join("layers"))
            .await
            .map_err(|err| Status::internal(format!("create layer staging dir failed: {err}")))?;

        let total_layers = manifest.layers.len();
        let total_bytes: i64 = manifest.layers.iter().map(|layer| layer.size.max(0)).sum();
        let mut layers = futures::stream::iter(manifest.layers.iter().cloned().enumerate())
            .map(|(index, layer)| async move {
                self.publish_registry_layer_progress(
                    sandbox_id,
                    image_ref,
                    &layer,
                    index,
                    total_layers,
                    total_bytes,
                );
                download_registry_layer_blob(
                    client,
                    reference,
                    image_ref,
                    staging_dir,
                    layer,
                    index,
                )
                .await
            })
            .buffer_unordered(registry_layer_download_concurrency())
            .try_collect::<Vec<_>>()
            .await?;
        layers.sort_by_key(|layer| layer.index);

        for layer in &layers {
            apply_registry_layer_blob(image_ref, rootfs, layer).await?;
        }

        remove_registry_layer_staging(staging_dir).await?;

        Ok(())
    }

    fn publish_registry_layer_progress(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        layer: &OciDescriptor,
        index: usize,
        total_layers: usize,
        total_bytes: i64,
    ) {
        let mut metadata = HashMap::new();
        metadata.insert("layer_index".to_string(), (index + 1).to_string());
        metadata.insert("layer_total".to_string(), total_layers.to_string());
        metadata.insert("layer_digest".to_string(), layer.digest.clone());
        metadata.insert("layer_size_bytes".to_string(), layer.size.to_string());
        metadata.insert("image_ref".to_string(), image_ref.to_string());
        if total_bytes > 0 {
            metadata.insert("image_size_bytes".to_string(), total_bytes.to_string());
        }
        let mut event = platform_event(
            "vm",
            "Normal",
            "PullingLayer",
            format!(
                "Pulling layer {}/{} ({} bytes) for image \"{image_ref}\"",
                index + 1,
                total_layers,
                layer.size
            ),
        );
        event.metadata = metadata;
        attach_vm_progress_metadata(&mut event);
        self.publish_platform_event(sandbox_id.to_string(), event);
    }

    /// Emit a `Pulled` platform event with progress metadata for the CLI.
    async fn publish_pulled_event(&self, sandbox_id: &str, image_ref: &str, image_path: &Path) {
        let mut metadata = HashMap::from([("image_ref".to_string(), image_ref.to_string())]);
        let size_suffix = tokio::fs::metadata(image_path).await.map_or_else(
            |_| String::new(),
            |meta| {
                metadata.insert("image_size_bytes".to_string(), meta.len().to_string());
                format!(" Image size: {} bytes.", meta.len())
            },
        );
        self.publish_vm_progress(
            sandbox_id,
            "Pulled",
            format!("Successfully pulled image \"{image_ref}\".{size_suffix}"),
            metadata,
        );
    }
}

struct DownloadedRegistryLayer {
    index: usize,
    digest: String,
    layer_root: PathBuf,
}

async fn download_registry_layer_blob(
    client: &OciClient,
    reference: &Reference,
    image_ref: &str,
    staging_dir: &Path,
    layer: OciDescriptor,
    index: usize,
) -> Result<DownloadedRegistryLayer, Status> {
    let digest_component = sanitize_image_identity(&layer.digest);
    let blob_path = staging_dir
        .join("layers")
        .join(format!("{index:02}-{digest_component}.blob"));
    let layer_root = staging_dir
        .join("layers")
        .join(format!("{index:02}-{digest_component}.root"));

    let mut file = pull_registry_blob_file(
        "download image layer",
        client,
        reference,
        &layer,
        &blob_path,
    )
    .await
    .map_err(|err| match err {
        RegistryBlobPullError::CreateFile(err) => {
            Status::internal(format!("create layer blob failed: {err}"))
        }
        RegistryBlobPullError::Registry(err) => Status::failed_precondition(format!(
            "failed to download layer '{}' for vm sandbox image '{image_ref}': {err}",
            layer.digest
        )),
    })?;
    file.flush()
        .await
        .map_err(|err| Status::internal(format!("flush layer blob failed: {err}")))?;

    let blob_path_for_digest = blob_path.clone();
    let expected_digest = layer.digest.clone();
    tokio::task::spawn_blocking(move || {
        verify_descriptor_digest(&blob_path_for_digest, &expected_digest)
    })
    .await
    .map_err(|err| Status::internal(format!("layer digest verification panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "vm sandbox image layer verification failed for '{}': {err}",
            layer.digest
        ))
    })?;

    let blob_path_for_unpack = blob_path.clone();
    let layer_root_for_unpack = layer_root.clone();
    let media_type = layer.media_type.clone();
    tokio::task::spawn_blocking(move || {
        extract_layer_blob_to_dir(&blob_path_for_unpack, &media_type, &layer_root_for_unpack)
    })
    .await
    .map_err(|err| Status::internal(format!("layer extraction panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "failed to extract layer '{}' for vm sandbox image '{image_ref}': {err}",
            layer.digest
        ))
    })?;

    Ok(DownloadedRegistryLayer {
        index,
        digest: layer.digest,
        layer_root,
    })
}

async fn apply_registry_layer_blob(
    image_ref: &str,
    rootfs: &Path,
    layer: &DownloadedRegistryLayer,
) -> Result<(), Status> {
    let layer_root_for_unpack = layer.layer_root.clone();
    let rootfs_for_unpack = rootfs.to_path_buf();
    tokio::task::spawn_blocking(move || {
        apply_layer_dir_to_rootfs(&layer_root_for_unpack, &rootfs_for_unpack)
    })
    .await
    .map_err(|err| Status::internal(format!("layer application panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "failed to apply layer '{}' for vm sandbox image '{image_ref}': {err}",
            layer.digest
        ))
    })
}

async fn remove_registry_layer_staging(staging_dir: &Path) -> Result<(), Status> {
    let layers_dir = staging_dir.join("layers");
    tokio::fs::remove_dir_all(&layers_dir).await.map_err(|err| {
        Status::internal(format!(
            "remove registry layer staging dir '{}' failed: {err}",
            layers_dir.display()
        ))
    })
}

async fn download_registry_descriptor_blob_file(
    client: &OciClient,
    reference: &Reference,
    image_ref: &str,
    layout_dir: &Path,
    descriptor: &OciDescriptor,
    kind: &str,
) -> Result<(), Status> {
    let blob_path = oci_layout_blob_path(layout_dir, &descriptor.digest)
        .map_err(|err| Status::failed_precondition(format!("invalid {kind} digest: {err}")))?;
    if let Some(parent) = blob_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| Status::internal(format!("create OCI blob dir failed: {err}")))?;
    }

    let mut file = pull_registry_blob_file(
        "download image blob",
        client,
        reference,
        descriptor,
        &blob_path,
    )
    .await
    .map_err(|err| match err {
        RegistryBlobPullError::CreateFile(err) => {
            Status::internal(format!("create OCI {kind} blob failed: {err}"))
        }
        RegistryBlobPullError::Registry(err) => Status::failed_precondition(format!(
            "failed to download {kind} '{}' for vm sandbox image '{image_ref}': {err}",
            descriptor.digest
        )),
    })?;
    file.flush()
        .await
        .map_err(|err| Status::internal(format!("flush OCI {kind} blob failed: {err}")))?;

    let blob_path_for_digest = blob_path.clone();
    let expected_digest = descriptor.digest.clone();
    tokio::task::spawn_blocking(move || {
        verify_descriptor_digest(&blob_path_for_digest, &expected_digest)
    })
    .await
    .map_err(|err| Status::internal(format!("OCI {kind} digest verification panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "vm sandbox image {kind} verification failed for '{}': {err}",
            descriptor.digest
        ))
    })
}

fn verify_descriptor_digest(path: &Path, expected_digest: &str) -> Result<(), String> {
    let expected = expected_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("unsupported layer digest '{expected_digest}'"))?;
    let actual = compute_file_sha256_hex(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "digest mismatch for {}: expected sha256:{expected}, got sha256:{actual}",
            path.display()
        ))
    }
}

fn compute_file_sha256_hex(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn compute_bytes_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn extract_layer_blob_to_dir(
    blob_path: &Path,
    media_type: &str,
    dest: &Path,
) -> Result<(), String> {
    if dest.exists() {
        fs::remove_dir_all(dest).map_err(|err| format!("remove {}: {err}", dest.display()))?;
    }
    fs::create_dir_all(dest).map_err(|err| format!("create {}: {err}", dest.display()))?;

    let file =
        fs::File::open(blob_path).map_err(|err| format!("open {}: {err}", blob_path.display()))?;
    match layer_compression_from_media_type(media_type)? {
        LayerCompression::None => extract_tar_reader_to_dir(file, dest),
        LayerCompression::Gzip => extract_tar_reader_to_dir(GzDecoder::new(file), dest),
        LayerCompression::Zstd => {
            let decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|err| format!("decompress {}: {err}", blob_path.display()))?;
            extract_tar_reader_to_dir(decoder, dest)
        }
    }
}

fn extract_tar_reader_to_dir(reader: impl Read, dest: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(reader);
    archive
        .unpack(dest)
        .map_err(|err| format!("extract layer into {}: {err}", dest.display()))
}

// `media_type` is an OCI media type string (e.g. `application/vnd.oci.image.layer.v1.tar+gzip`),
// not a filesystem path, so case-sensitive comparison is correct.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn layer_compression_from_media_type(media_type: &str) -> Result<LayerCompression, String> {
    if media_type.is_empty() {
        return Err("layer media type is missing".to_string());
    }
    if media_type.ends_with("+zstd") {
        return Ok(LayerCompression::Zstd);
    }
    if media_type.ends_with("+gzip") || media_type.ends_with(".gzip") {
        return Ok(LayerCompression::Gzip);
    }
    if media_type.ends_with(".tar")
        || media_type.ends_with("tar")
        || media_type == "application/vnd.oci.image.layer.v1.tar"
        || media_type == "application/vnd.oci.image.layer.nondistributable.v1.tar"
    {
        return Ok(LayerCompression::None);
    }
    Err(format!("unsupported layer media type '{media_type}'"))
}

fn apply_layer_dir_to_rootfs(layer_root: &Path, rootfs: &Path) -> Result<(), String> {
    merge_layer_directory(layer_root, rootfs)
}

fn merge_layer_directory(source_dir: &Path, target_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(target_dir)
        .map_err(|err| format!("create {}: {err}", target_dir.display()))?;

    let mut entries = fs::read_dir(source_dir)
        .map_err(|err| format!("read {}: {err}", source_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read {}: {err}", source_dir.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    if entries
        .iter()
        .any(|entry| entry.file_name().to_string_lossy() == ".wh..wh..opq")
    {
        clear_directory_contents(target_dir)?;
    }

    for entry in entries {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name == ".wh..wh..opq" {
            continue;
        }
        if let Some(hidden_name) = name.strip_prefix(".wh.") {
            remove_path_if_exists(&target_dir.join(hidden_name))?;
            continue;
        }

        let source_path = entry.path();
        let dest_path = target_dir.join(&file_name);
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            if let Ok(dest_metadata) = fs::symlink_metadata(&dest_path)
                && !dest_metadata.file_type().is_dir()
                && !path_is_dir_or_symlink_to_dir(&dest_path)?
            {
                remove_path_if_exists(&dest_path)?;
            }
            fs::create_dir_all(&dest_path)
                .map_err(|err| format!("create {}: {err}", dest_path.display()))?;
            merge_layer_directory(&source_path, &dest_path)?;
            if fs::symlink_metadata(&dest_path)
                .map_err(|err| format!("stat {}: {err}", dest_path.display()))?
                .file_type()
                .is_dir()
            {
                fs::set_permissions(&dest_path, metadata.permissions())
                    .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
            }
        } else if file_type.is_file() {
            remove_path_if_exists(&dest_path)?;
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("create {}: {err}", parent.display()))?;
            }
            fs::copy(&source_path, &dest_path).map_err(|err| {
                format!(
                    "copy {} to {}: {err}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
            fs::set_permissions(&dest_path, metadata.permissions())
                .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
        } else if file_type.is_symlink() {
            copy_symlink(&source_path, &dest_path)?;
        } else {
            return Err(format!(
                "unsupported layer entry type at {}",
                source_path.display()
            ));
        }
    }

    Ok(())
}

fn path_is_dir_or_symlink_to_dir(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("stat {}: {err}", path.display())),
    }
}

fn clear_directory_contents(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|err| format!("read {}: {err}", dir.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", dir.display()))?;
        remove_path_if_exists(&entry.path())?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), String> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path).map_err(|err| format!("remove {}: {err}", path.display()))
    } else {
        fs::remove_file(path).map_err(|err| format!("remove {}: {err}", path.display()))
    }
}

#[cfg(unix)]
fn copy_symlink(source_path: &Path, dest_path: &Path) -> Result<(), String> {
    let target = fs::read_link(source_path)
        .map_err(|err| format!("readlink {}: {err}", source_path.display()))?;
    remove_path_if_exists(dest_path)?;
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    std::os::unix::fs::symlink(&target, dest_path).map_err(|err| {
        format!(
            "symlink {} to {}: {err}",
            target.display(),
            dest_path.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(_source_path: &Path, _dest_path: &Path) -> Result<(), String> {
    Err("symlink layers are only supported on Unix hosts".to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayerCompression {
    None,
    Gzip,
    Zstd,
}

fn requested_sandbox_image(sandbox: &Sandbox) -> Option<&str> {
    sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.trim())
        .filter(|image| !image.is_empty())
}

fn merged_environment(sandbox: &Sandbox) -> HashMap<String, String> {
    let mut environment = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map_or_else(HashMap::new, |template| template.environment.clone());
    if let Some(spec) = sandbox.spec.as_ref() {
        environment.extend(spec.environment.clone());
    }
    environment
}

/// Rewrites loopback host references in a gateway URL to a hostname the guest
/// can reach via gvproxy.
///
/// The driver receives the gateway endpoint from `--openshell-endpoint`, which
/// in local/dev/e2e setups is typically `http://127.0.0.1:<port>`. That URL is
/// useless inside the guest because the guest's loopback interface is its own,
/// not the host's. Inside the guest we need a name that gvproxy will translate
/// into the host's loopback address.
///
/// We rewrite to `host.openshell.internal`, which gvproxy's embedded DNS resolves
/// to the host-loopback IP `192.168.127.254`. gvproxy installs a default NAT entry
/// rewriting that destination to the host's `127.0.0.1` and dialing out from the
/// host process, so any port the host is listening on becomes reachable. The
/// gateway IP `192.168.127.1` does **not** do this — it only listens on gvproxy's
/// own service ports (DNS, DHCP, HTTP API). The guest init script also seeds the
/// hostname in `/etc/hosts` so resolution works even if gvproxy's DNS isn't in
/// resolv.conf (e.g. when DHCP fails).
///
/// Non-loopback URLs are returned unchanged.
fn guest_visible_openshell_endpoint(endpoint: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };

    let should_rewrite = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    };

    if should_rewrite && url.set_host(Some(GVPROXY_HOST_LOOPBACK_ALIAS)).is_ok() {
        return url.to_string();
    }

    endpoint.to_string()
}

/// Whether a corporate proxy URL points at the gateway host itself, as seen
/// from a QEMU/TAP guest whose TAP host address is `tap_host_ip`.
///
/// On the libkrun backend gvproxy NATs the host-loopback alias
/// `host.openshell.internal` (and any loopback URL, which the driver rewrites
/// to that alias) to the gateway host's `127.0.0.1`, so a proxy bound to host
/// loopback is reachable from the guest. The QEMU/TAP backend used for GPU
/// sandboxes has no equivalent: `host.openshell.internal` resolves to the TAP
/// host address, and the driver's own nftables `input` chain accepts only the
/// gateway port from the guest and drops the rest, so no proxy on the gateway
/// host is reachable regardless of the address it binds.
///
/// The gateway host is therefore reached from a QEMU guest under exactly three
/// spellings: the guest's own loopback (never the host's, but a configuration
/// that plainly means the host), the documented host aliases that
/// `write_host_gateway_aliases` seeds to the TAP host address, and that TAP
/// host address written literally. `tap_host_ip` is this sandbox's allocated
/// address, so the comparison must be made after the launch plan's subnet
/// allocation; `None` means the plan carries no TAP host and only the
/// address-independent spellings are classified.
///
/// gvproxy's `GVPROXY_HOST_LOOPBACK_IP` is deliberately **not** matched here.
/// It is special only to libkrun; on QEMU/TAP it is an ordinary address that
/// may well be routable through the guest's masqueraded egress, and rejecting
/// it would refuse a working configuration.
///
/// Used to reject an unreachable configuration up front on the QEMU path
/// instead of letting every policy-approved CONNECT time out.
fn proxy_url_targets_gateway_host(url: &str, tap_host_ip: Option<&str>) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        // Unparseable URLs are rejected by shared validation before launch.
        return false;
    };
    let tap_host = tap_host_ip.and_then(|ip| ip.parse::<IpAddr>().ok());
    match parsed.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback() || tap_host == Some(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => ip.is_loopback() || tap_host == Some(IpAddr::V6(ip)),
        Some(Host::Domain(host)) => {
            host.eq_ignore_ascii_case("localhost")
                || host.eq_ignore_ascii_case(OPENSHELL_HOST_GATEWAY_ALIAS)
                || host.eq_ignore_ascii_case("host.containers.internal")
                || host.eq_ignore_ascii_case("host.docker.internal")
        }
        None => false,
    }
}

fn gateway_port_from_endpoint(endpoint: &str) -> Option<u16> {
    Url::parse(endpoint).ok().and_then(|url| url.port())
}

fn has_complete_qemu_network(plan: &LaunchPlan) -> bool {
    plan.tap_device.is_some()
        && plan.guest_ip.is_some()
        && plan.host_ip.is_some()
        && plan.vsock_cid.is_some()
        && plan.guest_mac.is_some()
}

fn guest_visible_openshell_endpoint_for_tap(endpoint: &str, host_ip: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };
    if url.set_host(Some(host_ip)).is_ok() {
        url.to_string()
    } else {
        endpoint.to_string()
    }
}

fn build_guest_environment(
    sandbox: &Sandbox,
    config: &VmDriverConfig,
    endpoint_override: Option<&str>,
) -> Vec<String> {
    let openshell_endpoint = endpoint_override.map_or_else(
        || guest_visible_openshell_endpoint(&config.openshell_endpoint),
        String::from,
    );
    // 1. User-supplied environment (lowest priority).
    let user_env = merged_environment(sandbox);
    let mut environment: HashMap<String, String> = HashMap::new();
    environment.extend(user_env.clone());
    if !user_env.is_empty()
        && let Ok(json) = serde_json::to_string(&user_env)
    {
        environment.insert(
            openshell_core::sandbox_env::USER_ENVIRONMENT.to_string(),
            json,
        );
    }

    // 2. Required driver vars (highest priority -- always overwrite).
    environment.insert("HOME".to_string(), "/root".to_string());
    environment.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    environment.insert("TERM".to_string(), "xterm".to_string());
    environment.insert(
        openshell_core::sandbox_env::ENDPOINT.to_string(),
        openshell_endpoint,
    );
    environment.insert(
        openshell_core::sandbox_env::SANDBOX_ID.to_string(),
        sandbox.id.clone(),
    );
    environment.insert(
        openshell_core::sandbox_env::SANDBOX.to_string(),
        sandbox.name.clone(),
    );
    environment.insert(
        openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
        GUEST_SSH_SOCKET_PATH.to_string(),
    );
    // The libkrun guest environment path does not preserve spaces in values
    // before guest startup. Use a whitespace-free base64url envelope so
    // command arguments remain lossless.
    let main_process =
        openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec_base64url(
            sandbox.spec.as_ref(),
        )
        .expect("main process config serialization cannot fail");
    environment.insert(
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC.to_string(),
        main_process,
    );
    environment.insert(
        openshell_core::sandbox_env::LOG_LEVEL.to_string(),
        openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level),
    );
    if config.requires_tls_materials() {
        environment.insert(
            openshell_core::sandbox_env::TLS_CA.to_string(),
            GUEST_TLS_CA_PATH.to_string(),
        );
        environment.insert(
            openshell_core::sandbox_env::TLS_CERT.to_string(),
            GUEST_TLS_CERT_PATH.to_string(),
        );
        environment.insert(
            openshell_core::sandbox_env::TLS_KEY.to_string(),
            GUEST_TLS_KEY_PATH.to_string(),
        );
    }
    environment.insert(
        openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
        openshell_core::telemetry::enabled_env_value().to_string(),
    );
    // Runtime capabilities are driver-owned. The VM driver does not yet
    // provide policy DNS and transparent TCP interception.
    environment.insert(
        openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES.to_string(),
        String::new(),
    );
    environment.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
    environment.remove(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE);
    // Prevent user-supplied environment from overriding the TLS server name
    // the supervisor verifies — a sandbox user who can redirect the gateway
    // hostname could otherwise present a certificate for a name they control
    // and intercept the sandbox JWT.
    environment.remove(openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME);
    if sandbox
        .spec
        .as_ref()
        .is_some_and(|spec| !spec.sandbox_token.is_empty())
    {
        environment.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE.to_string(),
            GUEST_SANDBOX_TOKEN_PATH.to_string(),
        );
    }

    let mut pairs = environment.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn sandboxes_root_dir(root: &Path) -> PathBuf {
    root.join("sandboxes")
}

async fn create_private_dir_all(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(path).await?;
    restrict_owner_only_dir(path).await
}

#[cfg(unix)]
async fn restrict_owner_only_dir(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(path, fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn restrict_owner_only_dir(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[allow(clippy::result_large_err)]
fn sandbox_state_dir(root: &Path, sandbox_id: &str) -> Result<PathBuf, Status> {
    validate_sandbox_id(sandbox_id)?;
    Ok(sandboxes_root_dir(root).join(sandbox_id))
}

fn sandbox_overlay_image(state_dir: &Path) -> PathBuf {
    state_dir.join(SANDBOX_OVERLAY_IMAGE)
}

fn overlay_template_image(root: &Path, size_bytes: u64) -> PathBuf {
    image_cache_root_dir(root)
        .join(OVERLAY_TEMPLATE_CACHE_DIR)
        .join(OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION)
        .join(format!("{size_bytes}.ext4"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxRuntimeDiskPaths {
    overlay_disk: PathBuf,
}

fn sandbox_runtime_disk_paths(state_dir: &Path) -> SandboxRuntimeDiskPaths {
    SandboxRuntimeDiskPaths {
        overlay_disk: sandbox_overlay_image(state_dir),
    }
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_state_dir(root: &Path, state_dir: &Path) -> Result<(), Status> {
    let sandboxes_root = sandboxes_root_dir(root);
    let relative = state_dir.strip_prefix(&sandboxes_root).map_err(|_| {
        Status::internal(format!(
            "refusing to use sandbox state path outside vm state root: {}",
            state_dir.display()
        ))
    })?;

    let mut components = relative.components();
    match components.next() {
        Some(Component::Normal(_)) => {}
        _ => {
            return Err(Status::internal(format!(
                "refusing to use malformed sandbox state path: {}",
                state_dir.display()
            )));
        }
    }
    if components.next().is_some() {
        return Err(Status::internal(format!(
            "refusing to use nested sandbox state path: {}",
            state_dir.display()
        )));
    }

    Ok(())
}

async fn remove_sandbox_state_dir(root: &Path, state_dir: &Path) -> Result<(), Status> {
    validate_sandbox_state_dir(root, state_dir)?;

    let metadata = match tokio::fs::symlink_metadata(state_dir).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(Status::internal(format!(
                "failed to stat sandbox state dir: {err}"
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Status::internal(format!(
            "refusing to remove symlinked sandbox state dir: {}",
            state_dir.display()
        )));
    }
    if !file_type.is_dir() {
        return Err(Status::internal(format!(
            "sandbox state path is not a directory: {}",
            state_dir.display()
        )));
    }

    tokio::fs::remove_dir_all(state_dir)
        .await
        .map_err(|err| Status::internal(format!("failed to remove state dir: {err}")))
}

fn image_cache_root_dir(root: &Path) -> PathBuf {
    root.join(IMAGE_CACHE_ROOT_DIR)
}

fn image_cache_dir(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_root_dir(root).join(sanitize_image_identity(image_identity))
}

fn image_cache_rootfs_image(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_dir(root, image_identity).join(IMAGE_CACHE_ROOTFS_IMAGE)
}

fn image_cache_staging_dir(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_root_dir(root).join(format!(
        "{}.staging-{}",
        sanitize_image_identity(image_identity),
        unique_image_cache_suffix()
    ))
}

fn oci_layout_blobs_dir(layout_dir: &Path) -> PathBuf {
    layout_dir.join("blobs").join("sha256")
}

fn oci_layout_blob_path(layout_dir: &Path, digest: &str) -> Result<PathBuf, String> {
    let hex = sha256_digest_hex(digest)?;
    Ok(oci_layout_blobs_dir(layout_dir).join(hex))
}

fn sha256_digest_hex(digest: &str) -> Result<&str, String> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(format!("digest '{digest}' is missing an algorithm"));
    };
    if algorithm != "sha256" {
        return Err(format!("unsupported digest algorithm '{algorithm}'"));
    }
    if hex.is_empty() || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("digest '{digest}' is not a valid sha256 digest"));
    }
    Ok(hex)
}

fn write_oci_layout_for_manifest(
    layout_dir: &Path,
    ref_name: &str,
    manifest: &OciImageManifest,
) -> Result<(), String> {
    fs::create_dir_all(oci_layout_blobs_dir(layout_dir))
        .map_err(|err| format!("create OCI layout blobs dir failed: {err}"))?;

    fs::write(
        layout_dir.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .map_err(|err| format!("write OCI layout marker failed: {err}"))?;

    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|err| format!("serialize OCI manifest failed: {err}"))?;
    let manifest_digest = format!("sha256:{}", compute_bytes_sha256_hex(&manifest_bytes));
    let manifest_blob = oci_layout_blob_path(layout_dir, &manifest_digest)
        .map_err(|err| format!("compute OCI manifest blob path failed: {err}"))?;
    fs::write(&manifest_blob, &manifest_bytes)
        .map_err(|err| format!("write OCI manifest blob failed: {err}"))?;

    let media_type = manifest
        .media_type
        .clone()
        .unwrap_or_else(|| OCI_IMAGE_MEDIA_TYPE.to_string());
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": media_type,
                "digest": manifest_digest,
                "size": manifest_bytes.len(),
                "annotations": {
                    "org.opencontainers.image.ref.name": ref_name
                }
            }
        ]
    });
    let index_bytes = serde_json::to_vec_pretty(&index)
        .map_err(|err| format!("serialize OCI index failed: {err}"))?;
    fs::write(layout_dir.join("index.json"), index_bytes)
        .map_err(|err| format!("write OCI index failed: {err}"))?;

    Ok(())
}

fn bootstrap_image_cache_identity(image_identity: &str) -> String {
    format!(
        "{BOOTSTRAP_IMAGE_CACHE_LAYOUT_VERSION}:openshell-{}:{image_identity}",
        openshell_core::VERSION
    )
}

fn prepared_image_cache_identity(image_identity: &str) -> String {
    format!(
        "{PREPARED_IMAGE_CACHE_LAYOUT_VERSION}:openshell-{}:{image_identity}",
        openshell_core::VERSION
    )
}

fn registry_layer_download_concurrency() -> usize {
    let value = std::env::var("OPENSHELL_VM_IMAGE_PULL_CONCURRENCY").ok();
    registry_layer_download_concurrency_value(value.as_deref())
}

fn registry_layer_download_concurrency_value(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map_or(DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY, |value| {
            value.min(MAX_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY)
        })
}

fn sanitize_image_identity(image_identity: &str) -> String {
    image_identity
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn unique_image_cache_suffix() -> String {
    let counter = IMAGE_CACHE_BUILD_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{counter}", openshell_core::time::now_ms())
}

async fn write_sandbox_image_metadata(
    state_dir: &Path,
    image_ref: &str,
    image_identity: &str,
) -> Result<(), std::io::Error> {
    tokio::fs::write(
        state_dir.join(IMAGE_IDENTITY_FILE),
        format!("{image_identity}\n"),
    )
    .await?;
    tokio::fs::write(
        state_dir.join(IMAGE_REFERENCE_FILE),
        format!("{image_ref}\n"),
    )
    .await?;

    Ok(())
}

async fn write_sandbox_request(state_dir: &Path, sandbox: &Sandbox) -> Result<(), std::io::Error> {
    restrict_owner_only_dir(state_dir).await?;
    write_private_file(
        &state_dir.join(SANDBOX_REQUEST_FILE),
        sandbox.encode_to_vec(),
    )
    .await
}

async fn read_sandbox_request(path: &Path) -> Result<Sandbox, std::io::Error> {
    let bytes = tokio::fs::read(path).await?;
    Sandbox::decode(bytes.as_slice()).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decode persisted sandbox request: {err}"),
        )
    })
}

async fn write_private_file(path: &Path, bytes: Vec<u8>) -> Result<(), std::io::Error> {
    tokio::fs::write(path, bytes).await?;
    restrict_owner_read_write(path).await
}

#[cfg(unix)]
async fn restrict_owner_read_write(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(path, fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn restrict_owner_read_write(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_restored_sandbox_state(
    root: &Path,
    state_dir: &Path,
    sandbox: &Sandbox,
) -> Result<(), Status> {
    validate_sandbox_id(&sandbox.id)?;
    validate_sandbox_state_dir(root, state_dir)?;
    let Some(dir_name) = state_dir.file_name().and_then(|name| name.to_str()) else {
        return Err(Status::internal(format!(
            "sandbox state path has no valid directory name: {}",
            state_dir.display()
        )));
    };
    if dir_name != sandbox.id {
        return Err(Status::internal(format!(
            "sandbox state dir '{}' does not match persisted sandbox id '{}'",
            dir_name, sandbox.id
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct GuestTlsMaterials {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
}

async fn read_guest_tls_materials(paths: &VmDriverTlsPaths) -> Result<GuestTlsMaterials, String> {
    let ca = tokio::fs::read(&paths.ca)
        .await
        .map_err(|err| format!("read {}: {err}", paths.ca.display()))?;
    let cert = tokio::fs::read(&paths.cert)
        .await
        .map_err(|err| format!("read {}: {err}", paths.cert.display()))?;
    let key = tokio::fs::read(&paths.key)
        .await
        .map_err(|err| format!("read {}: {err}", paths.key.display()))?;
    Ok(GuestTlsMaterials { ca, cert, key })
}

async fn overlay_template_image_ready(path: &Path, size_bytes: u64) -> Result<bool, String> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.is_file() && metadata.len() == size_bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("stat overlay template {}: {err}", path.display())),
    }
}

fn ensure_sandbox_overlay_template_image(
    template_path: &Path,
    size_bytes: u64,
) -> Result<(), String> {
    if let Ok(metadata) = fs::metadata(template_path)
        && metadata.is_file()
        && metadata.len() == size_bytes
    {
        return Ok(());
    }

    let parent = template_path.parent().ok_or_else(|| {
        format!(
            "overlay template path has no parent: {}",
            template_path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create overlay template cache dir {}: {err}",
            parent.display()
        )
    })?;

    let staging_image = parent.join(format!(
        ".{}.staging-{}-{}",
        template_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("overlay-template.ext4"),
        std::process::id(),
        openshell_core::time::now_ms()
    ));

    let result = (|| {
        create_empty_sandbox_overlay_image(&staging_image, size_bytes)?;
        fs::rename(&staging_image, template_path).map_err(|err| {
            format!(
                "move overlay template {} to {}: {err}",
                staging_image.display(),
                template_path.display()
            )
        })
    })();

    if result.is_err() {
        let _ = fs::remove_file(&staging_image);
    }
    result
}

fn create_empty_sandbox_overlay_image(overlay_disk: &Path, size_bytes: u64) -> Result<(), String> {
    let staging_dir = overlay_staging_dir(overlay_disk);
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .map_err(|err| format!("remove stale overlay staging dir: {err}"))?;
    }

    let result = (|| {
        fs::create_dir_all(staging_dir.join("upper"))
            .map_err(|err| format!("create overlay upper dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("work"))
            .map_err(|err| format!("create overlay work dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("config"))
            .map_err(|err| format!("create overlay config dir: {err}"))?;

        create_ext4_image_from_dir_with_size(&staging_dir, overlay_disk, size_bytes)
    })();

    let _ = fs::remove_dir_all(&staging_dir);
    result
}

fn create_sandbox_overlay_image_from_template(
    template_path: &Path,
    overlay_disk: &Path,
    tls_materials: Option<&GuestTlsMaterials>,
    sandbox_token: Option<&str>,
) -> Result<(), String> {
    clone_or_copy_sparse_file(template_path, overlay_disk)?;
    if let Some(tls) = tls_materials {
        inject_guest_tls_materials(overlay_disk, tls)?;
    }
    if let Some(token) = sandbox_token {
        inject_guest_sandbox_token(overlay_disk, token)?;
    }
    Ok(())
}

fn prepare_sandbox_overlay_image(
    template_path: &Path,
    overlay_disk: &Path,
    tls_materials: Option<&GuestTlsMaterials>,
    sandbox_token: Option<&str>,
    preparation: OverlayPreparation,
    expected_size_bytes: u64,
) -> Result<(), String> {
    if preparation == OverlayPreparation::PreserveExisting {
        match fs::metadata(overlay_disk) {
            Ok(metadata) if metadata.is_file() && metadata.len() == expected_size_bytes => {
                if let Some(tls) = tls_materials {
                    inject_guest_tls_materials(overlay_disk, tls)?;
                }
                if let Some(token) = sandbox_token {
                    inject_guest_sandbox_token(overlay_disk, token)?;
                }
                return Ok(());
            }
            Ok(metadata) if metadata.is_file() => {
                return Err(format!(
                    "existing overlay disk '{}' has size {}, expected {}",
                    overlay_disk.display(),
                    metadata.len(),
                    expected_size_bytes
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "existing overlay path '{}' is not a file",
                    overlay_disk.display()
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "stat overlay disk {}: {err}",
                    overlay_disk.display()
                ));
            }
        }
    }

    create_sandbox_overlay_image_from_template(
        template_path,
        overlay_disk,
        tls_materials,
        sandbox_token,
    )
}

fn inject_guest_tls_materials(
    overlay_disk: &Path,
    materials: &GuestTlsMaterials,
) -> Result<(), String> {
    write_rootfs_image_file(
        overlay_disk,
        &overlay_upper_path(GUEST_TLS_CA_PATH),
        &materials.ca,
    )?;
    write_rootfs_image_file(
        overlay_disk,
        &overlay_upper_path(GUEST_TLS_CERT_PATH),
        &materials.cert,
    )?;
    let key_path = overlay_upper_path(GUEST_TLS_KEY_PATH);
    write_rootfs_image_file(overlay_disk, &key_path, &materials.key)?;
    set_rootfs_image_file_mode(overlay_disk, &key_path, 0o600)
}

fn inject_guest_sandbox_token(overlay_disk: &Path, token: &str) -> Result<(), String> {
    let token_path = overlay_upper_path(GUEST_SANDBOX_TOKEN_PATH);
    write_rootfs_image_file(overlay_disk, &token_path, format!("{token}\n").as_bytes())?;
    set_rootfs_image_file_mode(overlay_disk, &token_path, 0o600)
}

#[allow(clippy::result_large_err)]
#[tracing::instrument(
    name = "vm.prepare_guest",
    skip(dropins),
    fields(
        otel.name = "vm.prepare_guest",
        otel.status_code = tracing::field::Empty,
        overlay.path = %overlay_disk.display(),
        dropin.count = dropins.len(),
    )
)]
fn inject_guest_init_dropins(
    overlay_disk: &Path,
    dropins: &[GuestInitDropin],
) -> Result<(), Status> {
    let span_status = openshell_otel::ErrorStatusGuard::current();
    validate_guest_init_dropins(dropins).map_err(Status::failed_precondition)?;

    // Drop-ins are *executed* in a child shell by run_openshell_init_dropins
    // in the guest init script, not sourced into the parent. Mode 0o755 is
    // required (the runner skips anything that is not `-x`) and is the
    // contract drop-in authors should rely on.
    for dropin in dropins {
        let guest_path = overlay_upper_path(&format!("{GUEST_INIT_DROPIN_DIR}/{}", dropin.name));
        write_rootfs_image_file(overlay_disk, &guest_path, &dropin.contents).map_err(|err| {
            Status::internal(format!(
                "write VM guest init drop-in '{}' failed: {err}",
                dropin.name
            ))
        })?;
        set_rootfs_image_file_mode(overlay_disk, &guest_path, 0o755).map_err(|err| {
            Status::internal(format!(
                "set VM guest init drop-in '{}' executable failed: {err}",
                dropin.name
            ))
        })?;
    }

    // Write the allow-list manifest the guest runner consults. We write it
    // unconditionally — including an empty manifest when no drop-ins were
    // injected — so the guest always fails closed: only names the driver
    // explicitly injected this launch are eligible to run, and a guest
    // image cannot smuggle in extra `init.d` entries.
    write_guest_init_dropin_manifest(overlay_disk, dropins)?;
    span_status.finish(Ok(()))
}

/// Build the corporate upstream-proxy arguments passed to the guest supervisor.
///
/// This operator-owned egress boundary travels on the supervisor's argv,
/// which sandbox spec/template environment and image `ENV` cannot influence.
/// Credentials are never on argv — only the root-only guest path is passed;
/// the supervisor reads the credential from that file.
fn upstream_proxy_cli_args(config: &VmDriverConfig) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(url) = &config.https_proxy {
        args.push("--upstream-proxy".to_string());
        args.push(url.clone());
    }
    if let Some(list) = &config.no_proxy {
        args.push("--upstream-no-proxy".to_string());
        args.push(list.clone());
    }
    if config.proxy_auth_file.is_some() {
        args.push("--upstream-proxy-auth-file".to_string());
        // The guest path, never the gateway-host path the operator configured.
        args.push(GUEST_UPSTREAM_PROXY_AUTH_PATH.to_string());
    }
    // Config validation guarantees the acknowledgement is `true` whenever an
    // auth file is configured against an http:// proxy; the supervisor
    // independently refuses credentials without it.
    if config.proxy_auth_allow_insecure == Some(true) {
        args.push("--upstream-proxy-auth-allow-insecure".to_string());
    }
    // Absent means the default validated-IP CONNECT binding; only the
    // explicit hostname opt-in is passed through.
    if config.proxy_connect_by_hostname == Some(true) {
        args.push("--upstream-proxy-connect-by-hostname".to_string());
    }
    if config.proxy_ca_bundle.is_some() {
        args.push("--upstream-proxy-ca-bundle".to_string());
        args.push(GUEST_PROXY_CA_PATH.to_string());
    }
    args
}

/// Render the supervisor argument list as newline-separated arguments.
///
/// One argument per line, verbatim: the guest reads the lines into an array
/// without word splitting or globbing, so values containing spaces survive
/// intact. An empty list renders an empty file, which the guest reads as "no
/// extra arguments".
fn render_guest_supervisor_args(args: &[String]) -> Vec<u8> {
    let mut body = args.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    body.into_bytes()
}

/// Reject argument values the newline-delimited guest file cannot represent.
///
/// Every value here is operator-supplied config, so this is a guard against
/// misconfiguration rather than an attack: a stray newline would otherwise
/// split one value into two arguments in the guest.
fn validate_guest_supervisor_args(args: &[String]) -> Result<(), String> {
    for arg in args {
        if arg.contains('\n') || arg.contains('\r') || arg.contains('\0') {
            return Err(
                "corporate proxy settings must not contain newline or NUL characters".to_string(),
            );
        }
    }
    Ok(())
}

/// Read and validate the corporate proxy credential from the gateway host.
///
/// Uses the validators shared with the supervisor, so a credential accepted
/// here is never rejected inside the guest. The error never carries the file
/// contents.
async fn read_sandbox_proxy_credential(path: &str) -> Result<String, Status> {
    let path_owned = path.to_string();
    let raw = tokio::task::spawn_blocking(move || {
        openshell_core::driver_utils::read_upstream_proxy_credential_file(&path_owned)
    })
    .await
    .map_err(|err| Status::internal(format!("proxy_auth_file read task failed: {err}")))?
    .map_err(Status::invalid_argument)?;
    let credential = openshell_core::driver_utils::parse_upstream_proxy_credential(&raw)
        .map_err(|err| Status::invalid_argument(format!("proxy_auth_file '{path}': {err}")))?;
    Ok(credential.to_string())
}

/// Read and validate the corporate proxy CA bundle from the gateway host.
///
/// Uses the reader shared with the supervisor, so the bundle is bounded and
/// non-regular files are rejected (an operator path such as `/dev/zero` can
/// otherwise exhaust driver memory), and a bundle accepted here contributes at
/// least one trust anchor rustls accepts rather than merely looking like PEM.
/// Checked here rather than only in the guest so the operator gets an error
/// attributable to `proxy_ca_bundle` instead of an opaque supervisor startup
/// failure inside every sandbox. The error never carries the file contents.
async fn read_sandbox_proxy_ca_bundle(path: &str) -> Result<Vec<u8>, Status> {
    let path_owned = path.to_string();
    let pem = tokio::task::spawn_blocking(move || {
        openshell_core::driver_utils::read_upstream_proxy_ca_bundle_file(
            &path_owned,
            "proxy_ca_bundle",
        )
    })
    .await
    .map_err(|err| Status::internal(format!("proxy_ca_bundle read task failed: {err}")))?
    .map_err(Status::invalid_argument)?;
    Ok(pem.into_bytes())
}

/// Stage the corporate upstream-proxy configuration into the guest overlay.
///
/// Writes three files into the overlay upperdir the driver owns:
///
/// * the credential at [`GUEST_UPSTREAM_PROXY_AUTH_PATH`], mode `0600`;
/// * the CA bundle at [`GUEST_PROXY_CA_PATH`], mode `0644` (a CA certificate
///   is not secret);
/// * the supervisor argument list at [`GUEST_SUPERVISOR_ARGS_PATH`], mode
///   `0644`.
///
/// All three are written on every launch, empty when the corresponding
/// setting is absent. Writing rather than skipping is what makes the channel
/// unforgeable: the upperdir copy always shadows the read-only image layer, so
/// a sandbox image cannot supply its own arguments or credential by baking a
/// file at these paths, and cannot disable the operator's by omitting one. It
/// also clears material a previous launch staged into a preserved overlay
/// after the operator removed the setting.
///
/// A microVM has no bind mounts or container secrets, so the credential lives
/// at rest inside the per-sandbox overlay disk on the host — the same
/// delivery the per-sandbox gateway JWT already uses. It is removed with the
/// sandbox when the state directory is deleted.
#[allow(clippy::result_large_err)]
async fn inject_guest_upstream_proxy(
    overlay_disk: &Path,
    config: &VmDriverConfig,
) -> Result<(), Status> {
    // Written whether or not they are configured. Writing empty files when
    // the operator removed a setting clears material a previous launch staged
    // into a preserved overlay, and shadows anything an image baked at these
    // paths, so a staged file is only ever the one this launch produced.
    let credential = match config.proxy_auth_file.as_deref() {
        Some(path) => format!("{}\n", read_sandbox_proxy_credential(path).await?).into_bytes(),
        None => Vec::new(),
    };
    let credential_path = overlay_upper_path(GUEST_UPSTREAM_PROXY_AUTH_PATH);
    write_rootfs_image_file(overlay_disk, &credential_path, &credential)
        .map_err(|err| Status::internal(format!("write VM guest proxy credential: {err}")))?;
    set_rootfs_image_file_mode(overlay_disk, &credential_path, 0o600)
        .map_err(|err| Status::internal(format!("set VM guest proxy credential mode: {err}")))?;

    let ca_bundle = match config.proxy_ca_bundle.as_deref() {
        Some(path) => read_sandbox_proxy_ca_bundle(path).await?,
        None => Vec::new(),
    };
    let ca_path = overlay_upper_path(GUEST_PROXY_CA_PATH);
    write_rootfs_image_file(overlay_disk, &ca_path, &ca_bundle)
        .map_err(|err| Status::internal(format!("write VM guest proxy CA bundle: {err}")))?;
    set_rootfs_image_file_mode(overlay_disk, &ca_path, 0o644)
        .map_err(|err| Status::internal(format!("set VM guest proxy CA bundle mode: {err}")))?;

    let args = upstream_proxy_cli_args(config);
    validate_guest_supervisor_args(&args).map_err(Status::failed_precondition)?;
    let guest_path = overlay_upper_path(GUEST_SUPERVISOR_ARGS_PATH);
    write_rootfs_image_file(
        overlay_disk,
        &guest_path,
        &render_guest_supervisor_args(&args),
    )
    .map_err(|err| Status::internal(format!("write VM guest supervisor arguments: {err}")))?;
    set_rootfs_image_file_mode(overlay_disk, &guest_path, 0o644).map_err(|err| {
        Status::internal(format!("set VM guest supervisor arguments mode: {err}"))
    })?;
    Ok(())
}

/// Render the drop-in allow-list as newline-separated, ASCII-sorted,
/// de-duplicated names. Names are already validated to be path-safe by
/// [`validate_guest_init_dropins`].
fn render_guest_init_dropin_manifest(dropins: &[GuestInitDropin]) -> Vec<u8> {
    let mut names: Vec<&str> = dropins.iter().map(|d| d.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut body = names.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    body.into_bytes()
}

#[allow(clippy::result_large_err)]
fn write_guest_init_dropin_manifest(
    overlay_disk: &Path,
    dropins: &[GuestInitDropin],
) -> Result<(), Status> {
    let guest_path = overlay_upper_path(GUEST_INIT_DROPIN_MANIFEST);
    let contents = render_guest_init_dropin_manifest(dropins);
    write_rootfs_image_file(overlay_disk, &guest_path, &contents).map_err(|err| {
        Status::internal(format!(
            "write VM guest init drop-in manifest failed: {err}"
        ))
    })?;
    set_rootfs_image_file_mode(overlay_disk, &guest_path, 0o644).map_err(|err| {
        Status::internal(format!(
            "set VM guest init drop-in manifest mode failed: {err}"
        ))
    })?;
    Ok(())
}

fn validate_guest_init_dropins(dropins: &[GuestInitDropin]) -> Result<(), String> {
    let mut names = HashSet::new();
    for dropin in dropins {
        validate_guest_init_dropin_name(&dropin.name)?;
        if !names.insert(dropin.name.clone()) {
            return Err(format!("duplicate VM guest init drop-in '{}'", dropin.name));
        }
    }
    Ok(())
}

fn validate_guest_init_dropin_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err("VM guest init drop-in name is empty or reserved".to_string());
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Err(format!(
            "VM guest init drop-in name '{name}' must contain only ASCII letters, numbers, '.', '-', or '_'"
        ));
    }
    Ok(())
}

fn overlay_upper_path(guest_path: &str) -> String {
    format!("/upper/{}", guest_path.trim_start_matches('/'))
}

fn create_image_prep_disk(
    image_path: &Path,
    size_bytes: u64,
    payload: &GuestImagePayload,
) -> Result<(), String> {
    let staging_dir = overlay_staging_dir(image_path);
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .map_err(|err| format!("remove stale image-prep staging dir: {err}"))?;
    }

    let result = (|| {
        fs::create_dir_all(staging_dir.join("upper").join("srv"))
            .map_err(|err| format!("create image-prep env dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("work"))
            .map_err(|err| format!("create image-prep work dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("config"))
            .map_err(|err| format!("create image-prep config dir: {err}"))?;
        stage_guest_image_payload(&staging_dir, payload)?;
        create_ext4_image_from_dir_with_size(&staging_dir, image_path, size_bytes)
    })();

    let _ = fs::remove_dir_all(&staging_dir);
    result
}

fn stage_guest_image_payload(
    staging_dir: &Path,
    payload: &GuestImagePayload,
) -> Result<(), String> {
    let image_dir = staging_dir.join("config").join(GUEST_IMAGE_CONFIG_DIR);
    fs::create_dir_all(&image_dir).map_err(|err| {
        format!(
            "create guest image config dir {}: {err}",
            image_dir.display()
        )
    })?;
    fs::write(image_dir.join("ref"), payload.image_ref.as_bytes())
        .map_err(|err| format!("write guest image ref: {err}"))?;
    fs::write(
        image_dir.join("identity"),
        payload.image_identity.as_bytes(),
    )
    .map_err(|err| format!("write guest image identity: {err}"))?;

    match &payload.source {
        GuestImagePayloadSource::RegistryOciLayout { layout_dir } => {
            fs::write(image_dir.join("source"), b"oci-layout")
                .map_err(|err| format!("write guest image source: {err}"))?;
            copy_dir_recursive(layout_dir, &image_dir.join(GUEST_IMAGE_OCI_LAYOUT_DIR))?;
        }
        GuestImagePayloadSource::LocalDocker { rootfs_archive } => {
            fs::write(image_dir.join("source"), b"local-docker")
                .map_err(|err| format!("write guest image source: {err}"))?;
            let dest = image_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
            fs::copy(rootfs_archive, &dest).map_err(|err| {
                format!(
                    "copy guest image rootfs archive {} to {}: {err}",
                    rootfs_archive.display(),
                    dest.display()
                )
            })?;
        }
    }

    Ok(())
}

fn copy_dir_recursive(source: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|err| format!("create {}: {err}", dest.display()))?;
    for entry in fs::read_dir(source).map_err(|err| format!("read {}: {err}", source.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", source.display()))?;
        let source_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
        if metadata.file_type().is_dir() {
            copy_dir_recursive(&source_path, &dest_path)?;
        } else if metadata.file_type().is_file() {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("create {}: {err}", parent.display()))?;
            }
            fs::copy(&source_path, &dest_path).map_err(|err| {
                format!(
                    "copy {} to {}: {err}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "unsupported payload entry type at {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn prepared_image_disk_size_bytes(
    payload: &GuestImagePayload,
    minimum_size_bytes: u64,
) -> Result<u64, String> {
    let payload_size = match &payload.source {
        GuestImagePayloadSource::RegistryOciLayout { layout_dir } => dir_size_bytes(layout_dir)?,
        GuestImagePayloadSource::LocalDocker { rootfs_archive } => fs::metadata(rootfs_archive)
            .map_err(|err| format!("stat {}: {err}", rootfs_archive.display()))?
            .len(),
    };
    let requested = payload_size
        .saturating_mul(3)
        .saturating_add(512 * 1024 * 1024);
    Ok(minimum_size_bytes.max(requested))
}

fn dir_size_bytes(path: &Path) -> Result<u64, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| format!("stat {}: {err}", path.display()))?;
    if metadata.file_type().is_file() {
        return Ok(metadata.len());
    }
    if metadata.file_type().is_symlink() {
        return Ok(0);
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(path).map_err(|err| format!("read {}: {err}", path.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", path.display()))?;
        total = total.saturating_add(dir_size_bytes(&entry.path())?);
    }
    Ok(total)
}

#[cfg(test)]
fn stage_guest_tls_materials(
    staging_dir: &Path,
    materials: &GuestTlsMaterials,
) -> Result<(), String> {
    let tls_dir = staging_dir
        .join("upper")
        .join(GUEST_TLS_CA_PATH.trim_start_matches('/'))
        .parent()
        .ok_or_else(|| "guest TLS CA path has no parent".to_string())?
        .to_path_buf();
    fs::create_dir_all(&tls_dir)
        .map_err(|err| format!("create guest TLS dir {}: {err}", tls_dir.display()))?;

    let ca_path = staging_dir
        .join("upper")
        .join(GUEST_TLS_CA_PATH.trim_start_matches('/'));
    let cert_path = staging_dir
        .join("upper")
        .join(GUEST_TLS_CERT_PATH.trim_start_matches('/'));
    let key_path = staging_dir
        .join("upper")
        .join(GUEST_TLS_KEY_PATH.trim_start_matches('/'));
    fs::write(&ca_path, &materials.ca)
        .map_err(|err| format!("write guest TLS CA {}: {err}", ca_path.display()))?;
    fs::write(&cert_path, &materials.cert)
        .map_err(|err| format!("write guest TLS cert {}: {err}", cert_path.display()))?;
    fs::write(&key_path, &materials.key)
        .map_err(|err| format!("write guest TLS key {}: {err}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("chmod guest TLS key {}: {err}", key_path.display()))?;
    }

    Ok(())
}

fn overlay_staging_dir(overlay_disk: &Path) -> PathBuf {
    let parent = overlay_disk.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        ".openshell-overlay-staging-{}-{}",
        std::process::id(),
        openshell_core::time::now_ms()
    ))
}

async fn terminate_vm_process(child: &mut Child) -> Result<(), std::io::Error> {
    if let Some(pid) = child.id()
        && let Err(err) = kill(Pid::from_raw(pid.cast_signed()), Signal::SIGTERM)
        && err != Errno::ESRCH
    {
        return Err(std::io::Error::other(format!(
            "send SIGTERM to vm process {pid}: {err}"
        )));
    }

    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(_) => {
            child.kill().await?;
            child.wait().await.map(|_| ())
        }
    }
}

#[tracing::instrument(
    name = "vm.launch",
    skip(command),
    fields(
        otel.name = "vm.launch",
        otel.status_code = tracing::field::Empty,
        sandbox.id = %sandbox_id,
        vm.backend = ?backend,
    )
)]
fn spawn_vm_launcher(
    command: &mut Command,
    sandbox_id: &str,
    backend: &VmBackend,
) -> Result<Child, std::io::Error> {
    openshell_otel::record_error_result(command.spawn())
}

fn sandbox_snapshot(sandbox: &Sandbox, condition: SandboxCondition, deleting: bool) -> Sandbox {
    Sandbox {
        id: sandbox.id.clone(),
        name: sandbox.name.clone(),
        namespace: sandbox.namespace.clone(),
        workspace: sandbox.workspace.clone(),
        status: Some(SandboxStatus {
            sandbox_name: sandbox.name.clone(),
            instance_id: String::new(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            deleting,
        }),
        ..Default::default()
    }
}

fn status_with_condition(
    snapshot: &Sandbox,
    condition: SandboxCondition,
    deleting: bool,
) -> SandboxStatus {
    SandboxStatus {
        sandbox_name: snapshot.name.clone(),
        instance_id: String::new(),
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions: vec![condition],
        deleting,
    }
}

fn provisioning_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: "Starting".to_string(),
        message: "VM is starting".to_string(),
        last_transition_time: String::new(),
    }
}

fn deleting_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: "Deleting".to_string(),
        message: "Sandbox is being deleted".to_string(),
        last_transition_time: String::new(),
    }
}

fn stopped_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Stopped".to_string(),
        status: "True".to_string(),
        reason: "ComputeStopped".to_string(),
        message: "VM compute is stopped and persistent state is retained".to_string(),
        last_transition_time: String::new(),
    }
}

fn error_condition(reason: &str, message: &str) -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: String::new(),
    }
}

fn platform_event(source: &str, event_type: &str, reason: &str, message: String) -> PlatformEvent {
    let mut event = PlatformEvent {
        timestamp_ms: openshell_core::time::now_ms(),
        source: source.to_string(),
        r#type: event_type.to_string(),
        reason: reason.to_string(),
        message,
        metadata: HashMap::new(),
    };
    attach_vm_progress_metadata(&mut event);
    event
}

fn attach_vm_progress_metadata(event: &mut PlatformEvent) {
    if event.source != "vm" {
        return;
    }

    match event.reason.as_str() {
        "Scheduled" => {
            mark_progress_complete(
                &mut event.metadata,
                PROGRESS_STEP_REQUESTING_SANDBOX,
                "Sandbox allocated",
            );
            mark_progress_active(&mut event.metadata, PROGRESS_STEP_PULLING_IMAGE);
        }
        "Pulling" => {
            mark_progress_active(&mut event.metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(image_ref) = event.metadata.get("image_ref").cloned() {
                mark_progress_detail(&mut event.metadata, image_ref);
            } else if let Some(image_ref) = pulling_image_from_message(&event.message) {
                mark_progress_detail(&mut event.metadata, image_ref);
            }
        }
        "Pulled" => {
            let label = pulled_label(event);
            mark_progress_complete(&mut event.metadata, PROGRESS_STEP_PULLING_IMAGE, label);
            mark_progress_active(&mut event.metadata, PROGRESS_STEP_STARTING_SANDBOX);
        }
        "PullingLayer" => {
            if let Some(detail) = pulling_layer_detail(&event.metadata) {
                mark_progress_detail(&mut event.metadata, detail);
            }
        }
        "ResolvingImage" => mark_progress_detail(&mut event.metadata, "Resolving image"),
        "AuthenticatingRegistry" => {
            mark_progress_detail(&mut event.metadata, "Authenticating registry");
        }
        "FetchingManifest" => mark_progress_detail(&mut event.metadata, "Fetching image manifest"),
        "CacheHit" => mark_progress_detail(&mut event.metadata, "Using cached root disk"),
        "CacheMiss" => mark_progress_detail(&mut event.metadata, "Preparing image cache"),
        "WaitingForImageCacheLock" => {
            mark_progress_detail(&mut event.metadata, "Waiting for image cache lock");
        }
        "ExportingRootfs" => {
            mark_progress_detail(&mut event.metadata, "Exporting local image rootfs");
        }
        "PreparingRootfs" => mark_progress_detail(&mut event.metadata, "Preparing rootfs"),
        "CreatingRootDisk" => mark_progress_detail(&mut event.metadata, "Formatting root disk"),
        "PreparingOverlay" => mark_progress_detail(&mut event.metadata, "Preparing overlay disk"),
        "Started" => mark_progress_detail(&mut event.metadata, "Waiting for VM supervisor"),
        _ => {}
    }
}

fn pulling_image_from_message(message: &str) -> Option<String> {
    let image = message
        .strip_prefix("Pulling image ")
        .map(str::trim)
        .map(|value| value.trim_matches('"'))?;
    (!image.is_empty()).then(|| image.to_string())
}

fn pulled_label(event: &PlatformEvent) -> String {
    event
        .metadata
        .get("image_size_bytes")
        .and_then(|value| value.parse::<u64>().ok())
        .map_or_else(
            || "Image pulled".to_string(),
            |bytes| format!("Image pulled ({})", format_bytes(bytes)),
        )
}

fn pulling_layer_detail(metadata: &HashMap<String, String>) -> Option<String> {
    let index = metadata.get("layer_index")?;
    let total = metadata.get("layer_total")?;
    let size = metadata
        .get("layer_size_bytes")
        .and_then(|value| value.parse::<u64>().ok())
        .map(format_bytes);
    Some(size.map_or_else(
        || format!("Layer {index}/{total}"),
        |size| format!("Layer {index}/{total} ({size})"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name};
    use openshell_core::progress::{
        PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
        PROGRESS_COMPLETE_STEP_KEY,
    };
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec as SandboxSpec, DriverSandboxTemplate as SandboxTemplate,
        GpuResourceRequirements, ResourceRequirements,
    };
    use prost_types::{Struct, Value, value::Kind};
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tonic::Code;

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    #[test]
    fn registry_throttling_errors_are_retryable() {
        let error = OciDistributionError::RegistryError {
            envelope: oci_client::errors::OciEnvelope {
                errors: vec![oci_client::errors::OciError {
                    code: OciErrorCode::Toomanyrequests,
                    message: "retry-after: 829.756µs, allowed: 44000/minute".to_string(),
                    detail: serde_json::Value::Null,
                }],
            },
            url: "https://ghcr.io/v2/example/manifests/latest".to_string(),
        };

        assert!(registry_error_is_retryable(&error));
    }

    #[test]
    fn permanent_registry_errors_are_not_retryable() {
        let error = OciDistributionError::UnauthorizedError {
            url: "https://example.invalid/v2/image/manifests/latest".to_string(),
        };

        assert!(!registry_error_is_retryable(&error));
    }

    #[tokio::test]
    async fn registry_request_retries_transient_errors_until_success() {
        let attempts = AtomicUsize::new(0);
        let result = retry_registry_request_with_delay("test request", Duration::ZERO, || async {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            if attempt < 2 {
                Err(OciDistributionError::ServerError {
                    code: 503,
                    url: "https://example.invalid/v2/".to_string(),
                    message: "temporarily unavailable".to_string(),
                })
            } else {
                Ok("success")
            }
        })
        .await;

        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    struct TestTracing {
        exporter: opentelemetry_sdk::trace::InMemorySpanExporter,
        _provider: opentelemetry_sdk::trace::SdkTracerProvider,
        dispatch: tracing::Dispatch,
    }

    impl TestTracing {
        fn new() -> Self {
            use opentelemetry::trace::TracerProvider as _;
            use tracing_subscriber::layer::SubscriberExt as _;

            let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build();
            let subscriber = tracing_subscriber::registry().with(
                tracing_opentelemetry::layer().with_tracer(provider.tracer("vm-driver-test")),
            );
            Self {
                exporter,
                _provider: provider,
                dispatch: tracing::Dispatch::new(subscriber),
            }
        }
    }

    fn assert_is_root(span: &opentelemetry_sdk::trace::SpanData) {
        assert_eq!(
            span.parent_span_id,
            opentelemetry::trace::SpanId::INVALID,
            "{:?} should be a trace root",
            span.name
        );
    }

    fn assert_has_parent(span: &opentelemetry_sdk::trace::SpanData) {
        assert_ne!(
            span.parent_span_id,
            opentelemetry::trace::SpanId::INVALID,
            "{:?} should have a parent",
            span.name
        );
    }

    fn request_with_traceparent<T>(message: T) -> Request<T> {
        let mut request = Request::new(message);
        request.metadata_mut().insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        request
    }

    type TestDriverClient =
        openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient<
            tonic::transport::Channel,
        >;

    struct TracedDriverClient {
        client: TestDriverClient,
        shutdown: tokio::sync::oneshot::Sender<()>,
        server: JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl std::ops::Deref for TracedDriverClient {
        type Target = TestDriverClient;

        fn deref(&self) -> &Self::Target {
            &self.client
        }
    }

    impl std::ops::DerefMut for TracedDriverClient {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.client
        }
    }

    impl TracedDriverClient {
        async fn shutdown(self) {
            let Self {
                client,
                shutdown,
                server,
            } = self;
            drop(client);
            let _ = shutdown.send(());
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("traced driver test server should stop")
                .expect("traced driver test server task should not panic")
                .expect("traced driver test server should stop cleanly");
        }
    }

    async fn traced_driver_client(driver: VmDriver) -> TracedDriverClient {
        use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .layer(openshell_otel::compute_driver_rpc_layer())
                .add_service(ComputeDriverServer::new(driver))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let client = TestDriverClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        TracedDriverClient {
            client,
            shutdown,
            server,
        }
    }

    #[tokio::test]
    async fn compute_driver_rpc_span_continues_the_gateway_trace() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        let mut client = traced_driver_client(driver).await;

        client
            .get_capabilities(request_with_traceparent(GetCapabilitiesRequest {}))
            .await
            .unwrap();
        client.shutdown().await;

        let spans = traced.exporter.get_finished_spans().unwrap();
        let rpc_spans = spans
            .iter()
            .filter(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
            .collect::<Vec<_>>();
        assert_eq!(
            rpc_spans.len(),
            1,
            "middleware should create exactly one VM driver RPC span, got {:?}",
            spans.iter().map(|span| &span.name).collect::<Vec<_>>()
        );
        let span = rpc_spans[0];
        assert_eq!(
            span.span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
    }

    #[tokio::test]
    async fn compute_driver_rpcs_record_server_spans_and_error_status() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        let mut client = traced_driver_client(driver).await;

        client
            .get_capabilities(request_with_traceparent(GetCapabilitiesRequest {}))
            .await
            .unwrap();
        assert!(
            client
                .validate_sandbox_create(request_with_traceparent(ValidateSandboxCreateRequest {
                    sandbox: None,
                }))
                .await
                .is_err()
        );
        assert!(
            client
                .create_sandbox(request_with_traceparent(CreateSandboxRequest {
                    sandbox: None,
                }))
                .await
                .is_err()
        );
        assert!(
            client
                .get_sandbox(request_with_traceparent(GetSandboxRequest {
                    sandbox_id: String::new(),
                    sandbox_name: String::new(),
                }))
                .await
                .is_err()
        );
        client
            .list_sandboxes(request_with_traceparent(ListSandboxesRequest {}))
            .await
            .unwrap();
        assert!(
            client
                .stop_sandbox(request_with_traceparent(StopSandboxRequest {
                    sandbox_id: String::new(),
                    sandbox_name: String::new(),
                }))
                .await
                .is_err()
        );
        client
            .delete_sandbox(request_with_traceparent(DeleteSandboxRequest {
                sandbox_id: String::new(),
                sandbox_name: String::new(),
            }))
            .await
            .unwrap();
        let watch = client
            .watch_sandboxes(request_with_traceparent(WatchSandboxesRequest {}))
            .await
            .unwrap();
        drop(watch);
        client.shutdown().await;

        let spans = traced.exporter.get_finished_spans().unwrap();
        let expected = [
            "openshell.compute.v1.ComputeDriver/GetCapabilities",
            "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate",
            "openshell.compute.v1.ComputeDriver/CreateSandbox",
            "openshell.compute.v1.ComputeDriver/GetSandbox",
            "openshell.compute.v1.ComputeDriver/ListSandboxes",
            "openshell.compute.v1.ComputeDriver/StopSandbox",
            "openshell.compute.v1.ComputeDriver/DeleteSandbox",
            "openshell.compute.v1.ComputeDriver/WatchSandboxes",
        ];
        for name in expected {
            let span = spans
                .iter()
                .find(|span| span.name == name)
                .unwrap_or_else(|| panic!("missing {name} span"));
            assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
            assert_has_parent(span);
        }
        for name in [
            "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate",
            "openshell.compute.v1.ComputeDriver/CreateSandbox",
            "openshell.compute.v1.ComputeDriver/GetSandbox",
            "openshell.compute.v1.ComputeDriver/StopSandbox",
        ] {
            let span = spans.iter().find(|span| span.name == name).unwrap();
            assert!(
                matches!(span.status, opentelemetry::trace::Status::Error { .. }),
                "{name} should record an error status, got {:?}",
                span.status
            );
        }
        let delete_rpc = spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/DeleteSandbox")
            .expect("delete RPC span");
        let cleanup = spans
            .iter()
            .find(|span| {
                span.name == "vm.teardown"
                    && span.span_context.trace_id() == delete_rpc.span_context.trace_id()
            })
            .expect("delete cleanup span");
        assert_has_parent(cleanup);
    }

    #[tokio::test]
    async fn spawned_provisioning_and_phases_have_parents() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let temp = tempfile::tempdir().unwrap();
        let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        driver.config.state_dir = temp.path().to_path_buf();
        let sandbox = Sandbox {
            id: "sb-spawned-trace".to_string(),
            name: "spawned-trace".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "invalid image reference".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let request = request_with_traceparent(CreateSandboxRequest {
            sandbox: Some(sandbox),
        });

        let mut client = traced_driver_client(driver.clone()).await;
        client.create_sandbox(request).await.unwrap();
        driver
            .wait_for_provisioning_for_test("sb-spawned-trace")
            .await;
        client.shutdown().await;

        let spans = traced.exporter.get_finished_spans().unwrap();
        let provisioning = spans
            .iter()
            .find(|span| span.name == "vm.provision")
            .expect("spawned provisioning span");
        assert_has_parent(provisioning);
        let prepare_images = spans
            .iter()
            .find(|span| span.name == "vm.prepare_images")
            .expect("image preparation span");
        assert_has_parent(prepare_images);
        let resolve_bootstrap = spans
            .iter()
            .find(|span| span.name == "vm.resolve_bootstrap_image")
            .expect("bootstrap image resolution span");
        assert_has_parent(resolve_bootstrap);
    }

    #[tokio::test]
    async fn startup_reconciliation_is_root_and_restore_operations_have_parents() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let temp = tempfile::tempdir().unwrap();
        let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        driver.config.state_dir = temp.path().to_path_buf();
        for suffix in ["a", "b"] {
            let sandbox = Sandbox {
                id: format!("sb-restored-trace-{suffix}"),
                name: format!("restored-trace-{suffix}"),
                spec: Some(SandboxSpec {
                    template: Some(SandboxTemplate {
                        image: "invalid image reference".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let state_dir = temp.path().join("sandboxes").join(&sandbox.id);
            tokio::fs::create_dir_all(&state_dir).await.unwrap();
            write_sandbox_request(&state_dir, &sandbox).await.unwrap();
        }

        driver.restore_persisted_sandboxes().await;
        for suffix in ["a", "b"] {
            driver
                .wait_for_provisioning_for_test(&format!("sb-restored-trace-{suffix}"))
                .await;
        }

        let spans = traced.exporter.get_finished_spans().unwrap();

        let reconciliations = spans
            .iter()
            .filter(|span| span.name == "reconcile.sandboxes")
            .collect::<Vec<_>>();
        assert_eq!(
            reconciliations.len(),
            1,
            "startup should reconcile all persisted sandboxes in one trace"
        );
        let reconciliation = reconciliations[0];
        assert_is_root(reconciliation);
        let restorations = spans
            .iter()
            .filter(|span| span.name == "vm.restore")
            .collect::<Vec<_>>();
        assert_eq!(restorations.len(), 2);
        for restoration in restorations {
            assert_has_parent(restoration);
        }
        let provisioning = spans
            .iter()
            .filter(|span| span.name == "vm.provision")
            .collect::<Vec<_>>();
        assert_eq!(provisioning.len(), 2);
        for span in provisioning {
            assert_has_parent(span);
        }
        let prepare_images = spans
            .iter()
            .filter(|span| span.name == "vm.prepare_images")
            .collect::<Vec<_>>();
        assert_eq!(prepare_images.len(), 2);
        for span in prepare_images {
            assert_has_parent(span);
        }
    }

    #[tokio::test]
    async fn startup_does_not_restore_terminal_canonical_process() {
        let temp = tempfile::tempdir().unwrap();
        let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        driver.config.state_dir = temp.path().to_path_buf();
        let sandbox = Sandbox {
            id: "sb-terminal-main".to_string(),
            name: "terminal-main".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "unused-image".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let state_dir = temp.path().join("sandboxes").join(&sandbox.id);
        tokio::fs::create_dir_all(&state_dir).await.unwrap();
        write_sandbox_request(&state_dir, &sandbox).await.unwrap();
        write_private_file(
            &state_dir.join(MAIN_PROCESS_EXITED_FILE),
            b"terminal\n".to_vec(),
        )
        .await
        .unwrap();

        driver.restore_persisted_sandboxes().await;

        let registry = driver.registry.lock().await;
        let record = registry.get(&sandbox.id).expect("terminal record");
        assert!(record.process.is_none());
        assert!(record.provisioning_task.is_none());
        let status = record.snapshot.status.as_ref().expect("terminal status");
        assert!(status.conditions.iter().any(|condition| {
            condition.reason == "ProcessExited" && condition.status == "False"
        }));
    }

    #[tokio::test]
    async fn background_provisioning_does_not_extend_the_rpc_span_lifetime() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let rpc = tracing::info_span!("openshell.compute.v1.ComputeDriver/CreateSandbox");
        let entered = rpc.enter();
        let provisioning =
            provisioning_span(&rpc.context(), "sb-lifetime", "invalid image reference");
        drop(entered);
        drop(rpc);

        assert!(
            traced
                .exporter
                .get_finished_spans()
                .unwrap()
                .iter()
                .any(|span| span.name == "openshell.compute.v1.ComputeDriver/CreateSandbox"),
            "the RPC span should finish while background provisioning is still active"
        );
        drop(provisioning);
    }

    #[tokio::test]
    async fn overlay_preparation_records_a_provisioning_phase_span() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        driver.config.overlay_disk_mib = u64::MAX;
        let parent = tracing::info_span!("vm.provision");

        let result = driver
            .prepare_runtime_overlay(Path::new("/unused"), None, None, OverlayPreparation::Fresh)
            .instrument(parent)
            .await;
        assert!(result.is_err(), "overflow should stop before disk I/O");

        let spans = traced.exporter.get_finished_spans().unwrap();
        let overlay = spans
            .iter()
            .find(|span| span.name == "vm.prepare_overlay")
            .expect("overlay preparation span");
        assert_has_parent(overlay);
        assert!(
            matches!(overlay.status, opentelemetry::trace::Status::Error { .. }),
            "failed overlay preparation should mark its phase span, got {:?}",
            overlay.status
        );
    }

    #[tokio::test]
    async fn post_overlay_provisioning_stages_record_child_spans() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::with(vec![Arc::new(
            AlwaysFailsExtension,
        )]));
        let sandbox = Sandbox {
            id: "sb-post-overlay".to_string(),
            ..Default::default()
        };
        let mut plan = driver
            .build_vm_launch_plan(&sandbox.id, false, false, None)
            .unwrap();
        let provisioning = tracing::info_span!("vm.provision");

        async {
            driver
                .lifecycle_extensions
                .configure_launch(&sandbox, Path::new("/unused"), &mut plan)
                .await
                .unwrap();
            let before_launch = driver
                .lifecycle_extensions
                .before_launch(&sandbox, Path::new("/unused"), &mut plan)
                .await;
            assert!(
                before_launch.is_err(),
                "the lifecycle hook should reject launch"
            );
            let invalid_dropin = GuestInitDropin::new("../invalid", Vec::new());
            assert!(
                inject_guest_init_dropins(Path::new("/unused"), &[invalid_dropin]).is_err(),
                "an invalid drop-in should fail after creating its span"
            );
        }
        .instrument(provisioning)
        .await;

        let spans = traced.exporter.get_finished_spans().unwrap();
        for name in [
            "vm.configure_launch",
            "vm.before_launch",
            "vm.prepare_guest",
        ] {
            let span = spans
                .iter()
                .find(|span| span.name == name)
                .unwrap_or_else(|| panic!("missing {name} span"));
            assert_has_parent(span);
        }
        for name in ["vm.before_launch", "vm.prepare_guest"] {
            let span = spans.iter().find(|span| span.name == name).unwrap();
            assert!(
                matches!(span.status, opentelemetry::trace::Status::Error { .. }),
                "{name} should record an error status, got {:?}",
                span.status
            );
        }
    }

    #[tokio::test]
    async fn launcher_spawn_failure_records_a_failed_provisioning_phase_span() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let provisioning = tracing::info_span!("vm.provision");
        let mut command = Command::new("/openshell-test/nonexistent-vm-launcher");

        let result =
            async { spawn_vm_launcher(&mut command, "sb-launch-trace", &VmBackend::Libkrun) }
                .instrument(provisioning)
                .await;
        assert!(result.is_err(), "the nonexistent launcher should fail");

        let spans = traced.exporter.get_finished_spans().unwrap();
        let launch = spans
            .iter()
            .find(|span| span.name == "vm.launch")
            .expect("launcher span");
        assert_has_parent(launch);
        assert!(
            matches!(launch.status, opentelemetry::trace::Status::Error { .. }),
            "failed launcher spawn should mark its phase span, got {:?}",
            launch.status
        );
    }

    #[tokio::test]
    async fn delete_failure_marks_the_delete_span() {
        let traced = TestTracing::new();
        let _dispatch = tracing::dispatcher::set_default(&traced.dispatch);
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());

        assert!(driver.delete_sandbox("../invalid", "").await.is_err());

        let spans = traced.exporter.get_finished_spans().unwrap();
        let deletion = spans
            .iter()
            .find(|span| span.name == "vm.teardown")
            .expect("delete span");
        assert!(
            matches!(deletion.status, opentelemetry::trace::Status::Error { .. }),
            "failed deletion should mark its span, got {:?}",
            deletion.status
        );
    }

    fn gpu_device_ids_config(device_ids: &[&str]) -> Struct {
        list_string_driver_config("gpu_device_ids", device_ids)
    }

    fn gpu_device_id_typo_config(device_ids: &[&str]) -> Struct {
        list_string_driver_config("gpu_device_id", device_ids)
    }

    fn list_string_driver_config(field: &str, values: &[&str]) -> Struct {
        Struct {
            fields: std::iter::once((
                field.to_string(),
                Value {
                    kind: Some(Kind::ListValue(prost_types::ListValue {
                        values: values
                            .iter()
                            .map(|device_id| Value {
                                kind: Some(Kind::StringValue((*device_id).to_string())),
                            })
                            .collect(),
                    })),
                },
            ))
            .collect(),
        }
    }

    fn gpu_resources(count: Option<u32>) -> ResourceRequirements {
        ResourceRequirements {
            gpu: Some(GpuResourceRequirements { count }),
        }
    }

    #[test]
    fn vm_pulling_layer_event_adds_progress_detail_metadata() {
        let mut event = platform_event(
            "vm",
            "Normal",
            "PullingLayer",
            "Pulling layer 3/8 for image".to_string(),
        );
        event.metadata = HashMap::from([
            ("layer_index".to_string(), "3".to_string()),
            ("layer_total".to_string(), "8".to_string()),
            ("layer_size_bytes".to_string(), "44040192".to_string()),
        ]);

        attach_vm_progress_metadata(&mut event);

        assert_eq!(
            event
                .metadata
                .get(PROGRESS_ACTIVE_DETAIL_KEY)
                .map(String::as_str),
            Some("Layer 3/8 (42 MB)")
        );
    }

    #[test]
    fn vm_pulled_event_adds_completed_image_progress_metadata() {
        let mut event = platform_event(
            "vm",
            "Normal",
            "Pulled",
            "Successfully pulled image".to_string(),
        );
        event
            .metadata
            .insert("image_size_bytes".to_string(), "44040192".to_string());

        attach_vm_progress_metadata(&mut event);

        assert_eq!(
            event
                .metadata
                .get(PROGRESS_COMPLETE_STEP_KEY)
                .map(String::as_str),
            Some(PROGRESS_STEP_PULLING_IMAGE)
        );
        assert_eq!(
            event
                .metadata
                .get(PROGRESS_COMPLETE_LABEL_KEY)
                .map(String::as_str),
            Some("Image pulled (42 MB)")
        );
        assert_eq!(
            event
                .metadata
                .get(PROGRESS_ACTIVE_STEP_KEY)
                .map(String::as_str),
            Some(PROGRESS_STEP_STARTING_SANDBOX)
        );
    }

    #[test]
    fn validate_vm_sandbox_rejects_gpu_when_not_enabled() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, false)
            .expect_err("gpu should be rejected when not enabled");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("GPU support is not enabled"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_missing_gpu_support_before_request_shape() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(Some(2))),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, false)
            .expect_err("missing GPU support should be rejected before request shape");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("GPU support is not enabled"));
    }

    #[test]
    fn validate_vm_sandbox_accepts_gpu_when_enabled() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, true).expect("gpu should be accepted when enabled");
    }

    #[test]
    fn validate_vm_sandbox_accepts_gpu_count_one() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(Some(1))),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, true).expect("one GPU should be accepted when enabled");
    }

    #[test]
    fn validate_vm_sandbox_accepts_single_gpu_device_without_gpu_count() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, true)
            .expect("single exact GPU device should be compatible with a default GPU request");
    }

    #[test]
    fn validate_vm_sandbox_rejects_multiple_gpu_device_ids_without_gpu_count() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0", "0000:31:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, true)
            .expect_err("multiple GPU device IDs without count should be rejected");

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message()
                .contains("gpu count (1) must match driver_config.gpu_device_ids length (2)")
        );
    }

    #[test]
    fn validate_vm_sandbox_accepts_gpu_count_matching_device_id() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(Some(1))),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, true)
            .expect("matching explicit GPU device count should be accepted");
    }

    #[test]
    fn validate_vm_sandbox_rejects_gpu_count_above_one() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(Some(2))),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, true)
            .expect_err("multiple GPU VM request should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("support only one GPU"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_gpu_count_mismatched_device_id() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(Some(2))),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, true)
            .expect_err("mismatched explicit GPU device count should be rejected");

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message()
                .contains("gpu count (2) must match driver_config.gpu_device_ids length (1)")
        );
    }

    #[test]
    fn validate_vm_sandbox_rejects_gpu_device_without_gpu_request() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, true)
            .expect_err("gpu_device_ids without a GPU request should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("requires a gpu request"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_multiple_gpu_device_ids() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(Some(2))),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&["0000:2d:00.0", "0000:31:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err =
            validate_vm_sandbox(&sandbox, true).expect_err("multiple GPUs should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("at most one gpu_device_ids"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_empty_gpu_device_ids() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_ids_config(&[])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err =
            validate_vm_sandbox(&sandbox, true).expect_err("empty GPU IDs should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("non-empty list"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_unknown_driver_config_fields() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                template: Some(SandboxTemplate {
                    driver_config: Some(gpu_device_id_typo_config(&["0000:2d:00.0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err =
            validate_vm_sandbox(&sandbox, true).expect_err("unknown field should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown field"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_template_errors_before_device_config() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                template: Some(SandboxTemplate {
                    agent_socket_path: "/tmp/agent.sock".to_string(),
                    driver_config: Some(gpu_device_ids_config(&[])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err =
            validate_vm_sandbox(&sandbox, true).expect_err("template error should be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("agent_socket_path"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_platform_config() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    platform_config: Some(Struct {
                        fields: std::iter::once((
                            "runtime_class_name".to_string(),
                            Value {
                                kind: Some(Kind::StringValue("kata".to_string())),
                            },
                        ))
                        .collect(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err =
            validate_vm_sandbox(&sandbox, false).expect_err("platform config should be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("platform_config"));
    }

    #[test]
    fn validate_vm_sandbox_accepts_template_image() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "ghcr.io/example/sandbox:latest".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, false).expect("template.image should be accepted");
    }

    #[test]
    fn validate_vm_sandbox_accepts_template_resources_as_noop() {
        use openshell_core::proto::compute::v1::DriverResourceRequirements;

        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    resources: Some(DriverResourceRequirements {
                        cpu_limit: "2".to_string(),
                        memory_limit: "4Gi".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, false)
            .expect("template.resources should be accepted and ignored");
    }

    #[test]
    fn validate_vm_sandbox_rejects_path_unsafe_ids() {
        let mut unsafe_ids = [
            "",
            ".",
            "..",
            "../escape",
            "/tmp/escape",
            "nested/path",
            "nested\\path",
            "bad\nid",
            "bad id",
            "unicodé",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        unsafe_ids.push("a".repeat(129));

        for sandbox_id in unsafe_ids {
            let sandbox = Sandbox {
                id: sandbox_id.clone(),
                spec: Some(SandboxSpec {
                    template: Some(SandboxTemplate {
                        image: "ghcr.io/example/sandbox:latest".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let err = validate_vm_sandbox(&sandbox, false)
                .expect_err("path-unsafe sandbox id should be rejected");
            assert_eq!(err.code(), Code::InvalidArgument, "id={sandbox_id:?}");
            assert!(err.message().contains("sandbox id"), "id={sandbox_id:?}");
        }
    }

    #[test]
    fn sandbox_state_dir_rejects_path_unsafe_ids() {
        let err = sandbox_state_dir(Path::new("/tmp/openshell-vm"), "../escape")
            .expect_err("path traversal should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn sandbox_runtime_disk_paths_use_per_sandbox_overlay() {
        let driver_state = Path::new("/tmp/openshell-vm");
        let state_dir = driver_state.join("sandboxes").join("sandbox-123");

        let disks = sandbox_runtime_disk_paths(&state_dir);

        assert_eq!(disks.overlay_disk, state_dir.join(SANDBOX_OVERLAY_IMAGE));
    }

    #[test]
    fn overlay_template_image_is_keyed_by_size_and_layout() {
        let path = overlay_template_image(Path::new("/tmp/openshell-vm"), 4 * 1024 * 1024);

        assert_eq!(
            path,
            Path::new("/tmp/openshell-vm")
                .join(IMAGE_CACHE_ROOT_DIR)
                .join(OVERLAY_TEMPLATE_CACHE_DIR)
                .join(OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION)
                .join("4194304.ext4")
        );
    }

    #[tokio::test]
    async fn sandbox_request_metadata_round_trips_for_start() {
        let base = unique_temp_dir();
        let state_dir = base.join("sandboxes").join("sandbox-123");
        std::fs::create_dir_all(&state_dir).unwrap();
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "start-sandbox".to_string(),
            namespace: "vm-dev".to_string(),
            spec: Some(SandboxSpec {
                environment: HashMap::from([("KEY".to_string(), "value".to_string())]),
                template: Some(SandboxTemplate {
                    image: "ghcr.io/example/sandbox:latest".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        write_sandbox_request(&state_dir, &sandbox)
            .await
            .expect("write sandbox request");
        let restored = read_sandbox_request(&state_dir.join(SANDBOX_REQUEST_FILE))
            .await
            .expect("read sandbox request");

        assert_eq!(restored, sandbox);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let dir_mode = std::fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777;
            let file_mode = std::fs::metadata(state_dir.join(SANDBOX_REQUEST_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
        validate_restored_sandbox_state(&base, &state_dir, &restored)
            .expect("restored state should validate");

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn failed_start_preserves_stopped_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        driver.config.state_dir = temp.path().to_path_buf();
        let sandbox = Sandbox {
            id: "sandbox-stopped".to_string(),
            name: "stopped".to_string(),
            ..Default::default()
        };
        let state_dir = temp.path().join("sandboxes").join(&sandbox.id);
        create_private_dir_all(&state_dir).await.unwrap();
        write_sandbox_request(&state_dir, &sandbox).await.unwrap();
        tokio::fs::write(state_dir.join(SANDBOX_STOPPED_FILE), b"stopped\n")
            .await
            .unwrap();
        let snapshot = sandbox_snapshot(&sandbox, stopped_condition(), false);
        driver.registry.lock().await.insert(
            sandbox.id.clone(),
            SandboxRecord {
                snapshot,
                state_dir: state_dir.clone(),
                process: None,
                provisioning_task: None,
                gpu_bdf: None,
                qemu_network_allocated: false,
                deleting: false,
            },
        );

        let err = driver
            .start_sandbox(&sandbox.id, &sandbox.name)
            .await
            .expect_err("start without an image should fail");

        assert_eq!(err.code(), Code::Internal);
        assert!(
            tokio::fs::metadata(state_dir.join(SANDBOX_STOPPED_FILE))
                .await
                .is_ok(),
            "failed start must retain its durable stop marker"
        );
        let restored = driver
            .get_sandbox(&sandbox.id, &sandbox.name)
            .await
            .unwrap()
            .expect("failed start must retain its stopped registry record");
        let condition = restored
            .status
            .as_ref()
            .and_then(|status| status.conditions.first())
            .expect("stopped condition");
        assert_eq!(condition.r#type, "Stopped");
        assert_eq!(condition.status, "True");
    }

    #[test]
    fn prepare_sandbox_overlay_preserves_existing_overlay_on_start() {
        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let template = base.join("template.ext4");
        let overlay = base.join("overlay.ext4");
        std::fs::write(&template, b"fresh-overlay").unwrap();
        std::fs::write(&overlay, b"saved-overlay").unwrap();

        prepare_sandbox_overlay_image(
            &template,
            &overlay,
            None,
            None,
            OverlayPreparation::PreserveExisting,
            "saved-overlay".len() as u64,
        )
        .expect("preserve existing overlay");

        assert_eq!(std::fs::read(&overlay).unwrap(), b"saved-overlay");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn prepare_sandbox_overlay_creates_missing_overlay_on_start() {
        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let template = base.join("template.ext4");
        let overlay = base.join("overlay.ext4");
        std::fs::write(&template, b"fresh-overlay").unwrap();

        prepare_sandbox_overlay_image(
            &template,
            &overlay,
            None,
            None,
            OverlayPreparation::PreserveExisting,
            "fresh-overlay".len() as u64,
        )
        .expect("create missing overlay");

        assert_eq!(std::fs::read(&overlay).unwrap(), b"fresh-overlay");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn overlay_upper_path_targets_overlay_upperdir() {
        assert_eq!(
            overlay_upper_path(GUEST_TLS_KEY_PATH),
            "/upper/opt/openshell/tls/tls.key"
        );
    }

    #[test]
    fn capabilities_report_configured_default_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:dev".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        assert_eq!(driver.capabilities().default_image, "openshell/sandbox:dev");
    }

    #[test]
    fn resolved_sandbox_image_prefers_template_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "ghcr.io/example/custom:latest".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            driver.resolved_sandbox_image(&sandbox).as_deref(),
            Some("ghcr.io/example/custom:latest")
        );
    }

    #[test]
    fn resolved_sandbox_image_falls_back_to_driver_default() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate::default()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            driver.resolved_sandbox_image(&sandbox).as_deref(),
            Some("openshell/sandbox:default")
        );
    }

    #[test]
    fn resolved_sandbox_image_returns_none_without_template_or_default() {
        let driver = VmDriver {
            config: VmDriverConfig::default(),
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate::default()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(driver.resolved_sandbox_image(&sandbox).is_none());
    }

    #[test]
    fn bootstrap_image_ref_prefers_explicit_bootstrap_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                bootstrap_image: "openshell/sandbox-bootstrap:latest".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        assert_eq!(
            driver.bootstrap_image_ref("ghcr.io/example/app:latest"),
            "openshell/sandbox-bootstrap:latest"
        );
    }

    #[test]
    fn bootstrap_image_ref_falls_back_to_default_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        assert_eq!(
            driver.bootstrap_image_ref("ghcr.io/example/app:latest"),
            "openshell/sandbox:default"
        );
    }

    #[test]
    fn bootstrap_image_ref_falls_back_to_requested_image() {
        let driver = VmDriver {
            config: VmDriverConfig::default(),
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        assert_eq!(
            driver.bootstrap_image_ref("ghcr.io/example/app:latest"),
            "ghcr.io/example/app:latest"
        );
    }

    #[test]
    fn merged_environment_prefers_spec_values() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                environment: HashMap::from([("A".to_string(), "spec".to_string())]),
                template: Some(SandboxTemplate {
                    environment: HashMap::from([
                        ("A".to_string(), "template".to_string()),
                        ("B".to_string(), "template".to_string()),
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = merged_environment(&sandbox);
        assert_eq!(merged.get("A"), Some(&"spec".to_string()));
        assert_eq!(merged.get("B"), Some(&"template".to_string()));
    }

    #[test]
    fn build_guest_environment_sets_supervisor_defaults() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "breezy-rhinoceros".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        assert!(env.contains(&"HOME=/root".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_ENDPOINT=http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/"
        )));
        assert!(env.contains(&"OPENSHELL_SANDBOX_ID=sandbox-123".to_string()));
        assert!(env.contains(&"OPENSHELL_SANDBOX=breezy-rhinoceros".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_SSH_SOCKET_PATH={GUEST_SSH_SOCKET_PATH}"
        )));
    }

    #[test]
    fn validate_sandbox_identity_accepts_non_root_system_ids() {
        let config = VmDriverConfig {
            sandbox_uid: Some(500),
            sandbox_gid: Some(30),
            ..Default::default()
        };
        assert!(config.validate_sandbox_identity().is_ok());
    }

    #[test]
    fn persisted_legacy_sandbox_without_command_uses_scratch_main() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        // Requests persisted before the canonical-main contract have a
        // present DriverSandboxSpec but no command or tty fields.
        let sandbox = Sandbox {
            id: "legacy-sandbox".to_string(),
            name: "legacy-sandbox".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        let encoded = env
            .iter()
            .find_map(|entry| {
                entry.strip_prefix(&format!(
                    "{}=",
                    openshell_core::sandbox_env::MAIN_PROCESS_SPEC
                ))
            })
            .expect("main process environment");
        let main = openshell_core::sandbox_env::MainProcessConfig::decode(encoded)
            .expect("legacy persisted request should produce a valid main config");

        assert_eq!(
            main,
            openshell_core::sandbox_env::MainProcessConfig::scratch()
        );
    }

    #[test]
    fn build_guest_environment_preserves_main_command_spaces() {
        let config = VmDriverConfig {
            openshell_endpoint: "https://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let command = vec![
            "sh".to_string(),
            "-lc".to_string(),
            "echo ready; while true; do sleep 1; done".to_string(),
        ];
        let sandbox = Sandbox {
            id: "space-command".to_string(),
            name: "space-command".to_string(),
            spec: Some(SandboxSpec {
                command: command.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        let encoded = env
            .iter()
            .find_map(|entry| {
                entry.strip_prefix(&format!(
                    "{}=",
                    openshell_core::sandbox_env::MAIN_PROCESS_SPEC
                ))
            })
            .expect("main process environment");

        assert!(!encoded.contains(char::is_whitespace));
        let main = openshell_core::sandbox_env::MainProcessConfig::decode(encoded).unwrap();
        assert_eq!(main.command, command);
    }

    #[test]
    fn build_guest_environment_uses_token_file_without_raw_token_env() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                sandbox_token: "secret.jwt.value".to_string(),
                environment: HashMap::from([(
                    openshell_core::sandbox_env::SANDBOX_TOKEN.to_string(),
                    "user-provided-token".to_string(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);

        assert!(!env.iter().any(|v| v.starts_with(&format!(
            "{}=",
            openshell_core::sandbox_env::SANDBOX_TOKEN
        ))));
        assert!(env.contains(&format!(
            "{}={GUEST_SANDBOX_TOKEN_PATH}",
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE
        )));
    }

    #[test]
    fn build_guest_environment_strips_gateway_tls_server_name() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                environment: HashMap::from([(
                    openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME.to_string(),
                    "evil.attacker.example.com".to_string(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);

        assert!(
            !env.iter().any(|v| v.starts_with(&format!(
                "{}=",
                openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME
            ))),
            "GATEWAY_TLS_SERVER_NAME must be stripped from the guest environment"
        );
    }

    #[test]
    fn build_guest_environment_uses_deployment_telemetry_toggle() {
        let _guard = ENV_LOCK.lock().unwrap();
        temp_env::with_vars(
            [(
                openshell_core::sandbox_env::TELEMETRY_ENABLED,
                Some("false"),
            )],
            || {
                let config = VmDriverConfig {
                    openshell_endpoint: "http://127.0.0.1:8080".to_string(),
                    ..Default::default()
                };
                let sandbox = Sandbox {
                    id: "sandbox-123".to_string(),
                    name: "sandbox-123".to_string(),
                    spec: Some(SandboxSpec {
                        environment: HashMap::from([(
                            openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
                            "true".to_string(),
                        )]),
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                let env = build_guest_environment(&sandbox, &config, None);
                let telemetry_entries = env
                    .iter()
                    .filter(|entry| {
                        entry.starts_with(&format!(
                            "{}=",
                            openshell_core::sandbox_env::TELEMETRY_ENABLED
                        ))
                    })
                    .collect::<Vec<_>>();

                assert_eq!(telemetry_entries.len(), 1);
                assert_eq!(
                    telemetry_entries[0],
                    &format!("{}=false", openshell_core::sandbox_env::TELEMETRY_ENABLED)
                );
            },
        );
    }

    #[test]
    fn build_guest_environment_clears_unsupported_network_capabilities() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                environment: HashMap::from([(
                    openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES.to_string(),
                    openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY.to_string(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let env = build_guest_environment(&sandbox, &config, None);
        assert!(env.contains(&format!(
            "{}=",
            openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES
        )));
        assert!(!env.contains(&format!(
            "{}={}",
            openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
            openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY
        )));
    }

    #[test]
    fn build_guest_environment_uses_endpoint_override_for_tap() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, Some("http://10.0.128.1:8080"));
        assert!(
            env.contains(&"OPENSHELL_ENDPOINT=http://10.0.128.1:8080".to_string()),
            "TAP endpoint override must replace the default"
        );
        let endpoint_count = env
            .iter()
            .filter(|e| e.starts_with("OPENSHELL_ENDPOINT="))
            .count();
        assert_eq!(
            endpoint_count, 1,
            "must have exactly one OPENSHELL_ENDPOINT"
        );
    }

    #[test]
    fn guest_visible_openshell_endpoint_rewrites_loopback_hosts_to_gvproxy_host_alias() {
        assert_eq!(
            guest_visible_openshell_endpoint("http://127.0.0.1:8080"),
            format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("http://localhost:8080"),
            format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("https://[::1]:8443"),
            format!("https://{GVPROXY_HOST_LOOPBACK_ALIAS}:8443/")
        );
    }

    #[test]
    fn guest_visible_openshell_endpoint_preserves_non_loopback_hosts() {
        assert_eq!(
            guest_visible_openshell_endpoint(&format!(
                "http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080"
            )),
            format!("http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080")
        );
        assert_eq!(
            guest_visible_openshell_endpoint(&format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080")),
            format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("http://192.168.127.1:8080"),
            "http://192.168.127.1:8080"
        );
        assert_eq!(
            guest_visible_openshell_endpoint("https://gateway.internal:8443"),
            "https://gateway.internal:8443"
        );
    }

    #[test]
    fn image_reference_registry_host_defaults_to_docker_hub() {
        assert_eq!(image_reference_registry_host("ubuntu:24.04"), "docker.io");
        assert_eq!(
            image_reference_registry_host("library/ubuntu:24.04"),
            "docker.io"
        );
        assert_eq!(
            image_reference_registry_host("ghcr.io/nvidia/openshell/base:latest"),
            "ghcr.io"
        );
        assert_eq!(
            image_reference_registry_host("localhost/example:dev"),
            "localhost"
        );
        assert_eq!(
            image_reference_registry_host("localhost:5000/example/sandbox:dev"),
            "localhost:5000"
        );
    }

    #[test]
    fn openshell_local_build_image_ref_matches_cli_tags() {
        assert!(is_openshell_local_build_image_ref(
            "openshell/sandbox-from:123"
        ));
        assert!(!is_openshell_local_build_image_ref("ubuntu:24.04"));
        assert!(!is_openshell_local_build_image_ref(
            "ghcr.io/nvidia/openshell/base:latest"
        ));
    }

    #[test]
    fn local_image_platform_mismatch_checks_guest_platform() {
        assert!(
            local_image_platform_mismatch(
                "openshell/sandbox-from:123",
                Some("linux"),
                Some(linux_oci_arch()),
            )
            .is_none()
        );

        let err = local_image_platform_mismatch(
            "openshell/sandbox-from:123",
            Some("linux"),
            Some("wrong-arch"),
        )
        .expect("architecture mismatch should be reported");
        assert!(err.contains("wrong-arch"));
        assert!(err.contains(linux_oci_arch()));

        let err = local_image_platform_mismatch("openshell/sandbox-from:123", None, None)
            .expect("unknown platform should be reported");
        assert!(err.contains("unknown/unknown"));
    }

    #[test]
    fn apply_layer_dir_to_rootfs_honors_whiteouts() {
        let base = unique_temp_dir();
        let rootfs = base.join("rootfs");
        let layer = base.join("layer");

        fs::create_dir_all(rootfs.join("dir")).unwrap();
        fs::write(rootfs.join("removed.txt"), "old").unwrap();
        fs::write(rootfs.join("dir/old.txt"), "old").unwrap();

        fs::create_dir_all(layer.join("dir")).unwrap();
        fs::write(layer.join(".wh.removed.txt"), "").unwrap();
        fs::write(layer.join("dir/.wh..wh..opq"), "").unwrap();
        fs::write(layer.join("dir/new.txt"), "new").unwrap();

        apply_layer_dir_to_rootfs(&layer, &rootfs).unwrap();

        assert!(!rootfs.join("removed.txt").exists());
        assert!(!rootfs.join("dir/old.txt").exists());
        assert_eq!(
            fs::read_to_string(rootfs.join("dir/new.txt")).unwrap(),
            "new"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn apply_layer_dir_to_rootfs_preserves_lower_symlink_dirs() {
        let base = unique_temp_dir();
        let rootfs = base.join("rootfs");
        let layer = base.join("layer");

        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        fs::write(rootfs.join("usr/bin/bash"), "bash").unwrap();
        std::os::unix::fs::symlink("usr/bin", rootfs.join("bin")).unwrap();

        fs::create_dir_all(layer.join("bin")).unwrap();
        fs::write(layer.join("bin/foo"), "foo").unwrap();

        apply_layer_dir_to_rootfs(&layer, &rootfs).unwrap();

        assert!(
            fs::symlink_metadata(rootfs.join("bin"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "lower /bin symlink should be preserved"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/bash")).unwrap(),
            "bash"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/foo")).unwrap(),
            "foo"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn layer_compression_from_media_type_supports_common_formats() {
        assert_eq!(
            layer_compression_from_media_type("application/vnd.oci.image.layer.v1.tar").unwrap(),
            LayerCompression::None
        );
        assert_eq!(
            layer_compression_from_media_type("application/vnd.oci.image.layer.v1.tar+gzip")
                .unwrap(),
            LayerCompression::Gzip
        );
        assert_eq!(
            layer_compression_from_media_type("application/vnd.oci.image.layer.v1.tar+zstd")
                .unwrap(),
            LayerCompression::Zstd
        );
    }

    #[test]
    fn build_guest_environment_includes_tls_paths_for_https_endpoint() {
        let config = VmDriverConfig {
            openshell_endpoint: "https://127.0.0.1:8443".to_string(),
            guest_tls_ca: Some(PathBuf::from("/host/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/host/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/host/tls.key")),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        assert!(env.contains(&format!("OPENSHELL_TLS_CA={GUEST_TLS_CA_PATH}")));
        assert!(env.contains(&format!("OPENSHELL_TLS_CERT={GUEST_TLS_CERT_PATH}")));
        assert!(env.contains(&format!("OPENSHELL_TLS_KEY={GUEST_TLS_KEY_PATH}")));
    }

    #[test]
    fn vm_driver_config_requires_tls_materials_for_https_endpoint() {
        let config = VmDriverConfig {
            openshell_endpoint: "https://127.0.0.1:8443".to_string(),
            ..Default::default()
        };
        let err = config
            .tls_paths()
            .expect_err("https endpoint should require TLS materials");
        assert!(err.contains("OPENSHELL_VM_TLS_CA"));
    }

    #[tokio::test]
    async fn delete_sandbox_keeps_registry_entry_when_cleanup_fails() {
        let base = unique_temp_dir();
        let driver_state = base.join("driver-state");
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig {
                state_dir: driver_state.clone(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        let state_file = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();
        std::fs::write(&state_file, "not a directory").unwrap();

        insert_test_record(
            &driver,
            "sandbox-123",
            state_file.clone(),
            spawn_exited_child(),
        )
        .await;

        let err = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect_err("state dir cleanup should fail for a file path");
        assert!(err.message().contains("not a directory"));
        assert!(driver.registry.lock().await.contains_key("sandbox-123"));

        std::fs::remove_file(&state_file).unwrap();
        let retry_state_dir = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(&retry_state_dir).unwrap();
        {
            let mut registry = driver.registry.lock().await;
            let record = registry.get_mut("sandbox-123").unwrap();
            record.state_dir = retry_state_dir;
            record.process = Some(Arc::new(Mutex::new(VmProcess {
                child: spawn_exited_child(),
                deleting: false,
            })));
        }

        let response = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect("delete retry should succeed once cleanup works");
        assert!(response.deleted);
        assert!(!driver.registry.lock().await.contains_key("sandbox-123"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn delete_sandbox_cleans_provisioning_record_without_process() {
        let base = unique_temp_dir();
        let driver_state = base.join("driver-state");
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig {
                state_dir: driver_state.clone(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        let state_dir = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        {
            let mut registry = driver.registry.lock().await;
            registry.insert(
                "sandbox-123".to_string(),
                SandboxRecord {
                    snapshot: Sandbox {
                        id: "sandbox-123".to_string(),
                        name: "sandbox-123".to_string(),
                        ..Default::default()
                    },
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    qemu_network_allocated: false,
                    deleting: false,
                },
            );
        }

        let response = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect("delete should handle accepted-but-not-started sandboxes");
        assert!(response.deleted);
        assert!(!driver.registry.lock().await.contains_key("sandbox-123"));
        assert!(!state_dir.exists());

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn duplicate_create_keeps_existing_state_dir() {
        let base = unique_temp_dir();
        let driver_state = base.join("driver-state");
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig {
                state_dir: driver_state.clone(),
                default_image: "ghcr.io/example/sandbox:latest".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
        };

        let state_dir = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("overlay.ext4"), b"live overlay").unwrap();
        {
            let mut registry = driver.registry.lock().await;
            registry.insert(
                "sandbox-123".to_string(),
                SandboxRecord {
                    snapshot: Sandbox {
                        id: "sandbox-123".to_string(),
                        name: "sandbox-123".to_string(),
                        ..Default::default()
                    },
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    qemu_network_allocated: false,
                    deleting: false,
                },
            );
        }

        let err = driver
            .create_sandbox(&Sandbox {
                id: "sandbox-123".to_string(),
                name: "sandbox-123".to_string(),
                spec: Some(SandboxSpec::default()),
                ..Default::default()
            })
            .await
            .expect_err("duplicate create should fail");

        assert_eq!(err.code(), Code::AlreadyExists);
        assert!(state_dir.join("overlay.ext4").exists());
        assert!(driver.registry.lock().await.contains_key("sandbox-123"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn remove_sandbox_state_dir_rejects_paths_outside_state_root() {
        let base = unique_temp_dir();
        let state_root = base.join("driver-state");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let err = remove_sandbox_state_dir(&state_root, &outside)
            .await
            .expect_err("outside state paths should be rejected");
        assert!(err.message().contains("outside vm state root"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_sandbox_state_dir_rejects_symlinked_state_dir() {
        let base = unique_temp_dir();
        let state_root = base.join("driver-state");
        let target = base.join("target");
        let state_dir = sandbox_state_dir(&state_root, "sandbox-123").unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(state_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &state_dir).unwrap();

        let err = remove_sandbox_state_dir(&state_root, &state_dir)
            .await
            .expect_err("symlinked state dir should be rejected");
        assert!(err.message().contains("symlinked sandbox state dir"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn validate_openshell_endpoint_accepts_loopback_hosts() {
        validate_openshell_endpoint("http://127.0.0.1:8080")
            .expect("ipv4 loopback should be allowed for TSI");
        validate_openshell_endpoint("http://localhost:8080")
            .expect("localhost should be allowed for TSI");
        validate_openshell_endpoint("http://[::1]:8080")
            .expect("ipv6 loopback should be allowed for TSI");
    }

    #[test]
    fn validate_openshell_endpoint_rejects_unspecified_hosts() {
        let err = validate_openshell_endpoint("http://0.0.0.0:8080")
            .expect_err("unspecified endpoint should fail");
        assert!(err.contains("not reachable from sandbox VMs"));
    }

    #[test]
    fn validate_openshell_endpoint_accepts_host_gateway() {
        validate_openshell_endpoint("http://host.containers.internal:8080")
            .expect("guest-reachable host alias should be accepted");
        validate_openshell_endpoint("http://192.168.127.1:8080")
            .expect("gateway IP should be accepted");
        validate_openshell_endpoint(&format!("http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080"))
            .expect("openshell host alias should be accepted");
        validate_openshell_endpoint("https://gateway.internal:8443")
            .expect("dns endpoint should be accepted");
    }

    #[test]
    fn prepared_image_cache_identity_includes_rootfs_layout_and_openshell_version() {
        assert_eq!(
            prepared_image_cache_identity("sha256:local-image"),
            format!(
                "sandbox-prepared-rootfs-ext4-umoci-v3:openshell-{}:sha256:local-image",
                openshell_core::VERSION
            )
        );
    }

    #[test]
    fn bootstrap_image_cache_identity_includes_rootfs_layout_and_openshell_version() {
        assert_eq!(
            bootstrap_image_cache_identity("sha256:bootstrap-image"),
            format!(
                "sandbox-bootstrap-rootfs-ext4-v3:openshell-{}:sha256:bootstrap-image",
                openshell_core::VERSION
            )
        );
    }

    #[test]
    fn stage_guest_image_payload_copies_registry_oci_layout() {
        let base = unique_temp_dir();
        let staging_dir = base.join("staging");
        let layout_dir = base.join("layout");
        let blob_dir = layout_dir.join("blobs").join("sha256");
        fs::create_dir_all(&blob_dir).unwrap();
        fs::write(
            layout_dir.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(layout_dir.join("index.json"), "{}").unwrap();
        fs::write(blob_dir.join("abc"), "blob").unwrap();

        stage_guest_image_payload(
            &staging_dir,
            &GuestImagePayload {
                image_ref: "ghcr.io/example/app:latest".to_string(),
                image_identity: prepared_image_cache_identity("sha256:abc"),
                source: GuestImagePayloadSource::RegistryOciLayout { layout_dir },
            },
        )
        .unwrap();

        let image_dir = staging_dir.join("config").join(GUEST_IMAGE_CONFIG_DIR);
        assert_eq!(
            fs::read_to_string(image_dir.join("source")).unwrap(),
            "oci-layout"
        );
        assert_eq!(
            fs::read_to_string(image_dir.join("ref")).unwrap(),
            "ghcr.io/example/app:latest"
        );
        assert_eq!(
            fs::read_to_string(
                image_dir
                    .join(GUEST_IMAGE_OCI_LAYOUT_DIR)
                    .join("blobs")
                    .join("sha256")
                    .join("abc")
            )
            .unwrap(),
            "blob"
        );

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn registry_layer_download_concurrency_is_bounded() {
        assert_eq!(
            registry_layer_download_concurrency_value(None),
            DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY
        );
        assert_eq!(
            registry_layer_download_concurrency_value(Some("0")),
            DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY
        );
        assert_eq!(registry_layer_download_concurrency_value(Some("8")), 8);
        assert_eq!(
            registry_layer_download_concurrency_value(Some("999")),
            MAX_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY
        );
    }

    #[tokio::test]
    async fn remove_registry_layer_staging_preserves_merged_rootfs() {
        let base = unique_temp_dir();
        let layers_dir = base.join("layers");
        let rootfs_dir = base.join("rootfs");
        fs::create_dir_all(&layers_dir).unwrap();
        fs::create_dir_all(&rootfs_dir).unwrap();
        fs::write(layers_dir.join("layer.blob"), b"compressed layer").unwrap();
        fs::write(rootfs_dir.join("merged.txt"), b"merged rootfs").unwrap();

        remove_registry_layer_staging(&base)
            .await
            .expect("remove layer staging");

        assert!(!layers_dir.exists());
        assert_eq!(
            fs::read(rootfs_dir.join("merged.txt")).unwrap(),
            b"merged rootfs"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn sanitize_image_identity_rewrites_path_separators() {
        assert_eq!(
            sanitize_image_identity("sha256:abc/def@ghi"),
            "sha256-abc-def-ghi"
        );
    }

    #[tokio::test]
    async fn read_guest_tls_materials_reports_missing_input() {
        let base = unique_temp_dir();
        let source_dir = base.join("missing-source");

        let err = read_guest_tls_materials(&VmDriverTlsPaths {
            ca: source_dir.join("ca.crt"),
            cert: source_dir.join("tls.crt"),
            key: source_dir.join("tls.key"),
        })
        .await
        .expect_err("missing TLS materials should fail before image injection");

        assert!(err.contains("ca.crt"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn stage_guest_tls_materials_places_files_in_overlay_upper_with_private_key_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = unique_temp_dir();
        let materials = GuestTlsMaterials {
            ca: b"ca".to_vec(),
            cert: b"cert".to_vec(),
            key: b"key".to_vec(),
        };

        stage_guest_tls_materials(&base, &materials).expect("stage TLS materials");

        assert_eq!(
            fs::read(
                base.join("upper")
                    .join(GUEST_TLS_CA_PATH.trim_start_matches('/'))
            )
            .unwrap(),
            b"ca"
        );
        assert_eq!(
            fs::read(
                base.join("upper")
                    .join(GUEST_TLS_CERT_PATH.trim_start_matches('/'))
            )
            .unwrap(),
            b"cert"
        );
        let key_path = base
            .join("upper")
            .join(GUEST_TLS_KEY_PATH.trim_start_matches('/'));
        assert_eq!(fs::read(&key_path).unwrap(), b"key");
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn subnet_allocator_assigns_and_releases() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 0, 128, 0), 17);
        let s1 = alloc.allocate("sandbox-1").unwrap();
        assert_eq!(s1.host_ip, Ipv4Addr::new(10, 0, 128, 1));
        assert_eq!(s1.guest_ip, Ipv4Addr::new(10, 0, 128, 2));
        assert_eq!(s1.prefix_len, 30);

        let s2 = alloc.allocate("sandbox-2").unwrap();
        assert_ne!(s1.host_ip, s2.host_ip);

        alloc.release("sandbox-1");
        let s3 = alloc.allocate("sandbox-3").unwrap();
        assert!(s3.host_ip != s2.host_ip);
    }

    #[test]
    fn tap_device_name_fits_ifnamsiz() {
        let name = tap_device_name("sandbox-abc-def-ghi");
        assert!(name.len() <= 15);
        assert!(name.starts_with("vmtap-"));
    }

    #[test]
    fn mac_address_is_locally_administered() {
        let mac = mac_from_sandbox_id("test-sandbox");
        assert_eq!(mac[0] & 0x02, 0x02);
        assert_eq!(mac[0] & 0x01, 0x00);
    }

    #[test]
    fn vsock_cid_monotonically_increases() {
        let cid1 = allocate_vsock_cid();
        let cid2 = allocate_vsock_cid();
        assert!(cid2 > cid1);
    }

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "openshell-vm-driver-test-{}-{nanos}-{suffix}",
            std::process::id()
        ))
    }

    fn spawn_exited_child() -> Child {
        Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    async fn insert_test_record(
        driver: &VmDriver,
        sandbox_id: &str,
        state_dir: PathBuf,
        child: Child,
    ) {
        let sandbox = Sandbox {
            id: sandbox_id.to_string(),
            name: sandbox_id.to_string(),
            ..Default::default()
        };
        let process = Arc::new(Mutex::new(VmProcess {
            child,
            deleting: false,
        }));

        let mut registry = driver.registry.lock().await;
        registry.insert(
            sandbox_id.to_string(),
            SandboxRecord {
                snapshot: sandbox,
                state_dir,
                process: Some(process),
                provisioning_task: None,
                gpu_bdf: None,
                qemu_network_allocated: false,
                deleting: false,
            },
        );
    }

    use crate::lifecycle::{
        BackendFeature, LaunchPlan, LifecycleError, LifecycleExtension, LifecycleExtensionRegistry,
        LifecycleResult,
    };
    use crate::runtime::VmBackend;

    fn test_driver_with_extensions(extensions: LifecycleExtensionRegistry) -> VmDriver {
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        VmDriver {
            config: VmDriverConfig {
                openshell_endpoint: "http://127.0.0.1:8080".to_string(),
                vcpus: 2,
                mem_mib: 2048,
                gpu_vcpus: 8,
                gpu_mem_mib: 16384,
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
            lifecycle_extensions: Arc::new(extensions),
        }
    }

    fn test_driver_with_proxy(https_proxy: &str) -> VmDriver {
        let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        driver.config.https_proxy = Some(https_proxy.to_string());
        driver
    }

    #[derive(Debug)]
    struct QemuRequiringExtension {
        name: String,
    }

    #[tonic::async_trait]
    impl LifecycleExtension for QemuRequiringExtension {
        fn name(&self) -> &str {
            &self.name
        }

        async fn configure_launch(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            plan: &mut LaunchPlan,
        ) -> LifecycleResult<()> {
            plan.require_backend(VmBackend::Qemu);
            plan.require_backend_feature(BackendFeature::PciPassthrough);
            Ok(())
        }

        async fn before_launch(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            plan: &mut LaunchPlan,
        ) -> LifecycleResult<()> {
            if plan.backend != VmBackend::Qemu {
                return Err(LifecycleError::new(
                    "qemu-requiring extension demands QEMU backend",
                ));
            }
            plan.env.push("EXT_DECLARED_QEMU=1".to_string());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AlwaysFailsExtension;

    #[tonic::async_trait]
    impl LifecycleExtension for AlwaysFailsExtension {
        fn name(&self) -> &'static str {
            "always-fails"
        }

        async fn before_launch(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            _plan: &mut LaunchPlan,
        ) -> LifecycleResult<()> {
            Err(LifecycleError::resource_exhausted("pool empty"))
        }
    }

    #[test]
    fn empty_registry_keeps_non_gpu_sandbox_on_libkrun() {
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());

        let plan = driver
            .build_vm_launch_plan("sandbox-x", false, false, None)
            .expect("plan should build");

        assert_eq!(plan.backend, VmBackend::Libkrun);
        assert_eq!(plan.vcpus, 2);
        assert_eq!(plan.mem_mib, 2048);
        assert!(plan.tap_device.is_none());
        assert!(plan.guest_ip.is_none());
        assert!(plan.host_ip.is_none());
        assert!(plan.vsock_cid.is_none());
        assert!(plan.guest_mac.is_none());
        assert!(plan.gpu_bdf.is_none());
        assert!(plan.env.is_empty());
    }

    #[test]
    fn empty_registry_has_no_extension_descriptors() {
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        assert!(driver.lifecycle_extensions.descriptors().is_empty());
    }

    #[test]
    fn gpu_sandbox_uses_qemu_backend_and_gpu_sizing() {
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());

        let plan = driver
            .build_vm_launch_plan("sandbox-gpu", true, true, Some("0000:01:00.0".to_string()))
            .expect("gpu plan should build");

        assert_eq!(plan.backend, VmBackend::Qemu);
        assert_eq!(plan.vcpus, 8);
        assert_eq!(plan.mem_mib, 16384);
        assert_eq!(plan.gpu_bdf.as_deref(), Some("0000:01:00.0"));
        assert!(plan.tap_device.is_some());
        assert!(plan.guest_ip.is_some());
        assert!(plan.host_ip.is_some());
        assert!(plan.vsock_cid.is_some());
        assert!(plan.guest_mac.is_some());
    }

    #[test]
    fn launch_plan_rejects_external_kernel_on_unsupported_backend() {
        let mut plan = LaunchPlan {
            backend: VmBackend::Libkrun,
            vcpus: 2,
            mem_mib: 2048,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: Some(PathBuf::from("/tmp/openshell-test-kernel")),
            gpu_bdf: None,
            tap_device: None,
            guest_ip: None,
            host_ip: None,
            vsock_cid: None,
            guest_mac: None,
            gateway_port: None,
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
        };

        let err = VmDriver::validate_launch_plan_backend(false, &plan)
            .expect_err("external kernels require a compatible backend");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("external kernel images"));

        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let kernel = base.join("vmlinux");
        std::fs::write(&kernel, b"kernel").unwrap();
        plan.backend = VmBackend::Qemu;
        plan.kernel_image = Some(kernel);
        VmDriver::validate_launch_plan_backend(true, &plan).expect("existing kernel is accepted");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn backend_feature_requirements_select_qemu_launch_plan() {
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        let mut plan = driver
            .build_vm_launch_plan("sandbox-vfio", false, false, None)
            .expect("base plan should build");
        plan.require_backend_feature(BackendFeature::PciPassthrough);

        driver
            .resolve_launch_plan_backend("sandbox-vfio", false, None, &mut plan)
            .expect("backend feature should resolve");

        assert_eq!(plan.backend, VmBackend::Qemu);
        assert!(plan.tap_device.is_some());
        assert!(plan.guest_ip.is_some());
        assert!(plan.host_ip.is_some());
        assert!(plan.vsock_cid.is_some());
        assert!(plan.guest_mac.is_some());

        driver.release_subnet("sandbox-vfio");
    }

    #[test]
    fn explicit_backend_requirement_selects_qemu_launch_plan() {
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        let mut plan = driver
            .build_vm_launch_plan("sandbox-qemu", false, false, None)
            .expect("base plan should build");
        plan.require_backend(VmBackend::Qemu);

        driver
            .resolve_launch_plan_backend("sandbox-qemu", false, None, &mut plan)
            .expect("backend requirement should resolve");

        assert_eq!(plan.backend, VmBackend::Qemu);
        assert!(plan.tap_device.is_some());
        assert!(plan.guest_ip.is_some());
        assert!(plan.host_ip.is_some());

        driver.release_subnet("sandbox-qemu");
    }

    #[test]
    fn guest_init_dropin_feature_does_not_force_qemu() {
        let driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        let mut plan = driver
            .build_vm_launch_plan("sandbox-init", false, false, None)
            .expect("base plan should build");
        plan.require_backend_feature(BackendFeature::GuestInitDropins);

        driver
            .resolve_launch_plan_backend("sandbox-init", false, None, &mut plan)
            .expect("guest init feature should resolve");

        assert_eq!(plan.backend, VmBackend::Libkrun);
        assert!(plan.tap_device.is_none());
    }

    #[test]
    fn guest_init_dropin_validation_rejects_unsafe_or_duplicate_names() {
        validate_guest_init_dropins(&[GuestInitDropin::new("50-vfio.sh", b"true\n".to_vec())])
            .expect("safe drop-in name is accepted");

        let err = validate_guest_init_dropins(&[GuestInitDropin::new(
            "../50-vfio.sh",
            b"true\n".to_vec(),
        )])
        .expect_err("path traversal is rejected");
        assert!(err.contains("must contain only ASCII"));

        let err = validate_guest_init_dropins(&[
            GuestInitDropin::new("50-vfio.sh", b"true\n".to_vec()),
            GuestInitDropin::new("50-vfio.sh", b"true\n".to_vec()),
        ])
        .expect_err("duplicate drop-ins are rejected");
        assert!(err.contains("duplicate"));
    }

    #[test]
    fn guest_init_dropin_manifest_lists_only_injected_names_sorted() {
        let manifest = render_guest_init_dropin_manifest(&[
            GuestInitDropin::new("50-vfio.sh", b"true\n".to_vec()),
            GuestInitDropin::new("10-nemo.sh", b"true\n".to_vec()),
        ]);
        assert_eq!(
            String::from_utf8(manifest).unwrap(),
            "10-nemo.sh\n50-vfio.sh\n"
        );
    }

    #[test]
    fn guest_init_dropin_manifest_is_empty_when_no_dropins() {
        // An empty manifest is the fail-closed signal that nothing under
        // init.d should run.
        assert!(render_guest_init_dropin_manifest(&[]).is_empty());
    }

    #[tokio::test]
    async fn extension_can_validate_backend_in_before_launch() {
        let extension = Arc::new(QemuRequiringExtension {
            name: "validate".to_string(),
        });
        let extensions = LifecycleExtensionRegistry::with(vec![extension.clone()]);
        let sandbox = Sandbox {
            id: "sandbox-validate".to_string(),
            name: "sandbox-validate".to_string(),
            ..Default::default()
        };

        let mut libkrun_plan = LaunchPlan {
            backend: VmBackend::Libkrun,
            vcpus: 2,
            mem_mib: 2048,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: None,
            gpu_bdf: None,
            tap_device: None,
            guest_ip: None,
            host_ip: None,
            vsock_cid: None,
            guest_mac: None,
            gateway_port: None,
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
        };
        let err = extensions
            .before_launch(&sandbox, Path::new("/tmp/state"), &mut libkrun_plan)
            .await
            .expect_err("backend mismatch should fail validation");
        assert!(err.message().contains("demands QEMU"));

        let mut qemu_plan = LaunchPlan {
            backend: VmBackend::Qemu,
            vcpus: 2,
            mem_mib: 2048,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: None,
            gpu_bdf: None,
            tap_device: Some("vmtap-x".to_string()),
            guest_ip: Some("10.0.0.2".to_string()),
            host_ip: Some("10.0.0.1".to_string()),
            vsock_cid: Some(7),
            guest_mac: Some("02:00:00:00:00:01".to_string()),
            gateway_port: Some(8080),
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
        };
        extensions
            .before_launch(&sandbox, Path::new("/tmp/state"), &mut qemu_plan)
            .await
            .expect("QEMU backend should satisfy the extension");
        assert!(qemu_plan.env.contains(&"EXT_DECLARED_QEMU=1".to_string()));
    }

    #[tokio::test]
    async fn lifecycle_error_resource_exhausted_propagates() {
        let extensions = LifecycleExtensionRegistry::with(vec![Arc::new(AlwaysFailsExtension)]);
        let sandbox = Sandbox {
            id: "sandbox-resource".to_string(),
            name: "sandbox-resource".to_string(),
            ..Default::default()
        };
        let mut plan = LaunchPlan {
            backend: VmBackend::Qemu,
            vcpus: 2,
            mem_mib: 2048,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: None,
            gpu_bdf: None,
            tap_device: Some("vmtap-x".to_string()),
            guest_ip: Some("10.0.0.2".to_string()),
            host_ip: Some("10.0.0.1".to_string()),
            vsock_cid: Some(7),
            guest_mac: Some("02:00:00:00:00:01".to_string()),
            gateway_port: Some(8080),
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
        };
        let err = extensions
            .before_launch(&sandbox, Path::new("/tmp/state"), &mut plan)
            .await
            .expect_err("scripted pool exhaustion should surface");
        assert!(err.is_resource_exhausted());
        assert_eq!(err.message(), "pool empty");
    }

    /// A driver config carrying only corporate proxy settings.
    fn proxy_config(
        https_proxy: Option<&str>,
        auth_file: Option<&str>,
        ca_bundle: Option<&str>,
    ) -> VmDriverConfig {
        VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            https_proxy: https_proxy.map(ToString::to_string),
            proxy_auth_file: auth_file.map(ToString::to_string),
            proxy_auth_allow_insecure: auth_file.map(|_| true),
            proxy_ca_bundle: ca_bundle.map(ToString::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn driver_config_debug_redacts_the_proxy_url_and_credential_path() {
        // `Debug` can be emitted before validation runs, and an unvalidated
        // proxy URL may still carry inline `user:pass@` credentials.
        let rendered = format!(
            "{:?}",
            proxy_config(
                Some("http://user:secret@proxy.corp.test:3128"),
                Some("/etc/openshell/secrets/proxy-auth"),
                Some("/etc/openshell/tls/corp-ca.pem"),
            )
        );
        assert!(
            !rendered.contains("secret") && !rendered.contains("proxy.corp.test"),
            "the proxy URL must be logged as presence only: {rendered}"
        );
        assert!(
            !rendered.contains("/etc/openshell/secrets/proxy-auth"),
            "the credential path must be logged as presence only: {rendered}"
        );
        assert!(
            rendered.contains("https_proxy: true") && rendered.contains("proxy_auth_file: true"),
            "presence of each must still be visible for debugging: {rendered}"
        );
        // A CA path is not sensitive and stays readable.
        assert!(
            rendered.contains("corp-ca.pem"),
            "the CA bundle path is not a secret and should stay legible: {rendered}"
        );
    }

    #[test]
    fn proxy_material_is_staged_inside_the_per_sandbox_overlay() {
        // Everything the driver stages lands in the overlay upperdir, which
        // lives in the sandbox's own state directory. That is what makes the
        // credential removable with the sandbox (remove_sandbox_state_dir
        // deletes the whole directory) and unforgeable by the guest image
        // (the upperdir shadows the read-only image layer).
        for guest_path in [
            GUEST_UPSTREAM_PROXY_AUTH_PATH,
            GUEST_PROXY_CA_PATH,
            GUEST_SUPERVISOR_ARGS_PATH,
        ] {
            assert!(
                guest_path.starts_with("/opt/openshell/"),
                "{guest_path} must be under the reserved guest control root"
            );
            assert_eq!(
                overlay_upper_path(guest_path),
                format!("/upper{guest_path}"),
                "{guest_path} must be staged into the overlay upperdir"
            );
        }
    }

    #[test]
    fn upstream_proxy_args_are_empty_without_a_configured_proxy() {
        assert!(upstream_proxy_cli_args(&VmDriverConfig::default()).is_empty());
        // The file is still written, empty, so the guest cannot fall back to
        // an image-baked argument list.
        assert!(render_guest_supervisor_args(&[]).is_empty());
    }

    #[test]
    fn upstream_proxy_args_pass_guest_paths_not_host_paths() {
        let config = proxy_config(
            Some("http://proxy.corp.test:3128"),
            Some("/etc/openshell/secrets/proxy-auth"),
            Some("/etc/openshell/tls/corp-ca.pem"),
        );
        let args = upstream_proxy_cli_args(&config);

        // The credential and CA live at fixed guest paths; the gateway-host
        // paths the operator configured must never reach the guest argv.
        let auth = args
            .iter()
            .position(|arg| arg == "--upstream-proxy-auth-file")
            .map(|i| args[i + 1].as_str());
        assert_eq!(auth, Some(GUEST_UPSTREAM_PROXY_AUTH_PATH));
        let ca = args
            .iter()
            .position(|arg| arg == "--upstream-proxy-ca-bundle")
            .map(|i| args[i + 1].as_str());
        assert_eq!(ca, Some(GUEST_PROXY_CA_PATH));
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("/etc/openshell/secrets") || arg.contains("corp-ca.pem")),
            "host paths leaked into the guest argv: {args:?}"
        );
    }

    #[test]
    fn upstream_proxy_args_pass_only_explicit_opt_ins() {
        let mut config = proxy_config(Some("https://proxy.corp.test:3130"), None, None);
        config.no_proxy = Some("10.0.0.0/8,.svc.cluster.local".to_string());
        let args = upstream_proxy_cli_args(&config);
        assert_eq!(
            args,
            vec![
                "--upstream-proxy".to_string(),
                "https://proxy.corp.test:3130".to_string(),
                "--upstream-no-proxy".to_string(),
                "10.0.0.0/8,.svc.cluster.local".to_string(),
            ]
        );

        // `Some(false)` must not be passed as the presence flag it is on the
        // supervisor side.
        config.proxy_connect_by_hostname = Some(false);
        assert!(
            !upstream_proxy_cli_args(&config)
                .iter()
                .any(|arg| arg == "--upstream-proxy-connect-by-hostname")
        );
        config.proxy_connect_by_hostname = Some(true);
        assert!(
            upstream_proxy_cli_args(&config)
                .iter()
                .any(|arg| arg == "--upstream-proxy-connect-by-hostname")
        );
    }

    #[test]
    fn guest_supervisor_args_render_one_argument_per_line() {
        let args = vec![
            "--upstream-proxy".to_string(),
            "http://proxy.corp.test:3128".to_string(),
            "--upstream-no-proxy".to_string(),
            "a.example, b.example".to_string(),
        ];
        // A value containing a space stays one line, so the guest reads it
        // back as a single argument rather than word-splitting it.
        assert_eq!(
            String::from_utf8(render_guest_supervisor_args(&args)).unwrap(),
            "--upstream-proxy\nhttp://proxy.corp.test:3128\n--upstream-no-proxy\na.example, b.example\n"
        );
    }

    #[test]
    fn guest_supervisor_args_reject_line_breaking_values() {
        // A newline would split one operator value into two guest arguments.
        for bad in ["a\nb", "a\rb", "a\0b"] {
            assert!(
                validate_guest_supervisor_args(&[bad.to_string()]).is_err(),
                "{bad:?} must be rejected"
            );
        }
        validate_guest_supervisor_args(&["--upstream-proxy".to_string()])
            .expect("ordinary arguments are accepted");
    }

    #[test]
    fn proxy_config_validation_rejects_settings_without_a_proxy_url() {
        let config = VmDriverConfig {
            no_proxy: Some("10.0.0.0/8".to_string()),
            ..Default::default()
        };
        let err = config
            .validate_proxy_config()
            .expect_err("a bypass list without a proxy would hide a fail-open state");
        assert!(err.contains("no_proxy"), "{err}");

        let config = proxy_config(Some("http://proxy.corp.test:3128"), None, None);
        config
            .validate_proxy_config()
            .expect("a lone proxy URL is a complete configuration");
    }

    #[test]
    fn proxy_config_validation_requires_the_cleartext_acknowledgement() {
        let mut config = proxy_config(
            Some("http://proxy.corp.test:3128"),
            Some("/etc/openshell/secrets/proxy-auth"),
            None,
        );
        config.proxy_auth_allow_insecure = None;
        let err = config
            .validate_proxy_config()
            .expect_err("Basic auth to an http:// proxy is cleartext on the wire");
        assert!(err.contains("proxy_auth_allow_insecure"), "{err}");
    }

    #[tokio::test]
    async fn proxy_ca_bundle_without_a_certificate_fails_the_sandbox() {
        let dir = std::env::temp_dir().join(format!("openshell-vm-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not-a-ca.pem");
        std::fs::write(&path, b"this is not a certificate\n").unwrap();

        let err = read_sandbox_proxy_ca_bundle(path.to_str().unwrap())
            .await
            .expect_err("a certificate-free bundle must fail closed");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("no PEM certificate"), "{err}");

        std::fs::write(&path, b"").unwrap();
        let err = read_sandbox_proxy_ca_bundle(path.to_str().unwrap())
            .await
            .expect_err("an empty bundle must fail closed");
        assert!(err.message().contains("no PEM certificate"), "{err}");

        // PEM framing that base64-decodes but is not X.509 DER: accepted by
        // `rustls_pemfile` alone, contributes zero trust anchors at runtime,
        // and so would make every guest supervisor fail after boot.
        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let err = read_sandbox_proxy_ca_bundle(path.to_str().unwrap())
            .await
            .expect_err("a bundle with invalid DER must fail closed");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("no usable trust anchors"), "{err}");

        let err = read_sandbox_proxy_ca_bundle(dir.join("missing.pem").to_str().unwrap())
            .await
            .expect_err("an unreadable bundle must fail closed");
        assert!(err.message().contains("could not be read"), "{err}");

        // A special file must be rejected on its type, not read: an
        // unbounded read of /dev/zero would exhaust driver memory.
        #[cfg(unix)]
        {
            let err = read_sandbox_proxy_ca_bundle("/dev/zero")
                .await
                .expect_err("a non-regular bundle path must fail closed");
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("not a regular file"), "{err}");
        }

        // Oversized regular file: rejected on the stat'd length, again
        // without reading it whole.
        let oversized = dir.join("oversized.pem");
        let bound = openshell_core::driver_utils::MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES;
        std::fs::write(&oversized, vec![b'x'; usize::try_from(bound).unwrap() + 1]).unwrap();
        let err = read_sandbox_proxy_ca_bundle(oversized.to_str().unwrap())
            .await
            .expect_err("an oversized bundle must fail closed");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds"), "{err}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn qemu_backend_rejects_a_gateway_host_proxy() {
        // gvproxy's host-loopback NAT has no QEMU/TAP equivalent, so a proxy
        // on the gateway host is unreachable from a GPU sandbox and must be
        // rejected rather than time out on every CONNECT. The address that
        // reaches the gateway host from a QEMU guest is this sandbox's own
        // TAP host address, so the classifier is parameterized by it.
        let tap_host = Some("10.0.128.1");
        for url in [
            "http://host.openshell.internal:8080",
            "http://host.containers.internal:8080",
            "http://host.docker.internal:8080",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "https://[::1]:8080",
            // The address the aliases above resolve to inside the guest.
            "http://10.0.128.1:8080",
        ] {
            assert!(proxy_url_targets_gateway_host(url, tap_host), "{url}");
        }
        for url in [
            "http://proxy.corp.example:8080",
            "https://10.1.2.3:3128",
            // Special only to libkrun/gvproxy. On QEMU/TAP it is an ordinary
            // address that may be routable through the guest's masqueraded
            // egress, so rejecting it would refuse a working configuration.
            "http://192.168.127.254:8080",
            // Another sandbox's TAP host, not this one's.
            "http://10.0.128.5:8080",
            "not a url",
        ] {
            assert!(!proxy_url_targets_gateway_host(url, tap_host), "{url}");
        }

        // Without an allocated TAP host only the address-independent
        // spellings classify; the loopback and alias guards still hold.
        assert!(proxy_url_targets_gateway_host(
            "http://127.0.0.1:8080",
            None
        ));
        assert!(proxy_url_targets_gateway_host(
            "http://host.openshell.internal:8080",
            None
        ));
        assert!(!proxy_url_targets_gateway_host(
            "http://10.0.128.1:8080",
            None
        ));
    }

    #[test]
    fn qemu_launch_plan_rejects_a_proxy_at_the_allocated_tap_host() {
        // The preflight has to run against the address this sandbox actually
        // got, which only exists once the launch plan's subnet is allocated.
        // A proxy there is what `host.openshell.internal` resolves to in the
        // guest, and the driver's own nftables input chain drops the port.
        let probe = test_driver_with_extensions(LifecycleExtensionRegistry::new());
        let tap_host = probe
            .build_vm_launch_plan("sandbox-proxy-tap", true, true, None)
            .expect("gpu plan should build")
            .host_ip
            .expect("a QEMU plan carries a TAP host address");
        probe.release_subnet("sandbox-proxy-tap");

        let driver = test_driver_with_proxy(&format!("http://{tap_host}:8080"));
        let mut plan = driver
            .build_vm_launch_plan("sandbox-proxy-tap", true, true, None)
            .expect("gpu plan should build");
        assert_eq!(plan.host_ip.as_deref(), Some(tap_host.as_str()));

        let err = driver
            .resolve_launch_plan_backend("sandbox-proxy-tap", true, None, &mut plan)
            .expect_err("a proxy at the TAP host address is unreachable from the guest");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains(&tap_host), "{err}");

        driver.release_subnet("sandbox-proxy-tap");
    }

    #[test]
    fn qemu_launch_plan_allows_a_proxy_at_the_gvproxy_host_loopback_address() {
        // 192.168.127.254 carries no meaning on QEMU/TAP, so a launch must
        // proceed rather than be refused for a libkrun-only reason.
        let driver = test_driver_with_proxy(&format!("http://{GVPROXY_HOST_LOOPBACK_IP}:8080"));
        let mut plan = driver
            .build_vm_launch_plan("sandbox-proxy-gvproxy", true, true, None)
            .expect("gpu plan should build");
        assert_ne!(plan.host_ip.as_deref(), Some(GVPROXY_HOST_LOOPBACK_IP));

        driver
            .resolve_launch_plan_backend("sandbox-proxy-gvproxy", true, None, &mut plan)
            .expect("a routable proxy address must not block a GPU launch");
        assert_eq!(plan.backend, VmBackend::Qemu);

        driver.release_subnet("sandbox-proxy-gvproxy");
    }

    #[tokio::test]
    async fn proxy_credential_is_validated_against_the_supervisor_rules() {
        let dir = std::env::temp_dir().join(format!("openshell-vm-cred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxy-auth");

        std::fs::write(&path, "proxyuser:proxypass\n").unwrap();
        assert_eq!(
            read_sandbox_proxy_credential(path.to_str().unwrap())
                .await
                .expect("a well-formed credential is accepted"),
            "proxyuser:proxypass"
        );

        // Rejected here rather than inside every sandbox's supervisor.
        std::fs::write(&path, "no-separator\n").unwrap();
        let err = read_sandbox_proxy_credential(path.to_str().unwrap())
            .await
            .expect_err("a malformed credential must fail closed");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            !err.message().contains("no-separator"),
            "the error must not echo credential file contents: {err}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn guest_environment_carries_no_corporate_proxy_settings() {
        // The egress boundary is argv-only: `build_guest_environment` merges
        // user-supplied environment, so anything it emitted here would be
        // attacker-influenced.
        let config = proxy_config(
            Some("http://proxy.corp.test:3128"),
            Some("/etc/openshell/secrets/proxy-auth"),
            Some("/etc/openshell/tls/corp-ca.pem"),
        );
        let sandbox = Sandbox {
            id: "sb-proxy".to_string(),
            name: "proxy".to_string(),
            spec: Some(SandboxSpec {
                environment: [
                    (
                        "HTTPS_PROXY".to_string(),
                        "http://attacker:3128".to_string(),
                    ),
                    ("NO_PROXY".to_string(), "*".to_string()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        assert!(
            !env.iter().any(|entry| entry.starts_with("--upstream")),
            "driver environment must never carry supervisor arguments: {env:?}"
        );
        // A sandbox may still set the conventional variables for its own
        // workload, but the supervisor ignores them on this path -- what
        // matters is that the driver never derives the boundary from them.
        assert!(
            !env.iter()
                .any(|entry| entry.contains("proxy.corp.test") || entry.contains("proxy-auth")),
            "operator proxy settings must not reach the guest environment: {env:?}"
        );
    }

    #[test]
    fn sandbox_driver_config_cannot_carry_proxy_settings() {
        // The upstream proxy is host network topology, not a per-sandbox
        // setting: the caller-supplied envelope must reject it outright
        // rather than silently ignoring it.
        for key in [
            "https_proxy",
            "no_proxy",
            "proxy_auth_file",
            "proxy_auth_allow_insecure",
            "proxy_connect_by_hostname",
            "proxy_ca_bundle",
        ] {
            let template = SandboxTemplate {
                driver_config: Some(Struct {
                    fields: std::iter::once((
                        key.to_string(),
                        Value {
                            kind: Some(Kind::StringValue("http://attacker:3128".to_string())),
                        },
                    ))
                    .collect(),
                }),
                ..Default::default()
            };
            assert!(
                VmSandboxDriverConfig::from_template(&template).is_err(),
                "template.driver_config.vm must reject '{key}'"
            );
        }
    }
}
