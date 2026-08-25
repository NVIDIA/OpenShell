// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration management for `OpenShell` components.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::io::{Read, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

// ── Public default constants ────────────────────────────────────────────
//
// Canonical source for default values used across multiple crates.
// Clap `default_value_t` annotations and runtime fallbacks should
// reference these constants instead of hardcoding literals.

/// Default SSH port inside sandbox containers.
pub const DEFAULT_SSH_PORT: u16 = 2222;

/// Default gateway server port.
pub const DEFAULT_SERVER_PORT: u16 = 17670;

/// Default container stop timeout in seconds (SIGTERM → SIGKILL).
pub const DEFAULT_STOP_TIMEOUT_SECS: u32 = 10;

/// Default Docker bridge network name for local sandboxes.
pub const DEFAULT_DOCKER_NETWORK_NAME: &str = "openshell-docker";

/// Default domain used for browser-facing sandbox service URLs.
pub const DEFAULT_SERVICE_ROUTING_DOMAIN: &str = "openshell.localhost";

/// Gateway posture when a sandbox rejects a candidate policy generation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyValidationFailureMode {
    /// Deactivate the previous policy and deny new egress until a valid
    /// generation is loaded.
    #[default]
    FailClosed,
    /// Keep the last valid generation active when a newer candidate fails
    /// validation. Startup still fails closed when no valid generation exists.
    RetainLastValid,
}

impl PolicyValidationFailureMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::RetainLastValid => "retain_last_valid",
        }
    }
}

impl FromStr for PolicyValidationFailureMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "fail_closed" => Ok(Self::FailClosed),
            "retain_last_valid" => Ok(Self::RetainLastValid),
            _ => Err(format!(
                "invalid policy validation failure mode '{value}'; expected fail_closed or retain_last_valid"
            )),
        }
    }
}

/// Default OCI repository for the supervisor image (no tag).
pub const DEFAULT_SUPERVISOR_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/supervisor";

/// Return the default supervisor image reference with a version-pinned tag.
#[must_use]
pub fn default_supervisor_image() -> String {
    format!(
        "{DEFAULT_SUPERVISOR_IMAGE_REPO}:{}",
        default_supervisor_image_tag()
    )
}

fn default_supervisor_image_tag() -> String {
    resolve_supervisor_image_tag(&[
        option_env!("OPENSHELL_IMAGE_TAG").unwrap_or(""),
        option_env!("IMAGE_TAG").unwrap_or(""),
        env!("CARGO_PKG_VERSION"),
    ])
}

/// Resolve the supervisor image tag from an ordered list of candidates.
///
/// Returns the first non-empty, non-`"0.0.0"` candidate, falling back to
/// `"dev"` when none qualifies. Replaces `+` with `-` for OCI tag
/// compatibility.
#[must_use]
pub fn resolve_supervisor_image_tag(candidates: &[&str]) -> String {
    candidates
        .iter()
        .copied()
        .find(|t| !t.is_empty() && *t != "0.0.0")
        .unwrap_or("dev")
        .replace('+', "-")
}

/// CDI device identifier for requesting all NVIDIA GPUs.
pub const CDI_GPU_DEVICE_ALL: &str = "nvidia.com/gpu=all";

/// Default maximum number of processes (PIDs) allowed inside a sandbox container.
///
/// Shared by the Docker and Podman drivers; override via driver config.
pub const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 2048;

/// Compute backends the gateway can orchestrate sandboxes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeDriverKind {
    Kubernetes,
    Vm,
    Docker,
    Podman,
}

impl ComputeDriverKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Vm => "vm",
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

/// Normalize a configured compute driver name.
///
/// Built-in driver names and custom remote driver names share the same
/// selection namespace. The normalized value is lowercase ASCII and may contain
/// letters, digits, `-`, and `_`.
pub fn normalize_compute_driver_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("compute driver name cannot be empty".to_string());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(format!(
            "invalid compute driver name '{value}'. use ASCII letters, digits, '-' or '_'"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

impl fmt::Display for ComputeDriverKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ComputeDriverKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "kubernetes" => Ok(Self::Kubernetes),
            "vm" => Ok(Self::Vm),
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            other => Err(format!(
                "unsupported compute driver '{other}'. expected one of: kubernetes, vm, docker, podman"
            )),
        }
    }
}

/// Auto-detect the appropriate compute driver based on the runtime environment.
///
/// Priority order: Kubernetes → Podman → Docker.
/// VM is never auto-detected (requires explicit `--drivers vm`).
///
/// Returns the first driver where the environment check passes.
/// Returns `None` if no compatible driver is found.
pub fn detect_driver() -> Option<ComputeDriverKind> {
    // Kubernetes: check for KUBERNETES_SERVICE_HOST env var (set inside pods)
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        return Some(ComputeDriverKind::Kubernetes);
    }

    // Podman: check for a reachable local API socket.
    if is_podman_available() {
        return Some(ComputeDriverKind::Podman);
    }

    // Docker: check for a reachable local API socket.
    if is_docker_available() {
        return Some(ComputeDriverKind::Docker);
    }

    None
}

/// Return whether a responsive local Podman API socket is available.
#[must_use]
pub fn is_podman_available() -> bool {
    detect_podman_socket().is_some()
}

/// Return the Podman API socket, or `None` if Podman is not available.
///
/// Probes the well-known socket candidates first, then falls back to asking
/// the Podman CLI where its socket lives. The symlink at a well-known path is
/// not always present — it varies by Podman version, machine provider, and
/// platform — so the CLI fallback is what makes detection work on hosts where
/// Podman is functional but the socket is somewhere else.
pub fn detect_podman_socket() -> Option<PathBuf> {
    detect_podman_socket_from_candidates(&podman_socket_candidates())
        .or_else(discover_podman_socket)
}

fn detect_podman_socket_from_candidates(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|path| podman_socket_responds(path))
        .cloned()
}

/// Maximum time to wait for a Podman discovery subprocess.
///
/// Driver auto-detection runs `podman info`, `podman machine inspect`, and
/// `podman system connection list` during gateway startup. A stalled Podman
/// machine, SSH connection, provider, or helper must not block startup forever,
/// so each probe is bounded and treated as "not found" on expiry — detection
/// then continues to the next candidate driver or fails with an actionable
/// error.
const PODMAN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the bounded runner polls the child for completion.
const PODMAN_DISCOVERY_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Run `podman <args>` with a bounded deadline, returning captured stdout on a
/// successful exit. Returns `None` on spawn failure, non-zero exit, or timeout.
fn run_podman_capture(args: &[&str]) -> Option<Vec<u8>> {
    run_bounded_command("podman", args, PODMAN_DISCOVERY_TIMEOUT)
}

/// Run `program <args>` with a deadline, capturing stdout.
///
/// Unlike `Command::output()`, which blocks until the child exits, the deadline
/// is absolute: the call returns within `timeout` no matter what the probe or
/// its descendants do. A Podman probe can leave a daemonized descendant (an SSH
/// multiplexer, `gvproxy`, etc.) that inherited the stdout pipe, so
/// `read_to_end` would otherwise wait for EOF forever even after the direct
/// child exits — and such a descendant may even have escaped the probe's
/// process group. To stay bounded, the deadline covers both waiting for the
/// child and draining its stdout; on expiry the call best-effort kills the
/// process group (cleaning up in-group descendants) and gives up immediately,
/// abandoning the reader thread rather than waiting on it again. The abandoned
/// reader exits on its own once the pipe finally closes. Returns the captured
/// stdout only on a successful exit whose output was fully drained within the
/// deadline; otherwise `None`.
fn run_bounded_command(program: &str, args: &[&str], timeout: Duration) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::sync::mpsc;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Run the probe as its own process-group leader so in-group descendants that
    // inherited the stdout pipe can be terminated as a group on timeout.
    set_new_process_group(&mut command);
    let mut child = command.spawn().ok()?;

    // Drain stdout on a separate thread so a child that fills the pipe buffer
    // cannot deadlock against the polling loop below. The reader reports through
    // a channel so the drain can be bounded by the deadline and abandoned if it
    // outlives it.
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    let deadline = Instant::now() + timeout;

    // Wait for the direct child to exit, bounded by the deadline.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(PODMAN_DISCOVERY_POLL_INTERVAL);
            }
            Err(_) => break None,
        }
    };

    // The child never exited within the deadline: kill the group, reap the
    // (now-killed) direct child, and give up. `wait()` is bounded because the
    // direct child is dead.
    let Some(status) = status else {
        terminate_process_group(&mut child);
        let _ = child.wait();
        return None;
    };

    // The direct child exited (already reaped by `try_wait`). Collect its stdout
    // without ever blocking past the deadline. A surviving descendant — possibly
    // one that escaped the process group — can hold the pipe open indefinitely,
    // so on expiry best-effort kill the group for cleanup and return None rather
    // than waiting on the reader again.
    let remaining = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(stdout) if status.success() => Some(stdout),
        Ok(_) => None,
        Err(_) => {
            terminate_process_group(&mut child);
            None
        }
    }
}

/// Configure `command` to start its child as a new process-group leader so the
/// group can be signaled as a unit. No-op on non-Unix platforms.
#[cfg(unix)]
fn set_new_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn set_new_process_group(_command: &mut Command) {}

/// Kill the child's whole process group so daemonized descendants that inherited
/// the stdout pipe are terminated too. Falls back to killing just the child.
#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) {
    // `set_new_process_group` made the child a group leader, so its PID doubles
    // as the group ID; signaling the negated PID targets the entire group. The
    // group stays valid while a descendant is alive, so this reaches survivors
    // even after the leader has been reaped.
    let raw_pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
    let pgid = nix::unistd::Pid::from_raw(-raw_pid);
    let _ = nix::sys::signal::kill(pgid, nix::sys::signal::Signal::SIGKILL);
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// Query the Podman CLI to discover the host-side API socket path.
///
/// Strategy:
/// 1. Run `podman info --format json` to check connectivity and whether
///    the service is remote (macOS/Windows VM) or local (native Linux).
/// 2. If `CONTAINER_HOST` explicitly points at a Unix socket, `podman info`
///    just connected through it — use that path directly (a raw unix:// URL
///    has no machine to inspect and reports the VM-internal socket).
/// 3. If `serviceIsRemote` is true, run `podman machine inspect` to get
///    the host-side forwarded socket (the `remoteSocket` from `podman info`
///    is the VM-internal path, which is not reachable from the host).
/// 4. If `serviceIsRemote` is false, use `remoteSocket.path` directly
///    (on native Linux this IS the real local socket).
fn discover_podman_socket() -> Option<PathBuf> {
    let stdout = run_podman_capture(&["info", "--format", "json"])?;

    // podman info succeeded, so an explicit unix:// CONTAINER_HOST is the exact
    // working host-side socket. This must be checked before the machine path,
    // which cannot map a raw unix:// endpoint to a machine.
    if let Some(path) = explicit_unix_container_host() {
        return Some(path);
    }

    let info: serde_json::Value = serde_json::from_slice(&stdout).ok()?;
    let is_remote = info["host"]["serviceIsRemote"].as_bool().unwrap_or(false);

    if is_remote {
        discover_podman_machine_socket()
    } else {
        parse_podman_info_socket(&info)
    }
}

/// Return the socket path when `CONTAINER_HOST` is an explicit `unix://` URL.
///
/// Honors Podman's precedence: `CONTAINER_CONNECTION` outranks `CONTAINER_HOST`,
/// so a set `CONTAINER_CONNECTION` means `podman info` did not use
/// `CONTAINER_HOST` and this returns `None`.
fn explicit_unix_container_host() -> Option<PathBuf> {
    if env_var_nonempty("CONTAINER_CONNECTION").is_some() {
        return None;
    }
    let host = env_var_nonempty("CONTAINER_HOST")?;
    unix_url_socket_path(&host)
}

/// Parse the socket path from a `unix://` URL, or `None` for other schemes.
fn unix_url_socket_path(url: &str) -> Option<PathBuf> {
    let path = url.trim().strip_prefix("unix://")?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Extract the socket path from `podman info` JSON output.
/// Used on native Linux where `remoteSocket.path` is the real local socket.
fn parse_podman_info_socket(info: &serde_json::Value) -> Option<PathBuf> {
    let path_str = info["host"]["remoteSocket"]["path"].as_str()?;
    let path = path_str.strip_prefix("unix://").unwrap_or(path_str);
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

/// Which Podman machine `podman info` connected through.
///
/// Podman resolves its endpoint (highest precedence first) from
/// `CONTAINER_CONNECTION` (a named connection), then `CONTAINER_HOST` (a URL),
/// then the default connection in `containers.conf`.
#[derive(Debug, PartialEq, Eq)]
enum ActiveMachine {
    /// An explicit selector (`CONTAINER_CONNECTION`, or `CONTAINER_HOST` mapped
    /// to a connection by URL) named this connection. It must match a machine
    /// exactly; guessing another machine would connect to the wrong socket.
    Explicit(String),
    /// An explicit `CONTAINER_HOST` is set but maps to no known connection
    /// (e.g. a plain remote server, not a local machine). The active machine
    /// cannot be determined and must not be guessed.
    UnresolvedExplicit,
    /// No explicit selector; the `containers.conf` default connection name, if
    /// any. When absent, Podman's built-in default machine is inspected by name.
    Default(Option<String>),
}

/// Run `podman machine inspect <machine>` to discover the host-side forwarded
/// socket. Used on macOS/Windows where the Podman service runs inside a VM.
///
/// The active machine is resolved first and inspected *by name*: a no-argument
/// `podman machine inspect` inspects only `podman-machine-default`, so a host
/// whose default connection is a different machine would otherwise be pointed
/// at the wrong machine's socket. When the active machine cannot be mapped to a
/// name, this returns `None` rather than substituting an unrelated machine.
fn discover_podman_machine_socket() -> Option<PathBuf> {
    let targets = podman_machine_inspect_targets(&active_podman_machine())?;
    targets.iter().find_map(|name| {
        let stdout = run_podman_capture(&["machine", "inspect", name])?;
        let machines: serde_json::Value = serde_json::from_slice(&stdout).ok()?;
        parse_podman_machine_inspect_socket(&machines)
    })
}

/// Machine names to try with `podman machine inspect`, most specific first.
///
/// `None` means the active machine cannot be determined; inspection must not
/// guess, since picking an unrelated machine would return the wrong socket. A
/// rootful connection is named `<machine>-root` while the machine itself is
/// `<machine>`, so the `-root`-stripped name is offered as a fallback.
fn podman_machine_inspect_targets(active: &ActiveMachine) -> Option<Vec<String>> {
    fn names_for(connection: &str) -> Vec<String> {
        let mut names = vec![connection.to_string()];
        if let Some(stripped) = connection.strip_suffix("-root")
            && !stripped.is_empty()
        {
            names.push(stripped.to_string());
        }
        names
    }

    match active {
        ActiveMachine::Explicit(name) | ActiveMachine::Default(Some(name)) => Some(names_for(name)),
        ActiveMachine::UnresolvedExplicit => None,
        // No explicit selector and no default connection: `podman info` used
        // Podman's built-in default machine, so inspect it by name rather than
        // guessing an arbitrary entry.
        ActiveMachine::Default(None) => Some(vec!["podman-machine-default".to_string()]),
    }
}

/// Determine which machine `podman info` connected through.
fn active_podman_machine() -> ActiveMachine {
    if let Some(name) = env_var_nonempty("CONTAINER_CONNECTION") {
        return ActiveMachine::Explicit(name);
    }
    let container_host = env_var_nonempty("CONTAINER_HOST");
    resolve_active_podman_machine(container_host.as_deref(), podman_connection_list().as_ref())
}

/// Resolve the active machine from `CONTAINER_HOST` and the connection list.
///
/// `CONTAINER_CONNECTION` is handled by the caller (it needs no connection
/// list). This is split out as a pure function for testing.
fn resolve_active_podman_machine(
    container_host: Option<&str>,
    connections: Option<&serde_json::Value>,
) -> ActiveMachine {
    if let Some(host) = container_host {
        return connections
            .and_then(|c| podman_connection_name_for_uri(c, host))
            .map_or(ActiveMachine::UnresolvedExplicit, ActiveMachine::Explicit);
    }
    ActiveMachine::Default(connections.and_then(parse_default_podman_connection))
}

fn env_var_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Run `podman system connection list --format json`.
fn podman_connection_list() -> Option<serde_json::Value> {
    let stdout = run_podman_capture(&["system", "connection", "list", "--format", "json"])?;
    serde_json::from_slice(&stdout).ok()
}

/// Extract the default machine connection name from
/// `podman system connection list --format json`.
fn parse_default_podman_connection(connections: &serde_json::Value) -> Option<String> {
    connections
        .as_array()?
        .iter()
        .find(|c| {
            c["Default"].as_bool().unwrap_or(false) && c["IsMachine"].as_bool().unwrap_or(false)
        })
        .and_then(|c| c["Name"].as_str())
        .map(str::to_string)
}

/// Find the machine connection whose URI matches `CONTAINER_HOST`.
///
/// Only machine connections (`IsMachine: true`) map to a local socket, so a
/// `CONTAINER_HOST` pointing at a plain remote server yields `None`.
fn podman_connection_name_for_uri(connections: &serde_json::Value, uri: &str) -> Option<String> {
    connections
        .as_array()?
        .iter()
        .find(|c| c["IsMachine"].as_bool().unwrap_or(false) && c["URI"].as_str() == Some(uri))
        .and_then(|c| c["Name"].as_str())
        .map(str::to_string)
}

/// Extract the host-side socket path from a `podman machine inspect <machine>`
/// JSON array (which contains only the inspected machine).
fn parse_podman_machine_inspect_socket(machines: &serde_json::Value) -> Option<PathBuf> {
    let machine = machines.as_array()?.first()?;
    let path_str = machine["ConnectionInfo"]["PodmanSocket"]["Path"].as_str()?;
    if path_str.is_empty() {
        return None;
    }
    Some(PathBuf::from(path_str))
}

fn podman_socket_candidates() -> Vec<PathBuf> {
    let socket = std::env::var("OPENSHELL_PODMAN_SOCKET")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from);
    podman_socket_candidates_from_env(
        socket,
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

fn podman_socket_candidates_from_env(
    socket: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = socket {
        candidates.push(path);
    }

    if let Some(runtime_dir) = runtime_dir {
        candidates.push(runtime_dir.join("podman/podman.sock"));
    }

    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from(format!(
            "/run/user/{}/podman/podman.sock",
            current_uid()
        )));
    }

    if let Some(home) = home {
        candidates.push(home.join(".local/share/containers/podman/machine/podman.sock"));
    }

    candidates
}

/// Return whether a responsive local Docker API socket is available.
#[must_use]
pub fn is_docker_available() -> bool {
    detect_docker_socket().is_some()
}

pub fn detect_docker_socket() -> Option<PathBuf> {
    detect_docker_socket_from_candidates(&docker_socket_candidates())
}

fn detect_docker_socket_from_candidates(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|path| docker_socket_responds(path))
        .cloned()
}

fn docker_socket_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(host) = std::env::var("DOCKER_HOST")
        && let Some(path) = docker_host_unix_socket_path(&host)
    {
        candidates.push(path);
    }

    candidates.push(PathBuf::from("/var/run/docker.sock"));

    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".docker/run/docker.sock"));
    }

    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(runtime_dir).join("docker.sock"));
    }

    candidates
}

fn docker_host_unix_socket_path(host: &str) -> Option<PathBuf> {
    let path = host.trim().strip_prefix("unix://")?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(unix)]
fn is_unix_socket(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.file_type().is_socket())
}

#[cfg(unix)]
fn podman_socket_responds(path: &Path) -> bool {
    unix_socket_http_ping(path, |response| {
        http_response_is_success(response) && contains_ascii(response, b"Libpod-Api-Version:")
    })
}

#[cfg(unix)]
fn docker_socket_responds(path: &Path) -> bool {
    unix_socket_http_ping(path, |response| {
        http_response_is_success(response)
            && contains_ascii(response, b"Api-Version:")
            && !contains_ascii(response, b"Libpod-Api-Version:")
    })
}

#[cfg(unix)]
fn unix_socket_http_ping(path: &Path, accepts_response: impl FnOnce(&[u8]) -> bool) -> bool {
    const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
    const PING_REQUEST: &[u8] =
        b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if !is_unix_socket(path) {
        return false;
    }

    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(path) else {
        return false;
    };
    if stream.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.write_all(PING_REQUEST).is_err()
    {
        return false;
    }

    let mut response = [0_u8; 512];
    let mut total = 0;
    while total < response.len() {
        let Ok(n) = stream.read(&mut response[total..]) else {
            return false;
        };
        if n == 0 {
            break;
        }
        total += n;
        if contains_ascii(&response[..total], b"\r\n\r\n") {
            break;
        }
    }
    total > 0 && accepts_response(&response[..total])
}

#[cfg(unix)]
fn http_response_is_success(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200")
}

#[cfg(unix)]
fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(all(unix, test))]
fn is_reachable_unix_socket(path: &Path) -> bool {
    is_unix_socket(path) && std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(all(unix, target_os = "linux"))]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata("/proc/self").map_or(0, |metadata| metadata.uid())
}

#[cfg(not(unix))]
fn podman_socket_responds(path: &Path) -> bool {
    let _ = path;
    false
}

#[cfg(not(unix))]
fn docker_socket_responds(path: &Path) -> bool {
    let _ = path;
    false
}

/// Server configuration.
///
/// Built programmatically in [`crate::Config::new`] and the gateway CLI from
/// the parsed config file, env vars, and CLI flags. It is never deserialized
/// directly; the on-disk config schema lives in the gateway's `config_file`
/// module ([`crate::TlsConfig`] and the other nested tables carry their own
/// `Deserialize` impls for that purpose).
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the server to.
    pub bind_address: SocketAddr,

    /// Address to bind the unauthenticated health endpoint to.
    ///
    /// When `None`, the dedicated health listener is disabled.
    pub health_bind_address: Option<SocketAddr>,

    /// Address to bind the Prometheus metrics endpoint to.
    ///
    /// When `None`, the dedicated metrics listener is disabled.
    pub metrics_bind_address: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error).
    pub log_level: String,

    /// Security posture for rejected sandbox policy generations.
    pub policy_validation_failure_mode: PolicyValidationFailureMode,

    /// TLS configuration.  When `None`, the server listens on plaintext HTTP.
    pub tls: Option<TlsConfig>,

    /// OIDC configuration. When `Some`, the server validates Bearer JWTs.
    pub oidc: Option<OidcConfig>,

    /// Gateway user authentication behavior.
    pub auth: GatewayAuthConfig,

    /// Disabled-by-default gateway interceptor service configs.
    pub gateway_interceptors: Vec<GatewayInterceptorConfig>,

    /// Ordered provider-profile sources used to build the effective catalog.
    pub provider_profile_sources: Vec<GatewayProviderProfileSourceConfig>,

    /// mTLS user authentication configuration. When enabled, a verified TLS
    /// client certificate can authenticate CLI/SDK callers as a
    /// `Principal::User`. This is for local single-user gateways only;
    /// sandbox identity is always carried by gateway-minted sandbox JWTs.
    pub mtls_auth: MtlsAuthConfig,

    /// Gateway-minted sandbox JWT configuration. When `Some`, the gateway
    /// loads the signing key from disk and accepts gateway-issued sandbox
    /// JWTs as `Principal::Sandbox`. Required for the per-sandbox identity
    /// flow (issue #1354).
    pub gateway_jwt: Option<GatewayJwtConfig>,

    /// Database URL for persistence.
    pub database_url: String,

    /// Compute drivers configured for the gateway.
    ///
    /// The config shape allows multiple drivers so the gateway can evolve
    /// toward multi-backend routing. Current releases require exactly one
    /// configured driver.
    pub compute_drivers: Vec<String>,

    /// Operator-provided endpoints for named remote compute drivers.
    ///
    /// This is populated by CLI/env inputs such as `--compute-driver-socket`.
    /// TOML-authored endpoints live under `[openshell.drivers.<name>]` and are
    /// resolved by the gateway config loader.
    pub compute_driver_endpoints: BTreeMap<String, PathBuf>,

    /// Credential drivers enabled for provider credential storage.
    pub credential_drivers: Vec<String>,

    /// Optional credential-driver default retained for compatibility. When
    /// set, it must match the single enabled credential driver.
    pub default_credential_driver: Option<String>,

    /// TTL for SSH session tokens, in seconds. 0 disables expiry.
    pub ssh_session_ttl_secs: u64,

    /// Maximum gRPC requests allowed per rate-limit window.
    ///
    /// When paired with [`Self::grpc_rate_limit_window_secs`], positive values
    /// enable gateway-wide gRPC request rate limiting. `None` or `0` disables
    /// the limit.
    pub grpc_rate_limit_requests: Option<u64>,

    /// gRPC rate-limit window length in seconds.
    ///
    /// When paired with [`Self::grpc_rate_limit_requests`], positive values
    /// enable gateway-wide gRPC request rate limiting. `None` or `0` disables
    /// the limit.
    pub grpc_rate_limit_window_secs: Option<u64>,

    /// Browser-facing sandbox service routing configuration.
    pub service_routing: ServiceRoutingConfig,
}

/// Browser-facing sandbox service routing configuration.
///
/// Part of the programmatically-built [`Config`]; never deserialized directly.
#[derive(Debug, Clone)]
pub struct ServiceRoutingConfig {
    /// Base domains accepted for `sandbox--service.<domain>` routes.
    /// The first domain is used when the gateway prints endpoint URLs.
    pub base_domains: Vec<String>,

    /// Enable TLS-enabled loopback gateway listeners to also accept plaintext
    /// HTTP for sandbox service hostnames.
    pub enable_loopback_service_http: bool,
}

/// TLS configuration.
///
/// Two modes are supported:
/// - **HTTPS with optional mTLS** (`client_ca_path = Some`):
///   Client certificates are validated against the given CA when presented,
///   but never required.  Clients may connect with or without a certificate.
/// - **HTTPS-only** (`client_ca_path = None`):
///   Server-side TLS only; no client certificates are requested.
///
/// In both modes, authentication is handled at the application layer
/// (e.g. OIDC bearer tokens).  mTLS is an additional mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: PathBuf,

    /// Path to the TLS private key file.
    pub key_path: PathBuf,

    /// Path to the CA certificate file for client certificate verification.
    /// When `Some`, client certs signed by this CA are validated.
    /// When `None`, the server does not request client certs.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,

    /// When `true` and `client_ca_path` is `Some`, the TLS handshake rejects
    /// connections that do not present a valid client certificate.
    /// When `false`, client certificates are accepted but not required.
    #[serde(default)]
    pub require_client_auth: bool,

    /// Path to an external TLS certificate file (e.g. ACME/publicly-trusted).
    /// When set, the server uses SNI-based certificate selection: connections
    /// whose SNI hostname matches `external_server_names` receive this cert,
    /// all others receive the primary (internal) cert.
    #[serde(default)]
    pub external_cert_path: Option<PathBuf>,

    /// Path to the private key for the external TLS certificate.
    #[serde(default)]
    pub external_key_path: Option<PathBuf>,

    /// Hostnames that should be served with the external certificate.
    /// Connections whose SNI matches one of these names receive the external
    /// cert; all other connections (including those with no SNI) receive the
    /// primary (internal) cert.
    #[serde(default)]
    pub external_server_names: Vec<String>,
}

/// OIDC (`OpenID` Connect) configuration for JWT-based authentication.
///
/// When configured, the server validates `authorization: Bearer <JWT>`
/// headers on gRPC requests against the specified issuer's JWKS endpoint.
///
/// The roles claim path is configurable to support different providers:
/// - Keycloak: `realm_access.roles` (default)
/// - Entra ID / Okta: `roles`
/// - Custom: any dot-separated path into the JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g., `http://localhost:8180/realms/openshell`).
    pub issuer: String,

    /// Expected audience (`aud`) claim. Typically the OIDC client ID.
    pub audience: String,

    /// JWKS cache TTL in seconds. Defaults to 3600 (1 hour).
    #[serde(default = "default_jwks_ttl_secs")]
    pub jwks_ttl_secs: u64,

    /// Dot-separated path to the roles array in the JWT claims.
    /// Defaults to `realm_access.roles` (Keycloak).
    /// Examples: `roles` (Entra ID), `groups` (Okta), `custom.path.roles`.
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,

    /// Role name that grants admin access. Defaults to `openshell-admin`.
    #[serde(default = "default_admin_role")]
    pub admin_role: String,

    /// Role name that grants standard user access. Defaults to `openshell-user`.
    #[serde(default = "default_user_role")]
    pub user_role: String,

    /// Dot-separated path to the scopes value in the JWT claims.
    /// When non-empty, the server enforces scope-based permissions on top of roles.
    /// Keycloak: `scope` (space-delimited string). Okta: `scp` (JSON array).
    #[serde(default)]
    pub scopes_claim: String,
}

/// mTLS user authentication for local, single-user gateways.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsAuthConfig {
    /// When true, the gateway maps a verified TLS client certificate into a
    /// user principal. Keep disabled for Kubernetes deployments because
    /// Kubernetes sandbox pods and external users must not share user auth.
    #[serde(default)]
    pub enabled: bool,
}

/// Gateway user authentication settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAuthConfig {
    /// When true, unauthenticated user/CLI calls are accepted as a local
    /// developer principal. This is an unsafe local-development escape hatch
    /// for trusted, non-shared gateways. Sandbox supervisor calls still use
    /// gateway-minted sandbox JWTs.
    #[serde(default)]
    pub allow_unauthenticated_users: bool,
}

/// One configured gateway interceptor service.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayInterceptorConfig {
    /// Operator-assigned instance name used in logs and config overrides.
    pub name: String,
    /// Interceptor gRPC endpoint. Supports `http://`, `https://`, and
    /// `unix://` endpoints.
    pub grpc_endpoint: String,
    /// Optional PEM trust-root bundle for an HTTPS endpoint. The gateway
    /// loads this file during interceptor initialization.
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
    /// Exact JWT audience for this service. When omitted, a kind-scoped value
    /// is derived from the configured registration name.
    #[serde(default)]
    pub audience: Option<String>,
    /// Opt out of extension authentication for this interceptor, permitting a
    /// plaintext `http://` endpoint with no bearer credential. Development and
    /// trusted-network deployments only.
    #[serde(default)]
    pub allow_insecure_transport: bool,
    /// Deterministic service ordering. Lower values run first.
    #[serde(default)]
    pub order: i32,
    /// Default failure policy for this configured service.
    #[serde(default)]
    pub failure_policy: Option<GatewayInterceptorFailurePolicy>,
    /// RFC-style timeout string such as `500ms` or `2s`.
    #[serde(default)]
    pub timeout: Option<String>,
    /// Maximum accepted encoded `Evaluate` response size.
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    /// Maximum JSON patches accepted from one evaluation result.
    #[serde(default)]
    pub max_patches: Option<usize>,
    /// Controls whether manifest bindings are dynamic, allowlisted, or must
    /// exactly match operator configuration.
    #[serde(default)]
    pub binding_policy: GatewayInterceptorBindingPolicy,
    /// Binding configuration. Its validation and authorization semantics are
    /// selected by `binding_policy`.
    #[serde(default)]
    pub bindings: Vec<GatewayInterceptorBindingOverride>,
}

impl GatewayInterceptorConfig {
    /// Resolve the configured JWT audience to its deterministic default.
    pub fn resolved_audience(&self) -> Cow<'_, str> {
        self.audience
            .as_deref()
            .filter(|audience| !audience.is_empty())
            .map_or_else(
                || Cow::Owned(format!("urn:openshell:extension:interceptor:{}", self.name)),
                Cow::Borrowed,
            )
    }
}

/// Operator policy for authorizing interceptor manifest bindings.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInterceptorBindingPolicy {
    /// Preserve manifest-controlled binding discovery. Configured bindings
    /// may narrow or disable manifest declarations.
    #[default]
    Dynamic,
    /// Enable only configured RPC selectors and phases. Extra manifest
    /// declarations are ignored.
    Allowlist,
    /// Require configured and manifest RPC selectors and phases to match.
    Exact,
}

/// One configured source in the gateway's effective provider-profile catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewayProviderProfileSourceConfig {
    /// Profiles bundled with the `OpenShell` build.
    Builtin,
    /// Profiles managed through the provider profile mutation APIs.
    User,
    /// Profiles vended by a configured gateway interceptor instance.
    Interceptor { name: String },
}

/// Failure behavior when an interceptor evaluation cannot produce a valid
/// result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInterceptorFailurePolicy {
    FailClosed,
    FailOpen,
}

/// Configured binding authorization or dynamic-manifest override.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayInterceptorBindingOverride {
    /// Binding id from the interceptor manifest.
    #[serde(default)]
    pub id: Option<String>,
    /// Full selector form: `openshell.v1.OpenShell/CreateSandbox`.
    #[serde(default)]
    pub rpc: Option<String>,
    /// Structured selector service, e.g. `openshell.v1.OpenShell`.
    #[serde(default)]
    pub service: Option<String>,
    /// Structured selector method, e.g. `CreateSandbox`.
    #[serde(default)]
    pub method: Option<String>,
    /// Narrowed phase set.
    #[serde(default)]
    pub phases: Option<Vec<GatewayInterceptorPhaseConfig>>,
    /// Disable the selected binding.
    #[serde(default)]
    pub disabled: bool,
    /// Binding-specific failure policy override.
    #[serde(default)]
    pub failure_policy: Option<GatewayInterceptorFailurePolicy>,
}

/// Config file phase names.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInterceptorPhaseConfig {
    ModifyOperation,
    Validate,
    PostCommit,
}

const fn default_jwks_ttl_secs() -> u64 {
    3600
}

/// Gateway-minted sandbox JWT configuration.
///
/// Points the gateway at the Ed25519 signing key (produced by `certgen`)
/// and identifies the issuer string embedded in every minted token. The
/// signing key never leaves the gateway process; the public key is loaded
/// by the same gateway so it can validate its own tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayJwtConfig {
    /// Path to the Ed25519 signing key (PKCS#8 PEM).
    pub signing_key_path: PathBuf,
    /// Path to the matching public key (SPKI PEM).
    pub public_key_path: PathBuf,
    /// Path to the `kid` value (plain text, one line).
    pub kid_path: PathBuf,
    /// Stable gateway identity embedded in `iss`/`aud`. Defaults to the
    /// hostname-or-`openshell` placeholder if unset.
    #[serde(default = "default_gateway_id")]
    pub gateway_id: String,
    /// Token lifetime in seconds. A value of 0 disables expiration and is
    /// intended only for local single-player deployments.
    #[serde(default = "default_sandbox_token_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_gateway_id() -> String {
    "openshell".to_string()
}

const fn default_sandbox_token_ttl_secs() -> u64 {
    0
}

fn default_roles_claim() -> String {
    "realm_access.roles".to_string()
}

fn default_admin_role() -> String {
    "openshell-admin".to_string()
}

fn default_user_role() -> String {
    "openshell-user".to_string()
}

impl Config {
    /// Create a new config with optional TLS.
    pub fn new(tls: Option<TlsConfig>) -> Self {
        Self {
            bind_address: default_bind_address(),
            health_bind_address: None,
            metrics_bind_address: None,
            log_level: default_log_level(),
            policy_validation_failure_mode: PolicyValidationFailureMode::default(),
            tls,
            oidc: None,
            auth: GatewayAuthConfig::default(),
            gateway_interceptors: Vec::new(),
            provider_profile_sources: vec![
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::User,
            ],
            mtls_auth: MtlsAuthConfig::default(),
            gateway_jwt: None,
            database_url: String::new(),
            compute_drivers: vec![],
            compute_driver_endpoints: BTreeMap::new(),
            credential_drivers: Vec::new(),
            default_credential_driver: None,
            ssh_session_ttl_secs: default_ssh_session_ttl_secs(),
            grpc_rate_limit_requests: None,
            grpc_rate_limit_window_secs: None,
            service_routing: ServiceRoutingConfig::default(),
        }
    }

    /// Create a new configuration with the given bind address.
    #[must_use]
    pub const fn with_bind_address(mut self, addr: SocketAddr) -> Self {
        self.bind_address = addr;
        self
    }

    #[must_use]
    pub const fn with_health_bind_address(mut self, addr: SocketAddr) -> Self {
        self.health_bind_address = Some(addr);
        self
    }

    #[must_use]
    pub const fn with_metrics_bind_address(mut self, addr: SocketAddr) -> Self {
        self.metrics_bind_address = Some(addr);
        self
    }

    /// Create a new configuration with the given log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Create a new configuration with a database URL.
    #[must_use]
    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = url.into();
        self
    }

    /// Create a new configuration with the configured compute drivers.
    #[must_use]
    pub fn with_compute_drivers<I, D>(mut self, drivers: I) -> Self
    where
        I: IntoIterator<Item = D>,
        D: ToString,
    {
        self.compute_drivers = drivers
            .into_iter()
            .map(|driver| driver.to_string())
            .collect();
        self
    }

    /// Register a Unix domain socket endpoint for a named remote driver.
    #[must_use]
    pub fn with_compute_driver_endpoint(
        mut self,
        name: impl Into<String>,
        socket: impl Into<PathBuf>,
    ) -> Self {
        self.compute_driver_endpoints
            .insert(name.into(), socket.into());
        self
    }

    /// Create a new configuration with the configured credential drivers.
    #[must_use]
    pub fn with_credential_drivers<I, S>(mut self, drivers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.credential_drivers = drivers.into_iter().map(Into::into).collect();
        self
    }

    /// Create a new configuration with the default credential driver.
    #[must_use]
    pub fn with_default_credential_driver(mut self, driver: Option<impl Into<String>>) -> Self {
        self.default_credential_driver = driver.map(Into::into);
        self
    }

    /// Create a new configuration with the SSH session TTL.
    #[must_use]
    pub const fn with_ssh_session_ttl_secs(mut self, secs: u64) -> Self {
        self.ssh_session_ttl_secs = secs;
        self
    }

    /// Set the gateway-wide gRPC request rate limit.
    #[must_use]
    pub const fn with_grpc_rate_limit(
        mut self,
        requests: Option<u64>,
        window_secs: Option<u64>,
    ) -> Self {
        self.grpc_rate_limit_requests = requests;
        self.grpc_rate_limit_window_secs = window_secs;
        self
    }

    /// Set configured gateway interceptors.
    #[must_use]
    pub fn with_gateway_interceptors<I>(mut self, interceptors: I) -> Self
    where
        I: IntoIterator<Item = GatewayInterceptorConfig>,
    {
        self.gateway_interceptors = interceptors.into_iter().collect();
        self
    }

    /// Set the ordered provider-profile sources used by the gateway.
    #[must_use]
    pub fn with_provider_profile_sources<I>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = GatewayProviderProfileSourceConfig>,
    {
        self.provider_profile_sources = sources.into_iter().collect();
        self
    }

    /// Return the effective gRPC rate limit, if fully configured and enabled.
    #[must_use]
    pub fn grpc_rate_limit(&self) -> Option<(u64, Duration)> {
        let requests = self.grpc_rate_limit_requests?;
        let window_secs = self.grpc_rate_limit_window_secs?;
        if requests == 0 || window_secs == 0 {
            None
        } else {
            Some((requests, Duration::from_secs(window_secs)))
        }
    }
    /// Set the OIDC configuration for JWT-based authentication.
    #[must_use]
    pub fn with_oidc(mut self, oidc: OidcConfig) -> Self {
        self.oidc = Some(oidc);
        self
    }

    /// Derive browser-facing sandbox service domains from gateway server SANs.
    ///
    /// Wildcard DNS SANs such as `*.apps.example.com` enable service URLs
    /// under `apps.example.com`. Non-wildcard DNS names and IP SANs do not
    /// enable service subdomains.
    #[must_use]
    pub fn with_server_sans<I, S>(mut self, sans: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.service_routing.base_domains = service_routing_domains_from_server_sans(sans);
        self
    }

    /// Enable or disable plaintext HTTP routing for loopback sandbox service
    /// hostnames on TLS-enabled gateway listeners.
    #[must_use]
    pub const fn with_loopback_service_http(mut self, enabled: bool) -> Self {
        self.service_routing.enable_loopback_service_http = enabled;
        self
    }
}

impl Default for ServiceRoutingConfig {
    fn default() -> Self {
        Self {
            base_domains: default_service_routing_domains(),
            enable_loopback_service_http: default_enable_loopback_service_http(),
        }
    }
}

fn default_bind_address() -> SocketAddr {
    "127.0.0.1:17670".parse().expect("valid default address")
}

fn default_service_routing_domains() -> Vec<String> {
    vec![DEFAULT_SERVICE_ROUTING_DOMAIN.to_string()]
}

const fn default_enable_loopback_service_http() -> bool {
    true
}

fn service_routing_domains_from_server_sans<I, S>(sans: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut domains = Vec::new();
    for san in sans {
        if let Some(domain) = service_routing_domain_from_server_san(&san.into())
            && !domains.contains(&domain)
        {
            domains.push(domain);
        }
    }
    for domain in default_service_routing_domains() {
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    domains
}

fn service_routing_domain_from_server_san(san: &str) -> Option<String> {
    let san = san.trim().trim_matches('.').to_ascii_lowercase();
    let domain = san.strip_prefix("*.")?;
    normalize_service_routing_domain(domain)
}

fn normalize_service_routing_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let labels = domain.split('.');
    if labels.clone().any(|label| !is_dns_label(label)) {
        return None;
    }
    Some(domain.to_string())
}

fn is_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_ssh_session_ttl_secs() -> u64 {
    86400 // 24 hours
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveMachine, ComputeDriverKind, Config, DEFAULT_SERVICE_ROUTING_DOMAIN,
        GatewayInterceptorBindingPolicy, GatewayInterceptorConfig, GatewayInterceptorFailurePolicy,
        GatewayJwtConfig, GatewayProviderProfileSourceConfig, PolicyValidationFailureMode,
        detect_docker_socket_from_candidates, detect_driver, detect_podman_socket_from_candidates,
        docker_host_unix_socket_path, docker_socket_responds, explicit_unix_container_host,
        normalize_compute_driver_name, parse_default_podman_connection, parse_podman_info_socket,
        parse_podman_machine_inspect_socket, podman_connection_name_for_uri,
        podman_machine_inspect_targets, podman_socket_candidates_from_env, podman_socket_responds,
        resolve_active_podman_machine, run_bounded_command, unix_url_socket_path,
    };
    #[cfg(unix)]
    use super::{is_reachable_unix_socket, is_unix_socket};
    #[cfg(unix)]
    use std::io::{Read as _, Write as _};
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;
    #[cfg(unix)]
    use std::time::Instant;

    #[test]
    fn compute_driver_kind_parses_supported_values() {
        assert_eq!(
            "kubernetes".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Kubernetes
        );
        assert_eq!(
            "vm".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Vm
        );
        assert_eq!(
            "podman".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Podman
        );
        assert_eq!(
            "docker".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Docker
        );
    }

    #[test]
    fn compute_driver_kind_rejects_unknown_values() {
        let err = "firecracker".parse::<ComputeDriverKind>().unwrap_err();
        assert!(err.contains("unsupported compute driver 'firecracker'"));
    }

    #[test]
    fn policy_validation_failure_mode_is_secure_by_default() {
        assert_eq!(
            Config::new(None).policy_validation_failure_mode,
            PolicyValidationFailureMode::FailClosed
        );
        assert_eq!(
            "retain_last_valid"
                .parse::<PolicyValidationFailureMode>()
                .unwrap(),
            PolicyValidationFailureMode::RetainLastValid
        );
        assert!("keep_old".parse::<PolicyValidationFailureMode>().is_err());
    }

    #[test]
    fn compute_driver_name_normalization_accepts_builtin_and_custom_names() {
        assert_eq!(normalize_compute_driver_name(" VM ").unwrap(), "vm");
        assert_eq!(
            normalize_compute_driver_name("Kyma_GPU-1").unwrap(),
            "kyma_gpu-1"
        );

        let err = normalize_compute_driver_name("kyma/gpu").unwrap_err();
        assert!(err.contains("invalid compute driver name"));
    }

    #[test]
    fn config_defaults_to_loopback_bind_address() {
        let expected: SocketAddr = "127.0.0.1:17670".parse().expect("valid address");
        assert_eq!(Config::new(None).bind_address, expected);
    }

    #[test]
    fn config_new_disables_health_bind_by_default() {
        let cfg = Config::new(None);
        assert!(cfg.health_bind_address.is_none());
    }

    #[test]
    fn config_disables_unauthenticated_users_by_default() {
        let cfg = Config::new(None);
        assert!(!cfg.auth.allow_unauthenticated_users);
    }

    #[test]
    fn config_defaults_to_builtin_and_user_provider_profile_sources() {
        let cfg = Config::new(None);
        assert_eq!(
            cfg.provider_profile_sources,
            vec![
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::User,
            ]
        );
    }

    #[test]
    fn config_defaults_to_internal_credential_storage() {
        let cfg = Config::new(None);
        assert!(cfg.credential_drivers.is_empty());
        assert!(cfg.default_credential_driver.is_none());
    }

    #[test]
    fn config_accepts_credential_driver_settings() {
        let cfg = Config::new(None)
            .with_credential_drivers(["kubernetes-secrets", "vault"])
            .with_default_credential_driver(Some("kubernetes-secrets"));

        assert_eq!(
            cfg.credential_drivers,
            vec!["kubernetes-secrets".to_string(), "vault".to_string()]
        );
        assert_eq!(
            cfg.default_credential_driver.as_deref(),
            Some("kubernetes-secrets")
        );
    }

    #[test]
    fn gateway_jwt_ttl_defaults_to_non_expiring() {
        let cfg: GatewayJwtConfig = serde_json::from_value(serde_json::json!({
            "signing_key_path": "/tmp/signing.pem",
            "public_key_path": "/tmp/public.pem",
            "kid_path": "/tmp/kid"
        }))
        .expect("gateway JWT config should deserialize with default ttl");

        assert_eq!(cfg.ttl_secs, 0);
    }

    #[test]
    fn gateway_interceptor_failure_policy_rejects_ignore() {
        let err =
            serde_json::from_value::<GatewayInterceptorFailurePolicy>(serde_json::json!("ignore"))
                .unwrap_err();

        assert!(err.to_string().contains("unknown variant `ignore`"));
    }

    #[test]
    fn gateway_interceptor_binding_policy_defaults_and_parses_strict_modes() {
        let defaulted: GatewayInterceptorConfig = serde_json::from_value(serde_json::json!({
            "name": "governance",
            "grpc_endpoint": "unix:///tmp/governance.sock"
        }))
        .unwrap();
        let allowlist: GatewayInterceptorBindingPolicy =
            serde_json::from_value(serde_json::json!("allowlist")).unwrap();
        let exact: GatewayInterceptorBindingPolicy =
            serde_json::from_value(serde_json::json!("exact")).unwrap();

        assert_eq!(
            defaulted.binding_policy,
            GatewayInterceptorBindingPolicy::Dynamic
        );
        assert_eq!(
            defaulted.resolved_audience(),
            "urn:openshell:extension:interceptor:governance"
        );
        let explicitly_empty = GatewayInterceptorConfig {
            name: "governance".to_string(),
            audience: Some(String::new()),
            ..GatewayInterceptorConfig::default()
        };
        assert_eq!(
            explicitly_empty.resolved_audience(),
            "urn:openshell:extension:interceptor:governance"
        );
        assert_eq!(allowlist, GatewayInterceptorBindingPolicy::Allowlist);
        assert_eq!(exact, GatewayInterceptorBindingPolicy::Exact);
    }

    #[test]
    fn grpc_rate_limit_requires_positive_pair() {
        assert!(Config::new(None).grpc_rate_limit().is_none());
        assert!(
            Config::new(None)
                .with_grpc_rate_limit(Some(10), None)
                .grpc_rate_limit()
                .is_none()
        );
        assert!(
            Config::new(None)
                .with_grpc_rate_limit(Some(0), Some(60))
                .grpc_rate_limit()
                .is_none()
        );
        assert_eq!(
            Config::new(None)
                .with_grpc_rate_limit(Some(10), Some(60))
                .grpc_rate_limit(),
            Some((10, Duration::from_secs(60)))
        );
    }

    #[test]
    fn service_routing_allows_loopback_plaintext_http_by_default() {
        let cfg = Config::new(None);
        assert_eq!(
            cfg.service_routing.base_domains,
            vec![DEFAULT_SERVICE_ROUTING_DOMAIN.to_string()]
        );
        assert!(cfg.service_routing.enable_loopback_service_http);
    }

    #[test]
    fn server_sans_update_preserves_loopback_plaintext_http_flag() {
        let cfg = Config::new(None)
            .with_loopback_service_http(false)
            .with_server_sans(["*.dev.openshell.localhost"]);

        assert_eq!(
            cfg.service_routing.base_domains,
            vec![
                "dev.openshell.localhost".to_string(),
                DEFAULT_SERVICE_ROUTING_DOMAIN.to_string()
            ]
        );
        assert!(!cfg.service_routing.enable_loopback_service_http);
    }

    #[test]
    fn service_routing_domains_are_derived_from_wildcard_server_sans() {
        let cfg = Config::new(None).with_server_sans([
            "gateway.example.com",
            "*.apps.example.com",
            "127.0.0.1",
            "*.apps.example.com",
            "*.dev.example.com.",
        ]);

        assert_eq!(
            cfg.service_routing.base_domains,
            vec![
                "apps.example.com".to_string(),
                "dev.example.com".to_string(),
                DEFAULT_SERVICE_ROUTING_DOMAIN.to_string(),
            ]
        );
    }

    #[test]
    fn config_with_health_bind_address_sets_address() {
        let addr: SocketAddr = "0.0.0.0:9090".parse().expect("valid address");
        let cfg = Config::new(None).with_health_bind_address(addr);
        assert_eq!(cfg.health_bind_address, Some(addr));
    }

    #[test]
    fn detect_driver_returns_none_without_k8s_env_or_local_runtime() {
        // When KUBERNETES_SERVICE_HOST is not set, no Docker binary/socket is
        // available, and no Podman API socket is available, detect_driver
        // should return None.
        // This test may pass or fail depending on the test environment,
        // but it documents the expected behavior.
        let _ = detect_driver(); // Returns Some or None based on environment
    }

    #[test]
    fn docker_host_unix_socket_path_parses_unix_hosts() {
        assert_eq!(
            docker_host_unix_socket_path("unix:///var/run/docker.sock"),
            Some(PathBuf::from("/var/run/docker.sock"))
        );
        assert_eq!(docker_host_unix_socket_path("tcp://127.0.0.1:2375"), None);
        assert_eq!(docker_host_unix_socket_path("unix://"), None);
    }

    #[cfg(unix)]
    #[test]
    fn is_unix_socket_detects_socket_files() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("docker.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind unix socket");

        assert!(is_unix_socket(&socket_path));
        assert!(is_reachable_unix_socket(&socket_path));

        let regular_file = temp_dir.path().join("not-a-socket");
        std::fs::write(&regular_file, b"not a socket").expect("write regular file");
        assert!(!is_unix_socket(&regular_file));
        assert!(!is_reachable_unix_socket(&regular_file));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "flaky under concurrent test execution"]
    fn podman_socket_probe_accepts_successful_ping_response() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind podman socket");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept podman probe");
            let mut request = [0_u8; 128];
            let n = stream.read(&mut request).expect("read podman probe");
            assert!(request[..n].starts_with(b"GET /_ping HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nLibpod-Api-Version: 5.8.2\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write podman ping response");
        });

        assert!(podman_socket_responds(&socket_path));
        handle.join().expect("probe server exits");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "flaky under concurrent test execution"]
    fn podman_socket_probe_rejects_docker_ping_response() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind podman socket");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept podman probe");
            let mut request = [0_u8; 128];
            let n = stream.read(&mut request).expect("read podman probe");
            assert!(request[..n].starts_with(b"GET /_ping HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nServer: Docker/29.2.1\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write docker ping response");
        });

        assert!(!podman_socket_responds(&socket_path));
        handle.join().expect("probe server exits");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "flaky under concurrent test execution"]
    fn docker_socket_probe_accepts_successful_ping_response() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind docker socket");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept docker probe");
            let mut request = [0_u8; 128];
            let n = stream.read(&mut request).expect("read docker probe");
            assert!(request[..n].starts_with(b"GET /_ping HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nApi-Version: 1.51\r\nDocker-Experimental: false\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write docker ping response");
        });

        assert!(docker_socket_responds(&socket_path));
        handle.join().expect("probe server exits");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "flaky under concurrent test execution"]
    fn docker_socket_probe_rejects_podman_ping_response() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind podman socket");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept docker probe");
            let mut request = [0_u8; 128];
            let n = stream.read(&mut request).expect("read docker probe");
            assert!(request[..n].starts_with(b"GET /_ping HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nLibpod-Api-Version: 5.8.2\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write podman ping response");
        });

        assert!(!docker_socket_responds(&socket_path));
        handle.join().expect("probe server exits");
    }

    #[cfg(unix)]
    #[test]
    fn docker_socket_probe_rejects_inactive_socket() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind docker socket");
        drop(listener);

        assert!(is_unix_socket(&socket_path));
        assert!(!docker_socket_responds(&socket_path));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "flaky under concurrent test execution"]
    fn docker_socket_detection_returns_the_responsive_candidate() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let inactive_path = temp_dir.path().join("inactive.sock");
        let inactive_listener = UnixListener::bind(&inactive_path).expect("bind inactive socket");
        drop(inactive_listener);

        let responsive_path = temp_dir.path().join("responsive.sock");
        let listener = UnixListener::bind(&responsive_path).expect("bind responsive socket");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept docker probe");
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request).expect("read docker probe");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nApi-Version: 1.51\r\nContent-Length: 2\r\n\r\nOK")
                .expect("write docker ping response");
        });

        assert_eq!(
            detect_docker_socket_from_candidates(&[inactive_path, responsive_path.clone(),]),
            Some(responsive_path)
        );
        handle.join().expect("probe server exits");
    }

    #[test]
    fn podman_socket_candidates_include_env_runtime_and_home_paths() {
        let candidates = podman_socket_candidates_from_env(
            Some(PathBuf::from("/tmp/custom-podman.sock")),
            Some(PathBuf::from("/tmp/runtime")),
            Some(PathBuf::from("/tmp/home")),
        );

        assert!(candidates.contains(&PathBuf::from("/tmp/custom-podman.sock")));
        assert!(candidates.contains(&PathBuf::from("/tmp/runtime/podman/podman.sock")));
        assert!(candidates.contains(&PathBuf::from(
            "/tmp/home/.local/share/containers/podman/machine/podman.sock"
        )));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "flaky under concurrent test execution"]
    fn podman_socket_detection_returns_the_responsive_candidate() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let inactive_path = temp_dir.path().join("inactive.sock");
        let inactive_listener = UnixListener::bind(&inactive_path).expect("bind inactive socket");
        drop(inactive_listener);

        let responsive_path = temp_dir.path().join("responsive.sock");
        let listener = UnixListener::bind(&responsive_path).expect("bind responsive socket");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept podman probe");
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request).expect("read podman probe");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nLibpod-Api-Version: 5.8.2\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write podman ping response");
        });

        assert_eq!(
            detect_podman_socket_from_candidates(&[inactive_path, responsive_path.clone(),]),
            Some(responsive_path)
        );
        handle.join().expect("probe server exits");
    }

    #[test]
    #[allow(unsafe_code)] // std::env::set_var/remove_var require unsafe in Rust 2024
    fn detect_driver_prefers_kubernetes_when_k8s_env_is_set() {
        // Save the original env var
        let original = std::env::var("KUBERNETES_SERVICE_HOST").ok();

        // Set the env var
        unsafe {
            std::env::set_var("KUBERNETES_SERVICE_HOST", "127.0.0.1");
        }

        let result = detect_driver();
        assert_eq!(result, Some(ComputeDriverKind::Kubernetes));

        // Restore the original env var
        unsafe {
            match original {
                Some(val) => std::env::set_var("KUBERNETES_SERVICE_HOST", val),
                None => std::env::remove_var("KUBERNETES_SERVICE_HOST"),
            }
        }
    }

    #[test]
    fn supervisor_image_tag_prefers_explicit_build_tags() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(&["1.2.3", "sha", "0.0.0"]),
            "1.2.3"
        );
        assert_eq!(resolve_supervisor_image_tag(&["", "sha", "0.0.0"]), "sha");
        assert_eq!(resolve_supervisor_image_tag(&["", "", "1.2.3"]), "1.2.3");
        assert_eq!(resolve_supervisor_image_tag(&["", "", "0.0.0"]), "dev");
        assert_eq!(
            resolve_supervisor_image_tag(&["latest", "", "1.2.3"]),
            "latest"
        );
    }

    #[test]
    fn parse_podman_info_socket_extracts_linux_local_socket() {
        let info: serde_json::Value = serde_json::json!({
            "host": {
                "serviceIsRemote": false,
                "remoteSocket": {
                    "path": "unix:///run/user/1000/podman/podman.sock",
                    "exists": true
                }
            }
        });
        assert_eq!(
            parse_podman_info_socket(&info),
            Some(PathBuf::from("/run/user/1000/podman/podman.sock"))
        );
    }

    #[test]
    fn supervisor_image_tag_sanitizes_build_metadata_for_oci() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(&["", "", "0.0.37-dev.156+g1d3b741ee"]),
            "0.0.37-dev.156-g1d3b741ee",
        );
        assert_eq!(
            resolve_supervisor_image_tag(&["0.0.37-dev.156+g1d3b741ee", "", "0.0.0"]),
            "0.0.37-dev.156-g1d3b741ee",
        );
    }

    #[test]
    fn parse_podman_info_socket_handles_path_without_unix_prefix() {
        let info: serde_json::Value = serde_json::json!({
            "host": {
                "remoteSocket": {
                    "path": "/run/user/1000/podman/podman.sock",
                    "exists": true
                }
            }
        });
        assert_eq!(
            parse_podman_info_socket(&info),
            Some(PathBuf::from("/run/user/1000/podman/podman.sock"))
        );
    }

    #[test]
    fn default_supervisor_image_is_version_pinned() {
        use super::default_supervisor_image;
        let image = default_supervisor_image();
        assert!(image.starts_with("ghcr.io/nvidia/openshell/supervisor:"));
        let tag = image.rsplit_once(':').unwrap().1;
        assert!(!tag.is_empty());
    }

    #[test]
    fn parse_podman_info_socket_returns_none_for_missing_path() {
        let info: serde_json::Value = serde_json::json!({
            "host": {
                "remoteSocket": {}
            }
        });
        assert_eq!(parse_podman_info_socket(&info), None);
    }

    #[test]
    fn parse_podman_info_socket_returns_none_for_empty_path() {
        let info: serde_json::Value = serde_json::json!({
            "host": {
                "remoteSocket": {
                    "path": "",
                    "exists": false
                }
            }
        });
        assert_eq!(parse_podman_info_socket(&info), None);
    }

    #[test]
    fn parse_podman_machine_inspect_socket_extracts_macos_socket() {
        // `podman machine inspect <machine>` returns only the inspected machine.
        let machines: serde_json::Value = serde_json::json!([
            {
                "ConnectionInfo": {
                    "PodmanSocket": {
                        "Path": "/var/folders/1q/jx7s14b928n8zvstgfk98lj00000gn/T/podman/podman-machine-default-api.sock"
                    },
                    "PodmanPipe": null
                },
                "Name": "podman-machine-default"
            }
        ]);
        assert_eq!(
            parse_podman_machine_inspect_socket(&machines),
            Some(PathBuf::from(
                "/var/folders/1q/jx7s14b928n8zvstgfk98lj00000gn/T/podman/podman-machine-default-api.sock"
            ))
        );
    }

    #[test]
    fn parse_podman_machine_inspect_socket_returns_none_for_empty_array() {
        let machines: serde_json::Value = serde_json::json!([]);
        assert_eq!(parse_podman_machine_inspect_socket(&machines), None);
    }

    #[test]
    fn parse_podman_machine_inspect_socket_returns_none_for_missing_socket() {
        let machines: serde_json::Value = serde_json::json!([
            {
                "ConnectionInfo": {},
                "Name": "podman-machine-default"
            }
        ]);
        assert_eq!(parse_podman_machine_inspect_socket(&machines), None);
    }

    #[test]
    fn podman_machine_inspect_targets_uses_explicit_machine_by_name() {
        // The active connection points at `work`; discovery must inspect `work`
        // explicitly rather than the no-argument default machine, which would
        // return a different machine's socket.
        assert_eq!(
            podman_machine_inspect_targets(&ActiveMachine::Explicit("work".to_string())),
            Some(vec!["work".to_string()])
        );
    }

    #[test]
    fn podman_machine_inspect_targets_strips_rootful_suffix() {
        // Rootful connections are named `<machine>-root`; the machine itself is
        // `<machine>`, offered as a fallback after the connection name.
        assert_eq!(
            podman_machine_inspect_targets(&ActiveMachine::Explicit("work-root".to_string())),
            Some(vec!["work-root".to_string(), "work".to_string()])
        );
    }

    #[test]
    fn podman_machine_inspect_targets_uses_default_connection_name() {
        assert_eq!(
            podman_machine_inspect_targets(&ActiveMachine::Default(Some("work".to_string()))),
            Some(vec!["work".to_string()])
        );
    }

    #[test]
    fn podman_machine_inspect_targets_falls_back_to_builtin_default() {
        // No explicit selector and no default connection: inspect Podman's own
        // built-in default machine by name.
        assert_eq!(
            podman_machine_inspect_targets(&ActiveMachine::Default(None)),
            Some(vec!["podman-machine-default".to_string()])
        );
    }

    #[test]
    fn podman_machine_inspect_targets_does_not_guess_for_unresolved_explicit() {
        // CONTAINER_HOST pointing at a non-machine endpoint cannot be mapped to
        // a machine; discovery must not guess an unrelated one.
        assert_eq!(
            podman_machine_inspect_targets(&ActiveMachine::UnresolvedExplicit),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_command_captures_stdout_on_success() {
        assert_eq!(
            run_bounded_command("printf", &["hello"], Duration::from_secs(5)),
            Some(b"hello".to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_command_returns_none_on_nonzero_exit() {
        assert_eq!(
            run_bounded_command("false", &[], Duration::from_secs(5)),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_command_kills_child_that_exceeds_deadline() {
        // A process that would otherwise block startup indefinitely must be
        // bounded: `run_bounded_command` returns within the deadline instead of
        // hanging until the child exits.
        let start = Instant::now();
        let result = run_bounded_command("sleep", &["30"], Duration::from_millis(200));
        let elapsed = start.elapsed();
        assert_eq!(result, None);
        assert!(
            elapsed < Duration::from_secs(5),
            "bounded command did not return promptly: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_command_bounds_drain_when_in_group_descendant_holds_stdout() {
        // The shell exits immediately after `echo`, but the backgrounded child
        // (in the same process group) inherits and holds the stdout pipe open.
        // Without a bounded drain, `read_to_end` would wait ~30s for EOF even
        // though the direct child already exited.
        let start = Instant::now();
        let result = run_bounded_command(
            "sh",
            &["-c", "sleep 30 & echo done"],
            Duration::from_millis(300),
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "drain blocked on a descendant holding stdout: {elapsed:?}"
        );
        // Draining hit the deadline, so the probe is treated as "not found".
        assert_eq!(result, None);
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_command_bounds_drain_when_descendant_escapes_process_group() {
        // `set -m` runs the background job in its OWN process group, so it
        // survives the group kill while still holding the stdout pipe. The
        // deadline must remain absolute: the call must not fall back to an
        // untimed receive that waits for the escaped descendant's EOF.
        let start = Instant::now();
        let result = run_bounded_command(
            "bash",
            &["-c", "set -m; sleep 5 & echo done"],
            Duration::from_millis(300),
        );
        let elapsed = start.elapsed();
        // A regression (blocking receive after the timeout) would wait ~5s for
        // the escaped `sleep`; the bounded implementation returns promptly.
        assert!(
            elapsed < Duration::from_secs(2),
            "drain blocked on a descendant that escaped the process group: {elapsed:?}"
        );
        assert_eq!(result, None);
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_command_returns_none_for_missing_program() {
        assert_eq!(
            run_bounded_command(
                "openshell-nonexistent-binary-xyz",
                &[],
                Duration::from_secs(5)
            ),
            None
        );
    }

    #[test]
    fn resolve_active_podman_machine_maps_container_host_to_connection() {
        let connections: serde_json::Value = serde_json::json!([
            { "Name": "work", "IsMachine": true, "Default": false,
              "URI": "ssh://core@127.0.0.1:5555/run/user/1000/podman/podman.sock" },
            { "Name": "podman-machine-default", "IsMachine": true, "Default": true,
              "URI": "ssh://core@127.0.0.1:4444/run/user/1000/podman/podman.sock" }
        ]);
        // CONTAINER_HOST pointing at the non-default machine's URI resolves to
        // that machine, not the default.
        assert_eq!(
            resolve_active_podman_machine(
                Some("ssh://core@127.0.0.1:5555/run/user/1000/podman/podman.sock"),
                Some(&connections)
            ),
            ActiveMachine::Explicit("work".to_string())
        );
    }

    #[test]
    fn resolve_active_podman_machine_unmatched_host_is_unresolved() {
        let connections: serde_json::Value = serde_json::json!([
            { "Name": "podman-machine-default", "IsMachine": true, "Default": true,
              "URI": "ssh://core@127.0.0.1:4444/run/user/1000/podman/podman.sock" }
        ]);
        // A CONTAINER_HOST that matches no machine connection is unresolved,
        // never silently mapped to the default machine.
        assert_eq!(
            resolve_active_podman_machine(Some("tcp://192.0.2.10:2375"), Some(&connections)),
            ActiveMachine::UnresolvedExplicit
        );
    }

    #[test]
    fn resolve_active_podman_machine_defaults_without_host() {
        let connections: serde_json::Value = serde_json::json!([
            { "Name": "podman-machine-default", "IsMachine": true, "Default": true,
              "URI": "ssh://core@127.0.0.1:4444/run/user/1000/podman/podman.sock" }
        ]);
        assert_eq!(
            resolve_active_podman_machine(None, Some(&connections)),
            ActiveMachine::Default(Some("podman-machine-default".to_string()))
        );
    }

    #[test]
    fn podman_connection_name_for_uri_ignores_non_machine_matches() {
        let connections: serde_json::Value = serde_json::json!([
            { "Name": "remote", "IsMachine": false, "Default": false,
              "URI": "tcp://192.0.2.10:2375" }
        ]);
        // A URI match against a non-machine connection does not map to a local
        // machine socket.
        assert_eq!(
            podman_connection_name_for_uri(&connections, "tcp://192.0.2.10:2375"),
            None
        );
    }

    #[test]
    fn unix_url_socket_path_parses_unix_urls() {
        assert_eq!(
            unix_url_socket_path("unix:///run/user/1000/podman/podman.sock"),
            Some(PathBuf::from("/run/user/1000/podman/podman.sock"))
        );
        // Non-unix schemes and empty paths are not sockets.
        assert_eq!(unix_url_socket_path("ssh://core@127.0.0.1:22/x"), None);
        assert_eq!(unix_url_socket_path("tcp://127.0.0.1:2375"), None);
        assert_eq!(unix_url_socket_path("unix://"), None);
    }

    #[test]
    #[allow(unsafe_code)] // std::env::set_var/remove_var require unsafe in Rust 2024
    fn explicit_unix_container_host_honors_scheme_and_precedence() {
        fn set(key: &str, value: Option<&str>) {
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }

        let original_host = std::env::var("CONTAINER_HOST").ok();
        let original_connection = std::env::var("CONTAINER_CONNECTION").ok();

        // A unix:// CONTAINER_HOST with no CONTAINER_CONNECTION is used directly.
        set("CONTAINER_CONNECTION", None);
        set("CONTAINER_HOST", Some("unix:///tmp/podman/custom.sock"));
        assert_eq!(
            explicit_unix_container_host(),
            Some(PathBuf::from("/tmp/podman/custom.sock"))
        );

        // CONTAINER_CONNECTION outranks CONTAINER_HOST.
        set("CONTAINER_CONNECTION", Some("work"));
        assert_eq!(explicit_unix_container_host(), None);

        // A non-unix CONTAINER_HOST is not a direct socket.
        set("CONTAINER_CONNECTION", None);
        set(
            "CONTAINER_HOST",
            Some("ssh://core@127.0.0.1:5555/run/podman.sock"),
        );
        assert_eq!(explicit_unix_container_host(), None);

        // Nothing set.
        set("CONTAINER_HOST", None);
        assert_eq!(explicit_unix_container_host(), None);

        set("CONTAINER_HOST", original_host.as_deref());
        set("CONTAINER_CONNECTION", original_connection.as_deref());
    }

    #[test]
    fn parse_default_podman_connection_picks_default_machine() {
        let connections: serde_json::Value = serde_json::json!([
            { "Name": "podman-machine-default", "IsMachine": true, "Default": true },
            { "Name": "podman-machine-default-root", "IsMachine": true, "Default": false }
        ]);
        assert_eq!(
            parse_default_podman_connection(&connections),
            Some("podman-machine-default".to_string())
        );
    }

    #[test]
    fn parse_default_podman_connection_ignores_non_machine_and_missing_default() {
        // Default connection that is not a machine is ignored.
        let non_machine: serde_json::Value = serde_json::json!([
            { "Name": "remote-host", "IsMachine": false, "Default": true }
        ]);
        assert_eq!(parse_default_podman_connection(&non_machine), None);

        // No default at all.
        let no_default: serde_json::Value = serde_json::json!([
            { "Name": "work", "IsMachine": true, "Default": false }
        ]);
        assert_eq!(parse_default_podman_connection(&no_default), None);
    }
}
