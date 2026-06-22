// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared port-forward PID file management and SSH utility functions.
//!
//! Used by both the CLI (`openshell-cli`) and the TUI (`openshell-tui`) to
//! start, stop, list, and track background SSH port forwards.

use crate::paths::{create_dir_restricted, xdg_config_dir};
use miette::{IntoDiagnostic, Result, WrapErr};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Forward PID file management
// ---------------------------------------------------------------------------

/// Base directory for forward PID files.
pub fn forward_pid_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("openshell").join("forwards"))
}

/// PID file path for a specific sandbox + port forward.
pub fn forward_pid_path(name: &str, port: u16) -> Result<PathBuf> {
    Ok(forward_pid_dir()?.join(format!("{name}-{port}.pid")))
}

/// Write a PID file for a background forward.
///
/// File format: `<pid>\t<sandbox_id>\t<bind_addr>`
pub fn write_forward_pid(
    name: &str,
    port: u16,
    pid: u32,
    sandbox_id: &str,
    bind_addr: &str,
) -> Result<()> {
    let dir = forward_pid_dir()?;
    create_dir_restricted(&dir)?;
    let path = forward_pid_path(name, port)?;
    std::fs::write(&path, format!("{pid}\t{sandbox_id}\t{bind_addr}"))
        .into_diagnostic()
        .wrap_err("failed to write forward PID file")?;
    Ok(())
}

/// Find the PID of a backgrounded SSH forward by searching for the matching
/// SSH process.  Falls back to `pgrep` since SSH `-f` forks a new process
/// whose PID we cannot capture directly.
pub fn find_ssh_forward_pid(sandbox_id: &str, port: u16) -> Option<u32> {
    // Use pgrep only as a broad process source. The command line still needs a
    // second exact check before the PID can be tracked or signaled, otherwise a
    // requested port such as 80 can substring-match an existing 8080 forward.
    let pattern = "ssh-proxy";
    let output = Command::new("pgrep").arg("-f").arg(pattern).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // pgrep may return multiple PIDs; scan from newest to oldest and return
    // the first one that still passes the exact command-line validation.
    stdout
        .lines()
        .rev()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .find(|pid| pid_matches_openshell_ssh_forward(*pid, port, Some(sandbox_id)))
}

/// Record read from a forward PID file.
pub struct ForwardPidRecord {
    pub pid: u32,
    pub sandbox_id: Option<String>,
    /// Bind address from the PID file, or `None` for old-format files.
    pub bind_addr: Option<String>,
}

/// Read the PID from a forward PID file.  Returns `None` if the file does not
/// exist or cannot be parsed.
pub fn read_forward_pid(name: &str, port: u16) -> Option<ForwardPidRecord> {
    let path = forward_pid_path(name, port).ok()?;
    let contents = std::fs::read_to_string(path).ok()?;
    let mut parts = contents.split('\t');
    let pid = parts.next()?.trim().parse().ok()?;
    let sandbox_id = parts.next().map(str::to_string);
    let bind_addr = parts.next().map(|s| s.trim().to_string());
    Some(ForwardPidRecord {
        pid,
        sandbox_id,
        bind_addr,
    })
}

/// Check whether a process is alive.
pub fn pid_is_alive(pid: u32) -> bool {
    // `kill -0 <pid>` checks if we can signal the process without actually
    // sending a signal.
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Validate that a PID belongs to the expected `OpenShell` SSH forward.
pub fn pid_matches_openshell_ssh_forward(pid: u32, port: u16, sandbox_id: Option<&str>) -> bool {
    let Some(argv) = process_forward_match_tokens(pid) else {
        return false;
    };
    let tokens: Vec<&str> = argv.iter().map(String::as_str).collect();
    args_match_ssh_forward(&tokens, port, sandbox_id)
}

/// Read a process command line as matcher tokens.
///
/// Linux exposes exact argv from `/proc/<pid>/cmdline`; embedded
/// `ProxyCommand=` values are split so the matcher sees a flat token sequence.
#[cfg(target_os = "linux")]
fn process_forward_match_tokens(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let argv: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .flat_map(|segment| expand_proxy_command_arg(&String::from_utf8_lossy(segment)))
        .collect();
    (!argv.is_empty()).then_some(argv)
}

/// Non-Linux fallback. `ps` flattens argv, so paths with spaces fail closed.
#[cfg(not(target_os = "linux"))]
fn process_forward_match_tokens(pid: u32) -> Option<Vec<String>> {
    let output = Command::new("ps")
        .arg("-ww")
        .arg("-o")
        .arg("command=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&output.stdout);
    let argv: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
    (!argv.is_empty()).then_some(argv)
}

/// Expand a `ProxyCommand=<value>` element into matcher tokens.
#[cfg(any(target_os = "linux", test))]
fn expand_proxy_command_arg(arg: &str) -> Vec<String> {
    let Some(value) = arg.strip_prefix("ProxyCommand=") else {
        return vec![arg.to_string()];
    };
    let mut words = split_proxy_command_words(value);
    if words.is_empty() {
        return vec![arg.to_string()];
    }
    words[0] = format!("ProxyCommand={}", words[0]);
    words
}

/// Split shell words well enough to round-trip values emitted by [`shell_escape`].
#[cfg(any(target_os = "linux", test))]
fn split_proxy_command_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current: Option<String> = None;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if let Some(word) = current.take() {
                    words.push(word);
                }
            }
            '\'' => {
                let buf = current.get_or_insert_with(String::new);
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    buf.push(q);
                }
            }
            '"' => {
                let buf = current.get_or_insert_with(String::new);
                for q in chars.by_ref() {
                    if q == '"' {
                        break;
                    }
                    buf.push(q);
                }
            }
            other => current.get_or_insert_with(String::new).push(other),
        }
    }
    if let Some(word) = current.take() {
        words.push(word);
    }
    words
}

#[derive(Debug, Clone, Copy)]
struct ProxyCommandMatch {
    outer_ssh_args_start: usize,
    sandbox_id_requirement_met: bool,
    prefix_has_no_command: bool,
}

/// Match an `OpenShell` SSH forward by proxy ownership and outer SSH args.
fn args_match_ssh_forward(args: &[&str], port: u16, sandbox_id: Option<&str>) -> bool {
    if args.first().and_then(|arg| arg.rsplit('/').next()) != Some("ssh") {
        return false;
    }
    let Some(proxy) = find_proxy_command_match(args, sandbox_id) else {
        return false;
    };
    if sandbox_id.is_some() && !proxy.sandbox_id_requirement_met {
        return false;
    }
    outer_ssh_forward_matches(
        &args[proxy.outer_ssh_args_start..],
        port,
        proxy.prefix_has_no_command,
    )
}

/// Test-only wrapper for flat command lines.
#[cfg(test)]
fn command_matches_ssh_forward(command: &str, port: u16, sandbox_id: Option<&str>) -> bool {
    let args = command.split_whitespace().collect::<Vec<_>>();
    args_match_ssh_forward(&args, port, sandbox_id)
}

fn find_proxy_command_match(args: &[&str], sandbox_id: Option<&str>) -> Option<ProxyCommandMatch> {
    for (index, arg) in args.iter().enumerate().skip(1) {
        let Some(prefix_has_no_command) = parse_ssh_prefix_before_proxy(args, index) else {
            continue;
        };
        if !is_ssh_proxy_arg(arg) || !proxy_command_option_present(args, index) {
            continue;
        }

        let mut current = index + 1;
        let mut sandbox_id_requirement_met = sandbox_id.is_none();
        while current < args.len() {
            let arg = args[current];
            if is_outer_ssh_option_start(arg) || arg == "sandbox" {
                return Some(ProxyCommandMatch {
                    outer_ssh_args_start: current,
                    sandbox_id_requirement_met,
                    prefix_has_no_command,
                });
            }

            if let Some(value) = arg.strip_prefix("--sandbox-id=") {
                sandbox_id_requirement_met |= sandbox_id == Some(value);
                current += 1;
                continue;
            }
            if arg == "--sandbox-id" {
                let value = args.get(current + 1)?;
                sandbox_id_requirement_met |= sandbox_id == Some(*value);
                current += 2;
                continue;
            }
            if proxy_option_takes_value(arg) {
                current += 2;
                continue;
            }
            if proxy_option_has_inline_value(arg) {
                current += 1;
                continue;
            }

            return None;
        }
    }
    None
}

fn is_ssh_proxy_arg(arg: &str) -> bool {
    arg == "ssh-proxy" || arg.rsplit('/').next() == Some("ssh-proxy")
}

fn proxy_command_option_present(args: &[&str], proxy_index: usize) -> bool {
    args.iter()
        .take(proxy_index + 1)
        .any(|arg| arg.starts_with("ProxyCommand="))
}

fn proxy_option_takes_value(arg: &str) -> bool {
    matches!(arg, "--gateway" | "--token" | "--gateway-name")
}

fn proxy_option_has_inline_value(arg: &str) -> bool {
    ["--gateway=", "--token=", "--gateway-name="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn is_outer_ssh_option_start(arg: &str) -> bool {
    matches!(arg, "-N" | "-f" | "-o" | "-L" | "-T" | "-tt")
        || arg.starts_with("-L")
        || arg.starts_with("-o")
        || arg.starts_with("-v")
}

fn parse_ssh_prefix_before_proxy(args: &[&str], proxy_index: usize) -> Option<bool> {
    let mut current = 1;
    let mut saw_no_command = false;
    while current < proxy_index {
        let arg = args[current];
        if arg == "-o" {
            current += 2;
            continue;
        }
        if arg == "-N" {
            saw_no_command = true;
            current += 1;
            continue;
        }
        if arg.starts_with("-o") || matches!(arg, "-f" | "-T" | "-tt") {
            current += 1;
            continue;
        }
        if arg.starts_with("-v") {
            current += 1;
            continue;
        }
        return None;
    }
    Some(saw_no_command)
}

fn outer_ssh_forward_matches(args: &[&str], port: u16, prefix_has_no_command: bool) -> bool {
    let Some(forward_args) = args.strip_suffix(&["sandbox"]) else {
        return false;
    };
    let mut saw_no_command = prefix_has_no_command;
    let mut saw_forward = false;
    let mut current = 0;

    while current < forward_args.len() {
        let arg = forward_args[current];
        match arg {
            "-N" => {
                saw_no_command = true;
                current += 1;
            }
            "-f" | "-T" | "-tt" => {
                current += 1;
            }
            "-o" => {
                if current + 1 >= forward_args.len() {
                    return false;
                }
                current += 2;
            }
            "-L" => {
                let Some(candidate) = forward_args.get(current + 1) else {
                    return false;
                };
                saw_forward |= ssh_forward_arg_matches_openshell_loopback_port(candidate, port);
                current += 2;
            }
            _ if arg.starts_with("-L") => {
                let Some(candidate) = arg.strip_prefix("-L").filter(|value| !value.is_empty())
                else {
                    return false;
                };
                saw_forward |= ssh_forward_arg_matches_openshell_loopback_port(candidate, port);
                current += 1;
            }
            _ if arg.starts_with("-o") || arg.starts_with("-v") => {
                current += 1;
            }
            _ => return false,
        }
    }

    saw_no_command && saw_forward
}

fn expected_sandbox_id_from_record(record: &ForwardPidRecord) -> Option<&str> {
    // Legacy one-field PID files are cleanup records, not signal authority.
    record.sandbox_id.as_deref().filter(|id| !id.is_empty())
}

fn ssh_forward_arg_matches_openshell_loopback_port(arg: &str, port: u16) -> bool {
    let unbound = format!("{port}:127.0.0.1:{port}");
    let bind_prefixed_suffix = format!(":{unbound}");
    arg == unbound || arg.ends_with(&bind_prefixed_suffix)
}

/// Find the live, validated forward owner for a local port.
pub fn find_forward_by_port(port: u16) -> Result<Option<String>> {
    Ok(list_forwards()?
        .into_iter()
        .find(|forward| forward.port == port && forward.validated_alive)
        .map(|forward| forward.sandbox_name))
}

/// Stop a background port forward.
pub fn stop_forward(name: &str, port: u16) -> Result<bool> {
    let pid_path = forward_pid_path(name, port)?;
    let Some(record) = read_forward_pid(name, port) else {
        return Ok(false);
    };
    let pid = record.pid;
    let Some(sandbox_id) = expected_sandbox_id_from_record(&record) else {
        // Legacy PID records do not prove process ownership.
        let _ = std::fs::remove_file(&pid_path);
        return Ok(false);
    };

    if pid_is_alive(pid) {
        if !pid_matches_openshell_ssh_forward(pid, port, Some(sandbox_id)) {
            let _ = std::fs::remove_file(&pid_path);
            return Ok(false);
        }
        let _ = Command::new("kill")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        // Give the process a moment to exit.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let _ = std::fs::remove_file(&pid_path);
    Ok(true)
}

/// Stop all forwards for a given sandbox name.
pub fn stop_forwards_for_sandbox(name: &str) -> Result<Vec<u16>> {
    let Ok(dir) = forward_pid_dir() else {
        return Ok(Vec::new());
    };
    let prefix = format!("{name}-");
    let mut stopped = Vec::new();

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if let Some(rest) = file_name.strip_prefix(&prefix)
            && let Some(port_str) = rest.strip_suffix(".pid")
            && let Ok(port) = port_str.parse::<u16>()
            && stop_forward(name, port)?
        {
            stopped.push(port);
        }
    }

    Ok(stopped)
}

/// Information about a tracked forward.
pub struct ForwardInfo {
    /// User-facing sandbox name from the PID file path.
    pub sandbox_name: String,
    /// Local port bound by the SSH forward.
    pub port: u16,
    /// PID recorded for the background SSH process.
    pub pid: u32,
    /// PID is alive and validates as this `OpenShell` forward.
    pub validated_alive: bool,
    /// Bind address (defaults to `127.0.0.1` for old PID files).
    pub bind_addr: String,
}

/// List all tracked forwards.
pub fn list_forwards() -> Result<Vec<ForwardInfo>> {
    let Ok(dir) = forward_pid_dir() else {
        return Ok(Vec::new());
    };

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };

    let mut forwards = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy().to_string();
        if let Some(stem) = file_name.strip_suffix(".pid")
            // Parse "<sandbox>-<port>" — the port is the last segment after '-'.
            && let Some(dash_pos) = stem.rfind('-')
            && let Ok(port) = stem[dash_pos + 1..].parse::<u16>()
            && let Some(record) = read_forward_pid(&stem[..dash_pos], port)
        {
            // Revalidate ownership so PID reuse does not look like a live forward.
            let validated_alive =
                expected_sandbox_id_from_record(&record).is_some_and(|sandbox_id| {
                    pid_is_alive(record.pid)
                        && pid_matches_openshell_ssh_forward(record.pid, port, Some(sandbox_id))
                });
            forwards.push(ForwardInfo {
                sandbox_name: stem[..dash_pos].to_string(),
                port,
                pid: record.pid,
                validated_alive,
                bind_addr: record
                    .bind_addr
                    .unwrap_or_else(|| ForwardSpec::DEFAULT_BIND_ADDR.to_string()),
            });
        }
    }

    forwards.sort_by(|a, b| {
        a.sandbox_name
            .cmp(&b.sandbox_name)
            .then(a.port.cmp(&b.port))
    });
    Ok(forwards)
}

// ---------------------------------------------------------------------------
// Forward spec parsing
// ---------------------------------------------------------------------------

/// A parsed port-forward specification: optional bind address + port.
///
/// Supports the same `[bind_address:]port` syntax as SSH `-L`.  When no bind
/// address is given, defaults to `127.0.0.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    pub bind_addr: String,
    pub port: u16,
}

impl ForwardSpec {
    /// Default bind address when none is specified.
    pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1";

    /// Create a new `ForwardSpec` with the default bind address.
    pub fn new(port: u16) -> Self {
        Self {
            bind_addr: Self::DEFAULT_BIND_ADDR.to_string(),
            port,
        }
    }

    /// Parse a `[bind_address:]port` string.
    ///
    /// Examples:
    /// - `"8080"` → `ForwardSpec { bind_addr: "127.0.0.1", port: 8080 }`
    /// - `"0.0.0.0:8080"` → `ForwardSpec { bind_addr: "0.0.0.0", port: 8080 }`
    /// - `"::1:8080"` → `ForwardSpec { bind_addr: "::1", port: 8080 }`
    pub fn parse(s: &str) -> Result<Self> {
        // Split on the last ':' to handle IPv6 addresses like "::1:8080".
        if let Some(pos) = s.rfind(':') {
            let addr = &s[..pos];
            let port_str = &s[pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                if port == 0 {
                    return Err(miette::miette!("port must be between 1 and 65535"));
                }
                return Ok(Self {
                    bind_addr: addr.to_string(),
                    port,
                });
            }
        }

        // No colon or the part after the last colon isn't a valid port —
        // treat the entire string as a port number.
        let port: u16 = s.parse().map_err(|_| {
            miette::miette!("invalid forward spec '{s}': expected [bind_address:]port")
        })?;
        if port == 0 {
            return Err(miette::miette!("port must be between 1 and 65535"));
        }
        Ok(Self::new(port))
    }

    /// The SSH `-L` local-forward argument: `bind_addr:port:127.0.0.1:port`.
    pub fn ssh_forward_arg(&self) -> String {
        format!("{}:{}:127.0.0.1:{}", self.bind_addr, self.port, self.port)
    }

    /// A human-readable URL for the forwarded port.
    pub fn access_url(&self) -> String {
        let host = if self.bind_addr == "0.0.0.0" || self.bind_addr == "::" {
            "localhost"
        } else {
            &self.bind_addr
        };
        format!("http://{host}:{}/", self.port)
    }
}

impl std::fmt::Display for ForwardSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.bind_addr == Self::DEFAULT_BIND_ADDR {
            write!(f, "{}", self.port)
        } else {
            write!(f, "{}:{}", self.bind_addr, self.port)
        }
    }
}

// ---------------------------------------------------------------------------
// Port availability check
// ---------------------------------------------------------------------------

/// Check whether a local port is available for forwarding.
///
/// Uses a two-pronged check:
/// 1. Attempts to bind `<bind_addr>:<port>` — catches same-family conflicts.
/// 2. Runs `lsof -i :<port> -sTCP:LISTEN` — catches cross-family conflicts
///    (e.g. an IPv6 wildcard listener blocking a port the IPv4 bind test
///    would miss).
///
/// If the port is already in use the error message includes an actionable
/// hint:
///
/// - If an existing openshell forward owns the port, suggest the stop command.
/// - Otherwise, show the `lsof` output and suggest `kill` to terminate the
///   owning process.
pub fn check_port_available(spec: &ForwardSpec) -> Result<()> {
    let port = spec.port;

    // Fast path: try binding on the requested address.  If this fails, the
    // port is definitely taken on this address family.
    let bind_ok = TcpListener::bind((spec.bind_addr.as_str(), port)).is_ok();

    // Also ask the OS whether *any* process is listening on this port,
    // regardless of address family.  This catches situations where e.g. a
    // server binds [::]:8080 but our IPv4 bind test succeeds.
    let lsof_output = lsof_listeners(port);
    let lsof_occupied = lsof_output.is_some();

    if bind_ok && !lsof_occupied {
        return Ok(());
    }

    // Port is occupied.  Check if it belongs to a tracked openshell forward.
    if let Ok(forwards) = list_forwards()
        && let Some(fwd) = forwards
            .iter()
            .find(|f| f.port == port && f.validated_alive)
    {
        return Err(miette::miette!(
            "Port {port} is already forwarded to sandbox '{}'.\n\
             Stop it with: openshell forward stop {port} {}",
            fwd.sandbox_name,
            fwd.sandbox_name,
        ));
    }

    // Build a helpful error with lsof details when available.
    if let Some(output) = lsof_output {
        return Err(miette::miette!(
            "Port {port} is already in use by another process.\n\n\
             {output}\n\n\
             To free the port, find the PID above and run:\n  \
             kill <PID>\n\n\
             Or find it yourself with:\n  \
             lsof -i :{port} -sTCP:LISTEN",
        ));
    }

    Err(miette::miette!(
        "Port {port} is already in use by another process.\n\
         Find it with: lsof -i :{port} -sTCP:LISTEN\n\
         Then terminate it with: kill <PID>",
    ))
}

/// Run `lsof` to check for any process listening on `port`.
///
/// Returns the trimmed stdout if at least one listener is found, or `None` if
/// the port is free (or `lsof` is unavailable).
fn lsof_listeners(port: u16) -> Option<String> {
    let output = Command::new("lsof")
        .arg("-i")
        .arg(format!(":{port}"))
        .arg("-sTCP:LISTEN")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

// ---------------------------------------------------------------------------
// SSH utility functions (shared between CLI and TUI)
// ---------------------------------------------------------------------------

/// Resolve the SSH gateway host and port for a sandbox connection.
///
/// If the server-provided gateway host is a loopback address, use the host
/// and port from the cluster endpoint instead so the client connects to the
/// right machine. The server returns its internal bind address (e.g. 0.0.0.0:8080)
/// which may not be reachable from outside — the cluster URL has the actual
/// Docker-mapped or tunnel port.
pub fn resolve_ssh_gateway(
    gateway_host: &str,
    gateway_port: u16,
    cluster_url: &str,
) -> (String, u16) {
    let is_loopback = gateway_host == "127.0.0.1"
        || gateway_host == "0.0.0.0"
        || gateway_host == "localhost"
        || gateway_host == "::1";

    if !is_loopback {
        return (gateway_host.to_string(), gateway_port);
    }

    // Extract host and port from the cluster URL. The cluster URL represents
    // the externally reachable endpoint (e.g. Docker port-mapped address).
    if let Ok(url) = url::Url::parse(cluster_url)
        && let Some(host) = url.host_str()
    {
        let cluster_port = url.port_or_known_default().unwrap_or(gateway_port);
        let cluster_is_loopback =
            host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost" || host == "::1";
        if !cluster_is_loopback {
            // Remote cluster: use the remote host but keep the cluster URL port.
            return (host.to_string(), cluster_port);
        }
        // Both endpoints loopback. The unspecified addresses (0.0.0.0 / ::)
        // are bind-only — they aren't valid connect targets and aren't in TLS
        // cert SANs, so fall back to the cluster URL's host (which the CLI
        // is already using to reach the gateway).
        if gateway_host == "0.0.0.0" || gateway_host == "::" {
            return (host.to_string(), cluster_port);
        }
        return (gateway_host.to_string(), cluster_port);
    }

    (gateway_host.to_string(), gateway_port)
}

/// Format a gateway URL, bracketing IPv6 literals when needed.
pub fn format_gateway_url(scheme: &str, host: &str, port: u16) -> String {
    let host = if host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_ipv6())
        && !host.starts_with('[')
    {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("{scheme}://{host}:{port}")
}

/// Shell-escape a value for use inside a `ProxyCommand` string.
pub fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let safe = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'));
    if safe {
        return value.to_string();
    }

    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

/// Build the SSH `ProxyCommand` string used to tunnel to a sandbox.
///
/// Every interpolated argument is shell-escaped so that server-supplied values
/// (gateway URL, sandbox id, token, gateway name) cannot inject shell
/// metacharacters into the command that OpenSSH executes via `/bin/sh -c`.
pub fn build_proxy_command(
    exe: &str,
    gateway_url: &str,
    sandbox_id: &str,
    token: &str,
    gateway_name: &str,
) -> String {
    format!(
        "{} ssh-proxy --gateway {} --sandbox-id {} --token {} --gateway-name {}",
        shell_escape(exe),
        shell_escape(gateway_url),
        shell_escape(sandbox_id),
        shell_escape(token),
        shell_escape(gateway_name),
    )
}

/// Error returned when a `CreateSshSessionResponse` fails validation.
///
/// The response fields flow into a `ProxyCommand` string executed by
/// `/bin/sh -c`; any deviation from the documented charset is rejected at the
/// gRPC trust boundary before escaping is attempted.
#[derive(Debug, thiserror::Error)]
pub enum SshSessionResponseError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds maximum length of {max} bytes")]
    TooLong { field: &'static str, max: usize },
    #[error("{field} contains invalid characters")]
    InvalidChars { field: &'static str },
    #[error("gateway_scheme must be 'http' or 'https'")]
    InvalidScheme,
    #[error("gateway_port must be in range 1..=65535")]
    InvalidPort,
}

const MAX_SANDBOX_ID_LEN: usize = 128;
const MAX_TOKEN_LEN: usize = 4096;
const MAX_GATEWAY_HOST_LEN: usize = 253;
const MAX_FINGERPRINT_LEN: usize = 256;

fn is_sandbox_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
}

fn is_token_byte(b: u8) -> bool {
    // URL-safe base64 + common token charset. No shell metacharacters, no
    // whitespace, no control bytes.
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~' | b'+' | b'/' | b'=')
}

fn is_gateway_host_byte(b: u8) -> bool {
    // DNS hostname (alphanumeric + `.-`), IPv4, or bracketed IPv6 (`[::1]`).
    // Rejects Unicode — callers must Punycode-encode IDN hosts before emitting.
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
}

fn is_fingerprint_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b':' | b'+' | b'/' | b'=' | b'-')
}

/// Validate a `CreateSshSessionResponse` before any of its fields are used to
/// build a shell command or config file.
///
/// This is a belt-and-suspenders pair to [`build_proxy_command`]: escaping
/// alone is sufficient to prevent injection, but rejecting malformed fields
/// at the trust boundary fails loudly before the string is assembled and
/// catches gateway bugs or tampering early.
pub fn validate_ssh_session_response(
    resp: &crate::proto::CreateSshSessionResponse,
) -> std::result::Result<(), SshSessionResponseError> {
    validate_field(
        "sandbox_id",
        &resp.sandbox_id,
        MAX_SANDBOX_ID_LEN,
        is_sandbox_id_byte,
    )?;
    validate_field("token", &resp.token, MAX_TOKEN_LEN, is_token_byte)?;
    validate_field(
        "gateway_host",
        &resp.gateway_host,
        MAX_GATEWAY_HOST_LEN,
        is_gateway_host_byte,
    )?;
    match resp.gateway_scheme.as_str() {
        "http" | "https" => {}
        _ => return Err(SshSessionResponseError::InvalidScheme),
    }
    if resp.gateway_port == 0 || resp.gateway_port > u32::from(u16::MAX) {
        return Err(SshSessionResponseError::InvalidPort);
    }
    if !resp.host_key_fingerprint.is_empty() {
        if resp.host_key_fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err(SshSessionResponseError::TooLong {
                field: "host_key_fingerprint",
                max: MAX_FINGERPRINT_LEN,
            });
        }
        if !resp.host_key_fingerprint.bytes().all(is_fingerprint_byte) {
            return Err(SshSessionResponseError::InvalidChars {
                field: "host_key_fingerprint",
            });
        }
    }
    Ok(())
}

fn validate_field(
    name: &'static str,
    value: &str,
    max_len: usize,
    byte_ok: fn(u8) -> bool,
) -> std::result::Result<(), SshSessionResponseError> {
    if value.is_empty() {
        return Err(SshSessionResponseError::Empty { field: name });
    }
    if value.len() > max_len {
        return Err(SshSessionResponseError::TooLong {
            field: name,
            max: max_len,
        });
    }
    if !value.bytes().all(byte_ok) {
        return Err(SshSessionResponseError::InvalidChars { field: name });
    }
    Ok(())
}

/// Build notes string for a sandbox based on active forwards.
///
/// Returns a string like `fwd:8080,3000` or an empty string if no forwards
/// are active for the given sandbox.
pub fn build_sandbox_notes(sandbox_name: &str, forwards: &[ForwardInfo]) -> String {
    let ports: Vec<String> = forwards
        .iter()
        .filter(|f| f.sandbox_name == sandbox_name && f.validated_alive)
        .map(|f| f.port.to_string())
        .collect();
    if ports.is_empty() {
        String::new()
    } else {
        format!("fwd:{}", ports.join(","))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        #[allow(unsafe_code)] // Tests serialize process-wide environment changes with ENV_LOCK.
        fn set_path(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    #[allow(unsafe_code)] // Tests serialize process-wide environment changes with ENV_LOCK.
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn resolve_ssh_gateway_keeps_non_loopback() {
        let (host, port) = resolve_ssh_gateway("10.0.0.5", 8080, "https://spark.local");
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_loopback_with_cluster_host() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "https://spark.local");
        assert_eq!(host, "spark.local");
        assert_eq!(port, 443);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_zeros_with_cluster_host() {
        let (host, port) = resolve_ssh_gateway("0.0.0.0", 8080, "https://10.0.0.5:443");
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 443);
    }

    #[test]
    fn resolve_ssh_gateway_uses_known_default_http_port() {
        let (host, port) = resolve_ssh_gateway("0.0.0.0", 8080, "http://gateway.example.test");
        assert_eq!(host, "gateway.example.test");
        assert_eq!(port, 80);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_localhost() {
        let (host, port) = resolve_ssh_gateway("localhost", 8080, "https://remote-host:443");
        assert_eq!(host, "remote-host");
        assert_eq!(port, 443);
    }

    #[test]
    fn resolve_ssh_gateway_no_override_when_cluster_is_also_loopback() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "https://127.0.0.1:443");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn resolve_ssh_gateway_swaps_zeros_for_loopback_cluster_host() {
        // The gateway binds 0.0.0.0 but advertises that bind address via the
        // SSH session response. 0.0.0.0 is not a valid connect target and is
        // not in any TLS cert SAN; fall through to the cluster URL's host.
        let (host, port) = resolve_ssh_gateway("0.0.0.0", 8080, "https://127.0.0.1:9000");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9000);
    }

    #[test]
    fn resolve_ssh_gateway_handles_invalid_cluster_url() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "not-a-url");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn format_gateway_url_brackets_ipv6_literals() {
        assert_eq!(
            format_gateway_url("https", "::1", 8080),
            "https://[::1]:8080"
        );
    }

    #[test]
    fn format_gateway_url_leaves_dns_and_bracketed_ipv6_unchanged() {
        assert_eq!(
            format_gateway_url("https", "gateway.example.com", 443),
            "https://gateway.example.com:443"
        );
        assert_eq!(
            format_gateway_url("https", "[::1]", 8080),
            "https://[::1]:8080"
        );
    }

    #[test]
    fn shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn shell_escape_safe_chars() {
        assert_eq!(shell_escape("hello-world/foo.bar"), "hello-world/foo.bar");
    }

    #[test]
    fn shell_escape_special_chars() {
        assert_eq!(shell_escape("it's"), "'it'\"'\"'s'");
    }

    fn valid_session_response() -> crate::proto::CreateSshSessionResponse {
        crate::proto::CreateSshSessionResponse {
            sandbox_id: "sb-1234".to_string(),
            token: "abcDEF-123_456.789".to_string(),
            gateway_scheme: "https".to_string(),
            gateway_host: "gateway.example.com".to_string(),
            gateway_port: 443,
            host_key_fingerprint: String::new(),
            expires_at_ms: 0,
        }
    }

    #[test]
    fn validate_ssh_session_response_accepts_realistic_response() {
        assert!(validate_ssh_session_response(&valid_session_response()).is_ok());
    }

    #[test]
    fn validate_ssh_session_response_accepts_bracketed_ipv6_host() {
        let mut r = valid_session_response();
        r.gateway_host = "[::1]".to_string();
        assert!(validate_ssh_session_response(&r).is_ok());
    }

    #[test]
    fn validate_ssh_session_response_accepts_optional_fingerprint() {
        let mut r = valid_session_response();
        r.host_key_fingerprint = "SHA256:abcd+/=".to_string();
        assert!(validate_ssh_session_response(&r).is_ok());
    }

    #[test]
    fn validate_ssh_session_response_rejects_empty_sandbox_id() {
        let mut r = valid_session_response();
        r.sandbox_id.clear();
        assert!(matches!(
            validate_ssh_session_response(&r),
            Err(SshSessionResponseError::Empty {
                field: "sandbox_id"
            })
        ));
    }

    #[test]
    fn validate_ssh_session_response_rejects_shell_metachars_in_sandbox_id() {
        for bad in ["a;b", "a b", "a$(id)", "a`id`", "a|b", "a&b", "a\nb"] {
            let mut r = valid_session_response();
            r.sandbox_id = bad.to_string();
            assert!(
                validate_ssh_session_response(&r).is_err(),
                "expected reject for sandbox_id={bad:?}"
            );
        }
    }

    #[test]
    fn validate_ssh_session_response_rejects_shell_metachars_in_token() {
        for bad in ["$(id)", "`id`", "a;b", "a b", "a\tb", "a\0b"] {
            let mut r = valid_session_response();
            r.token = bad.to_string();
            assert!(
                validate_ssh_session_response(&r).is_err(),
                "expected reject for token={bad:?}"
            );
        }
    }

    #[test]
    fn validate_ssh_session_response_rejects_invalid_gateway_host() {
        for bad in ["evil; cmd", "evil host", "ev$(id)il", "ev\nil", "evil/x"] {
            let mut r = valid_session_response();
            r.gateway_host = bad.to_string();
            assert!(
                validate_ssh_session_response(&r).is_err(),
                "expected reject for gateway_host={bad:?}"
            );
        }
    }

    #[test]
    fn validate_ssh_session_response_rejects_unknown_scheme() {
        for bad in ["javascript", "file", "", "HTTPS", "ftp"] {
            let mut r = valid_session_response();
            r.gateway_scheme = bad.to_string();
            assert!(
                matches!(
                    validate_ssh_session_response(&r),
                    Err(SshSessionResponseError::InvalidScheme)
                ),
                "expected InvalidScheme for scheme={bad:?}"
            );
        }
    }

    #[test]
    fn validate_ssh_session_response_rejects_out_of_range_port() {
        for bad in [0u32, 65_536, 100_000] {
            let mut r = valid_session_response();
            r.gateway_port = bad;
            assert!(matches!(
                validate_ssh_session_response(&r),
                Err(SshSessionResponseError::InvalidPort)
            ));
        }
    }

    #[test]
    fn build_proxy_command_escapes_shell_metacharacters() {
        // Attacker-controlled values in every escapable position.
        let cmd = build_proxy_command(
            "/usr/local/bin/openshell",
            "https://gw:443/connect",
            "x$(touch /tmp/pwn)x",
            "tok`id`",
            "gw-name",
        );

        // The `$` / backtick must only appear inside single-quoted regions.
        // A simple grep-based check: split on single-quoted runs and assert
        // no shell metacharacter remains in the unquoted remainder.
        assert!(!outside_single_quotes(&cmd).contains('$'));
        assert!(!outside_single_quotes(&cmd).contains('`'));
        assert!(!outside_single_quotes(&cmd).contains('|'));
        assert!(!outside_single_quotes(&cmd).contains(';'));
        assert!(!outside_single_quotes(&cmd).contains('&'));
        assert!(!outside_single_quotes(&cmd).contains('\n'));
    }

    #[test]
    fn build_proxy_command_empty_values_quote_rather_than_vanish() {
        // An empty value must become `''` rather than disappearing — otherwise
        // downstream argv splitting would misalign.
        let cmd = build_proxy_command("exe", "gw", "", "tok", "name");
        assert!(cmd.contains("--sandbox-id ''"));
    }

    #[test]
    fn build_proxy_command_safe_values_pass_through_unquoted() {
        let cmd = build_proxy_command(
            "/usr/local/bin/openshell",
            "gw",
            "sb-123",
            "tok.456",
            "name_1",
        );
        assert_eq!(
            cmd,
            "/usr/local/bin/openshell ssh-proxy --gateway gw --sandbox-id sb-123 --token tok.456 --gateway-name name_1"
        );
    }

    /// Helper: return the concatenation of characters that appear outside
    /// POSIX single-quoted runs. Used by the metacharacter assertions above.
    fn outside_single_quotes(s: &str) -> String {
        let mut out = String::new();
        let mut inside = false;
        for c in s.chars() {
            if c == '\'' {
                inside = !inside;
                continue;
            }
            if !inside {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn build_sandbox_notes_with_forwards() {
        let forwards = vec![
            ForwardInfo {
                sandbox_name: "mybox".to_string(),
                port: 8080,
                pid: 123,
                validated_alive: true,
                bind_addr: "127.0.0.1".to_string(),
            },
            ForwardInfo {
                sandbox_name: "mybox".to_string(),
                port: 3000,
                pid: 456,
                validated_alive: true,
                bind_addr: "127.0.0.1".to_string(),
            },
            ForwardInfo {
                sandbox_name: "other".to_string(),
                port: 9090,
                pid: 789,
                validated_alive: true,
                bind_addr: "0.0.0.0".to_string(),
            },
        ];
        assert_eq!(build_sandbox_notes("mybox", &forwards), "fwd:8080,3000");
        assert_eq!(build_sandbox_notes("other", &forwards), "fwd:9090");
        assert_eq!(build_sandbox_notes("missing", &forwards), "");
    }

    #[test]
    fn build_sandbox_notes_dead_forwards_excluded() {
        let forwards = vec![ForwardInfo {
            sandbox_name: "mybox".to_string(),
            port: 8080,
            pid: 123,
            validated_alive: false,
            bind_addr: "127.0.0.1".to_string(),
        }];
        assert_eq!(build_sandbox_notes("mybox", &forwards), "");
    }

    #[test]
    fn port_parsing_comma_separated() {
        let input = "8080,3000, 443";
        let ports: Vec<u16> = input
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();
        assert_eq!(ports, vec![8080, 3000, 443]);
    }

    #[test]
    fn port_parsing_empty_string() {
        let input = "";
        let has_ports = input.split(',').any(|s| s.trim().parse::<u16>().is_ok());
        assert!(!has_ports);
    }

    #[test]
    fn port_parsing_invalid_mixed() {
        let input = "8080,abc,3000,0,99999";
        let ports: Vec<u16> = input
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();
        // 0 is valid u16 but we may want to filter it; 99999 overflows u16.
        assert_eq!(ports, vec![8080, 3000, 0]);
    }

    #[test]
    fn check_port_available_free_port() {
        // Bind to port 0 to get an OS-assigned free port, then drop the
        // listener so the port is released before we test it. On busy CI
        // hosts, another process can claim that single ephemeral port before
        // we re-bind it, so retry with fresh OS-assigned ports.
        let mut last_error = None;
        for _ in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);

            match check_port_available(&ForwardSpec::new(port)) {
                Ok(()) => return,
                Err(err) => {
                    last_error = Some(err.to_string());
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }

        panic!(
            "expected an OS-assigned port to be available; last error: {}",
            last_error.unwrap_or_else(|| "none".to_string())
        );
    }

    #[test]
    fn check_port_available_occupied_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Keep the listener alive so the port stays occupied.

        let result = check_port_available(&ForwardSpec::new(port));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("already in use"),
            "expected 'already in use' in error message, got: {msg}"
        );
    }

    #[test]
    fn check_port_available_occupied_ipv6_wildcard() {
        // Bind on [::]:0 (IPv6 wildcard) — this simulates a server like
        // `python3 -m http.server` which listens on [::] by default.  The
        // IPv4-only TcpListener::bind("127.0.0.1", port) might succeed, but
        // lsof should detect the listener and the check should still fail.
        let Ok(listener) = TcpListener::bind("[::]:0") else {
            return; // IPv6 not available, skip
        };
        let port = listener.local_addr().unwrap().port();

        let result = check_port_available(&ForwardSpec::new(port));
        assert!(
            result.is_err(),
            "expected error for IPv6-occupied port {port}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("already in use"),
            "expected 'already in use' in error message, got: {msg}"
        );
    }

    #[test]
    fn forward_spec_parse_port_only() {
        let spec = ForwardSpec::parse("8080").unwrap();
        assert_eq!(spec.bind_addr, "127.0.0.1");
        assert_eq!(spec.port, 8080);
    }

    #[test]
    fn forward_spec_parse_ipv4_and_port() {
        let spec = ForwardSpec::parse("0.0.0.0:8080").unwrap();
        assert_eq!(spec.bind_addr, "0.0.0.0");
        assert_eq!(spec.port, 8080);
    }

    #[test]
    fn forward_spec_parse_ipv6_and_port() {
        let spec = ForwardSpec::parse("::1:8080").unwrap();
        assert_eq!(spec.bind_addr, "::1");
        assert_eq!(spec.port, 8080);
    }

    #[test]
    fn forward_spec_parse_localhost_and_port() {
        let spec = ForwardSpec::parse("localhost:3000").unwrap();
        assert_eq!(spec.bind_addr, "localhost");
        assert_eq!(spec.port, 3000);
    }

    #[test]
    fn forward_spec_parse_rejects_zero_port() {
        assert!(ForwardSpec::parse("0").is_err());
        assert!(ForwardSpec::parse("0.0.0.0:0").is_err());
    }

    #[test]
    fn forward_spec_parse_rejects_invalid() {
        assert!(ForwardSpec::parse("abc").is_err());
        assert!(ForwardSpec::parse("").is_err());
    }

    #[test]
    fn forward_spec_ssh_forward_arg() {
        let spec = ForwardSpec::parse("0.0.0.0:8080").unwrap();
        assert_eq!(spec.ssh_forward_arg(), "0.0.0.0:8080:127.0.0.1:8080");

        let spec = ForwardSpec::parse("8080").unwrap();
        assert_eq!(spec.ssh_forward_arg(), "127.0.0.1:8080:127.0.0.1:8080");
    }

    #[test]
    fn ssh_forward_command_matches_exact_l_argument() {
        let command = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L 80:127.0.0.1:80 sandbox";
        let compact = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L80:127.0.0.1:80 sandbox";

        assert!(command_matches_ssh_forward(command, 80, Some("sbx-1")));
        assert!(command_matches_ssh_forward(compact, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_matches_bind_prefixed_l_argument() {
        let command = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L 127.0.0.1:80:127.0.0.1:80 sandbox";
        let compact = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L[::1]:80:127.0.0.1:80 sandbox";

        assert!(command_matches_ssh_forward(command, 80, Some("sbx-1")));
        assert!(command_matches_ssh_forward(compact, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_rejects_substring_port_collision() {
        let command = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L 127.0.0.1:8080:127.0.0.1:8080 sandbox";

        assert!(!command_matches_ssh_forward(command, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_requires_matching_sandbox_id() {
        let command = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-2 -N -L 80:127.0.0.1:80 sandbox";
        let equals = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id=sbx-1 -N -L 80:127.0.0.1:80 sandbox";

        assert!(!command_matches_ssh_forward(command, 80, Some("sbx-1")));
        assert!(command_matches_ssh_forward(equals, 80, Some("sbx-1")));
        assert!(command_matches_ssh_forward(command, 80, None));
    }

    #[test]
    fn ssh_forward_command_rejects_sandbox_id_prefix_collision() {
        let split = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-10 -N -L 80:127.0.0.1:80 sandbox";
        let equals = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id=sbx-10 -N -L 80:127.0.0.1:80 sandbox";

        assert!(!command_matches_ssh_forward(split, 80, Some("sbx-1")));
        assert!(!command_matches_ssh_forward(equals, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_rejects_host_port_ambiguity() {
        let wrong_remote_port = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L 80:127.0.0.1:8080 sandbox";
        let wrong_local_port = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L 127.0.0.1:8080:127.0.0.1:80 sandbox";
        let wrong_remote_host = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N -L 80:localhost:80 sandbox";

        assert!(!command_matches_ssh_forward(
            wrong_remote_port,
            80,
            Some("sbx-1")
        ));
        assert!(!command_matches_ssh_forward(
            wrong_local_port,
            80,
            Some("sbx-1")
        ));
        assert!(!command_matches_ssh_forward(
            wrong_remote_host,
            80,
            Some("sbx-1")
        ));
    }

    #[test]
    fn ssh_forward_command_matches_path_basenames_and_bind_variants() {
        let command = "/usr/bin/ssh -o ProxyCommand=/usr/local/bin/ssh-proxy --sandbox-id=sbx-1 -N -L localhost:80:127.0.0.1:80 sandbox";

        assert!(command_matches_ssh_forward(command, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_matches_generated_forward_shape() {
        let command = "/usr/bin/ssh -N -o ProxyCommand=/path/openshell ssh-proxy --gateway https://127.0.0.1:9443 --sandbox-id sbx-1 --token tok_123 --gateway-name local -o ExitOnForwardFailure=yes -L 127.0.0.1:80:127.0.0.1:80 -f sandbox";

        assert!(command_matches_ssh_forward(command, 80, Some("sbx-1")));
    }

    #[test]
    fn split_proxy_command_words_round_trips_shell_escape() {
        assert_eq!(split_proxy_command_words("a b c"), vec!["a", "b", "c"]);
        // A quoted executable path with whitespace stays a single word.
        assert_eq!(
            split_proxy_command_words("'/Application Support/openshell' ssh-proxy"),
            vec!["/Application Support/openshell", "ssh-proxy"]
        );
        // The `'\"'\"'` idiom shell_escape emits for an embedded single quote.
        assert_eq!(split_proxy_command_words("'it'\"'\"'s'"), vec!["it's"]);
        // An explicitly empty argument survives as an empty word.
        assert_eq!(split_proxy_command_words("''"), vec![String::new()]);
    }

    #[test]
    fn expand_proxy_command_arg_splits_value_and_keeps_prefix() {
        let exe = "/Application Support/openshell";
        let arg = format!(
            "ProxyCommand={} ssh-proxy --sandbox-id sbx-1",
            shell_escape(exe)
        );
        assert_eq!(
            expand_proxy_command_arg(&arg),
            vec![
                format!("ProxyCommand={exe}"),
                "ssh-proxy".to_string(),
                "--sandbox-id".to_string(),
                "sbx-1".to_string(),
            ]
        );
        // Non-proxy arguments pass through untouched.
        assert_eq!(expand_proxy_command_arg("-N"), vec!["-N".to_string()]);
    }

    #[test]
    fn args_match_ssh_forward_handles_expanded_proxy_command_with_whitespace_in_exe_path() {
        // Exact argv as recovered from /proc/<pid>/cmdline: the ProxyCommand
        // value is one element whose executable path contains spaces. The flat
        // `ps` parse cannot represent this, but the exact-argv path expands the
        // ProxyCommand element and matches correctly.
        let exe = "/Application Support/openshell";
        let proxy_arg = format!(
            "ProxyCommand={} ssh-proxy --gateway https://127.0.0.1:9443 --sandbox-id sbx-1 --token tok_123 --gateway-name local",
            shell_escape(exe)
        );
        // Mirror process_forward_match_tokens: the ProxyCommand element is expanded.
        let mut argv = vec![
            "/usr/bin/ssh".to_string(),
            "-N".to_string(),
            "-o".to_string(),
        ];
        argv.extend(expand_proxy_command_arg(&proxy_arg));
        argv.extend([
            "-o".to_string(),
            "ExitOnForwardFailure=yes".to_string(),
            "-L".to_string(),
            "127.0.0.1:80:127.0.0.1:80".to_string(),
            "-f".to_string(),
            "sandbox".to_string(),
        ]);
        let tokens: Vec<&str> = argv.iter().map(String::as_str).collect();

        assert!(args_match_ssh_forward(&tokens, 80, Some("sbx-1")));
        // Port and sandbox-id discrimination still holds on the exact path.
        assert!(!args_match_ssh_forward(&tokens, 8080, Some("sbx-1")));
        assert!(!args_match_ssh_forward(&tokens, 80, Some("sbx-2")));
    }

    #[test]
    fn ssh_forward_command_rejects_proxy_name_collisions() {
        let wrong_ssh = "notssh ssh-proxy --sandbox-id sbx-1 -N -L 80:127.0.0.1:80 sandbox";
        let wrong_proxy = "ssh -o ProxyCommand=/usr/local/bin/not-ssh-proxy --sandbox-id=sbx-1 -N -L 80:127.0.0.1:80 sandbox";

        assert!(!command_matches_ssh_forward(wrong_ssh, 80, Some("sbx-1")));
        assert!(!command_matches_ssh_forward(wrong_proxy, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_rejects_non_ssh_process_with_matching_tokens() {
        let command = "python3 /tmp/ssh ssh-proxy --sandbox-id sbx-1 -N -L 80:127.0.0.1:80 sandbox";

        assert!(!command_matches_ssh_forward(command, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_rejects_bare_ssh_proxy_destination() {
        let command = "ssh ssh-proxy --sandbox-id sbx-1 -N -L80:127.0.0.1:80 sandbox";

        assert!(!command_matches_ssh_forward(command, 80, Some("sbx-1")));
    }

    #[test]
    fn ssh_forward_command_rejects_remote_command_l_argument() {
        let remote_arg = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 -N sandbox -L 80:127.0.0.1:80";
        let missing_no_command = "ssh ssh-proxy --sandbox-id sbx-1 -L 80:127.0.0.1:80 sandbox";
        let remote_command_lookalike = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-1 real-host echo -N -L 80:127.0.0.1:80 sandbox";
        let sandbox_id_in_remote_command = "ssh -o ProxyCommand=openshell ssh-proxy --sandbox-id sbx-2 real-host --sandbox-id sbx-1 -N -L 80:127.0.0.1:80 sandbox";

        assert!(!command_matches_ssh_forward(remote_arg, 80, Some("sbx-1")));
        assert!(!command_matches_ssh_forward(
            missing_no_command,
            80,
            Some("sbx-1")
        ));
        assert!(!command_matches_ssh_forward(
            remote_command_lookalike,
            80,
            Some("sbx-1")
        ));
        assert!(!command_matches_ssh_forward(
            sandbox_id_in_remote_command,
            80,
            Some("sbx-1")
        ));
    }

    #[test]
    fn stop_forward_removes_legacy_pid_file_without_signaling() {
        let _lock = ENV_LOCK.lock().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let _xdg_config = EnvVarGuard::set_path("XDG_CONFIG_HOME", config_dir.path());

        let pid_path = forward_pid_path("sbx-1", 80).unwrap();
        std::fs::create_dir_all(pid_path.parent().unwrap()).unwrap();
        std::fs::write(&pid_path, "12345").unwrap();

        assert!(!stop_forward("sbx-1", 80).unwrap());
        assert!(!pid_path.exists());
    }

    #[test]
    fn list_forwards_marks_legacy_pid_records_not_alive() {
        let _lock = ENV_LOCK.lock().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let _xdg_config = EnvVarGuard::set_path("XDG_CONFIG_HOME", config_dir.path());

        let pid_path = forward_pid_path("sbx-1", 80).unwrap();
        std::fs::create_dir_all(pid_path.parent().unwrap()).unwrap();
        std::fs::write(&pid_path, "12345").unwrap();

        let forwards = list_forwards().unwrap();
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].sandbox_name, "sbx-1");
        assert_eq!(forwards[0].port, 80);
        assert!(!forwards[0].validated_alive);
    }

    #[test]
    fn find_forward_by_port_ignores_legacy_pid_records() {
        let _lock = ENV_LOCK.lock().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let _xdg_config = EnvVarGuard::set_path("XDG_CONFIG_HOME", config_dir.path());

        let pid_path = forward_pid_path("old", 80).unwrap();
        std::fs::create_dir_all(pid_path.parent().unwrap()).unwrap();
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();

        assert_eq!(find_forward_by_port(80).unwrap(), None);
    }

    #[test]
    fn forward_spec_access_url() {
        let spec = ForwardSpec::parse("8080").unwrap();
        assert_eq!(spec.access_url(), "http://127.0.0.1:8080/");

        let spec = ForwardSpec::parse("0.0.0.0:8080").unwrap();
        assert_eq!(spec.access_url(), "http://localhost:8080/");
    }

    #[test]
    fn forward_spec_display() {
        let spec = ForwardSpec::parse("8080").unwrap();
        assert_eq!(spec.to_string(), "8080");

        let spec = ForwardSpec::parse("0.0.0.0:8080").unwrap();
        assert_eq!(spec.to_string(), "0.0.0.0:8080");
    }
}
