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
    // Match the ProxyCommand argument which contains the sandbox ID, plus
    // the -L port forwarding spec. The ProxyCommand (with --sandbox-id)
    // appears before -L in the SSH command line.
    let pattern = format!("ssh.*sandbox-id.*{sandbox_id}.*-L.*{port}:127.0.0.1:{port}");
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(&pattern)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // pgrep may return multiple PIDs (e.g., parent + child). Take the last
    // one, which is typically the backgrounded SSH process.
    stdout
        .lines()
        .rev()
        .find_map(|l| l.trim().parse::<u32>().ok())
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

/// Validate that a PID belongs to an SSH forward process matching the expected
/// port and optional sandbox ID.
pub fn pid_matches_forward(pid: u32, port: u16, sandbox_id: Option<&str>) -> bool {
    let output = match Command::new("ps")
        .arg("-ww")
        .arg("-o")
        .arg("command=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };

    let cmd = String::from_utf8_lossy(&output.stdout);
    let forward_spec = format!("{port}:127.0.0.1:{port}");
    if !cmd.contains("ssh") || !cmd.contains("ssh-proxy") || !cmd.contains(&forward_spec) {
        return false;
    }

    sandbox_id.is_none_or(|id| cmd.contains(id))
}

/// Find the sandbox name that owns a forward on the given port.
///
/// Scans all PID files in the forwards directory for a file matching
/// `*-<port>.pid`.  Ports are unique across sandboxes so at most one
/// match is expected.
pub fn find_forward_by_port(port: u16) -> Result<Option<String>> {
    let dir = forward_pid_dir()?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    let suffix = format!("-{port}.pid");
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if let Some(name) = file_name.strip_suffix(&suffix) {
            if !name.is_empty() {
                return Ok(Some(name.to_string()));
            }
        }
    }
    Ok(None)
}

/// Stop a background port forward.
pub fn stop_forward(name: &str, port: u16) -> Result<bool> {
    let pid_path = forward_pid_path(name, port)?;
    let Some(record) = read_forward_pid(name, port) else {
        return Ok(false);
    };
    let pid = record.pid;

    if pid_is_alive(pid) {
        if !pid_matches_forward(pid, port, record.sandbox_id.as_deref()) {
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
    pub sandbox: String,
    pub port: u16,
    pub pid: u32,
    pub alive: bool,
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
            forwards.push(ForwardInfo {
                sandbox: stem[..dash_pos].to_string(),
                port,
                pid: record.pid,
                alive: pid_is_alive(record.pid),
                bind_addr: record
                    .bind_addr
                    .unwrap_or_else(|| ForwardSpec::DEFAULT_BIND_ADDR.to_string()),
            });
        }
    }

    forwards.sort_by(|a, b| a.sandbox.cmp(&b.sandbox).then(a.port.cmp(&b.port)));
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
        && let Some(fwd) = forwards.iter().find(|f| f.port == port && f.alive)
    {
        return Err(miette::miette!(
            "Port {port} is already forwarded to sandbox '{}'.\n\
             Stop it with: openshell forward stop {port} {}",
            fwd.sandbox,
            fwd.sandbox,
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
        let cluster_port = url.port().unwrap_or(gateway_port);
        let cluster_is_loopback =
            host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost" || host == "::1";
        if !cluster_is_loopback {
            // Remote cluster: use the remote host but keep the cluster URL port.
            return (host.to_string(), cluster_port);
        }
        // Local cluster: both loopback — use cluster URL's port (Docker-mapped).
        return (gateway_host.to_string(), cluster_port);
    }

    (gateway_host.to_string(), gateway_port)
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

/// Build notes string for a sandbox based on active forwards.
///
/// Returns a string like `fwd:8080,3000` or an empty string if no forwards
/// are active for the given sandbox.
pub fn build_sandbox_notes(sandbox_name: &str, forwards: &[ForwardInfo]) -> String {
    let ports: Vec<String> = forwards
        .iter()
        .filter(|f| f.sandbox == sandbox_name && f.alive)
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
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_zeros_with_cluster_host() {
        let (host, port) = resolve_ssh_gateway("0.0.0.0", 8080, "https://10.0.0.5:443");
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_overrides_localhost() {
        let (host, port) = resolve_ssh_gateway("localhost", 8080, "https://remote-host:443");
        assert_eq!(host, "remote-host");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_no_override_when_cluster_is_also_loopback() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "https://127.0.0.1:443");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn resolve_ssh_gateway_handles_invalid_cluster_url() {
        let (host, port) = resolve_ssh_gateway("127.0.0.1", 8080, "not-a-url");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
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

    #[test]
    fn build_sandbox_notes_with_forwards() {
        let forwards = vec![
            ForwardInfo {
                sandbox: "mybox".to_string(),
                port: 8080,
                pid: 123,
                alive: true,
                bind_addr: "127.0.0.1".to_string(),
            },
            ForwardInfo {
                sandbox: "mybox".to_string(),
                port: 3000,
                pid: 456,
                alive: true,
                bind_addr: "127.0.0.1".to_string(),
            },
            ForwardInfo {
                sandbox: "other".to_string(),
                port: 9090,
                pid: 789,
                alive: true,
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
            sandbox: "mybox".to_string(),
            port: 8080,
            pid: 123,
            alive: false,
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
        // listener so the port is released before we test it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        assert!(check_port_available(&ForwardSpec::new(port)).is_ok());
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
        let listener = match TcpListener::bind("[::]:0") {
            Ok(l) => l,
            Err(_) => return, // IPv6 not available, skip
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
