// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman socket discovery for local and machine-backed installations.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVERY_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Return the first responsive well-known socket, then ask the Podman CLI for
/// the active native or machine-backed connection.
pub fn detect_socket() -> Option<PathBuf> {
    openshell_core::local_api_socket::first_responsive_socket(&socket_candidates(), |response| {
        openshell_core::local_api_socket::http_response_is_success(response)
            && openshell_core::local_api_socket::contains_ascii(response, b"Libpod-Api-Version:")
    })
    .or_else(discover_socket)
}

fn socket_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env_var_nonempty("OPENSHELL_PODMAN_SOCKET") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(runtime_dir).join("podman/podman.sock"));
    }
    #[cfg(target_os = "linux")]
    candidates.push(PathBuf::from(format!(
        "/run/user/{}/podman/podman.sock",
        rustix::process::geteuid().as_raw()
    )));
    if let Some(home) = std::env::var_os("HOME") {
        candidates
            .push(PathBuf::from(home).join(".local/share/containers/podman/machine/podman.sock"));
    }
    candidates
}

/// Query the same active connection selected by the Podman CLI. This covers
/// named/rootful machines and provider-specific forwarded socket locations that
/// do not have a stable well-known path.
fn discover_socket() -> Option<PathBuf> {
    let stdout = run_podman_capture(&["info", "--format", "json"])?;

    // A successful `podman info` proves this explicit socket is usable. A named
    // connection has higher precedence, so only honor CONTAINER_HOST directly
    // when no CONTAINER_CONNECTION is set.
    if env_var_nonempty("CONTAINER_CONNECTION").is_none()
        && let Some(path) = env_var_nonempty("CONTAINER_HOST")
            .as_deref()
            .and_then(unix_url_socket_path)
    {
        return Some(path);
    }

    let info: serde_json::Value = serde_json::from_slice(&stdout).ok()?;
    if !info["host"]["serviceIsRemote"].as_bool().unwrap_or(false) {
        return parse_info_socket(&info);
    }

    discover_machine_socket()
}

fn discover_machine_socket() -> Option<PathBuf> {
    let connections = connection_list();
    let active = active_machine(
        env_var_nonempty("CONTAINER_CONNECTION").as_deref(),
        env_var_nonempty("CONTAINER_HOST").as_deref(),
        connections.as_ref(),
    )?;
    machine_inspect_targets(&active)
        .into_iter()
        .find_map(|name| {
            let stdout = run_podman_capture(&["machine", "inspect", &name])?;
            let machines: serde_json::Value = serde_json::from_slice(&stdout).ok()?;
            parse_machine_socket(&machines)
        })
}

fn active_machine(
    container_connection: Option<&str>,
    container_host: Option<&str>,
    connections: Option<&serde_json::Value>,
) -> Option<String> {
    if let Some(name) = container_connection.filter(|name| !name.trim().is_empty()) {
        return Some(name.to_string());
    }
    if let Some(host) = container_host.filter(|host| !host.trim().is_empty()) {
        // An explicit non-machine endpoint must not fall back to an unrelated
        // local machine.
        return connection_name_for_uri(connections?, host);
    }
    default_machine_connection(connections).or_else(|| Some("podman-machine-default".to_string()))
}

fn machine_inspect_targets(connection: &str) -> Vec<String> {
    let mut names = vec![connection.to_string()];
    if let Some(machine) = connection.strip_suffix("-root")
        && !machine.is_empty()
    {
        names.push(machine.to_string());
    }
    names
}

fn connection_list() -> Option<serde_json::Value> {
    let stdout = run_podman_capture(&["system", "connection", "list", "--format", "json"])?;
    serde_json::from_slice(&stdout).ok()
}

fn default_machine_connection(connections: Option<&serde_json::Value>) -> Option<String> {
    connections?
        .as_array()?
        .iter()
        .find(|connection| {
            connection["Default"].as_bool().unwrap_or(false)
                && connection["IsMachine"].as_bool().unwrap_or(false)
        })
        .and_then(|connection| connection["Name"].as_str())
        .map(str::to_string)
}

fn connection_name_for_uri(connections: &serde_json::Value, uri: &str) -> Option<String> {
    connections
        .as_array()?
        .iter()
        .find(|connection| {
            connection["IsMachine"].as_bool().unwrap_or(false)
                && connection["URI"].as_str() == Some(uri)
        })
        .and_then(|connection| connection["Name"].as_str())
        .map(str::to_string)
}

fn parse_info_socket(info: &serde_json::Value) -> Option<PathBuf> {
    let path = info["host"]["remoteSocket"]["path"].as_str()?;
    unix_url_socket_path(path).or_else(|| (!path.is_empty()).then(|| PathBuf::from(path)))
}

fn parse_machine_socket(machines: &serde_json::Value) -> Option<PathBuf> {
    let path = machines.as_array()?.first()?["ConnectionInfo"]["PodmanSocket"]["Path"].as_str()?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn unix_url_socket_path(url: &str) -> Option<PathBuf> {
    let path = url.trim().strip_prefix("unix://")?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn env_var_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn run_podman_capture(args: &[&str]) -> Option<Vec<u8>> {
    run_bounded_command("podman", args, DISCOVERY_TIMEOUT)
}

/// Capture stdout without allowing a stalled Podman machine, SSH transport, or
/// descendant holding the stdout pipe open to block gateway startup forever.
fn run_bounded_command(program: &str, args: &[&str], timeout: Duration) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::sync::mpsc;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    set_new_process_group(&mut command);
    let mut child = command.spawn().ok()?;

    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout.read_to_end(&mut output);
        let _ = sender.send(output);
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(DISCOVERY_POLL_INTERVAL);
            }
            Ok(None) | Err(_) => break None,
        }
    };

    let Some(status) = status else {
        terminate_process_group(&mut child);
        let _ = child.wait();
        return None;
    };

    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(output) if status.success() => Some(output),
        Ok(_) => None,
        Err(_) => {
            terminate_process_group(&mut child);
            None
        }
    }
}

#[cfg(unix)]
fn set_new_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn set_new_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) {
    let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
    let group = nix::unistd::Pid::from_raw(-pid);
    let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_info_socket_rejects_missing_or_empty_paths() {
        assert_eq!(
            parse_info_socket(&json!({"host": {"remoteSocket": {}}})),
            None
        );
        assert_eq!(
            parse_info_socket(&json!({"host": {"remoteSocket": {"path": ""}}})),
            None
        );
    }

    #[test]
    fn parse_machine_socket_rejects_missing_socket_or_machine() {
        assert_eq!(parse_machine_socket(&json!([])), None);
        assert_eq!(parse_machine_socket(&json!([{"ConnectionInfo": {}}])), None);
    }

    #[test]
    fn parses_native_and_machine_socket_paths() {
        let info = json!({"host": {"remoteSocket": {"path": "unix:///run/user/1000/podman.sock"}}});
        assert_eq!(
            parse_info_socket(&info),
            Some(PathBuf::from("/run/user/1000/podman.sock"))
        );

        let machine = json!([{"ConnectionInfo": {"PodmanSocket": {"Path": "/tmp/machine.sock"}}}]);
        assert_eq!(
            parse_machine_socket(&machine),
            Some(PathBuf::from("/tmp/machine.sock"))
        );
    }

    #[test]
    fn resolves_named_rootful_and_default_machine_connections() {
        let connections = json!([
            {"Name": "team-machine-root", "URI": "ssh://team", "Default": true, "IsMachine": true},
            {"Name": "remote", "URI": "ssh://remote", "Default": false, "IsMachine": false}
        ]);
        assert_eq!(
            active_machine(Some("team-machine-root"), None, Some(&connections)),
            Some("team-machine-root".to_string())
        );
        assert_eq!(
            machine_inspect_targets("team-machine-root"),
            ["team-machine-root", "team-machine"]
        );
        assert_eq!(
            active_machine(None, None, Some(&connections)),
            Some("team-machine-root".to_string())
        );
    }

    #[test]
    fn explicit_non_machine_endpoint_does_not_guess_a_machine() {
        let connections = json!([
            {"Name": "local", "URI": "ssh://local", "Default": true, "IsMachine": true},
            {"Name": "remote", "URI": "ssh://remote", "Default": false, "IsMachine": false}
        ]);
        assert_eq!(
            active_machine(None, Some("ssh://remote"), Some(&connections)),
            None
        );
    }

    #[test]
    fn container_host_maps_to_the_matching_machine_connection() {
        let connections = json!([
            {"Name": "work", "URI": "ssh://core@127.0.0.1:5555/run/podman.sock", "Default": false, "IsMachine": true},
            {"Name": "podman-machine-default", "URI": "ssh://core@127.0.0.1:4444/run/podman.sock", "Default": true, "IsMachine": true}
        ]);
        assert_eq!(
            active_machine(
                None,
                Some("ssh://core@127.0.0.1:5555/run/podman.sock"),
                Some(&connections),
            ),
            Some("work".to_string())
        );
    }

    #[test]
    fn unix_url_socket_path_only_accepts_nonempty_unix_urls() {
        assert_eq!(
            unix_url_socket_path("unix:///run/user/1000/podman.sock"),
            Some(PathBuf::from("/run/user/1000/podman.sock"))
        );
        assert_eq!(unix_url_socket_path("ssh://core@127.0.0.1/x"), None);
        assert_eq!(unix_url_socket_path("tcp://127.0.0.1:2375"), None);
        assert_eq!(unix_url_socket_path("unix://"), None);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_captures_stdout_on_success() {
        assert_eq!(
            run_bounded_command("printf", &["hello"], Duration::from_secs(5)),
            Some(b"hello".to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_returns_none_on_nonzero_exit_or_missing_program() {
        assert_eq!(
            run_bounded_command("false", &[], Duration::from_secs(5)),
            None
        );
        assert_eq!(
            run_bounded_command(
                "openshell-nonexistent-binary-xyz",
                &[],
                Duration::from_secs(5),
            ),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_kills_child_that_exceeds_deadline() {
        let start = Instant::now();
        let result = run_bounded_command("sleep", &["30"], Duration::from_millis(200));
        assert_eq!(result, None);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "bounded command did not return promptly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_bounds_drain_when_in_group_descendant_holds_stdout() {
        let start = Instant::now();
        let result = run_bounded_command(
            "sh",
            &["-c", "sleep 30 & echo done"],
            Duration::from_millis(300),
        );
        assert_eq!(result, None);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "drain blocked on a descendant holding stdout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_bounds_drain_when_descendant_escapes_process_group() {
        let start = Instant::now();
        let result = run_bounded_command(
            "bash",
            &["-c", "set -m; sleep 5 & echo done"],
            Duration::from_millis(300),
        );
        assert_eq!(result, None);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "drain blocked on a descendant that escaped the process group"
        );
    }
}
