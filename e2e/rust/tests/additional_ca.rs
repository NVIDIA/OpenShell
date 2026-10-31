// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-backed e2e coverage for the global network-supervisor additional CA.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_healthy, wait_for_sandbox_phase};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use sha2::Digest as _;
use tempfile::NamedTempFile;

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
use openshell_e2e::harness::container::ContainerEngine;

const ADDITIONAL_CA_MOUNT_PATH: &str = "/etc/openshell/tls/additional/ca-bundle.pem";
#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
const GATEWAY_CA_PATH: &str = "/etc/openshell/tls/client/ca.crt";
const READY_MARKER: &str = "additional-ca-e2e-ready";
const LIFECYCLE_READY_MARKER: &str = "additional-ca-lifecycle-ready";
const LIFECYCLE_DURABLE_MARKER: &str = "additional-ca-lifecycle-durable";
const LIFECYCLE_DURABLE_PATH: &str = "/sandbox/additional-ca-lifecycle-marker";
const ADDITIONAL_CA_VOLUME: &str = "openshell-additional-ca";

struct PortForwardGuard {
    child: Child,
}

impl Drop for PortForwardGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn driver() -> Result<&'static str, String> {
    match std::env::var("OPENSHELL_E2E_DRIVER").as_deref() {
        Ok("docker") => Ok("docker"),
        Ok("podman") => Ok("podman"),
        Ok("kubernetes") => Ok("kubernetes"),
        Ok("vm") => Ok("vm"),
        Ok(other) => Err(format!("unsupported additional CA e2e driver: {other}")),
        Err(error) => Err(format!("OPENSHELL_E2E_DRIVER must be set: {error}")),
    }
}

const MISMATCH_HOST: &str = "mismatch.openshell.internal";

fn write_policy(port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  additional_ca_e2e:
    name: additional_ca_e2e
    endpoints:
      - host: host.openshell.internal
        port: {port}
        path: /**
        protocol: rest
        access: full
        enforcement: enforce
        allowed_ips: ["10.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
      - host: {MISMATCH_HOST}
        port: {port}
        path: /**
        protocol: rest
        access: full
        enforcement: enforce
        allowed_ips: ["10.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
      - host: example.com
        port: 443
        path: /**
        protocol: rest
        access: full
        enforcement: enforce
    binaries:
      # The network-policy binary identity is the resolved /proc/<pid>/exe
      # target, so the versioned real binaries must be allowlisted rather
      # than the unversioned symlinks: python3.12 on the Noble fixture image
      # (/usr/bin/python3 -> python3.12) and on the uv-based Kubernetes/VM
      # workload image (/usr/local/bin/python3 -> python3.12).
      - path: /usr/bin/python3.12
      - path: /usr/local/bin/python3.12
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn run_json(mut command: Command, description: &str) -> Result<Value, String> {
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("run {description}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!("{description} failed:\n{stdout}{stderr}"));
    }
    serde_json::from_str(stdout.trim())
        .map_err(|error| format!("parse {description} JSON: {error}; output={stdout}"))
}

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn engine_command(container_engine: &ContainerEngine) -> Command {
    let mut command = container_engine.command();
    if container_engine.name() == "podman"
        && let Ok(socket) = std::env::var("OPENSHELL_PODMAN_SOCKET")
    {
        command.arg("--url").arg(format!("unix://{socket}"));
    }
    command
}

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn inspect_local_container(driver: &str, sandbox_name: &str) -> Result<(), String> {
    let container_engine = ContainerEngine::from_env().map_err(|error| error.clone())?;
    // The supervisor container owns the additional CA mount and command. It is
    // host-networked (or attached to a runtime bridge), so it cannot be
    // located through e2e network membership; select it by managed labels.
    // The sandbox namespace label is not used because the Podman driver
    // labels containers with the gateway-elided request namespace.
    let output = engine_command(&container_engine)
        .args([
            "ps",
            "-aq",
            "--filter",
            "label=openshell.ai/isolation-role=supervisor",
            "--filter",
        ])
        .arg(format!("label=openshell.ai/sandbox-name={sandbox_name}"))
        .output()
        .map_err(|error| format!("run {driver} ps: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{driver} ps failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let [container_id] = ids.as_slice() else {
        return Err(format!(
            "expected one {driver} supervisor container for {sandbox_name}, found {ids:?}"
        ));
    };

    let mut mounts_command = engine_command(&container_engine);
    mounts_command.args(["inspect", "--format", "{{json .Mounts}}", container_id]);
    let mounts = run_json(mounts_command, &format!("{driver} mount inspection"))?;
    let mounts = mounts.as_array().ok_or("mounts must be an array")?;
    let destination_mounts = mounts
        .iter()
        .filter(|mount| mount["Destination"] == ADDITIONAL_CA_MOUNT_PATH)
        .collect::<Vec<_>>();
    if destination_mounts.len() != 1 || destination_mounts[0]["RW"] != false {
        return Err(format!("unexpected destination CA mounts: {mounts:#?}"));
    }
    // Podman bind-mounts the gateway mTLS CA only when user namespaces are
    // not remapping UIDs; otherwise it is delivered as a container secret
    // (`openshell-tls-ca-*`), which does not appear in `.Mounts`. Docker never
    // bind-mounts it: the gateway CA is staged inside the read-only supervisor
    // state volume as `tls/ca.pem` and the supervisor is pointed at it through
    // the `OPENSHELL_TLS_CA` environment variable.
    let gateway_ca_mount = mounts
        .iter()
        .find(|mount| mount["Destination"] == GATEWAY_CA_PATH);
    let gateway_ca_secret = gateway_ca_mount.is_none()
        && driver == "podman"
        && podman_gateway_ca_secret(&container_engine, driver, container_id)?;
    let gateway_ca_staged = gateway_ca_mount.is_none()
        && driver == "docker"
        && docker_gateway_ca_staged(&container_engine, container_id, mounts)?;
    if gateway_ca_mount.is_none() && !gateway_ca_secret && !gateway_ca_staged {
        return Err("gateway mTLS CA delivery must remain present".to_string());
    }
    let gateway_ca_source = gateway_ca_mount.map(|mount| mount["Source"].clone());
    if let Some(gateway_ca_source) = gateway_ca_source
        && destination_mounts[0]["Source"] == gateway_ca_source
    {
        return Err("destination and gateway CA mounts must be distinct".to_string());
    }

    let mut command_inspect = engine_command(&container_engine);
    command_inspect.args(["inspect", "--format", "{{json .Config.Cmd}}", container_id]);
    let command = run_json(command_inspect, &format!("{driver} command inspection"))?;
    assert_network_ca_command(command.as_array().ok_or("command must be an array")?)
}

/// Check whether the supervisor received the gateway mTLS CA as a Podman
/// container secret (the delivery path used when user namespaces remap UIDs).
#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn podman_gateway_ca_secret(
    container_engine: &ContainerEngine,
    driver: &str,
    container_id: &str,
) -> Result<bool, String> {
    let mut secrets_command = engine_command(container_engine);
    secrets_command.args([
        "inspect",
        "--format",
        "{{json .Config.Secrets}}",
        container_id,
    ]);
    let secrets = run_json(secrets_command, &format!("{driver} secret inspection"))?;
    let secrets = secrets
        .as_array()
        .ok_or("supervisor secrets must be an array")?;
    Ok(secrets.iter().any(|secret| {
        secret["Name"]
            .as_str()
            .is_some_and(|name| name.starts_with("openshell-tls-ca-"))
    }))
}

/// Check whether the Docker supervisor received the gateway mTLS CA through
/// its staged delivery path: the read-only supervisor state volume plus the
/// `OPENSHELL_TLS_CA` environment pointer.
#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn docker_gateway_ca_staged(
    container_engine: &ContainerEngine,
    container_id: &str,
    mounts: &[Value],
) -> Result<bool, String> {
    const SUPERVISOR_STATE_MOUNT_PATH: &str = "/.openshell/supervisor";
    let supervisor_volume = mounts
        .iter()
        .find(|mount| mount["Destination"] == SUPERVISOR_STATE_MOUNT_PATH);
    if supervisor_volume.is_none_or(|mount| mount["RW"] != false) {
        return Ok(false);
    }
    let mut env_command = engine_command(container_engine);
    env_command.args(["inspect", "--format", "{{json .Config.Env}}", container_id]);
    let envs = run_json(env_command, "docker environment inspection")?;
    let envs = envs
        .as_array()
        .ok_or("supervisor environment must be an array")?;
    Ok(envs
        .iter()
        .any(|env| env.as_str() == Some("OPENSHELL_TLS_CA=/.openshell/supervisor/tls/ca.pem")))
}

fn assert_additional_ca_command(command: &[Value]) -> Result<(), String> {
    let bundle_pairs = command
        .windows(2)
        .filter(|pair| pair[0] == "--additional-ca-bundle")
        .collect::<Vec<_>>();
    if bundle_pairs.len() != 1 || bundle_pairs[0][1] != ADDITIONAL_CA_MOUNT_PATH {
        return Err(format!(
            "unexpected additional CA command arguments: {command:#?}"
        ));
    }
    Ok(())
}

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn assert_network_ca_command(command: &[Value]) -> Result<(), String> {
    assert_additional_ca_command(command)
}

fn kubectl_json(args: &[&str]) -> Result<Value, String> {
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    let mut command = Command::new("kubectl");
    command.arg("--context").arg(context).args(args);
    run_json(command, "kubectl")
}

fn inspect_kubernetes_pod() -> Result<String, String> {
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
        .map_err(|error| format!("sandbox namespace missing: {error}"))?;
    let pods = kubectl_json(&["-n", &namespace, "get", "pods", "-o", "json"])?;
    let items = pods["items"]
        .as_array()
        .ok_or("Kubernetes Pod list missing items")?;
    let supervisor = items
        .iter()
        .find(|pod| {
            pod["metadata"]["labels"]["openshell.ai/boundary-role"] == "supervisor"
                && pod["spec"]["volumes"].as_array().is_some_and(|volumes| {
                    volumes
                        .iter()
                        .any(|volume| volume["name"] == ADDITIONAL_CA_VOLUME)
                })
        })
        .ok_or("dedicated supervisor Pod with destination CA volume not found")?;
    let supervisor_name = supervisor["metadata"]["name"]
        .as_str()
        .ok_or("dedicated supervisor Pod name missing")?;
    let containers = supervisor["spec"]["containers"]
        .as_array()
        .ok_or("dedicated supervisor Pod containers missing")?;
    let [supervisor_container] = containers.as_slice() else {
        return Err(format!(
            "destination CA must be mounted only in the one-container dedicated supervisor Pod: {containers:#?}"
        ));
    };
    if supervisor_container["name"] != "supervisor" {
        return Err(format!(
            "destination CA mounted in non-supervisor control container: {supervisor_container:#?}"
        ));
    }
    let mounts = supervisor_container["volumeMounts"]
        .as_array()
        .ok_or("dedicated supervisor Pod volume mounts missing")?;
    let destination_mounts = mounts
        .iter()
        .filter(|mount| mount["name"] == ADDITIONAL_CA_VOLUME)
        .collect::<Vec<_>>();
    let [destination_mount] = destination_mounts.as_slice() else {
        return Err(format!(
            "expected exactly one destination CA mount in dedicated supervisor Pod: {mounts:#?}"
        ));
    };
    if destination_mount["mountPath"] != ADDITIONAL_CA_MOUNT_PATH
        || destination_mount["subPath"] != "ca.crt"
        || destination_mount["readOnly"] != true
    {
        return Err(format!(
            "dedicated supervisor destination CA mount must be a read-only ca.crt file: {destination_mount:#?}"
        ));
    }
    assert_additional_ca_command(
        supervisor_container["command"]
            .as_array()
            .ok_or("dedicated supervisor command missing")?,
    )?;
    let volume = supervisor["spec"]["volumes"]
        .as_array()
        .ok_or("dedicated supervisor Pod volumes missing")?
        .iter()
        .find(|volume| volume["name"] == ADDITIONAL_CA_VOLUME)
        .ok_or("dedicated supervisor destination CA volume missing")?;
    let managed_name = volume["configMap"]["name"]
        .as_str()
        .ok_or("managed destination CA ConfigMap name missing")?;
    if !managed_name.starts_with("openshell-additional-ca-")
        || volume["configMap"]["items"].as_array().is_none_or(|items| {
            items != &vec![serde_json::json!({"key": "ca.crt", "path": "ca.crt"})]
        })
    {
        return Err(format!(
            "dedicated supervisor has an unexpected destination CA ConfigMap volume: {volume:#?}"
        ));
    }

    let workload = items
        .iter()
        .find(|pod| pod["metadata"]["labels"]["openshell.ai/boundary-role"] == "workload")
        .ok_or("paired workload Pod not found")?;
    let workload_volumes = workload["spec"]["volumes"]
        .as_array()
        .ok_or("workload Pod volumes missing")?;
    if workload_volumes
        .iter()
        .any(|volume| volume["name"] == ADDITIONAL_CA_VOLUME)
    {
        return Err("destination CA ConfigMap leaked into workload Pod volumes".to_string());
    }
    for container in workload["spec"]["containers"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            workload["spec"]["initContainers"]
                .as_array()
                .into_iter()
                .flatten(),
        )
    {
        if container["volumeMounts"].as_array().is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                mount["name"] == ADDITIONAL_CA_VOLUME
                    || mount["mountPath"] == ADDITIONAL_CA_MOUNT_PATH
            })
        }) {
            return Err(format!(
                "destination CA leaked into workload container or bootstrap init container: {container:#?}"
            ));
        }
    }

    let config_map = kubectl_json(&[
        "-n",
        &namespace,
        "get",
        "configmap",
        managed_name,
        "-o",
        "json",
    ])?;
    let supervisor_gateway = supervisor["metadata"]["labels"]["openshell.ai/gateway-id"]
        .as_str()
        .ok_or("dedicated supervisor gateway ownership label missing")?;
    if config_map["metadata"]["labels"]["openshell.ai/managed-by"] != "openshell"
        || config_map["metadata"]["labels"]["openshell.ai/gateway-id"] != supervisor_gateway
        || config_map["metadata"]["ownerReferences"].is_array()
        || config_map["immutable"] != true
        || config_map["data"] != serde_json::json!({"ca.crt": config_map["data"]["ca.crt"].clone()})
        || config_map["data"]["ca.crt"].as_str().is_none()
        || !config_map["binaryData"].is_null()
    {
        return Err("managed destination CA ConfigMap ownership/data is incomplete".to_string());
    }
    let config_map_digest =
        config_map["metadata"]["annotations"]["openshell.ai/additional-ca-generation"]
            .as_str()
            .ok_or("managed destination CA ConfigMap generation missing")?;
    let expected_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(
            config_map["data"]["ca.crt"]
                .as_str()
                .unwrap_or_default()
                .as_bytes(),
        )
    );
    if config_map_digest != expected_digest {
        return Err("managed ConfigMap generation does not match its CA data".to_string());
    }
    Ok(format!("{namespace}/{managed_name}/{supervisor_name}"))
}

#[cfg(feature = "e2e-vm")]
fn inspect_vm_overlay() -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    let state_dir = PathBuf::from(
        std::env::var("OPENSHELL_E2E_VM_STATE_DIR")
            .map_err(|error| format!("VM state directory missing: {error}"))?,
    );
    let source_ca = PathBuf::from(
        std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_CERT")
            .map_err(|error| format!("additional CA source path missing: {error}"))?,
    );
    let mut sandboxes = std::fs::read_dir(state_dir.join("sandboxes"))
        .map_err(|error| format!("read VM sandbox state: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("overlay.ext4").is_file())
        .collect::<Vec<_>>();
    sandboxes.sort();
    let [sandbox_state] = sandboxes.as_slice() else {
        return Err(format!(
            "expected one VM sandbox overlay, found {sandboxes:?}"
        ));
    };
    let overlay = sandbox_state.join("overlay.ext4");

    // Host-only delivery: the driver stages the normalized destination CA as
    // a driver-owned artifact beside the sandbox state, where the host
    // supervisor consumes it. The guest never receives CA material through
    // its overlay, rootfs, argv, or console.
    let staged = std::fs::read(sandbox_state.join("additional-ca.crt"))
        .map_err(|error| format!("read host-staged VM destination CA: {error}"))?;
    let source = std::fs::read(&source_ca)
        .map_err(|error| format!("read additional CA source for digest comparison: {error}"))?;
    if Sha256::digest(&staged) != Sha256::digest(&source) {
        return Err(
            "host-staged VM destination CA digest does not match normalized source".to_string(),
        );
    }

    // debugfs exits successfully even for missing inodes, so presence is
    // detected from the "Inode:" stat header rather than the exit status.
    let overlay_has = |guest_path: &str| -> Result<bool, String> {
        let output = Command::new("debugfs")
            .args(["-R", &format!("stat {guest_path}")])
            .arg(&overlay)
            .output()
            .map_err(|error| format!("run debugfs overlay inspection: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "debugfs overlay inspection failed for {guest_path}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains("Inode:"))
    };
    for guest_path in [
        "/upper/etc/openshell-tls/additional-ca.crt",
        "/etc/openshell-tls/additional-ca.crt",
    ] {
        if overlay_has(guest_path)? {
            return Err(format!(
                "VM guest overlay received CA material at {guest_path}; the \
                 destination CA must stay host-only"
            ));
        }
    }

    let console = sandbox_state.join("rootfs-console.log");
    let console = std::fs::read_to_string(&console)
        .map_err(|error| format!("read VM serial log: {error}"))?;
    if console.contains("-----BEGIN CERTIFICATE-----") {
        return Err("VM serial log disclosed certificate material".to_string());
    }
    Ok(())
}

fn local_staged_artifact() -> Result<std::path::PathBuf, String> {
    let configured = std::path::PathBuf::from(
        std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_ARTIFACT")
            .map_err(|error| format!("gateway-owned CA artifact location missing: {error}"))?,
    );
    if configured.is_file() {
        return Ok(configured);
    }
    if !configured.is_dir() {
        return Err(format!(
            "gateway-owned CA artifact location does not exist: {}",
            configured.display()
        ));
    }

    let mut artifacts = std::fs::read_dir(&configured)
        .map_err(|error| {
            format!(
                "read gateway-owned CA artifact directory {}: {error}",
                configured.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("additional-ca-") && name.ends_with(".crt")
                })
        })
        .collect::<Vec<_>>();
    artifacts.sort();
    let [artifact] = artifacts.as_slice() else {
        return Err(format!(
            "expected exactly one content-addressed CA artifact in {}, found {artifacts:?}",
            configured.display()
        ));
    };
    Ok(artifact.clone())
}

#[cfg(unix)]
fn set_staged_artifact_mode(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set gateway-owned CA artifact permissions: {error}"))
}

#[cfg(not(unix))]
fn set_staged_artifact_mode(path: &std::path::Path, mode: u32) -> Result<(), String> {
    let mut permissions = std::fs::metadata(path)
        .map_err(|error| format!("read gateway-owned CA artifact permissions: {error}"))?
        .permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| format!("set gateway-owned CA artifact permissions: {error}"))
}

fn replace_staged_material(driver: &str, kubernetes_identity: Option<&str>) -> Result<(), String> {
    if driver == "kubernetes" {
        return replace_kubernetes_config_map_with_invalid_material(
            kubernetes_identity.ok_or("Kubernetes staging identity missing")?,
        );
    }

    let artifact = local_staged_artifact()?;
    set_staged_artifact_mode(&artifact, 0o644)?;
    std::fs::write(&artifact, b"not-a-certificate\n")
        .map_err(|error| format!("replace gateway-owned CA artifact: {error}"))?;
    set_staged_artifact_mode(&artifact, 0o444)
}

fn restore_staged_material(driver: &str, kubernetes_identity: Option<&str>) -> Result<(), String> {
    if driver == "kubernetes" {
        return delete_kubernetes_config_map(
            kubernetes_identity.ok_or("Kubernetes staging identity missing")?,
        );
    }

    let source = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_CERT")
        .map_err(|error| format!("additional CA source path missing: {error}"))?;
    let artifact = local_staged_artifact()?;
    if !std::path::Path::new(&source).is_file() {
        return Err(format!("additional CA source does not exist: {source}"));
    }
    set_staged_artifact_mode(&artifact, 0o644)?;
    std::fs::copy(&source, &artifact)
        .map_err(|error| format!("restore gateway-owned CA artifact from {source}: {error}"))?;
    set_staged_artifact_mode(&artifact, 0o444)
}

async fn sandbox_id(sandbox_name: &str) -> String {
    let (output, code) = run_cli(&["sandbox", "get", sandbox_name, "--output", "json"]).await;
    assert_eq!(
        code, 0,
        "get lifecycle sandbox identity should succeed:\n{output}"
    );
    let sandbox: Value = serde_json::from_str(&output).unwrap_or_else(|error| {
        panic!("parse lifecycle sandbox identity JSON: {error}; output={output}")
    });
    assert_eq!(
        sandbox["name"].as_str(),
        Some(sandbox_name),
        "lifecycle sandbox name changed: {sandbox:#?}"
    );
    sandbox["id"]
        .as_str()
        .unwrap_or_else(|| panic!("lifecycle sandbox identity is missing: {sandbox:#?}"))
        .to_string()
}

async fn assert_kubernetes_invalid_staged_material_fails_closed(
    sandbox_name: &str,
) -> Result<(), String> {
    let (stop_output, stop_code) = run_cli(&["sandbox", "stop", sandbox_name]).await;
    if stop_code != 0 {
        return Err(format!(
            "stop Kubernetes sandbox before trust validation failed: {stop_output}"
        ));
    }

    // Ordinary stop/start is the supported reconciliation path. The driver
    // must validate the equal-generation immutable ConfigMap before changing
    // the Sandbox resource back to an operating state.
    let (start_output, start_code) = run_cli(&["sandbox", "start", sandbox_name]).await;
    if start_code == 0 {
        return Err("Kubernetes sandbox start accepted replaced destination trust".to_string());
    }
    let normalized_start_output = start_output
        .lines()
        .map(|line| line.trim().trim_start_matches('│').trim())
        .collect::<Vec<_>>()
        .join(" ");
    if !normalized_start_output.contains("network additional CA ConfigMap")
        || !(normalized_start_output.contains("unexpected trust generation")
            || normalized_start_output
                .contains("did not retain the exact gateway-normalized trust bundle")
            || normalized_start_output.contains("is not immutable")
            || normalized_start_output.contains("is not owned by this gateway"))
    {
        return Err(format!(
            "Kubernetes sandbox start lacked stable additional-CA validation evidence: {start_output}"
        ));
    }
    if start_output.contains("-----BEGIN CERTIFICATE-----")
        || start_output.contains("-----BEGIN PRIVATE KEY-----")
    {
        return Err("Kubernetes start validation disclosed CA material".to_string());
    }
    Ok(())
}

async fn assert_invalid_staged_material_fails_closed(policy_path: &str) {
    let startup_error = match SandboxGuard::create(&["--policy", policy_path, "--", "true"]).await {
        Ok(mut unexpected) => {
            unexpected.cleanup().await;
            panic!("a new sandbox accepted invalid staged destination trust");
        }
        Err(error) => error,
    };
    assert!(
        startup_error.contains("error phase") || startup_error.contains("failed"),
        "invalid staged trust did not fail sandbox startup: {startup_error}"
    );
    // Miette wraps long CLI diagnostics and prefixes continuation lines with a
    // box-drawing marker. Normalize that presentation before matching the
    // driver's stable error text.
    let normalized_startup_error = startup_error
        .lines()
        .map(|line| line.trim().trim_start_matches('│').trim())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        normalized_startup_error.contains("--additional-ca-bundle")
            || normalized_startup_error.contains("additional destination CA bundle")
            || normalized_startup_error.contains("invalid staged destination CA bundle")
            || normalized_startup_error
                .contains("network additional CA artifact verification failed")
            || normalized_startup_error
                .contains("does not match the gateway startup trust generation"),
        "invalid staged trust lacked stable supervisor additional-CA validation evidence: {startup_error}"
    );
    assert!(
        !startup_error.contains("-----BEGIN CERTIFICATE-----")
            && !startup_error.contains("-----BEGIN PRIVATE KEY-----"),
        "invalid staged trust failure disclosed certificate or key material"
    );
}

fn remove_additional_ca_section(config: &str) -> Result<String, String> {
    const SECTION: &str = "[openshell.supervisor.network]";
    let mut found = false;
    let mut skipping = false;
    let mut output = Vec::new();

    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed == SECTION {
            if found {
                return Err("gateway config contains duplicate supervisor network sections".into());
            }
            found = true;
            skipping = true;
            continue;
        }
        if skipping && trimmed.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            output.push(line);
        }
    }
    if !found {
        return Err("gateway config does not contain the additional CA section".into());
    }
    Ok(format!("{}\n", output.join("\n")))
}

async fn restart_kubernetes_gateway_port_forward() -> Result<Option<PortForwardGuard>, String> {
    // Depending on kubectl and rollout timing, a Service port-forward may
    // survive and reconnect to the replacement pod. Keep it when the existing
    // registered endpoint is already healthy.
    if wait_for_healthy(Duration::from_secs(10)).await.is_ok() {
        return Ok(None);
    }

    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    let namespace = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_HELM_NAMESPACE")
        .map_err(|error| format!("Helm namespace missing: {error}"))?;
    let local_port = std::env::var("OPENSHELL_E2E_KUBE_GATEWAY_LOCAL_PORT")
        .map_err(|error| format!("Kubernetes gateway local port missing: {error}"))?
        .parse::<u16>()
        .map_err(|error| format!("Kubernetes gateway local port is invalid: {error}"))?;

    // kubectl port-forward binds to one selected pod even when given a Service.
    // A Helm rollout therefore terminates the wrapper-owned process. Wait for
    // its local socket to be released, then restore the same endpoint already
    // registered in the CLI configuration.
    let mut released = false;
    for _ in 0..30 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", local_port)) {
            drop(listener);
            released = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if !released {
        return Err("previous Kubernetes gateway port-forward did not exit after rollout".into());
    }

    let child = Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            &namespace,
            "port-forward",
            "svc/openshell",
            &format!("{local_port}:8080"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("restart Kubernetes gateway port-forward: {error}"))?;
    Ok(Some(PortForwardGuard { child }))
}

async fn remove_configuration_and_restart(
    driver: &str,
) -> Result<Option<PortForwardGuard>, String> {
    let port_forward = if driver == "kubernetes" {
        let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
            .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
        let namespace = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_HELM_NAMESPACE")
            .map_err(|error| format!("Helm namespace missing: {error}"))?;
        let release = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_HELM_RELEASE")
            .map_err(|error| format!("Helm release missing: {error}"))?;
        let chart = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_HELM_CHART")
            .map_err(|error| format!("Helm chart path missing: {error}"))?;
        let output = Command::new("helm")
            .args([
                "upgrade",
                &release,
                &chart,
                "--kube-context",
                &context,
                "--namespace",
                &namespace,
                "--reuse-values",
                "--set-string",
                "supervisor.network.additionalCaConfigMapName=",
                "--wait",
                "--timeout",
                "5m",
            ])
            .output()
            .map_err(|error| format!("remove additional CA Helm value: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "remove additional CA Helm value failed:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        restart_kubernetes_gateway_port_forward().await?
    } else {
        let config_path = std::env::var("OPENSHELL_E2E_GATEWAY_CONFIG")
            .map_err(|error| format!("gateway config path missing: {error}"))?;
        let config = std::fs::read_to_string(&config_path)
            .map_err(|error| format!("read gateway config: {error}"))?;
        let without_additional_ca = remove_additional_ca_section(&config)?;
        std::fs::write(&config_path, without_additional_ca)
            .map_err(|error| format!("write gateway config without additional CA: {error}"))?;

        let gateway = ManagedGateway::from_env()?
            .ok_or_else(|| "managed gateway metadata disappeared".to_string())?;
        gateway.stop()?;
        gateway.start()?;
        None
    };

    wait_for_healthy(Duration::from_secs(180)).await?;
    Ok(port_forward)
}

fn replace_kubernetes_config_map_with_invalid_material(identity: &str) -> Result<(), String> {
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let config_map = parts.next().ok_or("ConfigMap name missing")?;
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    let current = kubectl_json(&[
        "--context",
        &context,
        "-n",
        namespace,
        "get",
        "configmap",
        config_map,
        "-o",
        "json",
    ])?;
    let replacement = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": config_map,
            "namespace": namespace,
            "labels": current["metadata"]["labels"].clone(),
            "annotations": current["metadata"]["annotations"].clone(),
        },
        "immutable": true,
        "data": {"ca.crt": "not-a-certificate\n"},
    });
    let mut child = Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            namespace,
            "replace",
            "--force",
            "-f",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("replace immutable destination CA ConfigMap: {error}"))?;
    child
        .stdin
        .take()
        .ok_or("kubectl replacement stdin missing")?
        .write_all(replacement.to_string().as_bytes())
        .map_err(|error| format!("write replacement destination CA ConfigMap: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for destination CA ConfigMap replacement: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "replace immutable destination CA ConfigMap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn delete_kubernetes_config_map(identity: &str) -> Result<(), String> {
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let config_map = parts.next().ok_or("ConfigMap name missing")?;
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    let output = Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            namespace,
            "delete",
            "configmap",
            config_map,
            "--wait=true",
        ])
        .output()
        .map_err(|error| format!("delete invalid destination CA ConfigMap: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "delete invalid destination CA ConfigMap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Exec argv that fetches `url` with the workload's default TLS verification
/// and prints the body. Exits nonzero when validation fails, so a failed exec
/// surfaces the verification error. Uses python3 because the Kubernetes and
/// VM workload images do not ship curl.
fn python_fetch_argv(driver: &str, url: &str) -> Vec<String> {
    let script = format!(
        "import sys, urllib.request\ntry:\n    with urllib.request.urlopen({url:?}, timeout=30) as response:\n        sys.stdout.write(response.read().decode())\nexcept Exception as error:\n    sys.exit(str(error))\n"
    );
    vec![
        python_binary_for_driver(driver).to_string(),
        "-c".to_string(),
        script,
    ]
}

fn python_binary_for_driver(driver: &str) -> &'static str {
    match driver {
        // The container-engine lanes run the Noble fixture image.
        "docker" | "podman" => "/usr/bin/python3",
        // The Kubernetes and VM lanes run the uv-based workload image, where
        // python3 lives under /usr/local/bin and curl is not present.
        _ => "/usr/local/bin/python3",
    }
}

fn hostname_validation_script(matching_host: &str, port: u16) -> String {
    format!(
        r#"
import json
import socket
import ssl
import sys
import time
import urllib.request

port = {port}
matching_host = {matching_host:?}
mismatch_host = {MISMATCH_HOST:?}

# 1. The matching destination must validate through the workload trust
#    store (system roots plus the provisioned destination CA).
with urllib.request.urlopen("https://" + matching_host + ":%d/" % port, timeout=30) as response:
    body = response.read()
if json.loads(body) != {{"additional_ca": "trusted"}}:
    sys.exit("unexpected matching-host body: %r" % (body,))
print("matching-host-trusted", flush=True)

# 2. Hostname mismatch against the same reachable fixture: connect to the
# matching host's address while presenting the mismatch hostname as TLS
# SNI. The fixture's private CA is trusted, so the failure must be the
# hostname check itself, not an untrusted issuer or a routing error.
address = socket.getaddrinfo(matching_host, port, proto=socket.IPPROTO_TCP)[0][4]
sock = socket.create_connection(address, timeout=15)
try:
    context = ssl.create_default_context()
    try:
        context.wrap_socket(sock, server_hostname=mismatch_host)
    except ssl.SSLCertVerificationError as error:
        message = str(error).lower()
        if "mismatch" not in message and "doesn't match" not in message:
            sys.exit("unexpected hostname verification error: %s" % error)
    else:
        sys.exit("hostname mismatch was accepted by the destination trust")
finally:
    sock.close()
print("hostname-mismatch-rejected", flush=True)

# 3. Public roots must keep validating alongside the destination CA.
with urllib.request.urlopen("https://example.com/", timeout=30) as response:
    response.read()
print("public-root-trusted", flush=True)

print({READY_MARKER:?}, flush=True)
while True:
    time.sleep(1)
"#,
    )
}

#[tokio::test]
async fn additional_ca_trusts_matching_and_public_hosts_and_rejects_mismatch() {
    let driver = driver().expect("select compute driver");
    let port = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_PORT")
        .expect("wrapper must export OPENSHELL_E2E_ADDITIONAL_CA_PORT")
        .parse::<u16>()
        .expect("additional CA fixture port must be numeric");
    let policy = write_policy(port).expect("write additional CA e2e policy");
    let policy_path = policy.path().to_str().expect("policy path must be UTF-8");
    let matching_url = format!("https://host.openshell.internal:{port}/");
    let script = hostname_validation_script("host.openshell.internal", port);

    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", policy_path],
        &[python_binary_for_driver(driver), "-c", script.as_str()],
        READY_MARKER,
    )
    .await
    .expect("create sandbox using configured destination CA");
    assert!(sandbox.create_output.contains("matching-host-trusted"));
    assert!(sandbox.create_output.contains("hostname-mismatch-rejected"));
    assert!(sandbox.create_output.contains("public-root-trusted"));
    // Reaching the workload command and then using sandbox exec below requires
    // the supervisor's independently configured gateway callback mTLS path.

    let kubernetes_identity = if driver == "kubernetes" {
        Some(inspect_kubernetes_pod().expect("inspect Kubernetes ConfigMap and pod placement"))
    } else if driver == "vm" {
        #[cfg(feature = "e2e-vm")]
        {
            inspect_vm_overlay().expect("inspect VM overlay and guest-init delivery");
            None
        }
        #[cfg(not(feature = "e2e-vm"))]
        {
            panic!("VM driver feature missing");
        }
    } else {
        #[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
        {
            inspect_local_container(driver, &sandbox.name)
                .expect("inspect local container delivery");
            None
        }
        #[cfg(not(any(feature = "e2e-docker", feature = "e2e-podman")))]
        {
            panic!("local-container driver feature missing");
        }
    };

    replace_staged_material(driver, kubernetes_identity.as_deref())
        .expect("replace staged destination trust with invalid material");
    if driver == "kubernetes" || driver == "vm" {
        let fetch_argv = python_fetch_argv(driver, &matching_url);
        let fetch_argv = fetch_argv.iter().map(String::as_str).collect::<Vec<_>>();
        let output = sandbox
            .exec(&fetch_argv)
            .await
            .expect("running supervisor retains startup trust after staged material changes");
        assert!(
            output.contains(r#"{"additional_ca":"trusted"}"#),
            "running supervisor lost startup trust after staged material changed: {output}"
        );
    }

    if driver == "kubernetes" {
        assert_kubernetes_invalid_staged_material_fails_closed(&sandbox.name)
            .await
            .expect("stopped Kubernetes sandbox rejects invalid staged trust on start");
    } else if driver == "vm" {
        let mut retained_snapshot_sandbox = SandboxGuard::create_keep_with_args(
            &["--policy", policy_path],
            &[python_binary_for_driver(driver), "-c", script.as_str()],
            READY_MARKER,
        )
        .await
        .expect("VM child uses its retained startup trust snapshot for later launches");
        assert!(
            retained_snapshot_sandbox
                .create_output
                .contains("matching-host-trusted")
        );
        retained_snapshot_sandbox.cleanup().await;
    } else {
        assert_invalid_staged_material_fails_closed(policy_path).await;
    }

    // Remove the sandbox whose startup trust and staged material were mutated
    // before restoring delivery. For Kubernetes, remove the deliberately
    // replaced immutable map so the driver's ensure path can recreate the
    // exact gateway startup snapshot for the next sandbox.
    sandbox.cleanup().await;
    restore_staged_material(driver, kubernetes_identity.as_deref())
        .expect("restore destination trust after invalid-material check");

    // Use a neutral, long-running main process so stop/start is the only
    // lifecycle transition. The exec calls below prove both destination trust
    // and gateway-authenticated control traffic independently of that process.
    let lifecycle_script = format!("echo {LIFECYCLE_READY_MARKER}; while true; do sleep 1; done");
    let mut lifecycle_sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", policy_path],
        &["sh", "-lc", &lifecycle_script],
        LIFECYCLE_READY_MARKER,
    )
    .await
    .expect("create lifecycle sandbox using restored destination CA");
    let lifecycle_fetch_argv = python_fetch_argv(driver, &matching_url);
    let lifecycle_fetch_argv = lifecycle_fetch_argv
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let private_ca_output = lifecycle_sandbox
        .exec(&lifecycle_fetch_argv)
        .await
        .expect("lifecycle sandbox trusts the private CA before removal");
    assert!(
        private_ca_output.contains(r#"{"additional_ca":"trusted"}"#),
        "lifecycle sandbox did not trust private CA before removal: {private_ca_output}"
    );
    let durable_marker_output = lifecycle_sandbox
        .exec(&[
            "sh",
            "-lc",
            &format!(
                "printf '%s\\n' '{LIFECYCLE_DURABLE_MARKER}' > {LIFECYCLE_DURABLE_PATH}; sync; cat {LIFECYCLE_DURABLE_PATH}"
            ),
        ])
        .await
        .expect("write durable lifecycle marker");
    assert!(
        durable_marker_output.contains(LIFECYCLE_DURABLE_MARKER),
        "lifecycle sandbox did not write durable marker: {durable_marker_output}"
    );
    let lifecycle_id_before_removal = sandbox_id(&lifecycle_sandbox.name).await;

    let (stop_output, stop_code) = run_cli(&["sandbox", "stop", &lifecycle_sandbox.name]).await;
    assert_eq!(
        stop_code, 0,
        "stop lifecycle sandbox should succeed:\n{stop_output}"
    );
    wait_for_sandbox_phase(&lifecycle_sandbox.name, "Stopped", Duration::from_secs(180))
        .await
        .expect("lifecycle sandbox should be stopped before removing configuration");

    let _gateway_port_forward = remove_configuration_and_restart(driver)
        .await
        .expect("remove additional CA configuration and restart gateway");

    let (start_output, start_code) = run_cli(&["sandbox", "start", &lifecycle_sandbox.name]).await;
    assert_eq!(
        start_code, 0,
        "start the same lifecycle sandbox should succeed:\n{start_output}"
    );
    wait_for_sandbox_phase(&lifecycle_sandbox.name, "Ready", Duration::from_secs(180))
        .await
        .expect("same lifecycle sandbox should become ready after configuration removal");
    assert_eq!(
        sandbox_id(&lifecycle_sandbox.name).await,
        lifecycle_id_before_removal,
        "stop/start after configuration removal must retain sandbox identity"
    );

    let removed_validation_script = format!(
        r#"import os
import sys
import urllib.request

marker = open({LIFECYCLE_DURABLE_PATH:?}).read().strip()
if marker != {LIFECYCLE_DURABLE_MARKER:?}:
    sys.exit("lifecycle durable marker was lost across the restart")
if os.path.exists({ADDITIONAL_CA_MOUNT_PATH:?}):
    sys.exit("destination CA mount path survived configuration removal")
try:
    urllib.request.urlopen({matching_url:?}, timeout=30).read()
except Exception:
    print("same-sandbox-private-ca-rejected", flush=True)
else:
    sys.exit("private CA remained trusted after configuration removal")
print("gateway-authenticated-exec-works", flush=True)"#
    );
    let removed_validation_argv = [
        python_binary_for_driver(driver).to_string(),
        "-c".to_string(),
        removed_validation_script,
    ];
    let removed_validation_argv = removed_validation_argv
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let removed_validation_output = lifecycle_sandbox
        .exec(&removed_validation_argv)
        .await
        .expect("gateway-authenticated exec should work after lifecycle restart");
    assert!(
        removed_validation_output.contains("gateway-authenticated-exec-works"),
        "gateway-authenticated exec was not confirmed: {removed_validation_output}"
    );
    assert!(
        removed_validation_output.contains("same-sandbox-private-ca-rejected"),
        "same sandbox retained private CA after configuration removal: {removed_validation_output}"
    );

    lifecycle_sandbox.cleanup().await;
}
