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
use tempfile::NamedTempFile;

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
use openshell_e2e::harness::container::ContainerEngine;

const NETWORK_CA_PATH: &str = "/etc/openshell-tls/network-additional-ca.crt";
#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
const GATEWAY_CA_PATH: &str = "/etc/openshell/tls/client/ca.crt";
const READY_MARKER: &str = "additional-ca-e2e-ready";
const LIFECYCLE_READY_MARKER: &str = "additional-ca-lifecycle-ready";
const LIFECYCLE_DURABLE_MARKER: &str = "additional-ca-lifecycle-durable";
const LIFECYCLE_DURABLE_PATH: &str = "/sandbox/additional-ca-lifecycle-marker";
const NETWORK_CA_VOLUME: &str = "openshell-network-additional-ca";

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
      - path: /usr/bin/curl
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
    let network = std::env::var("OPENSHELL_E2E_NETWORK_NAME")
        .or_else(|_| std::env::var("OPENSHELL_E2E_DOCKER_NETWORK_NAME"))
        .map_err(|error| format!("wrapper must export sandbox network: {error}"))?;
    let network_filter = format!("network={network}");
    let output = engine_command(&container_engine)
        .args(["ps", "-aq", "--filter"])
        .arg(network_filter)
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
            "expected one {driver} container for {sandbox_name}, found {ids:?}"
        ));
    };

    let mut mounts_command = engine_command(&container_engine);
    mounts_command.args(["inspect", "--format", "{{json .Mounts}}", container_id]);
    let mounts = run_json(mounts_command, &format!("{driver} mount inspection"))?;
    let mounts = mounts.as_array().ok_or("mounts must be an array")?;
    let destination_mounts = mounts
        .iter()
        .filter(|mount| mount["Destination"] == NETWORK_CA_PATH)
        .collect::<Vec<_>>();
    if destination_mounts.len() != 1 || destination_mounts[0]["RW"] != false {
        return Err(format!("unexpected destination CA mounts: {mounts:#?}"));
    }
    let gateway_ca_mount = mounts
        .iter()
        .find(|mount| mount["Destination"] == GATEWAY_CA_PATH)
        .ok_or("gateway mTLS CA mount must remain present")?;
    if destination_mounts[0]["Source"] == gateway_ca_mount["Source"] {
        return Err("destination and gateway CA mounts must be distinct".to_string());
    }

    let mut command_inspect = engine_command(&container_engine);
    command_inspect.args(["inspect", "--format", "{{json .Config.Cmd}}", container_id]);
    let command = run_json(command_inspect, &format!("{driver} command inspection"))?;
    assert_network_ca_command(command.as_array().ok_or("command must be an array")?)
}

fn network_ca_command_digest(command: &[Value]) -> Result<String, String> {
    let bundle_pairs = command
        .windows(2)
        .filter(|pair| pair[0] == "--network-additional-ca-bundle")
        .collect::<Vec<_>>();
    let digest_pairs = command
        .windows(2)
        .filter(|pair| pair[0] == "--network-additional-ca-digest")
        .collect::<Vec<_>>();
    let digest = digest_pairs
        .first()
        .and_then(|pair| pair[1].as_str())
        .unwrap_or_default();
    let valid_digest = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    });
    if bundle_pairs.len() != 1
        || bundle_pairs[0][1] != NETWORK_CA_PATH
        || digest_pairs.len() != 1
        || !valid_digest
    {
        return Err(format!(
            "unexpected network CA command arguments: {command:#?}"
        ));
    }
    Ok(digest.to_string())
}

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn assert_network_ca_command(command: &[Value]) -> Result<(), String> {
    network_ca_command_digest(command).map(|_| ())
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
    let pod = pods["items"]
        .as_array()
        .and_then(|items| {
            items.iter().find(|pod| {
                pod["spec"]["volumes"].as_array().is_some_and(|volumes| {
                    volumes
                        .iter()
                        .any(|volume| volume["name"] == NETWORK_CA_VOLUME)
                })
            })
        })
        .ok_or("sandbox pod with destination CA volume not found")?;
    let pod_name = pod["metadata"]["name"]
        .as_str()
        .ok_or("sandbox pod name missing")?;
    let containers = pod["spec"]["containers"]
        .as_array()
        .ok_or("pod containers missing")?;
    let mounted = containers
        .iter()
        .filter(|container| {
            container["volumeMounts"].as_array().is_some_and(|mounts| {
                mounts.iter().any(|mount| {
                    mount["name"] == NETWORK_CA_VOLUME
                        && mount["mountPath"] == NETWORK_CA_PATH
                        && mount["readOnly"] == true
                })
            })
        })
        .collect::<Vec<_>>();
    if mounted.len() != 1 {
        return Err(format!(
            "expected one destination CA container mount: {containers:#?}"
        ));
    }
    let expected_container = if containers
        .iter()
        .any(|container| container["name"] == "openshell-network")
    {
        "openshell-network"
    } else {
        "agent"
    };
    if mounted[0]["name"] != expected_container {
        return Err(format!(
            "destination CA mounted in {}, expected {expected_container}",
            mounted[0]["name"]
        ));
    }
    let supervisor_digest = network_ca_command_digest(
        mounted[0]["command"]
            .as_array()
            .ok_or("supervisor command missing")?,
    )?;
    let trust_init_containers = pod["spec"]["initContainers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|init| {
            init["volumeMounts"].as_array().is_some_and(|mounts| {
                mounts
                    .iter()
                    .any(|mount| mount["name"] == NETWORK_CA_VOLUME)
            })
        })
        .collect::<Vec<_>>();
    if expected_container == "openshell-network" {
        let [network_init] = trust_init_containers.as_slice() else {
            return Err(format!(
                "expected trust only at the network-init boundary: {trust_init_containers:#?}"
            ));
        };
        if network_init["name"] != "openshell-network-init" {
            return Err(format!(
                "destination CA mounted in unexpected init container: {network_init:#?}"
            ));
        }
        let init_digest = network_ca_command_digest(
            network_init["command"]
                .as_array()
                .ok_or("network-init command missing")?,
        )?;
        if init_digest != supervisor_digest {
            return Err("network-init and supervisor trust digests differ".to_string());
        }
    } else if !trust_init_containers.is_empty() {
        return Err("destination CA leaked outside the network supervisor boundary".to_string());
    }

    let volume = pod["spec"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|volume| volume["name"] == NETWORK_CA_VOLUME)
        .unwrap();
    let managed_name = volume["configMap"]["name"]
        .as_str()
        .ok_or("managed destination CA ConfigMap name missing")?;
    let config_map = kubectl_json(&[
        "-n",
        &namespace,
        "get",
        "configmap",
        managed_name,
        "-o",
        "json",
    ])?;
    if config_map["metadata"]["labels"]["openshell.ai/managed-by"] != "openshell"
        || config_map["data"]["ca.crt"].as_str().is_none()
    {
        return Err("managed destination CA ConfigMap metadata/data is incomplete".to_string());
    }
    let config_map_digest =
        config_map["metadata"]["annotations"]["openshell.ai/network-additional-ca-generation"]
            .as_str()
            .ok_or("managed destination CA ConfigMap generation missing")?;
    if supervisor_digest != config_map_digest {
        return Err("supervisor digest does not match managed ConfigMap generation".to_string());
    }
    Ok(format!("{namespace}/{managed_name}/{pod_name}"))
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
    let mut overlays = std::fs::read_dir(state_dir.join("sandboxes"))
        .map_err(|error| format!("read VM sandbox state: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("overlay.ext4"))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    overlays.sort();
    let [overlay] = overlays.as_slice() else {
        return Err(format!(
            "expected one VM sandbox overlay, found {overlays:?}"
        ));
    };

    let debugfs_read = |guest_path: &str| -> Result<Vec<u8>, String> {
        let output = Command::new("debugfs")
            .args(["-R", &format!("cat {guest_path}")])
            .arg(overlay)
            .output()
            .map_err(|error| format!("run debugfs overlay inspection: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "debugfs overlay inspection failed for {guest_path}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(output.stdout)
    };

    let staged = debugfs_read("/upper/etc/openshell-tls/network-additional-ca.crt")?;
    let source = std::fs::read(&source_ca)
        .map_err(|error| format!("read additional CA source for digest comparison: {error}"))?;
    if Sha256::digest(&staged) != Sha256::digest(&source) {
        return Err(
            "VM overlay destination CA digest does not match normalized source".to_string(),
        );
    }

    let args = String::from_utf8(debugfs_read("/upper/opt/openshell/supervisor-args")?)
        .map_err(|error| format!("VM supervisor argument marker is not UTF-8: {error}"))?;
    let lines = args.lines().collect::<Vec<_>>();
    let staged_digest = format!("sha256:{:x}", Sha256::digest(&staged));
    if lines
        != [
            "--network-additional-ca-bundle",
            NETWORK_CA_PATH,
            "--network-additional-ca-digest",
            &staged_digest,
        ]
    {
        return Err(format!(
            "unexpected VM supervisor argument marker: {lines:?}"
        ));
    }

    let console = overlay
        .parent()
        .expect("overlay has sandbox state parent")
        .join("rootfs-console.log");
    let console = std::fs::read_to_string(&console)
        .map_err(|error| format!("read VM serial log: {error}"))?;
    if !console.contains("supervisor arguments from driver: 4 entries") {
        return Err("VM serial log did not confirm driver-owned supervisor argv".to_string());
    }
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
        normalized_startup_error.contains("--network-additional-ca-bundle")
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

fn hostname_validation_script(
    matching_url: &str,
    mismatch_url: &str,
    mismatch_connect: &str,
) -> String {
    format!(
        r#"set -eu
response="$(curl --fail --silent --show-error --max-time 30 '{matching_url}')"
test "$response" = '{{"additional_ca":"trusted"}}'
set +e
curl --fail --silent --show-error --verbose --max-time 15 --connect-to '{mismatch_connect}' '{mismatch_url}' >/tmp/mismatch.out 2>/tmp/mismatch.err
mismatch_status=$?
set -e
# --connect-to proves the mismatch uses the same reachable fixture as the
# matching request, while preserving the mismatch URL and TLS SNI. The
# fixture's private CA is trusted, so curl status 60 must specifically be its
# hostname-verification failure, not an untrusted issuer or routing error.
if [ "$mismatch_status" -ne 60 ]; then
  echo "hostname mismatch returned curl status $mismatch_status, expected 60" >&2
  cat /tmp/mismatch.err >&2
  exit 1
fi
if ! grep -Fq "no alternative certificate subject name matches target host name '{MISMATCH_HOST}'" /tmp/mismatch.err; then
  echo "hostname mismatch did not report hostname verification failure" >&2
  cat /tmp/mismatch.err >&2
  exit 1
fi
curl --fail --silent --show-error --max-time 30 https://example.com/ >/dev/null
echo matching-host-trusted
echo hostname-mismatch-rejected
echo public-root-trusted
echo {READY_MARKER}
while true; do sleep 1; done"#,
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
    let mismatch_url = format!("https://{MISMATCH_HOST}:{port}/");
    let mismatch_connect = format!("{MISMATCH_HOST}:{port}:host.openshell.internal:{port}");
    let script = hostname_validation_script(&matching_url, &mismatch_url, &mismatch_connect);

    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", policy_path],
        &["sh", "-lc", &script],
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
        let output = sandbox
            .exec(&[
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                &matching_url,
            ])
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
            &["sh", "-lc", &script],
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
    let private_ca_output = lifecycle_sandbox
        .exec(&[
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            &matching_url,
        ])
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
        r#"set -eu
test "$(cat {LIFECYCLE_DURABLE_PATH})" = "{LIFECYCLE_DURABLE_MARKER}"
test ! -e '{NETWORK_CA_PATH}'
set +e
curl --fail --silent --show-error --max-time 30 '{matching_url}' >/tmp/removed.out 2>/tmp/removed.err
removed_status=$?
set -e
if [ "$removed_status" -eq 0 ]; then
  echo "private CA remained trusted after configuration removal" >&2
  exit 1
fi
echo gateway-authenticated-exec-works
echo same-sandbox-private-ca-rejected"#
    );
    let removed_validation_output = lifecycle_sandbox
        .exec(&["sh", "-lc", &removed_validation_script])
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
