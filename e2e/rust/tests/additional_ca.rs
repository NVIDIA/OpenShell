// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-backed e2e coverage for the global network-supervisor additional CA.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::cli::wait_for_healthy;
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
const NETWORK_CA_VOLUME: &str = "openshell-network-additional-ca";
const UPSTREAM_HOSTNAME_VALIDATION_DIAGNOSTIC: &str = "upstream TLS hostname validation failed";

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

fn assert_network_ca_command(command: &[Value]) -> Result<(), String> {
    let pairs = command
        .windows(2)
        .filter(|pair| pair[0] == "--network-additional-ca-bundle")
        .collect::<Vec<_>>();
    if pairs.len() != 1 || pairs[0][1] != NETWORK_CA_PATH {
        return Err(format!(
            "unexpected network CA command arguments: {command:#?}"
        ));
    }
    Ok(())
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
    assert_network_ca_command(
        mounted[0]["command"]
            .as_array()
            .ok_or("supervisor command missing")?,
    )?;
    for init in pod["spec"]["initContainers"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if init["volumeMounts"].as_array().is_some_and(|mounts| {
            mounts
                .iter()
                .any(|mount| mount["name"] == NETWORK_CA_VOLUME)
        }) {
            return Err("destination CA leaked into an init container".to_string());
        }
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
    if lines != ["--network-additional-ca-bundle", NETWORK_CA_PATH] {
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
    if !console.contains("supervisor arguments from driver: 2 entries") {
        return Err("VM serial log did not confirm driver-owned supervisor argv".to_string());
    }
    if console.contains("-----BEGIN CERTIFICATE-----") {
        return Err("VM serial log disclosed certificate material".to_string());
    }
    Ok(())
}

fn supervisor_hostname_validation_seen(output: &str) -> bool {
    output.contains(UPSTREAM_HOSTNAME_VALIDATION_DIAGNOSTIC)
        && output.contains(MISMATCH_HOST)
        && !output.contains("-----BEGIN CERTIFICATE-----")
}

#[cfg(feature = "e2e-vm")]
fn vm_supervisor_output() -> Result<String, String> {
    let state_dir = std::env::var("OPENSHELL_E2E_VM_STATE_DIR")
        .map_err(|error| format!("VM state directory missing: {error}"))?;
    let mut output = String::new();
    for entry in std::fs::read_dir(std::path::Path::new(&state_dir).join("sandboxes"))
        .map_err(|error| format!("read VM sandbox state: {error}"))?
        .filter_map(Result::ok)
    {
        let console = entry.path().join("rootfs-console.log");
        if console.is_file() {
            output.push_str(
                &std::fs::read_to_string(&console).map_err(|error| {
                    format!("read VM serial log {}: {error}", console.display())
                })?,
            );
        }
    }
    Ok(output)
}

#[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
fn local_supervisor_output(driver: &str, sandbox_name: &str) -> Result<String, String> {
    let container_engine = ContainerEngine::from_env().map_err(|error| error.clone())?;
    let network = std::env::var("OPENSHELL_E2E_NETWORK_NAME")
        .or_else(|_| std::env::var("OPENSHELL_E2E_DOCKER_NETWORK_NAME"))
        .map_err(|error| format!("wrapper must export sandbox network: {error}"))?;
    let output = engine_command(&container_engine)
        .args(["ps", "-aq", "--filter"])
        .arg(format!("network={network}"))
        .output()
        .map_err(|error| format!("run {driver} ps for supervisor diagnostic: {error}"))?;
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
    let output = engine_command(&container_engine)
        .args(["logs", container_id])
        .output()
        .map_err(|error| format!("read {driver} supervisor log: {error}"))?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn kubernetes_supervisor_output(identity: &str) -> Result<String, String> {
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let _config_map = parts.next().ok_or("ConfigMap name missing")?;
    let pod = parts.next().ok_or("pod name missing")?;
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    let output = Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            namespace,
            "logs",
            pod,
            "--all-containers=true",
        ])
        .output()
        .map_err(|error| format!("read Kubernetes supervisor log: {error}"))?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn assert_supervisor_rejected_hostname_mismatch(
    driver: &str,
    sandbox_name: &str,
    kubernetes_identity: Option<&str>,
) -> Result<(), String> {
    // The workload's curl output only proves the client-to-supervisor MITM
    // leg. Require the supervisor's explicit *upstream* hostname-validation
    // diagnostic as well, so a direct fixture-leaf rejection cannot satisfy
    // this test.
    for _ in 0..30 {
        let output = match driver {
            "vm" => {
                #[cfg(feature = "e2e-vm")]
                {
                    vm_supervisor_output()
                }
                #[cfg(not(feature = "e2e-vm"))]
                {
                    Err("VM test compiled without e2e-vm feature".to_string())
                }
            }
            "docker" | "podman" => {
                #[cfg(any(feature = "e2e-docker", feature = "e2e-podman"))]
                {
                    local_supervisor_output(driver, sandbox_name)
                }
                #[cfg(not(any(feature = "e2e-docker", feature = "e2e-podman")))]
                {
                    Err("local-driver test compiled without its driver feature".to_string())
                }
            }
            "kubernetes" => kubernetes_supervisor_output(
                kubernetes_identity.ok_or("Kubernetes staging identity missing")?,
            ),
            other => return Err(format!("unsupported driver {other}")),
        }?;
        if supervisor_hostname_validation_seen(&output) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "{driver} supervisor never reported upstream hostname validation for {MISMATCH_HOST}"
    ))
}

fn replace_staged_material(driver: &str, kubernetes_identity: Option<&str>) -> Result<(), String> {
    if driver == "kubernetes" {
        return replace_kubernetes_config_map_with_invalid_material(
            kubernetes_identity.ok_or("Kubernetes staging identity missing")?,
        );
    }

    let artifact = std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_ARTIFACT")
        .map_err(|error| format!("gateway-owned CA artifact path missing: {error}"))?;
    if !std::path::Path::new(&artifact).is_file() {
        return Err(format!(
            "gateway-owned CA artifact does not exist: {artifact}"
        ));
    }
    std::fs::write(&artifact, b"not-a-certificate\n")
        .map_err(|error| format!("replace gateway-owned CA artifact: {error}"))
}

fn restart_kubernetes_sandbox_from_existing_resource(identity: &str) -> Result<String, String> {
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let _config_map = parts.next().ok_or("ConfigMap name missing")?;
    let pod = parts.next().ok_or("pod name missing")?;
    let previous = kubectl_json(&["-n", namespace, "get", "pod", pod, "-o", "json"])?;
    let previous_uid = previous["metadata"]["uid"]
        .as_str()
        .ok_or("original pod UID missing")?
        .to_string();
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    // Delete only the workload Pod. Its existing OpenShell Sandbox resource
    // remains managed by the controller and recreates the Pod, avoiding a new
    // driver `ensure`/server-side-apply request against our deliberately
    // mutated ConfigMap.
    let output = Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            namespace,
            "delete",
            "pod",
            pod,
            "--wait=false",
        ])
        .output()
        .map_err(|error| format!("restart existing Kubernetes sandbox pod: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "restart existing Kubernetes sandbox pod failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(previous_uid)
}

fn recreated_kubernetes_pod(identity: &str, previous_uid: &str) -> Result<String, String> {
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let config_map = parts.next().ok_or("ConfigMap name missing")?;
    let _previous_pod = parts.next().ok_or("pod name missing")?;
    let pods = kubectl_json(&["-n", namespace, "get", "pods", "-o", "json"])?;
    pods["items"]
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|pod| {
                let uses_config_map = pod["spec"]["volumes"].as_array().is_some_and(|volumes| {
                    volumes
                        .iter()
                        .any(|volume| volume["configMap"]["name"].as_str() == Some(config_map))
                });
                let uid = pod["metadata"]["uid"].as_str()?;
                let name = pod["metadata"]["name"].as_str()?;
                (uses_config_map && uid != previous_uid).then(|| name.to_string())
            })
        })
        .ok_or_else(|| {
            "distinct recreated pod using destination CA ConfigMap not found".to_string()
        })
}

fn assert_kubernetes_invalid_staged_material_fails_closed(identity: &str) -> Result<(), String> {
    let previous_uid = restart_kubernetes_sandbox_from_existing_resource(identity)?;
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let _config_map = parts.next().ok_or("ConfigMap name missing")?;
    let _previous_pod = parts.next().ok_or("pod name missing")?;
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;

    for _ in 0..120 {
        if let Ok(pod) = recreated_kubernetes_pod(identity, &previous_uid) {
            let output = Command::new("kubectl")
                .args([
                    "--context",
                    &context,
                    "-n",
                    namespace,
                    "logs",
                    &pod,
                    "--all-containers=true",
                ])
                .output()
                .map_err(|error| format!("read restarted Kubernetes sandbox logs: {error}"))?;
            let logs = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if logs.contains("additional destination CA bundle")
                || logs.contains("invalid staged destination CA bundle")
            {
                if logs.contains("-----BEGIN CERTIFICATE-----")
                    || logs.contains("-----BEGIN PRIVATE KEY-----")
                {
                    return Err(
                        "Kubernetes supervisor validation log disclosed CA material".to_string()
                    );
                }
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(
        "recreated Kubernetes sandbox lacked stable supervisor additional-CA validation evidence"
            .to_string(),
    )
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
    assert!(
        startup_error.contains("--network-additional-ca-bundle")
            || startup_error.contains("additional destination CA bundle")
            || startup_error.contains("invalid staged destination CA bundle"),
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

async fn remove_configuration_and_restart(driver: &str) -> Result<(), String> {
    if driver == "kubernetes" {
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
    }

    wait_for_healthy(Duration::from_secs(180)).await
}

async fn assert_removed_configuration_rejects_private_ca(policy_path: &str, matching_url: &str) {
    const REMOVED_MARKER: &str = "additional-ca-removed-private-ca-rejected";
    let script = format!(
        r#"set -eu
test ! -e '{NETWORK_CA_PATH}'
set +e
curl --fail --silent --show-error --max-time 30 '{matching_url}' >/tmp/removed.out 2>/tmp/removed.err
removed_status=$?
set -e
if [ "$removed_status" -eq 0 ]; then
  echo "private CA remained trusted after configuration removal" >&2
  exit 1
fi
echo {REMOVED_MARKER}
while true; do sleep 1; done"#
    );
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", policy_path],
        &["sh", "-lc", &script],
        REMOVED_MARKER,
    )
    .await
    .expect("new sandbox rejects the removed private CA trust");
    assert!(sandbox.create_output.contains(REMOVED_MARKER));
    sandbox.cleanup().await;
}

fn replace_kubernetes_config_map_with_invalid_material(identity: &str) -> Result<(), String> {
    let mut parts = identity.split('/');
    let namespace = parts.next().ok_or("namespace missing")?;
    let config_map = parts.next().ok_or("ConfigMap name missing")?;
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .map_err(|error| format!("active Kubernetes context missing: {error}"))?;
    let patch = r#"{"data":{"ca.crt":"not-a-certificate"}}"#;
    let output = Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            namespace,
            "patch",
            "configmap",
            config_map,
            "--type=merge",
            "-p",
            patch,
        ])
        .output()
        .map_err(|error| format!("patch destination CA ConfigMap: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "patch destination CA ConfigMap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
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
    let script = format!(
        r#"set -eu
response="$(curl --fail --silent --show-error --max-time 30 '{matching_url}')"
test "$response" = '{{"additional_ca":"trusted"}}'
set +e
curl --fail --silent --show-error --verbose --max-time 15 --connect-to '{mismatch_connect}' '{mismatch_url}' >/tmp/mismatch.out 2>/tmp/mismatch.err
mismatch_status=$?
set -e
# The client must successfully validate OpenShell's generated MITM leaf for
# the requested hostname. A curl 60 here would only show that curl rejected a
# fixture leaf; the supervisor-specific upstream diagnostic is asserted below.
if [ "$mismatch_status" -eq 0 ] || [ "$mismatch_status" -eq 60 ]; then
  echo "hostname mismatch returned curl status $mismatch_status; expected post-MITM upstream failure" >&2
  cat /tmp/mismatch.err >&2
  exit 1
fi
if ! grep -Fq 'SSL certificate verify ok' /tmp/mismatch.err; then
  echo "hostname mismatch never completed TLS verification against the OpenShell MITM leaf" >&2
  cat /tmp/mismatch.err >&2
  exit 1
fi
curl --fail --silent --show-error --max-time 30 https://example.com/ >/dev/null
echo matching-host-trusted
echo hostname-mismatch-rejected
echo public-root-trusted
echo {READY_MARKER}
while true; do sleep 1; done"#
    );

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

    assert_supervisor_rejected_hostname_mismatch(
        driver,
        &sandbox.name,
        kubernetes_identity.as_deref(),
    )
    .expect("supervisor rejected the upstream hostname mismatch after client MITM verification");

    replace_staged_material(driver, kubernetes_identity.as_deref())
        .expect("replace staged destination trust with invalid material");
    if driver == "kubernetes" {
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
            .expect("running supervisor retains startup trust until restart");
        assert!(
            output.contains(r#"{"additional_ca":"trusted"}"#),
            "running supervisor lost startup trust after ConfigMap update: {output}"
        );
    }

    if driver == "kubernetes" {
        assert_kubernetes_invalid_staged_material_fails_closed(
            kubernetes_identity
                .as_deref()
                .expect("Kubernetes staging identity must be present"),
        )
        .expect("recreated existing Kubernetes sandbox rejects invalid staged trust");
    } else {
        assert_invalid_staged_material_fails_closed(policy_path).await;
    }

    sandbox.cleanup().await;
    remove_configuration_and_restart(driver)
        .await
        .expect("remove additional CA configuration and restart gateway");
    assert_removed_configuration_rejects_private_ca(policy_path, &matching_url).await;
}
