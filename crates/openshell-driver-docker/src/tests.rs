// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::compute::v1::{
    DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
};
use std::fs;
use tempfile::TempDir;

const TLS_MOUNT_DIR: &str = "/etc/openshell/tls/client";

fn test_sandbox() -> DriverSandbox {
    // Mirrors the gateway-supplied request: the public `Sandbox` API no
    // longer carries `namespace`, so the gateway elides the field and the
    // driver must source it from its own runtime config.
    DriverSandbox {
        id: "sbx-123".to_string(),
        name: "demo".to_string(),
        namespace: String::new(),
        spec: Some(DriverSandboxSpec {
            log_level: "debug".to_string(),
            environment: HashMap::from([("SPEC_ENV".to_string(), "spec".to_string())]),
            template: Some(DriverSandboxTemplate {
                image: "ghcr.io/nvidia/openshell/sandbox:dev".to_string(),
                agent_socket_path: String::new(),
                labels: HashMap::new(),
                environment: HashMap::from([("TEMPLATE_ENV".to_string(), "template".to_string())]),
                resources: None,
                platform_config: None,
            }),
            gpu: false,
            gpu_device: String::new(),
        }),
        status: None,
    }
}

fn runtime_config() -> DockerDriverRuntimeConfig {
    DockerDriverRuntimeConfig {
        default_image: "image:latest".to_string(),
        image_pull_policy: String::new(),
        sandbox_namespace: "default".to_string(),
        grpc_endpoint: "https://localhost:8443".to_string(),
        ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
        stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
        log_level: "info".to_string(),
        supervisor_bin: PathBuf::from("/tmp/openshell-sandbox"),
        guest_tls: Some(DockerGuestTlsPaths {
            ca: PathBuf::from("/tmp/ca.crt"),
            cert: PathBuf::from("/tmp/tls.crt"),
            key: PathBuf::from("/tmp/tls.key"),
        }),
        daemon_version: "28.0.0".to_string(),
        supports_gpu: false,
    }
}

#[test]
fn build_environment_preserves_loopback_endpoint_for_host_network() {
    let mut config = runtime_config();
    config.grpc_endpoint = "http://127.0.0.1:8080".to_string();

    let env = build_environment(&test_sandbox(), &config);
    assert!(env.contains(&"OPENSHELL_ENDPOINT=http://127.0.0.1:8080".to_string()));

    config.grpc_endpoint = "https://localhost:8443".to_string();
    let env = build_environment(&test_sandbox(), &config);
    assert!(env.contains(&"OPENSHELL_ENDPOINT=https://localhost:8443".to_string()));
}

#[test]
fn parse_cpu_limit_supports_cores_and_millicores() {
    assert_eq!(parse_cpu_limit("250m").unwrap(), Some(250_000_000));
    assert_eq!(parse_cpu_limit("2").unwrap(), Some(2_000_000_000));
    assert!(parse_cpu_limit("0").is_err());
}

#[test]
fn parse_memory_limit_supports_binary_quantities() {
    assert_eq!(parse_memory_limit("512Mi").unwrap(), Some(536_870_912));
    assert_eq!(parse_memory_limit("1G").unwrap(), Some(1_000_000_000));
    assert!(parse_memory_limit("12XB").is_err());
}

#[test]
fn docker_resource_limits_rejects_requests() {
    let template = DriverSandboxTemplate {
        image: "img".to_string(),
        agent_socket_path: String::new(),
        labels: HashMap::new(),
        environment: HashMap::new(),
        resources: Some(DriverResourceRequirements {
            cpu_request: "250m".to_string(),
            cpu_limit: String::new(),
            memory_request: String::new(),
            memory_limit: String::new(),
        }),
        platform_config: None,
    };

    let err = docker_resource_limits(&template).unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("resources.requests.cpu"));
}

#[test]
fn build_environment_sets_docker_tls_paths() {
    let env = build_environment(&test_sandbox(), &runtime_config());
    assert!(env.contains(&format!("OPENSHELL_TLS_CA={TLS_CA_MOUNT_PATH}")));
    assert!(env.contains(&format!("OPENSHELL_TLS_CERT={TLS_CERT_MOUNT_PATH}")));
    assert!(env.contains(&format!("OPENSHELL_TLS_KEY={TLS_KEY_MOUNT_PATH}")));
    assert!(env.contains(&"TEMPLATE_ENV=template".to_string()));
    assert!(env.contains(&"SPEC_ENV=spec".to_string()));
    assert!(env.contains(&"OPENSHELL_SANDBOX_COMMAND=sleep infinity".to_string()));
    assert!(
        !env.iter()
            .any(|entry| entry.starts_with("OPENSHELL_SSH_HANDSHAKE_SECRET="))
    );
    assert!(
        !env.iter()
            .any(|entry| entry.starts_with("OPENSHELL_SSH_HANDSHAKE_SKEW_SECS="))
    );
}

#[test]
fn build_mounts_uses_docker_tls_directory() {
    let mounts = build_mounts(&runtime_config());
    let targets = mounts
        .iter()
        .filter_map(|mount| mount.target.clone())
        .collect::<Vec<_>>();
    assert!(targets.contains(&SUPERVISOR_MOUNT_PATH.to_string()));
    assert!(targets.contains(&TLS_CA_MOUNT_PATH.to_string()));
    assert!(targets.contains(&TLS_CERT_MOUNT_PATH.to_string()));
    assert!(targets.contains(&TLS_KEY_MOUNT_PATH.to_string()));
    assert!(
        targets
            .iter()
            .all(|target| target.starts_with(TLS_MOUNT_DIR) || target == SUPERVISOR_MOUNT_PATH)
    );
}

#[test]
fn managed_container_label_filters_include_gateway_namespace() {
    let filters =
        managed_container_label_filters("tenant-a", [format!("{SANDBOX_ID_LABEL_KEY}=sbx-123")]);
    let labels = filters.get("label").unwrap();

    assert!(labels.contains(&format!("{MANAGED_BY_LABEL_KEY}={MANAGED_BY_LABEL_VALUE}")));
    assert!(labels.contains(&format!("{SANDBOX_NAMESPACE_LABEL_KEY}=tenant-a")));
    assert!(labels.contains(&format!("{SANDBOX_ID_LABEL_KEY}=sbx-123")));
}

#[test]
fn build_container_create_body_clears_inherited_cmd() {
    let create_body = build_container_create_body(&test_sandbox(), &runtime_config()).unwrap();

    assert_eq!(
        create_body.entrypoint,
        Some(vec![SUPERVISOR_MOUNT_PATH.to_string()])
    );
    assert_eq!(create_body.cmd, Some(Vec::new()));
    assert_eq!(
        create_body
            .labels
            .as_ref()
            .and_then(|labels| labels.get(SANDBOX_NAMESPACE_LABEL_KEY)),
        Some(&"default".to_string())
    );
    assert!(
        create_body
            .host_config
            .as_ref()
            .and_then(|host_config| host_config.device_requests.as_ref())
            .is_none(),
        "non-GPU containers should not request Docker devices"
    );
}

#[test]
fn validate_sandbox_rejects_gpu_when_cdi_unavailable() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().gpu = true;

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("Docker CDI"));
}

#[test]
fn build_container_create_body_maps_gpu_to_all_cdi_device() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().gpu = true;

    let create_body = build_container_create_body(&sandbox, &config).unwrap();
    let request = create_body
        .host_config
        .as_ref()
        .and_then(|host_config| host_config.device_requests.as_ref())
        .and_then(|requests| requests.first())
        .expect("GPU request should add a Docker device request");

    assert_eq!(request.driver.as_deref(), Some("cdi"));
    assert_eq!(
        request.device_ids.as_ref().unwrap(),
        &vec![CDI_GPU_DEVICE_ALL.to_string()]
    );
}

#[test]
fn require_sandbox_identifier_rejects_when_id_and_name_are_empty() {
    // Regression test: `delete_sandbox` (and the other identifier-keyed
    // RPCs) must refuse requests where both the id and the name are
    // empty. Otherwise the empty filters fed to
    // `find_managed_container_summary` match the first managed container
    // in the namespace, allowing an arbitrary sandbox to be deleted.
    let err = require_sandbox_identifier("", "").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("sandbox_id or sandbox_name"));

    require_sandbox_identifier("sbx-1", "").expect("id-only is accepted");
    require_sandbox_identifier("", "demo").expect("name-only is accepted");
    require_sandbox_identifier("sbx-1", "demo").expect("id and name is accepted");
}

#[test]
fn build_container_create_body_uses_host_network() {
    let create_body = build_container_create_body(&test_sandbox(), &runtime_config()).unwrap();
    let host_config = create_body.host_config.expect("host_config is populated");

    assert_eq!(
        host_config.network_mode,
        Some("host".to_string()),
        "sandbox must use host networking so 127.0.0.1 reaches the host gateway"
    );
    assert_eq!(
        host_config.extra_hosts,
        Some(vec!["host.openshell.internal:127.0.0.1".to_string()]),
        "sandbox should expose a stable host alias without host /etc/hosts edits"
    );
}

#[test]
fn build_container_create_body_uses_runtime_namespace_label() {
    // Regression test: the namespace label must come from the driver's
    // runtime config, not from `DriverSandbox.namespace`. The gateway
    // does not populate `DriverSandbox.namespace`, so a container created
    // with that empty value would not match subsequent list/get/find
    // queries (which filter on `config.sandbox_namespace`), leaking
    // sandboxes that the driver itself cannot observe.
    let mut config = runtime_config();
    config.sandbox_namespace = "tenant-a".to_string();
    let mut sandbox = test_sandbox();
    sandbox.namespace = "ignored-by-driver".to_string();

    let create_body = build_container_create_body(&sandbox, &config).unwrap();
    let labels = create_body.labels.expect("labels are populated");

    assert_eq!(
        labels.get(SANDBOX_NAMESPACE_LABEL_KEY),
        Some(&"tenant-a".to_string()),
        "namespace label must reflect the driver's runtime config"
    );
}

#[test]
fn driver_status_keeps_running_sandboxes_provisioning_with_stable_message() {
    let running = ContainerSummary {
        id: Some("cid".to_string()),
        names: Some(vec!["/openshell-demo".to_string()]),
        labels: Some(HashMap::from([
            (SANDBOX_ID_LABEL_KEY.to_string(), "sbx-1".to_string()),
            (SANDBOX_NAME_LABEL_KEY.to_string(), "demo".to_string()),
            (
                SANDBOX_NAMESPACE_LABEL_KEY.to_string(),
                "default".to_string(),
            ),
        ])),
        state: Some(ContainerSummaryStateEnum::RUNNING),
        status: Some("Up 2 seconds".to_string()),
        ..Default::default()
    };
    let exited = ContainerSummary {
        state: Some(ContainerSummaryStateEnum::EXITED),
        status: Some("Exited (1) 3 seconds ago".to_string()),
        ..running.clone()
    };
    let running_later = ContainerSummary {
        status: Some("Up 4 seconds".to_string()),
        ..running.clone()
    };

    let running_status = driver_status_from_summary(&running, "demo", false);
    let running_later_status = driver_status_from_summary(&running_later, "demo", false);
    assert_eq!(running_status.conditions[0].status, "False");
    assert_eq!(running_status.conditions[0].reason, "DependenciesNotReady");
    assert_eq!(
        running_status.conditions[0].message,
        "Container is running; waiting for supervisor relay"
    );
    assert_eq!(running_status.conditions, running_later_status.conditions);

    let exited_status = driver_status_from_summary(&exited, "demo", false);
    assert_eq!(exited_status.conditions[0].status, "False");
    assert_eq!(exited_status.conditions[0].reason, "ContainerExited");
    assert_eq!(exited_status.conditions[0].message, "Container exited");

    // With a live supervisor session, a RUNNING container flips Ready=True
    // so ExecSandbox and other "sandbox must be ready" gates can proceed.
    let running_connected = driver_status_from_summary(&running, "demo", true);
    assert_eq!(running_connected.conditions[0].status, "True");
    assert_eq!(
        running_connected.conditions[0].reason,
        "SupervisorConnected"
    );

    // Supervisor readiness is ignored for non-RUNNING states -- an exited
    // container must not report Ready=True.
    let exited_connected = driver_status_from_summary(&exited, "demo", true);
    assert_eq!(exited_connected.conditions[0].status, "False");
}

#[test]
fn driver_status_marks_restarting_sandboxes_as_error() {
    let restarting = ContainerSummary {
        id: Some("cid".to_string()),
        names: Some(vec!["/openshell-demo".to_string()]),
        labels: Some(HashMap::from([
            (SANDBOX_ID_LABEL_KEY.to_string(), "sbx-1".to_string()),
            (SANDBOX_NAME_LABEL_KEY.to_string(), "demo".to_string()),
            (
                SANDBOX_NAMESPACE_LABEL_KEY.to_string(),
                "default".to_string(),
            ),
        ])),
        state: Some(ContainerSummaryStateEnum::RESTARTING),
        status: Some("Restarting (1) 2 seconds ago".to_string()),
        ..Default::default()
    };

    let status = driver_status_from_summary(&restarting, "demo", false);
    assert_eq!(status.conditions[0].status, "False");
    assert_eq!(status.conditions[0].reason, "ContainerRestarting");
    assert_eq!(
        status.conditions[0].message,
        "Container is restarting after a failure"
    );
}

#[test]
fn validate_linux_elf_binary_rejects_non_elf_files() {
    let tempdir = TempDir::new().unwrap();
    let path = tempdir.path().join("openshell-sandbox");
    fs::write(&path, b"not-elf").unwrap();

    let err = validate_linux_elf_binary(&path).unwrap_err();
    assert!(err.to_string().contains("Linux ELF executable"));
}

#[test]
fn docker_guest_tls_paths_require_all_files_for_https() {
    let config = Config::new(None).with_grpc_endpoint("https://localhost:8443");
    let tempdir = TempDir::new().unwrap();
    let ca = tempdir.path().join("ca.crt");
    fs::write(&ca, b"ca").unwrap();

    let err = docker_guest_tls_paths(
        &config,
        &DockerComputeConfig {
            guest_tls_ca: Some(ca),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("--docker-tls-cert"));
}

#[test]
fn linux_supervisor_candidates_follow_daemon_arch() {
    assert_eq!(
        linux_supervisor_candidates("amd64"),
        vec![PathBuf::from(
            "target/x86_64-unknown-linux-gnu/release/openshell-sandbox",
        )]
    );
    assert_eq!(
        linux_supervisor_candidates("arm64"),
        vec![PathBuf::from(
            "target/aarch64-unknown-linux-gnu/release/openshell-sandbox",
        )]
    );
}

#[test]
fn container_name_preserves_id_suffix_for_long_names() {
    // Names up to 253 chars are permitted by the gRPC layer. The id
    // suffix is what makes the container name unique between sandboxes
    // sharing a prefix, so it must always appear in the final name.
    let long_name = "a".repeat(253);
    let first = DriverSandbox {
        id: "sbx-first-1234567890".to_string(),
        name: long_name,
        namespace: "default".to_string(),
        spec: None,
        status: None,
    };
    let second = DriverSandbox {
        id: "sbx-second-0987654321".to_string(),
        ..first.clone()
    };

    let first_container = container_name_for_sandbox(&first);
    let second_container = container_name_for_sandbox(&second);

    assert!(
        first_container.len() <= MAX_CONTAINER_NAME_LEN,
        "container name {} exceeded {MAX_CONTAINER_NAME_LEN} chars: {first_container}",
        first_container.len(),
    );
    assert!(
        first_container.ends_with(&first.id),
        "container name should end with sandbox id: {first_container}",
    );
    assert_ne!(
        first_container, second_container,
        "container names must differ for sandboxes with distinct ids",
    );
}

#[test]
fn container_name_empty_sandbox_name_uses_id_only() {
    let sandbox = DriverSandbox {
        id: "sbx-abc".to_string(),
        name: String::new(),
        namespace: "default".to_string(),
        spec: None,
        status: None,
    };
    assert_eq!(container_name_for_sandbox(&sandbox), "openshell-sbx-abc",);
}

#[test]
fn trim_container_name_tail_strips_separators() {
    assert_eq!(trim_container_name_tail("foo-".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo-.".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo_-.".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo".to_string()), "foo");
}

#[test]
fn docker_guest_tls_paths_rejects_tls_flags_without_https() {
    let config = Config::new(None).with_grpc_endpoint("http://localhost:8080");
    let tempdir = TempDir::new().unwrap();
    let ca = tempdir.path().join("ca.crt");
    fs::write(&ca, b"ca").unwrap();

    let err = docker_guest_tls_paths(
        &config,
        &DockerComputeConfig {
            guest_tls_ca: Some(ca),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("https://"));
}

#[test]
fn docker_guest_tls_paths_allows_plain_http_without_tls_flags() {
    let config = Config::new(None).with_grpc_endpoint("http://localhost:8080");
    let result = docker_guest_tls_paths(&config, &DockerComputeConfig::default()).unwrap();
    assert!(result.is_none());
}

#[test]
fn default_docker_supervisor_image_uses_nvidia_ghcr_repo() {
    let image = default_docker_supervisor_image();
    assert!(
        image.starts_with("ghcr.io/nvidia/openshell/supervisor:"),
        "unexpected default image reference: {image}",
    );
}

#[test]
fn docker_supervisor_image_tag_prefers_explicit_build_tags() {
    assert_eq!(
        resolve_default_docker_supervisor_image_tag(Some("1.2.3"), Some("sha"), "0.0.0"),
        "1.2.3",
    );
    assert_eq!(
        resolve_default_docker_supervisor_image_tag(None, Some("sha"), "0.0.0"),
        "sha",
    );
    assert_eq!(
        resolve_default_docker_supervisor_image_tag(None, None, "1.2.3"),
        "1.2.3",
    );
    assert_eq!(
        resolve_default_docker_supervisor_image_tag(Some(""), Some(""), "0.0.0"),
        "dev",
    );
}

#[test]
fn supervisor_cache_path_namespaces_by_digest_under_openshell_data_dir() {
    let base = PathBuf::from("/var/cache/share");
    let path =
        supervisor_cache_path_with_base(&base, "sha256:abc123deadbeef0123456789cafe0123456789fe");

    assert_eq!(
        path,
        PathBuf::from(
            "/var/cache/share/openshell/docker-supervisor/sha256-abc123deadbeef0123456789cafe0123456789fe/openshell-sandbox",
        ),
    );
}

#[test]
fn supervisor_cache_path_isolates_different_digests() {
    let base = PathBuf::from("/data");
    let left = supervisor_cache_path_with_base(&base, "sha256:aaaaaaaa");
    let right = supervisor_cache_path_with_base(&base, "sha256:bbbbbbbb");
    assert_ne!(
        left.parent().unwrap(),
        right.parent().unwrap(),
        "digest-keyed directories must differ so rollouts are isolated",
    );
}

#[test]
fn write_cache_binary_atomic_materializes_file_with_executable_mode() {
    let tempdir = TempDir::new().unwrap();
    let target = tempdir.path().join("nested").join("openshell-sandbox");
    fs::create_dir_all(target.parent().unwrap()).unwrap();

    write_cache_binary_atomic(&target, b"\x7fELFpayload").unwrap();

    assert!(target.is_file());
    assert_eq!(fs::read(&target).unwrap(), b"\x7fELFpayload");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0755, got {mode:04o}");
    }
}

#[test]
fn write_cache_binary_atomic_overwrites_existing_file() {
    let tempdir = TempDir::new().unwrap();
    let target = tempdir.path().join("openshell-sandbox");
    fs::write(&target, b"stale").unwrap();

    write_cache_binary_atomic(&target, b"\x7fELFfresh").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"\x7fELFfresh");
}

#[test]
fn temp_extract_container_names_are_unique_per_call() {
    let first = temp_extract_container_name();
    let second = temp_extract_container_name();
    assert_ne!(first, second);
    assert!(first.starts_with("openshell-supervisor-extract-"));
}

#[test]
fn extract_first_tar_entry_returns_payload_of_single_file_archive() {
    // Build a tar archive with the same shape Docker returns from
    // `/containers/<id>/archive` for a single file.
    let payload = b"\x7fELFtest-binary-bytes";
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        header.set_path("openshell-sandbox").unwrap();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, payload.as_slice()).unwrap();
        builder.finish().unwrap();
    }

    let extracted = extract_first_tar_entry(&tar_buf).unwrap();
    assert_eq!(extracted, payload);
}

#[test]
fn extract_first_tar_entry_rejects_empty_archive() {
    let mut tar_buf = Vec::new();
    tar::Builder::new(&mut tar_buf).finish().unwrap();
    let err = extract_first_tar_entry(&tar_buf).unwrap_err();
    assert!(err.contains("empty"), "unexpected error message: {err}");
}

#[test]
fn container_state_needs_resume_matches_startable_states() {
    for state in [
        ContainerSummaryStateEnum::EXITED,
        ContainerSummaryStateEnum::CREATED,
    ] {
        assert!(
            container_state_needs_resume(state),
            "{state:?} should be resumed with Docker start",
        );
    }

    for state in [
        ContainerSummaryStateEnum::RUNNING,
        ContainerSummaryStateEnum::RESTARTING,
        ContainerSummaryStateEnum::PAUSED,
        ContainerSummaryStateEnum::DEAD,
        ContainerSummaryStateEnum::REMOVING,
        ContainerSummaryStateEnum::EMPTY,
    ] {
        assert!(
            !container_state_needs_resume(state),
            "{state:?} should not be resumed with Docker start",
        );
    }
}
