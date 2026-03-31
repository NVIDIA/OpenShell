// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway error detection and user-friendly guidance.
//!
//! This module analyzes error messages and container logs to detect known
//! failure patterns and provide actionable recovery guidance.

/// A diagnosed gateway failure with user-friendly guidance.
#[derive(Debug, Clone)]
pub struct GatewayFailureDiagnosis {
    /// Short summary of what went wrong.
    pub summary: String,
    /// Detailed explanation of the issue.
    pub explanation: String,
    /// Commands or steps the user can take to fix the issue.
    pub recovery_steps: Vec<RecoveryStep>,
    /// Whether the issue might be auto-recoverable by retrying.
    pub retryable: bool,
}

/// A recovery step with a command and description.
#[derive(Debug, Clone)]
pub struct RecoveryStep {
    /// Description of what this step does.
    pub description: String,
    /// Command to run (if applicable).
    pub command: Option<String>,
}

impl RecoveryStep {
    fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            command: None,
        }
    }

    fn with_command(description: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            command: Some(command.into()),
        }
    }
}

/// How multiple matchers should be combined.
#[derive(Debug, Clone, Copy, Default)]
enum MatchMode {
    /// Match if ANY of the matchers is found (default).
    #[default]
    Any,
    /// Match only if ALL of the matchers are found.
    All,
}

/// Known failure patterns and their detection logic.
struct FailurePattern {
    /// Patterns to match in error message or logs.
    matchers: &'static [&'static str],
    /// How to combine multiple matchers (default: Any).
    match_mode: MatchMode,
    /// Function to generate diagnosis.
    diagnose: fn(gateway_name: &str) -> GatewayFailureDiagnosis,
}

const FAILURE_PATTERNS: &[FailurePattern] = &[
    // Corrupted cluster state / RBAC issues
    FailurePattern {
        matchers: &[
            "extension-apiserver-authentication",
            "cannot get resource",
            "is forbidden",
        ],
        match_mode: MatchMode::Any,
        diagnose: diagnose_corrupted_state,
    },
    // No default route (Docker networking)
    FailurePattern {
        matchers: &["no default route present"],
        match_mode: MatchMode::Any,
        diagnose: diagnose_no_default_route,
    },
    // Port already in use
    FailurePattern {
        matchers: &["port is already allocated", "address already in use"],
        match_mode: MatchMode::Any,
        diagnose: diagnose_port_conflict,
    },
    // Image pull failures (auth/registry issues)
    FailurePattern {
        matchers: &[
            "pull access denied",
            "image not found",
            "manifest unknown",
            "unauthorized to access repository",
            "denied: access forbidden",
        ],
        match_mode: MatchMode::Any,
        diagnose: diagnose_image_pull_auth_failure,
    },
    // k3s internal DNS proxy failure (must be before general network connectivity)
    // This happens when the k3s cluster starts but its internal DNS proxy can't resolve
    // external names, causing all image pulls to fail with "Try again" DNS errors.
    // The pattern "Try again" is a DNS EAGAIN error indicating temporary failure.
    // IMPORTANT: Both patterns must match to distinguish from other network issues.
    FailurePattern {
        matchers: &["dial tcp: lookup", "Try again"],
        match_mode: MatchMode::All,
        diagnose: diagnose_k3s_dns_proxy_failure,
    },
    // Network connectivity issues (DNS, timeouts, unreachable)
    FailurePattern {
        matchers: &[
            "no such host",
            "i/o timeout",
            "network is unreachable",
            "connection refused",
            "connection reset by peer",
            "TLS handshake timeout",
            "dial tcp",
            "lookup ghcr.io",
            "lookup registry",
            "no route to host",
            "temporary failure in name resolution",
        ],
        match_mode: MatchMode::Any,
        diagnose: diagnose_network_connectivity,
    },
    // OOM killed
    FailurePattern {
        matchers: &["exit_code=137", "OOMKilled"],
        match_mode: MatchMode::Any,
        diagnose: diagnose_oom_killed,
    },
    // Node resource pressure (DiskPressure, MemoryPressure, PIDPressure)
    FailurePattern {
        matchers: &["HEALTHCHECK_NODE_PRESSURE"],
        match_mode: MatchMode::Any,
        diagnose: diagnose_node_pressure,
    },
    // Missing sandbox supervisor binary
    FailurePattern {
        matchers: &["HEALTHCHECK_MISSING_SUPERVISOR"],
        match_mode: MatchMode::Any,
        diagnose: diagnose_missing_supervisor,
    },
    // TLS/certificate issues
    FailurePattern {
        matchers: &[
            "certificate has expired",
            "x509: certificate",
            "tls: failed to verify",
        ],
        match_mode: MatchMode::Any,
        diagnose: diagnose_certificate_issue,
    },
    // Docker daemon not running or socket not found
    FailurePattern {
        matchers: &[
            "Cannot connect to the Docker daemon",
            "docker daemon is not running",
            "Is the docker daemon running",
            "Socket not found",
            "No such file or directory",
            "Failed to create Docker client",
            "Docker socket exists but the daemon is not responding",
        ],
        match_mode: MatchMode::Any,
        diagnose: diagnose_docker_not_running,
    },
    // CDI specs missing — Docker daemon has CDI configured but no spec files exist
    // or the requested device ID (nvidia.com/gpu=all) is not in any spec.
    // Matches errors from Docker 25+ and containerd CDI injection paths.
    FailurePattern {
        matchers: &[
            "CDI device not found",
            "unknown CDI device",
            "failed to inject CDI devices",
            "no CDI devices found",
            "CDI device injection failed",
            "unresolvable CDI devices",
        ],
        match_mode: MatchMode::Any,
        diagnose: diagnose_cdi_specs_missing,
    },
];

fn diagnose_corrupted_state(gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Corrupted cluster state".to_string(),
        explanation: "The gateway cluster has corrupted internal state, likely from a previous \
            interrupted startup or unclean shutdown. Resources from the failed deploy have been \
            automatically cleaned up."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::new("Retry the gateway start (cleanup was automatic)"),
            RecoveryStep::with_command(
                "If the retry fails, manually destroy and recreate",
                format!(
                    "openshell gateway destroy --name {gateway_name} && openshell gateway start"
                ),
            ),
        ],
        retryable: true,
    }
}

fn diagnose_no_default_route(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Docker networking issue".to_string(),
        explanation: "The gateway container has no network route. This can happen when \
            another container is already bound to the same host port (Docker silently \
            skips network attachment), or due to stale Docker networks."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Check for containers using the same port",
                "docker ps --format '{{.Names}}\\t{{.Ports}}'",
            ),
            RecoveryStep::new(
                "Stop any container holding the gateway port (default 8080), then retry",
            ),
            RecoveryStep::with_command("Prune unused Docker networks", "docker network prune -f"),
            RecoveryStep::new("Restart your Docker runtime"),
            RecoveryStep::new("Then retry: openshell gateway start"),
        ],
        retryable: true,
    }
}

fn diagnose_port_conflict(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Port already in use".to_string(),
        explanation: "The gateway port is already in use by another process or container."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Check what's using the port",
                "lsof -i :8080 || netstat -an | grep 8080",
            ),
            RecoveryStep::with_command(
                "Use a different port",
                "openshell gateway start --port 8081",
            ),
            RecoveryStep::with_command(
                "Or stop other openshell gateways",
                "openshell gateway list && openshell gateway destroy --name <name>",
            ),
        ],
        retryable: false,
    }
}

fn diagnose_image_pull_auth_failure(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Registry authentication failed".to_string(),
        explanation: "Could not authenticate with the container registry. The image may not \
            exist, or you may not have permission to access it. Public GHCR repos \
            should not require authentication — if you see this error with the default \
            registry, it may indicate the image does not exist or a network issue."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Verify the image exists and you have access",
                "docker pull ghcr.io/nvidia/openshell/cluster:latest",
            ),
            RecoveryStep::new(
                "If using a private registry, set OPENSHELL_REGISTRY_USERNAME and OPENSHELL_REGISTRY_TOKEN \
                 (or use --registry-username and --registry-token)",
            ),
            RecoveryStep::with_command("Check your Docker login", "docker login ghcr.io"),
        ],
        retryable: false,
    }
}

fn diagnose_k3s_dns_proxy_failure(gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Cluster DNS resolution failed".to_string(),
        explanation: "The gateway cluster started but its internal DNS proxy cannot resolve \
            external hostnames. Docker's embedded DNS inside the container cannot reach \
            an upstream resolver. This is typically caused by Docker not being configured \
            with the host's DNS servers, stale Docker networking state, or (on Desktop) \
            DNS configuration issues."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Check your host's DNS servers",
                "resolvectl status | grep 'DNS Servers' -A2",
            ),
            RecoveryStep::with_command(
                "Configure Docker to use those DNS servers \
                 (add to /etc/docker/daemon.json, then restart Docker)",
                "echo '{\"dns\": [\"<your-dns-server-ip>\"]}' | sudo tee /etc/docker/daemon.json \
                 && sudo systemctl restart docker",
            ),
            RecoveryStep::with_command("Prune Docker networks", "docker network prune -f"),
            RecoveryStep::with_command(
                "Destroy and recreate the gateway",
                format!(
                    "openshell gateway destroy --name {gateway_name} && openshell gateway start"
                ),
            ),
        ],
        retryable: true,
    }
}

fn diagnose_network_connectivity(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Network connectivity issue".to_string(),
        explanation: "Could not reach the container registry. This could be a DNS resolution \
            failure, firewall blocking the connection, or general internet connectivity issue."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::new("Check your internet connection"),
            RecoveryStep::with_command("Test DNS resolution", "nslookup ghcr.io"),
            RecoveryStep::with_command("Test registry connectivity", "curl -I https://ghcr.io/v2/"),
            RecoveryStep::new(
                "If behind a corporate firewall/proxy, ensure Docker is configured to use it",
            ),
            RecoveryStep::new("Restart Docker and try again"),
        ],
        retryable: true,
    }
}

fn diagnose_oom_killed(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Container killed due to memory limits".to_string(),
        explanation: "The gateway container was killed because it exceeded memory limits. \
            The gateway requires at least 4GB of memory."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::new("Increase Docker memory allocation to at least 4GB"),
            RecoveryStep::new("Close other memory-intensive applications"),
            RecoveryStep::new("Then retry: openshell gateway start"),
        ],
        retryable: false,
    }
}

fn diagnose_node_pressure(gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Node under resource pressure".to_string(),
        explanation: "The cluster node is reporting a resource pressure condition \
            (DiskPressure, MemoryPressure, or PIDPressure). When a node is under \
            pressure the kubelet evicts running pods and rejects new pod scheduling, \
            so the gateway will never become healthy until the pressure is resolved."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command("Check available disk space on the host", "df -h /"),
            RecoveryStep::with_command(
                "Free disk space by pruning unused Docker resources",
                "docker system prune -a --volumes",
            ),
            RecoveryStep::with_command("Check available memory on the host", "free -h"),
            RecoveryStep::new("Increase Docker resource allocation or free resources on the host"),
            RecoveryStep::with_command(
                "Destroy and recreate the gateway after freeing resources",
                format!(
                    "openshell gateway destroy --name {gateway_name} && openshell gateway start"
                ),
            ),
        ],
        retryable: false,
    }
}

fn diagnose_missing_supervisor(gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Sandbox supervisor binary missing from cluster image".to_string(),
        explanation: "The sandbox supervisor binary (/opt/openshell/bin/openshell-sandbox) \
            was not found in the gateway container. This binary is side-loaded into every \
            sandbox pod via a hostPath volume mount. Without it, all sandbox pods will \
            crash immediately with \"no such file or directory\". This typically means the \
            cluster image was built or published without the supervisor-builder stage."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Rebuild the cluster image with the supervisor binary included",
                "mise run docker:build:cluster",
            ),
            RecoveryStep::with_command(
                "Destroy and recreate the gateway with the updated image",
                format!(
                    "openshell gateway destroy --name {gateway_name} && openshell gateway start"
                ),
            ),
            RecoveryStep::new(
                "Or set OPENSHELL_CLUSTER_IMAGE to a cluster image version that includes \
                the supervisor binary",
            ),
        ],
        retryable: false,
    }
}

fn diagnose_certificate_issue(gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "TLS certificate issue".to_string(),
        explanation: "There's a problem with the gateway's TLS certificates, possibly expired \
            or mismatched certificates from a previous installation."
            .to_string(),
        recovery_steps: vec![RecoveryStep::with_command(
            "Destroy and recreate the gateway to regenerate certificates",
            format!("openshell gateway destroy --name {gateway_name} && openshell gateway start"),
        )],
        retryable: false,
    }
}

fn diagnose_cdi_specs_missing(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "CDI specs not found on host".to_string(),
        explanation: "GPU passthrough via CDI was selected (your Docker daemon has CDI spec \
            directories configured) but no CDI device specs were found on the host. \
            Specs must be pre-generated before OpenShell can inject the GPU into the \
            cluster container."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Generate CDI specs on the host (nvidia-ctk creates /etc/cdi/ if it does not exist)",
                "sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml",
            ),
            RecoveryStep::with_command(
                "Verify the specs were generated and include nvidia.com/gpu entries",
                "nvidia-ctk cdi list",
            ),
            RecoveryStep::new("Then retry: openshell gateway start --gpu"),
        ],
        retryable: false,
    }
}

fn diagnose_docker_not_running(_gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Docker is not running".to_string(),
        explanation: "The Docker daemon is not running or not accessible. OpenShell requires \
            a Docker-compatible container runtime to manage gateway clusters."
            .to_string(),
        recovery_steps: vec![
            RecoveryStep::new("Start your Docker runtime"),
            RecoveryStep::with_command("Verify Docker is accessible", "docker info"),
            RecoveryStep::new(
                "If using a non-default Docker socket, set DOCKER_HOST:\n     \
                 export DOCKER_HOST=unix:///var/run/docker.sock",
            ),
            RecoveryStep::new("Then retry: openshell gateway start"),
        ],
        retryable: true,
    }
}

/// Analyze an error message and container logs to diagnose the failure.
///
/// Returns `Some(diagnosis)` if a known pattern is detected, `None` otherwise.
pub fn diagnose_failure(
    gateway_name: &str,
    error_message: &str,
    container_logs: Option<&str>,
) -> Option<GatewayFailureDiagnosis> {
    let combined = container_logs.map_or_else(
        || error_message.to_string(),
        |logs| format!("{error_message}\n{logs}"),
    );

    for pattern in FAILURE_PATTERNS {
        let matches = match pattern.match_mode {
            MatchMode::Any => pattern.matchers.iter().any(|m| combined.contains(m)),
            MatchMode::All => pattern.matchers.iter().all(|m| combined.contains(m)),
        };
        if matches {
            return Some((pattern.diagnose)(gateway_name));
        }
    }

    None
}

/// Create a generic diagnosis when no specific pattern is matched.
pub fn generic_failure_diagnosis(gateway_name: &str) -> GatewayFailureDiagnosis {
    GatewayFailureDiagnosis {
        summary: "Gateway failed to start".to_string(),
        explanation: "The gateway encountered an unexpected error during startup.".to_string(),
        recovery_steps: vec![
            RecoveryStep::with_command(
                "Check container logs for details",
                format!("openshell doctor logs --name {gateway_name}"),
            ),
            RecoveryStep::with_command(
                "Run diagnostics",
                format!("openshell doctor check --name {gateway_name}"),
            ),
            RecoveryStep::with_command(
                "Try destroying and recreating the gateway",
                format!(
                    "openshell gateway destroy --name {gateway_name} && openshell gateway start"
                ),
            ),
            RecoveryStep::new(
                "If the issue persists, report it at https://github.com/nvidia/openshell/issues",
            ),
        ],
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnose_corrupted_state() {
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready",
            Some("configmaps \"extension-apiserver-authentication\" is forbidden"),
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("Corrupted"));
    }

    #[test]
    fn test_diagnose_corrupted_state_is_retryable_after_auto_cleanup() {
        // After the auto-cleanup fix (#463), corrupted state errors should be
        // marked retryable because deploy_gateway_with_logs now automatically
        // cleans up Docker resources on failure.
        let d = diagnose_failure(
            "mygw",
            "K8s namespace not ready",
            Some("configmaps \"extension-apiserver-authentication\" is forbidden"),
        )
        .expect("should match corrupted state pattern");
        assert!(
            d.retryable,
            "corrupted state should be retryable after auto-cleanup"
        );
        assert!(
            d.explanation.contains("automatically cleaned up"),
            "explanation should mention automatic cleanup, got: {}",
            d.explanation
        );
    }

    #[test]
    fn test_diagnose_corrupted_state_recovery_no_manual_volume_rm() {
        // The recovery steps should no longer include a manual docker volume rm
        // command, since cleanup is now automatic. The first step should tell
        // the user to simply retry.
        let d = diagnose_failure("mygw", "cannot get resource \"namespaces\"", None)
            .expect("should match corrupted state pattern");

        let all_commands: Vec<String> = d
            .recovery_steps
            .iter()
            .filter_map(|s| s.command.clone())
            .collect();
        let all_commands_joined = all_commands.join(" ");

        assert!(
            !all_commands_joined.contains("docker volume rm"),
            "recovery steps should not include manual docker volume rm, got: {all_commands_joined}"
        );

        // First step should be a description-only step (no command) about retrying
        assert!(
            d.recovery_steps[0].command.is_none(),
            "first recovery step should be description-only (automatic cleanup)"
        );
        assert!(
            d.recovery_steps[0]
                .description
                .contains("cleanup was automatic"),
            "first recovery step should mention automatic cleanup"
        );
    }

    #[test]
    fn test_diagnose_corrupted_state_fallback_step_includes_gateway_name() {
        // The fallback recovery step should interpolate the gateway name so
        // users can copy-paste the command.
        let d = diagnose_failure("my-gateway", "is forbidden", None)
            .expect("should match corrupted state pattern");

        assert!(
            d.recovery_steps.len() >= 2,
            "should have at least 2 recovery steps"
        );
        let fallback = &d.recovery_steps[1];
        let cmd = fallback
            .command
            .as_deref()
            .expect("fallback step should have a command");
        assert!(
            cmd.contains("my-gateway"),
            "fallback command should contain gateway name, got: {cmd}"
        );
        assert!(
            cmd.contains("openshell gateway destroy"),
            "fallback command should include gateway destroy, got: {cmd}"
        );
    }

    #[test]
    fn test_diagnose_no_default_route() {
        let diagnosis = diagnose_failure(
            "test",
            "container exited with code 1",
            Some("Error: no default route present before starting k3s"),
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("networking"));
    }

    #[test]
    fn test_diagnose_port_conflict() {
        let diagnosis = diagnose_failure("test", "port is already allocated", None);
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("Port"));
    }

    #[test]
    fn test_no_match_returns_none() {
        let diagnosis = diagnose_failure("test", "some random error", Some("random logs"));
        assert!(diagnosis.is_none());
    }

    #[test]
    fn test_diagnose_k3s_dns_proxy_failure_both_patterns() {
        // Should match when BOTH patterns are present
        let diagnosis = diagnose_failure(
            "test",
            "failed to pull image",
            Some("dial tcp: lookup registry-1.docker.io: Try again"),
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("DNS"));
        assert!(d.retryable);
    }

    #[test]
    fn test_diagnose_k3s_dns_proxy_failure_requires_both_patterns() {
        // Should NOT match with only "dial tcp: lookup" (falls through to network connectivity)
        let diagnosis = diagnose_failure(
            "test",
            "failed to pull image",
            Some("dial tcp: lookup registry-1.docker.io: connection refused"),
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        // Should match the general network connectivity pattern, not k3s DNS
        assert!(d.summary.contains("Network connectivity"));

        // Should NOT match with only "Try again" (no match at all since it's too generic)
        let diagnosis = diagnose_failure("test", "Try again later", None);
        assert!(diagnosis.is_none());
    }

    #[test]
    fn test_diagnose_node_pressure_disk() {
        let diagnosis = diagnose_failure(
            "test",
            "HEALTHCHECK_NODE_PRESSURE: DiskPressure\n\
             The cluster node is under resource pressure.",
            None,
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("pressure"),
            "expected pressure diagnosis, got: {}",
            d.summary
        );
        assert!(!d.retryable);
    }

    #[test]
    fn test_diagnose_node_pressure_from_container_logs() {
        let diagnosis = diagnose_failure(
            "test",
            "gateway health check reported unhealthy",
            Some("HEALTHCHECK_NODE_PRESSURE: MemoryPressure"),
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("pressure"),
            "expected pressure diagnosis, got: {}",
            d.summary
        );
    }

    #[test]
    fn test_diagnose_docker_not_running() {
        let diagnosis = diagnose_failure("test", "Cannot connect to the Docker daemon", None);
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("Docker"));
        assert!(d.retryable);
    }

    #[test]
    fn test_diagnose_docker_socket_not_found() {
        let diagnosis = diagnose_failure("test", "Socket not found: /var/run/docker.sock", None);
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("Docker"));
        assert!(d.retryable);
    }

    #[test]
    fn test_diagnose_docker_no_such_file() {
        let diagnosis = diagnose_failure("test", "No such file or directory (os error 2)", None);
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("Docker"));
    }

    #[test]
    fn test_diagnose_docker_preflight_error() {
        let diagnosis = diagnose_failure(
            "test",
            "Failed to create Docker client.\n\n  connection error",
            None,
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(d.summary.contains("Docker"));
        assert!(d.retryable);
    }

    #[test]
    fn test_diagnose_docker_recovery_mentions_docker_host() {
        let diagnosis = diagnose_failure("test", "Cannot connect to the Docker daemon", None);
        let d = diagnosis.unwrap();
        let steps_text: String = d
            .recovery_steps
            .iter()
            .map(|s| s.description.clone())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            steps_text.contains("DOCKER_HOST"),
            "recovery steps should mention DOCKER_HOST"
        );
    }

    #[test]
    fn test_diagnose_dns_failure_from_namespace_timeout() {
        // When wait_for_namespace detects DNS failure, the error message itself
        // (not container logs) contains the DNS markers. The diagnose_failure
        // function must match these from the error_message parameter alone,
        // since container_logs may be None in this path.
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready\n\nCaused by:\n    dial tcp: lookup registry: Try again\n    DNS resolution is failing inside the gateway container.",
            None,
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("DNS"),
            "expected DNS diagnosis, got: {}",
            d.summary
        );
        assert!(d.retryable);
    }

    // -- generic_failure_diagnosis tests --

    #[test]
    fn generic_diagnosis_suggests_doctor_logs() {
        let d = generic_failure_diagnosis("my-gw");
        let commands: Vec<String> = d
            .recovery_steps
            .iter()
            .filter_map(|s| s.command.clone())
            .collect();
        assert!(
            commands.iter().any(|c| c.contains("openshell doctor logs")),
            "expected 'openshell doctor logs' in recovery commands, got: {commands:?}"
        );
    }

    #[test]
    fn generic_diagnosis_suggests_doctor_check() {
        let d = generic_failure_diagnosis("my-gw");
        let commands: Vec<String> = d
            .recovery_steps
            .iter()
            .filter_map(|s| s.command.clone())
            .collect();
        assert!(
            commands
                .iter()
                .any(|c| c.contains("openshell doctor check")),
            "expected 'openshell doctor check' in recovery commands, got: {commands:?}"
        );
    }

    #[test]
    fn generic_diagnosis_includes_gateway_name() {
        let d = generic_failure_diagnosis("custom-name");
        let all_text: String = d
            .recovery_steps
            .iter()
            .filter_map(|s| s.command.clone())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            all_text.contains("custom-name"),
            "expected gateway name in recovery commands, got: {all_text}"
        );
    }

    // -- fallback behavior tests --

    #[test]
    fn namespace_timeout_without_logs_returns_none() {
        // This is the most common user-facing error: a plain timeout with only
        // kubectl output. It must NOT match any specific pattern so the caller
        // can fall back to generic_failure_diagnosis.
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready\n\nCaused by:\n    \
             timed out waiting for namespace 'openshell' to exist: \
             error: the server doesn't have a resource type \"namespace\"",
            None,
        );
        assert!(
            diagnosis.is_none(),
            "plain namespace timeout should not match any specific pattern, got: {:?}",
            diagnosis.map(|d| d.summary)
        );
    }

    #[test]
    fn namespace_timeout_with_pressure_logs_matches() {
        // When container logs reveal node pressure, the diagnosis engine
        // should detect it even though the error message itself is generic.
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready\n\nCaused by:\n    \
             timed out waiting for namespace 'openshell' to exist: <kubectl output>",
            Some("HEALTHCHECK_NODE_PRESSURE: DiskPressure"),
        );
        assert!(diagnosis.is_some(), "expected node pressure diagnosis");
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("pressure"),
            "expected pressure in summary, got: {}",
            d.summary
        );
    }

    #[test]
    fn namespace_timeout_with_corrupted_state_logs_matches() {
        // Container logs revealing RBAC corruption should be caught.
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready\n\nCaused by:\n    \
             timed out waiting for namespace 'openshell' to exist: <output>",
            Some(
                "configmaps \"extension-apiserver-authentication\" is forbidden: \
                 User cannot get resource",
            ),
        );
        assert!(diagnosis.is_some(), "expected corrupted state diagnosis");
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("Corrupted"),
            "expected Corrupted in summary, got: {}",
            d.summary
        );
    }

    #[test]
    fn namespace_timeout_with_no_route_logs_matches() {
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready",
            Some("Error: no default route present before starting k3s"),
        );
        assert!(diagnosis.is_some(), "expected networking diagnosis");
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("networking"),
            "expected networking in summary, got: {}",
            d.summary
        );
    }

    #[test]
    fn diagnose_failure_with_logs_uses_combined_text() {
        // Verify that diagnose_failure combines error_message + container_logs
        // for pattern matching. The pattern "connection refused" is in logs,
        // not in the error message.
        let diagnosis = diagnose_failure(
            "test",
            "K8s namespace not ready",
            Some("dial tcp 127.0.0.1:6443: connect: connection refused"),
        );
        assert!(
            diagnosis.is_some(),
            "expected diagnosis from container logs pattern"
        );
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("Network") || d.summary.contains("connectivity"),
            "expected network diagnosis, got: {}",
            d.summary
        );
    }

    // -- end-to-end fallback pattern (mirrors CLI code) --

    #[test]
    fn fallback_to_generic_produces_actionable_diagnosis() {
        // This mirrors the actual CLI pattern:
        //   diagnose_failure(...).unwrap_or_else(|| generic_failure_diagnosis(name))
        // For a plain namespace timeout with no useful container logs, the
        // specific matcher returns None and we must fall back to the generic
        // diagnosis that suggests doctor commands.
        let err_str = "K8s namespace not ready\n\nCaused by:\n    \
                        timed out waiting for namespace 'openshell' to exist: \
                        error: the server doesn't have a resource type \"namespace\"";
        let container_logs = Some("k3s is starting\nwaiting for kube-apiserver");

        let diagnosis = diagnose_failure("my-gw", err_str, container_logs)
            .unwrap_or_else(|| generic_failure_diagnosis("my-gw"));

        // Should have gotten the generic diagnosis (no specific pattern matched)
        assert_eq!(diagnosis.summary, "Gateway failed to start");
        // Must contain actionable recovery steps
        assert!(
            !diagnosis.recovery_steps.is_empty(),
            "generic diagnosis should have recovery steps"
        );
        // Must mention doctor commands
        let all_commands: String = diagnosis
            .recovery_steps
            .iter()
            .filter_map(|s| s.command.as_ref())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            all_commands.contains("doctor logs"),
            "should suggest 'doctor logs', got: {all_commands}"
        );
        assert!(
            all_commands.contains("doctor check"),
            "should suggest 'doctor check', got: {all_commands}"
        );
        assert!(
            all_commands.contains("my-gw"),
            "commands should include gateway name, got: {all_commands}"
        );
    }

    #[test]
    fn test_diagnose_cdi_device_not_found() {
        let diagnosis = diagnose_failure(
            "test",
            "could not run container: CDI device not found: nvidia.com/gpu=all",
            None,
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("CDI"),
            "expected CDI diagnosis, got: {}",
            d.summary
        );
        assert!(!d.retryable);
    }

    #[test]
    fn test_diagnose_cdi_injection_failed_unresolvable() {
        // Exact error observed from Docker 500 response
        let diagnosis = diagnose_failure(
            "test",
            "Docker responded with status code 500: CDI device injection failed: unresolvable CDI devices nvidia.com/gpu=all",
            None,
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("CDI"),
            "expected CDI diagnosis, got: {}",
            d.summary
        );
        assert!(!d.retryable);
    }

    #[test]
    fn test_diagnose_unknown_cdi_device() {
        // containerd error path
        let diagnosis = diagnose_failure(
            "test",
            "unknown CDI device requested: nvidia.com/gpu=all",
            None,
        );
        assert!(diagnosis.is_some());
        let d = diagnosis.unwrap();
        assert!(
            d.summary.contains("CDI"),
            "expected CDI diagnosis, got: {}",
            d.summary
        );
    }

    #[test]
    fn test_diagnose_cdi_recovery_mentions_nvidia_ctk() {
        let d = diagnose_failure("test", "CDI device not found", None)
            .expect("should match CDI pattern");
        let all_steps: String = d
            .recovery_steps
            .iter()
            .map(|s| format!("{} {}", s.description, s.command.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            all_steps.contains("nvidia-ctk cdi generate"),
            "recovery steps should mention nvidia-ctk cdi generate, got: {all_steps}"
        );
        assert!(
            all_steps.contains("/etc/cdi/"),
            "recovery steps should mention /etc/cdi/, got: {all_steps}"
        );
    }
}
