// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker prerequisite checks.

use super::{PrerequisiteCheck, command_output};
use futures::future::BoxFuture;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct DockerCheck {
    docker: std::path::PathBuf,
    timeout: Duration,
    docker_host: Option<String>,
}

impl DockerCheck {
    pub(super) fn new() -> Self {
        let docker_host =
            if std::env::var("DOCKER_CONTEXT").is_ok_and(|context| !context.is_empty()) {
                None
            } else {
                std::env::var("DOCKER_HOST").ok()
            };
        Self {
            docker: "docker".into(),
            timeout: COMMAND_TIMEOUT,
            docker_host,
        }
    }
}

impl PrerequisiteCheck for DockerCheck {
    fn run<'a>(&'a self, out: &'a mut (dyn Write + Send)) -> BoxFuture<'a, Result<()>> {
        Box::pin(check_docker(
            &self.docker,
            out,
            self.timeout,
            self.docker_host.as_deref(),
        ))
    }
}

async fn check_docker(
    docker: &Path,
    out: &mut (dyn Write + Send),
    timeout: Duration,
    docker_host: Option<&str>,
) -> Result<()> {
    write!(out, "  Docker ............. ").into_diagnostic()?;
    out.flush().into_diagnostic()?;

    let output = command_output(docker, &["info", "--format", "{{json .}}"], timeout).await?;
    if !output.status.success() {
        writeln!(out, "FAILED").into_diagnostic()?;
        return Err(miette!(
            "docker info failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let info: serde_json::Value = serde_json::from_slice(&output.stdout)
        .into_diagnostic()
        .wrap_err("failed to read Docker daemon information")?;
    let version = info["ServerVersion"].as_str().unwrap_or("unknown");
    writeln!(out, "ok (version {version})").into_diagnostic()?;
    writeln!(
        out,
        "  DOCKER_HOST ........ {}",
        std::env::var("DOCKER_HOST")
            .unwrap_or_else(|_| "(not set, using Docker context)".to_string())
    )
    .into_diagnostic()?;

    let desktop = info["OperatingSystem"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("docker desktop");
    if desktop {
        // An SSH/TCP context can point at another machine. A listener on this
        // CLI host cannot qualify that machine's loopback networking.
        let endpoint = if let Some(host) = docker_host {
            host.to_string()
        } else {
            let context = command_output(
                docker,
                &[
                    "context",
                    "inspect",
                    "--format",
                    "{{.Endpoints.docker.Host}}",
                ],
                timeout,
            )
            .await?;
            if !context.status.success() {
                return Err(miette!(
                    "cannot determine Docker context endpoint: {}",
                    String::from_utf8_lossy(&context.stderr).trim()
                ));
            }
            String::from_utf8_lossy(&context.stdout).trim().to_string()
        };
        if endpoint.starts_with("unix://") || endpoint.starts_with("npipe://") {
            check_host_network(docker, out, timeout).await?;
        } else {
            writeln!(out, "  Host networking .... skipped (remote Docker endpoint; run doctor on the gateway host)")
                .into_diagnostic()?;
        }
    }
    Ok(())
}

async fn check_host_network(
    docker: &Path,
    out: &mut (dyn Write + Send),
    timeout: Duration,
) -> Result<()> {
    let probe_image = openshell_core::image::default_sandbox_image();
    writeln!(
        out,
        "  Host networking .... checking (may pull {probe_image})"
    )
    .into_diagnostic()?;
    out.flush().into_diagnostic()?;
    // No running gateway is needed. Keep the listener alive throughout the
    // probe; Bash opens a TCP socket without sending application traffic.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .into_diagnostic()?;
    let port = listener.local_addr().into_diagnostic()?.port().to_string();
    let name = format!("openshell-doctor-{}-{port}", std::process::id());
    let result = command_output(
        docker,
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "--network",
            "host",
            "--pull=missing",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--read-only",
            "--entrypoint",
            "/usr/bin/timeout",
            &probe_image,
            "3",
            "/bin/bash",
            "-c",
            "exec 3<>/dev/tcp/127.0.0.1/$1",
            "openshell-doctor",
            &port,
        ],
        timeout,
    )
    .await;
    if !result.as_ref().is_ok_and(|output| output.status.success()) {
        // Killing the CLI does not stop a daemon-side container. Clean up only
        // this probe, with its own bounded deadline.
        let _ = command_output(docker, &["rm", "--force", &name], Duration::from_secs(5)).await;
    }
    let output = result.wrap_err("could not complete the Docker Desktop host-network probe; check Docker and registry access, then rerun doctor")?;
    if output.status.success() {
        writeln!(
            out,
            "  Host networking .... ok (container reached host loopback)"
        )
        .into_diagnostic()?;
        return Ok(());
    }
    writeln!(out, "  Host networking .... FAILED").into_diagnostic()?;
    if matches!(output.status.code(), Some(1 | 124)) {
        return Err(miette!(
            "Docker Desktop host networking could not reach this machine's loopback listener. Enable host networking in Docker Desktop Settings > Resources > Network, ensure Enhanced Container Isolation is disabled, then Apply and restart Docker Desktop. Rerun `openshell doctor check` before creating a sandbox."
        ));
    }
    Err(miette!(
        "could not run the Docker Desktop host-network probe (exit {}): {}. Check image-pull access and container-start errors; host networking has not been verified.",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::run_checks;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn check_script(
        script: &str,
        timeout: Duration,
        docker_host: Option<&str>,
    ) -> (Result<()>, String) {
        let dir = tempfile::tempdir().unwrap();
        let docker = dir.path().join("docker");
        std::fs::write(&docker, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut out = Vec::new();
        let check = DockerCheck {
            docker,
            timeout,
            docker_host: docker_host.map(str::to_string),
        };
        let result = run_checks(&[&check], &mut out).await;
        (result, String::from_utf8(out).unwrap())
    }

    fn desktop_script(probe: &str) -> String {
        format!(
            r#"case "$1" in
info) echo '{{"ServerVersion":"29.8.0","OperatingSystem":"Docker Desktop"}}';;
context) echo unix:///tmp/docker.sock;;
run) {probe};;
rm) exit 0;;
*) exit 99;;
esac"#
        )
    }

    #[tokio::test]
    async fn desktop_connectivity_failure_is_actionable() {
        for code in [1, 124] {
            let (result, out) = check_script(
                &desktop_script(&format!("exit {code}")),
                COMMAND_TIMEOUT,
                None,
            )
            .await;
            let error = result.unwrap_err().to_string();
            assert!(error.contains("Settings > Resources > Network"));
            assert!(error.contains("Enhanced Container Isolation"));
            assert!(out.contains("FAILED"));
            assert!(!out.contains("All checks passed"));
        }
    }

    #[tokio::test]
    async fn image_failure_is_not_reported_as_network_misconfiguration() {
        let (result, out) = check_script(
            &desktop_script("echo 'pull denied' >&2; exit 125"),
            COMMAND_TIMEOUT,
            None,
        )
        .await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("pull denied"));
        assert!(error.contains("host networking has not been verified"));
        assert!(!error.contains("Enable host networking"));
        assert!(!out.contains("All checks passed"));
    }

    #[tokio::test]
    async fn successful_desktop_probe_passes() {
        let image = openshell_core::image::default_sandbox_image();
        let probe = format!(
            r#"case "$*" in
*'--network host'*'--entrypoint /usr/bin/timeout {image} 3 /bin/bash -c exec 3<>/dev/tcp/127.0.0.1/$1 openshell-doctor '*) exit 0;;
*) exit 99;;
esac"#
        );
        let (result, out) = check_script(&desktop_script(&probe), COMMAND_TIMEOUT, None).await;
        result.unwrap();
        assert!(out.contains(&image));
        assert!(out.contains("container reached host loopback"));
        assert!(out.contains("All checks passed"));
    }

    #[tokio::test]
    async fn native_engine_does_not_launch_a_desktop_probe() {
        let (result, out) = check_script(
            r#"case "$1" in
info) echo '{"ServerVersion":"29.8.0","OperatingSystem":"Ubuntu"}';;
*) exit 99;;
esac"#,
            COMMAND_TIMEOUT,
            None,
        )
        .await;
        result.unwrap();
        assert!(!out.contains("Host networking"));
    }

    #[tokio::test]
    async fn remote_desktop_does_not_probe_cli_host() {
        let (result, out) = check_script(
            &desktop_script("exit 99"),
            COMMAND_TIMEOUT,
            Some("ssh://remote"),
        )
        .await;
        result.unwrap();
        assert!(out.contains("skipped (remote Docker endpoint"));
    }

    #[tokio::test]
    async fn stalled_probe_is_bounded_and_does_not_pass() {
        let dir = tempfile::tempdir().unwrap();
        let docker = dir.path().join("docker");
        let cleaned = dir.path().join("cleaned");
        std::fs::write(
            &docker,
            format!(
                "#!/bin/sh\ncase \"$1\" in\nrun) exec sleep 10;;\nrm) touch '{}';;\nesac\n",
                cleaned.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = std::time::Instant::now();
        let mut out = Vec::new();
        let result = check_host_network(&docker, &mut out, Duration::from_secs(1)).await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("could not complete")
        );
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains("All checks passed")
        );
        assert!(cleaned.exists());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
