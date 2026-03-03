// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::constants::{KUBECONFIG_PATH, container_name};
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::CreateExecOptions;
use bollard::models::HealthStatusEnum;
use bollard::query_parameters::{InspectContainerOptions, LogsOptionsBuilder};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

pub async fn wait_for_kubeconfig(docker: &Docker, name: &str) -> Result<String> {
    let container_name = container_name(name);
    let attempts = 30;
    for attempt in 0..attempts {
        // Check if the container is still running before trying to exec into it
        if let Err(status_err) =
            crate::docker::check_container_running(docker, &container_name).await
        {
            let logs = fetch_recent_logs(docker, &container_name, 20).await;
            return Err(miette::miette!(
                "cluster container is not running while waiting for kubeconfig: {status_err}\n{logs}"
            ));
        }

        match exec_capture(
            docker,
            &container_name,
            vec!["cat".to_string(), KUBECONFIG_PATH.to_string()],
        )
        .await
        {
            Ok(output) if is_valid_kubeconfig(&output) => return Ok(output),
            Ok(_) => {}
            Err(err) if attempt + 1 < attempts => {
                let _ = err;
            }
            Err(err) => {
                let logs = fetch_recent_logs(docker, &container_name, 20).await;
                return Err(err.wrap_err(format!("failed waiting for kubeconfig\n{logs}")));
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let logs = fetch_recent_logs(docker, &container_name, 20).await;
    Err(miette::miette!("timed out waiting for kubeconfig\n{logs}"))
}

pub async fn wait_for_cluster_ready<F>(docker: &Docker, name: &str, mut on_log: F) -> Result<()>
where
    F: FnMut(String) + Send,
{
    let container_name = container_name(name);
    let (log_tx, mut log_rx) = unbounded_channel();
    let log_docker = docker.clone();
    let log_container_name = container_name.clone();
    let log_task = tokio::spawn(async move {
        stream_container_logs(&log_docker, &log_container_name, &log_tx).await;
    });

    let mut recent_logs = VecDeque::with_capacity(15);
    let attempts = 180;
    let mut result = None;

    for attempt in 0..attempts {
        drain_logs(&mut log_rx, &mut recent_logs, &mut on_log);

        let inspect = docker
            .inspect_container(&container_name, None::<InspectContainerOptions>)
            .await
            .into_diagnostic()?;

        // Check if the container has exited before checking health
        let running = inspect
            .state
            .as_ref()
            .and_then(|s| s.running)
            .unwrap_or(false);
        if !running {
            drain_logs(&mut log_rx, &mut recent_logs, &mut on_log);
            let exit_code = inspect
                .state
                .as_ref()
                .and_then(|s| s.exit_code)
                .unwrap_or(-1);
            let error_msg = inspect
                .state
                .as_ref()
                .and_then(|s| s.error.as_deref())
                .unwrap_or("");
            let mut detail =
                format!("cluster container exited unexpectedly (exit_code={exit_code})");
            if !error_msg.is_empty() {
                use std::fmt::Write;
                let _ = write!(detail, ", error={error_msg}");
            }
            result = Some(Err(miette::miette!(
                "{detail}\n{}",
                format_recent_logs(&recent_logs)
            )));
            break;
        }

        let status = inspect
            .state
            .and_then(|state| state.health)
            .and_then(|health| health.status);

        match status {
            Some(HealthStatusEnum::HEALTHY) => {
                result = Some(Ok(()));
                break;
            }
            Some(HealthStatusEnum::UNHEALTHY) if attempt + 1 == attempts => {
                result = Some(Err(miette::miette!(
                    "cluster health check reported unhealthy\n{}",
                    format_recent_logs(&recent_logs)
                )));
                break;
            }
            Some(HealthStatusEnum::NONE | HealthStatusEnum::EMPTY) | None if attempt == 0 => {
                result = Some(Err(miette::miette!(
                    "cluster container does not expose a health check\n{}",
                    format_recent_logs(&recent_logs)
                )));
                break;
            }
            _ => {}
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    if result.is_none() {
        drain_logs(&mut log_rx, &mut recent_logs, &mut on_log);
        result = Some(Err(miette::miette!(
            "timed out waiting for cluster health check\n{}",
            format_recent_logs(&recent_logs)
        )));
    }

    log_task.abort();

    result.unwrap_or_else(|| Err(miette::miette!("cluster health status unavailable")))
}

async fn stream_container_logs(
    docker: &Docker,
    container_name: &str,
    tx: &UnboundedSender<String>,
) {
    let options = LogsOptionsBuilder::new()
        .follow(true)
        .stdout(true)
        .stderr(true)
        .tail("0")
        .build();
    let mut stream = docker.logs(container_name, Some(options));

    let mut stdout_partial = String::new();
    let mut stderr_partial = String::new();
    let mut console_partial = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(log) => match log {
                LogOutput::StdOut { message } => {
                    append_log_chunk(tx, &mut stdout_partial, &String::from_utf8_lossy(&message));
                }
                LogOutput::StdErr { message } => {
                    append_log_chunk(tx, &mut stderr_partial, &String::from_utf8_lossy(&message));
                }
                LogOutput::Console { message } => {
                    append_log_chunk(tx, &mut console_partial, &String::from_utf8_lossy(&message));
                }
                LogOutput::StdIn { .. } => {}
            },
            Err(err) => {
                let _ = tx.send(format!("[log stream error] {err}"));
                return;
            }
        }
    }

    flush_partial(tx, &mut stdout_partial);
    flush_partial(tx, &mut stderr_partial);
    flush_partial(tx, &mut console_partial);
}

fn append_log_chunk(tx: &UnboundedSender<String>, partial: &mut String, chunk: &str) {
    partial.push_str(chunk);
    while let Some(pos) = partial.find('\n') {
        let line = partial[..pos].trim_end_matches('\r').to_string();
        if !line.is_empty() {
            let _ = tx.send(line);
        }
        partial.drain(..=pos);
    }
}

fn flush_partial(tx: &UnboundedSender<String>, partial: &mut String) {
    let line = partial.trim();
    if !line.is_empty() {
        let _ = tx.send(line.to_string());
    }
    partial.clear();
}

fn drain_logs<F>(
    rx: &mut UnboundedReceiver<String>,
    recent_logs: &mut VecDeque<String>,
    on_log: &mut F,
) where
    F: FnMut(String),
{
    while let Ok(line) = rx.try_recv() {
        if recent_logs.len() == 15 {
            recent_logs.pop_front();
        }
        recent_logs.push_back(line.clone());
        on_log(line);
    }
}

fn format_recent_logs(recent_logs: &VecDeque<String>) -> String {
    if recent_logs.is_empty() {
        return "container logs: none received".to_string();
    }

    let mut rendered = String::from("container logs:");
    for line in recent_logs {
        rendered.push('\n');
        rendered.push_str("  ");
        rendered.push_str(line);
    }
    rendered
}

/// Fetch the last `n` lines of container logs (non-streaming, for error context).
pub async fn fetch_recent_logs(docker: &Docker, container_name: &str, n: usize) -> String {
    let options = LogsOptionsBuilder::new()
        .follow(false)
        .stdout(true)
        .stderr(true)
        .tail(&n.to_string())
        .build();
    let mut stream = docker.logs(container_name, Some(options));

    let mut lines = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(log) => {
                let text = match log {
                    LogOutput::StdOut { message }
                    | LogOutput::StdErr { message }
                    | LogOutput::Console { message } => {
                        String::from_utf8_lossy(&message).to_string()
                    }
                    LogOutput::StdIn { .. } => continue,
                };
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
            }
            Err(_) => break,
        }
    }

    if lines.is_empty() {
        return "container logs: none available".to_string();
    }

    let mut rendered = String::from("container logs:");
    for line in &lines {
        rendered.push('\n');
        rendered.push_str("  ");
        rendered.push_str(line);
    }
    rendered
}

/// Remove stale k3s nodes from a cluster with a reused persistent volume.
///
/// When a cluster container is recreated but the volume is reused, k3s registers
/// a new node (using the container ID as the hostname) while old node entries
/// persist in etcd. Pods scheduled on those stale `NotReady` nodes will never run,
/// causing health checks to fail.
///
/// This function identifies all `NotReady` nodes and deletes them so k3s can
/// reschedule workloads onto the current (Ready) node.
///
/// Returns the number of stale nodes removed.
pub async fn clean_stale_nodes(docker: &Docker, name: &str) -> Result<usize> {
    let container_name = container_name(name);

    // Get the list of NotReady nodes.
    // The last condition on a node is always type=Ready; we need to check its
    // **status** (True/False/Unknown), not its type.  Nodes where the Ready
    // condition status is not "True" are stale and should be removed.
    let (output, exit_code) = exec_capture_with_exit(
        docker,
        &container_name,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "KUBECONFIG={KUBECONFIG_PATH} kubectl get nodes \
                 --no-headers -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].status \
                 2>/dev/null | grep -v '\\bTrue$' | awk '{{print $1}}'"
            ),
        ],
    )
    .await?;

    if exit_code != 0 {
        // kubectl not ready yet or no nodes — nothing to clean
        return Ok(0);
    }

    let stale_nodes: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if stale_nodes.is_empty() {
        return Ok(0);
    }

    let node_list = stale_nodes.join(" ");
    let count = stale_nodes.len();
    tracing::info!("removing {} stale node(s): {}", count, node_list);

    let (_output, exit_code) = exec_capture_with_exit(
        docker,
        &container_name,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "KUBECONFIG={KUBECONFIG_PATH} kubectl delete node {node_list} --ignore-not-found"
            ),
        ],
    )
    .await?;

    if exit_code != 0 {
        tracing::warn!("failed to delete stale nodes (exit code {exit_code})");
    }

    Ok(count)
}

/// Restart the navigator workload so pods pick up updated images or secrets.
///
/// Probes for a `StatefulSet` first, then falls back to a `Deployment`, matching
/// the same detection pattern used by `cluster-deploy-fast.sh`.
pub async fn restart_navigator_deployment(docker: &Docker, name: &str) -> Result<()> {
    let cname = container_name(name);

    // Detect which workload kind exists in the cluster.
    let workload_kind = detect_navigator_workload_kind(docker, &cname).await?;
    let workload_ref = format!("{workload_kind}/navigator");

    let (restart_output, restart_exit) = exec_capture_with_exit(
        docker,
        &cname,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "KUBECONFIG={KUBECONFIG_PATH} kubectl rollout restart {workload_ref} -n navigator"
            ),
        ],
    )
    .await?;
    if restart_exit != 0 {
        return Err(miette::miette!(
            "failed to restart navigator {workload_ref} (exit code {restart_exit})\n{restart_output}"
        ));
    }

    let (status_output, status_exit) = exec_capture_with_exit(
        docker,
        &cname,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "KUBECONFIG={KUBECONFIG_PATH} kubectl rollout status {workload_ref} -n navigator --timeout=180s"
            ),
        ],
    )
    .await?;
    if status_exit != 0 {
        return Err(miette::miette!(
            "navigator rollout status failed for {workload_ref} (exit code {status_exit})\n{status_output}"
        ));
    }

    Ok(())
}

/// Check whether a navigator workload exists in the cluster (`StatefulSet` or `Deployment`).
pub async fn navigator_workload_exists(docker: &Docker, name: &str) -> Result<bool> {
    let cname = container_name(name);
    match detect_navigator_workload_kind(docker, &cname).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Detect whether navigator is deployed as a `StatefulSet` or `Deployment`.
/// Returns "statefulset" or "deployment".
async fn detect_navigator_workload_kind(docker: &Docker, container_name: &str) -> Result<String> {
    // Check StatefulSet first (primary workload type for fresh deploys)
    let (_, ss_exit) = exec_capture_with_exit(
        docker,
        container_name,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "KUBECONFIG={KUBECONFIG_PATH} kubectl get statefulset/navigator -n navigator -o name 2>/dev/null"
            ),
        ],
    )
    .await?;
    if ss_exit == 0 {
        return Ok("statefulset".to_string());
    }

    // Fall back to Deployment
    let (_, dep_exit) = exec_capture_with_exit(
        docker,
        container_name,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "KUBECONFIG={KUBECONFIG_PATH} kubectl get deployment/navigator -n navigator -o name 2>/dev/null"
            ),
        ],
    )
    .await?;
    if dep_exit == 0 {
        return Ok("deployment".to_string());
    }

    Err(miette::miette!(
        "no navigator workload (statefulset or deployment) found in namespace 'navigator'"
    ))
}

fn is_valid_kubeconfig(output: &str) -> bool {
    output.contains("apiVersion:") && output.contains("clusters:")
}

pub async fn exec_capture(
    docker: &Docker,
    container_name: &str,
    cmd: Vec<String>,
) -> Result<String> {
    let (output, _status) = exec_capture_with_exit(docker, container_name, cmd).await?;
    Ok(output)
}

pub async fn exec_capture_with_exit(
    docker: &Docker,
    container_name: &str,
    cmd: Vec<String>,
) -> Result<(String, i64)> {
    let exec = docker
        .create_exec(
            container_name,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(cmd),
                ..Default::default()
            },
        )
        .await
        .into_diagnostic()?
        .id;

    let start = docker.start_exec(&exec, None).await.into_diagnostic()?;
    let mut buffer = String::new();
    if let bollard::exec::StartExecResults::Attached { mut output, .. } = start {
        while let Some(item) = output.next().await {
            let log = item.into_diagnostic()?;
            match log {
                LogOutput::StdOut { message }
                | LogOutput::StdErr { message }
                | LogOutput::Console { message } => {
                    buffer.push_str(&String::from_utf8_lossy(&message));
                }
                LogOutput::StdIn { .. } => {}
            }
        }
    }

    let mut exit_code = None;
    for _ in 0..20 {
        let inspect = docker.inspect_exec(&exec).await.into_diagnostic()?;
        if let Some(code) = inspect.exit_code {
            exit_code = Some(code);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    Ok((buffer, exit_code.unwrap_or(1)))
}
