// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in, process-wide supervisor metrics. No sandbox identity labels.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::serve::ListenerExt as _;
use axum::{Router, extract::State, http::header, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use miette::{IntoDiagnostic as _, Result};
use openshell_supervisor_control::{SandboxInstancePhaseReport, SandboxInstanceStatusReport};

use crate::shared_host::SharedHost;

mod tls;

/// Validate the metrics-only TLS options without reading certificate material.
///
/// # Errors
/// Returns an error for incomplete TLS options or client auth without a CA.
pub fn tls_config(
    cert_path: Option<std::path::PathBuf>,
    key_path: Option<std::path::PathBuf>,
    client_ca_path: Option<std::path::PathBuf>,
    require_client_auth: bool,
) -> Result<Option<openshell_core::MetricsTlsConfig>> {
    if cert_path.is_none() && key_path.is_none() && client_ca_path.is_none() && !require_client_auth
    {
        return Ok(None);
    }
    let cert_path =
        cert_path.ok_or_else(|| miette::miette!("metrics TLS requires --metrics-tls-cert"))?;
    let key_path =
        key_path.ok_or_else(|| miette::miette!("metrics TLS requires --metrics-tls-key"))?;
    if require_client_auth && client_ca_path.is_none() {
        return Err(miette::miette!(
            "--metrics-require-client-auth requires --metrics-tls-client-ca"
        ));
    }
    Ok(Some(openshell_core::MetricsTlsConfig {
        cert_path,
        key_path,
        client_ca_path,
        require_client_auth,
    }))
}

/// Owns the listener task; dropping it stops serving.
pub struct MetricsServer(tokio::task::JoinHandle<()>);

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Bind before installing the process-wide recorder. Invalid TLS disables only
/// this listener; a configured TLS listener never falls back to plaintext.
///
/// # Errors
/// Returns an error when the listener cannot bind or a recorder already exists.
pub async fn serve(
    address: SocketAddr,
    host: Option<Arc<SharedHost>>,
    tls_config: Option<openshell_core::MetricsTlsConfig>,
) -> Result<Option<MetricsServer>> {
    // Invalid TLS must never expose plaintext or prevent sandbox supervision.
    let tls = match tls_config {
        Some(config) => match tls::Config::load(config) {
            Ok(tls) => Some(Arc::new(tls)),
            Err(error) => {
                tracing::error!(%error, listener = "metrics", "Supervisor metrics TLS listener disabled");
                return Ok(None);
            }
        },
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .into_diagnostic()?;
    let handle = PrometheusBuilder::new()
        .set_buckets(&[
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ])
        .into_diagnostic()?
        .install_recorder()
        .into_diagnostic()?;
    describe();
    let router = Router::new()
        .route("/metrics", get(scrape))
        .with_state((host, handle));
    tracing::info!(address = %listener.local_addr().into_diagnostic()?, "Supervisor metrics listener ready");
    Ok(Some(MetricsServer(tokio::spawn(async move {
        if let Some(tls) = tls {
            tls::serve(listener, router, tls).await;
            return;
        }
        let listener = listener.tap_io(|stream| {
            openshell_core::net::set_tcp_nodelay_best_effort(stream);
        });
        if let Err(error) = axum::serve(listener, router).await {
            tracing::error!(%error, "Supervisor metrics listener failed");
        }
    }))))
}

async fn scrape(
    State((host, handle)): State<(Option<Arc<SharedHost>>, PrometheusHandle)>,
) -> impl axum::response::IntoResponse {
    if let Some(host) = host {
        record_snapshot(&host.list(), host.gateway_connected());
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        handle.render(),
    )
}

fn record_snapshot(instances: &[SandboxInstanceStatusReport], connected: bool) {
    let mut counts = [0_u32; 5];
    for instance in instances {
        let index = match instance.phase {
            SandboxInstancePhaseReport::Starting => 0,
            SandboxInstancePhaseReport::Supervising => 1,
            SandboxInstancePhaseReport::Stopping => 2,
            SandboxInstancePhaseReport::Exited { .. } => 3,
            SandboxInstancePhaseReport::Failed { .. } => 4,
        };
        counts[index] += 1;
    }
    for (phase, count) in ["starting", "supervising", "stopping", "exited", "failed"]
        .into_iter()
        .zip(counts)
    {
        metrics::gauge!("openshell_supervisor_sandboxes", "phase" => phase).set(f64::from(count));
    }
    metrics::gauge!("openshell_supervisor_gateway_connected").set(f64::from(connected));
}

/// Lifecycle accounting for the one instance of a dedicated process.
/// Dropping without a result records failure, including cancelled startup.
pub(crate) struct DedicatedInstance {
    phase: &'static str,
    has_gateway: bool,
    finished: bool,
}

impl DedicatedInstance {
    pub(crate) fn start(has_gateway: bool) -> Self {
        let mut instance = Self {
            phase: "starting",
            has_gateway,
            finished: false,
        };
        instance.set_phase("starting");
        instance
    }

    fn set_phase(&mut self, phase: &'static str) {
        for candidate in ["starting", "supervising", "stopping", "exited", "failed"] {
            metrics::gauge!("openshell_supervisor_sandboxes", "phase" => candidate)
                .set(f64::from(candidate == phase));
        }
        self.phase = phase;
    }

    pub(crate) fn readiness(&mut self, ready: bool) {
        if ready && self.phase == "starting" {
            self.set_phase("supervising");
        }
        metrics::gauge!("openshell_supervisor_gateway_connected")
            .set(f64::from(ready && self.has_gateway));
    }

    pub(crate) fn stopping(&mut self) {
        self.set_phase("stopping");
    }

    pub(crate) fn finish(&mut self, result: &Result<i32>) {
        let (phase, outcome) = match result {
            Ok(0) => ("exited", "exited"),
            Ok(_) => ("exited", "nonzero_exit"),
            Err(_) => ("failed", "failed"),
        };
        self.set_phase(phase);
        self.readiness(false);
        metrics::counter!("openshell_supervisor_instance_terminations_total", "outcome" => outcome)
            .increment(1);
        self.finished = true;
    }
}

impl Drop for DedicatedInstance {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(&Err(miette::miette!(
                "dedicated instance ended without a result"
            )));
        }
    }
}

fn describe() {
    metrics::describe_gauge!(
        "openshell_supervisor_sandboxes",
        "Sandbox lifecycle by phase; shared mode includes rejected and deferred assignments. Not a live connection count."
    );
    metrics::describe_gauge!(
        "openshell_supervisor_gateway_connected",
        "Whether the gateway control stream is accepted and ready (assignment stream in shared mode, sandbox session in dedicated mode)."
    );
    metrics::describe_gauge!(
        "openshell_supervisor_runtime_connections",
        "Open Sandbox Protocol control transports after boundary opening; excludes mediation streams."
    );
    metrics::describe_counter!(
        "openshell_supervisor_runtime_connections_total",
        "Successfully opened Sandbox Protocol control transports, including replacements and reconnects."
    );
    metrics::describe_counter!(
        "openshell_supervisor_runtime_disconnects_total",
        "Opened runtime control transports closed by EOF, I/O error, replacement, or drop."
    );
    metrics::describe_counter!(
        "openshell_supervisor_gateway_connection_attempts_total",
        "Gateway control stream connection attempts, including initial connection and reconnects."
    );
    metrics::describe_counter!(
        "openshell_supervisor_instance_terminations_total",
        "Sandbox instance terminations, including cancellation during removal."
    );
    metrics::describe_counter!(
        "openshell_supervisor_admission_failures_total",
        "Failed attempts to admit a pool assignment; retries count again."
    );
    metrics::describe_counter!(
        "openshell_supervisor_network_decisions_total",
        "OCSF domain allow/deny records by layer; companion findings excluded. L4 and HTTP are separate decisions."
    );
    metrics::describe_counter!(
        "openshell_supervisor_network_failures_total",
        "Network domain records with failure status, excluding policy denials."
    );
    metrics::describe_counter!(
        "openshell_supervisor_upstream_connect_errors_total",
        "Failed upstream dial operations after policy authorization, including corporate proxy failures."
    );
    metrics::describe_gauge!(
        "openshell_supervisor_proxy_connections",
        "In-flight client proxy handlers, including setup and policy evaluation."
    );
    metrics::describe_counter!(
        "openshell_supervisor_policy_updates_total",
        "Policy runtime activation attempts by outcome; unchanged polls excluded, retries included."
    );
    metrics::describe_histogram!(
        "openshell_supervisor_policy_update_duration_seconds",
        "Time spent attempting atomic policy runtime activation."
    );
    metrics::describe_counter!(
        "openshell_supervisor_settings_poll_failures_total",
        "Failed gateway settings polls."
    );
    record_snapshot(&[], false);
    metrics::gauge!("openshell_supervisor_runtime_connections").set(0.0);
    metrics::gauge!("openshell_supervisor_proxy_connections", "path" => "mediated").set(0.0);
    metrics::gauge!("openshell_supervisor_proxy_connections", "path" => "transparent").set(0.0);
    // Publish zero series before the first event so a scrape can observe its
    // first increment, rather than treating the initial nonzero sample as baseline.
    for name in [
        "openshell_supervisor_runtime_connections_total",
        "openshell_supervisor_runtime_disconnects_total",
        "openshell_supervisor_gateway_connection_attempts_total",
        "openshell_supervisor_settings_poll_failures_total",
        "openshell_supervisor_admission_failures_total",
    ] {
        metrics::counter!(name).increment(0);
    }
    for outcome in ["success", "runtime_failure", "validation_rejected"] {
        metrics::counter!("openshell_supervisor_policy_updates_total", "outcome" => outcome)
            .increment(0);
    }
    for outcome in ["exited", "nonzero_exit", "failed"] {
        metrics::counter!("openshell_supervisor_instance_terminations_total", "outcome" => outcome)
            .increment(0);
    }
    for layer in ["l4", "http"] {
        for outcome in ["allow", "deny"] {
            metrics::counter!("openshell_supervisor_network_decisions_total", "layer" => layer, "outcome" => outcome).increment(0);
        }
        metrics::counter!("openshell_supervisor_network_failures_total", "layer" => layer)
            .increment(0);
    }
    for path in ["proxy", "transparent"] {
        metrics::counter!("openshell_supervisor_upstream_connect_errors_total", "path" => path)
            .increment(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_options_require_complete_material_and_an_explicit_client_ca() {
        let cert = Some("cert.pem".into());
        let key = Some("key.pem".into());
        let ca = Some("ca.pem".into());
        assert!(tls_config(None, None, None, false).unwrap().is_none());
        assert!(tls_config(cert.clone(), None, None, false).is_err());
        assert!(tls_config(None, key.clone(), None, false).is_err());
        assert!(tls_config(cert.clone(), key.clone(), None, true).is_err());
        assert!(
            tls_config(cert, key, ca, true)
                .unwrap()
                .unwrap()
                .require_client_auth
        );
    }

    #[tokio::test]
    async fn dedicated_scrapes_preserve_lifecycle_and_common_instrumentation() {
        use axum::response::IntoResponse as _;
        use http_body_util::BodyExt as _;

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        describe();
        let mut instance = DedicatedInstance::start(true);
        instance.readiness(true);
        metrics::counter!("openshell_supervisor_network_decisions_total", "layer" => "http", "outcome" => "allow").increment(1);
        for _ in 0..2 {
            let response = scrape(State((None, handle.clone()))).await.into_response();
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(text.contains("sandboxes{phase=\"supervising\"} 1"));
            assert!(text.contains("gateway_connected 1"));
            assert!(text.contains("network_decisions_total{layer=\"http\",outcome=\"allow\"} 1"));
        }
        instance.finish(&Ok(0));
    }

    #[test]
    fn dedicated_lifecycle_tracks_reconnect_shutdown_and_nonzero_exit() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let mut instance = DedicatedInstance::start(true);
            assert!(handle.render().contains("sandboxes{phase=\"starting\"} 1"));
            instance.readiness(true);
            assert!(
                handle
                    .render()
                    .contains("sandboxes{phase=\"supervising\"} 1")
            );
            assert!(handle.render().contains("gateway_connected 1"));
            instance.readiness(false);
            assert!(handle.render().contains("gateway_connected 0"));
            assert!(
                handle
                    .render()
                    .contains("sandboxes{phase=\"supervising\"} 1")
            );
            instance.readiness(true);
            instance.stopping();
            instance.readiness(false);
            instance.readiness(true);
            assert!(handle.render().contains("sandboxes{phase=\"stopping\"} 1"));
            instance.finish(&Ok(7));
            drop(instance);
            let rendered = handle.render();
            assert!(rendered.contains("sandboxes{phase=\"exited\"} 1"));
            assert!(rendered.contains("sandboxes{phase=\"stopping\"} 0"));
            assert!(rendered.contains("gateway_connected 0"));
            assert!(rendered.contains("instance_terminations_total{outcome=\"nonzero_exit\"} 1"));
        });
    }

    #[test]
    fn dedicated_without_gateway_and_cancelled_startup() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let mut instance = DedicatedInstance::start(false);
            instance.readiness(true);
            assert!(handle.render().contains("gateway_connected 0"));
            instance.finish(&Ok(0));
            drop(instance);
            assert!(
                handle
                    .render()
                    .contains("instance_terminations_total{outcome=\"exited\"} 1")
            );
            drop(DedicatedInstance::start(true));
            let rendered = handle.render();
            assert!(rendered.contains("sandboxes{phase=\"failed\"} 1"));
            assert!(rendered.contains("sandboxes{phase=\"starting\"} 0"));
            assert!(rendered.contains("instance_terminations_total{outcome=\"failed\"} 1"));
        });
    }

    #[test]
    fn snapshots_reset_removed_instances_and_do_not_label_identities() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            record_snapshot(
                &[SandboxInstanceStatusReport {
                    route: "private-route".into(),
                    sandbox_id: "private-id".into(),
                    phase: SandboxInstancePhaseReport::Supervising,
                    ready: true,
                }],
                true,
            );
            assert!(
                handle
                    .render()
                    .contains("openshell_supervisor_sandboxes{phase=\"supervising\"} 1")
            );
            record_snapshot(&[], false);
            let rendered = handle.render();
            assert!(rendered.contains("openshell_supervisor_sandboxes{phase=\"supervising\"} 0"));
            assert!(rendered.contains("openshell_supervisor_gateway_connected 0"));
            assert!(!rendered.contains("private-"));
        });
    }
}
