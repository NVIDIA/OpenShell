// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-direct OTLP trace relay.
//!
//! The gateway wrapper writes `[openshell.gateway.otlp].endpoint` from
//! `OPENSHELL_E2E_OTLP_ENDPOINT`. These tests bind a collector stub on that
//! endpoint's port and prove that a span exported from inside a sandbox
//! arrives with the supervisor's attribution. With the variable unset or
//! empty, the inert case runs instead.

#![cfg(feature = "e2e-local-container-driver")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use openshell_e2e::harness::cli;
use openshell_e2e::harness::sandbox::SandboxGuard;
use openshell_otel_test_support::OtlpTestServer;
use openshell_otel_test_support::relay::{
    SANDBOX_ID_KEY, SOURCE_KEY, SOURCE_VALUE, encoded_trace_request,
};
use serial_test::serial;

const ENV_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const ENV_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";
const ENV_COLLECTOR: &str = "OPENSHELL_OTLP_ENDPOINT";

/// Posts the base64 body from `OTLP_BODY_B64` to the relay and prints the
/// status plus the complete environment, one `ENV key=value` line each, so
/// the test can check values and prove the collector address is nowhere.
const EXPORT_SCRIPT: &str = r#"
import base64, os, requests
body = base64.b64decode(os.environ["OTLP_BODY_B64"])
url = os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/traces"
response = requests.post(url, data=body, headers={"Content-Type": "application/x-protobuf"}, timeout=10)
print("STATUS", response.status_code)
for key, value in sorted(os.environ.items()):
    if key != "OTLP_BODY_B64":
        print("ENV " + key + "=" + value)
"#;

/// Main-process variant: the payload is embedded so no `--env` is needed,
/// and the process exits the moment the POST returns.
fn exit_script(body_b64: &str) -> String {
    format!(
        r#"
import base64, os, requests
body = base64.b64decode("{body_b64}")
url = os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/traces"
response = requests.post(url, data=body, headers={{"Content-Type": "application/x-protobuf"}}, timeout=10)
raise SystemExit(0 if response.status_code == 200 else 1)
"#
    )
}

/// Same export, but reports the failure class instead of raising, for the
/// inert case.
const INERT_SCRIPT: &str = r#"
import os, requests
url = os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/traces"
try:
    response = requests.post(url, data=b"", headers={"Content-Type": "application/x-protobuf"}, timeout=3)
    print("STATUS", response.status_code)
except Exception as error:
    print("ERROR", type(error).__name__)
"#;

fn collector_endpoint() -> Option<String> {
    std::env::var("OPENSHELL_E2E_OTLP_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty())
}

fn collector_bind_addr(endpoint: &str) -> SocketAddr {
    let url = url::Url::parse(endpoint).expect("OPENSHELL_E2E_OTLP_ENDPOINT is a URL");
    let port = url
        .port_or_known_default()
        .expect("OPENSHELL_E2E_OTLP_ENDPOINT names a port");
    // Containers reach the host through its bridge address, not loopback.
    SocketAddr::from(([0, 0, 0, 0], port))
}

/// `host:port` of the collector as the gateway configures it, the string
/// that must not appear anywhere in the sandbox environment.
fn collector_host_port(endpoint: &str) -> String {
    let url = url::Url::parse(endpoint).expect("OPENSHELL_E2E_OTLP_ENDPOINT is a URL");
    format!(
        "{}:{}",
        url.host_str().expect("collector host"),
        url.port_or_known_default().expect("collector port")
    )
}

/// One span with the agent's own service name and spoofed values for both
/// attribution keys, base64-encoded for the workload's environment.
fn encoded_request(span_name: &str) -> String {
    let request = encoded_trace_request(
        span_name,
        &[
            ("service.name", "e2e-agent"),
            (SANDBOX_ID_KEY, "spoofed"),
            (SOURCE_KEY, "infrastructure"),
        ],
    );
    base64::engine::general_purpose::STANDARD.encode(request)
}

/// The harness CLI runner with a `Result` for the failure path.
async fn run_cli(args: &[&str]) -> Result<String, String> {
    let (output, code) = cli::run_cli(args).await;
    if code != 0 {
        return Err(format!(
            "openshell {} failed (exit {code}):\n{output}",
            args.join(" ")
        ));
    }
    Ok(output)
}

async fn sandbox_id(name: &str) -> Result<String, String> {
    let details = run_cli(&["sandbox", "get", name, "--output", "json"]).await?;
    let details: serde_json::Value =
        serde_json::from_str(&details).map_err(|e| format!("parse sandbox JSON: {e}"))?;
    details["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("sandbox has no id: {details}"))
}

/// Polls `sandbox get` until the gateway no longer knows the sandbox, so
/// the next create does not overlap the previous teardown.
async fn wait_for_sandbox_gone(name: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while run_cli(&["sandbox", "get", name]).await.is_ok() {
        if tokio::time::Instant::now() >= deadline {
            eprintln!("sandbox {name} still listed after delete; continuing");
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Waits for the sandbox to reach `phase` through the harness, then returns
/// its details for further assertions.
async fn wait_for_sandbox_phase(name: &str, phase: &str) -> Result<String, String> {
    cli::wait_for_sandbox_phase(name, phase, Duration::from_secs(60)).await?;
    run_cli(&["sandbox", "get", name]).await
}

async fn wait_for_sandbox_logs(
    sandbox_name: &str,
    expected: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let logs = run_cli(&[
            "logs",
            sandbox_name,
            "-n",
            "500",
            "--since",
            "5m",
            "--source",
            "sandbox",
        ])
        .await?;
        if expected(&logs) {
            return Ok(logs);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for expected sandbox logs:\n{logs}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Waits up to `within` until the collector holds every span in `names`,
/// returning the resource attributes keyed by span name.
async fn wait_for_spans(
    collector: &OtlpTestServer,
    names: &[&str],
    within: Duration,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let received = collector.received();
        let received_names: Vec<&str> = received
            .spans
            .iter()
            .map(|span| span.name.as_str())
            .collect();
        if names.iter().all(|name| received_names.contains(name)) {
            // Supervisor batches share the collector; `span_resources` pairs
            // every span with the resource of the batch it arrived in.
            let by_name = received
                .spans
                .iter()
                .zip(received.span_resources.iter())
                .map(|(span, attributes)| (span.name.clone(), attributes.clone()))
                .collect();
            return Ok(by_name);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "collector received {received_names:?}, expected all of {names:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The collector keeps the last value per key, so a spoofed attribute that
/// was appended to rather than replaced is only visible as a duplicate.
fn assert_no_duplicate_resource_keys(collector: &OtlpTestServer) {
    let duplicates = collector.received().duplicate_resource_keys;
    assert!(
        duplicates.is_empty(),
        "attribution keys were appended, not replaced: {duplicates:?}"
    );
}

fn assert_attribution(attributes: &HashMap<String, String>, sandbox_id: &str) {
    assert!(
        !attributes
            .values()
            .any(|value| value == "spoofed" || value == "infrastructure"),
        "agent-supplied attribution values must be discarded: {attributes:?}"
    );
    assert_eq!(
        attributes.get("service.name").map(String::as_str),
        Some("e2e-agent"),
        "agent service name is preserved: {attributes:?}"
    );
    assert_eq!(
        attributes.get(SOURCE_KEY).map(String::as_str),
        Some(SOURCE_VALUE),
        "{attributes:?}"
    );
    assert_eq!(
        attributes.get(SANDBOX_ID_KEY).map(String::as_str),
        Some(sandbox_id),
        "spoofed sandbox id is replaced: {attributes:?}"
    );
}

#[tokio::test]
#[serial]
async fn agent_span_reaches_collector_with_attribution() {
    let Some(endpoint) = collector_endpoint() else {
        eprintln!("OPENSHELL_E2E_OTLP_ENDPOINT is unset; skipping the collector case");
        return;
    };
    let collector = OtlpTestServer::start_on(collector_bind_addr(&endpoint)).await;

    let body = format!("OTLP_BODY_B64={}", encoded_request("e2e-span"));
    let mut sandbox = SandboxGuard::create(&[
        "--env",
        &body,
        "--no-auto-providers",
        "--",
        "python3",
        "-c",
        EXPORT_SCRIPT,
    ])
    .await
    .expect("sandbox exports one span to the relay");
    let output = sandbox.create_output.clone();
    assert!(
        output.contains("STATUS 200"),
        "relay must accept the export:\n{output}"
    );
    // US1-S3: the exact values a standard SDK needs.
    assert!(
        output.contains(&format!("ENV {ENV_ENDPOINT}=http://192.0.0.8:4318")),
        "the relay endpoint is set for the workload:\n{output}"
    );
    assert!(
        output.contains(&format!("ENV {ENV_PROTOCOL}=http/protobuf")),
        "the exporter protocol is set for the workload:\n{output}"
    );
    // US1-S4: neither the variable nor the address itself is present anywhere.
    assert!(
        !output.contains(ENV_COLLECTOR),
        "the collector variable must not be visible inside the sandbox:\n{output}"
    );
    let host_port = collector_host_port(&endpoint);
    assert!(
        !output.contains(&host_port),
        "the collector address {host_port} must not appear in the sandbox environment:\n{output}"
    );

    let id = sandbox_id(&sandbox.name).await.expect("sandbox id");
    // US1-S1: within 5 seconds.
    let spans = wait_for_spans(&collector, &["e2e-span"], Duration::from_secs(5))
        .await
        .expect("span reaches the collector stub within 5 s");
    assert_no_duplicate_resource_keys(&collector);
    assert_attribution(&spans["e2e-span"], &id);

    sandbox.cleanup().await;
    drop(collector.shutdown().await);
}

#[tokio::test]
#[serial]
async fn relay_is_inert_without_collector() {
    if collector_endpoint().is_some() {
        eprintln!("OPENSHELL_E2E_OTLP_ENDPOINT is set; skipping the inert case");
        return;
    }

    let mut sandbox =
        SandboxGuard::create(&["--no-auto-providers", "--", "python3", "-c", INERT_SCRIPT])
            .await
            .expect("sandbox attempts an export without a collector");
    let output = sandbox.create_output.clone();
    assert!(
        output.contains("ERROR ConnectionError"),
        "the export must fail with a connection error, not a timeout:\n{output}"
    );

    let logs = wait_for_sandbox_logs(&sandbox.name, |logs| {
        logs.contains("OTLP agent trace relay inactive")
    })
    .await
    .expect("supervisor reports the relay as inactive");
    assert!(!logs.contains("OTLP agent trace relay enabled"), "{logs}");

    sandbox.cleanup().await;
}

#[tokio::test]
#[serial]
async fn span_emitted_before_exit_is_delivered() {
    let Some(endpoint) = collector_endpoint() else {
        eprintln!("OPENSHELL_E2E_OTLP_ENDPOINT is unset; skipping the flush case");
        return;
    };
    let collector = OtlpTestServer::start_on(collector_bind_addr(&endpoint)).await;

    // The main process posts and exits at once; the supervisor must flush
    // the batch before it reports the exit. Five cycles stand in for SC-005.
    let names: Vec<String> = (1..=5).map(|i| format!("exit-span-{i}")).collect();
    let mut ids = HashMap::new();
    for name in &names {
        let script = exit_script(&encoded_request(name));
        let mut sandbox = SandboxGuard::create_detached_main(&["python3", "-c", &script])
            .await
            .expect("sandbox whose main process exports one span and exits");
        let details = match wait_for_sandbox_phase(&sandbox.name, "Completed").await {
            Ok(details) => details,
            Err(error) => {
                let logs = run_cli(&[
                    "logs",
                    &sandbox.name,
                    "-n",
                    "500",
                    "--since",
                    "5m",
                    "--source",
                    "sandbox",
                ])
                .await
                .unwrap_or_else(|e| format!("(logs unavailable: {e})"));
                sandbox.cleanup().await;
                panic!(
                    "main process did not exit after the export: {error}\nsupervisor logs:\n{logs}"
                );
            }
        };
        assert!(
            !details.contains("Exit Code: 1"),
            "relay must accept the export:\n{details}"
        );
        // US4-S1: the gateway marks the sandbox Completed only after the
        // supervisor's exit report, and the supervisor flushes before that
        // report, so the span must already be at the collector now.
        let snapshot = collector.received();
        assert!(
            snapshot.spans.iter().any(|span| &span.name == name),
            "{name} must reach the collector before the exit is reported; collector holds {:?}",
            snapshot
                .spans
                .iter()
                .map(|span| span.name.as_str())
                .collect::<Vec<_>>()
        );
        ids.insert(
            name.clone(),
            sandbox_id(&sandbox.name).await.expect("sandbox id"),
        );
        sandbox.cleanup().await;
        wait_for_sandbox_gone(&sandbox.name).await;
    }

    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let spans = wait_for_spans(&collector, &name_refs, Duration::from_secs(15))
        .await
        .expect("every span emitted right before exit reaches the collector");
    assert_no_duplicate_resource_keys(&collector);
    for name in &names {
        assert_attribution(&spans[name], &ids[name]);
    }
    drop(collector.shutdown().await);
}
