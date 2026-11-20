// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The supervisor's agent trace relay.
//!
//! The collector tests need a gateway whose OTLP export and agent trace relay
//! point at a collector the test runs ([`otlp_support`]). The inert test
//! needs a gateway without either, so no environment runs all three: select
//! them with a filter.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use otlp_support::{Attributes, Collector, SANDBOX_ID_KEY, SOURCE_KEY, SOURCE_VALUE};
use testkit::sdk::SandboxPhase;
use testkit::{Context, Error, Result, ResultExt as _};

const ENV_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const ENV_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";
const ENV_COLLECTOR: &str = "OPENSHELL_OTLP_ENDPOINT";
const RELAY_ENDPOINT: &str = "http://192.0.0.8:4318";

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

/// Reports whether an endpoint was injected, then posts to the relay address
/// directly and reports the failure class instead of raising.
const INERT_SCRIPT: &str = r#"
import os, requests
print("ENDPOINT", os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "unset"))
url = "http://192.0.0.8:4318/v1/traces"
try:
    response = requests.post(url, data=b"", headers={"Content-Type": "application/x-protobuf"}, timeout=3)
    print("STATUS", response.status_code)
except Exception as error:
    print("ERROR", type(error).__name__)
"#;

/// A main process that posts one span with the payload embedded, and exits
/// as soon as the POST returns: 0 if the relay accepted it.
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

/// A span exported from a sandbox reaches the collector within 5 seconds,
/// with the supervisor's attribution in place of the agent's spoofed values.
/// The workload gets the relay endpoint and protocol, and never the
/// collector's address.
#[testkit::test]
async fn agent_span_reaches_collector_with_attribution(cx: &mut Context) -> testkit::Result {
    let collector = Collector::start().await?;
    let body = format!("OTLP_BODY_B64={}", encoded_request("e2e-span"));
    let builder = cx
        .cli_sandbox("otlp")
        .image(testkit::python_image())
        .args(["--env", &body, "--no-auto-providers"])
        .command(["python3", "-c", EXPORT_SCRIPT]);
    let name = builder.name().to_string();
    let run = builder.run().await?.success()?;
    let output = format!("{}{}", run.stdout, run.stderr);

    testkit::ensure!(
        output.contains("STATUS 200"),
        "the relay did not accept the export:\n{output}"
    );
    for expected in [
        format!("ENV {ENV_ENDPOINT}={RELAY_ENDPOINT}"),
        format!("ENV {ENV_PROTOCOL}=http/protobuf"),
    ] {
        testkit::ensure!(
            output.contains(&expected),
            "the workload environment lacks {expected}:\n{output}"
        );
    }
    testkit::ensure!(
        !output.contains(ENV_COLLECTOR),
        "{ENV_COLLECTOR} is visible inside the sandbox:\n{output}"
    );
    let host_port = collector.host_port();
    testkit::ensure!(
        !output.contains(host_port),
        "the collector address {host_port} appears in the sandbox environment:\n{output}"
    );

    let sandbox = cx.adopt(&name).await?;
    let spans = collector
        .wait_for_spans(&["e2e-span"], Duration::from_secs(5))
        .await?;
    expect_no_duplicate_resource_keys(&collector)?;
    expect_attribution(&spans["e2e-span"], sandbox.id())?;
    collector.shutdown().await;
    Ok(())
}

/// A main process that exports a span and exits at once still delivers it:
/// the supervisor flushes before it reports the exit, so the span is at the
/// collector by the time the sandbox is Completed. Five sandboxes in a row.
#[testkit::test]
async fn span_emitted_before_exit_is_delivered(cx: &mut Context) -> testkit::Result {
    let collector = Collector::start().await?;
    let names: Vec<String> = (1..=5).map(|i| format!("exit-span-{i}")).collect();
    let mut ids = HashMap::new();
    for (index, name) in names.iter().enumerate() {
        let sandbox = cx
            .cli_sandbox(&format!("otlp{index}"))
            .image(testkit::python_image())
            .command(["python3", "-c", &exit_script(&encoded_request(name))])
            .create()
            .await?;
        let finished = sandbox.wait_finished().await?;
        if finished.phase != SandboxPhase::Completed || finished.exit_code != Some(0) {
            let logs = sandbox.logs().await?;
            return Err(Error::msg(format!(
                "sandbox {} finished in {:?} with exit code {:?}; expected Completed with 0. Supervisor logs:\n{logs}",
                sandbox.name(),
                finished.phase,
                finished.exit_code
            )));
        }
        let arrived: Vec<String> = collector
            .received()
            .spans
            .into_iter()
            .map(|span| span.name)
            .collect();
        testkit::ensure!(
            arrived.contains(name),
            "{name} had not reached the collector when the exit was reported; it holds {arrived:?}"
        );
        ids.insert(name.clone(), sandbox.id().to_string());
        sandbox.delete().await?;
        sandbox
            .wait_absent(Duration::from_secs(60))
            .await
            .context("let the sandbox's teardown finish before the next create")?;
    }

    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let spans = collector
        .wait_for_spans(&name_refs, Duration::from_secs(15))
        .await?;
    expect_no_duplicate_resource_keys(&collector)?;
    for name in &names {
        expect_attribution(&spans[name], &ids[name])?;
    }
    collector.shutdown().await;
    Ok(())
}

/// Without a collector, the supervisor injects no relay endpoint, nothing
/// listens on the relay address, and the supervisor logs that the relay is
/// inactive.
#[testkit::test]
async fn relay_is_inert_without_collector(cx: &mut Context) -> testkit::Result {
    let builder = cx
        .cli_sandbox("otlpi")
        .image(testkit::python_image())
        .args(["--no-auto-providers"])
        .command(["python3", "-c", INERT_SCRIPT]);
    let name = builder.name().to_string();
    let run = builder.run().await?.success()?;
    let output = format!("{}{}", run.stdout, run.stderr);
    testkit::ensure!(
        output.contains("ENDPOINT unset"),
        "a relay endpoint was injected while the relay is inactive:\n{output}"
    );
    testkit::ensure!(
        output.contains("ERROR ConnectionError"),
        "the export did not fail with a connection error:\n{output}"
    );

    let sandbox = cx.adopt(&name).await?;
    let logs = sandbox
        .logs_until("that the OTLP agent trace relay is inactive", |logs| {
            logs.contains("OTLP agent trace relay inactive")
        })
        .await?;
    testkit::ensure!(
        !logs.contains("OTLP agent trace relay enabled"),
        "the supervisor also reported the relay enabled:\n{logs}"
    );
    Ok(())
}

/// One span with the agent's own service name and spoofed values for both
/// attribution keys, base64-encoded.
fn encoded_request(span_name: &str) -> String {
    let request = otlp_support::encoded_trace_request(
        span_name,
        &[
            ("service.name", "e2e-agent"),
            (SANDBOX_ID_KEY, "spoofed"),
            (SOURCE_KEY, "infrastructure"),
        ],
    );
    base64::engine::general_purpose::STANDARD.encode(request)
}

/// The received attributes keep the last value of a key, so a spoofed
/// attribute that was appended to rather than replaced shows only as a
/// duplicate.
fn expect_no_duplicate_resource_keys(collector: &Collector) -> Result {
    let duplicates = collector.received().duplicate_resource_keys;
    testkit::ensure!(
        duplicates.is_empty(),
        "attribution keys were appended, not replaced: {duplicates:?}"
    );
    Ok(())
}

fn expect_attribution(attributes: &Attributes, sandbox_id: &str) -> Result {
    testkit::ensure!(
        !attributes
            .values()
            .any(|value| value == "spoofed" || value == "infrastructure"),
        "the agent's attribution values were kept: {attributes:?}"
    );
    for (key, expected) in [
        ("service.name", "e2e-agent"),
        (SOURCE_KEY, SOURCE_VALUE),
        (SANDBOX_ID_KEY, sandbox_id),
    ] {
        testkit::ensure!(
            attributes.get(key).map(String::as_str) == Some(expected),
            "resource attribute {key} is not {expected}: {attributes:?}"
        );
    }
    Ok(())
}
