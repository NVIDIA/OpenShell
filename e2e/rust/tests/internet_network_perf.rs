// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in Internet benchmark for the complete sandbox-to-supervisor data path.

#![cfg(feature = "e2e-host-gateway")]

use std::io::Write as _;
use std::process::Stdio;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const BENCHMARK: &str = r#"
import http.client
import json
import os
import socket
import ssl
import statistics
import time

HOST = "example.com"
ITERATIONS = int(os.environ.get("OPENSHELL_INET_PERF_ITERATIONS", "20"))

def percentile(values, fraction):
    values = sorted(values)
    return values[min(len(values) - 1, int((len(values) - 1) * fraction))]

def measure(name, operation, iterations=ITERATIONS):
    operation()
    samples = []
    started = time.perf_counter_ns()
    for _ in range(iterations):
        before = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - before) / 1_000_000)
    elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
    return {
        "name": name,
        "iterations": iterations,
        "mean_ms": statistics.fmean(samples),
        "p50_ms": percentile(samples, 0.50),
        "p95_ms": percentile(samples, 0.95),
        "ops_per_second": iterations / elapsed,
    }

def dns_lookup():
    result = socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    if not result:
        raise RuntimeError("DNS returned no IPv4 addresses")

def tcp_connect():
    with socket.create_connection((HOST, 443), timeout=10):
        pass

tls_context = ssl.create_default_context()

def https_cold():
    connection = http.client.HTTPSConnection(HOST, 443, timeout=10, context=tls_context)
    try:
        connection.request("HEAD", "/", headers={"Connection": "close"})
        response = connection.getresponse()
        response.read()
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP status {response.status}")
    finally:
        connection.close()

warm_connection = http.client.HTTPSConnection(HOST, 443, timeout=10, context=tls_context)

def https_reuse():
    warm_connection.request("HEAD", "/", headers={"Connection": "keep-alive"})
    response = warm_connection.getresponse()
    response.read()
    if response.status != 200:
        raise RuntimeError(f"unexpected HTTP status {response.status}")

try:
    metrics = [
        measure("dns_lookup", dns_lookup),
        measure("tcp_connect", tcp_connect),
        measure("https_cold", https_cold, max(5, ITERATIONS // 2)),
        measure("https_reuse", https_reuse),
    ]
finally:
    warm_connection.close()

print(json.dumps({"metrics": metrics}, separators=(",", ":")))
"#;

fn write_policy() -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    write!(
        file,
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

network_policies:
  internet_performance:
    name: internet_performance
    endpoints:
      - host: example.com
        port: 80
        protocol: tcp
      - host: example.com
        port: 443
        protocol: tcp
    binaries:
      - path: "/**"
"#
    )
    .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

async fn run_host_benchmark() -> Result<String, String> {
    let output = tokio::process::Command::new("python3")
        .args(["-c", BENCHMARK])
        .env("OPENSHELL_INET_PERF_ITERATIONS", "20")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| format!("run host benchmark: {error}"))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!("host benchmark failed: {combined}"));
    }
    Ok(combined)
}

#[tokio::test]
#[ignore = "manual Internet performance benchmark"]
async fn benchmark_complete_internet_path() {
    let policy = write_policy().expect("write Internet benchmark policy");
    let policy_path = policy.path().to_str().expect("UTF-8 policy path");
    let sandbox = SandboxGuard::create(&["--policy", policy_path])
        .await
        .expect("create benchmark sandbox");

    for round in 1..=3 {
        let host = run_host_benchmark().await.expect("host benchmark");
        println!("INTERNET_PERF host round={round} {}", host.trim());
        let mediated = sandbox
            .exec(&[
                "sh",
                "-c",
                "OPENSHELL_INET_PERF_ITERATIONS=20 python3 -c \"$1\"",
                "openshell-internet-perf",
                BENCHMARK,
            ])
            .await
            .expect("sandbox benchmark");
        println!("INTERNET_PERF sandbox round={round} {}", mediated.trim());
    }
}
