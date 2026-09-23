// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Verifies that a Podman sandbox can connect to a service on its host through
//! the driver-neutral `host.openshell.internal` alias.

use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const RESPONSE: &str = "host.openshell.internal is reachable";
const READY_MARKER: &str = "podman-host-gateway-ready";

async fn assert_host_gateway_reachable(sandbox: &SandboxGuard, port: u16) {
    let command = format!(
        "exec 3<>/dev/tcp/host.openshell.internal/{port}; \
         printf 'GET / HTTP/1.1\\r\\nHost: host.openshell.internal:{port}\\r\\nConnection: close\\r\\n\\r\\n' >&3; \
         while IFS= read -r line <&3; do [ \"$line\" = $'\\r' ] && break; done; \
         IFS= read -r body <&3; printf '%s' \"$body\""
    );
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        sandbox.exec(&["/usr/bin/bash", "-c", &command]),
    )
    .await
    .expect("host gateway probe should not time out")
    .expect("connect from Podman sandbox to host.openshell.internal");
    assert!(
        output.contains(RESPONSE),
        "sandbox did not receive the host response:\n{output}"
    );
}

#[tokio::test]
async fn podman_sandbox_reaches_host_openshell_internal() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind host-side TCP listener");
    let port = listener.local_addr().expect("read listener address").port();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept sandbox connection");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.expect("read sandbox request");
                assert_ne!(read, 0, "sandbox closed before sending an HTTP request");
                request.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RESPONSE}\n",
                RESPONSE.len() + 1
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write host response");
        }
    });

    let policy = tempfile::NamedTempFile::new().expect("create policy file");
    std::fs::write(
        policy.path(),
        format!(
            r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /bin, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

network_policies:
  host_gateway:
    name: host_gateway
    endpoints:
      - host: host.openshell.internal
        port: {port}
        protocol: tcp
    binaries:
      - path: /usr/bin/bash
"#
        ),
    )
    .expect("write policy file");

    let policy_path = policy.path().to_str().expect("policy path is UTF-8");
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", policy_path, "--no-tty"],
        &[
            "/usr/bin/bash",
            "-c",
            &format!("echo {READY_MARKER}; exec sleep infinity"),
        ],
        READY_MARKER,
    )
    .await
    .expect("create long-running Podman sandbox");

    let resolv_conf = sandbox
        .exec(&["/usr/bin/cat", "/etc/resolv.conf"])
        .await
        .expect("read workload resolver configuration");
    assert!(
        resolv_conf
            .lines()
            .any(|line| line.trim() == "nameserver 127.0.0.53"),
        "Podman workload did not use the policy-DNS relay:\n{resolv_conf}"
    );

    assert_host_gateway_reachable(&sandbox, port).await;

    let (stop_output, stop_code) = run_cli(&["sandbox", "stop", &sandbox.name]).await;
    assert_eq!(stop_code, 0, "sandbox stop should succeed:\n{stop_output}");
    wait_for_sandbox_phase(&sandbox.name, "Stopped", Duration::from_secs(120))
        .await
        .expect("Podman sandbox should stop");

    let (start_output, start_code) = run_cli(&["sandbox", "start", &sandbox.name]).await;
    assert_eq!(
        start_code, 0,
        "sandbox start should succeed:\n{start_output}"
    );
    wait_for_sandbox_phase(&sandbox.name, "Ready", Duration::from_secs(120))
        .await
        .expect("Podman sandbox should become ready after restart");

    assert_host_gateway_reachable(&sandbox, port).await;

    sandbox.cleanup().await;
    server.await.expect("join host-side TCP server");
}
