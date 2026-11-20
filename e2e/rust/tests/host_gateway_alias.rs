// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct HostServer {
    port: u16,
    task: JoinHandle<()>,
}

impl HostServer {
    async fn start(response_body: &str) -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("bind host test server: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read host test server address: {e}"))?
            .port();
        let response_body = response_body.as_bytes().to_vec();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = response_body.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buf).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Ok(Self { port, task })
    }
}

impl Drop for HostServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn write_policy(port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create temp policy file: {e}"))?;
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /bin
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  host_echo:
    name: host_echo
    endpoints:
      - host: host.openshell.internal
        port: {port}
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
    binaries:
      - path: /usr/bin/bash
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

#[tokio::test]
async fn sandbox_reaches_host_openshell_internal_via_host_gateway_alias() {
    let server = HostServer::start(r#"{"message":"hello-from-host"}"#)
        .await
        .expect("start host echo server");
    let policy = write_policy(server.port).expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();

    let command = format!(
        r#"exec 3<>/dev/tcp/host.openshell.internal/{0}; printf 'GET / HTTP/1.1\r\nHost: host.openshell.internal:{0}\r\nConnection: close\r\n\r\n' >&3; while IFS= read -r line <&3 || [[ -n $line ]]; do printf '%s\n' "$line"; done"#,
        server.port
    );
    let guard = SandboxGuard::create(&[
        "--policy",
        &policy_path,
        "--",
        "/usr/bin/bash",
        "-c",
        &command,
    ])
    .await
    .expect("sandbox create with host.openshell.internal echo request");

    assert!(
        guard
            .create_output
            .contains("\"message\":\"hello-from-host\""),
        "expected sandbox to receive host echo response:\n{}",
        guard.create_output
    );
}

#[tokio::test]
async fn sandbox_receives_eof_after_closing_http_response() {
    for response in [
        "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n",
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nOK\n",
        "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nOK\n\r\n0\r\n\r\n",
    ] {
        let listener = TcpListener::bind(("0.0.0.0", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = HostServer {
            port,
            task: tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).expect("disable Nagle on fixture");
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                    assert!(request.len() < 4096);
                }
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }),
        };
        let policy = write_policy(server.port).unwrap();
        let command = format!(
            r#"set -eu
exec 3<>/dev/tcp/host.openshell.internal/{port}
printf 'GET / HTTP/1.1\r\nHost: host.openshell.internal:{port}\r\n\r\n' >&3
while true; do
  line=
  if IFS= read -r -t 5 line <&3; then
    printf '%s\n' "$line"
  else
    status=$?
    [ "$status" -eq 1 ] || {{ echo EOF_TIMEOUT; exit 1; }}
    [ -z "$line" ] || printf '%s\n' "$line"
    break
  fi
done
printf 'RESPONSE_EOF\n'
"#,
        );
        let mut sandbox = SandboxGuard::create(&[
            "--policy",
            policy.path().to_str().unwrap(),
            "--no-auto-providers",
            "--",
            "/usr/bin/bash",
            "-c",
            &command,
        ])
        .await
        .expect("closing response must finish without a client timeout");
        assert!(
            sandbox.create_output.lines().any(|line| line == "OK"),
            "{}",
            sandbox.create_output
        );
        assert!(
            sandbox.create_output.contains("RESPONSE_EOF"),
            "{}",
            sandbox.create_output
        );
        assert!(
            !sandbox.create_output.contains("EOF_TIMEOUT"),
            "{}",
            sandbox.create_output
        );
        sandbox.cleanup().await;
    }
}
