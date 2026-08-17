// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{SupportContainer, is_e2e_driver};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

// Use a qualified policy hostname so runtime-provided resolver search domains
// (for example Podman's `dns.podman`) cannot rewrite the policy identity.
const FIXTURE_ALIAS: &str = "transparent-tcp-fixture.openshell.test";
const MUSL_FIXTURE_ALIAS: &str = "transparent-tcp-musl.openshell.test";
const FIXTURE_PORT: u16 = 5432;
const TRANSPARENT_LISTENER_PORT: u16 = 15001;

fn write_policy() -> Result<NamedTempFile, String> {
    write_policy_for(FIXTURE_ALIAS)
}

fn write_policy_for(host: &str) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: {{ compatibility: best_effort }}
process: {{ run_as_user: sandbox, run_as_group: sandbox }}
network_policies:
  native_database:
    name: native_database
    endpoints:
      - host: {host}
        port: {FIXTURE_PORT}
        protocol: tcp
        allowed_ips: ["10.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16"]
    binaries:
      - path: "/**"
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

#[tokio::test]
async fn rootless_podman_musl_client_uses_udp_policy_dns() {
    if !is_e2e_driver("podman") {
        return;
    }

    let fixture = SupportContainer::start_python(
        MUSL_FIXTURE_ALIAS,
        &format!(
            r#"import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', {FIXTURE_PORT}))
s.listen()
while True:
  c, _ = s.accept()
  data = c.recv(1024)
  c.sendall(b'musl-native-tcp-ok:' + data)
  c.close()
"#
        ),
        FIXTURE_PORT,
    )
    .await
    .expect("start musl TCP fixture");

    let image = tempfile::tempdir().expect("create Alpine build context");
    std::fs::write(
        image.path().join("Dockerfile"),
        "FROM docker.io/library/alpine:3.22\nRUN addgroup -g 1000 sandbox && adduser -D -u 1000 -G sandbox sandbox\n",
    )
    .expect("write Alpine Dockerfile");
    let policy = write_policy_for(MUSL_FIXTURE_ALIAS).expect("write musl policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let image_path = image.path().to_string_lossy().into_owned();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--from", &image_path, "--policy", &policy_path, "--no-tty"],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create Alpine/musl sandbox");

    let script = format!(
        "set -eu; nslookup {MUSL_FIXTURE_ALIAS} | grep -E 'Address: 198\\.1[89]\\.'; printf probe | nc -w 5 {MUSL_FIXTURE_ALIAS} {FIXTURE_PORT} | grep musl-native-tcp-ok:probe; echo musl-policy-dns-ok"
    );
    let output = sandbox
        .exec(&["sh", "-c", &script])
        .await
        .expect("exercise musl UDP policy DNS");
    assert!(output.contains("musl-policy-dns-ok"), "{output}");

    sandbox.cleanup().await;
    drop(fixture);
}

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let output = openshell_cmd()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| format!("run openshell {}: {error}", args.join(" ")))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(combined)
    }
}

async fn wait_for_sandbox_logs(
    sandbox_name: &str,
    expected: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let logs = run_cli(&[
            "logs",
            sandbox_name,
            "-n",
            "500",
            "--since",
            "2m",
            "--source",
            "sandbox",
        ])
        .await?;
        if expected(&logs) {
            return Ok(logs);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for transparent TCP logs:\n{logs}"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn local_container_native_tcp_uses_policy_dns_and_fails_closed() {
    if !is_e2e_driver("docker") && !is_e2e_driver("podman") {
        return;
    }

    let fixture = SupportContainer::start_python(
        FIXTURE_ALIAS,
        &format!(
            r#"import socket, threading
def serve(port):
  s = socket.socket()
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(('0.0.0.0', port))
  s.listen()
  while True:
    c, _ = s.accept()
    data = c.recv(1024)
    c.sendall(b'native-tcp-ok:' + data)
    c.close()

threading.Thread(target=serve, args=({TRANSPARENT_LISTENER_PORT},), daemon=True).start()
serve({FIXTURE_PORT})
"#
        ),
        FIXTURE_PORT,
    )
    .await
    .expect("start TCP fixture");
    let real_ip = fixture.ip().expect("fixture IP");
    let policy = write_policy().expect("write policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create local-container sandbox");

    let script = format!(
        r#"import os, socket
for key in ('ALL_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'http_proxy', 'https_proxy'):
    os.environ.pop(key, None)
try:
    answers = socket.getaddrinfo({host:?}, {port}, type=socket.SOCK_STREAM)
except OSError as error:
    resolver = open('/etc/resolv.conf', encoding='utf-8').read()
    routes = open('/proc/net/route', encoding='utf-8').read()
    raise RuntimeError(f'policy DNS lookup failed: {{error}}\nresolv.conf:\n{{resolver}}\nroutes:\n{{routes}}') from error
synthetic = sorted({{item[4][0] for item in answers}})
assert any(ip.startswith('198.18.') or ip.startswith('198.19.') for ip in synthetic), synthetic
with socket.create_connection(({host:?}, {port}), timeout=10) as conn:
    conn.sendall(b'probe')
    assert conn.recv(1024) == b'native-tcp-ok:probe'

def denied(host, port):
    try:
        with socket.create_connection((host, port), timeout=3) as conn:
            conn.sendall(b'blocked')
            return conn.recv(1024) != b'native-tcp-ok:blocked'
    except OSError:
        return True

assert denied({host:?}, {wrong_port})
assert denied({real_ip:?}, {port})
assert denied({real_ip:?}, {transparent_port})
print('transparent-tcp-e2e-ok')
"#,
        host = FIXTURE_ALIAS,
        port = FIXTURE_PORT,
        wrong_port = FIXTURE_PORT + 1,
        real_ip = real_ip,
        transparent_port = TRANSPARENT_LISTENER_PORT,
    );
    let output = match sandbox.exec(&["python3", "-c", &script]).await {
        Ok(output) => output,
        Err(error) => {
            let logs = run_cli(&[
                "logs",
                &sandbox.name,
                "-n",
                "500",
                "--since",
                "2m",
                "--source",
                "sandbox",
            ])
            .await
            .unwrap_or_else(|log_error| format!("failed to collect logs: {log_error}"));
            panic!("exercise native TCP: {error}\nSandbox logs:\n{logs}");
        }
    };
    assert!(output.contains("transparent-tcp-e2e-ok"), "{output}");

    let logs = wait_for_sandbox_logs(&sandbox.name, |logs| {
        logs.contains(&format!("-> {FIXTURE_ALIAS}:{FIXTURE_PORT}"))
            && logs.contains("transparent_tcp_port_mismatch")
    })
    .await
    .expect("wait for sandbox logs");
    assert!(
        logs.contains(&format!("-> {FIXTURE_ALIAS}:{FIXTURE_PORT}")),
        "{logs}"
    );
    assert!(logs.contains("transparent_tcp_port_mismatch"), "{logs}");

    sandbox.cleanup().await;
}
