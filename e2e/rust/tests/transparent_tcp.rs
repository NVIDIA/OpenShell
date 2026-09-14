// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{SupportContainer, is_e2e_driver};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

// Use a qualified policy hostname so runtime-provided resolver search domains
// (for example Podman's `dns.podman`) cannot rewrite the policy identity.
const FIXTURE_ALIAS: &str = "transparent-tcp-fixture.openshell.test";
const MUSL_FIXTURE_ALIAS: &str = "transparent-tcp-musl.openshell.test";
const FIXTURE_PORT: u16 = 5432;
const TCP_DNS_PORT: u16 = 53;
const TRANSPARENT_LISTENER_PORT: u16 = 15001;

struct MuslDnsProbe {
    _tempdir: tempfile::TempDir,
    path: PathBuf,
}

impl MuslDnsProbe {
    fn build() -> Result<Self, String> {
        let target = match std::env::consts::ARCH {
            "x86_64" => "x86_64-linux-musl",
            "aarch64" => "aarch64-linux-musl",
            arch => return Err(format!("unsupported musl DNS probe architecture: {arch}")),
        };
        let tempdir =
            tempfile::tempdir().map_err(|error| format!("create probe directory: {error}"))?;
        let path = tempdir.path().join("musl-dns-probe");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../support/musl-dns-probe.c")
            .canonicalize()
            .map_err(|error| format!("locate musl DNS probe source: {error}"))?;

        let output = Command::new("mise")
            .args([
                "x",
                "--",
                "zig",
                "cc",
                "-target",
                target,
                "-static",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                source
                    .to_str()
                    .ok_or_else(|| "probe source path is not UTF-8".to_string())?,
                "-o",
                path.to_str()
                    .ok_or_else(|| "probe output path is not UTF-8".to_string())?,
            ])
            .output()
            .map_err(|error| format!("build static musl DNS probe: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "musl DNS probe build failed (exit {:?}):\n{}{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(Self {
            _tempdir: tempdir,
            path,
        })
    }
}

fn write_policy() -> Result<NamedTempFile, String> {
    write_policy_for_identity(
        FIXTURE_ALIAS,
        "sandbox",
        "sandbox",
        &[],
        &[FIXTURE_PORT, TCP_DNS_PORT],
    )
}

fn write_policy_for(host: &str) -> Result<NamedTempFile, String> {
    write_policy_for_identity(host, "sandbox", "sandbox", &[], &[FIXTURE_PORT])
}

fn write_policy_for_identity(
    host: &str,
    run_as_user: &str,
    run_as_group: &str,
    extra_read_only: &[&str],
    ports: &[u16],
) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let extra_read_only = extra_read_only
        .iter()
        .map(|path| format!(", {path}"))
        .collect::<String>();
    let ports = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let policy = format!(
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log{extra_read_only}]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: {{ compatibility: best_effort }}
process: {{ run_as_user: {run_as_user}, run_as_group: {run_as_group} }}
network_policies:
  native_database:
    name: native_database
    endpoints:
      - host: {host}
        ports: [{ports}]
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
async fn rootless_podman_musl_getaddrinfo_uses_udp_policy_dns() {
    if !is_e2e_driver("podman") {
        return;
    }

    let probe = MuslDnsProbe::build().expect("build static musl DNS probe");
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

    // Keep sandbox-image compatibility out of this test. The statically linked
    // probe executes musl's getaddrinfo inside the normal, known-good sandbox
    // image, so this test isolates rootless Podman's UDP policy-DNS path.
    let policy = write_policy_for(MUSL_FIXTURE_ALIAS).expect("write musl policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path, "--no-tty"],
        &["sh", "-c", "echo Ready; sleep 2147483647"],
        "Ready",
    )
    .await
    .expect("create sandbox for musl DNS probe");

    sandbox
        .upload(
            probe.path.to_str().expect("probe path is UTF-8"),
            "/sandbox/musl-dns-probe",
        )
        .await
        .expect("upload musl DNS probe");

    let output = sandbox
        .exec(&[
            "/sandbox/musl-dns-probe",
            MUSL_FIXTURE_ALIAS,
            &FIXTURE_PORT.to_string(),
        ])
        .await
        .expect("exercise musl getaddrinfo over policy DNS");
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

    let fixture = SupportContainer::start_python_with_capabilities(
        FIXTURE_ALIAS,
        &format!(
            r#"import socket, threading
def listen(port):
  s = socket.socket()
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(('0.0.0.0', port))
  s.listen()
  return s

def serve(s):
  while True:
    c, _ = s.accept()
    data = c.recv(1024)
    c.sendall(b'native-tcp-ok:' + data)
    c.close()

transparent_listener = listen({TRANSPARENT_LISTENER_PORT})
tcp_dns_listener = listen({TCP_DNS_PORT})
fixture_listener = listen({FIXTURE_PORT})
threading.Thread(target=serve, args=(transparent_listener,), daemon=True).start()
threading.Thread(target=serve, args=(tcp_dns_listener,), daemon=True).start()
serve(fixture_listener)
"#
        ),
        FIXTURE_PORT,
        &["NET_BIND_SERVICE"],
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
with socket.create_connection(({host:?}, {tcp_dns_port}), timeout=10) as conn:
    conn.sendall(b'tcp-53-probe')
    assert conn.recv(1024) == b'native-tcp-ok:tcp-53-probe'

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
        tcp_dns_port = TCP_DNS_PORT,
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
