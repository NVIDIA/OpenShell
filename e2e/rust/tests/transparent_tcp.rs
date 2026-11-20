// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use openshell_e2e::harness::container::{SupportContainer, is_e2e_driver};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

// Use a qualified policy hostname so runtime-provided resolver search domains
// (for example Podman's `dns.podman`) cannot rewrite the policy identity.
const MUSL_FIXTURE_ALIAS: &str = "transparent-tcp-musl.openshell.test";
const FIXTURE_PORT: u16 = 5432;

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

fn private_fixture_probe(host: &str, marker: &str, should_connect: bool) -> String {
    format!(
        r"import socket
answers = socket.getaddrinfo({host:?}, {FIXTURE_PORT}, type=socket.SOCK_STREAM)
assert any(item[4][0].startswith(('198.18.', '198.19.')) for item in answers), answers
reached = False
try:
    with socket.create_connection(({host:?}, {FIXTURE_PORT}), timeout=3) as conn:
        conn.sendall({marker:?}.encode('ascii'))
        reached = conn.recv(1024) == b'private-fixture-ok'
except OSError:
    pass
assert reached == {expected}, reached
print('private-pin-probe-ok')
",
        expected = if should_connect { "True" } else { "False" }
    )
}

#[tokio::test]
async fn rootless_podman_private_dns_pins_do_not_cross_binary_rules() {
    if !is_e2e_driver("podman") {
        return;
    }
    let host = "transparent-private.openshell.test";
    let fixture = SupportContainer::start_python(
        host,
        &format!(
            r"import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', {FIXTURE_PORT}))
s.listen()
while True:
    c, _ = s.accept()
    data = c.recv(1024)
    if data:
        print(data.decode('ascii'), flush=True)
        c.sendall(b'private-fixture-ok')
    c.close()
"
        ),
        FIXTURE_PORT,
    )
    .await
    .expect("start private-network fixture");
    let fixture_ip = fixture
        .ip()
        .expect("fixture IP")
        .parse::<std::net::Ipv4Addr>()
        .expect("IPv4 fixture");
    assert!(
        fixture_ip.is_private(),
        "fixture must exercise private address enforcement"
    );
    let mut policy = NamedTempFile::new().expect("create policy");
    write!(
        policy,
        r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: {{ compatibility: best_effort }}
process: {{ run_as_user: sandbox, run_as_group: sandbox }}
network_policies:
  declared:
    name: declared
    endpoints:
      - {{ host: {host}, port: {FIXTURE_PORT}, protocol: tcp }}
    binaries: [{{ path: /sandbox/declared-python }}]
  wildcard:
    name: wildcard
    endpoints:
      - {{ host: '*.openshell.test', port: {FIXTURE_PORT}, protocol: tcp }}
    binaries: [{{ path: /sandbox/wildcard-python }}]
"
    )
    .expect("write policy");
    policy.flush().expect("flush policy");
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", &policy.path().to_string_lossy()],
        &["sh", "-c", "set -e; cp $(command -v python3) /sandbox/declared-python; cp $(command -v python3) /sandbox/wildcard-python; echo Ready; sleep infinity"],
        "Ready",
    ).await.expect("create private DNS sandbox");
    // Copied uv-managed executables still need their original standard library.
    let python_prefix = sandbox
        .exec(&["python3", "-c", "import sys; print(sys.base_prefix)"])
        .await
        .expect("find original Python installation prefix");
    let python_home = format!("PYTHONHOME={}", python_prefix.trim());
    let positive = sandbox
        .exec(&[
            "env",
            &python_home,
            "/sandbox/declared-python",
            "-c",
            &private_fixture_probe(host, "authorized-control", true),
        ])
        .await
        .expect("exact-host binary reaches fixture");
    assert!(positive.contains("private-pin-probe-ok"), "{positive}");
    let negative = sandbox
        .exec(&[
            "env",
            &python_home,
            "/sandbox/wildcard-python",
            "-c",
            &private_fixture_probe(host, "blocked-probe", false),
        ])
        .await
        .expect("wildcard binary cannot borrow private pins");
    assert!(negative.contains("private-pin-probe-ok"), "{negative}");
    let logs = fixture.logs().expect("private fixture logs");
    assert!(logs.contains("authorized-control"), "{logs}");
    assert!(
        !logs.contains("blocked-probe"),
        "denied probe reached private fixture: {logs}"
    );
    sandbox.cleanup().await;
}
