// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `host.openshell.internal` names the host from inside a sandbox, on every
//! compute driver.
//!
//! The test starts an HTTP server where the tests run, which is the host the
//! gateway runs its sandboxes on, and runs a client in a sandbox from the
//! Python test image ([`testkit::python_image`]) that requests a page from that
//! server through the name.

use testkit::{Context, Error, Result, ResultExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The image's system Python, which needs nothing beyond its standard library.
/// The policy names its real path, `/usr/bin/python3.*`, because a rule matches
/// the executable behind a symlink.
const PYTHON: &str = "/usr/bin/python3";

/// Requests `/` from `host.openshell.internal` on the port in `argv[1]` and
/// prints the response. A failed connection is retried for 20 seconds, so a
/// slow start doesn't fail the test, and reported on stderr.
const CLIENT: &str = r#"
import socket, sys, time

host, port = "host.openshell.internal", int(sys.argv[1])
deadline = time.monotonic() + 20
while True:
    try:
        conn = socket.create_connection((host, port), timeout=10)
        break
    except OSError as error:
        print(f"connect {host}:{port}: {error}", file=sys.stderr, flush=True)
        if time.monotonic() > deadline:
            sys.exit(1)
        time.sleep(1)
with conn:
    conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
    response = b""
    while chunk := conn.recv(4096):
        response += chunk
print(response.decode(errors="replace"))
"#;

/// A sandbox from the Python test image resolves `host.openshell.internal`
/// and gets a response from a server the test runs on the host. The default
/// policy denies all network access, so the test passes one that lets only the
/// image's Python reach the server's port.
#[testkit::test]
async fn python_sandbox_reaches_host_server(cx: &mut Context) -> testkit::Result {
    let marker = format!("host-gateway-{}", cx.run_id());
    let server = HostServer::start(marker.clone()).await?;
    let policy = PolicyFile::new(&policy(server.port))?;
    let port = server.port.to_string();
    let image = testkit::python_image();

    let name = cx.name("hg");
    cx.track(&name);
    let client = cx
        .cli([
            "sandbox",
            "create",
            "--name",
            &name,
            "--from",
            &image,
            "--policy",
            policy.path()?,
            "--no-tty",
            "--",
            PYTHON,
            "-c",
            CLIENT,
            &port,
        ])
        .await?
        .success()
        .context("run the client as the sandbox's main process")?;
    testkit::ensure!(
        client.stdout.contains(&marker),
        "the client did not get the host server's response:\n{}{}",
        client.stdout,
        client.stderr
    );
    Ok(())
}

/// A sandbox policy that allows the image's system Python ([`PYTHON`]) to
/// connect to `host.openshell.internal` on `port`. The endpoint names only the
/// host and port, as the policy docs describe, so the driver's address for the
/// name is what makes it reachable, not an `allowed_ips` range.
fn policy(port: u16) -> String {
    format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /dev/urandom, /etc]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  host_server:
    name: host_server
    endpoints:
      - host: host.openshell.internal
        port: {port}
    binaries:
      - path: /usr/bin/python3.*
"#
    )
}

/// An HTTP server on the host that answers every request with `body`. It
/// stops when dropped.
struct HostServer {
    port: u16,
    task: JoinHandle<()>,
}

impl HostServer {
    /// Listen on every host address, since drivers map
    /// `host.openshell.internal` to different ones.
    async fn start(body: String) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| Error::from_error(&error))
            .context("bind the host server")?;
        let port = listener
            .local_addr()
            .map_err(|error| Error::from_error(&error))
            .context("read the host server's address")?
            .port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(respond(stream, body.clone()));
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

/// Read one request's headers from `stream` and answer with `body`.
async fn respond(mut stream: TcpStream, body: String) {
    let _ = stream.set_nodelay(true);
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(read) if read > 0 && request.len() < 64 * 1024 => {
                request.extend_from_slice(&buf[..read]);
            }
            _ => return,
        }
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// A sandbox policy written to a temporary file for `sandbox create --policy`.
struct PolicyFile(tempfile::NamedTempFile);

impl PolicyFile {
    fn new(contents: &str) -> Result<Self> {
        let file = tempfile::NamedTempFile::new()
            .map_err(|error| Error::from_error(&error))
            .context("create policy file")?;
        std::fs::write(file.path(), contents)
            .map_err(|error| Error::from_error(&error))
            .context(format!("write {}", file.path().display()))?;
        Ok(Self(file))
    }

    fn path(&self) -> Result<&str> {
        let path = self.0.path();
        path.to_str()
            .ok_or_else(|| Error::msg(format!("{} is not UTF-8", path.display())))
    }
}
