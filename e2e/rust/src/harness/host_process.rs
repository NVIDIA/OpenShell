// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-process TCP fixtures for e2e tests.
//!
//! [`HostSupportContainer`](super::container::HostSupportContainer) publishes
//! the same shape of fixture through a container engine. VM sandboxes reach
//! the host through gvproxy's `host.openshell.internal` alias and the VM e2e
//! lane has no container runtime of its own, so this variant runs the fixture
//! as a plain host process instead — keeping the lane free of a container
//! dependency it does not otherwise need.

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::port::wait_for_port;

/// A `python3` fixture listening on a host TCP port.
///
/// Output is captured to a temp file rather than a pipe: these fixtures log
/// every request they serve, and a full pipe buffer would block the process
/// mid-test. [`logs`](Self::logs) reads the file, which is where a test finds
/// its evidence (the CONNECT targets a proxy saw, for example).
pub struct HostPythonFixture {
    /// Host port the fixture listens on.
    pub port: u16,
    child: Child,
    log_path: PathBuf,
}

impl HostPythonFixture {
    /// Start `python3 -c <script>` and wait until `port` accepts connections.
    ///
    /// The script is responsible for binding `port`; pass it in through the
    /// script text so the caller controls which port the fixture uses.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned or does not listen
    /// within 60 seconds.
    pub async fn start(script: &str, port: u16) -> Result<Self, String> {
        let log_path = std::env::temp_dir().join(format!(
            "openshell-e2e-fixture-{}-{port}.log",
            std::process::id()
        ));
        let log = std::fs::File::create(&log_path)
            .map_err(|err| format!("create fixture log '{}': {err}", log_path.display()))?;
        let stderr = log
            .try_clone()
            .map_err(|err| format!("clone fixture log handle: {err}"))?;

        let child = Command::new("python3")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|err| format!("spawn python3 fixture on port {port}: {err}"))?;

        let fixture = Self {
            port,
            child,
            log_path,
        };
        // Bind to 127.0.0.1 for the readiness probe even though the fixture
        // listens on 0.0.0.0: the guest reaches it through gvproxy's NAT to
        // the host loopback, so loopback reachability is what matters.
        wait_for_port("127.0.0.1", port, Duration::from_secs(60))
            .await
            .map_err(|err| {
                format!(
                    "{err}. Fixture output:\n{}",
                    fixture.logs().unwrap_or_else(|err| err)
                )
            })?;
        Ok(fixture)
    }

    /// Read everything the fixture has written so far.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be read.
    pub fn logs(&self) -> Result<String, String> {
        let mut file = std::fs::File::open(&self.log_path)
            .map_err(|err| format!("open fixture log '{}': {err}", self.log_path.display()))?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .map_err(|err| format!("read fixture log '{}': {err}", self.log_path.display()))?;
        Ok(buf)
    }
}

impl Drop for HostPythonFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log_path);
    }
}
