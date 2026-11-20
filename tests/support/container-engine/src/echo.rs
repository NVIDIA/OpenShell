// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use testkit::{Context, Poll, Result};

use crate::Engine;

const ECHO_FIXTURE: &str = include_str!("../scripts/echo_fixture.py");
/// Checks that the fixture listens on every port in argv.
const LISTENING: &str = "import socket, sys
for port in sys.argv[1:]:
    socket.create_connection(('127.0.0.1', int(port)), timeout=1).close()
";
const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// A container on the gateway's network that echoes TCP, for a test that
/// needs an endpoint sandboxes reach by name at a private address rather
/// than through `host.openshell.internal`.
///
/// It runs `python3` from [`testkit::python_image`], answers each
/// connection's first read with the same bytes, and prints them, so
/// [`EchoContainer::received`] shows what arrived.
pub struct EchoContainer {
    engine: Engine,
    pub id: String,
    /// The container's address on the network.
    pub ip: String,
}

impl EchoContainer {
    /// Start the container on [`Engine::network_from_env`] with network
    /// alias `alias`, listening on `ports`, and wait until it listens. It's
    /// removed when the test ends.
    pub async fn start(cx: &Context, engine: &Engine, alias: &str, ports: &[u16]) -> Result<Self> {
        let network = Engine::network_from_env()?;
        let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
        let mut args = vec![
            "--network".to_string(),
            network.clone(),
            "--network-alias".to_string(),
            alias.to_string(),
            // For ports below 1024, such as 53.
            "--cap-add".to_string(),
            "NET_BIND_SERVICE".to_string(),
            "--entrypoint".to_string(),
            "python3".to_string(),
            testkit::python_image(),
            "-c".to_string(),
            ECHO_FIXTURE.to_string(),
        ];
        args.extend(ports.iter().cloned());
        let id = engine.run_test_container(cx, "echo", args).await?;

        let mut ready = vec![
            "exec".to_string(),
            id.clone(),
            "python3".to_string(),
            "-c".to_string(),
            LISTENING.to_string(),
        ];
        ready.extend(ports);
        testkit::poll_until(
            &format!("echo container {id} to listen"),
            READY_TIMEOUT,
            Duration::from_millis(500),
            async || {
                Ok(match engine.output(&ready).await {
                    Ok(_) => Poll::Ready(()),
                    Err(error) => Poll::Pending(error.to_string()),
                })
            },
        )
        .await?;
        let ip = engine.container_ip(&id, &network).await?;
        Ok(Self {
            engine: engine.clone(),
            id,
            ip,
        })
    }

    /// The bytes every connection has sent so far, one read per line.
    pub async fn received(&self) -> Result<String> {
        Ok(self.engine.logs(&self.id).await?.stdout)
    }
}
