// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Port forwarding with `openshell forward`.
//!
//! Ported from the `port_forward` e2e test.

use std::time::Duration;

use sandbox_clients_support::scripts::ECHO_SERVER;
use testkit::{Context, policy};

/// How long `forward start` and the first echo through it may take.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(60);

/// `forward start -d` forwards a local port to a server on the sandbox's
/// loopback, and `forward stop` ends it.
#[testkit::test]
async fn forward_reaches_sandbox_loopback_server(cx: &mut Context) -> testkit::Result {
    let local_port = host_server_support::free_port().await?;
    let port = local_port.to_string();
    let sandbox = cx
        .sandbox("fwd")
        .policy(policy::base())
        .image(testkit::python_image())
        .command(["python3", "-c", ECHO_SERVER, &port])
        .create_ready()
        .await?;
    let name = sandbox.name().to_string();

    // The forward's ssh keeps the CLI's stdout and stderr open, so wait for
    // the CLI to exit rather than for its output to end.
    let mut start = cx.cli_spawn(["forward", "start", "-d", &port, &name])?;
    let code = start.wait(FORWARD_TIMEOUT).await?;
    if code != 0 {
        let output = start.output(FORWARD_TIMEOUT).await?;
        return Err(testkit::Error::msg(format!(
            "`{}` exited {code}:\n{}",
            output.command,
            output.report_text()
        )));
    }
    // Stops the forward if the test fails before it does. Its outcome is
    // ignored, since the forward is already gone when the test passes.
    let cli = cx.cli_handle();
    let (stop_port, stop_name) = (port.clone(), name.clone());
    cx.on_cleanup(format!("stop forward {port}"), async move || {
        cli.run(["forward", "stop", &stop_port, &stop_name]).await?;
        Ok(())
    });

    testkit::poll_until(
        &format!("an echo through forwarded port {port}"),
        FORWARD_TIMEOUT,
        Duration::from_secs(1),
        async || {
            Ok(
                match host_server_support::exchange(local_port, b"hello-forward\n").await {
                    Ok(reply) if reply == b"echo:hello-forward\n" => testkit::Poll::Ready(()),
                    Ok(reply) => testkit::Poll::Pending(format!(
                        "reply {:?}",
                        String::from_utf8_lossy(&reply)
                    )),
                    Err(error) => testkit::Poll::Pending(error.to_string()),
                },
            )
        },
    )
    .await?;

    cx.cli(["forward", "stop", &port, &name]).await?.success()?;
    testkit::poll_until(
        &format!("forwarded port {port} to close"),
        FORWARD_TIMEOUT,
        Duration::from_secs(1),
        async || {
            Ok(
                match host_server_support::exchange(local_port, b"after-stop\n").await {
                    Err(_) => testkit::Poll::Ready(()),
                    Ok(reply) => testkit::Poll::Pending(format!(
                        "still forwarding; reply {:?}",
                        String::from_utf8_lossy(&reply)
                    )),
                },
            )
        },
    )
    .await
}
