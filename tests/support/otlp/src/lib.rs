// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! An OTLP collector for suites whose gateway exports to a collector the
//! test runs.
//!
//! The environment configures the gateway's `[openshell.gateway.otlp]`
//! endpoint and publishes it, with the port the test must listen on, in
//! `OPENSHELL_TEST_OTLP_*` variables. Under `openshell-test-runner`, the
//! tmachine `<podman base>-otlp` environments do that
//! (`tests/tmachine/ansible/playbooks/otlp.yaml`); against your own
//! deployment, set them yourself:
//!
//! | Variable | Example |
//! |---|---|
//! | `OPENSHELL_TEST_OTLP_PORT` | `4317` |
//! | `OPENSHELL_TEST_OTLP_ENDPOINT` | `http://host.containers.internal:4317` |
//!
//! A missing variable fails the test; it never skips it. Tests that start a
//! collector can't run at the same time, since they bind the same port.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use openshell_otel_test_support::OtlpTestServer;
use testkit::{Error, Poll, Result, ResultExt as _, poll_until};

pub use openshell_otel_test_support::ReceivedTraces;
pub use openshell_otel_test_support::relay::{
    SANDBOX_ID_KEY, SOURCE_KEY, SOURCE_VALUE, encoded_trace_request,
};

pub const PORT_ENV: &str = "OPENSHELL_TEST_OTLP_PORT";
pub const ENDPOINT_ENV: &str = "OPENSHELL_TEST_OTLP_ENDPOINT";

/// String resource attributes, keyed by name.
pub type Attributes = HashMap<String, String>;

/// An OTLP/gRPC collector on the port the environment chose. It records
/// what arrives and stops when dropped.
pub struct Collector {
    server: OtlpTestServer,
    endpoint: String,
}

impl Collector {
    /// Listen on [`PORT_ENV`] on every host address.
    pub async fn start() -> Result<Self> {
        let port = required(PORT_ENV)?;
        let endpoint = required(ENDPOINT_ENV)?;
        let port: u16 = port
            .parse()
            .map_err(|error| Error::msg(format!("{PORT_ENV}={port}: {error}")))?;
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let server = OtlpTestServer::try_start_on(addr)
            .await
            .context(format!("start the OTLP collector on {addr}"))?;
        Ok(Self { server, endpoint })
    }

    /// The endpoint the gateway exports to, such as
    /// `http://host.containers.internal:4317`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The `host:port` of [`Self::endpoint`].
    pub fn host_port(&self) -> &str {
        let authority = self
            .endpoint
            .split_once("://")
            .map_or(self.endpoint.as_str(), |(_, rest)| rest);
        authority.split('/').next().unwrap_or(authority)
    }

    /// Everything received so far.
    pub fn received(&self) -> ReceivedTraces {
        self.server.received()
    }

    /// Wait up to `within` until every span in `names` has arrived. Returns
    /// the resource attributes of the batch each span arrived in, keyed by
    /// span name.
    pub async fn wait_for_spans(
        &self,
        names: &[&str],
        within: Duration,
    ) -> Result<HashMap<String, Attributes>> {
        poll_until(
            &format!("the collector to receive spans {names:?}"),
            within,
            Duration::from_millis(250),
            async || {
                let received = self.received();
                let arrived: Vec<&str> = received
                    .spans
                    .iter()
                    .map(|span| span.name.as_str())
                    .collect();
                if !names.iter().all(|name| arrived.contains(name)) {
                    return Ok(Poll::Pending(format!("received spans {arrived:?}")));
                }
                Ok(Poll::Ready(
                    received
                        .spans
                        .iter()
                        .zip(&received.span_resources)
                        .map(|(span, attributes)| (span.name.clone(), attributes.clone()))
                        .collect(),
                ))
            },
        )
        .await
    }

    /// Stop listening, so the next test can bind the port.
    pub async fn shutdown(self) {
        drop(self.server.shutdown().await);
    }
}

fn required(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::msg(format!(
                "{name} is not set; this suite needs a gateway that exports to a test collector (see the otlp-support crate docs)"
            ))
        })
}
