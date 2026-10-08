// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy adapters driven as version 2 stages over the v0.1.2 wire.
//!
//! [`StageDriver`] plays the pipeline's side of one stage transport: it sends
//! version 2 events and reads results. The suites mirror the 0.1.x
//! characterization in `crate::compat_tests` and assert the same observable
//! outcomes through the adapters: what the legacy service received, the
//! bytes and head mutations released, deny reasons, findings, `fail_open`
//! handling, and the reported 0.1.x invocations.

mod request;
mod response;

use std::future::Future;
use std::time::Duration;

use futures::StreamExt as _;
use prost::Message;
use tokio::sync::mpsc;

use openshell_core::proto::{
    HttpEvent, HttpHeader, HttpRequestTarget, MiddlewareSessionEnd, MiddlewareSessionEndReason,
    RequestContext, SupervisorMiddlewareService, http_event, http_result,
};
use openshell_supervisor_middleware_wire_fixture::RunningFixture;

use super::codec::LegacyStageFailure;
use crate::{
    ChainEntry, ChainRunner, ContractFailureKind, HttpResultStream, HttpStageTransport,
    MiddlewareRegistry, OnError, StageReport, StageReports,
};

/// Longest a test waits for one result before failing instead of hanging.
const RESULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Operator registration for a fixture with the 500 ms default timeout.
fn registration(
    name: &str,
    fixture: &RunningFixture,
    max_payload_bytes: u64,
) -> SupervisorMiddlewareService {
    SupervisorMiddlewareService {
        name: name.into(),
        grpc_endpoint: fixture.endpoint(),
        max_payload_bytes,
        request_timeout: None,
        tls_ca_cert_pem: Vec::new(),
        audience: String::new(),
        allow_insecure_transport: true,
        ..Default::default()
    }
}

async fn connect(registrations: Vec<SupervisorMiddlewareService>) -> ChainRunner {
    ChainRunner::from_registry(
        MiddlewareRegistry::connect_services(Vec::new(), registrations)
            .await
            .expect("register legacy middleware"),
    )
}

/// One policy attachment whose config names it.
fn entry(name: &str, implementation: &str, order: i32, on_error: OnError) -> ChainEntry {
    ChainEntry {
        name: name.into(),
        implementation: implementation.into(),
        order,
        config: prost_types::Struct {
            fields: std::iter::once((
                "attachment".to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(name.into())),
                },
            ))
            .collect(),
        },
        on_error,
    }
}

/// Decode a v0.1.2 message with the in-tree schema.
fn transcode<T: Message, U: Message + Default>(message: &T) -> U {
    U::decode(message.encode_to_vec().as_slice())
        .expect("a v0.1.2 message decodes with the in-tree schema")
}

fn context() -> RequestContext {
    RequestContext {
        request_id: "adapter-request".into(),
        sandbox_id: "adapter-sandbox-id".into(),
        sandbox: "adapter-sandbox".into(),
        workspace: "adapter-workspace".into(),
        originating_process: None,
    }
}

fn target(method: &str, path: &str, query: &str) -> HttpRequestTarget {
    HttpRequestTarget {
        scheme: "https".into(),
        host: "api.example.test".into(),
        port: 443,
        method: method.into(),
        path: path.into(),
        query: query.into(),
    }
}

fn headers(pairs: &[(&str, &str)]) -> Vec<HttpHeader> {
    pairs
        .iter()
        .map(|(name, value)| HttpHeader {
            name: (*name).to_string(),
            value: (*value).to_string(),
        })
        .collect()
}

/// One version 2 result as the pipeline sees it.
#[derive(Debug, Clone, PartialEq)]
enum Out {
    Result(http_result::Result),
    /// The stage failed closed under `on_error` with this 0.1.x reason.
    Failed(LegacyStageFailure),
    /// The legacy RPC broke the wire contract.
    Contract(ContractFailureKind),
}

impl Out {
    fn failed_reason(&self) -> Option<&str> {
        match self {
            Self::Failed(failure) => Some(&failure.reason),
            _ => None,
        }
    }
}

/// The pipeline's side of one stage transport.
struct StageDriver {
    events: Option<mpsc::Sender<HttpEvent>>,
    results: HttpResultStream,
}

impl StageDriver {
    async fn open(transport: &dyn HttpStageTransport) -> Self {
        let (events, receiver) = mpsc::channel(16);
        let results = transport.open(receiver).await.expect("open stage");
        Self {
            events: Some(events),
            results,
        }
    }

    /// Send one event. A stage that already returned its last result has
    /// stopped reading, which the pipeline tolerates.
    fn send(&self, event: http_event::Event) -> impl Future<Output = ()> + Send + use<> {
        let events = self.events.clone();
        async move {
            if let Some(events) = events {
                let _ = events.send(HttpEvent { event: Some(event) }).await;
            }
        }
    }

    /// Next result, or `None` once the stage ended its stream.
    async fn next(&mut self) -> Option<Out> {
        let next = tokio::time::timeout(RESULT_TIMEOUT, self.results.next())
            .await
            .expect("the stage answers in time")?;
        Some(match next {
            Ok(result) => Out::Result(result.result.expect("results carry an alternative")),
            Err(status) => ContractFailureKind::from_status(&status).map_or_else(
                || {
                    Out::Failed(LegacyStageFailure::from_status(&status).unwrap_or_else(|| {
                        panic!(
                            "a legacy stage fails only with its own or contract statuses: {status}"
                        )
                    }))
                },
                Out::Contract,
            ),
        })
    }

    async fn result(&mut self) -> Out {
        self.next().await.expect("the stage returns a result")
    }

    /// Close the event stream without `session_end` and drain the results.
    async fn close(&mut self) {
        self.events.take();
        while tokio::time::timeout(RESULT_TIMEOUT, self.results.next())
            .await
            .expect("the stage ends in time")
            .is_some()
        {}
    }

    /// Send `session_end`, close the event stream, and drain the results, as
    /// the pipeline ends a stage.
    async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        self.send(http_event::Event::SessionEnd(MiddlewareSessionEnd {
            reason: reason as i32,
            protocol_error: None,
        }))
        .await;
        self.close().await;
    }
}

/// Reports for `config_name`, in arrival order.
fn reports_for(reports: &StageReports, config_name: &str) -> Vec<StageReport> {
    reports
        .drain()
        .into_iter()
        .filter(|(name, _)| name == config_name)
        .map(|(_, report)| report)
        .collect()
}

fn fail_open_reasons(reports: &[StageReport]) -> Vec<String> {
    reports
        .iter()
        .filter_map(|report| match report {
            StageReport::LegacyFailOpen { reason } => Some(reason.clone()),
            StageReport::LegacyResponseInvocation { .. } => None,
        })
        .collect()
}
