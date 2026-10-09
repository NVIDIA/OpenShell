// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! v2 HTTP hook decisions about traffic `OpenShell` cannot inspect.
//!
//! A connection that selects middleware but cannot be shown to it as HTTP
//! messages (`tls: skip`, h2c, unsupported tunnels, raw TCP, SQL passthrough)
//! opens one `EvaluateHttpRequestV2` exchange per selected stage whose
//! service binds `HTTP_REQUEST_V2`, in chain order, with an uninspectable
//! preflight. Each stage continues, which allows the connection, or rejects
//! it. Any failure or timeout denies.
//! Other entries keep the v1 HTTP hook rule: `fail_open` lets the
//! connection through with a finding, `fail_closed` denies it.

use openshell_core::proto::{
    MiddlewareSessionEndReason, RequestContext, UninspectableTraffic, UninspectableTrafficReason,
    http_preflight, http_preflight_result, http_result,
};

use super::pipeline::{
    self, BodyModeOffer, HttpStageDiagnostics, HttpStageInvocation, HttpStageOutcome,
    PipelineTimeouts, StageHead,
};
use crate::{
    ChainEntry, ChainRunner, DescribedChainEntry, HttpHookVersion, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MiddlewareDenial, MiddlewareWorkAdmissionOutcome, NamespacedFinding, OnError,
    sort_chain_entries, uninspectable_traffic_binding,
};

/// A connection `OpenShell` cannot show to middleware as HTTP messages.
#[derive(Debug, Clone)]
pub struct UninspectableTrafficInput {
    /// Sandbox and originating process identity.
    pub context: RequestContext,
    pub host: String,
    pub port: u16,
    /// Network policy that admitted the connection.
    pub endpoint: String,
    pub reason: UninspectableTrafficReason,
}

/// What one entry decided about an uninspectable connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninspectableInvocation {
    pub config_name: String,
    pub implementation: String,
    /// `Continue`, `Reject`, or `FailClosed` for a v2 HTTP hook stage;
    /// `FailOpen` or `FailClosed` for another entry, by its `on_error`.
    pub outcome: HttpStageOutcome,
    pub http_hook_version: Option<HttpHookVersion>,
    pub reason_code: Option<String>,
    /// Platform-owned failure reason.
    pub failure_reason: Option<String>,
}

/// Decision about one uninspectable connection.
#[derive(Debug, Clone, Default)]
pub struct UninspectableOutcome {
    pub allowed: bool,
    /// Platform-owned reason for a denial: `middleware_denied:<config>[:<code>]`
    /// for a rejection, `middleware_failed: <reason>` otherwise.
    pub reason: String,
    /// Present only when a v2 HTTP hook stage rejected the connection.
    pub denial: Option<MiddlewareDenial>,
    /// One record per evaluated entry, in chain order.
    pub invocations: Vec<UninspectableInvocation>,
    pub findings: Vec<NamespacedFinding>,
}

struct UninspectableHead<'a> {
    input: &'a UninspectableTrafficInput,
}

impl StageHead for UninspectableHead<'_> {
    fn context(&self) -> &RequestContext {
        &self.input.context
    }

    fn preflight_subject(
        &self,
        _headers: &[openshell_core::proto::HttpHeader],
    ) -> http_preflight::Subject {
        http_preflight::Subject::Uninspectable(UninspectableTraffic {
            host: self.input.host.clone(),
            port: u32::from(self.input.port),
            endpoint: self.input.endpoint.clone(),
            reason: self.input.reason as i32,
        })
    }

    fn body_modes(&self, _entry: &DescribedChainEntry) -> BodyModeOffer {
        BodyModeOffer::default()
    }
}

impl ChainRunner {
    /// Decide whether an uninspectable connection that selects `entries` may
    /// proceed. Every entry whose service binds `HTTP_REQUEST_V2` must
    /// continue; other entries follow their `on_error`. Evaluation stops at
    /// the first denial.
    pub async fn evaluate_uninspectable(
        &self,
        entries: &[ChainEntry],
        input: UninspectableTrafficInput,
    ) -> UninspectableOutcome {
        let mut entries = entries.to_vec();
        sort_chain_entries(&mut entries);
        let mut outcome = UninspectableOutcome {
            allowed: true,
            ..UninspectableOutcome::default()
        };
        let chain_deadline = tokio::time::Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let mut work = None;
        for entry in entries {
            if !self.decides_uninspectable_traffic(&entry.implementation) {
                let protocol = self.http_hook_version_of(&entry.implementation);
                let failed_open = entry.on_error == OnError::FailOpen;
                outcome.invocations.push(UninspectableInvocation {
                    config_name: entry.name.clone(),
                    implementation: entry.implementation.clone(),
                    outcome: if failed_open {
                        HttpStageOutcome::FailOpen
                    } else {
                        HttpStageOutcome::FailClosed
                    },
                    http_hook_version: protocol,
                    reason_code: None,
                    failure_reason: Some("traffic_uninspectable".to_string()),
                });
                if !failed_open {
                    return outcome.deny("middleware_failed: traffic_uninspectable", None);
                }
                continue;
            }
            if work.is_none() {
                match self.reserve_middleware_work().await {
                    Ok(MiddlewareWorkAdmissionOutcome::Admitted(admission)) => {
                        work = Some(admission);
                    }
                    Ok(MiddlewareWorkAdmissionOutcome::QueueExhausted) | Err(_) => {
                        outcome
                            .invocations
                            .push(failed(&entry, "admission_exhausted"));
                        return outcome.deny("middleware_failed: admission_exhausted", None);
                    }
                }
            }
            let Some(described) = self.describe_uninspectable_entry(&entry).await else {
                outcome
                    .invocations
                    .push(failed(&entry, "binding_not_described"));
                return outcome.deny("middleware_failed: binding_not_described", None);
            };
            match evaluate_stage(&described, &input, chain_deadline).await {
                Ok(diagnostics) => {
                    outcome.findings.extend(diagnostics.findings);
                    outcome
                        .invocations
                        .extend(diagnostics.invocations.into_iter().map(record));
                }
                Err(failure) => {
                    let diagnostics = *failure.diagnostics;
                    outcome.findings.extend(diagnostics.findings);
                    outcome
                        .invocations
                        .extend(diagnostics.invocations.into_iter().map(record));
                    return outcome.deny(&failure.reason, failure.denial);
                }
            }
        }
        outcome
    }

    /// Resolve an entry to its service for an uninspectable preflight, using
    /// the timeout of its `HTTP_REQUEST_V2` binding.
    async fn describe_uninspectable_entry(
        &self,
        entry: &ChainEntry,
    ) -> Option<DescribedChainEntry> {
        let manifests = self.manifests().await.ok()?;
        let (state, manifest) = manifests.iter().find(|(state, manifest)| {
            Self::attachment_name(state, manifest) == entry.implementation
        })?;
        let binding = *uninspectable_traffic_binding(manifest)?;
        let timeout = state.timeout_for_binding(&binding).ok()?;
        Some(DescribedChainEntry {
            entry: entry.clone(),
            service: Some(std::sync::Arc::clone(state)),
            binding: Some(binding),
            max_payload_bytes: 0,
            timeout,
            http_hook_version: Some(HttpHookVersion::V2),
        })
    }
}

impl UninspectableOutcome {
    fn deny(mut self, reason: &str, denial: Option<MiddlewareDenial>) -> Self {
        self.allowed = false;
        self.reason = reason.to_string();
        self.denial = denial;
        self
    }
}

fn failed(entry: &ChainEntry, reason: &str) -> UninspectableInvocation {
    UninspectableInvocation {
        config_name: entry.name.clone(),
        implementation: entry.implementation.clone(),
        outcome: HttpStageOutcome::FailClosed,
        http_hook_version: Some(HttpHookVersion::V2),
        reason_code: None,
        failure_reason: Some(reason.to_string()),
    }
}

fn record(invocation: HttpStageInvocation) -> UninspectableInvocation {
    UninspectableInvocation {
        config_name: invocation.config_name,
        implementation: invocation.implementation,
        outcome: invocation.outcome,
        http_hook_version: Some(HttpHookVersion::V2),
        reason_code: invocation.reason_code,
        failure_reason: invocation.failure_reason,
    }
}

/// Run one uninspectable preflight exchange.
async fn evaluate_stage(
    entry: &DescribedChainEntry,
    input: &UninspectableTrafficInput,
    chain_deadline: tokio::time::Instant,
) -> Result<HttpStageDiagnostics, pipeline::HttpMiddlewareFailure> {
    let head = UninspectableHead { input };
    let event = pipeline::preflight_event(
        entry,
        &head,
        &[],
        BodyModeOffer::default(),
        PipelineTimeouts::default(),
        None,
    );
    let (deadline, timeout_reason) = pipeline::preflight_deadline(entry, chain_deadline);
    let (mut stream, first) = pipeline::open_stage(entry, event, deadline, timeout_reason).await?;
    let result = match pipeline::classify_result(entry, first) {
        Ok(result) => result,
        Err(failure) => {
            stream.end(failure.end_reason).await;
            return Err(failure);
        }
    };
    let decided = match result {
        http_result::Result::PreflightResult(result) => {
            match pipeline::validate_diagnostics(entry, result.diagnostics.as_ref()) {
                Err(failure) => Err(failure),
                Ok(_) if !result.header_mutations.is_empty() => Err(pipeline::entry_failure(
                    entry,
                    "uninspectable_header_mutations",
                )),
                Ok(diagnostics) => match result.decision {
                    Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => {
                        let mut collected = HttpStageDiagnostics::default();
                        let reason_code = (!diagnostics.reason_code.is_empty())
                            .then(|| diagnostics.reason_code.clone());
                        pipeline::collect_diagnostics(entry, diagnostics, &mut collected);
                        collected.invocations.push(pipeline::invocation(
                            entry,
                            HttpStageOutcome::Continue,
                            reason_code,
                        ));
                        Ok(collected)
                    }
                    Some(http_preflight_result::Decision::Inspect(_)) => {
                        Err(pipeline::entry_failure(entry, "body_mode_not_permitted"))
                    }
                    None => Err(pipeline::entry_failure(entry, "preflight_result_unknown")),
                },
            }
        }
        http_result::Result::Reject(reject) => {
            Err(pipeline::rejection(entry, reject.diagnostics.as_ref()))
        }
        _ => Err(pipeline::entry_failure(entry, "preflight_result_expected")),
    };
    let end_reason = match &decided {
        Ok(_) => MiddlewareSessionEndReason::StageSkipped,
        Err(failure) => failure.end_reason,
    };
    stream.end(end_reason).await;
    decided
}
