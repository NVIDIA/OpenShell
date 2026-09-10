// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response preflight and stage selection.

use super::validation::{
    body_restriction, permitted_body_modes, strip_stale_integrity, validate_diagnostics,
    validate_inspect, validate_preflight_input,
};
use super::*;

impl ChainRunner {
    /// Apply selected stages' failure policies when valid HTTP cannot be encoded
    /// in the middleware protocol. The caller must validate HTTP safety first.
    pub fn http_response_input_unrepresentable(
        &self,
        entries: &[DescribedChainEntry],
    ) -> HttpResponsePreflightOutcome {
        response_preflight_input_failure(entries, Vec::new(), "response_input_unrepresentable")
    }

    pub async fn preflight_http_response(
        &self,
        entries: &[ChainEntry],
        input: HttpResponsePreflightInput,
    ) -> miette::Result<HttpResponsePreflightOutcome> {
        let described = self.describe_http_response_chain(entries).await?;
        self.preflight_described_http_response(described, input)
            .await
    }

    /// Run preflight with a response-filtered chain that the caller already
    /// described. This keeps response parsing and binding selection on one
    /// snapshot without repeating remote capability discovery.
    pub async fn preflight_described_http_response(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpResponsePreflightInput,
    ) -> miette::Result<HttpResponsePreflightOutcome> {
        if described.is_empty() {
            return Ok(empty_preflight_outcome(input.headers));
        }
        if validate_preflight_input(&input).is_err() {
            return Ok(response_preflight_input_failure(
                &described,
                input.headers,
                "response_input_over_capacity",
            ));
        }
        let session_admission = match self.try_reserve_middleware_session() {
            MiddlewareSessionAdmission::Admitted(admission) => admission,
            MiddlewareSessionAdmission::AtCapacity => {
                return Ok(response_session_capacity_exhausted(
                    described,
                    input.headers,
                ));
            }
        };
        let _work = self.reserve_middleware_work_admission().await?;
        let original_restriction = body_restriction(&input);
        let mut headers = input.headers.clone();
        let mut stages = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();

        for entry in described {
            let Some(service) = entry.service.as_ref() else {
                if let Some(reason) =
                    collect_preflight_failure(&entry, "binding_not_described", &mut invocations)
                {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            };
            let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
            let preflight = HttpResponsePreflight {
                context: Some(input.context.clone()),
                target: Some(input.target.clone()),
                status_code: u32::from(input.status_code),
                headers: headers.clone(),
                middleware_name: entry.entry.implementation.clone(),
                config: Some(entry.entry.config.clone()),
                max_payload_bytes: entry.max_payload_bytes as u64,
                permitted_body_modes: permitted_body_modes(
                    &input,
                    &entry,
                    original_restriction.as_deref(),
                ),
            };
            let timeout = entry.timeout;
            let opened = tokio::time::timeout(timeout, async {
                sender
                    .send(HttpResponseEvent {
                        event: Some(http_response_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
                let mut responses = service
                    .service
                    .open_http_response_pre_return(receiver)
                    .await?;
                let response = responses.next().await.ok_or_else(|| {
                    tonic::Status::unavailable("middleware result stream closed")
                })??;
                Ok::<_, tonic::Status>((responses, response))
            })
            .await;
            let (responses, response) = match opened {
                Ok(Ok(opened)) => opened,
                Ok(Err(error)) => {
                    let reason = if error.code() == tonic::Code::DeadlineExceeded {
                        "middleware_timeout".to_string()
                    } else {
                        service.diagnostic_policy.error_reason(&error)
                    };
                    if let Some(reason) =
                        collect_preflight_failure(&entry, &reason, &mut invocations)
                    {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                    continue;
                }
                Err(_) => {
                    if let Some(reason) =
                        collect_preflight_failure(&entry, "middleware_timeout", &mut invocations)
                    {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                    continue;
                }
            };
            let Some(http_response_event_result::Result::PreflightResult(decision)) =
                response.result
            else {
                if let Some(reason) = collect_preflight_failure(
                    &entry,
                    "unexpected_response_result",
                    &mut invocations,
                ) {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            };
            if let Err(reason) = validate_diagnostics(
                &decision.reason,
                &decision.reason_code,
                &decision.findings,
                &decision.metadata,
            ) {
                if let Some(reason) = collect_preflight_failure(&entry, reason, &mut invocations) {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            }
            let reason_code =
                (!decision.reason_code.is_empty()).then(|| decision.reason_code.clone());
            let decision_findings = decision.findings;
            let decision_metadata = decision.metadata;
            match decision.action {
                Some(http_response_preflight_result::Action::Skip(_)) => {
                    collect_preflight_diagnostics(
                        &entry,
                        decision_findings,
                        decision_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(HttpResponseInvocation {
                        config_name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        outcome: HttpResponseInvocationOutcome::Skip,
                        sequence: None,
                        input_size: 0,
                        output_size: None,
                        failed: false,
                        stage_disabled: false,
                        reason_code,
                        failure_category: None,
                    });
                    let mut skipped = HttpResponseStage {
                        entry,
                        transport: Some(HttpResponseStageTransport { sender, responses }),
                        mode: StageMode::HeadersOnly,
                        next_sequence: 1,
                        whole_body: Vec::new(),
                    };
                    skipped.end(MiddlewareSessionEndReason::StageSkipped).await;
                }
                Some(http_response_preflight_result::Action::Inspect(inspect)) => {
                    let permitted_modes =
                        permitted_body_modes(&input, &entry, original_restriction.as_deref());
                    let mode = match validate_inspect(&entry, &inspect, &permitted_modes) {
                        Ok(mode) => mode,
                        Err(reason) => {
                            if let Some(reason) =
                                collect_preflight_failure(&entry, &reason, &mut invocations)
                            {
                                end_stages(
                                    &mut stages,
                                    MiddlewareSessionEndReason::MiddlewareFailure,
                                )
                                .await;
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                            continue;
                        }
                    };
                    let updated = match headers::apply(
                        headers::HeaderAuthority::Response,
                        &headers,
                        &input.connection_nominated_headers,
                        &inspect.header_mutations,
                    ) {
                        Ok(updated) => updated,
                        Err(error) => {
                            let reason = service
                                .diagnostic_policy
                                .header_mutation_error_reason(&error);
                            if let Some(reason) =
                                collect_preflight_failure(&entry, &reason, &mut invocations)
                            {
                                end_stages(
                                    &mut stages,
                                    MiddlewareSessionEndReason::MiddlewareFailure,
                                )
                                .await;
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                            continue;
                        }
                    };
                    headers = updated;
                    if mode == StageMode::Stream {
                        strip_stale_integrity(&mut headers);
                    }
                    collect_preflight_diagnostics(
                        &entry,
                        decision_findings,
                        decision_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(HttpResponseInvocation {
                        config_name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        outcome: match mode {
                            StageMode::HeadersOnly => HttpResponseInvocationOutcome::HeadersOnly,
                            StageMode::WholeBody => HttpResponseInvocationOutcome::WholeBody,
                            StageMode::Stream => HttpResponseInvocationOutcome::Stream,
                        },
                        sequence: None,
                        input_size: 0,
                        output_size: None,
                        failed: false,
                        stage_disabled: false,
                        reason_code,
                        failure_category: None,
                    });
                    let mut stage = HttpResponseStage {
                        entry,
                        transport: Some(HttpResponseStageTransport { sender, responses }),
                        mode,
                        next_sequence: 1,
                        whole_body: Vec::new(),
                    };
                    if mode == StageMode::HeadersOnly {
                        stage.end(MiddlewareSessionEndReason::Normal).await;
                    } else {
                        stages.push(stage);
                    }
                }
                Some(http_response_preflight_result::Action::BlockDelivery(_)) => {
                    collect_preflight_diagnostics(
                        &entry,
                        decision_findings,
                        decision_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(HttpResponseInvocation {
                        config_name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        outcome: HttpResponseInvocationOutcome::BlockDelivery,
                        sequence: None,
                        input_size: 0,
                        output_size: None,
                        failed: false,
                        stage_disabled: false,
                        reason_code: reason_code.clone(),
                        failure_category: None,
                    });
                    stages.push(HttpResponseStage {
                        entry: entry.clone(),
                        transport: Some(HttpResponseStageTransport { sender, responses }),
                        mode: StageMode::HeadersOnly,
                        next_sequence: 1,
                        whole_body: Vec::new(),
                    });
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareDenial).await;
                    return Ok(blocked_preflight_outcome(
                        headers,
                        crate::MiddlewareDenial {
                            config_name: entry.entry.name.clone(),
                            reason_code,
                        },
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                None => {
                    if let Some(reason) = collect_preflight_failure(
                        &entry,
                        "invalid_preflight_decision",
                        &mut invocations,
                    ) {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                }
            }
        }

        if stages.is_empty() {
            drop(session_admission);
            return Ok(HttpResponsePreflightOutcome {
                allowed: true,
                reason: String::new(),
                denial: None,
                headers,
                session: None,
                findings,
                metadata,
                invocations,
                session_capacity_exhausted: false,
            });
        }
        let defer_output_until_finish = stages
            .iter()
            .any(|stage| stage.is_active() && stage.mode == StageMode::WholeBody);
        Ok(HttpResponsePreflightOutcome {
            allowed: true,
            reason: String::new(),
            denial: None,
            headers,
            session: Some(HttpResponseSession {
                runner: self.clone(),
                stages,
                findings: Vec::new(),
                metadata: BTreeMap::new(),
                invocations: Vec::new(),
                session_admission: Some(session_admission),
                body_transformed: false,
                retained_body_bytes: 0,
                defer_output_until_finish,
                deferred_output: Vec::new(),
                connection_nominated_headers: input.connection_nominated_headers,
                whole_body_deadline: None,
            }),
            findings,
            metadata,
            invocations,
            session_capacity_exhausted: false,
        })
    }
}
