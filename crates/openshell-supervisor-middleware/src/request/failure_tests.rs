// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn entry() -> DescribedChainEntry {
    DescribedChainEntry {
        entry: ChainEntry {
            name: "guard".into(),
            implementation: "test/guard".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        },
        service: None,
        binding: None,
        max_payload_bytes: 1024,
        timeout: Duration::from_millis(50),
    }
}

#[tokio::test(start_paused = true)]
async fn service_deadline_is_distinct_from_platform_deadlines() {
    let entry = entry();
    let mut remote: super::super::HttpResultStream = Box::pin(futures::stream::iter([Err(
        tonic::Status::deadline_exceeded("payload-and-secret"),
    )]));
    let failure = next_result_for_entry(
        &entry,
        Instant::now() + Duration::from_secs(30),
        MiddlewareDiagnosticPolicy::Normalize,
        &mut remote,
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.kind,
        Some(HttpRequestFailureKind::RemoteStatus(
            tonic::Code::DeadlineExceeded
        ))
    );
    assert_eq!(
        failure.diagnostics.invocations[0].failure_kind,
        failure.kind
    );
    assert_eq!(failure.reason, "middleware_failed: external_service_error");

    for (budget, expected) in [
        (
            Duration::from_secs(30),
            HttpRequestFailureKind::StageTimeout,
        ),
        (
            Duration::from_millis(10),
            HttpRequestFailureKind::ChainTimeout,
        ),
    ] {
        let mut pending: super::super::HttpResultStream = Box::pin(futures::stream::pending());
        let started = Instant::now();
        let failure = next_result_for_entry(
            &entry,
            started + budget,
            MiddlewareDiagnosticPolicy::Normalize,
            &mut pending,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.kind, Some(expected));
        assert_eq!(
            failure.diagnostics.invocations[0].failure_kind,
            Some(expected)
        );
        assert_eq!(Instant::now() - started, budget.min(entry.timeout()));
    }
}

#[tokio::test]
async fn compatibility_evaluator_preserves_unavailable_cause() {
    let runner = ChainRunner::default();
    let input = super::super::HttpRequestInput {
        request_id: "request".into(),
        sandbox_id: "sandbox".into(),
        sandbox_name: "name".into(),
        workspace: "default".into(),
        scheme: "https".into(),
        host: "example.com".into(),
        port: 443,
        method: "POST".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        connection_nominated_headers: Vec::new(),
        body: b"private-body".to_vec(),
    };
    let outcome = runner.evaluate_described(&[entry()], input).await.unwrap();
    assert!(!outcome.allowed);
    assert_eq!(
        outcome.failure_kind,
        Some(HttpRequestFailureKind::Unavailable)
    );
    assert_eq!(outcome.applied[0].failure_kind, outcome.failure_kind);
    assert!(outcome.denial.is_none());
}

#[test]
fn invalid_diagnostics_and_denial_have_different_causes() {
    let invalid = validate_diagnostics_message(Some(&MiddlewareDiagnostics {
        reason_code: "Invalid-Code".into(),
        ..Default::default()
    }))
    .unwrap_err();
    assert_eq!(invalid.kind, Some(HttpRequestFailureKind::InvalidResult));
    let oversized = validate_diagnostics_message(Some(&MiddlewareDiagnostics {
        reason: "x".repeat(MAX_MIDDLEWARE_REASON_BYTES + 1),
        ..Default::default()
    }))
    .unwrap_err();
    assert_eq!(oversized.kind, Some(HttpRequestFailureKind::Capacity));
    let denial = rejection_for_entry(
        &entry(),
        Some(MiddlewareDiagnostics {
            reason_code: "content_match".into(),
            ..Default::default()
        }),
    );
    assert!(denial.denial.is_some());
    assert_eq!(denial.kind, None);
    assert_eq!(denial.diagnostics.invocations[0].failure_kind, None);
}

#[test]
fn invocation_compaction_keeps_typed_cause() {
    let entry = entry();
    let mut invocations =
        vec![
            preflight_invocation(&entry, HttpRequestInvocationOutcome::Stream, None);
            MAX_RECORDED_REQUEST_INVOCATIONS
        ];
    record_request_invocation(
        &mut invocations,
        failed_invocation(&entry, Some(HttpRequestFailureKind::ChainTimeout)),
    );
    assert_eq!(invocations.len(), MAX_RECORDED_REQUEST_INVOCATIONS);
    assert_eq!(
        invocations[0].failure_kind,
        Some(HttpRequestFailureKind::ChainTimeout)
    );
    assert!(invocations[0].failed);
}

#[tokio::test(start_paused = true)]
async fn closed_transport_is_not_reported_as_cancellation() {
    let entry = entry();
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let failure = send_event_for_entry(
        &entry,
        Instant::now() + Duration::from_secs(30),
        &sender,
        HttpEvent::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.kind, Some(HttpRequestFailureKind::Io));
}

#[test]
fn stream_unit_limit_distinguishes_capacity_from_invalid_input() {
    let mut session = HttpRequestSession {
        stages: Vec::new(),
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        session_admission: None,
        declared_body_length: None,
        pending_input: Vec::new(),
    };
    let limit = session.stream_unit_limit();
    assert!(session.push_body(vec![0; limit]).is_ok());
    let too_large = session.push_body(vec![0; limit + 1]).unwrap_err();
    assert_eq!(too_large.kind, Some(HttpRequestFailureKind::Capacity));
    let empty = session.push_body(Vec::new()).unwrap_err();
    assert_eq!(empty.kind, Some(HttpRequestFailureKind::InvalidResult));
    // Both failures retain the same existing display text: classification
    // must come from the original cause, never from parsing that text.
    assert_eq!(empty.reason, too_large.reason);
}
