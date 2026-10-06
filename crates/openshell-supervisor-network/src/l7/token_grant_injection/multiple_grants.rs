// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::test_support::TokenGrantTestFixture;
use super::*;
use crate::l7::provider::BodyLength;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::SubscriberExt;

const SERVICE: &str = "api.example.com\t443\t/v1/**\trev:7\tprovider:service";
const IDENTITY: &str = "api.example.com\t443\t/v1/**\trev:7\tprovider:identity";

fn request() -> L7Request {
    L7Request {
        action: "POST".into(),
        target: "/v1/projects?view=full".into(),
        query_params: HashMap::default(),
        raw_header: b"POST /v1/projects?view=full HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer agent-token\r\nauthorization : duplicate\r\nX-Workload-Jwt: agent-identity\r\nx-workload-jwt: duplicate\r\nX-Static: openshell:placeholder\r\nContent-Length: 4\r\n\r\nbody".to_vec(),
        body_length: BodyLength::ContentLength(4),
    }
}

fn fixture(
    identity_result: std::result::Result<&str, &str>,
) -> (TokenGrantTestFixture, L7EvalContext) {
    let fixture = TokenGrantTestFixture::success(SERVICE, "service-token");
    let mut identity = fixture.dynamic_credentials().read().unwrap()[SERVICE].clone();
    identity.name = "identity".into();
    identity.auth_style = "header".into();
    identity.header_name = "X-Workload-Jwt".into();
    let grant = identity.token_grant.as_mut().unwrap();
    grant.token_endpoint = "https://identity.example.com/token".into();
    grant.jwt_svid_audience = "identity-proxy".into();
    grant.audience = "workload".into();
    grant.scopes = vec!["identity.read".into()];
    grant.cache_ttl = Some(prost_types::Duration {
        seconds: 45,
        nanos: 0,
    });
    fixture.add_credential(IDENTITY, identity, identity_result);
    let ctx = L7EvalContext {
        host: "api.example.com".into(),
        port: 443,
        dynamic_credentials: Some(fixture.dynamic_credentials()),
        token_grant_resolver: Some(fixture.resolver()),
        ..Default::default()
    };
    (fixture, ctx)
}

#[tokio::test]
async fn injects_independent_grants_and_replaces_all_protected_headers() {
    let (fixture, ctx) = fixture(Ok("identity-token"));
    let rewritten = inject_if_needed(request(), &ctx).await.unwrap();
    let bytes = String::from_utf8(rewritten.raw_header).unwrap();
    assert_eq!(
        bytes
            .matches("Authorization: Bearer service-token\r\n")
            .count(),
        1
    );
    assert_eq!(
        bytes.matches("X-Workload-Jwt: identity-token\r\n").count(),
        1
    );
    assert!(!bytes.contains("agent-token"));
    assert!(!bytes.contains("agent-identity"));
    assert!(!bytes.contains("duplicate"));
    assert!(bytes.contains("X-Static: openshell:placeholder\r\n"));
    assert!(bytes.ends_with("\r\n\r\nbody"));
    fixture.assert_requested_keys(&[SERVICE, IDENTITY]);
    for key in [SERVICE, IDENTITY] {
        let credentials = fixture.dynamic_credentials();
        let credentials = credentials.read().unwrap();
        fixture.assert_request_configuration(key, credentials[key].token_grant.as_ref().unwrap());
    }
}

#[tokio::test]
async fn chooses_specific_binding_independently_for_each_header() {
    let (fixture, ctx) = fixture(Ok("identity-token"));
    let specific_key = "api.example.com\t443\t/v1/projects\trev:7\tother:service";
    let mut specific = fixture.dynamic_credentials().read().unwrap()[SERVICE].clone();
    specific.token_grant.as_mut().unwrap().audience = "projects-only".into();
    fixture.add_credential(specific_key, specific, Ok("specific-service"));
    let rewritten = inject_if_needed(request(), &ctx).await.unwrap();
    let bytes = String::from_utf8(rewritten.raw_header).unwrap();
    assert!(bytes.contains("Authorization: Bearer specific-service\r\n"));
    assert!(bytes.contains("X-Workload-Jwt: identity-token\r\n"));
    fixture.assert_requested_keys(&[specific_key, IDENTITY]);
}

#[tokio::test]
async fn audience_override_changes_only_its_own_credential() {
    let (fixture, ctx) = fixture(Ok("identity-token"));
    let override_key = "api.example.com\t443\t/v1/projects\trev:7\tprovider:identity";
    let mut identity = fixture.dynamic_credentials().read().unwrap()[IDENTITY].clone();
    identity.token_grant.as_mut().unwrap().audience = "project-identity".into();
    fixture.add_credential(override_key, identity.clone(), Ok("project-identity-token"));
    let rewritten = inject_if_needed(request(), &ctx).await.unwrap();
    let bytes = String::from_utf8(rewritten.raw_header).unwrap();
    assert!(bytes.contains("Authorization: Bearer service-token\r\n"));
    assert!(bytes.contains("X-Workload-Jwt: project-identity-token\r\n"));
    fixture.assert_requested_keys(&[SERVICE, override_key]);
    fixture.assert_request_configuration(override_key, identity.token_grant.as_ref().unwrap());
}

#[tokio::test]
async fn rejects_tied_credentials_for_same_header_before_acquisition() {
    for header in ["Authorization", " authorization ", ""] {
        let (fixture, ctx) = fixture(Ok("identity-token"));
        let mut collision = fixture.dynamic_credentials().read().unwrap()[SERVICE].clone();
        collision.name = "collision".into();
        collision.header_name = header.into();
        fixture.add_credential(
            "api.example.com\t443\t/v1/**\trev:7\tother:collision",
            collision,
            Ok("collision-token"),
        );
        let error = inject_if_needed(request(), &ctx).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "ambiguous dynamic token grants for one header"
        );
        fixture.assert_no_requests();
    }
}

#[tokio::test]
async fn rejects_invalid_second_header_before_acquisition() {
    let (fixture, ctx) = fixture(Ok("identity-token"));
    let mut identity = fixture.dynamic_credentials().read().unwrap()[IDENTITY].clone();
    identity.header_name = "Content-Length".into();
    fixture.add_credential(IDENTITY, identity, Ok("identity-token"));
    assert!(inject_if_needed(request(), &ctx).await.is_err());
    fixture.assert_no_requests();
}

#[tokio::test]
async fn rejects_malformed_second_token_after_first_grant_succeeds() {
    let (fixture, ctx) = fixture(Ok("identity-token\r\nInjected: yes"));
    let error = inject_if_needed(request(), &ctx).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "token grant returned a malformed access token"
    );
    fixture.assert_requested_keys(&[SERVICE, IDENTITY]);
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn second_grant_failure_redacts_errors_and_emits_no_success() {
    // OCSF callsite interest is process-global. Run capture alone so unrelated
    // parallel tests cannot disable the event while its subscriber is installed.
    const CAPTURE_CHILD: &str = "OPENSHELL_MULTIPLE_GRANTS_CAPTURE_CHILD";
    if std::env::var_os(CAPTURE_CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "l7::token_grant_injection::multiple_grants::second_grant_failure_redacts_errors_and_emits_no_success",
                "--nocapture",
            ])
            .env(CAPTURE_CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated capture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (fixture, ctx) = fixture(Err("issuer echoed service-token and identity-secret"));
    let logs = Arc::new(Mutex::new(Vec::new()));
    let events = Arc::new(Mutex::new(Vec::new()));
    let log_writer = Capture(logs.clone());
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_writer(move || log_writer.clone()),
        )
        .with(openshell_ocsf::OcsfJsonlLayer::new(Capture(events.clone())));
    let error = inject_if_needed(request(), &ctx)
        .with_subscriber(subscriber)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Token grant failed");
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    let events = String::from_utf8(events.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("Token grant failed"));
    assert!(events.contains("Token grant failed"));
    for output in [&logs, &events] {
        assert!(!output.contains("service-token"));
        assert!(!output.contains("identity-secret"));
        assert!(!output.contains("Token grant successful"));
    }
    fixture.assert_requested_keys(&[SERVICE, IDENTITY]);
}

#[tokio::test]
async fn does_not_acquire_grants_outside_endpoint_bindings() {
    for (host, port, path) in [
        ("other.example.com", 443, "/v1/projects"),
        ("api.example.com", 8443, "/v1/projects"),
        ("api.example.com", 443, "/private/projects"),
    ] {
        let (fixture, mut ctx) = fixture(Ok("identity-token"));
        ctx.host = host.into();
        ctx.port = port;
        let mut req = request();
        req.target = path.into();
        let original = req.raw_header.clone();
        assert_eq!(
            inject_if_needed(req, &ctx).await.unwrap().raw_header,
            original
        );
        fixture.assert_no_requests();
    }
}

#[tokio::test]
async fn concurrent_requests_keep_credential_snapshots_separate() {
    let (first, first_ctx) = fixture(Ok("first-identity"));
    let (second, second_ctx) = fixture(Ok("second-identity"));
    let (first_result, second_result) = tokio::join!(
        inject_if_needed(request(), &first_ctx),
        inject_if_needed(request(), &second_ctx),
    );
    for (result, expected, absent) in [
        (first_result, "first-identity", "second-identity"),
        (second_result, "second-identity", "first-identity"),
    ] {
        let bytes = String::from_utf8(result.unwrap().raw_header).unwrap();
        assert!(bytes.contains(expected));
        assert!(!bytes.contains(absent));
    }
    first.assert_requested_keys(&[SERVICE, IDENTITY]);
    second.assert_requested_keys(&[SERVICE, IDENTITY]);
}

#[tokio::test]
async fn admitted_owners_select_grants_independently_per_header() {
    // The service grant keeps the fixture owner; the identity grant belongs to a
    // different endpoint. Each case lists the owners that admitted the request and
    // whether the service and identity headers are replaced.
    let cases: [(&[&str], bool, bool); 4] = [
        (&[], false, false),
        (&["test-owner"], true, false),
        (&["identity-owner"], false, true),
        (&["test-owner", "identity-owner"], true, true),
    ];
    for (admitted, service, identity) in cases {
        let (fixture, mut ctx) = fixture(Ok("identity-token"));
        fixture
            .dynamic_credentials()
            .write()
            .unwrap()
            .get_mut(IDENTITY)
            .unwrap()
            .token_grant_owners = vec!["identity-owner".into()];
        let state = fixture.provider_credentials();
        ctx.provider_credentials = Some(state.clone());
        let owners = admitted
            .iter()
            .map(|owner| (*owner).to_string())
            .collect::<HashSet<_>>();

        let rewritten = inject_for_admitted_owners(request(), &ctx, &state.snapshot(), &owners)
            .await
            .unwrap();
        let bytes = String::from_utf8(rewritten.raw_header).unwrap();

        // A grant whose owner did not admit the request is never acquired, and its
        // header keeps the workload's own value.
        assert_eq!(
            bytes.contains("Authorization: Bearer service-token\r\n"),
            service,
            "service header for {admitted:?}"
        );
        assert_eq!(
            bytes.contains("Authorization: Bearer agent-token\r\n"),
            !service,
            "workload Authorization for {admitted:?}"
        );
        assert_eq!(
            bytes.contains("X-Workload-Jwt: identity-token\r\n"),
            identity,
            "identity header for {admitted:?}"
        );
        let mut expected = Vec::new();
        if service {
            expected.push(SERVICE);
        }
        if identity {
            expected.push(IDENTITY);
        }
        fixture.assert_requested_keys(&expected);
    }
}
