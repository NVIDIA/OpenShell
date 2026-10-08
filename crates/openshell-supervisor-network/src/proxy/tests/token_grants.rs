// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

const POLICY: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        path: /v1/**
        protocol: rest
        token_grant_owner: other-owner
        rules:
          - allow: { method: GET, path: /v1/** }
      - host: api.example.test
        port: 8080
        path: /v1/projects
        protocol: rest
        token_grant_owner: test-owner
        rules:
          - allow: { method: POST, path: /v1/projects }
    binaries:
      - { path: /usr/bin/node }
"#;

fn forward_inspection_fixture() -> (
    crate::l7::L7EndpointConfig,
    crate::opa::TunnelPolicyEngine,
    crate::l7::relay::L7EvalContext,
    crate::l7::token_grant_injection::test_support::TokenGrantTestFixture,
) {
    let (config, engine, mut ctx) = forward_websocket_policy_parts(
        POLICY,
        "api.example.test",
        8080,
        "/v1/projects",
        "rest_api",
    );
    let fixture = forward_token_grant_fixture(
        "api.example.test\t8080\t/v1/**\tprovider:access_token",
        Ok("grant-token"),
        false,
    );
    ctx.dynamic_credentials = Some(fixture.dynamic_credentials());
    ctx.provider_credentials = Some(fixture.provider_credentials());
    ctx.token_grant_resolver = Some(fixture.resolver());
    (config, engine, ctx, fixture)
}

#[tokio::test]
async fn forward_inspection_selects_only_the_owner_admitting_the_request() {
    for method in ["GET", "POST"] {
        let (config, engine, mut ctx, fixture) = forward_inspection_fixture();
        let info = crate::l7::L7RequestInfo {
            action: method.into(),
            target: "/v1/projects".into(),
            query_params: TestHashMap::new(),
            graphql: None,
            jsonrpc: None,
        };
        assert!(
            crate::l7::relay::evaluate_l7_request(&engine, &ctx, &info)
                .unwrap()
                .0
        );
        let raw = format!(
            "{method} http://api.example.test:8080/v1/projects HTTP/1.1\r\nHost: api.example.test:8080\r\nAuthorization: Bearer stale-token\r\nContent-Length: 0\r\n\r\n"
        ).into_bytes();
        let prepared = inject_token_grant_for_forward_request(
            method,
            "/v1/projects",
            raw,
            &mut ctx,
            Some(ForwardL7Reevaluation {
                config: &config,
                engine: &engine,
                request_info: &info,
            }),
        )
        .await
        .expect("prepare admitted forward request");
        let rewritten = rewrite_forward_request(
            &prepared,
            prepared.len(),
            "/v1/projects",
            "api.example.test:8080",
            ctx.secret_resolver.as_deref(),
        )
        .expect("rewrite admitted forward request");
        let headers = String::from_utf8(rewritten).unwrap();
        assert!(headers.starts_with(&format!("{method} /v1/projects HTTP/1.1\r\n")));
        assert_eq!(authorization_header_count(&headers), 1);
        if method == "POST" {
            fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
            assert!(headers.contains("Authorization: Bearer grant-token\r\n"));
            assert!(!headers.contains("stale-token"));
        } else {
            fixture.assert_no_requests();
            assert!(headers.contains("Authorization: Bearer stale-token\r\n"));
            assert!(!headers.contains("grant-token"));
        }
    }
}

#[tokio::test]
async fn forward_inspection_retains_installation_through_guarded_write() {
    let (config, engine, mut ctx, fixture) = forward_inspection_fixture();
    let state = ctx.provider_credentials.as_ref().unwrap().clone();
    let info = crate::l7::L7RequestInfo {
        action: "POST".into(),
        target: "/v1/projects".into(),
        query_params: TestHashMap::new(),
        graphql: None,
        jsonrpc: None,
    };
    let raw = b"POST http://api.example.test:8080/v1/projects HTTP/1.1\r\nHost: api.example.test:8080\r\nContent-Length: 0\r\n\r\n".to_vec();
    let prepared = inject_token_grant_for_forward_request(
        "POST",
        "/v1/projects",
        raw,
        &mut ctx,
        Some(ForwardL7Reevaluation {
            config: &config,
            engine: &engine,
            request_info: &info,
        }),
    )
    .await
    .expect("prepare authenticated request");
    fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    let rewritten = rewrite_forward_request(
        &prepared,
        prepared.len(),
        "/v1/projects",
        "api.example.test:8080",
        ctx.secret_resolver.as_deref(),
    )
    .unwrap();
    let snapshot = state.snapshot();
    state.install_environment(
        snapshot.revision,
        TestHashMap::new(),
        TestHashMap::new(),
        fixture.dynamic_credentials().read().unwrap().clone(),
    );
    let guard = crate::l7::rest::CredentialGenerationGuard::new(
        &state,
        ctx.provider_credential_revision.expect("prepared revision"),
    )
    .with_installation_id(ctx.provider_credential_installation_id.as_deref());
    let (client, _app) = tokio::io::duplex(1024);
    let mut client = tokio::io::BufReader::new(client);
    let (mut upstream, mut target) = tokio::io::duplex(1024);
    let relay = relay_rewritten_forward_request(
        "POST",
        "/v1/projects",
        rewritten,
        &mut client,
        &mut upstream,
        ForwardRelayOptions {
            generation_guard: engine.generation_guard(),
            credential_generation: Some(guard),
            websocket_extensions: crate::l7::rest::WebSocketExtensionMode::Preserve,
            secret_resolver: ctx.secret_resolver.as_deref(),
            body_classifier: ctx.body_classifier.as_deref(),
            request_body_credential_rewrite: false,
            deny_uninspected_credentials: false,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: "",
            signing_region: "",
            host: &ctx.host,
            port: ctx.port,
            response_middleware: None,
            endpoint_observer: None,
        },
    );
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("credential rejection must finish before any response wait");
    assert!(
        result
            .unwrap_err()
            .downcast_ref::<crate::l7::rest::CredentialUnavailableError>()
            .is_some()
    );
    drop(upstream);
    let mut forwarded = Vec::new();
    target.read_to_end(&mut forwarded).await.unwrap();
    assert!(
        forwarded.is_empty(),
        "replaced installation cannot send any bytes"
    );
}
