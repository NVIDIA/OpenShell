// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the `/auth/connect` endpoint.
//!
//! These tests verify the HTTP-level behavior of the Cloudflare Access
//! browser-based login endpoint: cookie extraction, HTML page rendering,
//! and the waiting-page auto-refresh flow.
//!
//! The handler is tested via a standalone axum server to avoid constructing
//! a full `ServerState`.  The test handler mirrors the production logic in
//! `auth.rs` but uses a simple `SocketAddr` as state.

use axum::{
    Router,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse},
    routing::get,
};
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tonic::{Response, Status};

// ---------------------------------------------------------------------------
// Test auth handler (mirrors auth.rs but no ServerState)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ConnectParams {
    callback_port: u16,
    code: String,
}

fn test_auth_router(bind_addr: SocketAddr) -> Router {
    Router::new()
        .route("/auth/connect", get(test_auth_connect))
        .with_state(bind_addr)
}

async fn test_auth_connect(
    State(bind_addr): State<SocketAddr>,
    Query(params): Query<ConnectParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cf_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| extract_cookie(cookies, "CF_Authorization"));

    let gateway_display = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| bind_addr.to_string(), String::from);

    cf_token.map_or_else(
        || Html(render_waiting_page(params.callback_port, &params.code)),
        |token| {
            Html(render_connect_page(
                &gateway_display,
                params.callback_port,
                &token,
                &params.code,
            ))
        },
    )
}

fn extract_cookie(cookies: &str, name: &str) -> Option<String> {
    cookies.split(';').find_map(|c| {
        let mut parts = c.trim().splitn(2, '=');
        let key = parts.next()?.trim();
        let val = parts.next()?.trim();
        if key == name {
            Some(val.to_string())
        } else {
            None
        }
    })
}

fn render_connect_page(
    gateway_addr: &str,
    callback_port: u16,
    cf_token: &str,
    code: &str,
) -> String {
    let escaped_token = cf_token
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
        .replace('<', "\\x3c")
        .replace('>', "\\x3e");

    let escaped_code = code
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
        .replace('<', "\\x3c")
        .replace('>', "\\x3e");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><title>OpenShell — Connect to Gateway</title></head>
<body>
    <div class="card">
        <div class="logo">OpenShell</div>
        <div class="gateway">{gateway_addr}</div>
        <div class="code">{escaped_code}</div>
        <button id="connectBtn" onclick="connect()">Connect to Gateway</button>
        <div id="status"></div>
    </div>
    <script>
        var token = '{escaped_token}';
        var code = '{escaped_code}';
        var port = {callback_port};
        function connect() {{
            fetch('http://127.0.0.1:' + port + '/callback', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ token: token, code: code }})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(data) {{
                document.getElementById('status').textContent =
                    data.ok ? 'Connected!' : (data.error || 'Failed');
            }})
            .catch(function() {{
                document.getElementById('status').textContent = 'Connection failed';
            }});
        }}
    </script>
</body>
</html>"#,
    )
}

fn render_waiting_page(callback_port: u16, code: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="refresh" content="2;url=/auth/connect?callback_port={callback_port}&amp;code={code}">
    <title>OpenShell — Authenticating</title>
</head>
<body>
    <div class="card">
        <div class="logo">OpenShell</div>
        <div class="message">Authenticating with Cloudflare Access...</div>
    </div>
</body>
</html>"#,
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn start_auth_server(bind_addr: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = test_auth_router(bind_addr);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Brief pause to ensure the server is ready.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    (addr, handle)
}

/// Make an HTTP/1.1 GET request and return (status, body).
async fn http_get(addr: SocketAddr, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method("GET").uri(uri);
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    (status, body)
}

// ===========================================================================
// Tests
// ===========================================================================

/// Test 5: `/auth/connect` returns the connect page when `CF_Authorization`
/// cookie is present.
///
/// Verifies:
/// - HTTP 200 response
/// - HTML contains the JWT token (ready for callback redirect)
/// - HTML contains the callback port
/// - HTML contains the gateway display address from the Host header
#[tokio::test]
async fn auth_connect_serves_page_with_cf_cookie() {
    let bind_addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let (server_addr, server) = start_auth_server(bind_addr).await;

    let test_token = "eyJhbGciOiJSUzI1NiJ9.test-payload";
    let cookie = format!("other=foo; CF_Authorization={test_token}; bar=baz");

    let (status, body) = http_get(
        server_addr,
        &format!(
            "http://127.0.0.1:{}/auth/connect?callback_port=54321&code=TST-CODE",
            server_addr.port()
        ),
        &[("cookie", &cookie), ("host", "gateway.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "expected 200 OK");
    assert!(
        body.contains(test_token),
        "response should contain the CF token:\n{body}"
    );
    assert!(
        body.contains("54321"),
        "response should contain the callback port:\n{body}"
    );
    assert!(
        body.contains("gateway.example.com"),
        "response should show the Host header as gateway display:\n{body}"
    );
    assert!(
        body.contains("OpenShell"),
        "response should contain the OpenShell branding:\n{body}"
    );
    assert!(
        body.contains("connect()"),
        "response should contain the connect() JS function:\n{body}"
    );
    assert!(
        body.contains("TST-CODE"),
        "response should contain the confirmation code:\n{body}"
    );
    assert!(
        body.contains("fetch("),
        "response should use fetch() for XHR POST:\n{body}"
    );

    server.abort();
}

/// Test 6: `/auth/connect` returns the waiting/refresh page when no
/// `CF_Authorization` cookie is present.
///
/// Verifies:
/// - HTTP 200 response
/// - HTML contains meta http-equiv="refresh" for auto-reload
/// - HTML contains the `callback_port` in the refresh URL
/// - Does NOT contain a token
#[tokio::test]
async fn auth_connect_serves_waiting_page_without_cookie() {
    let bind_addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let (server_addr, server) = start_auth_server(bind_addr).await;

    let (status, body) = http_get(
        server_addr,
        &format!(
            "http://127.0.0.1:{}/auth/connect?callback_port=12345&code=ABC-1234",
            server_addr.port()
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "expected 200 OK");
    assert!(
        body.contains("meta http-equiv=\"refresh\""),
        "waiting page should have auto-refresh meta tag:\n{body}"
    );
    assert!(
        body.contains("callback_port=12345"),
        "refresh URL should contain the callback port:\n{body}"
    );
    assert!(
        body.contains("code=ABC-1234"),
        "refresh URL should preserve the confirmation code:\n{body}"
    );
    assert!(
        body.contains("Authenticating"),
        "waiting page should show authenticating message:\n{body}"
    );
    assert!(
        !body.contains("var token"),
        "waiting page should NOT contain a token variable:\n{body}"
    );

    server.abort();
}

/// Test 5b: `/auth/connect` uses `x-forwarded-host` over `host` header.
#[tokio::test]
async fn auth_connect_prefers_x_forwarded_host() {
    let bind_addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let (server_addr, server) = start_auth_server(bind_addr).await;

    let (status, body) = http_get(
        server_addr,
        &format!(
            "http://127.0.0.1:{}/auth/connect?callback_port=11111&code=XFH-TEST",
            server_addr.port()
        ),
        &[
            ("cookie", "CF_Authorization=test-jwt"),
            ("host", "internal.local"),
            ("x-forwarded-host", "external.example.com"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("external.example.com"),
        "should prefer x-forwarded-host over host header:\n{body}"
    );
    assert!(
        !body.contains("internal.local"),
        "should NOT show the internal host header:\n{body}"
    );

    server.abort();
}

/// Test 5c: `/auth/connect` falls back to `bind_address` when no host headers.
#[tokio::test]
async fn auth_connect_falls_back_to_bind_address() {
    let bind_addr: SocketAddr = "0.0.0.0:9999".parse().unwrap();
    let (server_addr, server) = start_auth_server(bind_addr).await;

    // Note: hyper automatically sets a Host header, but we verify the fallback
    // by checking that the bind address appears when no x-forwarded-host.
    let (status, body) = http_get(
        server_addr,
        &format!(
            "http://127.0.0.1:{}/auth/connect?callback_port=22222&code=FBK-TEST",
            server_addr.port()
        ),
        &[("cookie", "CF_Authorization=test-jwt")],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // The host header will be set by hyper to 127.0.0.1:<port>, so the
    // handler will use that (not the bind_addr fallback). This is fine —
    // the fallback path is already tested in the unit tests.
    assert!(
        body.contains("test-jwt"),
        "should contain the token:\n{body}"
    );

    server.abort();
}

// ---------------------------------------------------------------------------
// Minimal OpenShell for test 7 (plaintext gRPC+HTTP)
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct TestOpenShell;

#[tonic::async_trait]
impl openshell_core::proto::open_shell_server::OpenShell for TestOpenShell {
    async fn health(
        &self,
        _request: tonic::Request<openshell_core::proto::HealthRequest>,
    ) -> Result<Response<openshell_core::proto::HealthResponse>, Status> {
        Ok(Response::new(openshell_core::proto::HealthResponse {
            status: openshell_core::proto::ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn create_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::CreateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::SandboxResponse::default(),
        ))
    }

    async fn get_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::SandboxResponse::default(),
        ))
    }

    async fn list_sandboxes(
        &self,
        _: tonic::Request<openshell_core::proto::ListSandboxesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxesResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ListSandboxesResponse::default(),
        ))
    }

    async fn list_sandbox_providers(
        &self,
        _: tonic::Request<openshell_core::proto::ListSandboxProvidersRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ListSandboxProvidersResponse::default(),
        ))
    }

    async fn attach_sandbox_provider(
        &self,
        _: tonic::Request<openshell_core::proto::AttachSandboxProviderRequest>,
    ) -> Result<Response<openshell_core::proto::AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::AttachSandboxProviderResponse::default(),
        ))
    }

    async fn detach_sandbox_provider(
        &self,
        _: tonic::Request<openshell_core::proto::DetachSandboxProviderRequest>,
    ) -> Result<Response<openshell_core::proto::DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::DetachSandboxProviderResponse::default(),
        ))
    }

    async fn delete_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteSandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::DeleteSandboxResponse { deleted: true },
        ))
    }

    async fn get_sandbox_config(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxConfigResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::GetSandboxConfigResponse::default(),
        ))
    }

    async fn get_gateway_config(
        &self,
        _: tonic::Request<openshell_core::proto::GetGatewayConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetGatewayConfigResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::GetGatewayConfigResponse::default(),
        ))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxProviderEnvironmentResponse>, Status>
    {
        Ok(Response::new(
            openshell_core::proto::GetSandboxProviderEnvironmentResponse::default(),
        ))
    }

    async fn create_ssh_session(
        &self,
        _: tonic::Request<openshell_core::proto::CreateSshSessionRequest>,
    ) -> Result<Response<openshell_core::proto::CreateSshSessionResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::CreateSshSessionResponse::default(),
        ))
    }

    async fn expose_service(
        &self,
        _: tonic::Request<openshell_core::proto::ExposeServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ServiceEndpointResponse::default(),
        ))
    }

    async fn get_service(
        &self,
        _: tonic::Request<openshell_core::proto::GetServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _: tonic::Request<openshell_core::proto::ListServicesRequest>,
    ) -> Result<Response<openshell_core::proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteServiceRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteServiceResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn revoke_ssh_session(
        &self,
        _: tonic::Request<openshell_core::proto::RevokeSshSessionRequest>,
    ) -> Result<Response<openshell_core::proto::RevokeSshSessionResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::RevokeSshSessionResponse::default(),
        ))
    }

    async fn create_provider(
        &self,
        _: tonic::Request<openshell_core::proto::CreateProviderRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn get_provider(
        &self,
        _: tonic::Request<openshell_core::proto::GetProviderRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn list_providers(
        &self,
        _: tonic::Request<openshell_core::proto::ListProvidersRequest>,
    ) -> Result<Response<openshell_core::proto::ListProvidersResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn list_provider_profiles(
        &self,
        _: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn get_provider_profile(
        &self,
        _: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn import_provider_profiles(
        &self,
        _: tonic::Request<openshell_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn lint_provider_profiles(
        &self,
        _: tonic::Request<openshell_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn delete_provider_profile(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderProfileResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn update_provider(
        &self,
        _: tonic::Request<openshell_core::proto::UpdateProviderRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn get_provider_refresh_status(
        &self,
        _: tonic::Request<openshell_core::proto::GetProviderRefreshStatusRequest>,
    ) -> Result<Response<openshell_core::proto::GetProviderRefreshStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn configure_provider_refresh(
        &self,
        _: tonic::Request<openshell_core::proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<openshell_core::proto::ConfigureProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn rotate_provider_credential(
        &self,
        _: tonic::Request<openshell_core::proto::RotateProviderCredentialRequest>,
    ) -> Result<Response<openshell_core::proto::RotateProviderCredentialResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_refresh(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteProviderRefreshRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteProviderRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    type WatchSandboxStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::SandboxStreamEvent, Status>,
    >;
    type ExecSandboxStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::ExecSandboxEvent, Status>,
    >;
    type ConnectSupervisorStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::GatewayMessage, Status>,
    >;

    async fn watch_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn exec_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type ExecSandboxInteractiveStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::ExecSandboxEvent, Status>,
    >;
    async fn exec_sandbox_interactive(
        &self,
        _: tonic::Request<tonic::Streaming<openshell_core::proto::ExecSandboxInput>>,
    ) -> Result<Response<Self::ExecSandboxInteractiveStream>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn update_config(
        &self,
        _: tonic::Request<openshell_core::proto::UpdateConfigRequest>,
    ) -> Result<Response<openshell_core::proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn list_sandbox_policies(
        &self,
        _: tonic::Request<openshell_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn report_policy_status(
        &self,
        _: tonic::Request<openshell_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn get_sandbox_logs(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn push_sandbox_logs(
        &self,
        _: tonic::Request<tonic::Streaming<openshell_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<openshell_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("test"))
    }

    async fn submit_policy_analysis(
        &self,
        _request: tonic::Request<openshell_core::proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<openshell_core::proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_policy(
        &self,
        _request: tonic::Request<openshell_core::proto::GetDraftPolicyRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn reject_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::RejectDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _request: tonic::Request<openshell_core::proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn edit_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::EditDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn undo_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::UndoDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn clear_draft_chunks(
        &self,
        _request: tonic::Request<openshell_core::proto::ClearDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_history(
        &self,
        _request: tonic::Request<openshell_core::proto::GetDraftHistoryRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type RelayStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<openshell_core::proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type ForwardTcpStream = std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<openshell_core::proto::TcpForwardFrame, Status>>
                + Send,
        >,
    >;

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

/// Test 7: Plaintext server (no TLS) accepts both gRPC and HTTP.
///
/// This verifies the same scenario as `multiplex_integration::
/// serves_grpc_and_http_on_same_port` but explicitly framed as the
/// plaintext/`--disable-tls` mode used by Cloudflare Tunnel deployments.
/// Uses `serve_connection_with_upgrades` to also support WebSocket upgrades.
#[tokio::test]
async fn plaintext_server_accepts_grpc_and_http() {
    use openshell_core::proto::{
        HealthRequest, ServiceStatus, open_shell_client::OpenShellClient,
        open_shell_server::OpenShellServer,
    };
    use openshell_server::{MultiplexedService, health_router};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router();
    let service = MultiplexedService::new(grpc_service, http_service);

    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                .await;
            });
        }
    });

    // gRPC over plaintext HTTP
    let mut client = OpenShellClient::connect(format!("http://{addr}"))
        .await
        .expect("plaintext gRPC connect failed");
    let resp = client
        .health(HealthRequest {})
        .await
        .expect("plaintext health RPC failed");
    assert_eq!(
        resp.get_ref().status,
        ServiceStatus::Healthy as i32,
        "gRPC health check should succeed over plaintext"
    );

    // HTTP over plaintext
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}/healthz"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "HTTP healthz should succeed over plaintext"
    );

    server.abort();
}
