// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expected credential ownership at the REST relay boundary.
//!
//! OPA derives the routes from policy, but credential metadata is synthesized
//! here. These tests do not establish that the gateway accepts each composition
//! or that a real OAuth server issues the requested token. The resolver returns
//! inert values and records which provider and audience the relay requested.

use super::*;
use crate::l7::token_grant_injection::{TokenGrantRequest, TokenGrantResolver};
use crate::opa::{NetworkInput, OpaEngine};
use crate::token_grant::test_support::{CacheAcquisition, CachedTokenGrantResolver};
use openshell_core::proto::{
    ProviderCredentialTokenGrant, ProviderCredentialTokenGrantType, ProviderProfileCredential,
};
use openshell_core::provider_credentials::ProviderCredentialState;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");
const HOST: &str = "api.example.test";
const PORT: u16 = 8080;
const WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
struct GrantCall {
    provider_key: String,
    audience: String,
}

#[derive(Default)]
struct ScriptedResolver {
    calls: Mutex<Vec<GrantCall>>,
    fail_once: AtomicBool,
    hold_once: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl TokenGrantResolver for ScriptedResolver {
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls
                .lock()
                .expect("resolver calls lock")
                .push(GrantCall {
                    provider_key: request.provider_key.to_owned(),
                    audience: request.audience.to_owned(),
                });
            if self.hold_once.swap(false, Ordering::SeqCst) {
                // notify_one retains a permit if the test has not begun waiting.
                self.entered.notify_one();
                timeout(WAIT, self.release.notified())
                    .await
                    .expect("test releases the held grant");
            }
            if self.fail_once.swap(false, Ordering::SeqCst) {
                return Err(miette!("synthetic grant service unavailable"));
            }
            Ok(format!("inert-{}", request.audience))
        })
    }
}

impl ScriptedResolver {
    fn assert_calls(&self, expected: &[(&str, &str)]) {
        let calls = self.calls.lock().expect("resolver calls lock");
        let expected = expected
            .iter()
            .map(|(provider_key, audience)| GrantCall {
                provider_key: (*provider_key).to_owned(),
                audience: (*audience).to_owned(),
            })
            .collect::<Vec<_>>();
        assert_eq!(*calls, expected, "grant ownership and call count");
    }
}

struct Route<'a> {
    name: &'a str,
    path: &'a str,
    method: &'a str,
    binary: &'a str,
    enforcement: &'a str,
    deny_path: Option<&'a str>,
    body_rewrite: bool,
}

fn route<'a>(name: &'a str, path: &'a str) -> Route<'a> {
    Route {
        name,
        path,
        method: "GET",
        binary: "/usr/bin/curl",
        enforcement: "enforce",
        deny_path: None,
        body_rewrite: false,
    }
}

fn key(path: &str, owner: &str) -> String {
    format!("{HOST}\t{PORT}\t{path}\t{owner}:access_token")
}

fn credentials(entries: &[(&str, &str, &str)]) -> HashMap<String, ProviderProfileCredential> {
    entries
        .iter()
        .map(|(path, owner, audience)| {
            (
                key(path, owner),
                ProviderProfileCredential {
                    name: "access_token".into(),
                    auth_style: "bearer".into(),
                    header_name: "Authorization".into(),
                    token_grant_owners: vec![(*owner).into()],
                    token_grant: Some(ProviderCredentialTokenGrant {
                        token_endpoint: "https://auth.example.test/token".into(),
                        jwt_svid_audience: "https://auth.example.test".into(),
                        client_assertion_type:
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                        grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
                        audience: (*audience).into(),
                        scopes: vec!["read".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
        })
        .collect()
}

struct Fixture {
    engine: OpaEngine,
    generation: u64,
    policy_data: String,
    configs: Vec<L7EndpointConfig>,
    state: ProviderCredentialState,
    resolver: Arc<ScriptedResolver>,
}

impl Fixture {
    fn new(routes: &[Route<'_>], grants: &[(&str, &str, &str)], expected_routes: usize) -> Self {
        let policies = routes
            .iter()
            .map(|route| {
                let mut endpoint = serde_json::json!({
                    "host": HOST, "port": PORT, "path": route.path,
                    "protocol": "rest", "enforcement": route.enforcement,
                    "token_grant_owner": route.name,
                    "rules": [{"allow": {"method": route.method, "path": route.path}}]
                });
                // An explicit empty deny_rules list is invalid authored policy.
                if let Some(path) = route.deny_path {
                    endpoint["deny_rules"] = serde_json::json!([{"method": "GET", "path": path}]);
                }
                if route.body_rewrite {
                    endpoint["request_body_credential_rewrite"] = true.into();
                }
                (
                    route.name.to_owned(),
                    serde_json::json!({
                        "name": route.name,
                        "endpoints": [endpoint],
                        "binaries": [{"path": route.binary}]
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let data = serde_json::json!({"network_policies": policies}).to_string();
        let engine = OpaEngine::from_strings(POLICY, &data).expect("fixture policy compiles");
        let (raw_configs, generation) = engine
            .query_endpoint_configs_with_generation(&NetworkInput {
                host: HOST.into(),
                port: PORT,
                binary_path: PathBuf::from("/usr/bin/curl"),
                binary_sha256: "unused".into(),
                ancestors: vec![],
                cmdline_paths: vec![],
            })
            .expect("OPA endpoint query");
        assert_eq!(raw_configs.len(), expected_routes, "OPA route count");
        let configs = raw_configs
            .iter()
            .map(|raw| crate::l7::parse_l7_config(raw).expect("OPA REST endpoint config"))
            .collect();
        Self {
            engine,
            generation,
            policy_data: data,
            configs,
            state: ProviderCredentialState::from_environment(
                1,
                HashMap::new(),
                HashMap::new(),
                credentials(grants),
            ),
            resolver: Arc::new(ScriptedResolver::default()),
        }
    }

    fn install(&self, revision: u64, grants: &[(&str, &str, &str)]) {
        self.state.install_environment(
            revision,
            HashMap::new(),
            HashMap::new(),
            credentials(grants),
        );
    }

    fn grant_key(&self, path: &str, owner: &str) -> String {
        let snapshot = self.state.snapshot();
        format!(
            "{HOST}\t{PORT}\t{path}\trev:{}\tinstallation:{}\t{owner}:access_token",
            snapshot.revision, snapshot.installation_id
        )
    }

    fn reload_policy(&mut self) {
        self.engine
            .reload(POLICY, &self.policy_data)
            .expect("reload the same policy into a new generation");
        let generation = self.engine.current_generation();
        assert_ne!(
            generation, self.generation,
            "reload invalidates the old tunnel"
        );
        self.generation = generation;
    }

    fn connect(&self) -> Connection {
        self.connect_with_resolver(self.resolver.clone())
    }

    fn connect_with_resolver(&self, resolver: Arc<dyn TokenGrantResolver>) -> Connection {
        self.connect_observed(resolver, None)
    }

    fn connect_observed(
        &self,
        resolver: Arc<dyn TokenGrantResolver>,
        body_pending: Option<Arc<Notify>>,
    ) -> Connection {
        let configs = self.configs.clone();
        let engine = self
            .engine
            .clone_engine_for_tunnel(self.generation)
            .expect("tunnel policy snapshot");
        let snapshot = self.state.snapshot();
        // Mirror the proxy cache identity. Same-revision replacements remain
        // distinct because the installation ID precedes the provider segment.
        let dynamic_credentials = snapshot
            .dynamic_credentials
            .iter()
            .map(|(key, credential)| {
                let (selector, owner) = key.rsplit_once('\t').expect("endpoint-bound fixture key");
                (
                    format!(
                        "{selector}\trev:{}\tinstallation:{}\t{owner}",
                        snapshot.revision, snapshot.installation_id
                    ),
                    credential.clone(),
                )
            })
            .collect();
        let ctx = L7EvalContext {
            host: HOST.into(),
            port: PORT,
            request_default_port: Some(PORT),
            policy_name: "fixture".into(),
            binary_path: "/usr/bin/curl".into(),
            provider_credentials: Some(self.state.clone()),
            // Match the initial tunnel snapshot while retaining live provider
            // state. Refresh tests require requests to use the live ownership.
            dynamic_credentials: Some(Arc::new(RwLock::new(dynamic_credentials))),
            token_grant_resolver: Some(resolver),
            ..Default::default()
        };
        let (app, client) = tokio::io::duplex(16 * 1024);
        let mut client = BodyReadObservedStream {
            stream: client,
            body_pending,
            headers: Vec::new(),
            headers_complete: false,
            notified: false,
        };
        let (mut relay_upstream, upstream) = tokio::io::duplex(16 * 1024);
        let relay = tokio::spawn(async move {
            if let [config] = configs.as_slice() {
                relay_with_inspection(config, engine, &mut client, &mut relay_upstream, &ctx).await
            } else {
                relay_with_route_selection(&configs, engine, &mut client, &mut relay_upstream, &ctx)
                    .await
            }
        });
        Connection {
            app,
            relay,
            upstream: tokio::spawn(capture_upstream(upstream)),
        }
    }
}

#[derive(Default)]
struct Capture {
    requests: Vec<String>,
    bytes_seen: usize,
}

struct Connection {
    app: DuplexStream,
    relay: JoinHandle<Result<()>>,
    upstream: JoinHandle<Capture>,
}

// Notify when the relay has consumed complete headers and awaits body bytes.
// This observes the real buffering boundary without a sleep or a fake 100 reply.
struct BodyReadObservedStream {
    stream: DuplexStream,
    body_pending: Option<Arc<Notify>>,
    headers: Vec<u8>,
    headers_complete: bool,
    notified: bool,
}

impl AsyncRead for BodyReadObservedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(cx, buf);
        if let Some(body_pending) = &this.body_pending {
            match &result {
                Poll::Ready(Ok(())) if !this.headers_complete => {
                    this.headers.extend_from_slice(&buf.filled()[before..]);
                    this.headers_complete =
                        this.headers.windows(4).any(|window| window == b"\r\n\r\n");
                }
                Poll::Pending if this.headers_complete && !this.notified => {
                    this.notified = true;
                    body_pending.notify_one();
                }
                _ => {}
            }
        }
        result
    }
}

impl AsyncWrite for BodyReadObservedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

// Read through the complete header terminator, including fragmented writes.
// EOF preserves any partial header so a no-forwarding check counts all bytes.
async fn read_header(stream: &mut DuplexStream) -> Vec<u8> {
    timeout(WAIT, async {
        let mut header = Vec::new();
        loop {
            let mut byte = [0];
            if stream.read(&mut byte).await.expect("duplex read") == 0 {
                return header;
            }
            header.push(byte[0]);
            assert!(header.len() <= 16 * 1024, "bounded fixture header");
            if header.ends_with(b"\r\n\r\n") {
                return header;
            }
        }
    })
    .await
    .expect("header read completes or reaches EOF")
}

async fn capture_upstream(mut stream: DuplexStream) -> Capture {
    let mut capture = Capture::default();
    loop {
        let header = read_header(&mut stream).await;
        capture.bytes_seen += header.len();
        if header.is_empty() || !header.ends_with(b"\r\n\r\n") {
            return capture;
        }
        capture
            .requests
            .push(String::from_utf8(header).expect("HTTP fixture header"));
        timeout(
            WAIT,
            stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
        )
        .await
        .expect("upstream response write completes")
        .expect("upstream response write");
    }
}

impl Connection {
    async fn send(&mut self, method: &str, path: &str, stale_authorization: bool) {
        let authorization = if stale_authorization {
            "Authorization: Bearer stale-inert-value\r\n"
        } else {
            ""
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n{authorization}Content-Length: 0\r\n\r\n"
        );
        timeout(WAIT, self.app.write_all(request.as_bytes()))
            .await
            .expect("client request write completes")
            .expect("client request write");
    }

    async fn response(&mut self) -> String {
        let header =
            String::from_utf8(read_header(&mut self.app).await).expect("HTTP fixture response");
        let length = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, value)| {
                value.trim().parse::<usize>().expect("response length")
            });
        let mut body = vec![0; length];
        timeout(WAIT, self.app.read_exact(&mut body))
            .await
            .expect("response body read completes")
            .expect("response body read");
        header
    }

    async fn exchange(&mut self, method: &str, path: &str, stale: bool) -> String {
        self.send(method, path, stale).await;
        self.response().await
    }

    async fn observes_eof(&mut self) -> bool {
        let mut byte = [0];
        matches!(timeout(WAIT, self.app.read(&mut byte)).await, Ok(Ok(0)))
    }

    async fn finish(self) -> Capture {
        let (relay, upstream) = self.finish_with_result().await;
        relay.expect("relay result");
        upstream
    }

    async fn finish_with_result(self) -> (Result<()>, Capture) {
        drop(self.app);
        // Collect both task outcomes even when one panics or times out.
        let (relay, upstream) =
            tokio::join!(timeout(WAIT, self.relay), timeout(WAIT, self.upstream));
        let relay = relay
            .expect("relay task completes")
            .expect("relay task joins");
        let upstream = upstream
            .expect("upstream task observes EOF")
            .expect("upstream task joins");
        (relay, upstream)
    }
}

fn assert_authorization(request: &str, audience: &str) {
    let values = request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1, "exactly one Authorization replacement");
    assert!(
        values[0] == format!("Bearer inert-{audience}"),
        "expected owner token"
    );
    assert!(
        !request.contains("stale-inert-value"),
        "stale header removed"
    );
}

fn assert_no_authorization(capture: &Capture) {
    assert!(
        capture
            .requests
            .iter()
            .all(|request| request.lines().all(|line| {
                !line
                    .split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            })),
        "an unadmitted owner must not inject credentials"
    );
}

#[tokio::test]
async fn single_endpoint_grant_is_a_positive_control() {
    let fixture = Fixture::new(&[route("a", "/a/**")], &[("/a/**", "a", "aud-a")], 1);
    let mut connection = fixture.connect();
    let response = connection.exchange("GET", "/a/item", true).await;
    let capture = connection.finish().await;
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 1);
    assert_authorization(&capture.requests[0], "aud-a");
    fixture
        .resolver
        .assert_calls(&[(&fixture.grant_key("/a/**", "a"), "aud-a")]);
}

#[tokio::test]
async fn grant_selection_uses_canonical_path_and_ignores_query_selector_text() {
    let fixture = Fixture::new(&[route("a", "/a/**")], &[("/a/**", "a", "aud-a")], 1);
    let mut connection = fixture.connect();
    let response = connection
        .exchange("GET", "/outside/../a/%69tem?next=/b/item", true)
        .await;
    let capture = connection.finish().await;
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 1);
    assert_authorization(&capture.requests[0], "aud-a");
    fixture
        .resolver
        .assert_calls(&[(&fixture.grant_key("/a/**", "a"), "aud-a")]);
}

#[tokio::test]
async fn route_selected_grant_uses_canonical_path_and_ignores_query_selector_text() {
    let fixture = Fixture::new(
        &[route("a", "/a/**"), route("b", "/b/**")],
        &[("/a/**", "a", "aud-a"), ("/b/**", "b", "aud-b")],
        2,
    );
    let mut connection = fixture.connect();
    let response = connection
        .exchange("GET", "/a/../b/%69tem?next=/a/item", true)
        .await;
    let capture = connection.finish().await;
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 1);
    assert_authorization(&capture.requests[0], "aud-b");
    fixture
        .resolver
        .assert_calls(&[(&fixture.grant_key("/b/**", "b"), "aud-b")]);
}

#[tokio::test]
async fn route_selected_grants_follow_a_b_a_on_one_connection() {
    let fixture = Fixture::new(
        &[route("a", "/a/**"), route("b", "/b/**")],
        &[("/a/**", "a", "aud-a"), ("/b/**", "b", "aud-b")],
        2,
    );
    let mut connection = fixture.connect();
    let mut responses = Vec::new();
    for path in ["/a/first", "/b/second", "/a/third"] {
        responses.push(connection.exchange("GET", path, true).await);
    }
    let capture = connection.finish().await;
    assert!(
        responses
            .iter()
            .all(|response| response.starts_with("HTTP/1.1 204"))
    );
    assert_eq!(capture.requests.len(), 3);
    for ((request, audience), path) in capture
        .requests
        .iter()
        .zip(["aud-a", "aud-b", "aud-a"])
        .zip(["/a/first", "/b/second", "/a/third"])
    {
        assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
        assert_authorization(request, audience);
    }
    fixture.resolver.assert_calls(&[
        (&fixture.grant_key("/a/**", "a"), "aud-a"),
        (&fixture.grant_key("/b/**", "b"), "aud-b"),
        (&fixture.grant_key("/a/**", "a"), "aud-a"),
    ]);
}

#[tokio::test]
async fn broader_get_allow_does_not_authorize_narrow_post_owner() {
    let mut narrow = route("narrow", "/a/private/**");
    narrow.method = "POST";
    let fixture = Fixture::new(
        &[route("broad", "/a/**"), narrow],
        &[("/a/private/**", "narrow", "aud-private")],
        2,
    );
    let mut connection = fixture.connect();
    let response = connection.exchange("GET", "/a/private/item", false).await;
    let capture = connection.finish().await;
    // Forwarding without a token is permitted by the broader endpoint. This
    // control alone cannot prove ownership if route-selected injection is absent.
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 1);
    fixture.resolver.assert_calls(&[]);
    assert_no_authorization(&capture);
}

#[tokio::test]
async fn overlapping_get_and_post_select_their_admitted_owner_on_one_connection() {
    let mut narrow = route("narrow", "/a/private/**");
    narrow.method = "POST";
    let fixture = Fixture::new(
        &[route("broad", "/a/**"), narrow],
        &[
            ("/a/**", "broad", "aud-broad"),
            ("/a/private/**", "narrow", "aud-private"),
        ],
        2,
    );
    let mut connection = fixture.connect();
    let mut responses = Vec::new();
    for method in ["GET", "POST", "GET"] {
        responses.push(connection.exchange(method, "/a/private/item", true).await);
    }
    let capture = connection.finish().await;
    assert!(
        responses
            .iter()
            .all(|response| response.starts_with("HTTP/1.1 204"))
    );
    assert_eq!(capture.requests.len(), 3);
    for (request, audience) in
        capture
            .requests
            .iter()
            .zip(["aud-broad", "aud-private", "aud-broad"])
    {
        assert_authorization(request, audience);
    }
    fixture.resolver.assert_calls(&[
        (&fixture.grant_key("/a/**", "broad"), "aud-broad"),
        (&fixture.grant_key("/a/private/**", "narrow"), "aud-private"),
        (&fixture.grant_key("/a/**", "broad"), "aud-broad"),
    ]);
}

#[tokio::test]
async fn equal_selector_does_not_authorize_another_binarys_grant() {
    let mut owner = route("owner", "/a/**");
    owner.binary = "/usr/bin/other-client";
    let fixture = Fixture::new(
        &[route("allowed", "/a/**"), owner],
        &[("/a/**", "owner", "aud-owner")],
        1,
    );
    let mut connection = fixture.connect();
    let response = connection.exchange("GET", "/a/item", false).await;
    let capture = connection.finish().await;
    // One grant avoids dynamic-credential ambiguity. Equal selector text still
    // cannot establish that its owning policy authorized this executable.
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 1);
    fixture.resolver.assert_calls(&[]);
    assert_no_authorization(&capture);
}

#[tokio::test]
async fn enforced_denial_mints_nothing_and_forwards_no_bytes() {
    let fixture = Fixture::new(&[route("a", "/a/**")], &[("/a/**", "a", "aud-a")], 1);
    let mut connection = fixture.connect();
    let response = connection.exchange("POST", "/a/item", false).await;
    let capture = connection.finish().await;
    assert!(response.starts_with("HTTP/1.1 403"));
    fixture.resolver.assert_calls(&[]);
    assert_eq!(
        capture.bytes_seen, 0,
        "denial includes queued and partial bytes"
    );
}

#[tokio::test]
async fn audit_denial_does_not_authorize_a_grant() {
    let mut audit = route("a", "/a/**");
    audit.enforcement = "audit";
    let fixture = Fixture::new(&[audit], &[("/a/**", "a", "aud-a")], 1);
    let mut connection = fixture.connect();
    let response = connection.exchange("POST", "/a/item", false).await;
    let capture = connection.finish().await;
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 1);
    fixture.resolver.assert_calls(&[]);
    assert_no_authorization(&capture);
}

async fn failure_then_reconnect(route_selection: bool) {
    let mut routes = vec![route("a", "/a/**")];
    if route_selection {
        routes.push(route("b", "/b/**"));
    }
    let fixture = Fixture::new(&routes, &[("/a/**", "a", "aud-a")], routes.len());
    fixture.resolver.fail_once.store(true, Ordering::SeqCst);
    let mut first = fixture.connect();
    let failed = first.exchange("GET", "/a/item", true).await;
    let failure_closed = if failed.starts_with("HTTP/1.1 502") {
        first.observes_eof().await
    } else {
        false
    };
    let rejected = first.finish().await;
    // Both connections share one resolver: a new fixture cannot hide a poisoned
    // resolver or consume the scripted failure independently of the retry.
    let mut retry = fixture.connect();
    let recovered = retry.exchange("GET", "/a/item", true).await;
    let accepted = retry.finish().await;
    assert!(failed.starts_with("HTTP/1.1 502"));
    assert!(
        failure_closed,
        "relay closes the failed tunnel without client shutdown"
    );
    assert_eq!(
        rejected.bytes_seen, 0,
        "grant failure must close before upstream bytes"
    );
    assert!(recovered.starts_with("HTTP/1.1 204"));
    assert_eq!(accepted.requests.len(), 1);
    assert_authorization(&accepted.requests[0], "aud-a");
    fixture.resolver.assert_calls(&[
        (&fixture.grant_key("/a/**", "a"), "aud-a"),
        (&fixture.grant_key("/a/**", "a"), "aud-a"),
    ]);
}

#[tokio::test]
async fn single_endpoint_recovers_after_one_grant_failure() {
    failure_then_reconnect(false).await;
}

#[tokio::test]
async fn route_selected_endpoint_recovers_after_one_grant_failure() {
    failure_then_reconnect(true).await;
}

fn refresh_fixture(route_selection: bool) -> Fixture {
    let mut routes = vec![route("a", "/a/**")];
    if route_selection {
        routes.push(route("b", "/b/**"));
    }
    Fixture::new(&routes, &[("/a/**", "a", "aud-old")], routes.len())
}

async fn keepalive_refresh(route_selection: bool) {
    let fixture = refresh_fixture(route_selection);
    let old_key = fixture.grant_key("/a/**", "a");
    let mut connection = fixture.connect();
    let first = connection.exchange("GET", "/a/first", true).await;
    fixture.install(2, &[("/a/**", "a", "aud-new")]);
    let new_key = fixture.grant_key("/a/**", "a");
    let second = connection.exchange("GET", "/a/second", true).await;
    fixture.install(3, &[]);
    let third = connection.exchange("GET", "/a/third", false).await;
    let capture = connection.finish().await;
    assert!(first.starts_with("HTTP/1.1 204") && second.starts_with("HTTP/1.1 204"));
    assert!(third.starts_with("HTTP/1.1 204"));
    assert_eq!(capture.requests.len(), 3);
    fixture
        .resolver
        .assert_calls(&[(&old_key, "aud-old"), (&new_key, "aud-new")]);
    assert_authorization(&capture.requests[0], "aud-old");
    assert_authorization(&capture.requests[1], "aud-new");
    assert!(
        !capture.requests[2]
            .to_ascii_lowercase()
            .contains("authorization:"),
        "removing live grants must not reuse the connection's original credential"
    );
}

#[tokio::test]
async fn keepalive_uses_live_grant_state_after_refresh() {
    keepalive_refresh(false).await;
}

#[tokio::test]
async fn route_selected_keepalive_uses_live_grant_state_after_refresh() {
    keepalive_refresh(true).await;
}

async fn refresh_during_grant(same_revision_repair: bool, route_selection: bool) {
    let fixture = refresh_fixture(route_selection);
    let old_key = fixture.grant_key("/a/**", "a");
    fixture.resolver.hold_once.store(true, Ordering::SeqCst);
    let mut first = fixture.connect();
    first.send("GET", "/a/item", true).await;
    timeout(WAIT, fixture.resolver.entered.notified())
        .await
        .expect("grant enters before provider state changes");
    if same_revision_repair {
        // Synthesize same-revision removal and replacement through the public
        // state API. This does not exercise a gateway publication failure.
        // Installation identity changes and must fence the old grant.
        let old_installation = fixture.state.snapshot().installation_id.clone();
        fixture.install(1, &[]);
        assert_ne!(fixture.state.snapshot().installation_id, old_installation);
        fixture.install(1, &[("/a/**", "a", "aud-new")]);
    } else {
        fixture.install(2, &[("/a/**", "a", "aud-new")]);
    }
    let new_key = fixture.grant_key("/a/**", "a");
    assert_ne!(new_key, old_key, "replacement changes cache authority");
    fixture.resolver.release.notify_one();
    let _closed_or_denied = first.response().await;
    let rejected = first.finish().await;
    let mut retry = fixture.connect();
    let recovered = retry.exchange("GET", "/a/item", true).await;
    let accepted = retry.finish().await;
    assert_eq!(
        rejected.bytes_seen, 0,
        "superseded grant must not reach upstream"
    );
    assert!(recovered.starts_with("HTTP/1.1 204"));
    assert_eq!(accepted.requests.len(), 1);
    assert_authorization(&accepted.requests[0], "aud-new");
    fixture
        .resolver
        .assert_calls(&[(&old_key, "aud-old"), (&new_key, "aud-new")]);
}

#[tokio::test]
async fn refresh_during_grant_rejects_old_token_and_reconnects() {
    refresh_during_grant(false, false).await;
}

#[tokio::test]
async fn same_revision_repair_during_grant_rejects_old_installation() {
    refresh_during_grant(true, false).await;
}

#[tokio::test]
async fn route_selected_refresh_during_grant_rejects_old_token_and_reconnects() {
    refresh_during_grant(false, true).await;
}

#[tokio::test]
async fn route_selected_same_revision_repair_during_grant_rejects_old_installation() {
    refresh_during_grant(true, true).await;
}

async fn policy_reload_during_grant(route_selection: bool) {
    let mut fixture = refresh_fixture(route_selection);
    fixture.resolver.hold_once.store(true, Ordering::SeqCst);
    let mut first = fixture.connect();
    first.send("GET", "/a/item", true).await;
    timeout(WAIT, fixture.resolver.entered.notified())
        .await
        .expect("grant enters before policy reload");
    fixture.reload_policy();
    fixture.resolver.release.notify_one();
    let _closed_or_denied = first.response().await;
    let rejected = first.finish().await;
    let mut retry = fixture.connect();
    let response = retry.exchange("GET", "/a/item", true).await;
    let accepted = retry.finish().await;
    assert_eq!(
        rejected.bytes_seen, 0,
        "stale policy generation cannot forward a grant"
    );
    assert!(response.starts_with("HTTP/1.1 204"));
    assert_eq!(accepted.requests.len(), 1);
    assert_authorization(&accepted.requests[0], "aud-old");
    let key = fixture.grant_key("/a/**", "a");
    fixture
        .resolver
        .assert_calls(&[(&key, "aud-old"), (&key, "aud-old")]);
}

#[tokio::test]
async fn policy_reload_during_grant_closes_old_tunnel_and_reconnects() {
    policy_reload_during_grant(false).await;
}

#[tokio::test]
async fn route_selected_policy_reload_during_grant_closes_old_tunnel_and_reconnects() {
    policy_reload_during_grant(true).await;
}

fn assert_cache_acquisitions(resolver: &CachedTokenGrantResolver, expected: &[(&str, &str)]) {
    let expected = expected
        .iter()
        .map(|(provider_key, audience)| CacheAcquisition {
            provider_key: (*provider_key).to_owned(),
            audience: (*audience).to_owned(),
        })
        .collect::<Vec<_>>();
    assert_eq!(resolver.acquisitions(), expected, "actual cache misses");
}

#[tokio::test]
async fn route_selected_connection_reuses_then_reacquires_expired_cached_grant() {
    let fixture = refresh_fixture(true);
    let resolver = Arc::new(CachedTokenGrantResolver::new());
    let mut connection = fixture.connect_with_resolver(resolver.clone());
    let first = connection.exchange("GET", "/a/first", true).await;
    let second = connection.exchange("GET", "/a/second", true).await;
    let expired = resolver.expire("a:access_token", "aud-old");
    let third = connection.exchange("GET", "/a/third", true).await;
    let capture = connection.finish().await;
    assert!(
        [first, second, third]
            .iter()
            .all(|response| response.starts_with("HTTP/1.1 204"))
    );
    assert_eq!(expired, 1, "expiry changes a real populated cache entry");
    assert_eq!(capture.requests.len(), 3);
    for (request, audience) in capture
        .requests
        .iter()
        .zip(["aud-old-1", "aud-old-1", "aud-old-2"])
    {
        assert_authorization(request, audience);
    }
    let key = fixture.grant_key("/a/**", "a");
    assert_cache_acquisitions(&resolver, &[(&key, "aud-old"), (&key, "aud-old")]);
}

async fn cached_grant_after_installation_change(same_revision: bool) {
    let fixture = refresh_fixture(true);
    let resolver = Arc::new(CachedTokenGrantResolver::new());
    let old_key = fixture.grant_key("/a/**", "a");
    let mut connection = fixture.connect_with_resolver(resolver.clone());
    let first = connection.exchange("GET", "/a/first", true).await;
    // Keep audience and provider identity unchanged so only the installed
    // snapshot can prevent reuse of the previously cached token.
    fixture.install(
        if same_revision { 1 } else { 2 },
        &[("/a/**", "a", "aud-old")],
    );
    let new_key = fixture.grant_key("/a/**", "a");
    let second = connection.exchange("GET", "/a/second", true).await;
    let third = connection.exchange("GET", "/a/third", true).await;
    let capture = connection.finish().await;
    assert!(
        [first, second, third]
            .iter()
            .all(|response| response.starts_with("HTTP/1.1 204"))
    );
    assert_ne!(old_key, new_key, "installation changes cache authority");
    assert_eq!(capture.requests.len(), 3);
    for (request, audience) in capture
        .requests
        .iter()
        .zip(["aud-old-1", "aud-old-2", "aud-old-2"])
    {
        assert_authorization(request, audience);
    }
    assert_cache_acquisitions(&resolver, &[(&old_key, "aud-old"), (&new_key, "aud-old")]);
}

#[tokio::test]
async fn route_selected_refresh_reacquires_cached_grant_for_same_audience() {
    cached_grant_after_installation_change(false).await;
}

#[tokio::test]
async fn route_selected_same_revision_replacement_reacquires_cached_grant() {
    cached_grant_after_installation_change(true).await;
}

fn body_protocol_context(
    endpoints: Vec<serde_json::Value>,
    target: &str,
) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
    let expected_routes = endpoints.len();
    let data = serde_json::json!({"network_policies": {"body_api": {
        "name": "body_api", "endpoints": endpoints,
        "binaries": [{"path": "/usr/bin/curl"}]
    }}})
    .to_string();
    let engine = OpaEngine::from_strings(POLICY, &data).expect("body policy compiles");
    let (configs, generation) = engine
        .query_endpoint_configs_with_generation(&NetworkInput {
            host: HOST.into(),
            port: PORT,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        })
        .expect("body endpoint query");
    assert_eq!(
        configs.len(),
        expected_routes,
        "all body routes participate"
    );
    let configs = configs
        .iter()
        .map(|config| crate::l7::parse_l7_config(config).expect("body endpoint config"))
        .collect::<Vec<_>>();
    let config = select_l7_config_for_path(&configs, target)
        .expect("selected body endpoint")
        .clone();
    let tunnel = engine
        .clone_engine_for_tunnel(generation)
        .expect("body tunnel policy");
    let ctx = L7EvalContext {
        host: HOST.into(),
        port: PORT,
        request_default_port: Some(PORT),
        binary_path: "/usr/bin/curl".into(),
        policy_name: "body_api".into(),
        ..Default::default()
    };
    (config, tunnel, ctx)
}

fn body_request(target: &str, body: &[u8]) -> crate::l7::provider::L7Request {
    let mut raw_header = format!(
        "POST {target} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: application/json\r\nAuthorization: Bearer stale-inert-value\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ).into_bytes();
    raw_header.extend_from_slice(body);
    crate::l7::provider::L7Request {
        action: "POST".into(),
        target: target.into(),
        query_params: HashMap::new(),
        raw_header,
        body_length: crate::l7::provider::BodyLength::ContentLength(body.len() as u64),
    }
}

#[test]
fn jsonrpc_batch_requires_one_owner_to_admit_every_member() {
    // This tests owner intersection after normal batch admission. No dynamic
    // credential ambiguity or gateway configuration acceptance is asserted.
    let endpoint = |owner: &str, methods: &[&str]| {
        serde_json::json!({
            "host": HOST, "port": PORT, "path": "/rpc", "protocol": "json-rpc",
            "enforcement": "enforce", "token_grant_owner": owner,
            "rules": methods.iter().map(|method| serde_json::json!({"allow": {"method": method}})).collect::<Vec<_>>()
        })
    };
    for shared_owner in [false, true] {
        let mut endpoints = vec![
            endpoint("first", &["readFirst"]),
            endpoint("second", &["readSecond"]),
        ];
        if shared_owner {
            endpoints.push(endpoint("shared", &["readFirst", "readSecond"]));
        }
        let (config, engine, ctx) = body_protocol_context(endpoints, "/rpc");
        let request = body_request("/rpc", br#"[{"jsonrpc":"2.0","id":1,"method":"readFirst"},{"jsonrpc":"2.0","id":2,"method":"readSecond"}]"#);
        let jsonrpc = crate::l7::jsonrpc::inspect_buffered_jsonrpc_http_request(
            &request,
            crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(&config),
        )
        .expect("inspect complete JSON-RPC batch");
        assert!(jsonrpc.is_batch && jsonrpc.error.is_none());
        assert_eq!(jsonrpc.calls.len(), 2);
        let info = L7RequestInfo {
            action: request.action.clone(),
            target: request.target.clone(),
            query_params: HashMap::new(),
            graphql: None,
            jsonrpc: Some(jsonrpc),
        };
        assert!(
            evaluate_l7_request(&engine, &ctx, &info)
                .expect("batch admission")
                .0
        );
        let owners =
            admitted_token_grant_owners(&engine, &ctx, &info).expect("batch owner admission");
        let expected = if shared_owner {
            HashSet::from(["shared".to_owned()])
        } else {
            HashSet::new()
        };
        assert_eq!(
            owners, expected,
            "union admission cannot lend one member's credential to another"
        );
    }
}

#[tokio::test]
async fn transformed_jsonrpc_body_selects_final_operation_owner() {
    let endpoint = |owner: &str, path: &str, method: &str| {
        serde_json::json!({
            "host": HOST, "port": PORT, "path": path, "protocol": "json-rpc",
            "enforcement": "enforce", "token_grant_owner": owner,
            "rules": [{"allow": {"method": method}}]
        })
    };
    let (config, engine, mut ctx) = body_protocol_context(
        vec![
            endpoint("original", "/api/rpc", "readOriginal"),
            endpoint("transformed", "/api/**", "readTransformed"),
        ],
        "/api/rpc",
    );
    // Generic JSON-RPC preserves union admission across endpoints. GraphQL
    // endpoints instead deny operations outside their own allow rules, so
    // disjoint GraphQL field permissions cannot establish this owner switch.
    let original_body = br#"{"jsonrpc":"2.0","id":1,"method":"readOriginal"}"#;
    let final_body = br#"{"jsonrpc":"2.0","id":1,"method":"readTransformed"}"#;
    let original = body_request("/api/rpc", original_body);
    let info = L7RequestInfo {
        action: original.action.clone(),
        target: original.target.clone(),
        query_params: HashMap::new(),
        graphql: None,
        jsonrpc: Some(
            crate::l7::jsonrpc::inspect_buffered_jsonrpc_http_request(
                &original,
                crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(&config),
            )
            .expect("inspect original JSON-RPC operation"),
        ),
    };
    assert_eq!(
        admitted_token_grant_owners(&engine, &ctx, &info).expect("original owner"),
        HashSet::from(["original".to_owned()])
    );
    let state = ProviderCredentialState::from_environment(
        1,
        HashMap::new(),
        HashMap::new(),
        credentials(&[
            ("/api/rpc", "original", "aud-original"),
            ("/api/**", "transformed", "aud-transformed"),
        ]),
    );
    let resolver = Arc::new(ScriptedResolver::default());
    ctx.provider_credentials = Some(state.clone());
    ctx.token_grant_resolver = Some(resolver.clone());
    // Supply the rebuilt body at the exact pre-grant helper boundary. This
    // does not claim a middleware service performed the rewrite.
    let transformed = body_request("/api/rpc", final_body);
    let (injected, _) = timeout(
        WAIT,
        inject_inspected_request_grant(transformed, &ctx, &engine, &config, &info),
    )
    .await
    .expect("final-body grant finishes")
    .expect("final-body grant succeeds");
    assert!(
        injected.raw_header.ends_with(final_body),
        "rewritten body preserved"
    );
    assert_authorization(
        std::str::from_utf8(&injected.raw_header).expect("injected HTTP request"),
        "aud-transformed",
    );
    let snapshot = state.snapshot();
    let expected_key = format!(
        "{HOST}\t{PORT}\t/api/**\trev:{}\tinstallation:{}\ttransformed:access_token",
        snapshot.revision, snapshot.installation_id
    );
    resolver.assert_calls(&[(&expected_key, "aud-transformed")]);
}

async fn authorityless_body_refresh(route_selection: bool) {
    let mut a = route("a", "/a/**");
    a.method = "POST";
    a.body_rewrite = true;
    let mut routes = vec![a];
    if route_selection {
        routes.push(route("b", "/b/**"));
    }
    let fixture = Fixture::new(&routes, &[("/a/**", "a", "aud-old")], routes.len());
    let old_key = fixture.grant_key("/a/**", "a");
    let body_pending = Arc::new(Notify::new());
    let mut connection =
        fixture.connect_observed(fixture.resolver.clone(), Some(body_pending.clone()));
    timeout(
        WAIT,
        connection.app.write_all(
            b"POST /a/item HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n",
        ),
    )
    .await
    .expect("write authorityless headers")
    .expect("authorityless headers accepted");
    timeout(WAIT, body_pending.notified())
        .await
        .expect("relay waits for the request body");
    fixture.resolver.assert_calls(&[(&old_key, "aud-old")]);
    // Body buffering follows grant injection and static request scoping.
    // Removing static authority must not erase the dynamic installation pin.
    fixture.install(2, &[("/a/**", "a", "aud-new")]);
    timeout(WAIT, connection.app.write_all(b"{}"))
        .await
        .expect("write delayed body")
        .expect("delayed body accepted");
    let response = connection.response().await;
    let (relay, capture) = connection.finish_with_result().await;
    fixture.resolver.assert_calls(&[(&old_key, "aud-old")]);
    // The final writer closes on a stale credential installation before it
    // writes any bytes. Its typed error is the existing writer-stage contract.
    let error = relay.expect_err("superseded dynamic credential rejected");
    assert!(
        error
            .downcast_ref::<crate::l7::rest::CredentialUnavailableError>()
            .is_some(),
        "expected typed credential freshness error, got {error:?}"
    );
    assert!(response.is_empty(), "writer closes without a response");
    assert_eq!(
        capture.bytes_seen, 0,
        "authorityless request must retain the grant's installation guard"
    );

    let current_key = fixture.grant_key("/a/**", "a");
    let mut recovered = fixture.connect();
    let response = recovered.exchange("POST", "/a/item", true).await;
    let capture = recovered.finish().await;
    assert!(response.starts_with("HTTP/1.1 204"), "fresh grant recovers");
    assert_eq!(capture.requests.len(), 1, "one request after reconnect");
    assert_authorization(&capture.requests[0], "aud-new");
    fixture
        .resolver
        .assert_calls(&[(&old_key, "aud-old"), (&current_key, "aud-new")]);
}

#[tokio::test]
async fn authorityless_body_refresh_cannot_forward_superseded_grant() {
    authorityless_body_refresh(false).await;
}

#[tokio::test]
async fn route_selected_authorityless_body_refresh_cannot_forward_superseded_grant() {
    authorityless_body_refresh(true).await;
}
