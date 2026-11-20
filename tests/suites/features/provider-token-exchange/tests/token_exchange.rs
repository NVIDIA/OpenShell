// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider token grants: the gateway and the supervisor exchange SPIFFE
//! JWT-SVIDs at token endpoints the test runs, and the supervisor injects the
//! results into requests to a protected target.
//!
//! The gateway and supervisors fetch JWT-SVIDs from Workload APIs the test
//! runs ([`spiffe_support`]). The token endpoints listen on loopback, which
//! both the gateway and Podman's host-network supervisors reach and which the
//! token endpoint transport policy allows over plain HTTP. The targets listen
//! on every address, for sandboxes to reach through `host.openshell.internal`.
//! Tests never print the fixture tokens, though none are real.

use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use spiffe_support::{ISSUER, SUPERVISOR_SUBJECT, WorkloadApis, verify_supervisor_svid};
use testkit::{Context, Error, Poll, Result, ResultExt as _, Sandbox, poll_until};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const TEST_HOST: &str = "host.openshell.internal";
const USER_SUBJECT_TOKEN: &str = "stored-user-token";
const INTERMEDIATE_TOKEN: &str = "intermediate-token";
const FINAL_ACCESS_TOKEN: &str = "final-access-token";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
const IDENTITY_AUDIENCE: &str = "identity-proxy";
const IDENTITY_JWT_AUDIENCE: &str = "https://identity.openshell-e2e.test";
const IDENTITY_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const SUBJECT_TOKEN_ENV: &str = "subject_token";

/// Two sandboxes, each with its own provider, request the same host and
/// port at the same time. Each request carries its provider's bearer token,
/// from a two-stage token exchange, and its own signed JWT-SVID, from a
/// client-credentials grant; the target checks both. Repeat requests use the
/// cached credentials. A failed grant returns 502 and sends the target no
/// bytes, and the other credential stays cached. No credential reaches the
/// workload.
#[testkit::test]
async fn independent_grants_across_sandboxes(cx: &mut Context) -> testkit::Result {
    let apis = WorkloadApis::start().await?;
    let observations = Arc::new(GrantObservations::default());
    let (token_listener, token_port) = listen(Ipv4Addr::LOCALHOST).await?;
    let (identity_listener, identity_port) = listen(Ipv4Addr::LOCALHOST).await?;
    let (target_listener, target_port) = listen(Ipv4Addr::UNSPECIFIED).await?;
    let _token = serve(token_listener, {
        let observations = Arc::clone(&observations);
        move |stream| exchange_token(stream, Arc::clone(&observations))
    });
    let _identity = serve(identity_listener, {
        let observations = Arc::clone(&observations);
        move |stream| issue_identity(stream, Arc::clone(&observations))
    });
    let _target = serve(target_listener, {
        let observations = Arc::clone(&observations);
        move |stream| protected_target(stream, Arc::clone(&observations))
    });

    let mut sandboxes = Vec::new();
    for instance in ["a", "b"] {
        let provider = cx.name(&format!("grants-{instance}"));
        let profile_type = cx
            .import_profile(&grants_profile(
                &provider,
                token_port,
                identity_port,
                target_port,
                instance,
            ))
            .await?;
        let subject = format!("{USER_SUBJECT_TOKEN}-{instance}");
        cx.create_provider(&provider, &profile_type, &[(SUBJECT_TOKEN_ENV, &subject)])
            .await?;
        sandboxes.push(
            cx.sandbox(&format!("pte{instance}"))
                .image(testkit::python_image())
                .providers([provider.as_str()])
                .create_ready()
                .await?,
        );
    }
    let [a, b] = &sandboxes[..] else {
        unreachable!("two sandboxes")
    };

    for round in ["first", "cached"] {
        let (from_a, from_b) = tokio::join!(
            probe(a, target_port, "/resource/a", false),
            probe(b, target_port, "/resource/b", false),
        );
        from_a.context(format!("the {round} request from sandbox A"))?;
        from_b.context(format!("the {round} request from sandbox B"))?;
        if round == "first" {
            let issued = observations.issued();
            testkit::ensure!(
                issued
                    .iter()
                    .all(|(service, identity)| *service > 0 && *identity > 0),
                "each provider did not acquire both credentials: {issued:?}"
            );
        }
    }
    let issued = observations.issued();
    testkit::ensure!(
        observations.target_rejected.load(Ordering::SeqCst) == 0,
        "the target rejected a request with mismatched or untrusted credentials, even if a retry then passed"
    );
    // The first round's check passed, so any difference is the second round.
    testkit::ensure!(
        observations.issued() == issued,
        "repeat requests acquired credentials again instead of using the caches"
    );

    let target_requests = observations.target_requests.load(Ordering::SeqCst);
    // An audience override forces acquisition of only the failing credential;
    // the other stays cached from the successful requests.
    let (from_a, from_b) = tokio::join!(
        probe(a, target_port, "/deny-service/a", true),
        probe(b, target_port, "/deny-identity/b", true),
    );
    from_a.context("the request from sandbox A whose service grant fails")?;
    from_b.context("the request from sandbox B whose identity grant fails")?;
    testkit::ensure!(
        observations.service_denied.load(Ordering::SeqCst) > 0,
        "the token endpoint saw no request for the denied service audience"
    );
    testkit::ensure!(
        observations.identity_denied.load(Ordering::SeqCst) > 0,
        "the identity endpoint saw no request for the denied identity audience"
    );
    testkit::ensure!(
        observations.target_requests.load(Ordering::SeqCst) == target_requests,
        "a failed grant forwarded request bytes to the target"
    );
    apis.shutdown().await;
    Ok(())
}

/// A sandbox with two providers, each bound to its own path, reaches one
/// target. A transient grant failure on B returns 502 with a request ID the
/// token endpoint also saw, closes the tunnel, and shows in the sandbox's
/// status as a retryable failure. Then requests to A, B and A on one client
/// connection each carry only their own route's token, over one upstream
/// connection, and the success clears the reported failure. The failed
/// grant sends the target nothing.
#[testkit::test]
async fn routes_recover_and_select_a_b_a_on_one_connection(cx: &mut Context) -> testkit::Result {
    let apis = WorkloadApis::start().await?;
    let grants = Arc::new(RouteGrantState::default());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_bytes = Arc::new(AtomicUsize::new(0));
    let (token_listener, token_port) = listen(Ipv4Addr::LOCALHOST).await?;
    let (target_listener, target_port) = listen(Ipv4Addr::UNSPECIFIED).await?;
    let _token = serve(token_listener, {
        let grants = Arc::clone(&grants);
        move |stream| route_token(stream, Arc::clone(&grants))
    });
    let target = RouteTarget::start(
        target_listener,
        Arc::clone(&observed),
        Arc::clone(&observed_bytes),
    );

    let mut providers = Vec::new();
    for route in ["a", "b"] {
        let provider = cx.name(&format!("route-{route}"));
        let profile_type = cx
            .import_profile(&route_profile(&provider, token_port, target_port, route))
            .await?;
        cx.create_provider(
            &provider,
            &profile_type,
            &[(SUBJECT_TOKEN_ENV, &format!("stored-{route}"))],
        )
        .await?;
        providers.push(provider);
    }
    let sandbox = cx
        .sandbox("pter")
        .image(testkit::python_image())
        .providers(providers.iter().map(String::as_str))
        .create_ready()
        .await?;

    grants.fail_next_b.store(true, Ordering::SeqCst);
    // The supervisor mediates direct workload connections as CONNECT.
    // HTTPConnection keeps one client socket for the A/B/A run.
    let failure_script = format!(
        r#"import http.client, uuid
first = http.client.HTTPConnection({TEST_HOST:?}, {target_port}, timeout=10)
first.request('GET', '/b/failure', headers={{'Authorization': 'Bearer stale-value'}})
failed = first.getresponse()
failed.read()
assert failed.status == 502, 'the controlled grant failure must return 502'
request_id = failed.getheader('x-openshell-request-id', '')
assert str(uuid.UUID(request_id)) == request_id, 'the refusal must carry a canonical request ID'
print('failed-request-id=' + request_id)
assert failed.will_close, 'the failed tunnel must close'
first.close()
"#
    );
    let recovery_script = format!(
        r#"import http.client
recovered = http.client.HTTPConnection({TEST_HOST:?}, {target_port}, timeout=10)
connection = None
for path in ['/a/first', '/b/second', '/a/third']:
    recovered.request('GET', path, headers={{'Authorization': 'Bearer stale-value'}})
    if connection is None:
        connection = recovered.sock
    assert recovered.sock is connection, 'client connection was replaced'
    response = recovered.getresponse()
    response.read()
    assert response.status == 200, 'upstream rejected the selected credential'
    assert recovered.sock is connection and connection.fileno() >= 0, 'keepalive connection closed'
recovered.close()
print('route-recovery-a-b-a-ok')
"#
    );

    let failed = sandbox.run_python(&failure_script, &[]).await?;
    let request_id = failed
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("failed-request-id="))
        .ok_or_else(|| Error::msg("the workload did not print the refusal's request ID"))?
        .to_string();
    // An authorized reader sees the cause of the refused grant.
    let reported = wait_for_grant_failure(&sandbox, true).await?;
    let recovered = sandbox.run_python(&recovery_script, &[]).await?;
    testkit::ensure!(
        recovered.stdout.contains("route-recovery-a-b-a-ok"),
        "the A/B/A requests did not finish: {}",
        recovered.stdout
    );
    // The matching grant's later success clears it.
    wait_for_grant_failure(&sandbox, false).await?;
    sandbox.delete().await?;
    sandbox.wait_absent(Duration::from_secs(60)).await?;
    target
        .drain()
        .await
        .context("the route target saw EOF on every accepted connection")?;
    apis.shutdown().await;

    testkit::ensure!(
        grants.failed_request_id.lock().expect("lock").as_deref() == Some(request_id.as_str()),
        "the token endpoint and the refused response named different exchanges"
    );
    let expected_failure = [
        ("request_id", json!(request_id)),
        ("code", json!("unavailable")),
        ("recovery_action", json!("retry")),
        ("stage", json!("token_endpoint")),
        ("upstream_http_status", json!(503)),
        ("provider", json!(providers[1])),
        ("credential_key", json!("access_token")),
    ];
    testkit::ensure!(
        reported["destination_port"] == json!(target_port),
        "the reported failure names destination port {}, not {target_port}",
        reported["destination_port"]
    );
    for (key, expected) in expected_failure {
        testkit::ensure!(
            reported["failure"][key] == expected,
            "the reported failure's {key} is {}, not {expected}",
            reported["failure"][key]
        );
    }

    let requests = observed.lock().expect("lock");
    let summary: Vec<(usize, &str)> = requests
        .iter()
        .map(|request| (request.connection, request.path.as_str()))
        .collect();
    testkit::ensure!(
        requests.len() == 3,
        "the target saw {summary:?}; the failed grant must not reach it"
    );
    testkit::ensure!(
        observed_bytes.load(Ordering::Relaxed)
            == requests.iter().map(|request| request.bytes).sum::<usize>(),
        "part of the failed request reached the target"
    );
    for ((request, path), token) in requests
        .iter()
        .zip(["/a/first", "/b/second", "/a/third"])
        .zip(["Bearer final-a", "Bearer final-b", "Bearer final-a"])
    {
        testkit::ensure!(
            request.path == path && request.connection == requests[0].connection,
            "the target saw {summary:?}; expected the A/B/A paths on one upstream connection"
        );
        testkit::ensure!(
            request.authorization.len() == 1 && request.authorization[0] == token,
            "{path} did not carry exactly its own route's token"
        );
    }
    let exchanges = grants.supervisor_requests.lock().expect("lock").clone();
    testkit::ensure!(
        exchanges == ["b", "a", "b"],
        "the supervisor exchanged tokens for routes {exchanges:?}; expected B (failed), A, B and A from its cache"
    );
    Ok(())
}

#[derive(Default)]
struct GrantObservations {
    service_issued: [AtomicUsize; 2],
    identity_issued: [AtomicUsize; 2],
    service_denied: AtomicUsize,
    identity_denied: AtomicUsize,
    target_requests: AtomicUsize,
    target_rejected: AtomicUsize,
}

impl GrantObservations {
    fn issued(&self) -> [(usize, usize); 2] {
        std::array::from_fn(|index| {
            (
                self.service_issued[index].load(Ordering::SeqCst),
                self.identity_issued[index].load(Ordering::SeqCst),
            )
        })
    }
}

/// The gateway's and the supervisor's token exchanges. The gateway trades
/// the stored subject token for an intermediate token addressed to the
/// supervisor's SPIFFE ID; the supervisor trades that for the final token.
async fn exchange_token(mut stream: TcpStream, observations: Arc<GrantObservations>) {
    let Some(request) = read_http_request(&mut stream).await else {
        return;
    };
    let form = token_form(&request);
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let valid = request.starts_with("POST /token ")
        && field("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange"
        && field("client_assertion_type") == CLIENT_ASSERTION_TYPE
        && field("subject_token_type") == TOKEN_TYPE_ACCESS_TOKEN
        && field("requested_token_type") == TOKEN_TYPE_ACCESS_TOKEN
        && !field("client_assertion").is_empty();
    let mut access_token = None;
    for (index, instance) in ["a", "b"].into_iter().enumerate() {
        if !valid {
            break;
        }
        if field("subject_token") == format!("{USER_SUBJECT_TOKEN}-{instance}")
            && field("audience") == SUPERVISOR_SUBJECT
            && field("scope").is_empty()
        {
            access_token = Some(format!("{INTERMEDIATE_TOKEN}-{instance}"));
        } else if field("subject_token") == format!("{INTERMEDIATE_TOKEN}-{instance}")
            && field("scope") == "service.read"
        {
            if field("audience") == format!("service-{instance}") {
                observations.service_issued[index].fetch_add(1, Ordering::SeqCst);
                access_token = Some(format!("{FINAL_ACCESS_TOKEN}-{instance}"));
            } else if field("audience") == format!("denied-service-{instance}") {
                observations.service_denied.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    write_token_response(&mut stream, access_token.as_deref(), 600).await;
}

/// A client-credentials grant that checks the supervisor's JWT-SVID and
/// returns it as the access token. No new grant type or sandbox-visible
/// credential is needed to exercise custom-header injection.
async fn issue_identity(mut stream: TcpStream, observations: Arc<GrantObservations>) {
    let Some(request) = read_http_request(&mut stream).await else {
        return;
    };
    let form = token_form(&request);
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let mut access_token = None;
    for (index, instance) in ["a", "b"].into_iter().enumerate() {
        let valid = request.starts_with("POST /identity-token ")
            && field("grant_type") == "client_credentials"
            && field("client_assertion_type") == IDENTITY_ASSERTION_TYPE
            && field("scope") == "identity.read"
            && verify_supervisor_svid(field("client_assertion"), &identity_jwt_audience(instance));
        if valid && field("audience") == format!("{IDENTITY_AUDIENCE}-{instance}") {
            observations.identity_issued[index].fetch_add(1, Ordering::SeqCst);
            access_token = Some(field("client_assertion"));
        } else if valid && field("audience") == format!("denied-identity-{instance}") {
            observations.identity_denied.fetch_add(1, Ordering::SeqCst);
        }
    }
    write_token_response(&mut stream, access_token, 900).await;
}

/// Accepts `GET /resource/<instance>` only with exactly one bearer token and
/// one JWT-SVID, both for that instance.
async fn protected_target(mut stream: TcpStream, observations: Arc<GrantObservations>) {
    // Count any request bytes, including an incomplete header. A failed
    // grant may open a TCP stream but must send no request.
    let mut byte = [0_u8; 1];
    if !matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut byte)).await,
        Ok(Ok(1))
    ) {
        return;
    }
    observations.target_requests.fetch_add(1, Ordering::SeqCst);
    let Some(request) = read_http_request(&mut stream).await else {
        return;
    };
    let headers = request.split("\r\n\r\n").next().unwrap_or_default();
    let header_values = |name: &str| {
        headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>()
    };
    let bearer = header_values("authorization");
    let identity = header_values("x-workload-jwt");
    let ok = ["a", "b"].into_iter().any(|instance| {
        request.starts_with(&format!("GET /resource/{instance} "))
            && bearer.len() == 1
            && bearer[0] == format!("Bearer {FINAL_ACCESS_TOKEN}-{instance}")
            && identity.len() == 1
            && verify_supervisor_svid(identity[0], &identity_jwt_audience(instance))
    });
    let (status, body) = if ok {
        ("HTTP/1.1 200 OK", "independent-grants-ok")
    } else {
        // Keep the rejection even if the workload retries and a later
        // request gets the right credentials.
        observations.target_rejected.fetch_add(1, Ordering::SeqCst);
        (
            "HTTP/1.1 401 Unauthorized",
            "credential-verification-failed",
        )
    };
    let response = format!(
        "{status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

fn identity_jwt_audience(instance: &str) -> String {
    format!("{IDENTITY_JWT_AUDIENCE}/{instance}")
}

/// Request `path` from the target with agent-supplied credentials the
/// supervisor must replace, and fail if any credential reaches the workload.
/// `expect_denied` expects the supervisor's 502 refusal with a request ID.
/// Retries while the exec fails, as when a grant is still settling.
async fn probe(sandbox: &Sandbox, target_port: u16, path: &str, expect_denied: bool) -> Result {
    let url = format!("http://{TEST_HOST}:{target_port}{path}");
    let expect_denied_python = if expect_denied { "True" } else { "False" };
    let expected = if expect_denied {
        "grant-denied"
    } else {
        "independent-grants-ok"
    };
    // The script prints fixed markers only, so its output never holds a
    // credential.
    let script = format!(
        r#"import base64, json, os, re, urllib.error, urllib.request, uuid

def contains_credential(value):
    if any(marker in value for marker in (
        "stored-user-token", "intermediate-token", "final-access-token", "openshell:resolve:"
    )):
        return True
    for token in re.findall(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if claims.get("iss") == "{ISSUER}":
                return True
        except (ValueError, UnicodeError, AttributeError):
            pass
    return False

if any(contains_credential(value) for value in os.environ.values()):
    raise SystemExit("provider credential material reached the workload environment")
request = urllib.request.Request({url:?}, headers={{
    "Authorization": "Bearer agent-supplied",
    "X-Workload-Jwt": "agent-supplied",
}})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode()
    if contains_credential(body):
        raise SystemExit("provider credential material reached the workload response")
    if {expect_denied_python}:
        raise SystemExit("failed grant unexpectedly reached the target")
    print(body)
except urllib.error.HTTPError as error:
    body = error.read().decode()
    if contains_credential(body):
        raise SystemExit("provider credential material reached the workload error")
    if not {expect_denied_python} or error.code != 502:
        raise SystemExit("unexpected HTTP status " + str(error.code))
    # The refusal names the exchange with an opaque ID and nothing else.
    request_id = error.headers.get("x-openshell-request-id", "")
    if str(uuid.UUID(request_id)) != request_id:
        raise SystemExit("refusal did not carry a canonical request ID")
    print("grant-denied")
"#
    );
    let output = sandbox
        .poll_exec(
            &format!("{path} to answer from sandbox {}", sandbox.name()),
            Duration::from_secs(20),
            ["python3", "-c", &script],
            |output| output.exit_code == 0,
        )
        .await?;
    testkit::ensure!(
        output.stdout.trim() == expected,
        "{path} from sandbox {} printed {:?}, not {expected}",
        sandbox.name(),
        output.stdout.trim()
    );
    Ok(())
}

/// A profile with two grants for one request: a token-exchange bearer token
/// and a client-credentials JWT-SVID header. Each has a path whose audience
/// the token endpoints deny.
fn grants_profile(
    profile_type: &str,
    token_port: u16,
    identity_port: u16,
    target_port: u16,
    instance: &str,
) -> String {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    let identity_jwt_audience = identity_jwt_audience(instance);
    format!(
        r"id: {profile_type}
display_name: Token exchange test
description: Independent bearer and JWT-SVID grants for one request
category: other
credentials:
  - name: subject_token
    description: Stored user subject token
    required: true
  - name: access_token
    description: Access token obtained through token exchange
    required: false
    auth_style: bearer
    header_name: Authorization
    token_grant:
      grant_type: token_exchange
      token_endpoint: {token_endpoint}
      audience: service-{instance}
      scopes: [service.read]
      jwt_svid_audience: {token_endpoint}
      client_assertion_type: {CLIENT_ASSERTION_TYPE}
      requested_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
      cache_ttl_seconds: 300
      audience_overrides:
        - path: /deny-service/{instance}
          audience: denied-service-{instance}
      subject_token:
        source: provider_credential
        credential: subject_token
        subject_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
  - name: workload_identity
    description: Signed workload identity for the identity proxy
    required: false
    auth_style: header
    header_name: X-Workload-Jwt
    token_grant:
      grant_type: client_credentials
      token_endpoint: http://127.0.0.1:{identity_port}/identity-token
      audience: {IDENTITY_AUDIENCE}-{instance}
      scopes: [identity.read]
      jwt_svid_audience: {identity_jwt_audience}
      client_assertion_type: {IDENTITY_ASSERTION_TYPE}
      cache_ttl_seconds: 600
      audience_overrides:
        - path: /deny-identity/{instance}
          audience: denied-identity-{instance}
{}",
        endpoints(target_port, "/**")
    )
}

/// A profile with one token-exchange bearer grant bound to `/<route>/**`.
/// Each route has its own audience, so the token endpoint can tell which
/// endpoint's grant the supervisor selected.
fn route_profile(profile_type: &str, token_port: u16, target_port: u16, route: &str) -> String {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    format!(
        r"id: {profile_type}
display_name: Token exchange route test
description: Route-bound bearer grant
category: other
credentials:
  - name: subject_token
    description: Stored user subject token
    required: true
  - name: access_token
    description: Access token obtained through token exchange
    required: false
    auth_style: bearer
    header_name: Authorization
    token_grant:
      grant_type: token_exchange
      token_endpoint: {token_endpoint}
      audience: audience-{route}
      jwt_svid_audience: {token_endpoint}
      client_assertion_type: {CLIENT_ASSERTION_TYPE}
      requested_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
      cache_ttl_seconds: 300
      subject_token:
        source: provider_credential
        credential: subject_token
        subject_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
{}",
        endpoints(target_port, &format!("/{route}/**"))
    )
}

fn endpoints(target_port: u16, path: &str) -> String {
    format!(
        r"endpoints:
  - host: {TEST_HOST}
    port: {target_port}
    path: {path}
    protocol: rest
    access: read-write
    enforcement: enforce
    allowed_ips:
      - 10.0.0.0/8
      - 169.254.0.0/16
      - 172.0.0.0/8
      - 192.168.0.0/16
binaries:
  - /**
"
    )
}

/// Poll the sandbox's status until its last token-grant failure is present
/// or absent, and return it.
async fn wait_for_grant_failure(sandbox: &Sandbox, present: bool) -> Result<serde_json::Value> {
    let what = if present {
        "to report a token-grant failure"
    } else {
        "to clear its token-grant failure"
    };
    poll_until(
        &format!("sandbox {} {what}", sandbox.name()),
        Duration::from_secs(30),
        Duration::from_secs(1),
        async || {
            let failure = sandbox.get_json().await?["last_token_grant_failure"].clone();
            Ok(if failure.is_null() == present {
                Poll::Pending(format!("last_token_grant_failure is {failure}"))
            } else {
                Poll::Ready(failure)
            })
        },
    )
    .await
}

#[derive(Default)]
struct RouteGrantState {
    fail_next_b: AtomicBool,
    supervisor_requests: Mutex<Vec<String>>,
    failed_request_id: Mutex<Option<String>>,
}

/// The route grants' token endpoint. It records each supervisor exchange's
/// route, and fails the next one for B with a 503 when `fail_next_b` is set.
async fn route_token(mut stream: TcpStream, state: Arc<RouteGrantState>) {
    let Ok(Some(request)) = read_route_request(&mut stream, None).await else {
        return;
    };
    let form = token_form(&request);
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let subject = field("subject_token");
    let route = match subject {
        "stored-a" | "intermediate-a" => "a",
        "stored-b" | "intermediate-b" => "b",
        _ => "",
    };
    let supervisor = subject.starts_with("intermediate-");
    // The gateway's exchange targets the supervisor's SPIFFE ID; the
    // supervisor's targets the route's audience.
    let valid = !route.is_empty()
        && request.starts_with("POST /token ")
        && !field("client_assertion").is_empty()
        && !field("audience").is_empty()
        && (!supervisor || field("audience") == format!("audience-{route}"));
    let fail = if valid && supervisor {
        state
            .supervisor_requests
            .lock()
            .expect("lock")
            .push(route.to_owned());
        route == "b" && state.fail_next_b.swap(false, Ordering::SeqCst)
    } else {
        false
    };
    let (status, body) = if fail {
        let request_id = request
            .split_once("\r\n\r\n")
            .map(|(headers, _)| headers)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-openshell-request-id"))
            .map(|(_, value)| value.trim().to_owned());
        *state.failed_request_id.lock().expect("lock") = request_id;
        (
            "HTTP/1.1 503 Service Unavailable",
            json!({"error": "temporary_failure"}).to_string(),
        )
    } else if valid {
        let stage = if supervisor { "final" } else { "intermediate" };
        (
            "HTTP/1.1 200 OK",
            json!({"access_token": format!("{stage}-{route}"), "token_type": "Bearer", "expires_in": 300})
                .to_string(),
        )
    } else {
        (
            "HTTP/1.1 400 Bad Request",
            json!({"error": "unexpected_route_exchange"}).to_string(),
        )
    };
    let response = format!(
        "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        stream.write_all(response.as_bytes()),
    )
    .await;
}

struct RouteTargetRequest {
    connection: usize,
    path: String,
    authorization: Vec<String>,
    bytes: usize,
}

/// The route grants' target. It keeps each connection open across requests
/// and records every byte it reads, so draining it proves that nothing else
/// arrived.
struct RouteTarget {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::result::Result<(), String>>,
}

impl RouteTarget {
    fn start(
        listener: TcpListener,
        observed: Arc<Mutex<Vec<RouteTargetRequest>>>,
        observed_bytes: Arc<AtomicUsize>,
    ) -> Self {
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let next_connection = AtomicUsize::new(1);
            let mut connections = tokio::task::JoinSet::new();
            let mut completed = Vec::new();
            loop {
                tokio::select! {
                    // Once the workload has closed, accept queued connections
                    // before stopping so their buffered bytes are observed too.
                    biased;
                    accepted = listener.accept() => {
                        let (stream, _) = accepted
                            .map_err(|error| format!("route target accept failed: {error}"))?;
                        let connection = next_connection.fetch_add(1, Ordering::Relaxed);
                        connections.spawn(route_connection(
                            stream,
                            connection,
                            Arc::clone(&observed),
                            Arc::clone(&observed_bytes),
                        ));
                    }
                    _ = &mut stopped => break,
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        completed.push(result);
                    }
                }
            }
            drop(listener);
            // Only EOF proves that the byte count includes everything sent on
            // each accepted connection, so wait for every reader.
            while let Some(result) = connections.join_next().await {
                completed.push(result);
            }
            for result in completed {
                result.map_err(|error| format!("route target reader task failed: {error}"))??;
            }
            Ok(())
        });
        Self {
            stop: Some(stop),
            task,
        }
    }

    /// Stop accepting, then wait for every connection to reach EOF.
    async fn drain(mut self) -> Result {
        if let Some(stop) = self.stop.take() {
            // A closed receiver means the task already stopped; joining still
            // reports its error.
            let _ = stop.send(());
        }
        tokio::time::timeout(Duration::from_secs(35), &mut self.task)
            .await
            .map_err(|_| Error::msg("the route target did not drain its connections"))?
            .map_err(|error| Error::msg(format!("the route target task failed: {error}")))?
            .map_err(Error::msg)
    }
}

impl Drop for RouteTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn route_connection(
    mut stream: TcpStream,
    connection: usize,
    observed: Arc<Mutex<Vec<RouteTargetRequest>>>,
    observed_bytes: Arc<AtomicUsize>,
) -> std::result::Result<(), String> {
    while let Some(request) = read_route_request(&mut stream, Some(&observed_bytes)).await? {
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_owned();
        let authorization = request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim().to_owned())
            .collect::<Vec<_>>();
        let expected = if path.starts_with("/a/") {
            "Bearer final-a"
        } else {
            "Bearer final-b"
        };
        let valid = authorization.len() == 1 && authorization[0] == expected;
        observed.lock().expect("lock").push(RouteTargetRequest {
            connection,
            path,
            authorization,
            bytes: request.len(),
        });
        let status = if valid {
            "HTTP/1.1 200 OK"
        } else {
            "HTTP/1.1 401 Unauthorized"
        };
        let response = format!("{status}\r\nContent-Length: 0\r\n\r\n");
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.write_all(response.as_bytes()),
        )
        .await
        .map_err(|_| "route target response write timed out".to_owned())?
        .map_err(|error| format!("route target response write failed: {error}"))?;
    }
    Ok(())
}

async fn listen(ip: Ipv4Addr) -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0)))
        .await
        .context(format!("listen on {ip}"))?;
    let port = listener
        .local_addr()
        .context("read the listener's port")?
        .port();
    Ok((listener, port))
}

/// Handle each connection `listener` accepts with `handle`, until dropped.
struct Served(tokio::task::JoinHandle<()>);

impl Drop for Served {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn serve<F, Fut>(listener: TcpListener, handle: F) -> Served
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Served(tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            tokio::spawn(handle(stream));
        }
    }))
}

/// Read one bounded request framed by Content-Length. Forms and JWT headers
/// can span TCP reads.
async fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let length = stream.read(&mut buffer).await.ok()?;
            if length == 0 || request.len() + length > 32 * 1024 {
                return None;
            }
            request.extend_from_slice(&buffer[..length]);
            if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).ok()?;
                let content_length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map_or(Some(0), |(_, value)| value.trim().parse::<usize>().ok())?;
                if request.len() >= end.checked_add(4)?.checked_add(content_length)? {
                    return String::from_utf8(request).ok();
                }
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Read one whole request without consuming the next one on a keepalive
/// connection, counting the bytes read in `observed_bytes`. `None` is a
/// clean EOF.
async fn read_route_request(
    stream: &mut TcpStream,
    observed_bytes: Option<&AtomicUsize>,
) -> std::result::Result<Option<String>, String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream
                .read(&mut byte)
                .await
                .map_err(|error| error.to_string())?
                == 0
            {
                return if bytes.is_empty() {
                    Ok(None)
                } else {
                    Err("partial fixture header".into())
                };
            }
            bytes.push(byte[0]);
            if let Some(observed) = observed_bytes {
                observed.fetch_add(1, Ordering::Relaxed);
            }
            if bytes.len() > 16 * 1024 {
                return Err("fixture header exceeds limit".into());
            }
        }
        let header = std::str::from_utf8(&bytes).map_err(|error| error.to_string())?;
        let length = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse::<usize>())
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or(0);
        if length > 64 * 1024 {
            return Err("fixture body exceeds limit".into());
        }
        let header_len = bytes.len();
        bytes.resize(header_len + length, 0);
        stream
            .read_exact(&mut bytes[header_len..])
            .await
            .map_err(|error| error.to_string())?;
        if let Some(observed) = observed_bytes {
            observed.fetch_add(length, Ordering::Relaxed);
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "fixture request timed out".to_owned())?
}

fn token_form(request: &str) -> HashMap<String, String> {
    let (_, body) = request.split_once("\r\n\r\n").unwrap_or_default();
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

async fn write_token_response(stream: &mut TcpStream, access_token: Option<&str>, ttl: u64) {
    let (status, body) = if let Some(access_token) = access_token {
        (
            "HTTP/1.1 200 OK",
            json!({"access_token": access_token, "token_type": "Bearer", "expires_in": ttl})
                .to_string(),
        )
    } else {
        (
            "HTTP/1.1 400 Bad Request",
            json!({"error": "invalid_grant"}).to_string(),
        )
    };
    let response = format!(
        "{status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}
