// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTPS Gateway and OAuth broker with the real supervisor credential relay.
//! Exercises automatic Bearer and client-supplied header placement.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Form, FromRequest, Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use openshell_core::{
    grpc_client::{
        GatewayEndpoint, ProviderEnvironmentResult, fetch_provider_environment,
        fetch_settings_snapshot,
    },
    oauth::DEFAULT_CLIENT_ASSERTION_TYPE,
    proto::{
        NetworkAccessPreset, NetworkBinary, NetworkEndpoint, ProviderCredentialTokenGrant,
        ProviderCredentialTokenGrantType, ProviderProfile, ProviderProfileCategory,
        ProviderProfileCredential, SandboxPolicy,
    },
    provider_credentials::ProviderCredentialState,
    token_grant_failure::REQUEST_ID_HEADER,
};
use openshell_server::{
    TlsAcceptor,
    test_support::provider_grant::{PROVIDER_ID, ProviderGrantGateway, SANDBOX, SIBLING},
};
use serde::Deserialize;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

use super::{Connection, HOST, PORT, WAIT};
use crate::l7::relay::L7EvalContext;
use crate::l7::token_grant_injection::SpiffeTokenGrantResolver;
use crate::opa::{NetworkAction, NetworkInput, OpaEngine};
use crate::token_grant::SandboxInstanceTokenGrants;

#[cfg(target_os = "linux")]
mod placeholder_fetch;

const CHILD_CERT_DIR: &str = "OPENSHELL_PROVIDER_ASSERTION_WIRE_CERT_DIR";
const GATEWAY_ISSUER: &str = "openshell-gateway:wire-gateway";
const CREDENTIAL: &str = "access_token";
const ENV_KEY: &str = "WIRE_AUTHORIZATION";
const PLACEHOLDER_VALUE: &str = "fixture-placeholder-source";
const ACCESS_TOKEN: &str = "fixture-granted-access-token";
const RESOURCE_AUDIENCE: &str = "api://wire-origin";

#[test]
fn provider_client_assertion_wire() {
    let name = concat!(module_path!(), "::provider_client_assertion_wire");
    with_tls_fixture(name, |cert_dir| run_bounded(run(cert_dir), WAIT * 4));
}

fn run_bounded(exercise: impl Future<Output = ()>, timeout: Duration) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(timeout, exercise)
                .await
                .expect("bounded local wire test")
        });
}

fn with_tls_fixture(full_name: &str, exercise: impl FnOnce(&Path)) {
    if let Some(cert_dir) = std::env::var_os(CHILD_CERT_DIR) {
        exercise(Path::new(&cert_dir));
        return;
    }

    // TLS trust is process configuration for both real clients. Give this case
    // an isolated process so other tests never observe its ephemeral CA.
    let cert_dir = tempfile::tempdir().unwrap();
    let pki = openshell_otel_test_support::TestPki::generate();
    for (name, pem) in [
        ("ca.pem", pki.ca_pem),
        ("server-cert.pem", pki.server.cert_pem),
        ("server-key.pem", pki.server.key_pem),
    ] {
        std::fs::write(cert_dir.path().join(name), pem).unwrap();
    }
    let ca = cert_dir.path().join("ca.pem");
    let (_, test_name) = full_name.split_once("::").expect("crate prefix");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_CERT_DIR, cert_dir.path())
        .env("SSL_CERT_FILE", &ca)
        .env_remove("SSL_CERT_DIR")
        .env(openshell_core::sandbox_env::TLS_CA, &ca)
        .env_remove(openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME)
        .output()
        .expect("run wire test with isolated certificate trust");
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
        "wire test subprocess failed\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

async fn run(cert_dir: &Path) {
    openshell_crypto::tls::ensure_default_provider();
    let target = "/wire";
    let environment = &[(ENV_KEY, PLACEHOLDER_VALUE)];
    let tls = gateway_tls(cert_dir);
    let (listener, broker_url) = bind_broker().await;
    let binary = crate::test_support::executable_path("/usr/bin/curl");
    let gateway = ProviderGrantGateway::start(
        tls.clone(),
        profile(&broker_url, &binary, "bearer", target, environment),
        CREDENTIAL,
        &broker_url,
        environment,
    )
    .await;
    let broker = Broker::start(listener, tls.acceptor(), &broker_url, &gateway).await;

    let policy = gateway_policy(&gateway.sandbox, SANDBOX).await;
    let engine = Arc::new(OpaEngine::from_proto(&policy).expect("provider policy compiles"));
    let delivery = fetch_provider_environment(&gateway.sandbox, SANDBOX)
        .await
        .expect("fetch real provider installation over TLS");
    assert!(
        delivery
            .dynamic_credentials
            .values()
            .any(
                |credential| credential.token_grant_provider_id == PROVIDER_ID
                    && credential.auth_style == "bearer"
            ),
        "Gateway delivers the immutable provider identity and authored placement"
    );
    let state = provider_state(delivery);
    let child = state.snapshot();
    let workload_header = &child.child_env[ENV_KEY];
    assert!(workload_header.starts_with("openshell:resolve:env:"));
    assert!(
        child
            .child_env
            .values()
            .all(|value| { !value.contains(PLACEHOLDER_VALUE) && !value.contains(ACCESS_TOKEN) }),
        "workload environment excludes granted and stored credential values",
    );

    let authorization = engine
        .authorize_egress(&NetworkInput {
            host: HOST.into(),
            port: PORT,
            binary_path: binary.clone(),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        })
        .expect("OPA resolves the provider route");
    let NetworkAction::Allow {
        matched_policy: Some(policy_name),
    } = authorization.action
    else {
        panic!("Gateway policy did not admit the fixture destination");
    };
    let [endpoint] = authorization.endpoint_configs.as_slice() else {
        panic!("expected one provider endpoint");
    };
    let config = crate::l7::parse_l7_config(endpoint).unwrap();
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\
                 Authorization: Bearer {workload_header}\r\n\
                 authorization: Bearer stale-value\r\nContent-Length: 0\r\n\r\n"
    );
    let exchange = async |caller: &GatewayEndpoint, expected_status: &str| {
        let ctx = L7EvalContext {
            host: HOST.into(),
            port: PORT,
            workspace: "default".into(),
            binary_path: binary.to_str().unwrap().into(),
            policy_name: policy_name.clone(),
            provider_credentials: Some(state.clone()),
            request_default_port: Some(443),
            // Each caller must reach acquisition instead of a cache hit.
            token_grant_resolver: Some(Arc::new(SpiffeTokenGrantResolver::new(
                SandboxInstanceTokenGrants::new(Some(caller.clone()), Some(SANDBOX.into()), None),
            ))),
            ..Default::default()
        };
        let mut connection = Connection::new(
            vec![config.clone()],
            engine.clone(),
            authorization.generation,
            ctx,
            None,
        );
        connection.app.write_all(request.as_bytes()).await.unwrap();
        let response = connection.response().await;
        assert!(response.starts_with(expected_status));
        assert!(response.contains("Content-Length: 0\r\n"));
        assert!(!response.contains(ACCESS_TOKEN));
        assert!(!response.contains(PLACEHOLDER_VALUE));
        connection.finish().await
    };

    // The sibling has a valid session, but cannot mint for this sandbox.
    fetch_provider_environment(&gateway.sibling, SIBLING)
        .await
        .expect("sibling session authenticates for its own sandbox");
    assert_eq!(
        exchange(&gateway.sibling, "HTTP/1.1 502 ").await.bytes_seen,
        0
    );
    broker.assert_outcomes(&[]);

    let capture = exchange(&gateway.sandbox, "HTTP/1.1 204 ").await;
    let [origin] = capture.requests.as_slice() else {
        panic!("expected one request at the origin");
    };
    let values = origin
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .collect::<Vec<_>>();
    assert!(origin.starts_with(&format!("GET {target} HTTP/1.1\r\n")));
    let expected = format!("Bearer {ACCESS_TOKEN}");
    assert!(
        values == [expected],
        "exactly one Authorization header carries the granted access token"
    );
    assert!(!origin.contains(workload_header));
    assert!(!origin.contains(PLACEHOLDER_VALUE));
    broker.assert_outcomes(&[Outcome::Issued]);

    *broker.state.audience.lock().unwrap() = format!("{broker_url}/other");
    assert_eq!(
        exchange(&gateway.sandbox, "HTTP/1.1 502 ").await.bytes_seen,
        0
    );
    broker.assert_outcomes(&[Outcome::Issued, Outcome::WrongAudience]);
}

fn gateway_tls(cert_dir: &Path) -> TlsAcceptor {
    TlsAcceptor::from_files(
        &cert_dir.join("server-cert.pem"),
        &cert_dir.join("server-key.pem"),
        None,
        false,
        None,
        None,
        Vec::new(),
    )
    .expect("fixture Gateway TLS")
}

async fn bind_broker() -> (TcpListener, String) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!(
        "https://localhost:{}/token",
        listener.local_addr().unwrap().port()
    );
    (listener, url)
}

async fn gateway_policy(gateway: &GatewayEndpoint, sandbox: &str) -> SandboxPolicy {
    let settings = fetch_settings_snapshot(gateway, sandbox)
        .await
        .expect("fetch gateway-composed policy over TLS");
    assert!(
        settings.configuration_admitted,
        "{}",
        settings.configuration_error
    );
    settings.policy.expect("gateway-composed provider policy")
}

fn provider_state(delivery: ProviderEnvironmentResult) -> ProviderCredentialState {
    ProviderCredentialState::from_bound_environment_with_stable_placeholders(
        delivery.provider_env_revision,
        delivery.environment,
        delivery.credential_expires_at_ms,
        delivery.dynamic_credentials,
        delivery.static_credential_bindings,
        delivery.non_secret_environment_keys,
        delivery.stable_placeholder_environment_keys,
    )
    .expect("provider installation accepted by supervisor")
}

fn profile(
    broker_url: &str,
    binary: &Path,
    auth_style: &str,
    path: &str,
    environment: &[(&str, &str)],
) -> ProviderProfile {
    ProviderProfile {
        id: "wire-grant".into(),
        display_name: "Local wire grant".into(),
        category: ProviderProfileCategory::Other as i32,
        credentials: vec![ProviderProfileCredential {
            name: CREDENTIAL.into(),
            env_vars: environment.iter().map(|(key, _)| (*key).into()).collect(),
            auth_style: auth_style.into(),
            header_name: "Authorization".into(),
            token_grant: Some(ProviderCredentialTokenGrant {
                grant_type: ProviderCredentialTokenGrantType::OpenshellClientCredentials as i32,
                token_endpoint: broker_url.into(),
                audience: RESOURCE_AUDIENCE.into(),
                scopes: vec!["wire.read".into(), "wire.inspect".into()],
                ..Default::default()
            }),
            ..Default::default()
        }],
        endpoints: vec![NetworkEndpoint {
            host: HOST.into(),
            port: u32::from(PORT),
            path: path.into(),
            protocol: "rest".into(),
            access: NetworkAccessPreset::Full as i32,
            ..Default::default()
        }],
        binaries: vec![NetworkBinary {
            path: binary.to_str().unwrap().into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Issued,
    WrongAudience,
    InvalidRequest,
    InvalidAssertion,
}

struct Broker {
    state: Arc<BrokerState>,
    _server: TlsServer,
}

struct BrokerState {
    audience: Mutex<String>,
    key_id: String,
    public_key: DecodingKey,
    outcomes: Mutex<Vec<Outcome>>,
}

impl Broker {
    async fn start(
        listener: TcpListener,
        tls: tokio_rustls::TlsAcceptor,
        audience: &str,
        gateway: &ProviderGrantGateway,
    ) -> Self {
        let jwks = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("broker discovery client")
            .get(format!("{}/.well-known/jwks.json", gateway.sandbox.url()))
            .send()
            .await
            .expect("fetch Gateway JWKS over TLS")
            .error_for_status()
            .expect("Gateway publishes verification key")
            .json::<JwkSet>()
            .await
            .expect("read Gateway JWKS");
        let [jwk] = jwks.keys.as_slice() else {
            panic!("expected one Gateway verification key");
        };
        let state = Arc::new(BrokerState {
            audience: Mutex::new(audience.into()),
            key_id: jwk.common.key_id.clone().expect("Gateway key ID"),
            public_key: DecodingKey::from_jwk(jwk).expect("Gateway verification key"),
            outcomes: Mutex::default(),
        });
        let router = Router::new()
            .fallback(token_request)
            .with_state(state.clone());
        Self {
            state,
            _server: TlsServer::start(listener, tls, router),
        }
    }

    fn assert_outcomes(&self, expected: &[Outcome]) {
        assert_eq!(*self.state.outcomes.lock().unwrap(), expected);
    }
}

struct TlsServer(JoinHandle<()>);

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl TlsServer {
    fn start(listener: TcpListener, tls: tokio_rustls::TlsAcceptor, router: Router) -> Self {
        Self(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("fixture accept");
                        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                        let tls = tls.clone();
                        let service = TowerToHyperService::new(router.clone());
                        connections.spawn(async move {
                            let stream = tls.accept(stream).await.expect("fixture TLS");
                            Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        let _ = completed.expect("fixture connection").expect("fixture task");
                    }
                }
            }
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthForm {
    grant_type: String,
    client_assertion_type: String,
    client_assertion: String,
    audience: String,
    scope: String,
}

#[derive(Deserialize)]
struct AssertionClaims {
    sub: String,
    sandbox_id: String,
    provider_id: String,
    credential_key: String,
    caller_kind: String,
}

async fn token_request(State(state): State<Arc<BrokerState>>, request: Request) -> Response {
    let outcome = state.verify(request).await;
    state.outcomes.lock().unwrap().push(outcome);
    if outcome == Outcome::Issued {
        Json(serde_json::json!({
            "access_token": ACCESS_TOKEN,
            "expires_in": 300,
            "token_type": "Bearer",
        }))
        .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response()
    }
}

impl BrokerState {
    async fn verify(&self, request: Request) -> Outcome {
        if request.method() != Method::POST
            || request.uri().path_and_query().map(|path| path.as_str()) != Some("/token")
            || request.headers().contains_key(header::AUTHORIZATION)
            || request
                .headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .is_none()
        {
            return Outcome::InvalidRequest;
        }
        let Ok(Form(form)) = Form::<OAuthForm>::from_request(request, &()).await else {
            return Outcome::InvalidRequest;
        };
        if form.grant_type != "client_credentials"
            || form.client_assertion_type != DEFAULT_CLIENT_ASSERTION_TYPE
            || form.audience != RESOURCE_AUDIENCE
            || form.scope != "wire.read wire.inspect"
        {
            return Outcome::InvalidRequest;
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0;
        validation.set_issuer(&[GATEWAY_ISSUER]);
        validation.set_audience(&[self.audience.lock().unwrap().as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        let token = match openshell_crypto::jwt::decode::<AssertionClaims>(
            &form.client_assertion,
            &self.public_key,
            &validation,
        ) {
            Ok(token) => token,
            Err(error) if error.kind() == &jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                return Outcome::WrongAudience;
            }
            Err(_) => return Outcome::InvalidAssertion,
        };
        let claims = token.claims;
        if token.header.typ.as_deref() != Some("openshell-provider-assertion+jwt")
            || token.header.kid.as_deref() != Some(self.key_id.as_str())
            || claims.sub != format!("openshell-sandbox:{SANDBOX}")
            || claims.sandbox_id != SANDBOX
            || claims.provider_id != PROVIDER_ID
            || claims.credential_key != CREDENTIAL
            || claims.caller_kind != "supervisor"
        {
            return Outcome::InvalidAssertion;
        }

        Outcome::Issued
    }
}
