// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::AtomicU32;

use axum::body::{Body, to_bytes};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openshell_core::policy::ProxyPolicy;
use tokio::process::Command as AsyncCommand;

use crate::identity::BinaryIdentityCache;
use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config};
use crate::policy_local::PolicyLocalContext;
use crate::proxy::ProxyHandle;

const ORIGIN_HOST: &str = "host.openshell.internal";
const REPOSITORY: &str = "/team/repo.git";
const RAW_HEADER: &str = "x-wire-api-key";
const CLIENT_USER: &str = "wire-repository-user";

#[test]
fn provider_client_assertion_git_placeholder_wire() {
    run_placeholder_test(
        concat!(
            module_path!(),
            "::provider_client_assertion_git_placeholder_wire"
        ),
        false,
    );
}

#[test]
fn provider_client_assertion_raw_placeholder_wire() {
    run_placeholder_test(
        concat!(
            module_path!(),
            "::provider_client_assertion_raw_placeholder_wire"
        ),
        true,
    );
}

fn run_placeholder_test(name: &str, raw: bool) {
    with_tls_fixture(name, |cert_dir| {
        run_bounded(exercise(cert_dir, raw), WAIT * 4);
    });
}

async fn exercise(cert_dir: &Path, raw: bool) {
    openshell_crypto::tls::ensure_default_provider();
    let tls = gateway_tls(cert_dir);
    let (broker_listener, broker_url) = bind_broker().await;

    let repo_root = tempfile::tempdir().unwrap();
    let server_repo = repo_root.path().join("team/repo.git");
    let (path, route, header_name, binary) = if raw {
        (
            "/v1/fixture",
            "/v1/fixture".to_string(),
            RAW_HEADER,
            std::env::current_exe().unwrap(),
        )
    } else {
        git_ok(
            repo_root.path(),
            &["init", "--bare", server_repo.to_str().unwrap()],
        )
        .await;
        let exec_path = git_ok(repo_root.path(), &["--exec-path"]).await;
        let helper = Path::new(&exec_path).join("git-remote-https");
        (
            REPOSITORY,
            format!("{REPOSITORY}/**"),
            "Authorization",
            helper.canonicalize().unwrap(),
        )
    };
    let origin = Origin::start(repo_root.path().to_path_buf(), raw).await;
    let url = format!("https://{ORIGIN_HOST}:{}{path}", origin.port);
    let mut profile = profile(&broker_url, &binary, "placeholder", &route, &[]);
    profile.endpoints[0].host = ORIGIN_HOST.into();
    profile.endpoints[0].port = origin.port.into();
    profile.credentials[0].env_vars = vec![ENV_KEY.into()];
    profile.credentials[0].header_name = header_name.into();
    let gateway =
        ProviderGrantGateway::start(tls.clone(), profile, CREDENTIAL, &broker_url, &[]).await;
    let broker = Broker::start(broker_listener, tls.acceptor(), &broker_url, &gateway).await;

    let policy = gateway_policy(&gateway.sandbox, SANDBOX).await;
    let delivery = fetch_provider_environment(&gateway.sandbox, SANDBOX)
        .await
        .unwrap();
    assert!(
        delivery.environment.is_empty(),
        "no stored or preinstalled credential"
    );
    let state = provider_state(delivery);
    let installed = state.snapshot();
    let handle = &installed.child_env[ENV_KEY];
    assert!(handle.starts_with("openshell:resolve:env:"));
    assert!(!handle.contains(ACCESS_TOKEN));
    let proxy_ca = SandboxCa::generate().unwrap();
    let proxy_ca_path = cert_dir.join("proxy-ca.pem");
    std::fs::write(&proxy_ca_path, proxy_ca.cert_pem()).unwrap();
    let proxy = start_proxy(
        gateway.sandbox.clone(),
        state.clone(),
        policy,
        proxy_ca,
        &origin.ca_pem,
    )
    .await;
    let proxy_url = format!("http://{}", proxy.http_addr().unwrap());

    broker.assert_outcomes(&[]);
    assert!(
        origin.requests().is_empty(),
        "startup must not contact the origin"
    );
    if raw {
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
            .add_root_certificate(
                reqwest::Certificate::from_pem(&std::fs::read(proxy_ca_path).unwrap()).unwrap(),
            )
            .build()
            .unwrap();
        let response = client
            .get(url)
            .header(RAW_HEADER, handle)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NO_CONTENT,
            "named header must reach the origin with one broker redemption",
        );
        broker.assert_outcomes(&[Outcome::Issued]);
        assert_eq!(origin.requests(), [(Method::GET, "/v1/fixture".into())]);
        return;
    }

    let first = publish_commit(&server_repo, "cold object").await;
    fetch_fresh(
        git_fetch(&url, &first, handle, &proxy_url, &proxy_ca_path),
        &first,
        ExpectedFetch::Present,
    )
    .await;
    let first_requests = origin.requests();
    assert_eq!(
        first_requests.first(),
        Some(&(Method::GET, format!("{REPOSITORY}/info/refs"))),
        "Git starts with service discovery",
    );
    let upload_pack = (Method::POST, format!("{REPOSITORY}/git-upload-pack"));
    assert!(!first_requests[1..].is_empty());
    assert!(
        first_requests[1..]
            .iter()
            .all(|request| *request == upload_pack)
    );
    broker.assert_outcomes(&[Outcome::Issued]);

    gateway.detach().await;
    // Install the live credential update while retaining the original route.
    // Withdrawal must take effect even if the policy refresh has yet to arrive.
    let withdrawn = fetch_provider_environment(&gateway.sandbox, SANDBOX)
        .await
        .unwrap();
    assert_ne!(withdrawn.provider_env_revision, installed.revision);
    assert!(withdrawn.dynamic_credentials.is_empty());
    state
        .install_bound_environment_with_stable_placeholders(
            withdrawn.provider_env_revision,
            withdrawn.environment,
            withdrawn.credential_expires_at_ms,
            withdrawn.dynamic_credentials,
            withdrawn.static_credential_bindings,
            withdrawn.non_secret_environment_keys,
            withdrawn.stable_placeholder_environment_keys,
        )
        .expect("install detached provider environment");
    assert!(!state.snapshot().child_env.contains_key(ENV_KEY));

    let second = publish_commit(&server_repo, "object after withdrawal").await;
    assert_ne!(first, second);
    fetch_fresh(
        git_fetch(&url, &second, handle, &proxy_url, &proxy_ca_path),
        &second,
        ExpectedFetch::Withdrawn,
    )
    .await;
    broker.assert_outcomes(&[Outcome::Issued]);
    assert_eq!(origin.requests(), first_requests);
}

async fn start_proxy(
    gateway: GatewayEndpoint,
    state: ProviderCredentialState,
    policy: SandboxPolicy,
    ca: SandboxCa,
    origin_ca: &str,
) -> ProxyHandle {
    let engine = Arc::new(OpaEngine::from_proto(&policy).expect("provider policy compiles"));
    let (_workspace_tx, workspace) = tokio::sync::watch::channel("default".into());
    let grants = SandboxInstanceTokenGrants::new(Some(gateway.clone()), Some(SANDBOX.into()), None);
    let context = PolicyLocalContext::new(
        Some(policy),
        Some(gateway),
        Some(SANDBOX.into()),
        Default::default(),
        workspace,
    )
    .with_token_grants(Arc::new(SpiffeTokenGrantResolver::new(grants)));
    let tls = ProxyTlsState::new(
        CertCache::new(ca),
        build_upstream_client_config(origin_ca).unwrap(),
    );
    let (_ready_tx, ready) = tokio::sync::watch::channel(true);
    ProxyHandle::start_with_bind_addr(
        &ProxyPolicy { http_addr: None },
        Some(([127, 0, 0, 1], 0).into()),
        engine,
        Arc::new(BinaryIdentityCache::new()),
        Arc::new(AtomicU32::new(std::process::id())),
        Some(Arc::new(tls)),
        Some(state),
        Some(Arc::new(context)),
        None,
        None,
        None,
        ready,
        &Default::default(),
        Some([127, 0, 0, 1].into()),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("start real supervisor CONNECT proxy")
}

fn git() -> AsyncCommand {
    let mut command = AsyncCommand::new("git");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true);
    command
}

async fn git_ok(directory: &Path, args: &[&str]) -> String {
    let output = git()
        .current_dir(directory)
        .args(args)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

async fn has_commit(directory: &Path, oid: &str) -> bool {
    git()
        .current_dir(directory)
        .args(["cat-file", "-e", &format!("{oid}^{{commit}}")])
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap()
        .success()
}

async fn publish_commit(repository: &Path, message: &str) -> String {
    let tree = git_ok(repository, &["mktree"]).await;
    let oid = git_ok(
        repository,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit-tree",
            &tree,
            "-m",
            message,
        ],
    )
    .await;
    git_ok(repository, &["update-ref", "refs/heads/main", &oid]).await;
    oid
}

fn git_fetch(url: &str, oid: &str, handle: &str, proxy: &str, ca: &Path) -> AsyncCommand {
    // Git supplies the normal Basic header. Scope preauthentication to this
    // repository so discovery and upload-pack both carry the opaque password.
    let basic = STANDARD.encode(format!("{CLIENT_USER}:{handle}"));
    let mut command = git();
    command
        .env("HTTPS_PROXY", proxy)
        .env("GIT_SSL_CAINFO", ca)
        .args([
            "-c",
            &format!("http.{url}.extraHeader=Authorization: Basic {basic}"),
            "fetch",
            "--no-tags",
            url,
            oid,
        ]);
    command
}

enum ExpectedFetch {
    Present,
    Withdrawn,
}

async fn fetch_fresh(mut command: AsyncCommand, oid: &str, expected: ExpectedFetch) {
    assert!(oid.len() == 40 && oid.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let client = tempfile::tempdir().unwrap();
    git_ok(client.path(), &["init"]).await;
    assert!(!has_commit(client.path(), oid).await);
    let output = command.current_dir(client.path()).output().await.unwrap();
    let expected_present = matches!(expected, ExpectedFetch::Present);
    assert_eq!(
        output.status.code(),
        Some(if expected_present { 0 } else { 128 }),
        "Git fetch: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let present = has_commit(client.path(), oid).await;
    assert_eq!(present, expected_present, "requested object presence");
    if present {
        assert_eq!(
            git_ok(client.path(), &["rev-parse", "FETCH_HEAD"]).await,
            oid
        );
    }
}

struct Origin {
    port: u16,
    ca_pem: String,
    state: Arc<OriginState>,
    _server: TlsServer,
}

struct OriginState {
    root: PathBuf,
    raw: bool,
    requests: Mutex<Vec<(Method, String)>>,
}

impl Origin {
    async fn start(root: PathBuf, raw: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ca_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = openshell_crypto::pki::self_signed(ca_params, &ca_key).unwrap();
        let leaf_key = openshell_crypto::pki::generate_keypair().unwrap();
        let leaf = openshell_crypto::pki::signed_by(
            rcgen::CertificateParams::new(vec![ORIGIN_HOST.to_string()]).unwrap(),
            &leaf_key,
            &ca,
            &ca_key,
        )
        .unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der().unwrap());
        let config = openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key.into())
            .unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let state = Arc::new(OriginState {
            root,
            raw,
            requests: Mutex::default(),
        });
        let router = Router::new()
            .fallback(origin_request)
            .with_state(state.clone());
        Self {
            port,
            ca_pem: ca.pem(),
            state,
            _server: TlsServer::start(listener, tls, router),
        }
    }

    fn requests(&self) -> Vec<(Method, String)> {
        self.state.requests.lock().unwrap().clone()
    }
}

async fn origin_request(State(state): State<Arc<OriginState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    state
        .requests
        .lock()
        .unwrap()
        .push((parts.method.clone(), parts.uri.path().into()));
    let (name, expected) = if state.raw {
        (RAW_HEADER, ACCESS_TOKEN.into())
    } else {
        (
            "authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{CLIENT_USER}:{ACCESS_TOKEN}"))
            ),
        )
    };
    if parts
        .headers
        .get_all(name)
        .iter()
        .collect::<Vec<_>>()
        .as_slice()
        != [expected.as_str()]
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if state.raw {
        return StatusCode::NO_CONTENT.into_response();
    }
    let body = to_bytes(body, 1024 * 1024).await.unwrap();
    let mut backend = git();
    backend
        .args(["http-backend"])
        .env("GIT_PROJECT_ROOT", &state.root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("PATH_INFO", parts.uri.path())
        .env("REQUEST_METHOD", parts.method.as_str())
        .env("QUERY_STRING", parts.uri.query().unwrap_or_default())
        .env("CONTENT_LENGTH", body.len().to_string())
        .env(
            "CONTENT_TYPE",
            parts
                .headers
                .get(header::CONTENT_TYPE)
                .map_or("", |h| h.to_str().unwrap()),
        )
        .env(
            "HTTP_GIT_PROTOCOL",
            parts
                .headers
                .get("git-protocol")
                .map_or("", |h| h.to_str().unwrap()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = backend.spawn().unwrap();
    child.stdin.take().unwrap().write_all(&body).await.unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(output.status.success(), "stock git http-backend");
    let end = output
        .stdout
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let mut response = Response::builder();
    for line in std::str::from_utf8(&output.stdout[..end])
        .unwrap()
        .split("\r\n")
    {
        let (key, value) = line.split_once(": ").unwrap();
        if key.eq_ignore_ascii_case("status") {
            response = response.status(value[..3].parse::<u16>().unwrap());
        } else {
            response = response.header(key, value);
        }
    }
    response
        .body(Body::from(output.stdout[end + 4..].to_vec()))
        .unwrap()
}
