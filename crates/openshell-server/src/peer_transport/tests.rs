// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::gateway_listener::BoundGatewayListener;
use crate::grpc::test_support::test_server_state;
use crate::supervisor_session::build_peer_channel;
use crate::tls_test_utils::{generate_test_certs_with_ca, write_test_file};
use crate::{MultiplexService, ServerState, TlsAcceptor};
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{HealthRequest, ServiceStatus};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tonic::Code;
use tonic::transport::Channel;

/// Mirrors the chart's `OPENSHELL_PEER_TLS_SERVER_NAME`.
const PEER_SERVER_NAME: &str = "openshell.openshell.svc.cluster.local";

/// A peer CA with a server certificate whose only SAN is the Service name and
/// a client certificate, plus a rogue CA with its own pair.
struct Pki {
    _dir: TempDir,
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
    rogue_ca: PathBuf,
    rogue_server_cert: PathBuf,
    rogue_server_key: PathBuf,
    rogue_client_cert: PathBuf,
    rogue_client_key: PathBuf,
}

impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let trusted = dir.path().join("trusted");
        let rogue = dir.path().join("rogue");
        std::fs::create_dir(&trusted).expect("failed to create pki dir");
        std::fs::create_dir(&rogue).expect("failed to create pki dir");
        let trusted_ca = generate_test_certs_with_ca(&trusted);
        let untrusted_ca = rogue_ca(&rogue);
        for (path, (ca_cert, ca_key)) in [(&trusted, trusted_ca), (&rogue, untrusted_ca)] {
            sign_leaf(&ca_cert, &ca_key, path, "peer", &[PEER_SERVER_NAME]);
            sign_leaf(&ca_cert, &ca_key, path, "client", &[]);
        }
        Self {
            ca: trusted.join("ca.pem"),
            server_cert: trusted.join("peer-cert.pem"),
            server_key: trusted.join("peer-key.pem"),
            client_cert: trusted.join("client-cert.pem"),
            client_key: trusted.join("client-key.pem"),
            rogue_ca: rogue.join("ca.pem"),
            rogue_server_cert: rogue.join("peer-cert.pem"),
            rogue_server_key: rogue.join("peer-key.pem"),
            rogue_client_cert: rogue.join("client-cert.pem"),
            rogue_client_key: rogue.join("client-key.pem"),
            _dir: dir,
        }
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let dir = self.ca.parent().expect("pki dir");
        write_test_file(dir, name, contents);
        dir.join(name)
    }
}

/// An unrelated CA written to `ca.pem`. Its own name matters: a CA that
/// reused the trusted CA's name would be tried as the issuer and fail with
/// `BadSignature` rather than `UnknownIssuer`.
fn rogue_ca(dir: &Path) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("failed to create params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "rogue-ca");
    let key = KeyPair::generate().expect("failed to generate key");
    let cert = params.self_signed(&key).expect("failed to sign rogue CA");
    write_test_file(dir, "ca.pem", cert.pem().as_bytes());
    (cert, key)
}

/// Writes `<name>-cert.pem` and `<name>-key.pem` signed by the given CA.
fn sign_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    dir: &Path,
    name: &str,
    sans: &[&str],
) {
    sign_leaf_with(ca_cert, ca_key, dir, name, sans, |_| {});
}

/// `sign_leaf` with a hook to adjust the parameters, e.g. the validity window.
fn sign_leaf_with(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    dir: &Path,
    name: &str,
    sans: &[&str],
    customize: impl FnOnce(&mut CertificateParams),
) {
    let mut params = CertificateParams::new(
        sans.iter()
            .map(|san| (*san).to_string())
            .collect::<Vec<_>>(),
    )
    .expect("failed to create cert params");
    params.distinguished_name.push(DnType::CommonName, name);
    customize(&mut params);
    let key = KeyPair::generate().expect("failed to generate key");
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .expect("failed to sign cert");
    write_test_file(dir, &format!("{name}-cert.pem"), cert.pem().as_bytes());
    write_test_file(
        dir,
        &format!("{name}-key.pem"),
        key.serialize_pem().as_bytes(),
    );
}

fn server_tls(cert: &Path, key: &Path) -> TlsConfig {
    TlsConfig {
        cert_path: cert.to_path_buf(),
        key_path: key.to_path_buf(),
        client_ca_path: None,
        require_client_auth: false,
        external_cert_path: None,
        external_key_path: None,
        external_server_names: Vec::new(),
    }
}

fn tls_client(
    ca: Option<&Path>,
    server_name: Option<&str>,
    identity: Option<(&Path, &Path)>,
) -> PeerTlsClientConfig {
    PeerTlsClientConfig {
        ca_file: ca.map(Path::to_path_buf),
        cert_file: identity.map(|(cert, _)| cert.to_path_buf()),
        key_file: identity.map(|(_, key)| key.to_path_buf()),
        server_name: server_name.map(str::to_string),
    }
}

fn policy(
    ca: &Path,
    server_name: Option<&str>,
    identity: Option<(&Path, &Path)>,
) -> PeerTransportPolicy {
    PeerTransportPolicy::new(false, tls_client(Some(ca), server_name, identity))
}

fn plaintext_policy() -> PeerTransportPolicy {
    PeerTransportPolicy::new(true, PeerTlsClientConfig::default())
}

/// Serves the full gateway over TLS on `127.0.0.1:0`, like a peer replica.
/// Dropping the returned sender stops the listener.
async fn spawn_tls_gateway(
    state: Arc<ServerState>,
    pki: &Pki,
    require_client_auth: bool,
) -> (SocketAddr, watch::Sender<bool>) {
    let acceptor = TlsAcceptor::from_files(
        &pki.server_cert,
        &pki.server_key,
        Some(&pki.ca),
        require_client_auth,
        None,
        None,
        Vec::new(),
    )
    .expect("failed to build tls acceptor");
    serve_tls_gateway(state, acceptor).await
}

/// Serves the full gateway with `acceptor` on `127.0.0.1:0`. Dropping the
/// returned sender stops the listener.
async fn serve_tls_gateway(
    state: Arc<ServerState>,
    acceptor: TlsAcceptor,
) -> (SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test listener");
    let address = listener.local_addr().expect("failed to read local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(crate::serve_gateway_listener(
        BoundGatewayListener { listener, address },
        MultiplexService::new(state),
        Some(acceptor),
        false,
        shutdown_rx,
    ));
    (address, shutdown_tx)
}

fn closed_local_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind probe listener")
        .local_addr()
        .expect("failed to read probe addr")
        .port()
}

async fn health(channel: Channel) -> std::result::Result<i32, Status> {
    OpenShellClient::new(channel)
        .health(HealthRequest {})
        .await
        .map(|response| response.into_inner().status)
}

// ---- dial rule --------------------------------------------------------------

#[test]
fn dial_rule_accepts_https_endpoints() {
    let policy = PeerTransportPolicy::default();
    for endpoint in [
        "https://10.0.0.5:8080",
        "HTTPS://gw.ns.svc:8080",
        "https://[fd00::1]:8080",
    ] {
        assert_eq!(
            policy.check_dial(endpoint).unwrap(),
            PeerDialScheme::Https,
            "{endpoint}"
        );
    }
}

#[test]
fn dial_rule_refuses_plaintext_without_opt_out() {
    let err = PeerTransportPolicy::default()
        .check_dial("http://10.0.0.5:8080")
        .expect_err("plaintext peers need the opt-out");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().starts_with("gateway peer transport refused"),
        "{}",
        err.message()
    );
    assert!(err.message().contains(PEER_ALLOW_INSECURE_TRANSPORT_ENV));
    assert!(
        !err.message().contains("10.0.0.5"),
        "dial refusals must not name the endpoint: {}",
        err.message()
    );
}

#[test]
fn dial_rule_allows_plaintext_with_opt_out() {
    let policy = plaintext_policy();
    for endpoint in ["http://10.0.0.5:8080", "HTTP://10.0.0.5:8080"] {
        assert_eq!(
            policy.check_dial(endpoint).unwrap(),
            PeerDialScheme::Http,
            "{endpoint}"
        );
    }
}

const LOOPBACK_PLAINTEXT_ENDPOINTS: [&str; 4] = [
    "http://127.0.0.1:1",
    "http://127.10.0.1:1",
    "http://[::1]:1",
    "http://[::ffff:127.0.0.1]:1",
];

#[test]
fn dial_rule_refuses_numeric_loopback_plaintext_in_production() {
    let policy = PeerTransportPolicy::default();
    for endpoint in LOOPBACK_PLAINTEXT_ENDPOINTS {
        let err = policy
            .check_dial_with(endpoint, false)
            .expect_err("production has no loopback plaintext exception");
        assert_eq!(err.code(), Code::FailedPrecondition, "{endpoint}");
    }
}

#[test]
fn dial_rule_allows_numeric_loopback_plaintext_in_test_builds() {
    let policy = PeerTransportPolicy::default();
    for endpoint in LOOPBACK_PLAINTEXT_ENDPOINTS {
        assert_eq!(
            policy.check_dial_with(endpoint, true).unwrap(),
            PeerDialScheme::Http,
            "{endpoint}"
        );
        assert_eq!(
            policy.check_dial(endpoint).unwrap(),
            PeerDialScheme::Http,
            "{endpoint}"
        );
    }
}

#[test]
fn dial_rule_refuses_localhost_hostname_plaintext() {
    let err = PeerTransportPolicy::default()
        .check_dial_with("http://localhost:1", true)
        .expect_err("only numeric loopback is admitted in test builds");
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[test]
fn dial_rule_refuses_non_http_schemes_even_with_opt_out() {
    for policy in [PeerTransportPolicy::default(), plaintext_policy()] {
        for endpoint in [
            "unix:///tmp/p.sock",
            "unix:/tmp/p.sock",
            "UNIX:///tmp/p.sock",
            "local://replica-a",
            "grpc://10.0.0.1:1",
            "10.0.0.1:8080",
            "https://",
            "",
            "   ",
        ] {
            let err = policy
                .check_dial(endpoint)
                .expect_err("only https and http are dialable");
            assert_eq!(err.code(), Code::FailedPrecondition, "{endpoint:?}");
            assert!(
                err.message().starts_with("gateway peer transport refused"),
                "{endpoint:?}: {}",
                err.message()
            );
        }
    }
}

// ---- opt-out ----------------------------------------------------------------

fn resolve_opt_out(raw: Option<&str>, gateway_serves_tls: bool) -> Result<InsecureOptOut> {
    PeerTransportPolicy::resolve(raw, gateway_serves_tls, PeerTlsClientConfig::default())
        .map(|(_, outcome)| outcome)
}

#[test]
fn opt_out_parses_bool_like_values() {
    for raw in [None, Some("")] {
        assert_eq!(resolve_opt_out(raw, false).unwrap(), InsecureOptOut::Off);
    }
    for raw in ["true", "1", "yes", "on", " TRUE "] {
        assert_eq!(
            resolve_opt_out(Some(raw), false).unwrap(),
            InsecureOptOut::Active,
            "{raw:?}"
        );
    }
    for raw in ["false", "0", "off"] {
        assert_eq!(
            resolve_opt_out(Some(raw), false).unwrap(),
            InsecureOptOut::Off,
            "{raw:?}"
        );
    }
    let err = resolve_opt_out(Some("maybe"), false).expect_err("typos must fail startup");
    assert!(
        err.to_string().contains(PEER_ALLOW_INSECURE_TRANSPORT_ENV),
        "{err}"
    );
}

#[test]
fn opt_out_is_ignored_on_a_tls_gateway() {
    let (policy, outcome) =
        PeerTransportPolicy::resolve(Some("true"), true, PeerTlsClientConfig::default()).unwrap();
    assert!(!policy.allows_plaintext());
    assert_eq!(outcome, InsecureOptOut::IgnoredOnTlsGateway);
}

#[test]
fn opt_out_is_honored_on_a_plaintext_gateway() {
    let (policy, outcome) =
        PeerTransportPolicy::resolve(Some("true"), false, PeerTlsClientConfig::default()).unwrap();
    assert!(policy.allows_plaintext());
    assert_eq!(outcome, InsecureOptOut::Active);
}

// ---- startup ----------------------------------------------------------------

#[test]
fn startup_rejects_plaintext_own_endpoint_without_opt_out() {
    let policy = PeerTransportPolicy::default();
    for endpoint in ["http://10.0.0.1:8080", "http://127.0.0.1:8080"] {
        let err = policy
            .validate_own_endpoint(endpoint, None)
            .expect_err("plaintext own endpoint needs the opt-out")
            .to_string();
        assert!(err.contains("plaintext"), "{err}");
        assert!(err.contains(PEER_ALLOW_INSECURE_TRANSPORT_ENV), "{err}");
    }
}

#[test]
fn startup_accepts_plaintext_own_endpoint_with_opt_out() {
    plaintext_policy()
        .validate_own_endpoint("http://10.0.0.1:8080", None)
        .unwrap();
}

#[test]
fn startup_rejects_undialable_own_endpoints() {
    for policy in [PeerTransportPolicy::default(), plaintext_policy()] {
        for endpoint in ["local://x", "unix:///x", "grpc://x:1"] {
            let err = policy
                .validate_own_endpoint(endpoint, None)
                .expect_err("peers cannot dial this endpoint")
                .to_string();
            assert!(err.contains("is not dialable by peers"), "{err}");
        }
    }
}

#[test]
fn startup_requires_ca_for_https_own_endpoint() {
    let err = PeerTransportPolicy::default()
        .validate_own_endpoint("https://10.0.0.1:8080", None)
        .expect_err("https peers need an explicit CA")
        .to_string();
    assert!(err.contains("OPENSHELL_PEER_TLS_CA_FILE"), "{err}");
}

#[test]
fn startup_rejects_unusable_ca_files() {
    let pki = Pki::new();
    let missing = pki.ca.with_file_name("missing.pem");
    let empty = pki.write("empty.pem", b"");
    let not_pem = pki.write("not-pem.pem", b"test-ca");
    let garbage_der = pki.write(
        "garbage-der.pem",
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    );
    for ca in [&missing, &empty, &not_pem, &garbage_der] {
        let err = policy(ca, Some(PEER_SERVER_NAME), None)
            .validate_own_endpoint("https://10.0.0.1:8080", None)
            .expect_err("an unusable CA must fail startup")
            .to_string();
        assert!(err.contains("gateway peer TLS CA"), "{err}");
    }
}

#[test]
fn startup_accepts_valid_ca_identity_and_server_name() {
    let pki = Pki::new();
    policy(
        &pki.ca,
        Some(PEER_SERVER_NAME),
        Some((&pki.client_cert, &pki.client_key)),
    )
    .validate_own_endpoint("https://10.0.0.1:8080", None)
    .unwrap();
}

#[test]
fn startup_rejects_half_configured_identity() {
    let pki = Pki::new();
    for (cert, key) in [
        (Some(&pki.client_cert), None),
        (None, Some(&pki.client_key)),
    ] {
        let config = PeerTlsClientConfig {
            ca_file: Some(pki.ca.clone()),
            cert_file: cert.cloned(),
            key_file: key.cloned(),
            server_name: None,
        };
        let err = PeerTransportPolicy::new(false, config)
            .validate_own_endpoint("https://gw.openshell.svc:8080", None)
            .expect_err("a half-configured identity must fail startup")
            .to_string();
        assert!(err.contains("OPENSHELL_PEER_TLS_CERT_FILE"), "{err}");
        assert!(err.contains("OPENSHELL_PEER_TLS_KEY_FILE"), "{err}");
    }
}

#[test]
fn startup_rejects_unparseable_identity() {
    let pki = Pki::new();
    let garbage = pki.write("garbage.pem", b"not pem");
    for (cert, key) in [(&garbage, &pki.client_key), (&pki.client_cert, &garbage)] {
        let err = policy(&pki.ca, None, Some((cert, key)))
            .validate_own_endpoint("https://gw.openshell.svc:8080", None)
            .expect_err("an unparseable identity must fail startup")
            .to_string();
        assert!(err.contains("gateway peer TLS client identity"), "{err}");
    }
}

#[test]
fn startup_rejects_mismatched_identity() {
    let pki = Pki::new();
    let err = policy(
        &pki.ca,
        None,
        Some((&pki.client_cert, &pki.rogue_client_key)),
    )
    .validate_own_endpoint("https://gw.openshell.svc:8080", None)
    .expect_err("a certificate and key from different pairs must fail startup")
    .to_string();
    assert!(err.contains("do not match"), "{err}");
}

#[test]
fn startup_rejects_invalid_server_name() {
    let pki = Pki::new();
    let err = policy(&pki.ca, Some("not a name!"), None)
        .validate_own_endpoint("https://gw.openshell.svc:8080", None)
        .expect_err("an invalid server name must fail startup")
        .to_string();
    assert!(err.contains("OPENSHELL_PEER_TLS_SERVER_NAME"), "{err}");
}

#[test]
fn startup_validates_configured_tls_materials_for_plaintext_peers() {
    let pki = Pki::new();
    let garbage = pki.write("garbage-ca.pem", b"not pem");
    let err = PeerTransportPolicy::new(true, tls_client(Some(&garbage), None, None))
        .validate_own_endpoint("http://10.0.0.1:8080", None)
        .expect_err("configured peer TLS materials must be usable")
        .to_string();
    assert!(err.contains("gateway peer TLS CA"), "{err}");
}

#[test]
fn startup_rejects_server_certificate_from_another_ca() {
    let pki = Pki::new();
    let err = policy(&pki.ca, Some(PEER_SERVER_NAME), None)
        .validate_own_endpoint(
            "https://10.0.0.5:8080",
            Some(&server_tls(&pki.rogue_server_cert, &pki.rogue_server_key)),
        )
        .expect_err("a server certificate from another CA must fail startup")
        .to_string();
    assert!(err.contains("would fail peer verification"), "{err}");
}

#[test]
fn startup_rejects_server_certificate_without_peer_server_name() {
    let pki = Pki::new();
    let err = policy(&pki.ca, Some("other.openshell.svc.cluster.local"), None)
        .validate_own_endpoint(
            "https://10.0.0.5:8080",
            Some(&server_tls(&pki.server_cert, &pki.server_key)),
        )
        .expect_err("a server certificate without the peer name must fail startup")
        .to_string();
    assert!(err.contains("would fail peer verification"), "{err}");
}

#[test]
fn startup_accepts_server_certificate_matching_peer_contract() {
    let pki = Pki::new();
    policy(&pki.ca, Some(PEER_SERVER_NAME), None)
        .validate_own_endpoint(
            "https://10.0.0.5:8080",
            Some(&server_tls(&pki.server_cert, &pki.server_key)),
        )
        .unwrap();
}

/// SNI selects the external certificate when the peer name is one of its
/// names, so that is the certificate peers must be able to verify.
#[test]
fn startup_verifies_the_certificate_peer_sni_selects() {
    let pki = Pki::new();
    let with_external = |names: &[&str]| TlsConfig {
        external_cert_path: Some(pki.rogue_server_cert.clone()),
        external_key_path: Some(pki.rogue_server_key.clone()),
        external_server_names: names.iter().map(|name| (*name).to_string()).collect(),
        ..server_tls(&pki.server_cert, &pki.server_key)
    };
    let peer_policy = policy(&pki.ca, Some(PEER_SERVER_NAME), None);

    for names in [&[PEER_SERVER_NAME][..], &["*.openshell.svc.cluster.local"]] {
        let err = peer_policy
            .validate_own_endpoint("https://10.0.0.5:8080", Some(&with_external(names)))
            .expect_err("peers would receive the external certificate from another CA")
            .to_string();
        assert!(err.contains("would fail peer verification"), "{err}");
        assert!(err.contains("external_server_names"), "{err}");
        assert!(
            err.contains(&pki.rogue_server_cert.display().to_string()),
            "{err}"
        );
    }
    peer_policy
        .validate_own_endpoint(
            "https://10.0.0.5:8080",
            Some(&with_external(&["gateway.example.com"])),
        )
        .unwrap();
}

/// The external name in the dual-certificate tests.
const EXTERNAL_NAME: &str = "gateway.example.test";

/// A server TLS config with an internal certificate for `internal_san`,
/// signed by the peer CA, and an external certificate for `EXTERNAL_NAME`
/// that SNI selects, signed by the peer CA or by an unrelated CA.
struct DualCertPki {
    _dir: TempDir,
    ca: PathBuf,
    server_tls: TlsConfig,
}

impl DualCertPki {
    fn new(internal_san: &str, external_trusted: bool) -> Self {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let trusted = dir.path().join("trusted");
        let rogue = dir.path().join("rogue");
        std::fs::create_dir(&trusted).expect("failed to create pki dir");
        std::fs::create_dir(&rogue).expect("failed to create pki dir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(&trusted);
        sign_leaf(&ca_cert, &ca_key, &trusted, "internal", &[internal_san]);
        let external_dir = if external_trusted {
            sign_leaf(&ca_cert, &ca_key, &trusted, "external", &[EXTERNAL_NAME]);
            trusted.clone()
        } else {
            let (rogue_cert, rogue_key) = rogue_ca(&rogue);
            sign_leaf(
                &rogue_cert,
                &rogue_key,
                &rogue,
                "external",
                &[EXTERNAL_NAME],
            );
            rogue
        };
        Self {
            ca: trusted.join("ca.pem"),
            server_tls: TlsConfig {
                external_cert_path: Some(external_dir.join("external-cert.pem")),
                external_key_path: Some(external_dir.join("external-key.pem")),
                external_server_names: vec![EXTERNAL_NAME.to_string()],
                ..server_tls(
                    &trusted.join("internal-cert.pem"),
                    &trusted.join("internal-key.pem"),
                )
            },
            _dir: dir,
        }
    }

    /// Serves the gateway with the production dual-certificate resolver.
    async fn serve(&self) -> (SocketAddr, watch::Sender<bool>) {
        let tls = &self.server_tls;
        let acceptor = TlsAcceptor::from_files(
            &tls.cert_path,
            &tls.key_path,
            tls.client_ca_path.as_deref(),
            tls.require_client_auth,
            tls.external_cert_path.as_deref(),
            tls.external_key_path.as_deref(),
            tls.external_server_names.clone(),
        )
        .expect("failed to build dual-certificate tls acceptor");
        serve_tls_gateway(test_server_state().await, acceptor).await
    }
}

#[tokio::test]
async fn startup_and_handshake_select_the_external_certificate_for_dotted_names() {
    // Only the external certificate is valid for the peer name. rustls strips
    // a trailing dot before sending SNI, so both spellings get it, for exact
    // and wildcard external names alike.
    for pattern in [EXTERNAL_NAME, "*.example.test"] {
        let mut pki = DualCertPki::new("internal.example.test", true);
        pki.server_tls.external_server_names = vec![pattern.to_string()];
        let (address, _shutdown) = pki.serve().await;
        for peer_name in [EXTERNAL_NAME, "gateway.example.test."] {
            let peer_policy = policy(&pki.ca, Some(peer_name), None);
            peer_policy
                .validate_own_endpoint("https://10.0.0.5:8080", Some(&pki.server_tls))
                .unwrap_or_else(|err| panic!("{pattern} / {peer_name}: {err}"));
            let channel = build_peer_channel(
                &format!("https://127.0.0.1:{}", address.port()),
                &peer_policy,
            )
            .await
            .unwrap_or_else(|err| panic!("{pattern} / {peer_name}: {err}"));
            assert_eq!(
                health(channel).await.unwrap(),
                i32::from(ServiceStatus::Healthy),
                "{pattern} / {peer_name}"
            );
        }
    }
}

#[tokio::test]
async fn startup_rejects_an_untrusted_external_certificate_for_dotted_names() {
    // The internal certificate would pass for the peer name, but SNI selects
    // the external certificate, which peers cannot verify.
    let pki = DualCertPki::new(EXTERNAL_NAME, false);
    let (address, _shutdown) = pki.serve().await;
    for peer_name in [EXTERNAL_NAME, "gateway.example.test."] {
        let peer_policy = policy(&pki.ca, Some(peer_name), None);
        let err = peer_policy
            .validate_own_endpoint("https://10.0.0.5:8080", Some(&pki.server_tls))
            .expect_err("peers receive the untrusted external certificate")
            .to_string();
        assert!(
            err.contains("would fail peer verification"),
            "{peer_name}: {err}"
        );
        assert!(err.contains("external_server_names"), "{peer_name}: {err}");
        let err = build_peer_channel(
            &format!("https://127.0.0.1:{}", address.port()),
            &peer_policy,
        )
        .await
        .expect_err("the handshake fails on the external certificate");
        assert!(
            err.message().contains("UnknownIssuer"),
            "{peer_name}: {}",
            err.message()
        );
    }
}

#[test]
fn startup_requires_client_identity_when_the_listener_requires_client_certificates() {
    let pki = Pki::new();
    let listener = |require_client_auth: bool| TlsConfig {
        client_ca_path: Some(pki.ca.clone()),
        require_client_auth,
        ..server_tls(&pki.server_cert, &pki.server_key)
    };

    let err = policy(&pki.ca, Some(PEER_SERVER_NAME), None)
        .validate_own_endpoint("https://10.0.0.5:8080", Some(&listener(true)))
        .expect_err("peers without a client identity fail the handshake")
        .to_string();
    assert!(err.contains("requires client certificates"), "{err}");
    assert!(err.contains("OPENSHELL_PEER_TLS_CERT_FILE"), "{err}");

    policy(
        &pki.ca,
        Some(PEER_SERVER_NAME),
        Some((&pki.client_cert, &pki.client_key)),
    )
    .validate_own_endpoint("https://10.0.0.5:8080", Some(&listener(true)))
    .unwrap();
    // The gateway's own listener only requests client certificates.
    policy(&pki.ca, Some(PEER_SERVER_NAME), None)
        .validate_own_endpoint("https://10.0.0.5:8080", Some(&listener(false)))
        .unwrap();
}

#[test]
fn bare_ipv6_endpoint_hosts_are_bracketed() {
    for (raw, want) in [
        (
            "https://fd00:10:244::5:8080",
            "https://[fd00:10:244::5]:8080",
        ),
        ("http://fd00::5:8080", "http://[fd00::5]:8080"),
        ("https://fd00::5:8080/x", "https://[fd00::5]:8080/x"),
    ] {
        assert_eq!(bracket_ipv6_endpoint_host(raw), want);
    }
    for unchanged in [
        "https://[fd00::5]:8080",
        "https://10.0.0.5:8080",
        "https://gw.openshell.svc:8080",
        "https://fd00::5",
        "unix:///run/openshell.sock",
        "",
    ] {
        assert_eq!(bracket_ipv6_endpoint_host(unchanged), unchanged);
    }
}

/// The chart's Deployment endpoint for an IPv6 pod IP is valid once bracketed.
#[test]
fn startup_accepts_bracketed_ipv6_pod_ip_endpoints() {
    let pki = Pki::new();
    let raw = "https://fd00:10:244::5:8080";
    let err = policy(&pki.ca, Some(PEER_SERVER_NAME), None)
        .validate_own_endpoint(raw, None)
        .expect_err("an unbracketed IPv6 authority is not a URI")
        .to_string();
    assert!(err.contains("is not dialable by peers"), "{err}");
    policy(&pki.ca, Some(PEER_SERVER_NAME), None)
        .validate_own_endpoint(&bracket_ipv6_endpoint_host(raw), None)
        .unwrap();
    plaintext_policy()
        .validate_own_endpoint(&bracket_ipv6_endpoint_host("http://fd00::5:8080"), None)
        .unwrap();
}

/// Custom Secrets may carry an intermediate in `tls.crt`; the startup check
/// must accept exactly what the peer handshake accepts.
#[test]
fn startup_accepts_server_certificate_with_intermediate_chain() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let (root_cert, root_key) = generate_test_certs_with_ca(dir.path());
    let mut intermediate_params =
        CertificateParams::new(Vec::<String>::new()).expect("failed to create params");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "test-intermediate");
    let intermediate_key = KeyPair::generate().expect("failed to generate key");
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root_cert, &root_key)
        .expect("failed to sign intermediate");
    sign_leaf(
        &intermediate_cert,
        &intermediate_key,
        dir.path(),
        "leaf",
        &[PEER_SERVER_NAME],
    );
    let leaf_cert = dir.path().join("leaf-cert.pem");
    let leaf_key = dir.path().join("leaf-key.pem");
    let leaf_pem = std::fs::read_to_string(&leaf_cert).unwrap();
    write_test_file(
        dir.path(),
        "chain.pem",
        format!("{leaf_pem}{}", intermediate_cert.pem()).as_bytes(),
    );
    let peer_policy = policy(&dir.path().join("ca.pem"), Some(PEER_SERVER_NAME), None);

    peer_policy
        .validate_own_endpoint(
            "https://10.0.0.5:8080",
            Some(&server_tls(&dir.path().join("chain.pem"), &leaf_key)),
        )
        .unwrap();
    // Without the intermediate the chain does not reach the CA, for peers too.
    let err = peer_policy
        .validate_own_endpoint(
            "https://10.0.0.5:8080",
            Some(&server_tls(&leaf_cert, &leaf_key)),
        )
        .expect_err("a leaf without its intermediate does not chain to the CA")
        .to_string();
    assert!(err.contains("would fail peer verification"), "{err}");
}

/// webpki checks the validity window before the issuer and the name, so a
/// certificate outside its window must still chain to the CA and carry the
/// peer name; only the window itself is downgraded to a warning.
#[test]
fn startup_checks_chain_and_name_outside_validity_window() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let trusted = dir.path().join("trusted");
    let rogue = dir.path().join("rogue");
    std::fs::create_dir(&trusted).expect("failed to create pki dir");
    std::fs::create_dir(&rogue).expect("failed to create pki dir");
    let (ca_cert, ca_key) = generate_test_certs_with_ca(&trusted);
    let (rogue_cert, rogue_key) = rogue_ca(&rogue);
    let peer_policy = policy(&trusted.join("ca.pem"), Some(PEER_SERVER_NAME), None);

    for (window, not_before, not_after) in [
        ("expired", (2000, 1, 1), (2001, 1, 1)),
        ("not-yet-valid", (2999, 1, 1), (3000, 1, 1)),
    ] {
        let validity = |params: &mut CertificateParams| {
            params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
            params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        };
        sign_leaf_with(
            &ca_cert,
            &ca_key,
            &trusted,
            window,
            &[PEER_SERVER_NAME],
            validity,
        );
        sign_leaf_with(
            &rogue_cert,
            &rogue_key,
            &rogue,
            window,
            &[PEER_SERVER_NAME],
            validity,
        );
        let wrong_name = format!("{window}-wrong-name");
        sign_leaf_with(
            &ca_cert,
            &ca_key,
            &trusted,
            &wrong_name,
            &["other.openshell.svc.cluster.local"],
            validity,
        );
        let leaf = |dir: &Path, name: &str| {
            server_tls(
                &dir.join(format!("{name}-cert.pem")),
                &dir.join(format!("{name}-key.pem")),
            )
        };

        peer_policy
            .validate_own_endpoint("https://10.0.0.5:8080", Some(&leaf(&trusted, window)))
            .unwrap_or_else(|err| panic!("{window}: only the window is wrong: {err}"));
        for (case, server) in [
            ("rogue CA", leaf(&rogue, window)),
            ("wrong name", leaf(&trusted, &wrong_name)),
        ] {
            let err = peer_policy
                .validate_own_endpoint("https://10.0.0.5:8080", Some(&server))
                .expect_err("the chain and name are checked inside the window")
                .to_string();
            assert!(
                err.contains("would fail peer verification"),
                "{window} {case}: {err}"
            );
        }
    }
}

#[test]
fn validity_window_errors_are_not_fatal() {
    let invalid = rustls::Error::InvalidCertificate;
    assert!(is_validity_window_error(&invalid(
        CertificateError::Expired
    )));
    assert!(is_validity_window_error(&invalid(
        CertificateError::NotValidYet
    )));
    let (earlier, later) = (
        UnixTime::since_unix_epoch(Duration::from_secs(1)),
        UnixTime::since_unix_epoch(Duration::from_secs(2)),
    );
    // What rustls actually reports for webpki's expired and not-yet-valid.
    assert!(is_validity_window_error(&invalid(
        CertificateError::ExpiredContext {
            time: later,
            not_after: earlier,
        }
    )));
    assert!(is_validity_window_error(&invalid(
        CertificateError::NotValidYetContext {
            time: earlier,
            not_before: later,
        }
    )));
    assert!(!is_validity_window_error(&invalid(
        CertificateError::UnknownIssuer
    )));
    assert!(!is_validity_window_error(&invalid(
        CertificateError::NotValidForName
    )));
}

#[test]
fn startup_errors_link_peer_transport_docs() {
    let err = PeerTransportPolicy::default()
        .validate_own_endpoint("http://10.0.0.1:8080", None)
        .expect_err("plaintext own endpoint needs the opt-out")
        .to_string();
    assert!(err.ends_with(PEER_TRANSPORT_DOCS_URL), "{err}");
}

// ---- TLS dialer -------------------------------------------------------------

#[tokio::test]
async fn https_dial_without_ca_fails_closed_before_connecting() {
    let endpoint = format!("https://127.0.0.1:{}", closed_local_port());
    let err = build_peer_channel(&endpoint, &PeerTransportPolicy::default())
        .await
        .expect_err("https without a peer CA must not dial");
    // An attempted connect to the closed port would report `Unavailable`.
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("OPENSHELL_PEER_TLS_CA_FILE"),
        "{}",
        err.message()
    );
}

#[tokio::test]
async fn plaintext_dial_is_refused_before_connecting() {
    let err = tokio::time::timeout(
        Duration::from_secs(1),
        build_peer_channel("http://10.255.255.1:9", &PeerTransportPolicy::default()),
    )
    .await
    .expect("the refusal must not wait for the connect timeout")
    .expect_err("plaintext peers need the opt-out");
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn opt_out_does_not_downgrade_https_endpoints() {
    let endpoint = format!("https://127.0.0.1:{}", closed_local_port());
    let err = build_peer_channel(&endpoint, &plaintext_policy())
        .await
        .expect_err("the opt-out must not relax https peers");
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn https_dial_succeeds_with_ca_and_server_name_override() {
    let pki = Pki::new();
    let (address, _shutdown) = spawn_tls_gateway(test_server_state().await, &pki, false).await;
    let channel = build_peer_channel(
        &format!("https://127.0.0.1:{}", address.port()),
        &policy(&pki.ca, Some(PEER_SERVER_NAME), None),
    )
    .await
    .expect("the peer CA and server name override should verify the peer");
    assert_eq!(
        health(channel).await.unwrap(),
        i32::from(ServiceStatus::Healthy)
    );
}

#[tokio::test]
async fn https_dial_without_server_name_verifies_endpoint_ip() {
    let pki = Pki::new();
    let (address, _shutdown) = spawn_tls_gateway(test_server_state().await, &pki, false).await;
    let err = build_peer_channel(
        &format!("https://127.0.0.1:{}", address.port()),
        &policy(&pki.ca, None, None),
    )
    .await
    .expect_err("the certificate carries no IP SAN");
    assert_eq!(err.code(), Code::Unavailable);
    assert!(
        err.message().contains("not valid for name"),
        "{}",
        err.message()
    );
}

/// tonic keeps the IPv6 brackets in the verified host unless the dialer
/// strips them, which fails every dial as an invalid DNS name.
#[tokio::test]
async fn https_dial_without_server_name_accepts_ipv6_endpoint() {
    let pki = Pki::new();
    let endpoint = format!("https://[::1]:{}", closed_local_port());
    let err = build_peer_channel(&endpoint, &policy(&pki.ca, None, None))
        .await
        .expect_err("nothing listens on the probed port");
    // The TLS config is accepted, so only the connect itself fails.
    assert_eq!(err.code(), Code::Unavailable, "{}", err.message());
}

/// The startup check verifies an IPv6 endpoint against the bare address,
/// which is what the dialer verifies too.
#[test]
fn startup_verifies_ipv6_endpoint_against_bare_address() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
    sign_leaf(&ca_cert, &ca_key, dir.path(), "ipv6", &["::1"]);
    let peer_policy = policy(&dir.path().join("ca.pem"), None, None);

    peer_policy
        .validate_own_endpoint(
            "https://[::1]:8080",
            Some(&server_tls(
                &dir.path().join("ipv6-cert.pem"),
                &dir.path().join("ipv6-key.pem"),
            )),
        )
        .unwrap();
    let pki = Pki::new();
    let err = policy(&pki.ca, None, None)
        .validate_own_endpoint(
            "https://[::1]:8080",
            Some(&server_tls(&pki.server_cert, &pki.server_key)),
        )
        .expect_err("the certificate carries no IP SAN")
        .to_string();
    assert!(err.contains("peer name \"::1\""), "{err}");
}

#[tokio::test]
async fn https_dial_rejects_wrong_server_name() {
    let pki = Pki::new();
    let (address, _shutdown) = spawn_tls_gateway(test_server_state().await, &pki, false).await;
    let err = build_peer_channel(
        &format!("https://127.0.0.1:{}", address.port()),
        &policy(&pki.ca, Some("other.openshell.svc.cluster.local"), None),
    )
    .await
    .expect_err("the certificate is not valid for another name");
    assert_eq!(err.code(), Code::Unavailable);
    assert!(
        err.message().contains("not valid for name"),
        "{}",
        err.message()
    );
}

#[tokio::test]
async fn https_dial_rejects_rogue_ca() {
    let pki = Pki::new();
    let (address, _shutdown) = spawn_tls_gateway(test_server_state().await, &pki, false).await;
    let err = build_peer_channel(
        &format!("https://127.0.0.1:{}", address.port()),
        &policy(&pki.rogue_ca, Some(PEER_SERVER_NAME), None),
    )
    .await
    .expect_err("a peer signed by another CA must be refused");
    assert_eq!(err.code(), Code::Unavailable);
    assert!(
        err.message().starts_with("gateway peer connection failed:"),
        "{}",
        err.message()
    );
    assert!(err.message().contains("UnknownIssuer"), "{}", err.message());
}

#[tokio::test]
async fn https_dial_presents_client_identity_when_required() {
    let pki = Pki::new();
    let (address, _shutdown) = spawn_tls_gateway(test_server_state().await, &pki, true).await;
    let endpoint = format!("https://127.0.0.1:{}", address.port());

    let channel = build_peer_channel(
        &endpoint,
        &policy(
            &pki.ca,
            Some(PEER_SERVER_NAME),
            Some((&pki.client_cert, &pki.client_key)),
        ),
    )
    .await
    .expect("the chart client certificate should be accepted");
    assert_eq!(
        health(channel).await.unwrap(),
        i32::from(ServiceStatus::Healthy)
    );

    // TLS 1.3 may report the missing certificate only on the first read.
    if let Ok(channel) =
        build_peer_channel(&endpoint, &policy(&pki.ca, Some(PEER_SERVER_NAME), None)).await
    {
        health(channel)
            .await
            .expect_err("a peer that requires mTLS must refuse a dial without a client cert");
    }
}

#[tokio::test]
async fn https_dial_rejects_untrusted_client_identity() {
    let pki = Pki::new();
    let (address, _shutdown) = spawn_tls_gateway(test_server_state().await, &pki, true).await;
    let endpoint = format!("https://127.0.0.1:{}", address.port());
    let untrusted = policy(
        &pki.ca,
        Some(PEER_SERVER_NAME),
        Some((&pki.rogue_client_cert, &pki.rogue_client_key)),
    );
    if let Ok(channel) = build_peer_channel(&endpoint, &untrusted).await {
        health(channel)
            .await
            .expect_err("a client certificate from another CA must be refused");
    }
}
