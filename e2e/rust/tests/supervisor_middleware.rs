// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Black-box happy-path coverage for authenticated supervisor middleware.

#![cfg(feature = "e2e-docker")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use openshell_sdk::extension::GatewayJwtAuthenticator;
use serde_json::{Value, json};
use tempfile::NamedTempFile;

const MIDDLEWARE_AUDIENCE: &str = "urn:openshell:extension:middleware:e2e-scripted";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; e2e/with-docker-gateway.sh exports it for this lane")
    })
}

fn read_env_file(name: &str) -> Result<Vec<u8>, String> {
    let path = required_env(name);
    std::fs::read(&path).map_err(|error| format!("read {path}: {error}"))
}

fn gateway_https_client() -> Result<reqwest::Client, String> {
    // reqwest is built without a bundled TLS backend so the test binary shares
    // the AWS-LC provider already selected by the rest of its dependency graph.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = read_env_file("OPENSHELL_E2E_GATEWAY_CA_CERT")?;
    let ca = reqwest::Certificate::from_pem(&ca)
        .map_err(|error| format!("parse gateway CA certificate: {error}"))?;
    let mut identity = read_env_file("OPENSHELL_E2E_GATEWAY_CLIENT_CERT")?;
    identity.extend(read_env_file("OPENSHELL_E2E_GATEWAY_CLIENT_KEY")?);
    let identity = reqwest::Identity::from_pem(&identity)
        .map_err(|error| format!("parse gateway client identity: {error}"))?;
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .map_err(|error| format!("build gateway HTTPS client: {error}"))
}

async fn start_test_server() -> Result<ContainerHttpServer, String> {
    let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        parsed = json.loads(body)
        response = json.dumps({
            "received_payload": parsed.get("payload"),
            "fixture_header": self.headers.get("x-openshell-middleware-fixture"),
        }, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;
    ContainerHttpServer::start_python("middleware-happy.openshell.test", script).await
}

fn write_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r#"version: 1

network_middlewares:
  scripted-e2e:
    name: Scripted E2E middleware
    middleware: e2e-scripted
    order: 10
    config: {{}}
    on_error: fail_closed
    endpoints:
      include:
        - {host}

network_policies:
  middleware_target:
    name: middleware_target
    endpoints:
      - host: {host}
        port: {port}
        protocol: rest
        enforcement: enforce
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
        rules:
          - allow:
              method: POST
              path: "/inspect"
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

#[tokio::test]
async fn authenticated_middleware_mutates_request_body_and_headers() {
    let server = start_test_server().await.expect("start upstream server");
    let policy = write_policy(&server.host, server.port).expect("write middleware policy");
    let script = format!(
        r#"import json, urllib.request
request = urllib.request.Request(
    "http://{host}:{port}/inspect",
    data=json.dumps({{"payload": "raw-secret"}}).encode(),
    headers={{"Content-Type": "application/json"}},
    method="POST",
)
with urllib.request.urlopen(request, timeout=15) as response:
    print("MIDDLEWARE_RESULT=" + response.read().decode())
"#,
        host = server.host,
        port = server.port,
    );
    let policy_path = policy.path().to_string_lossy().into_owned();

    let sandbox = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("create middleware sandbox");
    let result = sandbox
        .create_output
        .lines()
        .find_map(|line| line.split_once("MIDDLEWARE_RESULT=").map(|(_, json)| json))
        .expect("sandbox output should contain the upstream response");
    let result: Value = serde_json::from_str(result).expect("upstream response should be JSON");

    assert_eq!(result["received_payload"], "[REDACTED]");
    assert_eq!(result["fixture_header"], "evaluated");
}

/// The extension SDK deliberately keeps its own copy of the gateway's trust
/// contract instead of depending on internal crates. This proves the SDK can
/// consume what a real gateway publishes: the discovery document names the
/// issuer the SDK expects and the JWKS parses into a usable verifier. Claim
/// shape is covered by the fixture in the same lane, which verifies real
/// gateway and supervisor tokens on every authenticated RPC.
#[tokio::test]
async fn sdk_verifier_accepts_gateway_published_trust_material() {
    let endpoint = required_env("OPENSHELL_E2E_GATEWAY_ENDPOINT");
    let gateway_name = required_env("OPENSHELL_GATEWAY");
    let client = gateway_https_client().expect("gateway HTTPS client");

    let discovery: Value = client
        .get(format!("{endpoint}/.well-known/openid-configuration"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .expect("fetch discovery document")
        .json()
        .await
        .expect("discovery document should be JSON");
    let issuer = discovery["issuer"]
        .as_str()
        .expect("discovery document should name an issuer");
    assert_eq!(issuer, format!("openshell-gateway:{gateway_name}"));
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["EdDSA"])
    );
    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .expect("discovery document should carry an absolute jwks_uri");
    assert!(
        jwks_uri.starts_with("https://") && jwks_uri.ends_with("/.well-known/jwks.json"),
        "unexpected jwks_uri {jwks_uri}"
    );

    let jwks = client
        .get(jwks_uri)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .expect("fetch JWKS")
        .bytes()
        .await
        .expect("read JWKS body");
    let published: Value = serde_json::from_slice(&jwks).expect("JWKS should be JSON");
    let keys = published["keys"].as_array().expect("JWKS should list keys");
    assert_eq!(keys.len(), 1, "gateway publishes a single-key JWKS");
    assert!(
        keys[0]["kid"].as_str().is_some_and(|kid| !kid.is_empty()),
        "published key must carry a kid"
    );

    GatewayJwtAuthenticator::builder(issuer, MIDDLEWARE_AUDIENCE)
        .jwks(&jwks)
        .build()
        .expect("SDK verifier accepts the gateway's published JWKS");
}
