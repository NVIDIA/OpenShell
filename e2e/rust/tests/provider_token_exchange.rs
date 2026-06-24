// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use futures_util::future::BoxFuture;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UnixListener};
use tokio::process::Command;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::body::Body as TonicBody;
use tonic::codegen::{Body, http};
use tonic::{Request, Response, Status};

const TRUST_DOMAIN: &str = "openshell-e2e.test";
const ISSUER: &str = "https://spiffe.openshell-e2e.test";
const KEY_ID: &str = "openshell-e2e-test-key";
const USER_SUBJECT_TOKEN: &str = "stored-user-token";
const INTERMEDIATE_TOKEN: &str = "intermediate-token";
const FINAL_ACCESS_TOKEN: &str = "final-access-token";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";

const TEST_RSA_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvCoZ0mVHpCHsF
zeeqw2caNIe/eb4BQUccFPhZfRnF7sCfyB84zTBmuwG2umRBdjFnVsfIIZRp2HcD
OESrRYYiE1RGfjBXImGVg2Wtza0HYhL1sLyX1eaEefylxoilmApAgWDh9p36h8J2
s5YHwyXPTttx4DpdWDnxju1iNmwoIB8uVE/5amWgbNvlETMBOcB1RxDHtnVy+xJz
jjjrzK4Qz9WsUTHAvngdi4Yyxvci+yKpjYTg5+UWxmAN6iW522TpLe32MDb5Ug1d
trBvvepWmdQ6CBwPhBHCt/sMoSJAYSO4RKeBnBjeLQBXFTxaOv5iTGIsRTX3K471
epHp3cT5AgMBAAECggEASQlRv/4nZN5SgsH/K8v7zb3kdHsmUly8AJYpaCGgauvr
uN/mUyueyga2uNl+MqhQBef6VWHZjO6y/gdw86v/Q2GgVQebQQhKAnpAp2w+Ceoc
siKMFqi8VkOWLU+xPbM6d97kH3TpRxt1g1T8wYFmWeF0BEiE4eUJzGaQW14M9BJ+
G0QxmP/zjX9cNpVeApKTjBWKiH4CXG3DuI3pJ93VOMpUlOsrdLXvKGTze0e01itr
MX/MHHTE+VXB4FB+/zKSA4c36egi676OSXrGC/GDmM8ntJ4CUGeD5uZsMSADiAUn
iccv5iGRWVMIKxUS5Q4k0jy8uWuK+QVP4Y6cQWYArwKBgQDhuSNORBNpIGRfsKGN
iJo/h+qinz6pEIpa3D3oVl7rpkyvgIyaTwfXvC1vfdS9V5VIel2gV2Cx0OrI8yrr
nQu1JuNV/rLmtvqX321fgBLRdoiqF3pAy1gbmdUz1elerAIYL578gXQ6jg1bbdic
kJpn0MsoDUJGwvJnXcgLqG7q3wKBgQDGhRIa4oJsj1vqICc8zt8YsCAcot3vjWLH
588X7JdBGOWJdWxfdmGXQRn5Zw9UhMQnYa3uyTBPeVcXopThlPotYeuFhLSU856T
IJzfpzCJzC4zIQayoyvJFrKe7N70iUQ986dewYy9oxQhHvFKd/qe4ylbzZJXpthX
eWEuuBSjJwKBgGkqXt6qLPj/1IQYwUw15tfOtW0LEKCoSi3HCzjidNsJ4hSqqdeD
Fr5WuDyHvcRxt+XKzTBVRYHTOnBhiw+3XasK8UQxpJyFh/+WY1jpTNs2hLnqslTZ
6LUDWSgLc+1d6qPmHAa9Ma/OWz7L0O4xGR9hUiXY95YMYe/y668yzGq1AoGBAJyU
Gsqfu7U6gYmxoKEine6QBFPx1dD7GF2KJdq93jMXGvyHZFoLOkAdtgnz0rCcI0bY
kWKUxwj4MMxQjNM8OPMQl75xBCmz2XA8Od9htDQLmqjzNKAzePabc3lMZTJFDlE6
29kuGf79IIRbLn/JECDAFT/2baW60Ep2T0OVJ5njAoGAfaCaQ4aVgjI027q7Y5qP
KfNSI8uuA8PLqmUY30I9KFWzN6VDLu00eKa90F4w3CeWRRQWXW1+007tTz3V1mNw
20A24Fi3HGQmXc7NyuLDODTJsWBICuOemCnRkvcxIlxb+ec7jp+XRmzDwKkzSnVN
pM2zFU8SeVkvHKlEuoHaP0s=
-----END PRIVATE KEY-----";

const TEST_RSA_MODULUS_HEX: &str = concat!(
    "af0a86749951e9087b05cde7aac3671a3487bf79be0141471c14f8597d19c5eec09fc81f38cd3066bb01b6ba",
    "644176316756c7c8219469d877033844ab4586221354467e30572261958365adcdad076212f5b0bc97d5e684",
    "79fca5c688a5980a408160e1f69dfa87c276b39607c325cf4edb71e03a5d5839f18eed62366c28201f2e54",
    "4ff96a65a06cdbe511330139c0754710c7b67572fb12738e38ebccae10cfd5ac5131c0be781d8b8632c6",
    "f722fb22a98d84e0e7e516c6600dea25b9db64e92dedf63036f9520d5db6b06fbdea5699d43a081c0f84",
    "11c2b7fb0ca122406123b844a7819c18de2d0057153c5a3afe624c622c4535f72b8ef57a91e9ddc4f9"
);

#[derive(Clone, PartialEq, prost::Message)]
struct JwtsvidRequest {
    #[prost(string, repeated, tag = "1")]
    audience: Vec<String>,
    #[prost(string, tag = "2")]
    spiffe_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtsvidResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<Jwtsvid>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Jwtsvid {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(string, tag = "2")]
    svid: String,
    #[prost(string, tag = "3")]
    hint: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtBundlesRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtBundlesResponse {
    #[prost(map = "string, bytes", tag = "1")]
    bundles: HashMap<String, Vec<u8>>,
}

#[derive(Clone)]
struct SpiffeWorkloadApi {
    subject: Arc<str>,
    jwks: Arc<Vec<u8>>,
    encoding_key: Arc<EncodingKey>,
}

impl SpiffeWorkloadApi {
    fn jwt_svid(&self, audience: Vec<String>) -> Result<String, Status> {
        let now = unix_timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KEY_ID.to_string());
        let claims = json!({
            "iss": ISSUER,
            "sub": self.subject.as_ref(),
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
        });
        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|err| Status::internal(format!("sign JWT-SVID: {err}")))
    }
}

#[derive(Clone)]
struct SpiffeWorkloadApiServer {
    inner: Arc<SpiffeWorkloadApi>,
}

impl SpiffeWorkloadApiServer {
    fn new(inner: SpiffeWorkloadApi) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<B> tower::Service<http::Request<B>> for SpiffeWorkloadApiServer
where
    B: Body + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
{
    type Response = http::Response<TonicBody>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        match req.uri().path() {
            "/SpiffeWorkloadAPI/FetchJWTSVID" => {
                #[derive(Clone)]
                struct FetchJwtsvidSvc(Arc<SpiffeWorkloadApi>);
                impl tonic::server::UnaryService<JwtsvidRequest> for FetchJwtsvidSvc {
                    type Response = JwtsvidResponse;
                    type Future = BoxFuture<'static, Result<Response<Self::Response>, Status>>;

                    fn call(&mut self, request: Request<JwtsvidRequest>) -> Self::Future {
                        let inner = Arc::clone(&self.0);
                        Box::pin(async move {
                            let request = request.into_inner();
                            let svid = inner.jwt_svid(request.audience)?;
                            Ok(Response::new(JwtsvidResponse {
                                svids: vec![Jwtsvid {
                                    spiffe_id: inner.subject.to_string(),
                                    svid,
                                    hint: String::new(),
                                }],
                            }))
                        })
                    }
                }

                let inner = Arc::clone(&self.inner);
                Box::pin(async move {
                    let codec = tonic_prost::ProstCodec::default();
                    let mut grpc = tonic::server::Grpc::new(codec);
                    Ok(grpc.unary(FetchJwtsvidSvc(inner), req).await)
                })
            }
            "/SpiffeWorkloadAPI/FetchJWTBundles" => {
                #[derive(Clone)]
                struct FetchJwtBundlesSvc(Arc<SpiffeWorkloadApi>);
                impl tonic::server::ServerStreamingService<JwtBundlesRequest> for FetchJwtBundlesSvc {
                    type Response = JwtBundlesResponse;
                    type ResponseStream = ReceiverStream<Result<JwtBundlesResponse, Status>>;
                    type Future =
                        BoxFuture<'static, Result<Response<Self::ResponseStream>, Status>>;

                    fn call(&mut self, _request: Request<JwtBundlesRequest>) -> Self::Future {
                        let inner = Arc::clone(&self.0);
                        Box::pin(async move {
                            let mut bundles = HashMap::new();
                            bundles.insert(TRUST_DOMAIN.to_string(), inner.jwks.as_ref().clone());
                            let (tx, rx) = tokio::sync::mpsc::channel(1);
                            tx.send(Ok(JwtBundlesResponse { bundles }))
                                .await
                                .map_err(|err| Status::internal(format!("send bundle: {err}")))?;
                            Ok(Response::new(ReceiverStream::new(rx)))
                        })
                    }
                }

                let inner = Arc::clone(&self.inner);
                Box::pin(async move {
                    let codec = tonic_prost::ProstCodec::default();
                    let mut grpc = tonic::server::Grpc::new(codec);
                    Ok(grpc.server_streaming(FetchJwtBundlesSvc(inner), req).await)
                })
            }
            _ => Box::pin(async move {
                let mut response = http::Response::new(TonicBody::empty());
                response.headers_mut().insert(
                    tonic::Status::GRPC_STATUS,
                    (tonic::Code::Unimplemented as i32).into(),
                );
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    tonic::metadata::GRPC_CONTENT_TYPE,
                );
                Ok(response)
            }),
        }
    }
}

impl tonic::server::NamedService for SpiffeWorkloadApiServer {
    const NAME: &'static str = "SpiffeWorkloadAPI";
}

struct FixtureHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FixtureHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs()
        .try_into()
        .expect("timestamp should fit i64")
}

fn jwks() -> Vec<u8> {
    let modulus = hex::decode(TEST_RSA_MODULUS_HEX).expect("valid test RSA modulus hex");
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus);
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01]);
    serde_json::to_vec(&json!({
        "keys": [{
            "kty": "RSA",
            "kid": KEY_ID,
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        }]
    }))
    .expect("JWKS should serialize")
}

async fn start_spiffe_workload_api(path: &Path, subject: &str) -> FixtureHandle {
    let api = SpiffeWorkloadApi {
        subject: Arc::<str>::from(subject),
        jwks: Arc::new(jwks()),
        encoding_key: Arc::new(
            EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
                .expect("test RSA key should parse"),
        ),
    };
    let endpoint = path.to_string_lossy();
    if endpoint.starts_with("tcp:") {
        let listen = std::env::var("OPENSHELL_E2E_PROVIDER_SPIFFE_LISTEN")
            .expect("OPENSHELL_E2E_PROVIDER_SPIFFE_LISTEN must be set for TCP SPIFFE fixture");
        let listener = TcpListener::bind(&listen)
            .await
            .expect("bind TCP SPIFFE Workload API fixture");
        let incoming = TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            let result = tonic::transport::Server::builder()
                .add_service(SpiffeWorkloadApiServer::new(api))
                .serve_with_incoming(incoming)
                .await;
            if let Err(err) = result {
                eprintln!("SPIFFE Workload API fixture failed: {err}");
            }
        });
        return FixtureHandle { task };
    }
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("bind SPIFFE Workload API socket");
    let mut permissions = fs::metadata(path)
        .expect("stat SPIFFE Workload API socket")
        .permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(path, permissions).expect("chmod SPIFFE Workload API socket");
    let incoming = UnixListenerStream::new(listener);
    let task = tokio::spawn(async move {
        let result = tonic::transport::Server::builder()
            .add_service(SpiffeWorkloadApiServer::new(api))
            .serve_with_incoming(incoming)
            .await;
        if let Err(err) = result {
            eprintln!("SPIFFE Workload API fixture failed: {err}");
        }
    });
    FixtureHandle { task }
}

async fn start_gateway_token_endpoint(port: u16) -> FixtureHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("bind gateway token endpoint");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let access_token = if request.starts_with("POST /token ")
                    && request.contains("subject_token=stored-user-token")
                    && request.contains("client_assertion=")
                {
                    Some(INTERMEDIATE_TOKEN)
                } else if request.starts_with("POST /token ")
                    && request.contains("subject_token=intermediate-token")
                    && request.contains("client_assertion=")
                {
                    Some(FINAL_ACCESS_TOKEN)
                } else {
                    None
                };
                let (status, body) = if let Some(access_token) = access_token {
                    (
                        "HTTP/1.1 200 OK",
                        json!({
                            "access_token": access_token,
                            "token_type": "Bearer",
                            "expires_in": 300
                        })
                        .to_string(),
                    )
                } else {
                    (
                        "HTTP/1.1 400 Bad Request",
                        json!({"error": "unexpected_token_exchange"}).to_string(),
                    )
                };
                let response = format!(
                    "{status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    FixtureHandle { task }
}

async fn start_protected_target(port: u16) -> FixtureHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .expect("bind protected target");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let ok = request.lines().any(|line| {
                    line.eq_ignore_ascii_case(&format!(
                        "authorization: Bearer {FINAL_ACCESS_TOKEN}"
                    ))
                });
                let (status, body) = if ok {
                    ("HTTP/1.1 200 OK", "token-exchange-ok")
                } else {
                    ("HTTP/1.1 401 Unauthorized", "missing-final-token")
                };
                let response = format!(
                    "{status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    FixtureHandle { task }
}

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let output = openshell_cmd()
        .args(args)
        .output()
        .await
        .map_err(|err| format!("spawn openshell: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "openshell {:?} failed with {:?}:\n{combined}",
            args,
            output.status.code()
        ))
    }
}

async fn run_cli_ignore_error(args: &[&str]) {
    let _ = openshell_cmd().args(args).output().await;
}

fn write_profile(profile_type: &str, token_port: u16, target_port: u16) -> NamedTempFile {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create provider profile temp file");
    let profile = format!(
        r#"id: {profile_type}
display_name: Podman token exchange e2e
description: Podman e2e provider profile for two-stage token exchange
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
      audience: final-audience
      jwt_svid_audience: {token_endpoint}
      client_assertion_type: {CLIENT_ASSERTION_TYPE}
      requested_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
      cache_ttl_seconds: 30
      subject_token:
        source: provider_credential
        credential: subject_token
        subject_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
endpoints:
  - host: host.openshell.internal
    port: {target_port}
    protocol: rest
    tls: none
    access: read-write
    enforcement: enforce
    allowed_ips:
      - 10.0.0.0/8
      - 172.0.0.0/8
      - 192.168.0.0/16
binaries:
  - /usr/bin/curl
  - /usr/local/bin/curl
"#
    );
    file.write_all(profile.as_bytes())
        .expect("write provider profile");
    file.flush().expect("flush provider profile");
    file
}

fn sandbox_script(token_port: u16) -> String {
    let _ = token_port;
    r#"set -eu
echo token-server-ready
while true; do sleep 60; done
"#
    .to_string()
}

fn container_token_endpoint_script() -> String {
    format!(
        r#"
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

PORT = int(sys.argv[1])

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/token":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("content-length", "0"))
        params = parse_qs(self.rfile.read(length).decode())
        subject_token = params.get("subject_token", [""])[0]
        client_assertion = params.get("client_assertion", [""])[0]
        if subject_token == "{USER_SUBJECT_TOKEN}" and client_assertion:
            access_token = "{INTERMEDIATE_TOKEN}"
        elif subject_token == "{INTERMEDIATE_TOKEN}" and client_assertion:
            access_token = "{FINAL_ACCESS_TOKEN}"
        else:
            self.send_response(400)
            body = json.dumps({{"error": "unexpected_token_exchange"}}).encode()
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({{
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 300,
        }}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
"#
    )
}

async fn start_container_token_endpoint(sandbox_name: &str, token_port: u16) -> Result<(), String> {
    let socket = std::env::var("OPENSHELL_PODMAN_SOCKET")
        .map_err(|_| "OPENSHELL_PODMAN_SOCKET must be set by e2e-podman.sh".to_string())?;
    let container_name = format!("openshell-sandbox-{sandbox_name}");
    let mut cmd = Command::new("podman");
    cmd.arg("--url")
        .arg(format!("unix://{socket}"))
        .arg("exec")
        .arg("-d")
        .arg(&container_name)
        .arg("python3")
        .arg("-c")
        .arg(container_token_endpoint_script())
        .arg(token_port.to_string());
    apply_podman_config_env(&mut cmd);
    let output = cmd
        .output()
        .await
        .map_err(|err| format!("spawn podman exec token endpoint: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "podman exec token endpoint failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    for _ in 0..20 {
        if container_loopback_port_ready(&container_name, token_port).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(format!(
        "container token endpoint did not become ready on 127.0.0.1:{token_port}"
    ))
}

fn apply_podman_config_env(cmd: &mut Command) {
    if std::env::var_os("OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME").is_some() {
        cmd.env_remove("XDG_CONFIG_HOME");
    } else if let Some(value) = std::env::var_os("OPENSHELL_E2E_CONTAINER_ENGINE_XDG_CONFIG_HOME") {
        cmd.env("XDG_CONFIG_HOME", value);
    }
}

async fn container_loopback_port_ready(container_name: &str, token_port: u16) -> bool {
    let Ok(socket) = std::env::var("OPENSHELL_PODMAN_SOCKET") else {
        return false;
    };
    let probe = format!(
        "import socket; s=socket.create_connection(('127.0.0.1', {token_port}), 1); s.close()"
    );
    let mut cmd = Command::new("podman");
    cmd.arg("--url")
        .arg(format!("unix://{socket}"))
        .arg("exec")
        .arg(container_name)
        .arg("python3")
        .arg("-c")
        .arg(probe);
    apply_podman_config_env(&mut cmd);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    cmd.status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

async fn sandbox_exec_curl(sandbox_name: &str, target_port: u16) -> Result<String, String> {
    let url = format!("http://host.openshell.internal:{target_port}/resource");
    for _ in 0..20 {
        let output = openshell_cmd()
            .args([
                "sandbox",
                "exec",
                "--name",
                sandbox_name,
                "--no-tty",
                "--",
                "curl",
                "-fsS",
                &url,
            ])
            .output()
            .await
            .map_err(|err| format!("spawn openshell sandbox exec: {err}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        if output.status.success() {
            return Ok(combined);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("curl to protected target did not succeed at {url}"))
}

#[tokio::test]
async fn podman_provider_token_exchange_injects_bearer_header() {
    let gateway_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET")
            .expect("OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET must be set by e2e-podman.sh"),
    );
    let provider_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET")
            .expect("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET must be set by e2e-podman.sh"),
    );

    let profile_type = format!("podman-token-exchange-e2e-{}", std::process::id());
    let provider_name = format!("podman-token-exchange-e2e-{}", std::process::id());
    let token_port = find_free_port();
    let target_port = find_free_port();
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    let gateway_subject = format!("spiffe://{TRUST_DOMAIN}/openshell/gateway");
    let supervisor_subject = format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e");

    let _gateway_spiffe = start_spiffe_workload_api(&gateway_socket, &gateway_subject).await;
    let _provider_spiffe = start_spiffe_workload_api(&provider_socket, &supervisor_subject).await;
    let _gateway_token = start_gateway_token_endpoint(token_port).await;
    let _target = start_protected_target(target_port).await;

    run_cli(&[
        "settings",
        "set",
        "--global",
        "--key",
        "providers_v2_enabled",
        "--value",
        "true",
        "--yes",
    ])
    .await
    .expect("enable providers v2");

    run_cli_ignore_error(&["provider", "delete", &provider_name, "--yes"]).await;
    run_cli_ignore_error(&["provider", "profile", "delete", &profile_type, "--yes"]).await;

    let profile = write_profile(&profile_type, token_port, target_port);
    let profile_path = profile
        .path()
        .to_str()
        .expect("profile path should be UTF-8");
    run_cli(&["provider", "profile", "import", "-f", profile_path])
        .await
        .expect("import provider profile");
    run_cli(&[
        "provider",
        "create",
        "--name",
        &provider_name,
        "--type",
        &profile_type,
        "--credential",
        &format!("subject_token={USER_SUBJECT_TOKEN}"),
    ])
    .await
    .expect("create provider");

    let script = sandbox_script(token_port);
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--provider", &provider_name],
        &["sh", "-lc", &script],
        "token-server-ready",
    )
    .await
    .unwrap_or_else(|err| {
        panic!(
            "sandbox should complete token exchange against {token_endpoint} and protected target port {target_port}:\n{err}"
        )
    });
    start_container_token_endpoint(&sandbox.name, token_port)
        .await
        .expect("start container token endpoint");
    let curl_output = sandbox_exec_curl(&sandbox.name, target_port)
        .await
        .expect("curl protected target from kept sandbox");

    run_cli_ignore_error(&["provider", "delete", &provider_name, "--yes"]).await;
    run_cli_ignore_error(&["provider", "profile", "delete", &profile_type, "--yes"]).await;
    sandbox.cleanup().await;

    assert!(
        curl_output.contains("token-exchange-ok"),
        "protected target should receive the final exchanged bearer token:\n{}",
        curl_output
    );
}
