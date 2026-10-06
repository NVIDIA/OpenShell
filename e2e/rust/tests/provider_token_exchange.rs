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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use futures_util::future::BoxFuture;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UnixListener};
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
const IDENTITY_AUDIENCE: &str = "identity-proxy";
const IDENTITY_JWT_AUDIENCE: &str = "https://identity.openshell-e2e.test";
const IDENTITY_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// The harness gives this test binary one pair of SPIFFE listener endpoints.
// Serialize their ownership even when the Rust test runner uses many threads.
static SPIFFE_FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
-----END PRIVATE KEY-----"; //notsecret

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
    fn jwt_svid(&self, audience: &[String]) -> Result<String, Status> {
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
                            let svid = inner.jwt_svid(&request.audience)?;
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

impl FixtureHandle {
    async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
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

// Forms and JWT headers can span TCP reads. Read the bounded, Content-Length
// framed request completely so packet boundaries cannot change fixture results.
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

fn verifies_jwt_svid(token: &str, instance: &str) -> bool {
    let keys: jsonwebtoken::jwk::JwkSet =
        serde_json::from_slice(&jwks()).expect("fixture JWKS should parse");
    let key = DecodingKey::from_jwk(keys.find(KEY_ID).expect("fixture signing key exists"))
        .expect("fixture verification key should parse");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[format!("{IDENTITY_JWT_AUDIENCE}/{instance}")]);
    validation.sub = Some(format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e"));
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
    jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
        .is_ok_and(|verified| verified.header.kid.as_deref() == Some(KEY_ID))
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

async fn start_gateway_token_endpoint(
    port: u16,
    observations: Arc<GrantObservations>,
) -> FixtureHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("bind gateway token endpoint");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let observations = Arc::clone(&observations);
            tokio::spawn(async move {
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
                    if valid
                        && field("subject_token") == format!("{USER_SUBJECT_TOKEN}-{instance}")
                        && field("audience")
                            == format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e")
                        && field("scope").is_empty()
                    {
                        access_token = Some(format!("{INTERMEDIATE_TOKEN}-{instance}"));
                    } else if valid
                        && field("subject_token") == format!("{INTERMEDIATE_TOKEN}-{instance}")
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
            });
        }
    });
    FixtureHandle { task }
}

// This issuer returns the actual Workload API JWT-SVID after checking its
// signature and audience. No new production grant type or sandbox-visible
// credential is needed to exercise custom-header injection.
async fn start_identity_token_endpoint(
    port: u16,
    observations: Arc<GrantObservations>,
) -> FixtureHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("bind identity token endpoint");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let observations = Arc::clone(&observations);
            tokio::spawn(async move {
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
                        && verifies_jwt_svid(field("client_assertion"), instance);
                    if valid && field("audience") == format!("{IDENTITY_AUDIENCE}-{instance}") {
                        observations.identity_issued[index].fetch_add(1, Ordering::SeqCst);
                        access_token = Some(field("client_assertion"));
                    } else if valid && field("audience") == format!("denied-identity-{instance}") {
                        observations.identity_denied.fetch_add(1, Ordering::SeqCst);
                    }
                }
                write_token_response(&mut stream, access_token, 900).await;
            });
        }
    });
    FixtureHandle { task }
}

async fn start_protected_target(port: u16, observations: Arc<GrantObservations>) -> FixtureHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .expect("bind protected target");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let observations = Arc::clone(&observations);
            tokio::spawn(async move {
                // Count any request bytes, including an incomplete header. A
                // failed grant may open a TCP stream but must send no request.
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
                        && verifies_jwt_svid(identity[0], instance)
                });
                let (status, body) = if ok {
                    ("HTTP/1.1 200 OK", "independent-grants-ok")
                } else {
                    // Keep rejection evidence even if the workload retries and
                    // a later request happens to receive the correct credentials.
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
            });
        }
    });
    FixtureHandle { task }
}

async fn run_cli(args: &[&str]) -> Result<(), String> {
    let output = openshell_cmd()
        .args(args)
        .output()
        .await
        .map_err(|_| "could not spawn openshell CLI".to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        // Provider creation arguments contain the stored subject token.
        // Keep command arguments and raw diagnostics out of test failures.
        Err(format!(
            "openshell command failed; exit={:?}",
            output.status.code()
        ))
    }
}

async fn run_cli_ignore_error(args: &[&str]) {
    let _ = openshell_cmd().args(args).output().await;
}

fn write_profile(
    profile_type: &str,
    token_port: u16,
    identity_port: u16,
    target_port: u16,
    instance: &str,
) -> NamedTempFile {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create provider profile temp file");
    let profile = format!(
        r"id: {profile_type}
display_name: Podman token exchange e2e
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
      jwt_svid_audience: {IDENTITY_JWT_AUDIENCE}/{instance}
      client_assertion_type: {IDENTITY_ASSERTION_TYPE}
      cache_ttl_seconds: 600
      audience_overrides:
        - path: /deny-identity/{instance}
          audience: denied-identity-{instance}
endpoints:
  - host: host.openshell.internal
    port: {target_port}
    path: /**
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
    );
    file.write_all(profile.as_bytes())
        .expect("write provider profile");
    file.flush().expect("flush provider profile");
    file
}

/// Writes a profile with one bearer token-exchange grant bound to `/{route}/**`.
/// Each route carries its own audience so the token endpoint can tell which
/// endpoint's grant the supervisor selected.
fn write_route_profile(
    profile_type: &str,
    token_port: u16,
    target_port: u16,
    route: &str,
) -> NamedTempFile {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create provider profile temp file");
    let profile = format!(
        r"id: {profile_type}
display_name: Podman token exchange route e2e
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
endpoints:
  - host: host.openshell.internal
    port: {target_port}
    path: /{route}/**
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
    );
    file.write_all(profile.as_bytes())
        .expect("write provider profile");
    file.flush().expect("flush provider profile");
    file
}

fn sandbox_script() -> String {
    r"set -eu
echo token-server-ready
while true; do sleep 60; done
"
    .to_string()
}

async fn sandbox_exec_http(
    sandbox_name: &str,
    target_port: u16,
    path: &str,
    expect_denied: bool,
) -> Result<String, String> {
    let url = format!("http://host.openshell.internal:{target_port}{path}");
    let expect_denied_python = if expect_denied { "True" } else { "False" };
    let script = format!(
        r#"import base64, json, os, re, urllib.error, urllib.request

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
        except (ValueError, UnicodeError):
            pass
    return False

if any(contains_credential(value) for value in os.environ.values()):
    raise RuntimeError("provider credential material reached the workload environment")
request = urllib.request.Request({url:?}, headers={{
    "Authorization": "Bearer agent-supplied",
    "X-Workload-Jwt": "agent-supplied",
}})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode()
    if contains_credential(body):
        raise RuntimeError("provider credential material reached the workload response")
    if {expect_denied_python}:
        raise RuntimeError("failed grant unexpectedly reached the target")
    print(body)
except urllib.error.HTTPError as error:
    body = error.read().decode()
    if contains_credential(body):
        raise RuntimeError("provider credential material reached the workload error")
    if not {expect_denied_python} or error.code != 502:
        raise RuntimeError("unexpected HTTP response") from None
    print("grant-denied")
"#
    );
    let mut last_status = None;
    for _ in 0..20 {
        let output = openshell_cmd()
            .args([
                "sandbox",
                "exec",
                "--name",
                sandbox_name,
                "--no-tty",
                "--",
                "python3",
                "-c",
                &script,
            ])
            .output()
            .await
            .map_err(|_| "could not spawn sandbox HTTP probe".to_string())?;
        if output.status.success() {
            // The child emits fixed markers only. Never return raw stderr:
            // runtime failures can include request or credential diagnostics.
            let stdout = String::from_utf8_lossy(&output.stdout);
            let expected = if expect_denied {
                "grant-denied"
            } else {
                "independent-grants-ok"
            };
            if stdout.trim() == expected {
                return Ok(expected.to_string());
            }
            return Err("sandbox probe returned unexpected output".to_string());
        }
        last_status = output.status.code();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("sandbox HTTP probe failed; exit={last_status:?}"))
}

async fn create_provider_instance(
    token_port: u16,
    identity_port: u16,
    target_port: u16,
    instance: &str,
) -> String {
    let name = format!("podman-grants-{instance}-{}", std::process::id());
    run_cli_ignore_error(&["provider", "delete", &name, "--yes"]).await;
    run_cli_ignore_error(&["profile", "delete", &name, "--yes"]).await;
    let profile = write_profile(&name, token_port, identity_port, target_port, instance);
    let profile_path = profile
        .path()
        .to_str()
        .expect("profile path should be UTF-8");
    run_cli(&["profile", "import", "-f", profile_path])
        .await
        .expect("import independent-grant profile");
    run_cli(&[
        "provider",
        "create",
        "--name",
        &name,
        "--type",
        &name,
        "--credential",
        &format!("subject_token={USER_SUBJECT_TOKEN}-{instance}"),
    ])
    .await
    .expect("create provider instance");
    name
}

#[tokio::test]
async fn podman_provider_token_exchange_injects_independent_grants_across_sandboxes() {
    let _fixture_guard = SPIFFE_FIXTURE_LOCK.lock().await;
    let gateway_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET")
            .expect("OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET must be set by e2e-podman.sh"),
    );
    let provider_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET")
            .expect("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET must be set by e2e-podman.sh"),
    );
    let token_port = find_free_port();
    let identity_port = find_free_port();
    let target_port = find_free_port();
    let gateway_subject = format!("spiffe://{TRUST_DOMAIN}/openshell/gateway");
    // The mock shares a workload subject. Distinct providers and JWT audiences
    // test cross-sandbox credential isolation, not production SPIRE attestation.
    let supervisor_subject = format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e");
    let observations = Arc::new(GrantObservations::default());
    let _gateway_spiffe = start_spiffe_workload_api(&gateway_socket, &gateway_subject).await;
    let _provider_spiffe = start_spiffe_workload_api(&provider_socket, &supervisor_subject).await;
    let _gateway_token = start_gateway_token_endpoint(token_port, Arc::clone(&observations)).await;
    let _identity_token =
        start_identity_token_endpoint(identity_port, Arc::clone(&observations)).await;
    let _target = start_protected_target(target_port, Arc::clone(&observations)).await;

    let mut provider_names = Vec::new();
    for instance in ["a", "b"] {
        provider_names
            .push(create_provider_instance(token_port, identity_port, target_port, instance).await);
    }

    let script = sandbox_script();
    let mut sandbox_a = SandboxGuard::create_keep_with_args(
        &["--provider", &provider_names[0]],
        &["sh", "-lc", &script],
        "token-server-ready",
    )
    .await
    .expect("create sandbox A");
    let mut sandbox_b = SandboxGuard::create_keep_with_args(
        &["--provider", &provider_names[1]],
        &["sh", "-lc", &script],
        "token-server-ready",
    )
    .await
    .expect("create sandbox B");

    // Both supervisors request the same host/port concurrently. The target
    // verifies each path's distinct bearer and signed JWT audience together.
    let initial = tokio::join!(
        sandbox_exec_http(&sandbox_a.name, target_port, "/resource/a", false),
        sandbox_exec_http(&sandbox_b.name, target_port, "/resource/b", false),
    );
    let before_cache = observations.issued();
    let cached = tokio::join!(
        sandbox_exec_http(&sandbox_a.name, target_port, "/resource/a", false),
        sandbox_exec_http(&sandbox_b.name, target_port, "/resource/b", false),
    );
    let after_cache = observations.issued();
    let target_requests = observations.target_requests.load(Ordering::SeqCst);
    // An audience override forces acquisition of only the failing credential;
    // the other credential remains cached from the successful request.
    let denied = tokio::join!(
        sandbox_exec_http(&sandbox_a.name, target_port, "/deny-service/a", true),
        sandbox_exec_http(&sandbox_b.name, target_port, "/deny-identity/b", true),
    );

    sandbox_a.cleanup().await;
    sandbox_b.cleanup().await;
    for name in &provider_names {
        run_cli_ignore_error(&["provider", "delete", name, "--yes"]).await;
        run_cli_ignore_error(&["profile", "delete", name, "--yes"]).await;
    }
    // Release the shared SPIFFE endpoints before the next test binds them.
    _target.shutdown().await;
    _identity_token.shutdown().await;
    _gateway_token.shutdown().await;
    _provider_spiffe.shutdown().await;
    _gateway_spiffe.shutdown().await;

    for outcome in [initial.0, initial.1, cached.0, cached.1] {
        assert_eq!(
            outcome.expect("independent grant request should succeed"),
            "independent-grants-ok"
        );
    }
    assert_eq!(
        observations.target_rejected.load(Ordering::SeqCst),
        0,
        "no request may present mismatched or untrusted credentials, even before a retry"
    );
    assert!(
        before_cache
            .iter()
            .all(|(service, identity)| *service > 0 && *identity > 0),
        "each provider instance must acquire both credentials"
    );
    assert_eq!(
        after_cache, before_cache,
        "repeat requests should use both caches"
    );
    for outcome in [denied.0, denied.1] {
        assert_eq!(
            outcome.expect("failed grant should return 502"),
            "grant-denied"
        );
    }
    assert!(observations.service_denied.load(Ordering::SeqCst) > 0);
    assert!(observations.identity_denied.load(Ordering::SeqCst) > 0);
    assert_eq!(
        observations.target_requests.load(Ordering::SeqCst),
        target_requests,
        "neither failed grant may forward any request bytes"
    );
}

// Read one whole fixture request without consuming the following keepalive
// request. OAuth forms can arrive separately from their headers.
async fn read_route_fixture_request(
    stream: &mut TcpStream,
    observed_bytes: Option<&AtomicUsize>,
) -> Result<Option<String>, String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream
                .read(&mut byte)
                .await
                .map_err(|err| err.to_string())?
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
        let header = std::str::from_utf8(&bytes).map_err(|err| err.to_string())?;
        let length = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse::<usize>())
            .transpose()
            .map_err(|err| err.to_string())?
            .unwrap_or(0);
        if length > 64 * 1024 {
            return Err("fixture body exceeds limit".into());
        }
        let header_len = bytes.len();
        bytes.resize(header_len + length, 0);
        stream
            .read_exact(&mut bytes[header_len..])
            .await
            .map_err(|err| err.to_string())?;
        if let Some(observed) = observed_bytes {
            observed.fetch_add(length, Ordering::Relaxed);
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|err| err.to_string())
    })
    .await
    .map_err(|_| "fixture request timed out".to_owned())?
}

#[derive(Default)]
struct RouteGrantState {
    fail_next_b: AtomicBool,
    supervisor_requests: Mutex<Vec<String>>,
}

async fn start_route_token_endpoint(port: u16, state: Arc<RouteGrantState>) -> FixtureHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("bind route token endpoint");
    let task = tokio::spawn(async move {
        let mut requests = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    let state = state.clone();
                    requests.spawn(async move {
                        let Ok(Some(request)) = read_route_fixture_request(&mut stream, None).await else { return; };
                        let form = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
                        let fields = form.split('&').filter_map(|part| part.split_once('=')).collect::<HashMap<_, _>>();
                        let subject = fields.get("subject_token").copied().unwrap_or_default();
                        let route = match subject {
                            "stored-a" | "intermediate-a" => "a",
                            "stored-b" | "intermediate-b" => "b",
                            _ => "",
                        };
                        let supervisor = subject.starts_with("intermediate-");
                        let valid = !route.is_empty() && request.starts_with("POST /token ")
                            && fields.get("client_assertion").is_some_and(|value| !value.is_empty())
                            // Gateway exchange targets the supervisor's SPIFFE
                            // subject; final exchange targets the route audience.
                            && fields.get("audience").is_some_and(|value| !value.is_empty()
                                && (!supervisor || *value == format!("audience-{route}")));
                        let fail = if valid && supervisor {
                            state.supervisor_requests.lock().expect("route grant requests lock").push(route.to_owned());
                            route == "b" && state.fail_next_b.swap(false, Ordering::SeqCst)
                        } else { false };
                        let (status, body) = if fail {
                            ("HTTP/1.1 503 Service Unavailable", json!({"error": "temporary_failure"}).to_string())
                        } else if valid {
                            let stage = if supervisor { "final" } else { "intermediate" };
                            ("HTTP/1.1 200 OK", json!({
                                "access_token": format!("{stage}-{route}"), "token_type": "Bearer", "expires_in": 300
                            }).to_string())
                        } else {
                            ("HTTP/1.1 400 Bad Request", json!({"error": "unexpected_route_exchange"}).to_string())
                        };
                        let response = format!("{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(response.as_bytes())).await;
                    });
                }
                _ = requests.join_next(), if !requests.is_empty() => {}
            }
        }
    });
    FixtureHandle { task }
}

struct RouteTargetRequest {
    connection: usize,
    path: String,
    authorization: Vec<String>,
    bytes: usize,
}

struct RouteTargetHandle {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl RouteTargetHandle {
    async fn drain(mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            // A closed receiver means the task already stopped; joining still
            // reports its error rather than hiding it behind the stop signal.
            let _ = stop.send(());
        }
        tokio::time::timeout(Duration::from_secs(35), &mut self.task)
            .await
            .map_err(|_| "route target did not drain accepted connections".to_owned())?
            .map_err(|err| format!("route target task failed: {err}"))?
    }
}

impl Drop for RouteTargetHandle {
    fn drop(&mut self) {
        // Failure and timeout cleanup must also cancel the owned JoinSet.
        self.task.abort();
    }
}

async fn start_route_target(
    port: u16,
    observed: Arc<Mutex<Vec<RouteTargetRequest>>>,
    observed_bytes: Arc<AtomicUsize>,
) -> RouteTargetHandle {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .expect("bind route target");
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let next_connection = AtomicUsize::new(1);
        let mut connections = tokio::task::JoinSet::new();
        let mut completed = Vec::new();
        let mut accept_error = None;
        loop {
            tokio::select! {
                // Once the workload has closed, accept queued connections
                // before stopping so their buffered bytes are also observed.
                biased;
                accepted = listener.accept() => {
                    let (mut stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(err) => {
                            accept_error = Some(format!("route target accept failed: {err}"));
                            break;
                        }
                    };
                    let connection = next_connection.fetch_add(1, Ordering::Relaxed);
                    let observed = observed.clone();
                    let observed_bytes = observed_bytes.clone();
                    connections.spawn(async move {
                        loop {
                            let Some(request) = read_route_fixture_request(&mut stream, Some(&observed_bytes)).await? else { return Ok::<(), String>(()); };
                            let path = request.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or_default().to_owned();
                            let authorization = request.lines().filter_map(|line| line.split_once(':'))
                                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                                .map(|(_, value)| value.trim().to_owned()).collect::<Vec<_>>();
                            let expected = if path.starts_with("/a/") { "Bearer final-a" } else { "Bearer final-b" };
                            let valid = authorization.len() == 1 && authorization[0] == expected;
                            observed.lock().expect("route target observations lock").push(RouteTargetRequest { connection, path, authorization, bytes: request.len() });
                            let status = if valid { "HTTP/1.1 200 OK" } else { "HTTP/1.1 401 Unauthorized" };
                            let response = format!("{status}\r\nContent-Length: 0\r\n\r\n");
                            tokio::time::timeout(Duration::from_secs(5), stream.write_all(response.as_bytes())).await
                                .map_err(|_| "route target response write timed out".to_owned())?
                                .map_err(|err| format!("route target response write failed: {err}"))?;
                        }
                    });
                }
                _ = &mut stopped => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => completed.push(result),
            }
        }
        drop(listener);
        // Only EOF proves that the byte counter includes everything sent on
        // each accepted connection. Do not abort pending readers on success.
        while let Some(result) = connections.join_next().await {
            completed.push(result);
        }
        if let Some(error) = accept_error {
            return Err(error);
        }
        for result in completed {
            result.map_err(|err| format!("route target reader task failed: {err}"))??;
        }
        Ok(())
    });
    RouteTargetHandle {
        stop: Some(stop),
        task,
    }
}

#[tokio::test]
async fn podman_provider_routes_recover_and_select_a_b_a_on_one_connection() {
    let _fixture_guard = SPIFFE_FIXTURE_LOCK.lock().await;
    let gateway_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET")
            .expect("gateway SPIFFE fixture endpoint"),
    );
    let provider_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET")
            .expect("provider SPIFFE fixture endpoint"),
    );
    // A remote Podman VM can forward this fixed loopback port to the test
    // process. Keep the issuer URL on loopback so the fixture obeys the
    // production token endpoint transport policy on both sides of the tunnel.
    let token_port = std::env::var("OPENSHELL_E2E_TOKEN_PORT").map_or_else(
        |_| find_free_port(),
        |port| {
            let port = port
                .parse::<u16>()
                .expect("OPENSHELL_E2E_TOKEN_PORT must be a valid TCP port");
            assert_ne!(port, 0, "OPENSHELL_E2E_TOKEN_PORT must be nonzero");
            port
        },
    );
    let target_port = find_free_port();
    let grants = Arc::new(RouteGrantState::default());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_bytes = Arc::new(AtomicUsize::new(0));
    let _gateway_spiffe = start_spiffe_workload_api(
        &gateway_socket,
        &format!("spiffe://{TRUST_DOMAIN}/openshell/gateway"),
    )
    .await;
    let _provider_spiffe = start_spiffe_workload_api(
        &provider_socket,
        &format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e"),
    )
    .await;
    let _token_endpoint = start_route_token_endpoint(token_port, grants.clone()).await;
    let _target = start_route_target(target_port, observed.clone(), observed_bytes.clone()).await;
    let names = ["a", "b"].map(|route| format!("podman-route-{route}-{}", std::process::id()));
    for name in &names {
        run_cli_ignore_error(&["provider", "delete", name, "--yes"]).await;
        run_cli_ignore_error(&["profile", "delete", name, "--yes"]).await;
    }
    let result: Result<String, String> = async {
        for (route, name) in ["a", "b"].iter().zip(&names) {
            let profile = write_route_profile(name, token_port, target_port, route);
            run_cli(&[
                "profile",
                "import",
                "-f",
                profile.path().to_str().expect("UTF-8 profile path"),
            ])
            .await?;
            run_cli(&[
                "provider",
                "create",
                "--name",
                name,
                "--type",
                name,
                "--credential",
                &format!("subject_token=stored-{route}"),
            ])
            .await?;
        }
        let mut sandbox = SandboxGuard::create_keep_with_args(
            &["--provider", &names[0], "--provider", &names[1]],
            &["sh", "-lc", &sandbox_script()],
            "token-server-ready",
        )
        .await?;
        grants.fail_next_b.store(true, Ordering::SeqCst);
        // The supervisor mediates direct workload connections as CONNECT.
        // HTTPConnection keeps one client socket for the successful A/B/A run.
        let script = format!(
            r#"import http.client
host = 'host.openshell.internal'
port = {target_port}
first = http.client.HTTPConnection(host, port, timeout=10)
first.request('GET', '/b/failure', headers={{'Authorization': 'Bearer stale-value'}})
failed = first.getresponse()
failed.read()
assert failed.status == 502, 'the controlled grant failure must return 502'
assert failed.will_close, 'the failed tunnel must close'
first.close()
recovered = http.client.HTTPConnection(host, port, timeout=10)
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
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            sandbox.exec(&["python3", "-c", &script]),
        )
        .await
        .map_err(|_| "route workload timed out".to_owned());
        sandbox.cleanup().await;
        output?
    }
    .await;
    for name in &names {
        run_cli_ignore_error(&["provider", "delete", name, "--yes"]).await;
        run_cli_ignore_error(&["profile", "delete", name, "--yes"]).await;
    }
    let target_result = _target.drain().await;
    _token_endpoint.shutdown().await;
    _provider_spiffe.shutdown().await;
    _gateway_spiffe.shutdown().await;
    let output = result.expect("gateway-configured route workload succeeds");
    target_result.expect("route target observes EOF on every accepted connection");
    assert!(output.contains("route-recovery-a-b-a-ok"));
    let requests = observed.lock().expect("route target observations lock");
    assert_eq!(requests.len(), 3, "failed grant must not reach the target");
    assert_eq!(
        observed_bytes.load(Ordering::Relaxed),
        requests.iter().map(|request| request.bytes).sum::<usize>(),
        "no partial failed request reached the target"
    );
    for ((request, path), token) in requests
        .iter()
        .zip(["/a/first", "/b/second", "/a/third"])
        .zip(["Bearer final-a", "Bearer final-b", "Bearer final-a"])
    {
        assert_eq!(request.path, path);
        assert_eq!(
            request.connection, requests[0].connection,
            "upstream connection reused"
        );
        assert_eq!(
            request.authorization.len(),
            1,
            "one Authorization replacement"
        );
        assert!(
            request.authorization[0] == token,
            "the admitted path owns the injected token"
        );
    }
    assert_eq!(
        *grants
            .supervisor_requests
            .lock()
            .expect("route grant requests lock"),
        ["b", "a", "b"],
        "failed grant retries; repeated A uses its own cached token"
    );
}
