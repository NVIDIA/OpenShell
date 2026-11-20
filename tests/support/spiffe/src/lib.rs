// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE Workload APIs for suites whose gateway and supervisors fetch
//! JWT-SVIDs from Workload APIs the test runs.
//!
//! The environment points the gateway's Workload API socket and the driver's
//! `provider_spiffe_workload_api_socket` at addresses the test listens on, and
//! publishes them in `OPENSHELL_TEST_SPIFFE_*` variables. Under
//! `openshell-test-runner`, the tmachine `<podman base>-spiffe` environments
//! do that (`tests/tmachine/ansible/playbooks/spiffe.yaml`); against your own
//! deployment, set them yourself:
//!
//! | Variable | Example |
//! |---|---|
//! | `OPENSHELL_TEST_SPIFFE_GATEWAY_LISTEN` | `/var/lib/openshell-test/spiffe/gateway.sock` |
//! | `OPENSHELL_TEST_SPIFFE_SUPERVISOR_LISTEN` | `0.0.0.0:17690` |
//!
//! Both Workload APIs sign with one fixture key and serve its bundle for
//! [`TRUST_DOMAIN`]. Every supervisor gets [`SUPERVISOR_SUBJECT`]: suites
//! test credential isolation with distinct providers and audiences, not
//! SPIRE attestation. A missing variable fails the test; it never skips it.
//! Tests that start the Workload APIs can't run at the same time, since they
//! bind the same addresses.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use futures_util::future::BoxFuture;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;
use testkit::{Error, Result, ResultExt as _};
use tokio::net::{TcpListener, UnixListener};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::body::Body as TonicBody;
use tonic::codegen::{Body, http};
use tonic::{Request, Response, Status};

pub const GATEWAY_LISTEN_ENV: &str = "OPENSHELL_TEST_SPIFFE_GATEWAY_LISTEN";
pub const SUPERVISOR_LISTEN_ENV: &str = "OPENSHELL_TEST_SPIFFE_SUPERVISOR_LISTEN";

pub const TRUST_DOMAIN: &str = "openshell-e2e.test";
/// The `iss` of every JWT-SVID.
pub const ISSUER: &str = "https://spiffe.openshell-e2e.test";
/// The SPIFFE ID the gateway's Workload API issues.
pub const GATEWAY_SUBJECT: &str = "spiffe://openshell-e2e.test/openshell/gateway";
/// The SPIFFE ID the supervisors' Workload API issues.
pub const SUPERVISOR_SUBJECT: &str = "spiffe://openshell-e2e.test/openshell/sandbox/e2e";
const KEY_ID: &str = "openshell-e2e-test-key";

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

/// The gateway's and the supervisors' Workload APIs. They stop when dropped.
pub struct WorkloadApis {
    gateway: Server,
    supervisor: Server,
}

impl WorkloadApis {
    /// Serve the gateway's Workload API on the Unix socket
    /// [`GATEWAY_LISTEN_ENV`] names, and the supervisors' on the TCP address
    /// [`SUPERVISOR_LISTEN_ENV`] names.
    pub async fn start() -> Result<Self> {
        let socket = PathBuf::from(required(GATEWAY_LISTEN_ENV)?);
        let listen = required(SUPERVISOR_LISTEN_ENV)?;
        let addr: SocketAddr = listen
            .parse()
            .map_err(|error| Error::msg(format!("{SUPERVISOR_LISTEN_ENV}={listen}: {error}")))?;

        // A socket a stopped test left behind would make the bind fail.
        match std::fs::remove_file(&socket) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).context(format!("remove {}", socket.display()));
            }
            _ => {}
        }
        let unix = UnixListener::bind(&socket).context(format!(
            "bind the gateway Workload API on {}",
            socket.display()
        ))?;
        // The gateway may run as another user.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o777)).context(
            format!("make {} reachable to the gateway", socket.display()),
        )?;
        let gateway = Server::spawn(
            WorkloadApi::new(GATEWAY_SUBJECT)?,
            UnixListenerStream::new(unix),
            Some(socket),
        );

        let tcp = TcpListener::bind(addr)
            .await
            .context(format!("bind the supervisors' Workload API on {addr}"))?;
        let supervisor = Server::spawn(
            WorkloadApi::new(SUPERVISOR_SUBJECT)?,
            TcpListenerStream::new(tcp),
            None,
        );
        Ok(Self {
            gateway,
            supervisor,
        })
    }

    /// Stop listening, so the next test can bind the addresses.
    pub async fn shutdown(self) {
        let Self {
            gateway,
            supervisor,
        } = self;
        gateway.shutdown().await;
        supervisor.shutdown().await;
    }
}

/// Whether `token` is a JWT-SVID these Workload APIs issued to a supervisor
/// for `audience`, with a valid signature and lifetime.
pub fn verify_supervisor_svid(token: &str, audience: &str) -> bool {
    let Ok(key) = decoding_key() else {
        return false;
    };
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[audience]);
    validation.sub = Some(SUPERVISOR_SUBJECT.to_string());
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
    openshell_crypto::jwt::decode::<serde_json::Value>(token, &key, &validation)
        .is_ok_and(|verified| verified.header.kid.as_deref() == Some(KEY_ID))
}

/// Whether `value` contains a JWT-SVID these Workload APIs could have issued,
/// judged by its issuer and without checking the signature. Use it to prove
/// that no SVID reached a place it must not.
pub fn contains_svid(value: &str) -> bool {
    value
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .filter_map(|word| {
            let mut parts = word.split('.');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(_), Some(payload), Some(_), None) => Some(payload),
                _ => None,
            }
        })
        .filter_map(|payload| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload.trim_end_matches('='))
                .ok()
        })
        .filter_map(|claims| serde_json::from_slice::<serde_json::Value>(&claims).ok())
        .any(|claims| claims["iss"] == ISSUER)
}

fn required(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::msg(format!(
                "{name} is not set; this suite needs a gateway and supervisors that use the test's SPIFFE Workload APIs (see the spiffe-support crate docs)"
            ))
        })
}

fn modulus() -> Result<Vec<u8>> {
    hex::decode(TEST_RSA_MODULUS_HEX)
        .map_err(|error| Error::msg(format!("decode the fixture RSA modulus: {error}")))
}

fn decoding_key() -> Result<DecodingKey> {
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus()?);
    DecodingKey::from_rsa_components(&n, "AQAB")
        .map_err(|error| Error::msg(format!("read the fixture verification key: {error}")))
}

fn jwks() -> Result<Vec<u8>> {
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus()?);
    serde_json::to_vec(&json!({
        "keys": [{"kty": "RSA", "kid": KEY_ID, "use": "sig", "alg": "RS256", "n": n, "e": "AQAB"}]
    }))
    .context("serialize the fixture JWKS")
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            elapsed.as_secs().try_into().unwrap_or(i64::MAX)
        })
}

struct Server {
    task: tokio::task::JoinHandle<()>,
    socket: Option<PathBuf>,
}

impl Server {
    fn spawn<S, IO, E>(api: WorkloadApi, incoming: S, socket: Option<PathBuf>) -> Self
    where
        S: tokio_stream::Stream<Item = std::result::Result<IO, E>> + Send + 'static,
        IO: tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + tonic::transport::server::Connected
            + Unpin
            + Send
            + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let task = tokio::spawn(async move {
            if let Err(error) = tonic::transport::Server::builder()
                .add_service(WorkloadApiServer(Arc::new(api)))
                .serve_with_incoming(incoming)
                .await
            {
                eprintln!("SPIFFE Workload API fixture failed: {error}");
            }
        });
        Self { task, socket }
    }

    async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(socket) = &self.socket {
            let _ = std::fs::remove_file(socket);
        }
    }
}

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

/// A Workload API that issues RS256 JWT-SVIDs for one subject and serves the
/// bundle that verifies them.
struct WorkloadApi {
    subject: &'static str,
    jwks: Vec<u8>,
    encoding_key: EncodingKey,
}

impl WorkloadApi {
    fn new(subject: &'static str) -> Result<Self> {
        Ok(Self {
            subject,
            jwks: jwks()?,
            encoding_key: EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
                .map_err(|error| Error::msg(format!("read the fixture signing key: {error}")))?,
        })
    }

    fn jwt_svid(&self, audience: &[String]) -> std::result::Result<String, Status> {
        let now = unix_timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KEY_ID.to_string());
        let claims = json!({
            "iss": ISSUER,
            "sub": self.subject,
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
        });
        openshell_crypto::jwt::encode(&header, &claims, &self.encoding_key)
            .map_err(|error| Status::internal(format!("sign JWT-SVID: {error}")))
    }
}

#[derive(Clone)]
struct WorkloadApiServer(Arc<WorkloadApi>);

impl tonic::server::NamedService for WorkloadApiServer {
    const NAME: &'static str = "SpiffeWorkloadAPI";
}

#[derive(Clone)]
struct FetchJwtsvid(Arc<WorkloadApi>);

impl tonic::server::UnaryService<JwtsvidRequest> for FetchJwtsvid {
    type Response = JwtsvidResponse;
    type Future = BoxFuture<'static, std::result::Result<Response<Self::Response>, Status>>;

    fn call(&mut self, request: Request<JwtsvidRequest>) -> Self::Future {
        let api = Arc::clone(&self.0);
        Box::pin(async move {
            let svid = api.jwt_svid(&request.into_inner().audience)?;
            Ok(Response::new(JwtsvidResponse {
                svids: vec![Jwtsvid {
                    spiffe_id: api.subject.to_string(),
                    svid,
                    hint: String::new(),
                }],
            }))
        })
    }
}

#[derive(Clone)]
struct FetchJwtBundles(Arc<WorkloadApi>);

impl tonic::server::ServerStreamingService<JwtBundlesRequest> for FetchJwtBundles {
    type Response = JwtBundlesResponse;
    type ResponseStream = ReceiverStream<std::result::Result<JwtBundlesResponse, Status>>;
    type Future = BoxFuture<'static, std::result::Result<Response<Self::ResponseStream>, Status>>;

    fn call(&mut self, _request: Request<JwtBundlesRequest>) -> Self::Future {
        let api = Arc::clone(&self.0);
        Box::pin(async move {
            let bundles = HashMap::from([(TRUST_DOMAIN.to_string(), api.jwks.clone())]);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(Ok(JwtBundlesResponse { bundles }))
                .await
                .map_err(|error| Status::internal(format!("send bundle: {error}")))?;
            Ok(Response::new(ReceiverStream::new(rx)))
        })
    }
}

impl<B> tower::Service<http::Request<B>> for WorkloadApiServer
where
    B: Body + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
{
    type Response = http::Response<TonicBody>;
    type Error = Infallible;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let api = Arc::clone(&self.0);
        match request.uri().path() {
            "/SpiffeWorkloadAPI/FetchJWTSVID" => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.unary(FetchJwtsvid(api), request).await)
            }),
            "/SpiffeWorkloadAPI/FetchJWTBundles" => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.server_streaming(FetchJwtBundles(api), request).await)
            }),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_svids_verify_for_their_audience_only() {
        let supervisor = WorkloadApi::new(SUPERVISOR_SUBJECT).unwrap();
        let svid = supervisor.jwt_svid(&["aud-a".to_string()]).unwrap();
        assert!(verify_supervisor_svid(&svid, "aud-a"));
        assert!(!verify_supervisor_svid(&svid, "aud-b"));

        let gateway = WorkloadApi::new(GATEWAY_SUBJECT).unwrap();
        let svid = gateway.jwt_svid(&["aud-a".to_string()]).unwrap();
        assert!(!verify_supervisor_svid(&svid, "aud-a"));
    }

    #[test]
    fn finds_svids_in_text() {
        let svid = WorkloadApi::new(SUPERVISOR_SUBJECT)
            .unwrap()
            .jwt_svid(&["aud".to_string()])
            .unwrap();
        assert!(contains_svid(&format!("X-Workload-Jwt: {svid}\r\n")));
        assert!(!contains_svid("a.b.c and no token"));
    }
}
