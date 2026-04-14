//! GRPC plumbing to interact with Docker's buildkit client
#![cfg(feature = "buildkit_providerless")]
#![allow(dead_code)]

/// End-user buildkit build functions
pub mod build;
/// A package of GRPC buildkit connection implementations
pub mod driver;
/// Errors for the GRPC modules
pub mod error;
/// End-user buildkit export functions
pub mod export;
mod fsutil;
/// Internal interfaces to convert types for GRPC communication
pub(crate) mod io;
/// End-user buildkit registry functions
pub mod registry;
mod ssh;

use crate::auth::DockerCredentials;
use crate::docker::BodyType;
use crate::health::health_check_response::ServingStatus;
use crate::health::health_server::Health;
use crate::health::{HealthCheckRequest, HealthCheckResponse};
use crate::moby::filesync::v1::auth_server::Auth;
use crate::moby::filesync::v1::file_send_server::FileSend;
use crate::moby::filesync::v1::{
    BytesMessage as FileSyncBytesMessage, CredentialsRequest, CredentialsResponse,
    FetchTokenRequest, FetchTokenResponse, GetTokenAuthorityRequest, GetTokenAuthorityResponse,
    VerifyTokenAuthorityRequest, VerifyTokenAuthorityResponse,
};
use crate::moby::upload::v1::upload_server::{Upload, UploadServer};
use crate::moby::upload::v1::BytesMessage as UploadBytesMessage;
use std::io::Write;

use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use bollard_buildkit_proto::fsutil::types::packet::PacketType;
use bollard_buildkit_proto::fsutil::types::Packet;
use bollard_buildkit_proto::health::{HealthListRequest, HealthListResponse};
use bollard_buildkit_proto::moby::buildkit::secrets::v1::secrets_server::{Secrets, SecretsServer};
use bollard_buildkit_proto::moby::buildkit::secrets::v1::{GetSecretRequest, GetSecretResponse};
use bollard_buildkit_proto::moby::filesync::packet::file_send_server::{
    FileSend as FileSendPacket, FileSendServer as FileSendPacketServer,
};
use bollard_buildkit_proto::moby::filesync::v1::auth_server::AuthServer;
use bollard_buildkit_proto::moby::filesync::v1::file_send_server::FileSendServer;
use bollard_buildkit_proto::moby::sshforward::v1::ssh_server::{Ssh, SshServer};
use bollard_buildkit_proto::moby::sshforward::v1::{CheckAgentRequest, CheckAgentResponse};
use bytes::Bytes;
use error::GrpcSshError;
use futures_core::Stream;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use log::trace;
use rustls::ALL_VERSIONS;
use serde_derive::Deserialize;
use ssh::SshAgentPacketDecoder;
use tokio::sync::mpsc;
use tokio_util::codec::FramedRead;
use tokio_util::io::{ReaderStream, StreamReader};
use tonic::server::NamedService;
use tonic::{Code, Request, Response, Status, Streaming};

use futures_util::{StreamExt, TryFutureExt};
use tokio::io::AsyncWriteExt;

use http::request::Builder;
use hyper::Method;
use std::future::Future;
use tower_service::Service;

use self::error::GrpcAuthError;
use self::io::GrpcTransport;

// Datetime handling with cfg guards for time/chrono feature parity
// BuildKit OAuth requires either 'time' or 'chrono' feature for RFC3339 parsing
#[cfg(not(any(feature = "time", feature = "chrono")))]
compile_error!(
    "BuildKit requires either 'time' or 'chrono' feature to be enabled for OAuth authentication"
);

#[cfg(feature = "time")]
type GrpcDateTime = time::OffsetDateTime;

#[cfg(all(feature = "chrono", not(feature = "time")))]
type GrpcDateTime = chrono::DateTime<chrono::Utc>;

#[cfg(feature = "time")]
fn grpc_now() -> GrpcDateTime {
    time::OffsetDateTime::now_utc()
}

#[cfg(all(feature = "chrono", not(feature = "time")))]
fn grpc_now() -> GrpcDateTime {
    chrono::Utc::now()
}

#[cfg(feature = "time")]
fn grpc_timestamp(dt: &GrpcDateTime) -> i64 {
    dt.unix_timestamp()
}

#[cfg(all(feature = "chrono", not(feature = "time")))]
fn grpc_timestamp(dt: &GrpcDateTime) -> i64 {
    dt.timestamp()
}

const MAX_SECRET_SIZE: u64 = 500 * 1024; // 500KB

#[derive(Debug)]
pub(crate) enum GrpcServer {
    Auth(AuthServer<AuthProvider>),
    Upload(UploadServer<UploadProvider>),
    FileSend(FileSendServer<FileSendImpl>),
    FileSendPacket(FileSendPacketServer<FileSendPacketImpl>),
    Secrets(SecretsServer<SecretProvider>),
    Ssh(SshServer<SshProvider>),
}

impl GrpcServer {
    pub(crate) fn append(
        self,
        builder: tonic::transport::server::Router,
    ) -> tonic::transport::server::Router {
        match self {
            GrpcServer::Auth(auth_server) => builder.add_service(auth_server),
            GrpcServer::Upload(upload_server) => builder.add_service(upload_server),
            GrpcServer::FileSend(file_send_server) => builder.add_service(file_send_server),
            GrpcServer::FileSendPacket(file_send_packet_server) => {
                builder.add_service(file_send_packet_server)
            }
            GrpcServer::Secrets(secret_server) => builder.add_service(secret_server),
            GrpcServer::Ssh(ssh_server) => builder.add_service(ssh_server),
        }
    }

    /// Internal name published as part of the GRPC communication
    pub fn names(&self) -> Vec<String> {
        match self {
            GrpcServer::Auth(_auth_server) => {
                vec![
                    format!("/{}/credentials", AuthServer::<AuthProvider>::NAME),
                    format!("/{}/fetch_token", AuthServer::<AuthProvider>::NAME),
                ]
            }
            GrpcServer::Upload(_upload_server) => {
                vec![format!("/{}/pull", UploadServer::<UploadProvider>::NAME)]
            }
            GrpcServer::FileSend(_file_send_server) => {
                vec![format!(
                    "/{}/diffcopy",
                    FileSendServer::<FileSendImpl>::NAME
                )]
            }
            GrpcServer::FileSendPacket(_file_send_packet_server) => {
                vec![format!(
                    "/{}/diffcopy",
                    FileSendPacketServer::<FileSendPacketImpl>::NAME
                )]
            }
            GrpcServer::Secrets(_secret_server) => {
                vec![format!(
                    "/{}/GetSecret",
                    SecretsServer::<SecretProvider>::NAME
                )]
            }
            GrpcServer::Ssh(_ssh_server) => {
                vec![
                    format!("/{}/CheckAgent", SshServer::<SshProvider>::NAME),
                    format!("/{}/ForwardAgent", SshServer::<SshProvider>::NAME),
                ]
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct HealthServerImpl {
    service_map: HashMap<String, ServingStatus>,
    shutdown: bool,
}

impl HealthServerImpl {
    pub fn new() -> Self {
        let mut service_map = HashMap::new();
        service_map.insert(String::from(""), ServingStatus::Serving);
        Self {
            service_map,
            shutdown: false,
        }
    }

    pub fn shutdown(mut self) {
        self.shutdown = true;
        for (_, val) in self.service_map.iter_mut() {
            *val = ServingStatus::NotServing;
        }
    }
}

#[tonic::async_trait]
impl Health for HealthServerImpl {
    type WatchStream = Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send>>;
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        trace!("Received GRPC Health Request: {:#?}", request);
        if let Some(status) = self.service_map.get(&request.get_ref().service) {
            Ok(Response::new(HealthCheckResponse {
                status: *status as i32,
            }))
        } else {
            Err(Status::new(Code::NotFound, "unknown service"))
        }
    }

    async fn list(
        &self,
        _: tonic::Request<HealthListRequest>,
    ) -> Result<tonic::Response<HealthListResponse>, tonic::Status> {
        unimplemented!()
    }

    #[allow(clippy::diverging_sub_expression)]
    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        unimplemented!();
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FileSendImpl {
    pub(crate) dest: PathBuf,
}

impl FileSendImpl {
    pub fn new(dest: &Path) -> Self {
        Self {
            dest: dest.to_owned(),
        }
    }
}

#[tonic::async_trait]
impl FileSend for FileSendImpl {
    type DiffCopyStream = Pin<Box<dyn Stream<Item = Result<FileSyncBytesMessage, Status>> + Send>>;
    async fn diff_copy(
        &self,
        request: Request<Streaming<FileSyncBytesMessage>>,
    ) -> Result<Response<Self::DiffCopyStream>, Status> {
        trace!("Protobuf FileSend diff_copy triggered: {:#?}", request);

        let path = self.dest.as_path();

        let mut in_stream = request.into_inner();

        let mut file = tokio::fs::File::create(path).await?;

        while let Some(result) = in_stream.next().await {
            match result {
                Ok(v) => {
                    file.write_all(&v.data).await?;
                }
                Err(err) => return Err(err),
            }
        }

        Ok(Response::new(Box::pin(futures_util::stream::empty())))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FileSendPacketImpl {
    pub(crate) dest: PathBuf,
}

impl FileSendPacketImpl {
    pub fn new(dest: &Path) -> Self {
        Self {
            dest: dest.to_owned(),
        }
    }
}

#[tonic::async_trait]
impl FileSendPacket for FileSendPacketImpl {
    type DiffCopyStream = Pin<Box<dyn Stream<Item = Result<Packet, Status>> + Send>>;
    async fn diff_copy(
        &self,
        request: Request<Streaming<Packet>>,
    ) -> Result<Response<Self::DiffCopyStream>, Status> {
        let base_path = self.dest.clone();
        std::fs::create_dir_all(&base_path).unwrap();
        trace!(
            "Protobuf FileSend (packet) diff_copy triggered: {:#?}",
            request
        );

        let mut in_stream = request.into_inner();

        // protocol reference: https://github.com/tonistiigi/fsutil/blob/91a3fc46842c58b62dd4630b688662842364da49/receive.go#L1-L15
        let out_stream = async_stream::try_stream! {
            let mut file_id = 0;
            let mut stats = HashMap::new();
            let mut received_all_stats = false;

            while let Some(Ok(packet)) = in_stream.next().await {
                match PacketType::try_from(packet.r#type) {
                    Ok(PacketType::PacketStat) => {
                        if let Some(stat) = packet.stat {
                            if fsutil::FileMode::Type.bits() & stat.mode == 0 {
                                std::fs::File::create(base_path.join(&stat.path)).unwrap();
                                stats.insert(file_id, stat);
                            } else if fsutil::FileMode::Dir.bits() & stat.mode != 0 {
                                std::fs::create_dir(base_path.join(stat.path)).unwrap()
                            };
                            file_id += 1;
                        } else {
                            received_all_stats = true;
                            for id in stats.keys() {
                                yield Packet {
                                    r#type: PacketType::PacketReq.into(),
                                    stat: None,
                                    id: *id,
                                    data: vec![]
                                };
                            }
                        }
                    },
                    Ok(PacketType::PacketReq) => panic!("server should not request"),
                    Ok(PacketType::PacketData) => {
                        if packet.data.is_empty() {
                            // all data for file has been received
                            stats.remove(&packet.id);
                        } else {
                            let stat = stats.get(&packet.id).unwrap();
                            let file_path = base_path.join(stat.path.clone());
                            std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
                            let mut file = OpenOptions::new()
                                .append(true)
                                .open(file_path)
                                .unwrap();
                            file.write_all(packet.data.as_slice()).unwrap();
                        }

                        if stats.is_empty() && received_all_stats {
                            yield Packet {
                                r#type: PacketType::PacketFin.into(),
                                stat: None,
                                id: 0,
                                data: vec![]
                            };
                        }
                    },
                    Ok(PacketType::PacketFin) => return,
                    Ok(PacketType::PacketErr) => panic!("{}", String::from_utf8(packet.data).unwrap()),
                    Err(_) => panic!("unhandled packet type")
                }
            }
        };

        Ok(Response::new(Box::pin(out_stream)))
    }
}

#[derive(Default, Debug)]
pub(crate) struct UploadProvider {
    pub(crate) store: HashMap<String, Vec<u8>>,
}

impl UploadProvider {
    pub(crate) fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub(crate) fn add(&mut self, reader: Vec<u8>) -> String {
        let id = new_id();
        let key = format!("http://buildkit-session/{}", id);

        self.store.insert(format!("/{}", id), reader);
        key
    }
}

#[tonic::async_trait]
impl Upload for UploadProvider {
    type PullStream = Pin<Box<dyn Stream<Item = Result<UploadBytesMessage, Status>> + Send>>;

    async fn pull(
        &self,
        request: Request<Streaming<UploadBytesMessage>>,
    ) -> Result<Response<Self::PullStream>, Status> {
        let key = request
            .metadata()
            .get("urlpath")
            .and_then(|key| key.to_str().ok())
            .map(String::from)
            .and_then(|str| self.store.get(&str));
        if let Some(read) = key {
            let out_stream =
                futures_util::stream::once(futures_util::future::ok(UploadBytesMessage {
                    data: read.to_owned(),
                }));

            Ok(Response::new(Box::pin(out_stream)))
        } else {
            Err(Status::invalid_argument(
                "invalid 'urlpath' in uploadprovider request",
            ))
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct AuthProvider {
    auth_config_cache: HashMap<String, DockerCredentials>,
    registry_token: Option<String>,
    token_seeds: HashMap<String, Bytes>,
}

const DEFAULT_TOKEN_EXPIRATION: i64 = 60;
const DOCKER_HUB_REGISTRY_HOST: &str = "https://index.docker.io/v1/";
const DOCKER_HUB_CONFIG_FILE_KEY: &str = "registry-1.docker.io";

enum TokenExpiry {
    DEFAULT,
    EXPIRES(i64),
}

struct TokenOptions {
    realm: String,
    service: String,
    scopes: Vec<String>,
    username: String,
    secret: String,
    fetch_refresh_token: bool,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    issued_at: GrpcDateTime,
    scope: String,
}

impl AuthProvider {
    pub(crate) fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub(crate) fn set_docker_credentials(
        &mut self,
        host: &str,
        docker_credentials: DockerCredentials,
    ) {
        self.auth_config_cache
            .insert(String::from(host), docker_credentials);
    }

    fn get_auth_config(&self, mut host: &str) -> Option<DockerCredentials> {
        if host == DOCKER_HUB_REGISTRY_HOST {
            host = DOCKER_HUB_CONFIG_FILE_KEY;
        }

        self.auth_config_cache
            .get(host)
            .map(DockerCredentials::to_owned)
    }

    fn to_token_response(
        &self,
        token: &str,
        issued_at: GrpcDateTime,
        expires: TokenExpiry,
    ) -> FetchTokenResponse {
        let expires = match expires {
            TokenExpiry::DEFAULT => DEFAULT_TOKEN_EXPIRATION,
            TokenExpiry::EXPIRES(expiry) => expiry,
        };

        FetchTokenResponse {
            token: String::from(token),
            expires_in: expires,
            issued_at: grpc_timestamp(&issued_at),
        }
    }

    fn get_credentials(&self, host: &str) -> Result<CredentialsResponse, Status> {
        if let Some(ac) = self.get_auth_config(host) {
            match ac {
                DockerCredentials {
                    identitytoken: Some(identitytoken),
                    ..
                } => Ok(CredentialsResponse {
                    username: String::new(),
                    secret: identitytoken,
                }),
                DockerCredentials {
                    username: Some(username),
                    password: Some(password),
                    ..
                } => Ok(CredentialsResponse {
                    username,
                    secret: password,
                }),
                DockerCredentials { .. } => {
                    Err(Status::unknown("Invalid DockerCredentials provided"))
                }
            }
        } else {
            Ok(CredentialsResponse {
                ..Default::default()
            })
        }
    }

    fn ssl_client(
    ) -> Result<Client<hyper_rustls::HttpsConnector<HttpConnector>, BodyType>, GrpcAuthError> {
        let mut root_store = rustls::RootCertStore::empty();

        #[cfg(not(any(feature = "test_ssl", feature = "webpki")))]
        let native_certs = rustls_native_certs::load_native_certs();

        #[cfg(not(any(feature = "test_ssl", feature = "webpki")))]
        if native_certs.errors.is_empty() {
            for cert in native_certs.certs {
                root_store
                    .add(cert)
                    .map_err(|err| GrpcAuthError::RustTlsError { err })?
            }
        } else {
            return Err(GrpcAuthError::RustlsNativeCertsErrors {
                errors: native_certs.errors,
            });
        }
        #[cfg(any(feature = "test_ssl", feature = "webpki"))]
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build();

        let client_builder = Client::builder(TokioExecutor::new());
        let client = client_builder.build(https_connector);

        Ok(client)
    }

    async fn fetch_token_with_oauth(
        &self,
        opts: &TokenOptions,
    ) -> Result<OAuthTokenResponse, GrpcAuthError> {
        let mut form = vec![];
        form.push(("client_id", "bollard-client"));
        let scopes = opts.scopes.join(" ");
        if !opts.scopes.is_empty() {
            form.push(("scope", &scopes));
        }
        form.push(("service", &opts.service));
        if opts.username.is_empty() {
            form.push(("grant_type", "refresh_token"));
            form.push(("refresh_token", &opts.secret));
        } else {
            form.push(("grant_type", "password"));
            form.push(("username", &opts.username));
            form.push(("password", &opts.secret));
        }
        if opts.fetch_refresh_token {
            form.push(("access_type", "offline"));
        }

        let params = serde_urlencoded::to_string(form)?;

        let client = Self::ssl_client()?;

        let full_uri = format!("{}?{}", opts.realm, &params);
        let request_uri: hyper::Uri = full_uri.try_into()?;
        let request =
            hyper::Request::post(request_uri).body(BodyType::Left(Full::new(Bytes::new())))?;

        let response = client.request(request).await?;

        let status = response.status().as_u16();
        if !(200..400).contains(&status) {
            // return custom error
            return Err(GrpcAuthError::BadRegistryResponse {
                status_code: status,
            });
        }

        let bytes = response.into_body().collect().await.unwrap().to_bytes();

        let oauth_token = serde_json::from_slice::<OAuthTokenResponse>(&bytes)?;

        Ok(oauth_token)
    }
}

#[tonic::async_trait]
impl Auth for AuthProvider {
    async fn credentials(
        &self,
        request: Request<CredentialsRequest>,
    ) -> Result<Response<CredentialsResponse>, Status> {
        let host = request.get_ref().host.as_ref();

        Ok(Response::new(self.get_credentials(host)?))
    }

    async fn fetch_token(
        &self,
        request: Request<FetchTokenRequest>,
    ) -> Result<Response<FetchTokenResponse>, Status> {
        let FetchTokenRequest {
            client_id: _,
            host,
            realm,
            service,
            scopes,
        } = request.get_ref();

        let creds = self.get_credentials(host)?;

        // check for statically configured bearer token
        if let Some(token) = self.registry_token.as_ref() {
            Ok(Response::new(self.to_token_response(
                token,
                grpc_now(),
                TokenExpiry::DEFAULT,
            )))
        } else {
            let to = TokenOptions {
                realm: String::clone(realm),
                service: String::clone(service),
                scopes: Vec::clone(scopes),
                username: creds.username,
                secret: creds.secret,
                fetch_refresh_token: false,
            };

            match self.fetch_token_with_oauth(&to).await {
                Ok(res) => Ok(Response::new(self.to_token_response(
                    &res.access_token,
                    res.issued_at,
                    TokenExpiry::EXPIRES(res.expires_in),
                ))),
                Err(e) => Err(Status::from_error(Box::new(e))),
            }
        }
    }

    #[allow(clippy::diverging_sub_expression)]
    async fn get_token_authority(
        &self,
        _request: Request<GetTokenAuthorityRequest>,
    ) -> Result<Response<GetTokenAuthorityResponse>, Status> {
        return Err(Status::unavailable("client-side authentication disabled"));
    }

    #[allow(clippy::diverging_sub_expression)]
    async fn verify_token_authority(
        &self,
        _request: Request<VerifyTokenAuthorityRequest>,
    ) -> Result<Response<VerifyTokenAuthorityResponse>, Status> {
        return Err(Status::unavailable("client-side authentication disabled"));
    }
}

#[derive(Default, Debug)]
pub(crate) struct SecretProvider {
    pub(crate) store: HashMap<String, build::SecretSource>,
}

impl SecretProvider {
    pub(crate) fn new(store: HashMap<String, build::SecretSource>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl Secrets for SecretProvider {
    async fn get_secret(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<GetSecretResponse>, Status> {
        let id: &str = request.get_ref().id.as_ref();

        match self.store.get(id) {
            Some(build::SecretSource::File(path)) if path.exists() => {
                match tokio::fs::metadata(&path).await {
                    Ok(metadata) => {
                        if metadata.len() > MAX_SECRET_SIZE {
                            return Err(Status::failed_precondition(format!(
                                "invalid secret size {}",
                                metadata.len(),
                            )));
                        }
                    }
                    Err(e) => return Err(Status::from_error(e.into())),
                }

                match tokio::fs::read(path).await {
                    Ok(contents) => Ok(Response::new(GetSecretResponse { data: contents })),
                    Err(e) => Err(Status::from_error(e.into())),
                }
            }
            Some(build::SecretSource::File(path)) => Err(Status::failed_precondition(format!(
                "path does not exist '{:?}'",
                path
            ))),
            Some(build::SecretSource::Env(v)) if env::var_os(v).is_some() => {
                trace!("Getting secret env var {}", v);
                Ok(Response::new(GetSecretResponse {
                    data: env::var_os(v).unwrap().as_encoded_bytes().to_owned(),
                }))
            }
            Some(build::SecretSource::Env(v)) => Err(Status::failed_precondition(format!(
                "env var '{}' does not exist",
                v
            ))),

            None => return Err(Status::not_found("secret missing ID")),
        }
    }
}

#[derive(Default, Debug)]
pub(crate) struct SshProvider {
    src: HashMap<String, PathBuf>,
}

struct SshSource {
    agent: (),
    socket: (),
}

impl SshProvider {
    pub(crate) fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[tonic::async_trait]
impl Ssh for SshProvider {
    async fn check_agent(
        &self,
        request: Request<CheckAgentRequest>,
    ) -> Result<Response<CheckAgentResponse>, Status> {
        let id: &str = request.get_ref().id.as_ref();
        if !id.is_empty() && id != "default" {
            return Err(Status::from(std::io::Error::other(
                GrpcSshError::SshAgentSocketInit(String::from("This buildkit server only handles sshforwarding to the ssh-agent running on environment variable SSH_AUTH_SOCK on the host")),
            )));
        }

        if env::var("SSH_AUTH_SOCK").is_err() {
            return Err(Status::from(std::io::Error::other(
                GrpcSshError::SshAgentSocketInit(String::from("The environment variable SSH_AUTH_SOCK is missing, and is required for the sshforwarding functionality")),
            )));
        }
        Ok(Response::new(CheckAgentResponse {}))
    }

    /// Server streaming response type for the ForwardAgent method.
    type ForwardAgentStream = Pin<
        Box<
            dyn Stream<
                    Item = Result<
                        bollard_buildkit_proto::moby::sshforward::v1::BytesMessage,
                        Status,
                    >,
                > + Send
                + 'static,
        >,
    >;

    #[cfg(not(windows))]
    async fn forward_agent(
        &self,
        request: Request<Streaming<bollard_buildkit_proto::moby::sshforward::v1::BytesMessage>>,
    ) -> Result<Response<Self::ForwardAgentStream>, Status> {
        let ssh_env_sock = env::var("SSH_AUTH_SOCK").expect("missing SSH_AUTH_SOCK");
        let sock = tokio::net::UnixStream::connect(&ssh_env_sock).await?;

        let (tx, rx) = mpsc::channel::<Result<Bytes, Status>>(100);
        let rx_stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(
            |res: Result<Bytes, _>| match res {
                Ok(v) => Ok(bollard_buildkit_proto::moby::sshforward::v1::BytesMessage {
                    data: v.to_vec(),
                }),
                Err(e) => Err(Status::from_error(e.into())),
            },
        );

        let in_stream = request.into_inner();
        let mut in_framed = FramedRead::new(
            StreamReader::new(in_stream.map(|res| match res {
                Ok(bollard_buildkit_proto::moby::sshforward::v1::BytesMessage { data: bytes }) => {
                    Ok(Bytes::from(bytes))
                }
                Err(e) => Err(std::io::Error::other(e)),
            })),
            SshAgentPacketDecoder::new(),
        );

        let (sock_read, sock_write) = sock.into_split();

        let output_reader = ReaderStream::new(sock_read).map(|res| match res {
            Ok(v) => {
                Ok(bollard_buildkit_proto::moby::sshforward::v1::BytesMessage { data: v.to_vec() })
            }
            Err(e) => Err(Status::from_error(e.into())),
        });

        tokio::spawn(async move {
            if let Err(e) = sock_write.writable().await {
                tx.send(Err(Status::from(e)))
                    .await
                    .unwrap_or_else(|e| log::error!("ssh agent socket not writable: {e}"));
                panic!("ssh agent socket not writable");
            }
            while let Some(result) = in_framed.next().await {
                match result {
                    Ok(data) => {
                        if let Err(e) = sock_write.try_write(&data) {
                            tx.send(Err(Status::from(e))).await.unwrap_or_else(|e| {
                                log::error!("Failed to send error to channel: {e}")
                            });
                            break;
                        }
                    }
                    Err(err) => {
                        tx.send(Err(Status::from(std::io::Error::other(err))))
                            .await
                            .unwrap_or_else(|e| {
                                log::error!("Failed to send error to channel: {e}")
                            });
                        break;
                    }
                }
            }
            sock_write.forget();
        });

        let combined_output_stream =
            futures_util::stream::iter(vec![output_reader.right_stream(), rx_stream.left_stream()])
                .flatten_unordered(None);

        Ok(Response::new(Box::pin(combined_output_stream)))
    }

    #[cfg(windows)]
    async fn forward_agent(
        &self,
        request: Request<Streaming<bollard_buildkit_proto::moby::sshforward::v1::BytesMessage>>,
    ) -> Result<Response<Self::ForwardAgentStream>, Status> {
        unimplemented!();
    }
}

pub(crate) struct GrpcClient {
    pub(crate) client: crate::Docker,
    pub(crate) session_id: String,
}

impl Service<tonic::transport::Uri> for GrpcClient {
    type Response = GrpcTransport;
    type Error = error::GrpcError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: tonic::transport::Uri) -> Self::Future {
        // create the body
        let opt: Option<serde_json::Value> = None;
        let url = "/grpc";
        let client = self.client.clone();
        let req = client.build_request(
            url,
            Builder::new()
                .method(Method::POST)
                .header("Connection", "Upgrade")
                .header("Upgrade", "h2c")
                .header("X-Docker-Expose-Session-Uuid", &self.session_id),
            opt,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );
        let fut = async move {
            client.process_upgraded(req).await.map(|(read, write)| {
                let output = Box::pin(read);
                let input = Box::pin(write);
                GrpcTransport {
                    read: output,
                    write: input,
                }
            })
        };

        // Return the response as an immediate future
        Box::pin(fut.map_err(From::from))
    }
}

// Reference: https://github.com/moby/buildkit/blob/master/identity/randomid.go
pub(crate) fn new_id() -> String {
    let mut p: [u8; 17] = Default::default();
    rand::fill(&mut p);
    p[0] |= 0x80; // set high bit to avoid the need for padding
    num::BigInt::from_bytes_be(num::bigint::Sign::Plus, &p[..]).to_str_radix(36)[1..26].to_string()
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_new_id() {
        let s = super::new_id();
        assert_eq!(s.len(), 25);
    }
}
