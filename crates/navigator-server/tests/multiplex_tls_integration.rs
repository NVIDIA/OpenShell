use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use navigator_core::proto::{
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteSandboxRequest,
    DeleteSandboxResponse, ExecSandboxEvent, ExecSandboxRequest, GetSandboxPolicyRequest,
    GetSandboxPolicyResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListSandboxesRequest, ListSandboxesResponse, RevokeSshSessionRequest, RevokeSshSessionResponse,
    SandboxResponse, SandboxStreamEvent, ServiceStatus, WatchSandboxRequest,
    navigator_client::NavigatorClient,
    navigator_server::{Navigator, NavigatorServer},
};
use navigator_server::{MultiplexedService, TlsAcceptor, health_router};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use std::io::Write;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Response, Status};

fn install_rustls_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[derive(Clone, Default)]
struct TestNavigator;

#[tonic::async_trait]
impl Navigator for TestNavigator {
    async fn health(
        &self,
        _request: tonic::Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn create_sandbox(
        &self,
        _request: tonic::Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse::default()))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse { deleted: true }))
    }

    async fn get_sandbox_policy(
        &self,
        _request: tonic::Request<GetSandboxPolicyRequest>,
    ) -> Result<Response<GetSandboxPolicyResponse>, Status> {
        Ok(Response::new(GetSandboxPolicyResponse::default()))
    }

    async fn create_ssh_session(
        &self,
        _request: tonic::Request<CreateSshSessionRequest>,
    ) -> Result<Response<CreateSshSessionResponse>, Status> {
        Ok(Response::new(CreateSshSessionResponse::default()))
    }

    async fn revoke_ssh_session(
        &self,
        _request: tonic::Request<RevokeSshSessionRequest>,
    ) -> Result<Response<RevokeSshSessionResponse>, Status> {
        Ok(Response::new(RevokeSshSessionResponse::default()))
    }

    type WatchSandboxStream = ReceiverStream<Result<SandboxStreamEvent, Status>>;
    type ExecSandboxStream = ReceiverStream<Result<ExecSandboxEvent, Status>>;

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn exec_sandbox(
        &self,
        _request: tonic::Request<ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn write_cert_pair() -> (tempfile::TempDir, Vec<u8>) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("failed to generate cert");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let dir = tempdir().expect("failed to create tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::File::create(&cert_path)
        .and_then(|mut f| f.write_all(cert_pem.as_bytes()))
        .expect("failed to write cert");
    std::fs::File::create(&key_path)
        .and_then(|mut f| f.write_all(key_pem.as_bytes()))
        .expect("failed to write key");

    (dir, cert_pem.into_bytes())
}

fn build_tls_root(cert_pem: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(cert_pem);
    let parsed = certs(&mut cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .expect("failed to parse cert pem");
    for cert in parsed {
        roots.add(cert).expect("failed to add cert");
    }
    roots
}

async fn grpc_client(addr: std::net::SocketAddr, cert_pem: Vec<u8>) -> NavigatorClient<Channel> {
    let ca_cert = tonic::transport::Certificate::from_pem(cert_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");
    let channel = endpoint.connect().await.expect("failed to connect");
    NavigatorClient::new(channel)
}

fn https_client(
    cert_pem: &[u8],
) -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
> {
    let roots = build_tls_root(cert_pem);
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

#[tokio::test]
async fn serves_grpc_and_http_over_tls_on_same_port() {
    install_rustls_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (temp, cert_pem) = write_cert_pair();
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    let tls_acceptor = TlsAcceptor::from_files(&cert_path, &key_path).unwrap();

    let grpc_service = NavigatorServer::new(TestNavigator);
    let http_service = health_router();
    let service = MultiplexedService::new(grpc_service, http_service);

    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            let tls = tls_acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = tls.inner().accept(stream).await else {
                    return;
                };
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), svc)
                    .await;
            });
        }
    });

    let mut grpc = grpc_client(addr, cert_pem.clone()).await;
    let response = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);

    let client = https_client(&cert_pem);
    let req = Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/healthz", addr.port()))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.abort();
}
