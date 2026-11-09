// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

use clap::Parser;
use openshell_core::proto::{
    GetServiceRouteSnapshotRequest, WatchServiceRoutesRequest, workspace_selector,
};
use openshell_sdk::{AuthConfig, ClientConfig, ClientIdentity, OpenShellClient};
use tonic::{Code, Status};

use crate::{Health, cache};

#[derive(Clone, Parser)]
#[command(
    version,
    about = "Route application TLS directly to discovered supervisor listeners"
)]
pub struct Args {
    #[arg(long)]
    pub gateway_endpoint: String,
    /// Repeat for a finite set. Exclusive with --all-workspaces.
    #[arg(
        long,
        required_unless_present = "all_workspaces",
        conflicts_with = "all_workspaces"
    )]
    pub workspace: Vec<String>,
    /// Discover all active workspaces, including newly created ones.
    #[arg(long, conflicts_with = "workspace")]
    pub all_workspaces: bool,
    #[arg(long, default_value = "0.0.0.0:8443")]
    pub listen_address: std::net::SocketAddr,
    #[arg(long, default_value = "0.0.0.0:9091")]
    pub health_address: std::net::SocketAddr,
    #[arg(long)]
    pub gateway_ca: Option<PathBuf>,
    #[arg(long, requires = "discovery_client_key")]
    pub discovery_client_cert: Option<PathBuf>,
    #[arg(long, requires = "discovery_client_cert")]
    pub discovery_client_key: Option<PathBuf>,
    #[arg(long)]
    pub discovery_token_file: Option<PathBuf>,
    /// Permit a plaintext loopback development gateway without credentials.
    #[arg(long)]
    pub allow_insecure_gateway: bool,
}

async fn read_file(path: &Path) -> Result<Vec<u8>, Status> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| Status::unavailable("credential file unavailable"))?;
    if metadata.len() > 1024 * 1024 {
        return Err(Status::invalid_argument("credential file too large"));
    }
    tokio::fs::read(path)
        .await
        .map_err(|_| Status::unavailable("credential file unavailable"))
}

impl Args {
    pub fn validate(&self) -> Result<(), &'static str> {
        let gateway = url::Url::parse(&self.gateway_endpoint).map_err(|_| "invalid gateway URL")?;
        if !gateway.username().is_empty()
            || gateway.password().is_some()
            || gateway.query().is_some()
            || gateway.fragment().is_some()
            || gateway.path() != "/"
            || self.all_workspaces != self.workspace.is_empty()
            || self.workspace.len() > 64
            || self
                .workspace
                .iter()
                .any(|name| !cache::valid_workspace(name))
            || self
                .workspace
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.workspace.len()
        {
            return Err("invalid gateway origin or workspace");
        }
        if gateway.scheme() != "https" {
            let loopback = gateway.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if gateway.scheme() != "http"
                || !loopback
                || !self.allow_insecure_gateway
                || self.discovery_token_file.is_some()
                || self.discovery_client_cert.is_some()
                || self.discovery_client_key.is_some()
                || self.gateway_ca.is_some()
            {
                return Err(
                    "discovery requires HTTPS; plaintext is limited to credential-free loopback development",
                );
            }
        }
        if self.discovery_token_file.is_some()
            && (self.discovery_client_cert.is_some() || self.discovery_client_key.is_some())
        {
            return Err("choose bearer credentials or a discovery client certificate");
        }
        if self.discovery_client_cert.is_some() != self.discovery_client_key.is_some() {
            return Err("client certificate and key must be configured together");
        }
        Ok(())
    }

    fn selector(&self) -> Option<openshell_core::proto::WorkspaceSelector> {
        if self.all_workspaces {
            Some(openshell_core::proto::all_workspaces_selector())
        } else if self.workspace.len() == 1 {
            Some(workspace_selector(&self.workspace[0]))
        } else {
            None
        }
    }

    fn selected_workspaces(&self) -> Vec<String> {
        if self.workspace.len() > 1 {
            self.workspace.clone()
        } else {
            Vec::new()
        }
    }

    /// Files are read on every reconnect so mounted credentials can rotate.
    async fn client(&self) -> Result<OpenShellClient, Status> {
        let mut config = ClientConfig::new(&self.gateway_endpoint);
        if let Some(path) = &self.gateway_ca {
            config.ca_cert = Some(read_file(path).await?);
        }
        if let (Some(cert), Some(key)) = (&self.discovery_client_cert, &self.discovery_client_key) {
            config.client_identity = Some(ClientIdentity::new(
                read_file(cert).await?,
                read_file(key).await?,
            ));
        }
        if let Some(path) = &self.discovery_token_file {
            let bytes = read_file(path).await?;
            let token = std::str::from_utf8(&bytes)
                .map_err(|_| Status::invalid_argument("invalid token encoding"))?
                .trim();
            if token.is_empty() {
                return Err(Status::invalid_argument("empty discovery token"));
            }
            config.auth = Some(AuthConfig::oidc(token));
        }
        OpenShellClient::connect(config)
            .await
            .map_err(|_| Status::unavailable("gateway connection failed"))
    }
}

async fn consume(args: &Args, routes: &cache::RouteCache, health: &Health) -> Result<(), Status> {
    let client = args.client().await?;
    let mut grpc = client.raw_service_discovery();
    let request = GetServiceRouteSnapshotRequest {
        workspace_scope: args.selector(),
        workspaces: args.selected_workspaces(),
    };
    let initial = tokio::time::timeout(
        Duration::from_secs(10),
        grpc.get_service_route_snapshot(request),
    )
    .await
    .map_err(|_| Status::deadline_exceeded("snapshot timeout"))??
    .into_inner()
    .snapshot
    .ok_or_else(|| Status::data_loss("snapshot missing"))?;
    cache::replace_selected(routes, initial, &args.workspace, args.all_workspaces)
        .map_err(Status::data_loss)?;
    health.discovery_ready.store(true, Ordering::Release);
    let mut stream = grpc
        .watch_service_routes(WatchServiceRoutesRequest {
            workspace_scope: args.selector(),
            workspaces: args.selected_workspaces(),
        })
        .await?
        .into_inner();
    loop {
        // The gateway ends bounded watches after one minute. A deadline also
        // protects against a stalled intermediary that never closes the stream.
        let message = tokio::time::timeout(Duration::from_secs(70), stream.message())
            .await
            .map_err(|_| Status::deadline_exceeded("watch stalled"))??;
        let Some(message) = message else {
            return Ok(());
        };
        cache::replace_selected(
            routes,
            message
                .snapshot
                .ok_or_else(|| Status::data_loss("snapshot missing"))?,
            &args.workspace,
            args.all_workspaces,
        )
        .map_err(Status::data_loss)?;
        health.discovery_ready.store(true, Ordering::Release);
    }
}

pub async fn run(args: Args, routes: cache::RouteCache, health: Arc<Health>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let result = consume(&args, &routes, &health).await;
        health.discovery_ready.store(false, Ordering::Release);
        match result {
            Ok(()) => {
                backoff = Duration::from_secs(1);
                tokio::time::sleep(backoff).await;
            }
            Err(error) => {
                if matches!(
                    error.code(),
                    Code::PermissionDenied
                        | Code::Unauthenticated
                        | Code::InvalidArgument
                        | Code::FailedPrecondition
                        | Code::DataLoss
                ) {
                    routes.send_replace(cache::Routes::new());
                }
                tracing::warn!(code = ?error.code(), "discovery reconnect required");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_require_tls_and_workspace_selection_is_explicit() {
        let args = |endpoint: &str| {
            Args::try_parse_from([
                "proxy",
                "--gateway-endpoint",
                endpoint,
                "--workspace",
                "default",
                "--allow-insecure-gateway",
            ])
            .unwrap()
        };
        assert!(args("https://gateway.example.com").validate().is_ok());
        assert!(args("http://localhost:8080").validate().is_ok());
        assert!(args("http://gateway.example.com").validate().is_err());
        let mut plaintext = args("http://localhost:8080");
        plaintext.discovery_token_file = Some("/run/token".into());
        assert!(plaintext.validate().is_err());
        assert!(
            args("https://user:secret@gateway.example.com")
                .validate()
                .is_err()
        );
        assert!(
            Args::try_parse_from(["proxy", "--gateway-endpoint", "https://gateway.example.com"])
                .is_err()
        );
    }
    #[test]
    fn workspace_modes_are_exclusive_bounded_and_preserve_single_workspace_wire_calls() {
        let parse = |flags: &[&str]| {
            let mut input = vec!["proxy", "--gateway-endpoint", "https://gateway.example.com"];
            input.extend_from_slice(flags);
            Args::try_parse_from(input)
        };
        let single = parse(&["--workspace", "team-a"]).unwrap();
        assert!(single.validate().is_ok());
        assert_eq!(
            single.selector().unwrap().selection,
            Some(workspace_selector::Selection::Workspace("team-a".into()))
        );
        let set = parse(&["--workspace", "team-a", "--workspace", "team-b"]).unwrap();
        assert!(set.validate().is_ok());
        assert!(set.selector().is_none());
        assert_eq!(set.selected_workspaces(), vec!["team-a", "team-b"]);
        let all = parse(&["--all-workspaces"]).unwrap();
        assert!(all.validate().is_ok());
        assert!(all.workspace.is_empty());
        assert!(all.selector().is_some());
        assert!(parse(&["--workspace", "team-a", "--all-workspaces"]).is_err());
        assert!(
            parse(&["--workspace", "team-a", "--workspace", "team-a"])
                .unwrap()
                .validate()
                .is_err()
        );
        let mut too_many = set;
        too_many.workspace = (0..65).map(|i| format!("team-{i}")).collect();
        assert!(too_many.validate().is_err());
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;
    use openshell_core::proto::{
        DiscoveredServiceRoute, GetServiceRouteSnapshotResponse, ServiceRouteEndpoint,
        ServiceRouteSnapshot, WatchServiceRoutesResponse, WorkspaceSelector,
        service_discovery_server::{ServiceDiscovery, ServiceDiscoveryServer},
    };
    use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
    use tonic::{Request, Response};

    type Updates = Arc<
        tokio::sync::Mutex<
            Option<tokio::sync::mpsc::Sender<Result<WatchServiceRoutesResponse, Status>>>,
        >,
    >;

    struct Discovery {
        scope: Option<WorkspaceSelector>,
        workspaces: Vec<String>,
        snapshot: ServiceRouteSnapshot,
        stream: Updates,
    }

    #[tonic::async_trait]
    impl ServiceDiscovery for Discovery {
        async fn get_service_route_snapshot(
            &self,
            request: Request<GetServiceRouteSnapshotRequest>,
        ) -> Result<Response<GetServiceRouteSnapshotResponse>, Status> {
            assert_eq!(request.get_ref().workspace_scope, self.scope);
            assert_eq!(request.get_ref().workspaces, self.workspaces);
            Ok(Response::new(GetServiceRouteSnapshotResponse {
                snapshot: Some(self.snapshot.clone()),
            }))
        }
        type WatchServiceRoutesStream = ReceiverStream<Result<WatchServiceRoutesResponse, Status>>;
        async fn watch_service_routes(
            &self,
            request: Request<WatchServiceRoutesRequest>,
        ) -> Result<Response<Self::WatchServiceRoutesStream>, Status> {
            assert_eq!(request.get_ref().workspace_scope, self.scope);
            assert_eq!(request.get_ref().workspaces, self.workspaces);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(Ok(WatchServiceRoutesResponse {
                snapshot: Some(self.snapshot.clone()),
            }))
            .await
            .unwrap();
            *self.stream.lock().await = Some(tx);
            Ok(Response::new(ReceiverStream::new(rx)))
        }
    }

    #[tokio::test]
    async fn discovery_only_service_drives_proxy_routes_for_single_finite_and_all_workspaces() {
        for mode in 0..3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut flags = vec![
                "openshell-sandbox-proxy".to_string(),
                "--gateway-endpoint".into(),
                format!("http://{addr}"),
                "--allow-insecure-gateway".into(),
            ];
            if mode == 2 {
                flags.push("--all-workspaces".into());
            } else {
                flags.extend(["--workspace".into(), "default".into()]);
                if mode == 1 {
                    flags.extend(["--workspace".into(), "team-b".into()]);
                }
            }
            let args = Args::try_parse_from(flags).unwrap();
            args.validate().unwrap();
            let workspaces = if mode == 0 {
                vec!["default"]
            } else {
                vec!["default", "team-b"]
            };
            let snapshot = ServiceRouteSnapshot {
                revision: "initial".into(),
                routes: workspaces
                    .iter()
                    .map(|workspace| DiscoveredServiceRoute {
                        workspace: (*workspace).into(),
                        sandbox: "demo".into(),
                        name: "web".into(),
                        hostname: format!("{workspace}--demo--web.example.com"),
                        endpoint: Some(ServiceRouteEndpoint {
                            host: "127.0.0.1".into(),
                            port: 9443,
                        }),
                        installation_version: "installation-1".into(),
                        expires_at: Some(
                            openshell_core::time::timestamp_from_millis(crate::now_ms() + 12_000)
                                .unwrap(),
                        ),
                        ..Default::default()
                    })
                    .collect(),
            };
            let stream = Arc::new(tokio::sync::Mutex::new(None));
            let service = ServiceDiscoveryServer::new(Discovery {
                scope: args.selector(),
                workspaces: args.selected_workspaces(),
                snapshot,
                stream: stream.clone(),
            });
            let (sockets, rx) = tokio::sync::mpsc::channel(4);
            let accept = tokio::spawn(async move {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    if sockets.send(Ok::<_, std::io::Error>(socket)).await.is_err() {
                        break;
                    }
                }
            });
            let (stop, stopped) = tokio::sync::oneshot::channel();
            // No OpenShell management service is registered: old RPC paths fail.
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(ReceiverStream::new(rx), async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
            let (routes, mut changes) = tokio::sync::watch::channel(cache::Routes::new());
            let health = Arc::new(Health::default());
            let task_routes = routes.clone();
            let task_health = health.clone();
            let consumer =
                tokio::spawn(async move { consume(&args, &task_routes, &task_health).await });
            tokio::time::timeout(Duration::from_secs(3), async {
                while stream.lock().await.is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(routes.borrow().len(), workspaces.len());
            assert!(health.discovery_ready.load(Ordering::Acquire));
            for workspace in workspaces {
                assert!(
                    routes
                        .borrow()
                        .contains_key(&format!("{workspace}--demo--web.example.com"))
                );
            }
            stream
                .lock()
                .await
                .as_ref()
                .unwrap()
                .send(Ok(WatchServiceRoutesResponse {
                    snapshot: Some(ServiceRouteSnapshot {
                        routes: Vec::new(),
                        revision: "withdrawn".into(),
                    }),
                }))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !changes.borrow_and_update().is_empty() {
                    changes.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
            drop(stream.lock().await.take());
            tokio::time::timeout(Duration::from_secs(3), consumer)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            stop.send(()).unwrap();
            accept.abort();
            server.await.unwrap();
        }
    }
}
