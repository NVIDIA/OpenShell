// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS passthrough: discovery credentials never enter application streams.

mod cache;
mod discovery;

use std::io::{self, Cursor};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use axum::{Router, extract::State, http::StatusCode, routing::get};
use clap::Parser as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CLIENT_HELLO: usize = 64 * 1024;

#[derive(Default)]
pub struct Health {
    discovery_ready: AtomicBool,
    accepted: AtomicU64,
    rejected: AtomicU64,
    active: AtomicU64,
}

#[cfg(test)]
fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )
    .expect("bounded timestamp")
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// rustls owns `ClientHello` parsing. No cryptographic handshake or TLS termination
/// happens here; every received byte is forwarded unchanged after SNI selection.
async fn client_hello(stream: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut hello = Vec::new();
    loop {
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await?;
        if count == 0 {
            return Err(denied("incomplete ClientHello"));
        }
        if hello.len() + count > MAX_CLIENT_HELLO {
            return Err(denied("ClientHello too large"));
        }
        hello.extend_from_slice(&bytes[..count]);
        acceptor.read_tls(&mut Cursor::new(&bytes[..count]))?;
        if let Some(accepted) = acceptor
            .accept()
            .map_err(|_| denied("invalid ClientHello"))?
        {
            let hostname = accepted
                .client_hello()
                .server_name()
                .filter(|name| cache::valid_hostname(name))
                .ok_or_else(|| denied("service SNI required"))?
                .to_string();
            return Ok((hostname, hello));
        }
    }
}

async fn connection(
    mut incoming: TcpStream,
    mut updates: watch::Receiver<cache::Routes>,
) -> io::Result<()> {
    openshell_core::net::set_tcp_nodelay_best_effort(&incoming);
    let (host, hello) = tokio::time::timeout(SETUP_TIMEOUT, client_hello(&mut incoming))
        .await
        .map_err(|_| denied("ClientHello timeout"))??;
    let route = updates
        .borrow()
        .get(&host)
        .filter(|route| route.deadline > Instant::now())
        .cloned()
        .ok_or_else(|| denied("unknown or expired service"))?;
    let _permit = route
        .connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| denied("service connection limit"))?;
    let mut outgoing = tokio::time::timeout(
        SETUP_TIMEOUT,
        openshell_core::net::connect_tcp_nodelay_best_effort(&[route.endpoint]),
    )
    .await
    .map_err(|_| denied("backend connect timeout"))??;
    let still_current = updates.borrow().get(&host).is_some_and(|current| {
        current.version == route.version
            && current.endpoint == route.endpoint
            && current.deadline > Instant::now()
    });
    if !still_current || route.deadline <= Instant::now() {
        return Err(denied("installation changed during setup"));
    }
    tokio::time::timeout_at(
        route.deadline.min(Instant::now() + SETUP_TIMEOUT),
        outgoing.write_all(&hello),
    )
    .await
    .map_err(|_| denied("backend setup timeout"))??;
    let transfer = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing);
    tokio::pin!(transfer);
    let mut deadline = route.deadline;
    loop {
        // Even a queued renewal cannot resurrect a connection after its
        // previously observed lease has lapsed.
        if Instant::now() >= deadline {
            return Ok(());
        }
        let current = updates.borrow().get(&host).cloned();
        let Some(current) = current.filter(|current| {
            current.version == route.version
                && current.endpoint == route.endpoint
                && current.deadline > Instant::now()
        }) else {
            return Ok(());
        };
        deadline = current.deadline;
        tokio::select! {
            result = &mut transfer => return result.map(|_| ()),
            () = tokio::time::sleep_until(deadline) => return Ok(()),
            result = updates.changed() => { if result.is_err() { return Ok(()); } }
        }
    }
}

async fn serve(
    listener: TcpListener,
    routes: cache::RouteCache,
    health: Arc<Health>,
) -> io::Result<()> {
    let capacity = Arc::new(Semaphore::new(1024));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = capacity.clone().try_acquire_owned() else {
                    health.rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let updates = routes.subscribe();
                let health = health.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    health.accepted.fetch_add(1, Ordering::Relaxed);
                    health.active.fetch_add(1, Ordering::Relaxed);
                    let result = connection(stream, updates).await;
                    health.active.fetch_sub(1, Ordering::Relaxed);
                    if result.is_err() { health.rejected.fetch_add(1, Ordering::Relaxed); }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn readiness(State(health): State<Arc<Health>>) -> StatusCode {
    if health.discovery_ready.load(Ordering::Acquire) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(health): State<Arc<Health>>) -> String {
    format!(
        "# TYPE openshell_proxy_connections_total counter\nopenshell_proxy_connections_total {}\n# TYPE openshell_proxy_rejected_total counter\nopenshell_proxy_rejected_total {}\n# TYPE openshell_proxy_active gauge\nopenshell_proxy_active {}\n",
        health.accepted.load(Ordering::Relaxed),
        health.rejected.load(Ordering::Relaxed),
        health.active.load(Ordering::Relaxed)
    )
}

async fn shutdown() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = discovery::Args::parse();
    args.validate()?;
    let listener = TcpListener::bind(args.listen_address).await?;
    let health_listener = TcpListener::bind(args.health_address).await?;
    let health = Arc::new(Health::default());
    let (routes, _) = watch::channel(cache::Routes::new());
    let discovery = tokio::spawn(discovery::run(args, routes.clone(), health.clone()));
    let diagnostics = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .with_state(health.clone());
    tokio::select! {
        result = serve(listener, routes, health) => result?,
        result = axum::serve(health_listener, diagnostics) => result?,
        result = shutdown() => result?,
    }
    discovery.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(host: &str) -> Vec<u8> {
        let config = openshell_crypto::tls::client_builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), host.to_owned().try_into().unwrap())
                .unwrap();
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        bytes
    }

    #[tokio::test]
    async fn passthrough_preserves_bytes_and_revokes_replaced_installations() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = frontend.local_addr().unwrap();
        let (routes, _) = watch::channel(cache::Routes::from([(
            "demo.example.com".into(),
            cache::Route {
                endpoint: backend.local_addr().unwrap(),
                version: "owner-1".into(),
                deadline: Instant::now() + Duration::from_secs(10),
                connections: Arc::new(Semaphore::new(64)),
            },
        )]));
        let updates = routes.subscribe();
        let server = tokio::spawn(async move {
            let (stream, _) = frontend.accept().await.unwrap();
            connection(stream, updates).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let bytes = hello("demo.example.com");
        client.write_all(&bytes).await.unwrap();
        let (mut peer, _) = backend.accept().await.unwrap();
        let mut received = vec![0; bytes.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
        peer.write_all(b"tls-stream").await.unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"tls-stream");
        routes.send_modify(|view| {
            view.get_mut("demo.example.com").unwrap().deadline =
                Instant::now() + Duration::from_secs(14);
        });
        peer.write_all(b"renewed").await.unwrap();
        let mut renewed = [0; 7];
        client.read_exact(&mut renewed).await.unwrap();
        assert_eq!(&renewed, b"renewed");
        routes.send_modify(|view| {
            view.get_mut("demo.example.com").unwrap().version = "owner-2".into();
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_sni_never_dials() {
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = frontend.local_addr().unwrap();
        let (routes, _) = watch::channel(cache::Routes::new());
        let server = tokio::spawn(async move {
            let (stream, _) = frontend.accept().await.unwrap();
            connection(stream, routes.subscribe()).await.unwrap_err()
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&hello("unknown.example.com"))
            .await
            .unwrap();
        assert_eq!(
            server.await.unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[tokio::test]
    async fn incomplete_hello_has_a_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (routes, _) = watch::channel(cache::Routes::new());
        tokio::time::pause();
        let result = tokio::time::timeout(
            SETUP_TIMEOUT + Duration::from_secs(1),
            connection(stream, routes.subscribe()),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
    #[tokio::test]
    async fn cached_lease_expiry_closes_a_live_backend_stream() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = frontend.local_addr().unwrap();
        let (routes, _) = watch::channel(cache::Routes::from([(
            "demo.example.com".into(),
            cache::Route {
                endpoint: backend.local_addr().unwrap(),
                version: "owner-1".into(),
                deadline: Instant::now() + Duration::from_secs(10),
                connections: Arc::new(Semaphore::new(64)),
            },
        )]));
        let updates = routes.subscribe();
        let server = tokio::spawn(async move {
            let (stream, _) = frontend.accept().await.unwrap();
            connection(stream, updates).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let bytes = hello("demo.example.com");
        client.write_all(&bytes).await.unwrap();
        let (mut peer, _) = backend.accept().await.unwrap();
        let mut received = vec![0; bytes.len()];
        peer.read_exact(&mut received).await.unwrap();
        routes.send_modify(|view| {
            view.get_mut("demo.example.com").unwrap().deadline =
                Instant::now() + Duration::from_millis(100);
        });
        let mut buffer = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        server.await.unwrap();
        drop(peer);
    }
}
