// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in application ingress, separate from the gateway control transport.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use miette::{IntoDiagnostic, Result};
use openshell_core::grpc_client::SettingsPollResult;
use openshell_core::proto::SandboxServiceRoute;
use openshell_isolation_interface::contract::LoopbackTarget;
use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DispositionId,
    HttpActivityBuilder, HttpResponse, NetworkActivityBuilder, SeverityId, StatusId, ocsf_emit,
};
use openshell_sandbox_backend::BoundaryLoopbackConnector;
use std::sync::Mutex;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

const FRESHNESS: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Config {
    address: SocketAddr,
    domain: String,
    certificate: PathBuf,
    key: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Option<Self>> {
        Self::from_values(|name| std::env::var(name).ok())
    }

    fn from_values(read: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        match read("OPENSHELL_APP_LISTENER_ENABLED").as_deref() {
            None | Some("false") => return Ok(None),
            Some("true") => {}
            _ => {
                return Err(miette::miette!(
                    "OPENSHELL_APP_LISTENER_ENABLED must be true or false"
                ));
            }
        }
        let address = read("OPENSHELL_APP_LISTEN_ADDRESS");
        let domain = read("OPENSHELL_APP_SERVICE_DOMAIN");
        let certificate = read("OPENSHELL_APP_TLS_CERT");
        let key = read("OPENSHELL_APP_TLS_KEY");
        let (Some(address), Some(domain), Some(certificate), Some(key)) =
            (address, domain, certificate, key)
        else {
            return Err(miette::miette!(
                "app listener requires address, domain, certificate, and key"
            ));
        };
        let address: SocketAddr = address.parse().into_diagnostic()?;
        openshell_core::app_listener::AppListenerConfig {
            public_url: None,
            enabled: true,
            port: address.port(),
            domain: domain.clone(),
        }
        .validate()
        .map_err(|error| miette::miette!(error))?;
        Ok(Some(Self {
            address,
            domain,
            certificate: certificate.into(),
            key: key.into(),
        }))
    }

    pub fn bind(self) -> Result<BoundListener> {
        let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(self.certificate).into_diagnostic()?,
        ))
        .collect::<std::io::Result<Vec<_>>>()
        .into_diagnostic()?;
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(self.key).into_diagnostic()?,
        ))
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("app TLS private key missing"))?;
        let mut tls = openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .into_diagnostic()?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let socket = std::net::TcpListener::bind(self.address).into_diagnostic()?;
        socket.set_nonblocking(true).into_diagnostic()?;
        let listener = tokio::net::TcpListener::from_std(socket).into_diagnostic()?;
        Ok(BoundListener {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            domain: self.domain,
        })
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Default)]
struct Snapshot {
    routes: BTreeMap<String, SandboxServiceRoute>,
    generations: BTreeMap<String, u64>,
    next_generation: u64,
    expires: Option<Instant>,
    authority_expires: Option<Instant>,
    workspace: String,
    configuration_instance_id: String,
    config_revision: u64,
    // Whole-sandbox suspension fence, independent of individual service edits.
    epoch: u64,
}

#[derive(Clone, Copy)]
struct RouteToken {
    epoch: u64,
    generation: u64,
}

/// Shared by policy reconciliation and ingress. Only accepted configuration
/// refreshes this lease; route changes cannot restart or replace the workload.
#[derive(Clone)]
pub struct Routes {
    registration: Option<Arc<Registration>>,
    requires_authority: bool,
    sender: watch::Sender<Snapshot>,
    stopped: Arc<AtomicBool>,
    serving: Arc<AtomicBool>,
}

impl Default for Routes {
    fn default() -> Self {
        Self {
            sender: watch::channel(Snapshot::default()).0,
            stopped: Arc::new(AtomicBool::new(false)),
            serving: Arc::new(AtomicBool::new(false)),
            registration: None,
            requires_authority: false,
        }
    }
}

pub(crate) struct ConfigurationGuard(Routes);
impl Drop for ConfigurationGuard {
    fn drop(&mut self) {
        self.0.suspend();
    }
}

impl Routes {
    pub(crate) fn installation_source(&self) -> openshell_core::app_listener::InstallationSource {
        let routes = self.clone();
        Arc::new(move |duration| {
            let snapshot = routes.sender.borrow();
            if routes.stopped.load(Ordering::Acquire)
                || !routes.serving.load(Ordering::Acquire)
                || snapshot.expires.is_none_or(|expiry| {
                    expiry.saturating_duration_since(Instant::now()) < duration
                })
            {
                return openshell_core::proto::SupervisorServiceAdvertisement::default();
            }
            drop(snapshot);
            if routes.requires_authority {
                routes.sender.send_modify(|snapshot| {
                    if snapshot
                        .authority_expires
                        .is_none_or(|expiry| expiry <= Instant::now())
                    {
                        // A later lease cannot revive a stream that already lost authority.
                        snapshot.epoch = snapshot.epoch.wrapping_add(1);
                    }
                    snapshot.authority_expires = Some(Instant::now() + duration);
                });
            }
            let snapshot = routes.sender.borrow();
            openshell_core::proto::SupervisorServiceAdvertisement {
                service_domain: routes
                    .registration
                    .as_ref()
                    .map_or_else(String::new, |registration| {
                        registration.router.domain.clone()
                    }),
                configuration_instance_id: snapshot.configuration_instance_id.clone(),
                config_revision: snapshot.config_revision,
                routes: snapshot.routes.values().cloned().collect(),
                ..Default::default()
            }
        })
    }

    pub(crate) fn configuration_guard(self) -> ConfigurationGuard {
        ConfigurationGuard(self)
    }

    fn serving_expiry(&self, snapshot: &Snapshot) -> Option<Instant> {
        let config = snapshot.expires?;
        if self.requires_authority {
            Some(config.min(snapshot.authority_expires?))
        } else {
            Some(config)
        }
    }

    fn valid(&self, route: &SandboxServiceRoute, token: RouteToken) -> bool {
        let snapshot = self.sender.borrow();
        self.serving_expiry(&snapshot)
            .is_some_and(|expiry| expiry > Instant::now())
            && snapshot.epoch == token.epoch
            && snapshot.generations.get(&route.name) == Some(&token.generation)
            && snapshot.routes.get(&route.name) == Some(route)
    }
    pub(crate) fn install(&self, result: &SettingsPollResult) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let mut routes = BTreeMap::new();
        if !result.configuration_admitted {
            self.suspend();
            return;
        }
        if result.configuration_admitted
            && valid_label(&result.workspace)
            && !result.workspace.contains("--")
        {
            for route in &result.service_routes {
                if route.endpoint_id.is_empty()
                    || route.target_port == 0
                    || route.target_port > 65535
                    || !matches!(route.authorization_mode, 0..=2)
                    || (!route.name.is_empty()
                        && (!valid_label(&route.name) || route.name.contains("--")))
                {
                    self.suspend();
                    return;
                }
                if routes.insert(route.name.clone(), route.clone()).is_some() {
                    self.suspend();
                    return;
                }
            }
        }
        if routes.len() > 1024 || !valid_label(&result.workspace) || result.workspace.contains("--")
        {
            self.suspend();
            return;
        }
        if let Some(registration) = &self.registration
            && !registration.bind(&result.workspace)
        {
            self.suspend();
            return;
        }
        let changed = self.sender.borrow().routes != routes;
        self.sender.send_modify(|snapshot| {
            // Renewal after a lapse cannot revive a connection whose lease expired.
            if snapshot
                .expires
                .is_some_and(|expiry| expiry <= Instant::now())
            {
                snapshot.epoch = snapshot.epoch.wrapping_add(1);
            }
            let generations = routes
                .iter()
                .map(|(name, route)| {
                    let previous = (snapshot.routes.get(name) == Some(route))
                        .then(|| snapshot.generations.get(name).copied())
                        .flatten();
                    let generation = previous.unwrap_or_else(|| {
                        snapshot.next_generation = snapshot
                            .next_generation
                            .checked_add(1)
                            .expect("app route generation exhausted");
                        snapshot.next_generation
                    });
                    (name.clone(), generation)
                })
                .collect();
            if snapshot.workspace != result.workspace {
                snapshot.epoch = snapshot.epoch.wrapping_add(1);
            }
            snapshot.workspace.clone_from(&result.workspace);
            snapshot
                .configuration_instance_id
                .clone_from(&result.configuration_instance_id);
            snapshot.config_revision = result.config_revision;
            snapshot.routes = routes;
            snapshot.generations = generations;
            snapshot.expires = Some(Instant::now() + FRESHNESS);
        });
        if changed {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .message("App listener service routes updated")
                    .build()
            );
        }
    }

    /// Renew only already installed routes while a live push session supplies
    /// freshness. A rejected configuration is suspended and cannot be revived.
    pub(crate) fn renew(&self) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        self.sender.send_modify(|snapshot| {
            if snapshot
                .expires
                .is_some_and(|expiry| expiry > Instant::now())
            {
                snapshot.expires = Some(Instant::now() + FRESHNESS);
            }
        });
    }

    pub(crate) fn suspend(&self) {
        self.sender.send_modify(|snapshot| {
            snapshot.routes.clear();
            snapshot.generations.clear();
            snapshot.expires = None;
            snapshot.authority_expires = None;
            snapshot.epoch = snapshot.epoch.wrapping_add(1);
        });
    }

    fn resolve(
        &self,
        sni: &str,
        prefix: &str,
        domain: &str,
    ) -> Option<(SandboxServiceRoute, RouteToken)> {
        let encoded = sni.strip_suffix(&format!(".{domain}"))?;
        let service = if encoded == prefix {
            ""
        } else {
            encoded.strip_prefix(&format!("{prefix}--"))?
        };
        let snapshot = self.sender.borrow();
        if self.serving_expiry(&snapshot)? <= Instant::now() {
            return None;
        }
        Some((
            snapshot.routes.get(service)?.clone(),
            RouteToken {
                epoch: snapshot.epoch,
                generation: *snapshot.generations.get(service)?,
            },
        ))
    }

    async fn revoked(&self, route: &SandboxServiceRoute, token: RouteToken) {
        let mut receiver = self.sender.subscribe();
        loop {
            let expiry = {
                let snapshot = receiver.borrow_and_update();
                if snapshot.epoch != token.epoch
                    || snapshot.generations.get(&route.name) != Some(&token.generation)
                    || snapshot.routes.get(&route.name) != Some(route)
                {
                    return;
                }
                let Some(expiry) = self.serving_expiry(&snapshot) else {
                    return;
                };
                expiry
            };
            tokio::select! {
                () = tokio::time::sleep_until(expiry) => return,
                result = receiver.changed() => if result.is_err() { return; },
            }
        }
    }
}

pub struct BoundListener {
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    domain: String,
}

/// Host-level dispatcher. It never shares a sandbox connector or policy
/// between instances: TLS streams are handed to the owning instance runtime.
#[derive(Clone, Default)]
pub struct Router {
    domain: String,
    requires_authority: bool,
    registrations: Arc<Mutex<BTreeMap<String, mpsc::Sender<Accepted>>>>,
}

struct Accepted {
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    permit: tokio::sync::OwnedSemaphorePermit,
}

struct Registration {
    router: Router,
    sandbox: String,
    prefix: Mutex<String>,
    sender: mpsc::Sender<Accepted>,
}

impl Registration {
    fn bind(&self, workspace: &str) -> bool {
        let next = format!("{workspace}--{}", self.sandbox);
        let mut prefix = self
            .prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries = self
            .router
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&next)
            .is_some_and(|sender| !sender.same_channel(&self.sender))
        {
            return false;
        }
        if *prefix != next {
            if entries
                .get(&*prefix)
                .is_some_and(|s| s.same_channel(&self.sender))
            {
                entries.remove(&*prefix);
            }
            prefix.clone_from(&next);
        }
        entries.insert(next, self.sender.clone());
        true
    }

    fn remove(&self) {
        let prefix = self
            .prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries = self
            .router
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&*prefix)
            .is_some_and(|s| s.same_channel(&self.sender))
        {
            entries.remove(&*prefix);
        }
    }
}

/// Process-owned listener. Dropping it stops acceptance without affecting
/// another host process. Individual instance lifetimes are independent.
pub struct HostHandle {
    task: tokio::task::JoinHandle<()>,
    router: Router,
}

impl HostHandle {
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Shared members require short gateway-issued ownership leases as well as
    /// accepted configuration; configuration renewal alone cannot extend service.
    pub(crate) fn leased_router(&self) -> Router {
        let mut router = self.router.clone();
        router.requires_authority = true;
        router
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct InstanceListener {
    pub(crate) routes: Routes,
    receiver: mpsc::Receiver<Accepted>,
    domain: String,
}

pub struct Handle {
    task: tokio::task::JoinHandle<()>,
    routes: Routes,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.routes.stopped.store(true, Ordering::Release);
        self.routes.suspend();
        if let Some(registration) = &self.routes.registration {
            registration.remove();
        }
        self.task.abort();
    }
}

impl Router {
    pub(crate) fn instance(&self, sandbox: &str) -> Result<InstanceListener> {
        if !valid_label(sandbox) || sandbox.contains("--") {
            return Err(miette::miette!(
                "app listener requires a canonical sandbox name"
            ));
        }
        let (sender, receiver) = mpsc::channel(16);
        let registration = Arc::new(Registration {
            router: self.clone(),
            sandbox: sandbox.to_string(),
            prefix: Mutex::new(String::new()),
            sender,
        });
        Ok(InstanceListener {
            routes: Routes {
                registration: Some(registration),
                requires_authority: self.requires_authority,
                ..Default::default()
            },
            receiver,
            domain: self.domain.clone(),
        })
    }
}

impl BoundListener {
    #[must_use]
    pub fn start(self) -> HostHandle {
        let router = Router {
            domain: self.domain.clone(),
            ..Default::default()
        };
        let dispatch = router.clone();
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(1024));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = self.listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                        let acceptor = self.acceptor.clone();
                        let domain = self.domain.clone();
                        let dispatch = dispatch.clone();
                        connections.spawn(async move {
                            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await else { return; };
                            let Some(sni) = tls.get_ref().1.server_name() else { return; };
                            let Some(label) = sni.strip_suffix(&format!(".{domain}")) else { return; };
                            let mut segments = label.split("--");
                            let (Some(workspace), Some(sandbox)) = (segments.next(), segments.next()) else { return; };
                            let prefix = format!("{workspace}--{sandbox}");
                            let sender = dispatch.registrations.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&prefix).cloned();
                            if let Some(sender) = sender { let _ = sender.try_send(Accepted { tls, permit }); }
                        });
                    }
                }
            }
        });
        HostHandle { task, router }
    }
}

struct Permits {
    _host: tokio::sync::OwnedSemaphorePermit,
    _instance: tokio::sync::OwnedSemaphorePermit,
}

impl InstanceListener {
    /// Called on the sandbox instance runtime, preserving its OCSF/logging
    /// identity even when multiple sandboxes share one listener process.
    pub(crate) fn start(mut self, connector: Arc<BoundaryLoopbackConnector>) -> Handle {
        self.routes.serving.store(true, Ordering::Release);
        let retained_routes = self.routes.clone();
        let task = tokio::spawn(async move {
            let routes = self.routes.clone();
            let permits = Arc::new(Semaphore::new(64));
            let mut connections = JoinSet::new();
            ocsf_emit!(
                AppLifecycleBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Open)
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .message("Supervisor app ingress ready")
                    .build()
            );
            loop {
                tokio::select! {
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = self.receiver.recv() => {
                        let Some(Accepted { tls, permit: host_permit }) = accepted else { break; };
                        let Ok(instance_permit) = permits.clone().try_acquire_owned() else { continue; };
                        let Some(sni) = tls.get_ref().1.server_name().map(str::to_ascii_lowercase) else { continue; };
                        let prefix = routes.registration.as_ref().expect("instance registration").prefix.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                        let Some((route, token)) = routes.resolve(&sni, &prefix, &self.domain) else {
                            emit_denial("App listener unknown or expired SNI route"); continue;
                        };
                        let routes = routes.clone();
                        let connector = connector.clone();
                        connections.spawn(async move {
                            let connection_routes = routes.clone();
                            let connection_route = route.clone();
                            let permit = Arc::new(Permits { _host: host_permit, _instance: instance_permit });
                            let service = hyper::service::service_fn(move |req| {
                                proxy(req, sni.clone(), route.clone(), routes.clone(), connector.clone(), permit.clone(), token)
                            });
                            let connection = hyper::server::conn::http1::Builder::new()
                                .timer(TokioTimer::new()).header_read_timeout(HANDSHAKE_TIMEOUT)
                                .max_buf_size(65536).max_headers(64)
                                .serve_connection(TokioIo::new(tls), service).with_upgrades();
                            tokio::select! {
                                _ = connection => {},
                                () = connection_routes.revoked(&connection_route, token) => {},
                            }
                        });
                    }
                }
            }
        });
        Handle {
            task,
            routes: retained_routes,
        }
    }
}

fn error(status: StatusCode) -> Response<Body> {
    ocsf_emit!(
        HttpActivityBuilder::new(crate::ocsf_ctx())
            .http_response(HttpResponse {
                code: status.as_u16()
            })
            .activity(ActivityId::Other)
            .action(ActionId::Denied)
            .disposition(if status.is_server_error() {
                DispositionId::Error
            } else {
                DispositionId::Blocked
            })
            .severity(if status.is_server_error() {
                SeverityId::Low
            } else {
                SeverityId::Medium
            })
            .status(StatusId::Failure)
            .message(format!(
                "App listener request rejected [status:{}]",
                status.as_u16()
            ))
            .build()
    );
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("valid error response")
}

fn emit_denial(message: &str) {
    ocsf_emit!(
        NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(openshell_ocsf::Endpoint {
                domain: None,
                ip: None,
                port: None,
                name: None,
            })
            .message(message)
            .build()
    );
}

fn authority_matches<B>(req: &Request<B>, sni: &str) -> bool {
    let mut values = req.headers().get_all(header::HOST).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    if value.contains('@') {
        return false;
    }
    let Ok(authority) = value.parse::<http::uri::Authority>() else {
        return false;
    };
    if authority.port().is_some() && authority.port_u16().is_none() {
        return false;
    }
    authority.host().eq_ignore_ascii_case(sni)
        && req
            .uri()
            .authority()
            .is_none_or(|uri| uri.as_str().eq_ignore_ascii_case(value))
}

fn gateway_header(name: &str) -> bool {
    matches!(
        name,
        "proxy-authorization"
            | "cf-access-jwt-assertion"
            | "cf-access-authenticated-user-email"
            | "x-openshell-principal"
            | "x-openshell-user"
            | "x-openshell-roles"
            | "x-forwarded-client-cert"
            | "x-ssl-client-cert"
            | "x-client-cert"
    )
}

fn hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn sanitize_headers(headers: &mut http::HeaderMap, passthrough: bool, websocket: bool) -> bool {
    if passthrough {
        let values: Vec<_> = headers.get_all(header::AUTHORIZATION).iter().collect();
        if values.len() > 1 {
            return false;
        }
        if let Some(value) = values.first() {
            let Ok(value) = value.to_str() else {
                return false;
            };
            let Some(token) = openshell_core::auth::strip_bearer_scheme(value) else {
                return false;
            };
            if token.is_empty()
                || !token
                    .trim_end_matches('=')
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
                || token.trim_end_matches('=').is_empty()
            {
                return false;
            }
        }
    } else {
        headers.remove(header::AUTHORIZATION);
    }
    let connection_headers: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect();
    let remove: Vec<_> = headers
        .keys()
        .filter(|name| {
            gateway_header(name.as_str())
                || ((hop_header(name.as_str())
                    || connection_headers
                        .iter()
                        .any(|value| value == name.as_str()))
                    && !(websocket && matches!(name.as_str(), "connection" | "upgrade")))
        })
        .cloned()
        .collect();
    for name in remove {
        headers.remove(name);
    }
    let cookies: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter(|cookie| {
            cookie.split_once('=').is_some_and(|(name, _)| {
                !name.trim().eq_ignore_ascii_case("CF_Authorization")
                    && !name.trim().eq_ignore_ascii_case("cf-authorization")
            })
        })
        .map(str::trim)
        .collect();
    let cookie = cookies.join("; ");
    headers.remove(header::COOKIE);
    if !cookie.is_empty()
        && let Ok(cookie) = cookie.parse()
    {
        headers.insert(header::COOKIE, cookie);
    }
    true
}

async fn proxy(
    mut req: Request<Incoming>,
    sni: String,
    route: SandboxServiceRoute,
    routes: Routes,
    connector: Arc<BoundaryLoopbackConnector>,
    permit: Arc<Permits>,
    token: RouteToken,
) -> std::result::Result<Response<Body>, std::convert::Infallible> {
    if !routes.valid(&route, token) {
        return Ok(error(StatusCode::SERVICE_UNAVAILABLE));
    }
    if !authority_matches(&req, &sni) {
        return Ok(error(StatusCode::MISDIRECTED_REQUEST));
    }
    // Keep the public authority after validating it against SNI. The dial target
    // is loopback, but rewriting Host would break application same-origin checks.
    let authority = req.headers()[header::HOST].clone();
    let websocket = req
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if !sanitize_headers(req.headers_mut(), route.authorization_mode == 2, websocket) {
        return Ok(error(StatusCode::BAD_REQUEST));
    }
    let downstream = websocket.then(|| hyper::upgrade::on(&mut req));
    let target = LoopbackTarget::new(
        "127.0.0.1".parse().expect("loopback"),
        u16::try_from(route.target_port).expect("validated route port"),
    )
    .expect("validated route port");
    let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(target)).await
    else {
        return Ok(error(StatusCode::BAD_GATEWAY));
    };
    let Ok((mut sender, connection)) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    else {
        return Ok(error(StatusCode::BAD_GATEWAY));
    };
    let upstream_task = tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let (mut parts, body) = req.into_parts();
    parts.uri = parts
        .uri
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .parse()
        .expect("valid path");
    parts.headers.insert(header::HOST, authority);
    let response = sender.send_request(Request::from_parts(parts, body)).await;
    let Ok(mut response) = response else {
        upstream_task.abort();
        return Ok(error(StatusCode::BAD_GATEWAY));
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS && websocket {
        let upstream = hyper::upgrade::on(&mut response);
        let downstream = downstream.expect("websocket upgrade");
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = async {
                    if let (Ok(upstream), Ok(downstream)) = tokio::join!(upstream, downstream) {
                        let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(upstream), &mut TokioIo::new(downstream)).await;
                    }
                } => {},
                () = routes.revoked(&route, token) => {},
            }
            upstream_task.abort();
        });
        let (parts, _) = response.into_parts();
        return Ok(Response::from_parts(parts, Body::empty()));
    }
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt as _, StreamExt as _};
    use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};
    use openshell_sandbox_backend::test_support as rpc_test;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    #[test]
    fn installation_evidence_requires_a_serving_instance_and_sufficient_freshness() {
        let routes = Routes::default();
        let source = routes.installation_source();
        let route = SandboxServiceRoute {
            endpoint_id: "endpoint".into(),
            name: "web".into(),
            target_port: 8080,
            authorization_mode: 1,
            resource_version: 1,
        };
        let mut config = installed(vec![route.clone()]);
        config.config_revision = 42;
        config.configuration_instance_id = "generation-a".into();
        routes.install(&config);
        assert!(source(Duration::from_secs(15)).routes.is_empty());
        routes.serving.store(true, Ordering::Release);
        let report = source(Duration::from_secs(15));
        assert_eq!(report.routes, vec![route]);
        assert_eq!(report.config_revision, 42);
        assert_eq!(report.configuration_instance_id, "generation-a");
        routes.sender.send_modify(|snapshot| {
            snapshot.expires = Some(Instant::now() + Duration::from_secs(5));
        });
        assert!(source(Duration::from_secs(15)).routes.is_empty());
        routes.renew();
        assert!(!source(Duration::from_secs(15)).routes.is_empty());
        routes.suspend();
        routes.renew();
        assert!(source(Duration::from_secs(15)).routes.is_empty());
        routes.install(&config);
        routes.stopped.store(true, Ordering::Release);
        assert!(source(Duration::from_secs(15)).routes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shared_authority_expires_despite_config_renewal_and_fences_old_streams() {
        let routes = Routes {
            requires_authority: true,
            ..Default::default()
        };
        routes.serving.store(true, Ordering::Release);
        let route = SandboxServiceRoute {
            endpoint_id: "endpoint".into(),
            name: "web".into(),
            target_port: 8080,
            authorization_mode: 1,
            resource_version: 1,
        };
        routes.install(&installed(vec![route.clone()]));
        assert!(
            routes
                .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
                .is_none()
        );
        let source = routes.installation_source();
        assert_eq!(source(Duration::from_secs(15)).routes, vec![route.clone()]);
        let (_, token) = routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        routes.renew();
        assert!(routes.valid(&route, token));
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(!routes.valid(&route, token));
        assert!(
            routes
                .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
                .is_none()
        );
        tokio::time::timeout(Duration::from_secs(1), routes.revoked(&route, token))
            .await
            .unwrap();
        source(Duration::from_secs(15));
        assert!(
            !routes.valid(&route, token),
            "renewal cannot revive a prior stream"
        );
        assert!(
            routes
                .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
                .is_some()
        );
        routes.suspend();
        assert!(source(Duration::from_secs(15)).routes.is_empty());
    }

    #[test]
    fn listener_requires_explicit_enablement_and_complete_configuration() {
        let complete = BTreeMap::from([
            ("OPENSHELL_APP_LISTEN_ADDRESS", "0.0.0.0:9443"),
            ("OPENSHELL_APP_SERVICE_DOMAIN", "services.example.com"),
            ("OPENSHELL_APP_TLS_CERT", "/operator/cert.pem"),
            ("OPENSHELL_APP_TLS_KEY", "/operator/key.pem"),
        ]);
        assert!(
            Config::from_values(|name| complete.get(name).map(ToString::to_string))
                .unwrap()
                .is_none()
        );
        let mut values = complete.clone();
        values.insert("OPENSHELL_APP_LISTENER_ENABLED", "false");
        assert!(
            Config::from_values(|name| values.get(name).map(ToString::to_string))
                .unwrap()
                .is_none()
        );
        values.insert("OPENSHELL_APP_LISTENER_ENABLED", "true");
        assert_eq!(
            Config::from_values(|name| values.get(name).map(ToString::to_string))
                .unwrap()
                .unwrap()
                .address
                .port(),
            9443
        );
        values.remove("OPENSHELL_APP_TLS_KEY");
        assert!(Config::from_values(|name| values.get(name).map(ToString::to_string)).is_err());
        assert!(
            Config::from_values(
                |name| (name == "OPENSHELL_APP_LISTENER_ENABLED").then(|| "true".into())
            )
            .is_err()
        );
    }

    const HOST: &str = "default--sandbox-a--web.svc.openshell.internal";

    fn installed(routes: Vec<SandboxServiceRoute>) -> SettingsPollResult {
        SettingsPollResult {
            service_routes: routes,
            settings_revision: 1,
            configuration_instance_id: "runtime-a".into(),
            configuration_admitted: true,
            configuration_error: String::new(),
            policy: None,
            version: 1,
            policy_hash: String::new(),
            config_revision: 1,
            policy_source: openshell_core::proto::PolicySource::Unspecified,
            settings: std::collections::HashMap::default(),
            global_policy_version: 0,
            provider_env_revision: 0,
            provider_attachment_epoch: String::new(),
            supervisor_middleware_services: Vec::new(),
            workspace: "default".into(),
            policy_validation_failure_mode: openshell_core::PolicyValidationFailureMode::default(),
            extension_authentication_enabled: false,
        }
    }

    struct Connector {
        calls: AtomicUsize,
    }

    #[tonic::async_trait]
    impl rpc_test::BoundaryLoopbackConnector for Connector {
        async fn connect(
            &self,
            target: LoopbackTarget,
        ) -> std::result::Result<BoundaryDuplexStream, BackendError> {
            assert_eq!(target.port(), 8080);
            let (client, server) = tokio::io::duplex(8192);
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|mut req: Request<Incoming>| async move {
                    if let Some(key) = req.headers().get("sec-websocket-key") {
                        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                            key.as_bytes(),
                        );
                        let upgraded = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            if let Ok(stream) = upgraded.await {
                                let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                                    TokioIo::new(stream),
                                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                                    None,
                                )
                                .await;
                                while let Some(Ok(message)) = ws.next().await {
                                    if ws.send(message).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        });
                        return Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(101)
                                .header("connection", "upgrade")
                                .header("upgrade", "websocket")
                                .header("sec-websocket-accept", accept)
                                .header("x-test-upstream-host", req.headers()[header::HOST].clone())
                                .header(
                                    "x-test-upstream-origin",
                                    req.headers()
                                        .get(header::ORIGIN)
                                        .cloned()
                                        .unwrap_or_else(|| "absent".parse().unwrap()),
                                )
                                .body(Body::empty())
                                .unwrap(),
                        );
                    }
                    let body = format!(
                        "{} {} {} {}",
                        req.uri(),
                        req.headers()[header::HOST].to_str().unwrap(),
                        req.headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("stripped"),
                        req.headers()
                            .get(header::ORIGIN)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("absent")
                    );
                    Ok::<_, std::convert::Infallible>(Response::new(Body::from(body)))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(server), service)
                    .with_upgrades()
                    .await;
            });
            Ok(Box::new(client))
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        handle: Handle,
        address: SocketAddr,
        tls: Arc<rustls::ClientConfig>,
        routes: Routes,
        connector: Arc<Connector>,
        route: SandboxServiceRoute,
        host: HostHandle,
    }

    fn fixture() -> Fixture {
        openshell_crypto::tls::ensure_default_provider();
        let directory = tempfile::tempdir().unwrap();
        let cert = openshell_crypto::pki::generate_simple_self_signed(vec![
            "*.svc.openshell.internal".into(),
        ])
        .unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem().unwrap()).unwrap();
        let config = Config {
            address: "127.0.0.1:0".parse().unwrap(),
            domain: "svc.openshell.internal".into(),
            certificate: cert_path,
            key: key_path,
        };
        let bound = config.bind().unwrap();
        let address = bound.listener.local_addr().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let tls = Arc::new(
            openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let host = bound.start();
        let instance = host.router().instance("sandbox-a").unwrap();
        let routes = instance.routes.clone();
        let route = SandboxServiceRoute {
            endpoint_id: "endpoint-a".into(),
            name: "web".into(),
            target_port: 8080,
            authorization_mode: 1,
            resource_version: 1,
        };
        routes.install(&installed(vec![route.clone()]));
        let connector = Arc::new(Connector {
            calls: AtomicUsize::new(0),
        });
        let handle = instance.start(rpc_test::loopback(connector.clone()));
        Fixture {
            _directory: directory,
            handle,
            address,
            tls,
            routes,
            connector,
            route,
            host,
        }
    }

    async fn request(f: &Fixture, sni: &str, host: &str, extra: &str) -> String {
        request_method(f, "GET", sni, host, extra).await
    }

    async fn request_method(
        f: &Fixture,
        method: &str,
        sni: &str,
        host: &str,
        extra: &str,
    ) -> String {
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[f.address])
            .await
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(f.tls.clone())
            .connect(server_name, stream)
            .await
            .unwrap();
        let _ = tls
            .write_all(
                format!(
                    "{method} /hello?x=1 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n"
                )
                .as_bytes(),
            )
            .await;
        let mut response = Vec::new();
        // Unknown SNI closes the TLS stream without an HTTP response.
        let _ = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
            .await
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn browser_post_preserves_public_authority_and_origin() {
        let f = fixture();
        let authority = format!("{HOST}:18443");
        let origin = format!("https://{authority}");
        let response = request_method(
            &f,
            "POST",
            HOST,
            &authority,
            &format!("Origin: {origin}\r\nContent-Length: 0\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains(&format!("/hello?x=1 {authority} stripped {origin}")),
            "{response}"
        );
    }

    #[tokio::test]
    async fn shared_listener_keeps_instance_connectors_and_lifetimes_separate() {
        let f = fixture();
        let second = f.host.router().instance("sandbox-b").unwrap();
        let second_routes = second.routes.clone();
        let second_connector = Arc::new(Connector {
            calls: AtomicUsize::new(0),
        });
        let second_handle = second.start(rpc_test::loopback(second_connector.clone()));
        second_routes.install(&installed(vec![SandboxServiceRoute {
            endpoint_id: "endpoint-b".into(),
            ..f.route.clone()
        }]));
        let host_b = "default--sandbox-b--web.svc.openshell.internal";
        assert!(
            request(&f, host_b, host_b, "")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert_eq!(second_connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 0);

        drop(second_handle);
        assert!(
            !request(&f, host_b, host_b, "")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            request(&f, HOST, HOST, "")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_instance_cleanup_cannot_remove_its_replacement() {
        let f = fixture();
        let replacement = f.host.router().instance("sandbox-a").unwrap();
        replacement
            .routes
            .install(&installed(vec![f.route.clone()]));
        assert!(
            replacement.routes.sender.borrow().routes.is_empty(),
            "duplicate instance must not claim a live registration"
        );
        let old_routes = f.routes.clone();
        drop(f.handle);
        replacement
            .routes
            .install(&installed(vec![f.route.clone()]));
        let prefix = "default--sandbox-a";
        assert!(
            f.host
                .router()
                .registrations
                .lock()
                .unwrap()
                .contains_key(prefix)
        );
        // Simulate delayed cleanup from the old runtime after replacement.
        old_routes.registration.as_ref().unwrap().remove();
        assert!(
            f.host
                .router()
                .registrations
                .lock()
                .unwrap()
                .contains_key(prefix)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn push_freshness_renews_live_routes_but_cannot_revive_rejected_routes() {
        let routes = Routes::default();
        let route = SandboxServiceRoute {
            endpoint_id: "ep".into(),
            name: "web".into(),
            target_port: 8080,
            authorization_mode: 1,
            resource_version: 1,
        };
        routes.install(&installed(vec![route.clone()]));
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(5)).await;
            routes.renew();
        }
        assert!(
            routes
                .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
                .is_some()
        );
        let mut rejected = installed(vec![route]);
        rejected.configuration_admitted = false;
        routes.install(&rejected);
        routes.renew();
        assert!(
            routes
                .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
                .is_none()
        );
    }

    #[tokio::test]
    async fn tls_routes_only_matching_sni_and_authority() {
        let f = fixture();
        let response = request(
            &f,
            HOST,
            &format!("{HOST}:18443"),
            "Authorization: Bearer app-token\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains(&format!("/hello?x=1 {HOST}:18443 stripped")),
            "{response}"
        );
        let mismatch = request(
            &f,
            HOST,
            "default--sandbox-b--web.svc.openshell.internal",
            "",
        )
        .await;
        assert!(mismatch.starts_with("HTTP/1.1 421"), "{mismatch}");
        let unknown = request(
            &f,
            "default--sandbox-b--web.svc.openshell.internal",
            "default--sandbox-b--web.svc.openshell.internal",
            "",
        )
        .await;
        assert!(unknown.is_empty());
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn duplicate_host_and_malformed_bearer_never_dial_boundary() {
        let f = fixture();
        let duplicate = request(&f, HOST, HOST, &format!("Host: {HOST}\r\n")).await;
        assert!(!duplicate.starts_with("HTTP/1.1 200"));
        f.routes
            .sender
            .send_modify(|snapshot| snapshot.routes.get_mut("web").unwrap().authorization_mode = 2);
        let malformed = request(&f, HOST, HOST, "Authorization: Basic credential\r\n").await;
        assert!(malformed.starts_with("HTTP/1.1 400"));
        let valid = request(&f, HOST, HOST, "Authorization: bEaReR app-token\r\n").await;
        assert!(valid.contains("bEaReR app-token"), "{valid}");
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn withdrawn_and_expired_routes_never_dial_boundary() {
        let f = fixture();
        let (_, old_token) = f
            .routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        f.routes.suspend();
        f.routes.install(&installed(vec![f.route.clone()]));
        // Even a quickly restored identical route cannot revive an old stream.
        tokio::time::timeout(
            Duration::from_secs(1),
            f.routes.revoked(&f.route, old_token),
        )
        .await
        .unwrap();
        f.routes.sender.send_modify(|snapshot| {
            snapshot.expires = Some(Instant::now() - Duration::from_secs(1));
        });
        assert!(request(&f, HOST, HOST, "").await.is_empty());
        f.routes.suspend();
        assert!(request(&f, HOST, HOST, "").await.is_empty());
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn headers_strip_edge_identity_and_connection_named_fields() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "app=session; CF_Authorization=secret".parse().unwrap(),
        );
        headers.insert("x-forwarded-client-cert", "secret".parse().unwrap());
        headers.insert(header::CONNECTION, "x-internal".parse().unwrap());
        headers.insert("x-internal", "secret".parse().unwrap());
        assert!(sanitize_headers(&mut headers, false, false));
        assert_eq!(headers[header::COOKIE], "app=session");
        assert!(!headers.contains_key("x-forwarded-client-cert"));
        assert!(!headers.contains_key("x-internal"));
    }
    #[tokio::test]
    async fn websocket_echo_closes_on_route_withdrawal() {
        let f = fixture();
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[f.address])
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from(HOST.to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(f.tls.clone())
            .connect(name, stream)
            .await
            .unwrap();
        let mut request = format!("wss://{HOST}/echo").into_client_request().unwrap();
        request
            .headers_mut()
            .insert(header::ORIGIN, format!("https://{HOST}").parse().unwrap());
        let (mut ws, response) = tokio_tungstenite::client_async(request, tls).await.unwrap();
        assert_eq!(response.headers()["x-test-upstream-host"], HOST);
        assert_eq!(
            response.headers()["x-test-upstream-origin"],
            format!("https://{HOST}")
        );
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            "hello".into(),
        ))
        .await
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .to_text()
                .unwrap(),
            "hello"
        );
        f.routes.suspend();
        let closed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap();
        assert!(closed.is_none() || closed.unwrap().is_err());
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    type TestWebSocket =
        tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

    async fn websocket(f: &Fixture, service: &str) -> TestWebSocket {
        let host = format!("default--sandbox-a--{service}.svc.openshell.internal");
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[f.address])
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from(host.clone()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(f.tls.clone())
            .connect(name, stream)
            .await
            .unwrap();
        tokio_tungstenite::client_async(format!("wss://{host}/echo"), tls)
            .await
            .unwrap()
            .0
    }

    async fn echo(ws: &mut TestWebSocket, value: &str) {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(value.into()))
            .await
            .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(echoed.to_text().unwrap(), value);
    }

    async fn closed(ws: &mut TestWebSocket) {
        let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("revoked WebSocket must close");
        assert!(next.is_none() || next.unwrap().is_err());
    }

    #[tokio::test]
    async fn service_edits_close_only_affected_websockets() {
        let f = fixture();
        let mut web = websocket(&f, "web").await;
        let mut portal = SandboxServiceRoute {
            endpoint_id: "portal-id".into(),
            name: "portal".into(),
            ..f.route.clone()
        };
        f.routes
            .install(&installed(vec![f.route.clone(), portal.clone()]));
        echo(&mut web, "web survives portal addition").await;
        let mut portal_ws = websocket(&f, "portal").await;
        echo(&mut portal_ws, "portal active").await;

        // Renewing identical declarations does not revoke either stream.
        f.routes
            .install(&installed(vec![f.route.clone(), portal.clone()]));
        echo(&mut web, "web renewed").await;
        echo(&mut portal_ws, "portal renewed").await;

        portal.authorization_mode = 2;
        portal.resource_version += 1;
        f.routes
            .install(&installed(vec![f.route.clone(), portal.clone()]));
        closed(&mut portal_ws).await;
        echo(&mut web, "web survives portal edit").await;

        let mut portal_ws = websocket(&f, "portal").await;
        f.routes.install(&installed(vec![f.route.clone()]));
        closed(&mut portal_ws).await;
        echo(&mut web, "web survives portal deletion").await;

        f.routes.install(&installed(vec![f.route.clone(), portal]));
        let mut portal_ws = websocket(&f, "portal").await;
        f.routes.suspend();
        closed(&mut web).await;
        closed(&mut portal_ws).await;
    }

    #[tokio::test]
    async fn coalesced_recreation_and_lease_lapse_cannot_revive_old_streams() {
        let f = fixture();
        let (_, original) = f
            .routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        // Both updates can occur before a watch receiver observes either one.
        f.routes.install(&installed(Vec::new()));
        f.routes.install(&installed(vec![f.route.clone()]));
        tokio::time::timeout(Duration::from_secs(1), f.routes.revoked(&f.route, original))
            .await
            .unwrap();

        let (_, renewed) = f
            .routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        f.routes.sender.send_modify(|snapshot| {
            snapshot.expires = Some(Instant::now() - Duration::from_secs(1));
        });
        f.routes.install(&installed(vec![f.route.clone()]));
        tokio::time::timeout(Duration::from_secs(1), f.routes.revoked(&f.route, renewed))
            .await
            .unwrap();
    }
}
