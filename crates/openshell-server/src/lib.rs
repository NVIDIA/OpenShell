// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Server library.
//!
//! This crate provides the server implementation for `OpenShell`, including:
//! - gRPC service implementation
//! - HTTP health endpoints
//! - Protocol multiplexing (gRPC + HTTP on same port)
//! - mTLS support
//!
//! Compiled-in compute drivers are installed into a registry at gateway
//! startup. Runtime selection only consults that registry or a configured
//! external endpoint; it does not switch on driver names.

mod auth;
pub mod certgen;
pub mod cli;
mod compute;
pub mod config_file;
mod credentials;
mod defaults;
mod gateway_listener;
mod grpc;
mod http;
mod inference;
mod middleware;
mod multiplex;
mod otel_tracing;
mod persistence;
pub(crate) mod policy_store;
mod provider_profile_sources;
mod provider_refresh;
mod readiness;
mod sandbox_index;
mod sandbox_watch;
mod service_routing;
mod ssh_sessions;
pub mod supervisor_session;
mod telemetry;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod tls;
#[cfg(test)]
pub(crate) mod tls_test_utils;
pub mod tracing_bus;
mod tracing_setup;
mod ws_tunnel;

use metrics_exporter_prometheus::PrometheusBuilder;
#[cfg(target_os = "windows")]
use openshell_core::ComputeDriverKind;
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_core::{Config, Error, ObjectLabels, Result};
use openshell_extension_core::{
    BearerTokenSlot, ExtensionAudience, ExtensionCallerKind, ExtensionKind, MAX_EXTENSION_TOKEN_TTL,
};
use openshell_supervisor_middleware::MiddlewareRegistry;
use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
#[cfg(test)]
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Serializes tests that assert on captured spans, which share one exporter.
#[cfg(test)]
pub(crate) static TEST_TRACING_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub(crate) fn install_jsonwebtoken_crypto_provider() {
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

use compute::ComputeRuntime;
use gateway_listener::{BoundGatewayListener, GatewayListenerScope, bind_gateway_listeners};
pub use grpc::OpenShellService;
pub use http::{health_router, http_router, metrics_router, service_http_router};

/// Deriving `Debug` is safe here: `BearerTokenSlot` renders only its expiry,
/// and an extension audience is configuration rather than secret material.
#[derive(Debug)]
struct GatewayExtensionCredential {
    name: String,
    audience: ExtensionAudience,
    slot: BearerTokenSlot,
    ttl: Duration,
}

fn extension_token_ttl(issuer: &auth::sandbox_jwt::SandboxJwtIssuer) -> Duration {
    if issuer.ttl().is_zero() {
        Duration::from_secs(15 * 60)
    } else {
        issuer.ttl().min(MAX_EXTENSION_TOKEN_TTL)
    }
}

/// Mint the gateway-caller credential for one extension registration.
///
/// Returns `Ok(None)` when the operator has explicitly opted the registration
/// out of extension authentication. The opt-out is deliberately loud: it
/// downgrades a security boundary, so it is reported once per registration at
/// startup rather than being silently tolerated.
fn mint_gateway_extension_credential(
    issuer: &Arc<auth::sandbox_jwt::SandboxJwtIssuer>,
    kind: ExtensionKind,
    name: &str,
    audience: &str,
    endpoint: &str,
    allow_insecure_transport: bool,
) -> Result<Option<GatewayExtensionCredential>> {
    // A middleware endpoint must be reachable from sandbox supervisors, so a
    // gateway-local Unix socket is only an option for interceptors.
    let (accepted, supports_unix) = match kind {
        ExtensionKind::Middleware => ("https://", false),
        ExtensionKind::Interceptor => ("https:// or unix://", true),
        _ => {
            return Err(Error::config(format!(
                "extension kind '{kind}' is not supported by gateway authentication"
            )));
        }
    };
    if allow_insecure_transport {
        warn!(
            extension = %name,
            endpoint = %endpoint,
            "extension authentication is DISABLED for this registration by \
             allow_insecure_transport; OpenShell attaches no caller credential \
             and the service cannot distinguish OpenShell from any other \
             network client. Use {accepted} with the opt-out removed outside \
             trusted-network development deployments."
        );
        return Ok(None);
    }
    let transport_supported =
        endpoint.starts_with("https://") || (supports_unix && endpoint.starts_with("unix://"));
    if !transport_supported {
        return Err(Error::config(format!(
            "authenticated {kind} '{name}' must use {accepted}; set \
             allow_insecure_transport = true to opt this registration out of \
             extension authentication instead"
        )));
    }
    let audience = ExtensionAudience::new(audience.to_string()).map_err(|error| {
        Error::config(format!(
            "extension '{name}' has an invalid audience: {error}"
        ))
    })?;
    let ttl = extension_token_ttl(issuer);
    let minted = issuer
        .mint_extension_token(&audience, ExtensionCallerKind::Gateway, None, ttl)
        .map_err(|status| {
            Error::config(format!(
                "failed to mint credential for extension '{name}': {}",
                status.message()
            ))
        })?;
    let slot = BearerTokenSlot::new(&minted.token, minted.expires_at_ms).map_err(|error| {
        Error::config(format!(
            "failed to install credential for extension '{name}': {error}"
        ))
    })?;
    Ok(Some(GatewayExtensionCredential {
        name: name.to_string(),
        audience,
        slot,
        ttl,
    }))
}

fn spawn_gateway_extension_token_refresh(
    issuer: Arc<auth::sandbox_jwt::SandboxJwtIssuer>,
    credentials: Vec<GatewayExtensionCredential>,
) {
    if credentials.is_empty() {
        return;
    }
    tokio::spawn(async move {
        loop {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| {
                    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
                });
            let remaining_ms = credentials
                .iter()
                .filter_map(|credential| credential.slot.expires_at_ms())
                .min()
                .map_or(60_000, |expiry_ms| expiry_ms.saturating_sub(now_ms));
            let refresh_delay = if remaining_ms <= 0 {
                Duration::from_millis(100)
            } else {
                Duration::from_millis(
                    u64::try_from(remaining_ms)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(4)
                        .checked_div(5)
                        .unwrap_or(100)
                        .max(100),
                )
            };
            tokio::time::sleep(refresh_delay).await;
            for credential in &credentials {
                match issuer.mint_extension_token(
                    &credential.audience,
                    ExtensionCallerKind::Gateway,
                    None,
                    credential.ttl,
                ) {
                    Ok(minted) => {
                        if let Err(error) =
                            credential.slot.update(&minted.token, minted.expires_at_ms)
                        {
                            warn!(
                                extension = %credential.name,
                                error = %error,
                                "failed to rotate gateway extension credential"
                            );
                        }
                    }
                    Err(status) => warn!(
                        extension = %credential.name,
                        error = %status,
                        "failed to mint gateway extension credential"
                    ),
                }
            }
        }
    });
}
pub use multiplex::{MultiplexService, MultiplexedService};
pub use persistence::Store;
use sandbox_index::SandboxIndex;
use sandbox_watch::SandboxWatchBus;
pub use tls::TlsAcceptor;
use tracing_bus::TracingLogBus;

pub(crate) struct ServerStartupConfig {
    pub config: Config,
    pub config_file: Option<config_file::ConfigFile>,
    pub guest_tls: Option<compute::driver_config::GuestTlsPaths>,
    pub compute_driver: ComputeDriverSelection,
}

/// Server state shared across handlers.
#[derive(Debug)]
pub struct ServerState {
    /// Server configuration.
    pub config: Config,

    /// Persistence store.
    pub store: Arc<Store>,

    /// Compute orchestration over the configured driver.
    pub compute: ComputeRuntime,

    /// Credential-driver selection and resolution runtime.
    pub credentials: credentials::CredentialRuntime,

    /// In-memory sandbox correlation index.
    pub sandbox_index: SandboxIndex,

    /// In-memory bus for sandbox update notifications.
    pub sandbox_watch_bus: SandboxWatchBus,

    /// In-memory bus for server process logs.
    pub tracing_log_bus: TracingLogBus,

    /// In-memory anonymous telemetry accounting for active sandbox sessions.
    pub(crate) telemetry: telemetry::TelemetryState,

    /// Active SSH tunnel connection counts per session token.
    pub ssh_connections_by_token: Mutex<HashMap<String, u32>>,

    /// Active SSH tunnel connection counts per sandbox id.
    pub ssh_connections_by_sandbox: Mutex<HashMap<String, u32>>,

    /// Serializes settings mutations (global and sandbox) to prevent
    /// read-modify-write races. Held for the duration of any setting
    /// set/delete operation, including the precedence check on sandbox
    /// mutations that reads global state.
    pub settings_mutex: tokio::sync::Mutex<()>,

    /// Registry of active supervisor sessions and pending relay channels.
    ///
    /// Stored as `Arc` so compute drivers (e.g. the Docker driver)
    /// can be constructed before `ServerState` and still
    /// query session state to surface supervisor readiness.
    pub supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,

    /// Validated built-in and operator-registered supervisor middleware.
    pub middleware_registry: Arc<MiddlewareRegistry>,

    /// OIDC JWKS cache for JWT validation. `None` when OIDC is not configured.
    pub oidc_cache: Option<Arc<auth::oidc::JwksCache>>,

    /// Gateway-minted sandbox JWT issuer. `None` when `config.gateway_jwt`
    /// is not configured; in that mode `IssueSandboxToken` returns
    /// `Status::unavailable`. Populated at startup from the on-disk key
    /// material that `certgen` writes.
    pub sandbox_jwt_issuer: Option<Arc<auth::sandbox_jwt::SandboxJwtIssuer>>,

    /// Authenticator that validates gateway-minted sandbox JWTs on every
    /// inbound request. Always set when `sandbox_jwt_issuer` is, so callers
    /// presenting a freshly minted token are recognized.
    pub sandbox_jwt_authenticator: Option<Arc<auth::sandbox_jwt::SandboxJwtAuthenticator>>,

    /// Optional K8s `ServiceAccount` authenticator that backs the
    /// `IssueSandboxToken` bootstrap path. Only present when the gateway
    /// runs in-cluster.
    pub k8s_sa_authenticator: Option<Arc<auth::k8s_sa::K8sServiceAccountAuthenticator>>,

    /// Gateway-wide gRPC request rate limiter shared by every multiplex path.
    pub(crate) grpc_rate_limiter: Option<multiplex::GrpcRateLimiter>,

    /// Per-sandbox bound on extension credential minting, which resolves the
    /// caller's effective policy on every request.
    pub(crate) extension_mint_limiter: auth::extension_mint_limit::ExtensionMintLimiter,

    /// Immutable gateway interceptor execution plan. `None` when disabled.
    pub(crate) gateway_interceptors:
        Option<openshell_gateway_interceptors::GatewayInterceptorRuntime>,

    /// Gateway-local provider profile sources. User-imported profiles are read
    /// on demand when the user source is configured.
    pub(crate) provider_profile_sources: provider_profile_sources::ProviderProfileSources,

    /// OIDC admin role name for workspace-level authorization.
    /// Empty when OIDC is not configured — `authorize_workspace()` treats
    /// every authenticated user as Platform Admin in that case.
    pub admin_role: String,
}

fn is_benign_tls_handshake_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
    )
}

fn is_benign_connection_close(error: &(dyn std::error::Error + 'static)) -> bool {
    openshell_core::transport_errors::is_expected_transport_close_error(error)
}

impl ServerState {
    /// Create new server state.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        store: Arc<Store>,
        compute: ComputeRuntime,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
        oidc_cache: Option<Arc<auth::oidc::JwksCache>>,
    ) -> Self {
        let credentials =
            credentials::CredentialRuntime::from_config_with_store(&config, Arc::clone(&store))
                .expect("server config should be validated before ServerState::new");
        Self::new_with_credentials(
            config,
            store,
            compute,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions,
            oidc_cache,
            credentials,
        )
    }

    /// Create new server state with an already-initialized credential runtime.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_credentials(
        config: Config,
        store: Arc<Store>,
        compute: ComputeRuntime,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
        oidc_cache: Option<Arc<auth::oidc::JwksCache>>,
        credentials: credentials::CredentialRuntime,
    ) -> Self {
        let grpc_rate_limiter = multiplex::GrpcRateLimiter::from_config(&config);
        let admin_role = config
            .oidc
            .as_ref()
            .map_or_else(String::new, |oidc| oidc.admin_role.clone());
        Self {
            config,
            store,
            compute,
            credentials,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            telemetry: telemetry::TelemetryState::new(),
            ssh_connections_by_token: Mutex::new(HashMap::new()),
            ssh_connections_by_sandbox: Mutex::new(HashMap::new()),
            settings_mutex: tokio::sync::Mutex::new(()),
            supervisor_sessions,
            extension_mint_limiter: auth::extension_mint_limit::ExtensionMintLimiter::default(),
            middleware_registry: Arc::new(MiddlewareRegistry::default()),
            oidc_cache,
            sandbox_jwt_issuer: None,
            sandbox_jwt_authenticator: None,
            k8s_sa_authenticator: None,
            grpc_rate_limiter,
            gateway_interceptors: None,
            provider_profile_sources:
                provider_profile_sources::ProviderProfileSources::with_default_sources(),
            admin_role,
        }
    }
}

/// Run the `OpenShell` server.
///
/// This starts a multiplexed gRPC/HTTP server on the configured bind address.
///
/// # Errors
///
/// Returns an error if the server fails to start or encounters a fatal error.
pub(crate) async fn run_server(
    startup: ServerStartupConfig,
    compute_driver: ConfiguredComputeDriver,
    tracing_log_bus: TracingLogBus,
) -> Result<()> {
    let ServerStartupConfig {
        config,
        config_file,
        guest_tls,
        compute_driver: _,
    } = startup;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    auth::descriptor_authz::init()
        .map_err(|error| Error::config(format!("invalid gRPC authorization metadata: {error}")))?;

    let database_url = config.database_url.trim();
    if database_url.is_empty() {
        return Err(Error::config("database_url is required"));
    }

    // Load signing material before connecting remote extensions so their
    // startup Describe calls can authenticate with gateway-caller tokens.
    let (sandbox_jwt_issuer, sandbox_jwt_authenticator) = if let Some(ref jwt) = config.gateway_jwt
    {
        let signing_pem = std::fs::read(&jwt.signing_key_path).map_err(|e| {
            Error::config(format!(
                "failed to read sandbox JWT signing key from {}: {e}",
                jwt.signing_key_path.display()
            ))
        })?;
        let public_pem = std::fs::read(&jwt.public_key_path).map_err(|e| {
            Error::config(format!(
                "failed to read sandbox JWT public key from {}: {e}",
                jwt.public_key_path.display()
            ))
        })?;
        let kid = std::fs::read_to_string(&jwt.kid_path)
            .map_err(|e| {
                Error::config(format!(
                    "failed to read sandbox JWT kid from {}: {e}",
                    jwt.kid_path.display()
                ))
            })?
            .trim()
            .to_string();
        if kid.is_empty() {
            return Err(Error::config(format!(
                "sandbox JWT kid file {} is empty",
                jwt.kid_path.display()
            )));
        }
        let issuer = Arc::new(
            auth::sandbox_jwt::SandboxJwtIssuer::from_pem(
                &signing_pem,
                kid.clone(),
                &jwt.gateway_id,
                Duration::from_secs(jwt.ttl_secs),
            )
            .map_err(Error::config)?,
        );
        let authenticator = Arc::new(
            auth::sandbox_jwt::SandboxJwtAuthenticator::from_pem(&public_pem, kid, &jwt.gateway_id)
                .map_err(Error::config)?,
        );
        info!(
            gateway_id = %jwt.gateway_id,
            ttl_secs = jwt.ttl_secs,
            "gateway-minted sandbox JWT enabled"
        );
        (Some(issuer), Some(authenticator))
    } else {
        (None, None)
    };

    let middleware_registrations = config_file
        .as_ref()
        .map(|file| {
            file.openshell
                .supervisor
                .middleware
                .iter()
                .map(openshell_core::proto::SupervisorMiddlewareService::try_from)
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|error| Error::config(format!("middleware registration failed: {error}")))?
        .unwrap_or_default();
    let mut gateway_extension_credentials = Vec::new();
    let middleware_registry = Arc::new(
        if let Some(issuer) = sandbox_jwt_issuer.as_ref() {
            let mut slots = HashMap::new();
            for registration in &middleware_registrations {
                if let Some(credential) = mint_gateway_extension_credential(
                    issuer,
                    ExtensionKind::Middleware,
                    &registration.name,
                    &registration.audience,
                    &registration.grpc_endpoint,
                    registration.allow_insecure_transport,
                )? {
                    slots.insert(registration.name.clone(), credential.slot.clone());
                    gateway_extension_credentials.push(credential);
                }
            }
            MiddlewareRegistry::connect_services_authenticated(
                openshell_supervisor_middleware_builtins::services(),
                middleware_registrations,
                &slots,
            )
            .await
        } else {
            MiddlewareRegistry::connect_services(
                openshell_supervisor_middleware_builtins::services(),
                middleware_registrations,
            )
            .await
        }
        .map_err(|error| Error::config(format!("middleware registration failed: {error}")))?,
    );

    let store = Arc::new(Store::connect(database_url).await?);
    let credentials = credentials::CredentialRuntime::from_config_file_with_store(
        &config,
        config_file.as_ref(),
        Arc::clone(&store),
    )
    .await?;

    let oidc_cache = if let Some(ref oidc) = config.oidc {
        // Validate RBAC configuration before starting.
        let policy = auth::authz::AuthzPolicy {
            admin_role: oidc.admin_role.clone(),
            user_role: oidc.user_role.clone(),
            scopes_enabled: !oidc.scopes_claim.is_empty(),
        };
        policy.validate().map_err(Error::config)?;

        let cache = auth::oidc::JwksCache::new(oidc)
            .await
            .map_err(|e| Error::config(format!("OIDC initialization failed: {e}")))?;
        info!("OIDC JWT validation enabled (issuer: {})", oidc.issuer);
        Some(Arc::new(cache))
    } else {
        None
    };

    let sandbox_index = SandboxIndex::new();
    let sandbox_watch_bus = SandboxWatchBus::new();
    let supervisor_sessions = Arc::new(supervisor_session::SupervisorSessionRegistry::new());
    let driver_startup = compute::driver_config::DriverStartupContext {
        file: config_file.as_ref(),
        guest_tls: guest_tls.as_ref(),
        gateway_port: config.bind_address.port(),
        gateway_tls_enabled: config.tls.is_some(),
        endpoint_overrides: &config.compute_driver_endpoints,
    };
    let (compute, operator_allowlist) = build_compute_runtime(
        &config,
        driver_startup,
        compute_driver,
        store.clone(),
        sandbox_index.clone(),
        sandbox_watch_bus.clone(),
        tracing_log_bus.clone(),
        supervisor_sessions.clone(),
        shutdown_rx.clone(),
    )
    .await?;
    let gateway_interceptors = if let Some(issuer) = sandbox_jwt_issuer.as_ref() {
        let mut slots = BTreeMap::new();
        for interceptor in &config.gateway_interceptors {
            let audience = interceptor.resolved_audience();
            if let Some(credential) = mint_gateway_extension_credential(
                issuer,
                ExtensionKind::Interceptor,
                &interceptor.name,
                audience.as_ref(),
                &interceptor.grpc_endpoint,
                interceptor.allow_insecure_transport,
            )? {
                slots.insert(interceptor.name.clone(), credential.slot.clone());
                gateway_extension_credentials.push(credential);
            }
        }
        openshell_gateway_interceptors::initialize_authenticated(
            config.gateway_interceptors.clone(),
            slots,
        )
        .await
    } else {
        openshell_gateway_interceptors::initialize(config.gateway_interceptors.clone()).await
    }
    .map_err(|e| Error::config(format!("gateway interceptor initialization failed: {e}")))?;
    let provider_profile_sources = provider_profile_sources::ProviderProfileSources::from_config(
        &config.provider_profile_sources,
        gateway_interceptors.as_ref(),
    )
    .map_err(|err| {
        Error::config(format!(
            "provider profile source configuration failed: {err}"
        ))
    })?;
    info!(
        sources = ?provider_profile_sources.source_ids(),
        "provider profile sources configured"
    );
    let mut state = ServerState::new_with_credentials(
        config.clone(),
        store.clone(),
        compute,
        sandbox_index,
        sandbox_watch_bus,
        tracing_log_bus,
        supervisor_sessions,
        oidc_cache,
        credentials,
    );
    state.middleware_registry = middleware_registry;
    state.gateway_interceptors = gateway_interceptors;
    state.provider_profile_sources = provider_profile_sources;
    state.sandbox_jwt_issuer = sandbox_jwt_issuer.clone();
    state.sandbox_jwt_authenticator = sandbox_jwt_authenticator;
    if let Some(issuer) = sandbox_jwt_issuer {
        spawn_gateway_extension_token_refresh(issuer, gateway_extension_credentials);
    }

    // K8s ServiceAccount bootstrap authenticator. Only constructed when
    // the gateway is running in-cluster (kubelet provides the API host
    // env var) and has a sandbox JWT issuer to mint replacements against;
    // outside the cluster we can't call the apiserver's TokenReview API,
    // and without the issuer there's nothing to exchange the SA token for.
    #[cfg(not(target_os = "windows"))]
    if state.sandbox_jwt_issuer.is_some() && std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        // Pod lookups and TokenReview identity checks must match the sandbox
        // namespace and service account used by the Kubernetes driver.
        let kubernetes_config =
            compute::driver_config::kubernetes_sa_bootstrap_config(config_file.as_ref())?;
        let sandbox_namespace = kubernetes_config.namespace.clone();
        let sandbox_service_account = kubernetes_config.service_account_name.clone();
        let namespace_validator =
            kubernetes_namespace_validator(&kubernetes_config, &operator_allowlist)?;
        match kube::Client::try_default().await {
            Ok(client) => {
                let resolver = Arc::new(auth::k8s_sa::LiveK8sResolver::new(
                    client,
                    namespace_validator,
                    "openshell-gateway".to_string(),
                    sandbox_service_account.clone(),
                ));
                let authenticator = auth::k8s_sa::K8sServiceAccountAuthenticator::new(resolver);
                state.k8s_sa_authenticator = Some(Arc::new(authenticator));
                info!(
                    namespace = %sandbox_namespace,
                    service_account = %sandbox_service_account,
                    "K8s ServiceAccount bootstrap authenticator enabled"
                );
            }
            Err(e) => warn!(
                error = %e,
                "in-cluster K8s client construction failed; \
                 K8s ServiceAccount bootstrap is disabled"
            ),
        }
    }

    let state = Arc::new(state);

    // Reconcile local-driver running intent before watchers spawn so their
    // first snapshots observe the post-start backend state. Explicitly stopped
    // sandboxes remain stopped.
    ensure_default_workspace(&store).await?;

    let gateway_listeners = bind_gateway_listeners(
        config.bind_address,
        state.compute.gateway_listener_requirements(),
    )
    .await?;

    if let Err(err) = state.compute.start_persisted_sandboxes().await {
        warn!(error = %err, "Failed to start persisted sandboxes during startup");
    }

    state.compute.spawn_watchers(shutdown_rx.clone());
    ssh_sessions::spawn_session_reaper(store.clone(), Duration::from_secs(3600));
    supervisor_session::spawn_relay_reaper(state.clone(), Duration::from_secs(30));
    provider_refresh::spawn_refresh_worker(state.clone(), Duration::from_secs(60));

    // Create the multiplexed service
    let service = MultiplexService::new(state.clone());

    // Bind the unauthenticated health endpoint on a separate port when configured.
    if let Some(health_bind_address) = config.health_bind_address {
        let health_listener = TcpListener::bind(health_bind_address).await.map_err(|e| {
            Error::transport(format!(
                "failed to bind health port {health_bind_address}: {e}"
            ))
        })?;
        info!(address = %health_bind_address, "Health server listening");
        // `health_router` returns immediately; the listener serves
        // `Initializing → 503` until the background monitor publishes the
        // first real probe outcome, so the endpoint is always responsive.
        let router = health_router(store.clone());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(health_listener, router.into_make_service()).await {
                error!("Health server error: {e}");
            }
        });
    } else {
        info!("Health server disabled");
    }

    // Bind the Prometheus metrics endpoint on a dedicated port when configured.
    if let Some(metrics_bind_address) = config.metrics_bind_address {
        let prometheus_handle = PrometheusBuilder::new()
            .install_recorder()
            .map_err(|e| Error::config(format!("failed to install metrics recorder: {e}")))?;
        let metrics_listener = TcpListener::bind(metrics_bind_address).await.map_err(|e| {
            Error::transport(format!(
                "failed to bind metrics port {metrics_bind_address}: {e}",
            ))
        })?;
        info!(address = %metrics_bind_address, "Metrics server listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                metrics_listener,
                metrics_router(prometheus_handle).into_make_service(),
            )
            .await
            {
                error!("Metrics server error: {e}");
            }
        });
    } else {
        info!("Metrics server disabled");
    }

    // Build TLS acceptor when TLS is configured; otherwise serve plaintext.
    let tls_acceptor = if let Some(tls) = &config.tls {
        let acceptor = TlsAcceptor::from_files(
            &tls.cert_path,
            &tls.key_path,
            tls.client_ca_path.as_deref(),
            tls.require_client_auth,
            tls.external_cert_path.as_deref(),
            tls.external_key_path.as_deref(),
            tls.external_server_names.clone(),
        )?;

        // Spawn file-watcher-based TLS certificate reload worker.
        // Watches parent directories of cert/key/CA files and atomically
        // reloads when changes are detected.
        acceptor.spawn_reload_worker(shutdown_rx.clone());

        Some(acceptor)
    } else {
        info!("TLS disabled — accepting plaintext connections");
        None
    };

    let mut listener_tasks = Vec::with_capacity(gateway_listeners.len());
    let enable_loopback_service_http = config.service_routing.enable_loopback_service_http;
    for listener in gateway_listeners {
        listener_tasks.push(tokio::spawn(serve_gateway_listener(
            listener,
            service.clone(),
            tls_acceptor.clone(),
            enable_loopback_service_http,
            shutdown_rx.clone(),
        )));
    }

    shutdown_signal().await;
    info!("Shutdown signal received; stopping gateway");
    let _ = shutdown_tx.send(true);

    for task in listener_tasks {
        if let Err(err) = task.await {
            warn!(error = %err, "Gateway listener task failed during shutdown");
        }
    }

    state
        .compute
        .cleanup_on_shutdown()
        .await
        .map_err(|err| Error::execution(format!("gateway shutdown cleanup failed: {err}")))?;

    Ok(())
}

async fn serve_gateway_listener(
    bound_listener: BoundGatewayListener,
    service: MultiplexService,
    tls_acceptor: Option<TlsAcceptor>,
    enable_loopback_service_http: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    let BoundGatewayListener { listener, spec } = bound_listener;
    let listen_addr = spec.address;

    loop {
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };

        let (stream, addr) = match accepted {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, listen = %listen_addr, "Failed to accept connection");
                continue;
            }
        };
        let listener_scope = match stream.local_addr() {
            Ok(local_addr) => spec.scope_for_local_addr(local_addr),
            Err(e) => {
                debug!(error = %e, client = %addr, listen = %listen_addr, "Failed to inspect accepted local address");
                spec.scope
            }
        };

        set_tcp_nodelay_best_effort(&stream);

        spawn_gateway_connection(
            stream,
            addr,
            listen_addr,
            listener_scope,
            service.clone(),
            tls_acceptor.clone(),
            enable_loopback_service_http,
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionProtocol {
    Tls,
    PlainHttp,
    Unknown,
}

async fn classify_connection_protocol(stream: &TcpStream) -> std::io::Result<ConnectionProtocol> {
    let mut prefix = [0_u8; 8];
    let read = stream.peek(&mut prefix).await?;
    Ok(classify_initial_bytes(&prefix[..read]))
}

fn classify_initial_bytes(prefix: &[u8]) -> ConnectionProtocol {
    if looks_like_tls(prefix) {
        ConnectionProtocol::Tls
    } else if looks_like_http(prefix) {
        ConnectionProtocol::PlainHttp
    } else {
        ConnectionProtocol::Unknown
    }
}

fn looks_like_tls(prefix: &[u8]) -> bool {
    prefix.len() >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03
}

fn looks_like_http(prefix: &[u8]) -> bool {
    const METHODS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
        b"PRI ",
    ];

    if prefix.is_empty() {
        return false;
    }
    METHODS
        .iter()
        .any(|method| method.starts_with(prefix) || prefix.starts_with(method))
}

fn allow_plaintext_service_http(
    enabled: bool,
    listen_addr: SocketAddr,
    peer_addr: SocketAddr,
    listener_scope: GatewayListenerScope,
) -> bool {
    enabled
        && matches!(listener_scope, GatewayListenerScope::Primary)
        && listen_addr.ip().is_loopback()
        && peer_addr.ip().is_loopback()
}

fn spawn_gateway_connection(
    stream: TcpStream,
    addr: SocketAddr,
    listen_addr: SocketAddr,
    listener_scope: GatewayListenerScope,
    service: MultiplexService,
    tls_acceptor: Option<TlsAcceptor>,
    enable_loopback_service_http: bool,
) {
    if let Some(acceptor) = tls_acceptor {
        tokio::spawn(async move {
            match classify_connection_protocol(&stream).await {
                Ok(ConnectionProtocol::PlainHttp)
                    if allow_plaintext_service_http(
                        enable_loopback_service_http,
                        listen_addr,
                        addr,
                        listener_scope,
                    ) =>
                {
                    if let Err(e) = service
                        .serve_service_http_on_listener(stream, listener_scope)
                        .await
                    {
                        if is_benign_connection_close(e.as_ref()) {
                            debug!(error = %e, client = %addr, listen = %listen_addr, "Plaintext service HTTP connection closed");
                        } else {
                            error!(error = %e, client = %addr, listen = %listen_addr, "Plaintext service HTTP connection error");
                        }
                    }
                }
                Ok(ConnectionProtocol::PlainHttp) => {
                    warn!(
                        client = %addr,
                        listen = %listen_addr,
                        scope = ?listener_scope,
                        "Rejected plaintext HTTP on gateway listener"
                    );
                }
                Ok(ConnectionProtocol::Tls | ConnectionProtocol::Unknown) => {
                    // acceptor.acceptor() snapshots the current TLS config;
                    // the returned acceptor owns an Arc that stays alive for
                    // the full duration of the handshake.
                    match acceptor.acceptor().accept(stream).await {
                        Ok(tls_stream) => {
                            let peer_identity = multiplex::extract_peer_identity(&tls_stream);
                            if let Err(e) = service
                                .serve_with_peer_identity_on_listener(
                                    tls_stream,
                                    peer_identity,
                                    listener_scope,
                                )
                                .await
                            {
                                if is_benign_connection_close(e.as_ref()) {
                                    debug!(error = %e, client = %addr, "Connection closed");
                                } else {
                                    error!(error = %e, client = %addr, "Connection error");
                                }
                            }
                        }
                        Err(e) => {
                            if is_benign_tls_handshake_failure(&e) {
                                debug!(error = %e, client = %addr, "TLS handshake closed early");
                            } else {
                                error!(error = %e, client = %addr, "TLS handshake failed");
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(error = %e, client = %addr, "Failed to inspect connection preface");
                }
            }
        });
    } else {
        tokio::spawn(async move {
            if let Err(e) = service.serve_on_listener(stream, listener_scope).await {
                if is_benign_connection_close(e.as_ref()) {
                    debug!(error = %e, client = %addr, "Connection closed");
                } else {
                    error!(error = %e, client = %addr, "Connection error");
                }
            }
        });
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        tokio::select! {
            () = ctrl_c_signal() => {}
            () = terminate_signal() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c_signal().await;
    }
}

async fn ctrl_c_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(error = %err, "Failed to install Ctrl-C signal handler");
        std::future::pending::<()>().await;
    }
}

#[cfg(unix)]
async fn terminate_signal() {
    let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        warn!("Failed to install SIGTERM signal handler");
        std::future::pending::<()>().await;
        return;
    };
    let _ = signal.recv().await;
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
fn unsupported_builtin_compute_driver(driver: ComputeDriverKind) -> compute::ComputeError {
    compute::ComputeError::Message(format!(
        "{} compute driver is unsupported on Windows",
        driver.as_str()
    ))
}

type OperatorAllowlistArc = Option<openshell_core::OperatorNamespaceAllowlist>;
pub use compute::{DriverWatchStream, SharedComputeDriver};

fn kubernetes_namespace_validator(
    config: &compute::driver_config::KubernetesSaBootstrapConfig,
    operator_allowlist: &OperatorAllowlistArc,
) -> Result<auth::k8s_sa::NamespaceValidator> {
    match config.workspace_mode.as_str() {
        "shared" => Ok(auth::k8s_sa::NamespaceValidator::Exact(
            config.namespace.clone(),
        )),
        "managed" => Ok(auth::k8s_sa::NamespaceValidator::Prefix(format!(
            "openshell-{}-",
            config.gateway_id
        ))),
        "operator" => operator_allowlist
            .clone()
            .map(auth::k8s_sa::NamespaceValidator::Allowlist)
            .ok_or_else(|| {
                Error::config("Kubernetes operator namespace allowlist was not initialized")
            }),
        mode => Err(Error::config(format!(
            "invalid Kubernetes workspace_mode '{mode}' for ServiceAccount bootstrap"
        ))),
    }
}

fn validate_remote_compute_driver_config(
    name: &str,
    file: Option<&config_file::ConfigFile>,
) -> Result<()> {
    if name != "kubernetes"
        || !file.is_some_and(|file| file.openshell.drivers.contains_key("kubernetes"))
    {
        return Ok(());
    }

    let config = compute::driver_config::kubernetes_sa_bootstrap_config(file)?;
    if config.workspace_mode == "operator" {
        return Err(Error::config(
            "Kubernetes workspace_mode 'operator' requires an in-process Kubernetes driver; \
             external Kubernetes compute drivers do not support operator mode",
        ));
    }

    Ok(())
}

/// Opaque result returned by a compiled compute-driver factory.
pub struct ComputeDriverBuildOutput {
    runtime: ComputeRuntime,
    operator_allowlist: OperatorAllowlistArc,
}

/// Factory for a compute driver linked into a gateway binary.
#[async_trait::async_trait]
pub trait ComputeDriverFactory: Send + Sync {
    async fn build(
        &self,
        context: ComputeDriverBuildContext<'_>,
    ) -> Result<ComputeDriverBuildOutput>;
}

/// One named compiled-driver registration.
#[derive(Clone)]
pub struct ComputeDriverRegistration {
    name: String,
    detection_priority: u16,
    detect: Option<fn() -> bool>,
    factory: Arc<dyn ComputeDriverFactory>,
}

impl std::fmt::Debug for ComputeDriverRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComputeDriverRegistration")
            .field("name", &self.name)
            .field("detection_priority", &self.detection_priority)
            .field("has_detection_probe", &self.detect.is_some())
            .finish_non_exhaustive()
    }
}

impl ComputeDriverRegistration {
    /// Define a compiled driver. Lower detection priorities are preferred.
    pub fn new(
        name: impl Into<String>,
        detection_priority: u16,
        detect: Option<fn() -> bool>,
        factory: impl ComputeDriverFactory + 'static,
    ) -> Result<Self> {
        let name = openshell_core::config::normalize_compute_driver_name(&name.into())
            .map_err(Error::config)?;
        Ok(Self {
            name,
            detection_priority,
            detect,
            factory: Arc::new(factory),
        })
    }
}

/// Registry of compute drivers compiled into this gateway binary.
///
/// Like `SQLx`'s `Any` driver registry, installation is explicit at the binary
/// composition boundary while runtime selection is generic.
#[derive(Clone, Default)]
pub struct ComputeDriverRegistry {
    drivers: BTreeMap<String, ComputeDriverRegistration>,
}

#[derive(Clone, Debug)]
struct ComputeDriverDetection {
    available: Vec<String>,
}

impl ComputeDriverDetection {
    fn selected(&self) -> Option<&str> {
        self.available.first().map(String::as_str)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ComputeDriverSelection {
    Configured { name: String },
    AutoDetected(ComputeDriverDetection),
}

impl ComputeDriverSelection {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Configured { name } => name,
            Self::AutoDetected(detection) => detection
                .selected()
                .expect("auto-detected selection has an available driver"),
        }
    }
}

impl ComputeDriverRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a compiled driver factory.
    pub fn install(&mut self, registration: ComputeDriverRegistration) -> Result<()> {
        let name = registration.name.clone();
        match self.drivers.entry(name.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(registration);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => Err(Error::config(format!(
                "compute driver '{name}' registered twice"
            ))),
        }
    }

    /// Names installed into this gateway binary, in lexical order.
    pub fn installed_driver_names(&self) -> impl Iterator<Item = &str> {
        self.drivers.keys().map(String::as_str)
    }

    fn get(&self, name: &str) -> Option<&ComputeDriverRegistration> {
        self.drivers.get(name)
    }

    fn detect(&self) -> ComputeDriverDetection {
        let mut candidates = self
            .drivers
            .values()
            .filter(|registration| registration.detect.is_some())
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.detection_priority
                .cmp(&right.detection_priority)
                .then_with(|| left.name.cmp(&right.name))
        });
        let available = candidates
            .into_iter()
            .filter(|registration| registration.detect.is_some_and(|detect| detect()))
            .map(|registration| registration.name.clone())
            .collect();
        ComputeDriverDetection { available }
    }

    pub(crate) fn select(&self, configured_drivers: &[String]) -> Result<ComputeDriverSelection> {
        match configured_drivers {
            [] => {
                let detection = self.detect();
                if detection.selected().is_none() {
                    return Err(Error::config(
                        "no compute driver configured and auto-detection found no suitable installed \
                        driver; set --drivers <name> or OPENSHELL_DRIVERS=<name>",
                    ));
                }
                Ok(ComputeDriverSelection::AutoDetected(detection))
            }
            [driver] => {
                let name = openshell_core::config::normalize_compute_driver_name(driver)
                    .map_err(Error::config)?;
                Ok(ComputeDriverSelection::Configured { name })
            }
            drivers => Err(Error::config(format!(
                "multiple compute drivers are not supported yet; configured drivers: {}",
                drivers.join(",")
            ))),
        }
    }
}

/// Install every first-party compute driver linked into the standard gateway.
#[must_use]
pub fn install_default_compute_drivers() -> ComputeDriverRegistry {
    #[allow(unused_mut)]
    let mut registry = ComputeDriverRegistry::new();
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    {
        registry
            .install(
                ComputeDriverRegistration::new(
                    "kubernetes",
                    100,
                    Some(|| std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()),
                    KubernetesComputeDriverFactory,
                )
                .expect("valid kubernetes registration"),
            )
            .expect("unique kubernetes registration");
        registry
            .install(
                ComputeDriverRegistration::new(
                    "podman",
                    200,
                    Some(openshell_core::config::is_podman_available),
                    PodmanComputeDriverFactory,
                )
                .expect("valid podman registration"),
            )
            .expect("unique podman registration");
        registry
            .install(
                ComputeDriverRegistration::new(
                    "docker",
                    300,
                    Some(openshell_core::config::is_docker_available),
                    DockerComputeDriverFactory,
                )
                .expect("valid docker registration"),
            )
            .expect("unique docker registration");
        registry
            .install(
                ComputeDriverRegistration::new("vm", u16::MAX, None, VmComputeDriverFactory)
                    .expect("valid vm registration"),
            )
            .expect("unique vm registration");
    }
    #[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
    for name in ["kubernetes", "podman", "docker", "vm"] {
        registry
            .install(
                ComputeDriverRegistration::new(
                    name,
                    u16::MAX,
                    None,
                    UnsupportedComputeDriverFactory,
                )
                .expect("valid unsupported registration"),
            )
            .expect("unique unsupported registration");
    }
    registry
}

pub struct ComputeDriverBuildContext<'a> {
    driver_name: String,
    config: &'a Config,
    driver_startup: compute::driver_config::DriverStartupContext<'a>,
    store: Arc<Store>,
    sandbox_index: SandboxIndex,
    sandbox_watch_bus: SandboxWatchBus,
    tracing_log_bus: TracingLogBus,
    supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
    shutdown_rx: watch::Receiver<bool>,
}

impl ComputeDriverBuildContext<'_> {
    #[must_use]
    pub fn driver_name(&self) -> &str {
        &self.driver_name
    }

    #[must_use]
    pub fn gateway_config(&self) -> &Config {
        self.config
    }

    #[must_use]
    pub fn gateway_port(&self) -> u16 {
        self.driver_startup.gateway_port
    }

    #[must_use]
    pub fn gateway_tls_enabled(&self) -> bool {
        self.driver_startup.gateway_tls_enabled
    }

    /// Gateway client credentials that a local driver may mount into guests.
    #[must_use]
    pub fn guest_tls_paths(&self) -> Option<(&Path, &Path, &Path)> {
        self.driver_startup
            .guest_tls
            .map(compute::driver_config::GuestTlsPaths::as_paths)
    }

    /// Deserialize the selected driver's merged TOML table.
    pub fn driver_config<T>(&self) -> Result<T>
    where
        T: Default + serde::de::DeserializeOwned,
    {
        compute::driver_config::driver_config_from_context(self.driver_startup, &self.driver_name)
    }

    #[must_use]
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Finish construction of an in-process driver through the common runtime path.
    pub async fn finish_in_process(
        self,
        driver: SharedComputeDriver,
    ) -> Result<ComputeDriverBuildOutput> {
        let runtime = ComputeRuntime::from_driver(
            self.driver_name,
            driver,
            None,
            self.store,
            self.sandbox_index,
            self.sandbox_watch_bus,
            self.tracing_log_bus,
            self.supervisor_sessions,
        )
        .await
        .map_err(|error| Error::execution(format!("failed to create compute runtime: {error}")))?;
        Ok(ComputeDriverBuildOutput {
            runtime,
            operator_allowlist: None,
        })
    }
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct UnsupportedComputeDriverFactory;

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl ComputeDriverFactory for UnsupportedComputeDriverFactory {
    async fn build(
        &self,
        context: ComputeDriverBuildContext<'_>,
    ) -> Result<ComputeDriverBuildOutput> {
        Err(Error::execution(
            unsupported_builtin_compute_driver(
                context
                    .driver_name
                    .parse()
                    .expect("default driver names are valid"),
            )
            .to_string(),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct KubernetesComputeDriverFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl ComputeDriverFactory for KubernetesComputeDriverFactory {
    async fn build(
        &self,
        context: ComputeDriverBuildContext<'_>,
    ) -> Result<ComputeDriverBuildOutput> {
        warn_if_kubernetes_sandbox_jwt_expiry_disabled(context.config);
        let config = compute::driver_config::builtin::kubernetes_config_from_context(
            context.driver_startup,
        )?;
        let (runtime, operator_allowlist) = ComputeRuntime::new_kubernetes(
            config,
            context.store,
            context.sandbox_index,
            context.sandbox_watch_bus,
            context.tracing_log_bus,
            context.supervisor_sessions,
            context.shutdown_rx,
        )
        .await
        .map_err(|error| Error::execution(format!("failed to create compute runtime: {error}")))?;
        Ok(ComputeDriverBuildOutput {
            runtime,
            operator_allowlist,
        })
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct DockerComputeDriverFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl ComputeDriverFactory for DockerComputeDriverFactory {
    async fn build(
        &self,
        context: ComputeDriverBuildContext<'_>,
    ) -> Result<ComputeDriverBuildOutput> {
        let driver_config =
            compute::driver_config::builtin::docker_config_from_context(context.driver_startup)?;
        let runtime = ComputeRuntime::new_docker(
            context.config.clone(),
            driver_config,
            context.store,
            context.sandbox_index,
            context.sandbox_watch_bus,
            context.tracing_log_bus,
            context.supervisor_sessions,
        )
        .await
        .map_err(|error| Error::execution(format!("failed to create compute runtime: {error}")))?;
        Ok(ComputeDriverBuildOutput {
            runtime,
            operator_allowlist: None,
        })
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct PodmanComputeDriverFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl ComputeDriverFactory for PodmanComputeDriverFactory {
    async fn build(
        &self,
        context: ComputeDriverBuildContext<'_>,
    ) -> Result<ComputeDriverBuildOutput> {
        let driver_config =
            compute::driver_config::builtin::podman_config_from_context(context.driver_startup)?;
        let runtime = ComputeRuntime::new_podman(
            driver_config,
            context.store,
            context.sandbox_index,
            context.sandbox_watch_bus,
            context.tracing_log_bus,
            context.supervisor_sessions,
        )
        .await
        .map_err(|error| Error::execution(format!("failed to create compute runtime: {error}")))?;
        Ok(ComputeDriverBuildOutput {
            runtime,
            operator_allowlist: None,
        })
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct VmComputeDriverFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl ComputeDriverFactory for VmComputeDriverFactory {
    async fn build(
        &self,
        context: ComputeDriverBuildContext<'_>,
    ) -> Result<ComputeDriverBuildOutput> {
        let driver_config =
            compute::driver_config::builtin::vm_config_from_context(context.driver_startup)?;
        let otlp_config = context
            .driver_startup
            .file
            .and_then(|file| file.openshell.gateway.otlp.as_ref());
        let endpoint = compute::vm::spawn(context.config, &driver_config, otlp_config).await?;
        let runtime = ComputeRuntime::new_remote_driver(
            endpoint,
            context.store,
            context.sandbox_index,
            context.sandbox_watch_bus,
            context.tracing_log_bus,
            context.supervisor_sessions,
        )
        .await
        .map_err(|error| Error::execution(format!("failed to create compute runtime: {error}")))?;
        Ok(ComputeDriverBuildOutput {
            runtime,
            operator_allowlist: None,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_compute_runtime(
    config: &Config,
    driver_startup: compute::driver_config::DriverStartupContext<'_>,
    driver: ConfiguredComputeDriver,
    store: Arc<Store>,
    sandbox_index: SandboxIndex,
    sandbox_watch_bus: SandboxWatchBus,
    tracing_log_bus: TracingLogBus,
    supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(ComputeRuntime, OperatorAllowlistArc)> {
    info!(driver = %driver.name(), "Using compute driver");

    let (runtime, operator_allowlist) = match driver {
        ConfiguredComputeDriver::Registered(registration) => {
            let output = registration
                .factory
                .build(ComputeDriverBuildContext {
                    driver_name: registration.name,
                    config,
                    driver_startup,
                    store,
                    sandbox_index,
                    sandbox_watch_bus,
                    tracing_log_bus,
                    supervisor_sessions,
                    shutdown_rx,
                })
                .await?;
            (output.runtime, output.operator_allowlist)
        }
        ConfiguredComputeDriver::Remote { name } => {
            validate_remote_compute_driver_config(&name, driver_startup.file)?;
            let remote_config =
                compute::driver_config::remote_driver_config_from_context(driver_startup, &name)?;
            info!(
                driver = %name,
                socket = %remote_config.socket_path.display(),
                "Using remote compute driver endpoint"
            );
            let endpoint = compute::connect_remote_compute_driver(name, &remote_config.socket_path)
                .await
                .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))?;
            let rt = ComputeRuntime::new_remote_driver(
                endpoint,
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
            .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))?;
            (rt, None)
        }
    };

    Ok((runtime, operator_allowlist))
}

#[derive(Debug, Clone)]
pub(crate) enum ConfiguredComputeDriver {
    Registered(ComputeDriverRegistration),
    Remote { name: String },
}

impl ConfiguredComputeDriver {
    fn name(&self) -> &str {
        match self {
            Self::Registered(registration) => &registration.name,
            Self::Remote { name } => name,
        }
    }
}

pub(crate) fn configured_compute_driver_for_startup(
    registry: &ComputeDriverRegistry,
    startup: &ServerStartupConfig,
) -> Result<ConfiguredComputeDriver> {
    resolve_configured_compute_driver(
        registry,
        startup.compute_driver.name(),
        compute::driver_config::DriverStartupContext {
            file: startup.config_file.as_ref(),
            guest_tls: startup.guest_tls.as_ref(),
            gateway_port: startup.config.bind_address.port(),
            gateway_tls_enabled: startup.config.tls.is_some(),
            endpoint_overrides: &startup.config.compute_driver_endpoints,
        },
    )
}

fn resolve_configured_compute_driver(
    registry: &ComputeDriverRegistry,
    driver_name: &str,
    driver_startup: compute::driver_config::DriverStartupContext<'_>,
) -> Result<ConfiguredComputeDriver> {
    let name = openshell_core::config::normalize_compute_driver_name(driver_name)
        .map_err(Error::config)?;
    // An operator-provided endpoint replaces normal construction for the
    // selected name, including a compiled registration with the same name.
    // The gateway connects to it; it does not provision the remote driver.
    if driver_startup.endpoint_overrides.contains_key(&name) {
        return Ok(ConfiguredComputeDriver::Remote { name });
    }

    if let Some(registration) = registry.get(&name) {
        return Ok(ConfiguredComputeDriver::Registered(registration.clone()));
    }

    Ok(ConfiguredComputeDriver::Remote { name })
}

#[cfg(any(test, feature = "in-tree-compute-drivers"))]
fn kubernetes_sandbox_jwt_expiry_disabled(config: &Config) -> bool {
    config
        .gateway_jwt
        .as_ref()
        .is_some_and(|jwt| jwt.ttl_secs == 0)
}

#[cfg(feature = "in-tree-compute-drivers")]
fn warn_if_kubernetes_sandbox_jwt_expiry_disabled(config: &Config) {
    if kubernetes_sandbox_jwt_expiry_disabled(config) {
        warn!(
            "Kubernetes gateway configured with non-expiring sandbox JWTs (gateway_jwt.ttl_secs = 0); set ttl_secs > 0 for shared Kubernetes deployments"
        );
    }
}

pub(crate) async fn ensure_default_workspace(store: &Store) -> Result<()> {
    use grpc::workspace::{DEFAULT_WORKSPACE_NAME, WORKSPACE_OBJECT_TYPE};
    use openshell_core::proto::Workspace;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use prost::Message;

    let id = uuid::Uuid::new_v4().to_string();
    let workspace = Workspace {
        metadata: Some(ObjectMeta {
            id: id.clone(),
            name: DEFAULT_WORKSPACE_NAME.to_string(),
            created_at_ms: persistence::current_time_ms(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            resource_version: 0,
            workspace: String::new(),
            deletion_timestamp_ms: 0,
        }),
        status: Some(openshell_core::proto::datamodel::v1::WorkspaceStatus {
            phase: openshell_core::proto::datamodel::v1::WorkspacePhase::Active.into(),
        }),
    };

    let labels_map = workspace.object_labels();
    let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
        None
    } else {
        Some(
            serde_json::to_string(&labels_map).map_err(|e| Error::Config {
                message: format!("failed to serialize labels: {e}"),
            })?,
        )
    };
    match store
        .put_if(
            WORKSPACE_OBJECT_TYPE,
            &id,
            DEFAULT_WORKSPACE_NAME,
            "",
            &workspace.encode_to_vec(),
            labels_json.as_deref(),
            persistence::WriteCondition::MustCreate,
        )
        .await
    {
        Ok(_) => {
            info!("Created default workspace");
            Ok(())
        }
        Err(persistence::PersistenceError::UniqueViolation { .. }) => {
            debug!("Default workspace already exists");
            Ok(())
        }
        Err(e) => Err(Error::config(format!(
            "failed to ensure default workspace: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundGatewayListener, ConfiguredComputeDriver, ConnectionProtocol, ExtensionKind,
        GatewayListenerScope, MultiplexService, ServerState, TlsAcceptor,
        allow_plaintext_service_http, bind_gateway_listeners, classify_initial_bytes,
        is_benign_tls_handshake_failure, kubernetes_sandbox_jwt_expiry_disabled,
        mint_gateway_extension_credential, serve_gateway_listener,
        validate_remote_compute_driver_config,
    };
    use openshell_core::{
        ComputeDriverKind, Config,
        proto::{HealthRequest, open_shell_client::OpenShellClient},
    };
    use std::io::{Error, ErrorKind};
    use std::net::SocketAddr;
    use std::sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;

    use crate::{
        compute::GatewayListenerRequirement,
        gateway_listener::GatewayListenerSpec,
        tls_test_utils::{generate_test_certs_with_ca, install_rustls_provider},
    };

    fn extension_test_issuer() -> Arc<crate::auth::sandbox_jwt::SandboxJwtIssuer> {
        let material = openshell_bootstrap::jwt::generate_jwt_key().expect("jwt key");
        Arc::new(
            crate::auth::sandbox_jwt::SandboxJwtIssuer::from_pem(
                material.signing_key_pem.as_bytes(),
                material.kid,
                "gateway-a",
                Duration::from_secs(900),
            )
            .expect("issuer"),
        )
    }

    #[test]
    fn external_kubernetes_operator_workspace_mode_is_rejected() {
        let file: crate::config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.kubernetes]
socket_path = "/run/openshell/kubernetes.sock"
workspace_mode = "operator"
operator_namespace_label = "openshell.ai/workspace=true"
"#,
        )
        .expect("valid config");

        let error = validate_remote_compute_driver_config("kubernetes", Some(&file))
            .expect_err("external operator mode must fail closed");

        assert!(
            error
                .to_string()
                .contains("external Kubernetes compute drivers do not support operator mode")
        );
    }

    #[test]
    fn plaintext_extension_endpoint_is_rejected_unless_explicitly_opted_out() {
        let issuer = extension_test_issuer();

        // Default posture: a plaintext endpoint cannot carry a bearer
        // credential, so startup fails and names the opt-out.
        let error = mint_gateway_extension_credential(
            &issuer,
            ExtensionKind::Middleware,
            "content-guard",
            "urn:openshell:extension:middleware:content-guard",
            "http://host.openshell.internal:50051",
            false,
        )
        .expect_err("plaintext endpoint must not silently downgrade");
        assert!(error.to_string().contains("allow_insecure_transport"));

        // Explicit opt-out starts the gateway with no credential attached.
        assert!(
            mint_gateway_extension_credential(
                &issuer,
                ExtensionKind::Middleware,
                "content-guard",
                "urn:openshell:extension:middleware:content-guard",
                "http://host.openshell.internal:50051",
                true,
            )
            .expect("opt-out must be permitted")
            .is_none()
        );
    }

    #[test]
    fn authenticated_extension_endpoints_mint_a_credential() {
        let issuer = extension_test_issuer();
        let credential = mint_gateway_extension_credential(
            &issuer,
            ExtensionKind::Middleware,
            "content-guard",
            "urn:openshell:extension:middleware:content-guard",
            "https://content-guard.example:50051",
            false,
        )
        .expect("credential")
        .expect("authenticated endpoint mints a credential");
        assert_eq!(credential.name, "content-guard");
        assert!(credential.slot.expires_at_ms().is_some_and(|ms| ms > 0));

        // Unix sockets are gateway-local, so only interceptors can use them.
        // A middleware endpoint must also be reachable from every supervisor.
        let error = mint_gateway_extension_credential(
            &issuer,
            ExtensionKind::Middleware,
            "content-guard",
            "urn:openshell:extension:middleware:content-guard",
            "unix:///run/openshell/content-guard.sock",
            false,
        )
        .expect_err("middleware cannot be reached over a gateway-local socket");
        assert!(error.to_string().contains("must use https://"));

        assert!(
            mint_gateway_extension_credential(
                &issuer,
                ExtensionKind::Interceptor,
                "quota",
                "urn:openshell:extension:interceptor:quota",
                "unix:///run/openshell/interceptors/quota.sock",
                false,
            )
            .expect("credential")
            .is_some()
        );
    }

    fn test_driver_startup<'a>(
        config: &'a Config,
        file: Option<&'a super::config_file::ConfigFile>,
    ) -> crate::compute::driver_config::DriverStartupContext<'a> {
        crate::compute::driver_config::DriverStartupContext {
            file,
            guest_tls: None,
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            gateway_tls_enabled: false,
            endpoint_overrides: &config.compute_driver_endpoints,
        }
    }

    fn test_compute_drivers() -> super::ComputeDriverRegistry {
        super::install_default_compute_drivers()
    }

    fn select_compute_driver(
        registry: &super::ComputeDriverRegistry,
        config: &Config,
        driver_startup: crate::compute::driver_config::DriverStartupContext<'_>,
    ) -> openshell_core::Result<ConfiguredComputeDriver> {
        let selection = registry.select(&config.compute_drivers)?;
        super::resolve_configured_compute_driver(registry, selection.name(), driver_startup)
    }

    #[derive(Clone, Copy)]
    struct TestComputeDriverFactory;

    static DETECTION_PROBE_ORDER: LazyLock<Mutex<Vec<&'static str>>> =
        LazyLock::new(|| Mutex::new(Vec::new()));

    fn record_detection_probe(name: &'static str, available: bool) -> bool {
        DETECTION_PROBE_ORDER.lock().unwrap().push(name);
        available
    }

    fn unavailable_first_probe() -> bool {
        record_detection_probe("first", false)
    }

    fn available_second_probe() -> bool {
        record_detection_probe("second", true)
    }

    fn available_third_probe() -> bool {
        record_detection_probe("third", true)
    }

    #[async_trait::async_trait]
    impl super::ComputeDriverFactory for TestComputeDriverFactory {
        async fn build(
            &self,
            _context: super::ComputeDriverBuildContext<'_>,
        ) -> openshell_core::Result<super::ComputeDriverBuildOutput> {
            unreachable!("selection tests do not construct the driver")
        }
    }

    fn test_tls_acceptor() -> (TempDir, TlsAcceptor) {
        install_rustls_provider();

        let dir = tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());

        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build tls acceptor");

        (dir, acceptor)
    }

    async fn test_state(
        bind_addr: SocketAddr,
        enable_loopback_service_http: bool,
    ) -> Arc<ServerState> {
        let store = Arc::new(
            crate::persistence::Store::connect("sqlite::memory:?cache=shared")
                .await
                .expect("failed to create test store"),
        );
        let compute = crate::compute::new_test_runtime(store.clone()).await;
        Arc::new(ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_bind_address(bind_addr)
                .with_server_sans(["*.dev.openshell.localhost"])
                .with_loopback_service_http(enable_loopback_service_http)
                .with_credential_drivers(["test-static"]),
            store,
            compute,
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
            None,
        ))
    }

    async fn start_tls_gateway_listener(
        bind_addr: &str,
        enable_loopback_service_http: bool,
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
        TempDir,
    ) {
        let listener = TcpListener::bind(bind_addr)
            .await
            .expect("failed to bind test listener");
        let listen_addr = listener.local_addr().expect("failed to read local addr");
        let state = test_state(listen_addr, enable_loopback_service_http).await;
        let service = MultiplexService::new(state);
        let (tls_dir, tls_acceptor) = test_tls_acceptor();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_gateway_listener(
            BoundGatewayListener {
                listener,
                spec: GatewayListenerSpec::new(listen_addr, GatewayListenerScope::Primary),
            },
            service,
            Some(tls_acceptor),
            enable_loopback_service_http,
            shutdown_rx,
        ));
        (listen_addr, shutdown_tx, handle, tls_dir)
    }

    async fn send_plain_http(addr: SocketAddr, request: String) -> String {
        let connect_addr: SocketAddr = format!("127.0.0.1:{}", addr.port())
            .parse()
            .expect("failed to build loopback connect addr");
        let mut stream = TcpStream::connect(connect_addr)
            .await
            .expect("failed to connect to test listener");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("failed to write request");

        let mut response = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("timed out reading response");
        if let Err(err) = read_result
            && err.kind() != ErrorKind::ConnectionReset
        {
            panic!("failed to read response: {err}");
        }
        String::from_utf8_lossy(&response).into_owned()
    }

    fn service_request(addr: SocketAddr, extra_headers: &[(&str, &str)]) -> String {
        let mut request = format!(
            "GET / HTTP/1.1\r\nHost: default--my-sandbox--web.dev.openshell.localhost:{}\r\nConnection: close\r\n",
            addr.port()
        );
        for (name, value) in extra_headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request
    }

    async fn stop_listener(shutdown: watch::Sender<bool>, handle: tokio::task::JoinHandle<()>) {
        let _ = shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[test]
    fn classifies_probe_style_tls_disconnects_as_benign() {
        for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset] {
            let error = Error::new(kind, "probe disconnected");
            assert!(is_benign_tls_handshake_failure(&error));
        }
    }

    #[test]
    fn preserves_real_tls_failures_as_errors() {
        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
        ] {
            let error = Error::new(kind, "real tls failure");
            assert!(!is_benign_tls_handshake_failure(&error));
        }
    }

    #[test]
    fn classifies_tls_and_plain_http_prefaces() {
        assert_eq!(
            classify_initial_bytes(&[0x16, 0x03, 0x01, 0x00]),
            ConnectionProtocol::Tls
        );
        assert_eq!(
            classify_initial_bytes(b"GET / HTTP/1.1\r\n"),
            ConnectionProtocol::PlainHttp
        );
        assert_eq!(classify_initial_bytes(b"G"), ConnectionProtocol::PlainHttp);
        assert_eq!(
            classify_initial_bytes(b"\x00\x01\x02"),
            ConnectionProtocol::Unknown
        );
    }

    #[test]
    fn plaintext_service_http_requires_loopback_listener_and_peer() {
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let wildcard: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let remote_peer: SocketAddr = "192.0.2.10:54000".parse().unwrap();
        let primary = GatewayListenerScope::Primary;
        let callback = GatewayListenerScope::ComputeDriverCallback;

        assert!(allow_plaintext_service_http(true, loopback, peer, primary));
        assert!(!allow_plaintext_service_http(
            false, loopback, peer, primary
        ));
        assert!(!allow_plaintext_service_http(true, wildcard, peer, primary));
        assert!(!allow_plaintext_service_http(
            true,
            loopback,
            remote_peer,
            primary
        ));
        assert!(!allow_plaintext_service_http(
            true, loopback, peer, callback
        ));
    }

    #[tokio::test]
    async fn plaintext_service_http_listener_rejects_non_loopback_bind() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("0.0.0.0:0", true).await;

        let response = send_plain_http(addr, service_request(addr, &[])).await;

        assert!(
            response.is_empty(),
            "non-loopback gateway listener should drop plaintext service HTTP, got: {response:?}"
        );
        stop_listener(shutdown, handle).await;
    }

    #[tokio::test]
    async fn plaintext_service_http_rejects_cross_origin_browser_contexts() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("127.0.0.1:0", true).await;
        let cases = [
            (
                "cross-site fetch metadata",
                vec![("Sec-Fetch-Site", "cross-site")],
            ),
            (
                "same-site sibling fetch metadata",
                vec![("Sec-Fetch-Site", "same-site")],
            ),
            (
                "mismatched origin",
                vec![(
                    "Origin",
                    "http://other-sandbox--web.dev.openshell.localhost:8080",
                )],
            ),
            (
                "mismatched referer",
                vec![(
                    "Referer",
                    "http://other-sandbox--web.dev.openshell.localhost:8080/page",
                )],
            ),
        ];

        for (name, headers) in cases {
            let response = send_plain_http(addr, service_request(addr, &headers)).await;

            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden"),
                "{name} should be rejected before service lookup, got: {response:?}"
            );
            assert!(
                response.contains("Cross-origin service request rejected"),
                "{name} should explain the service rejection, got: {response:?}"
            );
        }
        stop_listener(shutdown, handle).await;
    }

    #[tokio::test]
    async fn plaintext_service_http_allows_same_origin_browser_context_to_reach_service_lookup() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("127.0.0.1:0", true).await;
        let origin = format!(
            "http://default--my-sandbox--web.dev.openshell.localhost:{}",
            addr.port()
        );
        let response = send_plain_http(
            addr,
            service_request(
                addr,
                &[("Sec-Fetch-Site", "same-origin"), ("Origin", &origin)],
            ),
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "same-origin browser context should pass CSRF guard and miss only because no endpoint exists, got: {response:?}"
        );
        assert!(
            !response.contains("Cross-origin service request rejected"),
            "same-origin browser context should not be rejected as cross-origin, got: {response:?}"
        );
        stop_listener(shutdown, handle).await;
    }

    #[tokio::test]
    async fn plaintext_service_http_does_not_expose_grpc_gateway() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("127.0.0.1:0", true).await;
        let grpc_endpoint = format!("http://127.0.0.1:{}", addr.port());
        let grpc_succeeded = tokio::time::timeout(Duration::from_secs(2), async {
            match OpenShellClient::connect(grpc_endpoint).await {
                Ok(mut client) => client.health(HealthRequest {}).await.is_ok(),
                Err(_) => false,
            }
        })
        .await
        .expect("timed out checking plaintext gRPC exposure");

        assert!(
            !grpc_succeeded,
            "plaintext service HTTP must not expose successful gateway gRPC"
        );

        let request = format!(
            "POST /openshell.v1.OpenShell/Health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/grpc\r\nTE: trailers\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            addr.port()
        );

        let response = send_plain_http(addr, request).await;

        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "plaintext service HTTP router should not serve gateway gRPC, got: {response:?}"
        );
        assert!(
            !response.contains("grpc-status: 0"),
            "plaintext service HTTP must not return a successful gRPC response: {response:?}"
        );
        stop_listener(shutdown, handle).await;
    }

    #[test]
    fn configured_compute_driver_triggers_auto_detection_when_empty() {
        let config = Config::new(None).with_compute_drivers(std::iter::empty::<String>());
        // Empty drivers triggers auto-detection, which may return Some or None
        // depending on the environment. This test verifies the auto-detection path
        // is taken rather than immediately returning an error.
        let result = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        );
        // Either we get a detected driver or an error about none being detected.
        match result {
            Ok(ConfiguredComputeDriver::Registered(registration)) => {
                assert!(
                    matches!(
                        registration.name.as_str(),
                        "kubernetes" | "docker" | "podman"
                    ),
                    "auto-detected unexpected driver: {}",
                    registration.name
                );
            }
            Ok(ConfiguredComputeDriver::Remote { name }) => {
                panic!("auto-detection returned remote driver: {name}");
            }
            Err(e) => {
                assert!(
                    e.to_string()
                        .contains("auto-detection found no suitable installed driver"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    #[test]
    fn registry_detection_reports_available_drivers_in_priority_order() {
        DETECTION_PROBE_ORDER.lock().unwrap().clear();
        let mut registry = super::ComputeDriverRegistry::new();
        registry
            .install(
                super::ComputeDriverRegistration::new(
                    "third",
                    300,
                    Some(available_third_probe),
                    TestComputeDriverFactory,
                )
                .unwrap(),
            )
            .unwrap();
        registry
            .install(
                super::ComputeDriverRegistration::new(
                    "first",
                    100,
                    Some(unavailable_first_probe),
                    TestComputeDriverFactory,
                )
                .unwrap(),
            )
            .unwrap();
        registry
            .install(
                super::ComputeDriverRegistration::new(
                    "second",
                    200,
                    Some(available_second_probe),
                    TestComputeDriverFactory,
                )
                .unwrap(),
            )
            .unwrap();

        let detection = registry.detect();
        assert_eq!(detection.selected(), Some("second"));
        assert_eq!(
            detection
                .available
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["second", "third"]
        );
        assert_eq!(
            DETECTION_PROBE_ORDER.lock().unwrap().as_slice(),
            ["first", "second", "third"]
        );
        assert_eq!(
            registry.installed_driver_names().collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
    }

    #[test]
    fn configured_compute_driver_rejects_multiple_entries() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Kubernetes, ComputeDriverKind::Podman]);
        let err = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("multiple compute drivers are not supported yet")
        );
        assert!(err.to_string().contains("kubernetes,podman"));
    }

    #[test]
    fn configured_compute_driver_accepts_podman() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Podman]);
        let driver = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Registered(registration) if registration.name == "podman"
        ));
    }

    #[test]
    fn configured_compute_driver_accepts_vm() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Vm]);
        let driver = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Registered(registration) if registration.name == "vm"
        ));
    }

    #[test]
    fn configured_compute_driver_accepts_docker() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Docker]);
        let driver = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Registered(registration) if registration.name == "docker"
        ));
    }

    #[test]
    fn configured_compute_driver_resolves_named_remote() {
        let config = Config::new(None).with_compute_drivers(["kyma"]);

        let driver = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap();

        match driver {
            ConfiguredComputeDriver::Remote { name } => {
                assert_eq!(name, "kyma");
            }
            ConfiguredComputeDriver::Registered(other) => {
                panic!(
                    "expected remote driver, got registered driver {}",
                    other.name
                )
            }
        }
    }

    #[test]
    fn configured_compute_driver_uses_vm_endpoint_override() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Vm])
            .with_compute_driver_endpoint("vm", "/run/openshell/vm.sock");

        let driver = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Remote { name } if name == "vm"
        ));
    }

    #[test]
    fn configured_compute_driver_uses_builtin_endpoint_override() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Docker])
            .with_compute_driver_endpoint("docker", "/run/openshell/docker.sock");

        let driver = select_compute_driver(
            &test_compute_drivers(),
            &config,
            test_driver_startup(&config, None),
        )
        .unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Remote { name } if name == "docker"
        ));
    }

    #[test]
    fn kubernetes_sandbox_jwt_expiry_disabled_warns_for_zero_ttl() {
        fn config_with_jwt_ttl(ttl_secs: u64) -> Config {
            let mut config = Config::new(None);
            config.gateway_jwt = Some(openshell_core::GatewayJwtConfig {
                signing_key_path: "/tmp/signing.pem".into(),
                public_key_path: "/tmp/public.pem".into(),
                kid_path: "/tmp/kid".into(),
                gateway_id: "openshell".to_string(),
                ttl_secs,
            });
            config
        }

        assert!(kubernetes_sandbox_jwt_expiry_disabled(
            &config_with_jwt_ttl(0)
        ));
        assert!(!kubernetes_sandbox_jwt_expiry_disabled(
            &config_with_jwt_ttl(3600)
        ));
        assert!(!kubernetes_sandbox_jwt_expiry_disabled(&Config::new(None)));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_builtin_compute_drivers_report_unsupported() {
        for driver in [
            ComputeDriverKind::Docker,
            ComputeDriverKind::Kubernetes,
            ComputeDriverKind::Podman,
            ComputeDriverKind::Vm,
        ] {
            let message = super::unsupported_builtin_compute_driver(driver).to_string();
            assert!(
                message.contains("unsupported on Windows"),
                "{driver} rejection should be explicit, got: {message}"
            );
        }
    }

    #[tokio::test]
    async fn failed_gateway_listener_bind_does_not_attempt_persisted_sandbox_start() {
        let occupied_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_address = occupied_listener.local_addr().unwrap();
        let start_attempted = AtomicBool::new(false);
        let primary_address: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result: openshell_core::Result<()> = async {
            let _listeners = bind_gateway_listeners(
                primary_address,
                &[docker_listener_requirement(occupied_address)],
            )
            .await?;
            start_attempted.store(true, Ordering::SeqCst);
            Ok(())
        }
        .await;

        assert!(
            result.is_err(),
            "binding the occupied extra gateway address should fail"
        );
        assert!(
            !start_attempted.load(Ordering::SeqCst),
            "persisted sandbox start must not run before every gateway listener is bound"
        );
    }

    fn docker_listener_requirement(address: SocketAddr) -> GatewayListenerRequirement {
        GatewayListenerRequirement::Exact {
            address,
            driver_name: "docker".to_string(),
            reason: "managed bridge".to_string(),
        }
    }
}
