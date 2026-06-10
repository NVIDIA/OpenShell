// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! napi-rs bindings over [`openshell_sdk`].
//!
//! This crate is a thin adapter — it owns no business logic. It maps the
//! curated SDK surface to JS-shaped types (camelCase keys, string-literal
//! enums, JS `Error` with a discriminable `code` field), and bridges a
//! JS-side OIDC refresh callback to the SDK's [`openshell_sdk::Refresh`]
//! trait.
//!
//! Published as `@openshell/sdk` (alpha; no semver guarantee until 1.0).
//!
//! # Runtime ownership
//!
//! napi-rs v3 provides an ambient tokio runtime that's only available inside
//! `async fn` napi entry points. Every JS-facing function on [`OpenShellClient`]
//! is therefore `async`. Sync FFI entry points cannot call the SDK because
//! tonic requires a reactor; attempting `tokio::spawn` from a sync `#[napi]`
//! function panics with "no reactor running".

#![allow(clippy::needless_pass_by_value, clippy::missing_errors_doc)]

use napi::Status;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::ThreadsafeFunction;
use napi_derive::napi;
use openshell_sdk as sdk;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// ── Error mapping ─────────────────────────────────────────────────────

fn to_napi_error(error: sdk::SdkError) -> Error {
    let code = error.code();
    // Embed the SDK code as a `[code] message` prefix. N-API maps the
    // status enum to JS `err.code`, which is too coarse for discrimination
    // (`GenericFailure` covers most variants), so callers parse the prefix
    // or use the `errorCode()` helper exported from the JS shim.
    Error::new(Status::GenericFailure, format!("[{code}] {error}"))
}

// ── Public input/output types (JS-shaped) ────────────────────────────

/// Connection options. Mirrors [`openshell_sdk::ClientConfig`] with
/// JS-friendly field names.
#[napi(object)]
#[derive(Default)]
pub struct ConnectOptions {
    /// Gateway URL (`http://...` or `https://...`).
    pub gateway: String,
    /// CA certificate (PEM-encoded). `None` falls back to system roots.
    pub ca_cert: Option<Buffer>,
    /// Bearer token for direct OIDC auth. Mutually exclusive with `edge_token`.
    pub oidc_token: Option<String>,
    /// Cloudflare Access bearer token. Routes through a local WebSocket tunnel.
    pub edge_token: Option<String>,
    /// Disable TLS certificate verification (development/debug only).
    pub insecure_skip_verify: Option<bool>,
}

/// Gateway health snapshot.
#[napi(object)]
pub struct Health {
    /// Coarse status: `"healthy"`, `"degraded"`, `"unhealthy"`, `"unspecified"`.
    pub status: String,
    pub version: String,
}

/// Lifecycle phase: `"unspecified"`, `"provisioning"`, `"ready"`, `"error"`,
/// `"deleting"`, `"unknown"`.
#[napi(object)]
pub struct SandboxRef {
    pub id: String,
    pub name: String,
    pub phase: String,
    pub labels: HashMap<String, String>,
    /// Resource version as a string — JS numbers can't safely hold u64.
    pub resource_version: String,
}

/// Caller intent for a new sandbox.
#[napi(object)]
#[derive(Default)]
pub struct SandboxSpec {
    pub name: Option<String>,
    pub image: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub environment: Option<HashMap<String, String>>,
    pub providers: Option<Vec<String>>,
    pub gpu: Option<bool>,
    pub gpu_device: Option<String>,
}

/// Options for [`OpenShellClient::list_sandboxes`].
#[napi(object)]
#[derive(Default)]
pub struct ListOptions {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub label_selector: Option<String>,
}

/// Options for [`OpenShellClient::exec`].
#[napi(object)]
#[derive(Default)]
pub struct ExecOptions {
    pub workdir: Option<String>,
    pub environment: Option<HashMap<String, String>>,
    /// Timeout in seconds. `None` lets the gateway choose.
    pub timeout_secs: Option<u32>,
    /// Optional stdin payload.
    pub stdin: Option<Buffer>,
}

/// Result of a non-streaming exec call.
#[napi(object)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Buffer,
    pub stderr: Buffer,
}

// ── Type conversions ─────────────────────────────────────────────────

fn phase_to_str(phase: sdk::SandboxPhase) -> &'static str {
    match phase {
        sdk::SandboxPhase::Provisioning => "provisioning",
        sdk::SandboxPhase::Ready => "ready",
        sdk::SandboxPhase::Error => "error",
        sdk::SandboxPhase::Deleting => "deleting",
        sdk::SandboxPhase::Unknown => "unknown",
        _ => "unspecified",
    }
}

fn status_to_str(status: sdk::ServiceStatus) -> &'static str {
    match status {
        sdk::ServiceStatus::Healthy => "healthy",
        sdk::ServiceStatus::Degraded => "degraded",
        sdk::ServiceStatus::Unhealthy => "unhealthy",
        _ => "unspecified",
    }
}

impl From<sdk::SandboxRef> for SandboxRef {
    fn from(r: sdk::SandboxRef) -> Self {
        Self {
            id: r.id,
            name: r.name,
            phase: phase_to_str(r.phase).to_string(),
            labels: r.labels,
            resource_version: r.resource_version.to_string(),
        }
    }
}

fn sdk_spec_from_js(spec: SandboxSpec) -> sdk::SandboxSpec {
    sdk::SandboxSpec {
        name: spec.name,
        image: spec.image,
        labels: spec.labels.unwrap_or_default(),
        environment: spec.environment.unwrap_or_default(),
        providers: spec.providers.unwrap_or_default(),
        gpu: spec.gpu.unwrap_or(false),
        gpu_device: spec.gpu_device,
    }
}

fn sdk_list_opts_from_js(opts: ListOptions) -> sdk::ListOptions {
    sdk::ListOptions {
        limit: opts.limit.unwrap_or(0),
        offset: opts.offset.unwrap_or(0),
        label_selector: opts.label_selector,
    }
}

fn sdk_exec_opts_from_js(opts: ExecOptions) -> sdk::ExecOptions {
    sdk::ExecOptions {
        workdir: opts.workdir,
        environment: opts.environment.unwrap_or_default(),
        timeout: opts.timeout_secs.map(|s| Duration::from_secs(u64::from(s))),
        stdin: opts.stdin.map(|b| b.to_vec()),
    }
}

fn build_client_config(opts: ConnectOptions) -> sdk::ClientConfig {
    let auth = match (opts.oidc_token, opts.edge_token) {
        (Some(token), _) => Some(sdk::AuthConfig::Oidc(token)),
        (None, Some(token)) => Some(sdk::AuthConfig::EdgeJwt(token)),
        (None, None) => None,
    };
    let mut cfg = sdk::ClientConfig::new(opts.gateway);
    cfg.ca_cert = opts.ca_cert.map(|b| b.to_vec());
    cfg.auth = auth;
    cfg.insecure_skip_verify = opts.insecure_skip_verify.unwrap_or(false);
    cfg
}

// ── OIDC refresh callback bridge ─────────────────────────────────────

/// JS-side refresh callback returning a Promise<{ accessToken, expiresAt? }>.
#[napi(object)]
pub struct JsRefreshedToken {
    pub access_token: String,
    /// Expiry as Unix epoch seconds. Stored as `f64` because JS numbers
    /// can't hold `u64` exactly past 2^53; values are clamped to that range
    /// in practice (the year 287396 is fine).
    pub expires_at: Option<f64>,
}

/// Bridge between a JS refresh callback and the SDK's [`sdk::Refresh`] trait.
struct JsRefresher {
    callback: ThreadsafeFunction<(), Promise<JsRefreshedToken>, (), Status, false>,
}

#[async_trait::async_trait]
impl sdk::Refresh for JsRefresher {
    async fn refresh(&self) -> std::result::Result<sdk::RefreshedToken, sdk::RefreshError> {
        // Invoke the JS callback; it returns a Promise<JsRefreshedToken>.
        let promise =
            self.callback.call_async(()).await.map_err(|e| {
                sdk::RefreshError::Transient(format!("refresh callback failed: {e}"))
            })?;
        let result = promise
            .await
            .map_err(|e| sdk::RefreshError::Transient(format!("refresh promise rejected: {e}")))?;
        let token = sdk::RefreshedToken::new(result.access_token);
        Ok(match result.expires_at {
            Some(expires_at) if expires_at.is_finite() && expires_at > 0.0 => {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                {
                    token.with_expires_at(expires_at as u64)
                }
            }
            _ => token,
        })
    }
}

/// A live token source backed by a JS callback. Hand off to
/// [`OpenShellClient::set_oidc_refresher`] before any RPCs run; the SDK
/// proactively refreshes when the token is within 60s of expiry, and
/// coalesces concurrent refreshes into a single callback invocation.
#[napi]
pub struct OidcRefresher {
    inner: Arc<sdk::TokenSource>,
}

#[napi]
impl OidcRefresher {
    /// Create a refresher with an initial token and a JS callback.
    ///
    /// The callback must return a Promise resolving to
    /// `{ accessToken, expiresAt? }`. `expiresAt` is Unix epoch seconds.
    #[napi(constructor)]
    pub fn new(
        initial_token: String,
        initial_expires_at: Option<f64>,
        #[napi(ts_arg_type = "() => Promise<{ accessToken: string; expiresAt?: number }>")]
        callback: ThreadsafeFunction<(), Promise<JsRefreshedToken>, (), Status, false>,
    ) -> Self {
        let initial = match initial_expires_at {
            Some(exp) if exp.is_finite() && exp > 0.0 => {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                {
                    sdk::RefreshedToken::new(initial_token).with_expires_at(exp as u64)
                }
            }
            _ => sdk::RefreshedToken::new(initial_token),
        };
        let refresher = Arc::new(JsRefresher { callback });
        Self {
            inner: Arc::new(sdk::TokenSource::new(initial, refresher)),
        }
    }

    /// Snapshot the current token (no refresh check). Mostly useful for
    /// tests; in steady-state the SDK calls this internally.
    #[napi]
    pub fn current_token(&self) -> String {
        self.inner.snapshot()
    }

    /// Force a refresh now and return the new access token. Concurrent
    /// callers coalesce.
    #[napi]
    pub async fn refresh(&self) -> Result<String> {
        self.inner.refresh_now().await.map_err(to_napi_error)
    }
}

// ── Main client class ────────────────────────────────────────────────

/// The JS-facing client. Cheap to share between async tasks; do not call
/// `connect` per request.
#[napi]
pub struct OpenShellClient {
    inner: sdk::OpenShellClient,
}

#[napi]
impl OpenShellClient {
    /// Open a connection to the gateway described by `options`.
    #[napi(factory)]
    pub async fn connect(options: ConnectOptions) -> Result<Self> {
        let cfg = build_client_config(options);
        let inner = sdk::OpenShellClient::connect(cfg)
            .await
            .map_err(to_napi_error)?;
        Ok(Self { inner })
    }

    /// Gateway health snapshot.
    #[napi]
    pub async fn health(&self) -> Result<Health> {
        let h = self.inner.health().await.map_err(to_napi_error)?;
        Ok(Health {
            status: status_to_str(h.status).to_string(),
            version: h.version,
        })
    }

    /// Create a new sandbox.
    #[napi]
    pub async fn create_sandbox(&self, spec: SandboxSpec) -> Result<SandboxRef> {
        self.inner
            .create_sandbox(sdk_spec_from_js(spec))
            .await
            .map(Into::into)
            .map_err(to_napi_error)
    }

    /// Fetch a sandbox by name.
    #[napi]
    pub async fn get_sandbox(&self, name: String) -> Result<SandboxRef> {
        self.inner
            .get_sandbox(&name)
            .await
            .map(Into::into)
            .map_err(to_napi_error)
    }

    /// List sandboxes.
    #[napi]
    pub async fn list_sandboxes(&self, options: Option<ListOptions>) -> Result<Vec<SandboxRef>> {
        let opts = sdk_list_opts_from_js(options.unwrap_or_default());
        let items = self
            .inner
            .list_sandboxes(opts)
            .await
            .map_err(to_napi_error)?;
        Ok(items.into_iter().map(Into::into).collect())
    }

    /// Delete a sandbox by name. Returns `true` when the gateway acknowledged
    /// the deletion, `false` when it was already absent.
    #[napi]
    pub async fn delete_sandbox(&self, name: String) -> Result<bool> {
        self.inner
            .delete_sandbox(&name)
            .await
            .map_err(to_napi_error)
    }

    /// Poll until the sandbox reaches `ready` or `timeout_secs` elapses.
    #[napi]
    pub async fn wait_ready(&self, name: String, timeout_secs: u32) -> Result<SandboxRef> {
        self.inner
            .wait_ready(&name, Duration::from_secs(u64::from(timeout_secs)))
            .await
            .map(Into::into)
            .map_err(to_napi_error)
    }

    /// Poll until the sandbox is gone or `timeout_secs` elapses.
    #[napi]
    pub async fn wait_deleted(&self, name: String, timeout_secs: u32) -> Result<()> {
        self.inner
            .wait_deleted(&name, Duration::from_secs(u64::from(timeout_secs)))
            .await
            .map_err(to_napi_error)
    }

    /// Run a command inside a sandbox; buffers stdout/stderr to the end.
    #[napi]
    pub async fn exec(
        &self,
        name: String,
        command: Vec<String>,
        options: Option<ExecOptions>,
    ) -> Result<ExecResult> {
        let opts = sdk_exec_opts_from_js(options.unwrap_or_default());
        let res = self
            .inner
            .exec(&name, &command, opts)
            .await
            .map_err(to_napi_error)?;
        Ok(ExecResult {
            exit_code: res.exit_code,
            stdout: res.stdout.into(),
            stderr: res.stderr.into(),
        })
    }
}
