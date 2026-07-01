// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! High-level async client over the gateway gRPC surface.
//!
//! Covers the sandbox-focused MVP slice: health, sandbox CRUD, readiness /
//! deletion waits, and non-streaming exec. Other RPCs (inference, providers,
//! policy, logs, settings, SSH, forwarding) are reachable via
//! [`OpenShellClient::raw_grpc`] / [`OpenShellClient::raw_inference`].

use crate::auth::{BearerSlot, EdgeAuthInterceptor, bearer_metadata};
use crate::config::{AuthConfig, ClientConfig};
use crate::error::{Result, SdkError};
use crate::raw::{AuthedGrpcClient, AuthedInferenceClient};
use crate::refresh::{RefreshedToken, TokenSource};
use crate::transport;
use crate::types::{
    ExecOptions, ExecResult, Health, ListOptions, SandboxPhase, SandboxRef, SandboxSpec,
};
use futures::StreamExt;
use openshell_core::proto;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tonic::transport::Channel;

/// Async client for a single `OpenShell` gateway.
///
/// Cheap to clone — the underlying tonic [`Channel`] multiplexes RPCs over a
/// shared HTTP/2 connection. Construct one per logical gateway and share it
/// across tasks; do not call [`OpenShellClient::connect`] per request.
#[derive(Clone)]
pub struct OpenShellClient {
    channel: Channel,
    interceptor: EdgeAuthInterceptor,
    /// Drives OIDC token rotation. `None` when auth is static (edge token,
    /// anonymous, or an OIDC token with no refresher).
    token_source: Option<TokenSource>,
    /// Live bearer slot the interceptor reads; refreshed tokens are written
    /// here so rotation reaches in-flight requests. `None` for non-OIDC auth.
    bearer_slot: Option<BearerSlot>,
}

impl OpenShellClient {
    /// Open a connection to the gateway described by `config`.
    ///
    /// Performs the gRPC channel handshake immediately; subsequent RPCs reuse
    /// the connection.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let channel = transport::build_channel(&config).await?;
        let interceptor = interceptor_from_config(&config)?;
        let bearer_slot = interceptor.bearer_slot();
        let token_source = token_source_from_config(&config);
        Ok(Self {
            channel,
            interceptor,
            token_source,
            bearer_slot,
        })
    }

    /// Construct from an already-built [`Channel`] and interceptor.
    ///
    /// Use when the caller needs to customize channel construction beyond
    /// what [`ClientConfig`] exposes. The resulting client does not perform
    /// OIDC refresh; drive rotation externally via the interceptor's slot.
    pub fn from_parts(channel: Channel, interceptor: EdgeAuthInterceptor) -> Self {
        let bearer_slot = interceptor.bearer_slot();
        Self {
            channel,
            interceptor,
            token_source: None,
            bearer_slot,
        }
    }

    /// Underlying tonic [`Channel`].
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Authenticated gRPC client for the main `OpenShell` service.
    ///
    /// Use this when the curated surface below doesn't expose the RPC or
    /// field you need.
    ///
    /// This does **not** drive OIDC refresh: it returns a client bound to
    /// the interceptor's current bearer slot without checking expiry or
    /// retrying on `Unauthenticated`. A client that only ever issues raw
    /// RPCs keeps sending the initial token until it expires. When a
    /// refresher is wired, prefer [`OpenShellClient::raw_grpc_fresh`] (or
    /// interleave a curated call) so rotation reaches the shared slot, and
    /// call [`OpenShellClient::force_refresh`] to recover on a rejected
    /// token.
    pub fn raw_grpc(&self) -> AuthedGrpcClient {
        proto::open_shell_client::OpenShellClient::with_interceptor(
            self.channel.clone(),
            self.interceptor.clone(),
        )
    }

    /// Like [`OpenShellClient::raw_grpc`], but proactively refreshes the
    /// bearer token first when a refresher is wired and the token is within
    /// the refresh skew of expiry. The returned client reads the same live
    /// slot, so the refreshed token applies to every RPC issued through it.
    ///
    /// Reactive retry on `Unauthenticated` remains the caller's
    /// responsibility for raw RPCs: on a rejected token, call
    /// [`OpenShellClient::force_refresh`] and reissue.
    pub async fn raw_grpc_fresh(&self) -> Result<AuthedGrpcClient> {
        self.ensure_fresh().await?;
        Ok(self.raw_grpc())
    }

    /// Authenticated gRPC client for the inference service.
    ///
    /// Like [`OpenShellClient::raw_grpc`], this does not drive OIDC refresh;
    /// use [`OpenShellClient::raw_inference_fresh`] when a refresher is wired.
    pub fn raw_inference(&self) -> AuthedInferenceClient {
        proto::inference_client::InferenceClient::with_interceptor(
            self.channel.clone(),
            self.interceptor.clone(),
        )
    }

    /// Like [`OpenShellClient::raw_inference`], but proactively refreshes the
    /// bearer token first (see [`OpenShellClient::raw_grpc_fresh`]).
    pub async fn raw_inference_fresh(&self) -> Result<AuthedInferenceClient> {
        self.ensure_fresh().await?;
        Ok(self.raw_inference())
    }

    /// Force an OIDC refresh and write the new token into the live bearer
    /// slot, regardless of expiry. Returns `true` when a refresher is wired
    /// and a fresh token was minted, `false` for static auth. Use after a
    /// raw RPC returns `Unauthenticated` to recover before reissuing it.
    pub async fn force_refresh(&self) -> Result<bool> {
        self.refresh_on_unauthorized().await
    }

    /// Gateway health snapshot.
    pub async fn health(&self) -> Result<Health> {
        let resp = self
            .unary(|mut grpc| async move { grpc.health(proto::HealthRequest {}).await })
            .await?;
        Ok(Health {
            status: resp.status.into(),
            version: resp.version,
        })
    }

    /// Create a new sandbox from a curated [`SandboxSpec`].
    pub async fn create_sandbox(&self, spec: SandboxSpec) -> Result<SandboxRef> {
        let request = create_sandbox_request(spec);
        let response = self
            .unary(|mut grpc| {
                let request = request.clone();
                async move { grpc.create_sandbox(request).await }
            })
            .await?;
        sandbox_from_response(response.sandbox)
    }

    /// Fetch a sandbox by name.
    pub async fn get_sandbox(&self, name: &str) -> Result<SandboxRef> {
        let response = self
            .unary(|mut grpc| {
                let request = proto::GetSandboxRequest {
                    name: name.to_string(),
                };
                async move { grpc.get_sandbox(request).await }
            })
            .await?;
        sandbox_from_response(response.sandbox)
    }

    /// List sandboxes.
    pub async fn list_sandboxes(&self, opts: ListOptions) -> Result<Vec<SandboxRef>> {
        let response = self
            .unary(|mut grpc| {
                let request = proto::ListSandboxesRequest {
                    limit: opts.limit,
                    offset: opts.offset,
                    label_selector: opts.label_selector.clone().unwrap_or_default(),
                };
                async move { grpc.list_sandboxes(request).await }
            })
            .await?;
        Ok(response
            .sandboxes
            .into_iter()
            .map(SandboxRef::from_proto)
            .collect())
    }

    /// Delete a sandbox by name.
    ///
    /// Returns `true` when the gateway acknowledges the deletion, `false`
    /// when it was already absent. The sandbox may still be in
    /// [`SandboxPhase::Deleting`] when this returns — pair with
    /// [`OpenShellClient::wait_deleted`] when you need a terminal guarantee.
    pub async fn delete_sandbox(&self, name: &str) -> Result<bool> {
        let response = self
            .unary(|mut grpc| {
                let request = proto::DeleteSandboxRequest {
                    name: name.to_string(),
                };
                async move { grpc.delete_sandbox(request).await }
            })
            .await?;
        Ok(response.deleted)
    }

    /// Poll [`OpenShellClient::get_sandbox`] until the sandbox reaches
    /// [`SandboxPhase::Ready`] or the `timeout` elapses.
    ///
    /// Returns the terminal sandbox snapshot on success. Returns an
    /// [`SdkError::Connect`] when the timeout expires, or whatever error
    /// the gateway returns if the sandbox transitions into
    /// [`SandboxPhase::Error`].
    pub async fn wait_ready(&self, name: &str, timeout: Duration) -> Result<SandboxRef> {
        self.wait_for(name, timeout, |phase| match phase {
            SandboxPhase::Ready => Some(Ok(())),
            SandboxPhase::Error => Some(Err(SdkError::connect(format!(
                "sandbox '{name}' entered error phase"
            )))),
            _ => None,
        })
        .await
    }

    /// Poll until the sandbox is gone (gRPC `NotFound`) or the `timeout`
    /// elapses.
    pub async fn wait_deleted(&self, name: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(250);
        loop {
            match self.get_sandbox(name).await {
                Err(SdkError::NotFound { .. }) => return Ok(()),
                Err(other) => return Err(other),
                Ok(snapshot) if snapshot.phase == SandboxPhase::Deleting => {}
                Ok(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(SdkError::connect(format!(
                    "timed out waiting for sandbox '{name}' to delete"
                )));
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(2));
        }
    }

    /// Run a command inside a sandbox and buffer stdout/stderr to the end.
    ///
    /// For streaming output, drop down to [`OpenShellClient::raw_grpc`] and
    /// call `exec_sandbox` directly.
    pub async fn exec(&self, name: &str, cmd: &[String], opts: ExecOptions) -> Result<ExecResult> {
        let sandbox = self.get_sandbox(name).await?;
        let request = proto::ExecSandboxRequest {
            sandbox_id: sandbox.id,
            command: cmd.to_vec(),
            workdir: opts.workdir.unwrap_or_default(),
            environment: opts.environment,
            timeout_seconds: opts
                .timeout
                .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX)),
            stdin: opts.stdin.unwrap_or_default(),
            tty: false,
            cols: 0,
            rows: 0,
        };

        // Proactively refresh, then open the stream. On `Unauthenticated` at
        // open time, force-refresh and retry once; mid-stream rotation is out
        // of scope (streaming retry is tracked separately).
        self.ensure_fresh().await?;
        let mut stream = match self.raw_grpc().exec_sandbox(request.clone()).await {
            Ok(resp) => resp.into_inner(),
            Err(status) if status.code() == tonic::Code::Unauthenticated => {
                if self.refresh_on_unauthorized().await? {
                    self.raw_grpc()
                        .exec_sandbox(request)
                        .await
                        .map_err(map_status)?
                        .into_inner()
                } else {
                    return Err(map_status(status));
                }
            }
            Err(status) => return Err(map_status(status)),
        };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<i32> = None;

        while let Some(event) = stream.next().await {
            let event = event.map_err(map_status)?;
            match event.payload {
                Some(proto::exec_sandbox_event::Payload::Stdout(chunk)) => {
                    stdout.extend_from_slice(&chunk.data);
                }
                Some(proto::exec_sandbox_event::Payload::Stderr(chunk)) => {
                    stderr.extend_from_slice(&chunk.data);
                }
                Some(proto::exec_sandbox_event::Payload::Exit(exit)) => {
                    exit_code = Some(exit.exit_code);
                }
                None => {}
            }
        }

        Ok(ExecResult {
            exit_code: exit_code.unwrap_or(-1),
            stdout,
            stderr,
        })
    }

    /// Run a unary RPC with OIDC-aware auth: refresh proactively before the
    /// call (if the token is near expiry) and, on an `Unauthenticated`
    /// response, force a refresh and retry exactly once. No-op auth behaves
    /// as a plain single call.
    async fn unary<T, F, Fut>(&self, call: F) -> Result<T>
    where
        F: Fn(AuthedGrpcClient) -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    {
        self.ensure_fresh().await?;
        match call(self.raw_grpc()).await {
            Ok(resp) => Ok(resp.into_inner()),
            Err(status) if status.code() == tonic::Code::Unauthenticated => {
                if self.refresh_on_unauthorized().await? {
                    call(self.raw_grpc())
                        .await
                        .map(tonic::Response::into_inner)
                        .map_err(map_status)
                } else {
                    Err(map_status(status))
                }
            }
            Err(status) => Err(map_status(status)),
        }
    }

    /// Proactive refresh: if a token source is wired and the token is within
    /// the refresh skew of expiry, mint a new one and store it in the live
    /// bearer slot. Tokens with no advertised expiry are left untouched.
    async fn ensure_fresh(&self) -> Result<()> {
        if let (Some(source), Some(slot)) = (&self.token_source, &self.bearer_slot) {
            let token = source.current().await?;
            store_bearer(slot, &token)?;
        }
        Ok(())
    }

    /// Reactive refresh: force a new token (used on `Unauthenticated`) and
    /// store it in the live slot. Returns `false` when no refresher is wired,
    /// signalling the caller to surface the original error.
    async fn refresh_on_unauthorized(&self) -> Result<bool> {
        if let (Some(source), Some(slot)) = (&self.token_source, &self.bearer_slot) {
            let token = source.refresh_now().await?;
            store_bearer(slot, &token)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn wait_for<F>(&self, name: &str, timeout: Duration, mut decide: F) -> Result<SandboxRef>
    where
        F: FnMut(SandboxPhase) -> Option<Result<()>>,
    {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(250);
        loop {
            let snapshot = self.get_sandbox(name).await?;
            if let Some(verdict) = decide(snapshot.phase) {
                verdict?;
                return Ok(snapshot);
            }
            if Instant::now() >= deadline {
                return Err(SdkError::connect(format!(
                    "timed out waiting for sandbox '{name}'"
                )));
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(2));
        }
    }
}

fn interceptor_from_config(config: &ClientConfig) -> Result<EdgeAuthInterceptor> {
    match &config.auth {
        None => Ok(EdgeAuthInterceptor::noop()),
        Some(AuthConfig::Oidc { token, .. }) => EdgeAuthInterceptor::new(Some(token), None),
        Some(AuthConfig::EdgeJwt(token)) => EdgeAuthInterceptor::new(None, Some(token)),
    }
}

/// Build a [`TokenSource`] when the config carries an OIDC refresher. Returns
/// `None` for static OIDC tokens, edge tokens, and anonymous auth.
fn token_source_from_config(config: &ClientConfig) -> Option<TokenSource> {
    let Some(AuthConfig::Oidc {
        token,
        expires_at,
        refresh: Some(refresher),
    }) = &config.auth
    else {
        return None;
    };
    let mut initial = RefreshedToken::new(token.clone());
    // Prefer the caller-advertised expiry; otherwise derive a deadline from
    // the token's JWT `exp` claim (reusing openshell-core's decoder) so the
    // proactive refresh path has an expiry to schedule against. Non-JWT
    // bearers fall back to reactive-only refresh.
    let deadline = expires_at
        .or_else(|| openshell_core::jwt::parse_exp_secs(token).and_then(|s| u64::try_from(s).ok()));
    if let Some(exp) = deadline {
        initial = initial.with_expires_at(exp);
    }
    Some(TokenSource::new(initial, Arc::clone(refresher)))
}

/// Overwrite the live bearer slot with a freshly minted token.
///
/// Returns an error if the refreshed token can't be encoded as gRPC metadata
/// instead of silently keeping the previous value. The [`TokenSource`] has
/// already committed the new token to its state by this point, so a silent
/// drop would leave the interceptor sending the old token with no path back
/// to a refresh; surfacing the error fails the call loudly instead.
fn store_bearer(slot: &BearerSlot, token: &str) -> Result<()> {
    let value = bearer_metadata(token)?;
    let mut guard = slot
        .write()
        .map_err(|_| SdkError::auth("bearer slot lock poisoned"))?;
    *guard = Some(value);
    Ok(())
}

fn create_sandbox_request(spec: SandboxSpec) -> proto::CreateSandboxRequest {
    let SandboxSpec {
        name,
        image,
        labels,
        environment,
        providers,
        gpu,
    } = spec;
    let template = image.map(|image| proto::SandboxTemplate {
        image,
        ..proto::SandboxTemplate::default()
    });
    let resource_requirements = gpu.then_some(proto::ResourceRequirements {
        gpu: Some(proto::GpuResourceRequirements { count: None }),
    });
    proto::CreateSandboxRequest {
        spec: Some(proto::SandboxSpec {
            environment,
            template,
            providers,
            resource_requirements,
            ..proto::SandboxSpec::default()
        }),
        name: name.unwrap_or_default(),
        labels,
    }
}

fn sandbox_from_response(sandbox: Option<proto::Sandbox>) -> Result<SandboxRef> {
    sandbox
        .map(SandboxRef::from_proto)
        .ok_or_else(|| SdkError::invalid_config("sandbox missing from gateway response"))
}

fn map_status(status: tonic::Status) -> SdkError {
    let message = status.message().to_string();
    match status.code() {
        tonic::Code::NotFound => SdkError::NotFound { message },
        tonic::Code::AlreadyExists => SdkError::AlreadyExists { message },
        tonic::Code::InvalidArgument => SdkError::invalid_config(message),
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => SdkError::auth(message),
        _ => SdkError::Rpc {
            code: status.code() as i32,
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::{Refresh, RefreshError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tonic::transport::Channel;

    struct StubRefresher {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Refresh for StubRefresher {
        async fn refresh(&self) -> std::result::Result<RefreshedToken, RefreshError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(RefreshedToken::new(format!("token-{n}")).with_expires_at(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600,
            ))
        }
    }

    /// Build an OIDC client wired to a refresher, with a near-expiry initial
    /// token, over a lazy channel that never actually connects (no RPC is
    /// issued in these tests).
    fn oidc_client_with_refresher(calls: Arc<AtomicUsize>) -> OpenShellClient {
        let interceptor = EdgeAuthInterceptor::new(Some("initial"), None).unwrap();
        let bearer_slot = interceptor.bearer_slot();
        let near = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 5;
        let source = TokenSource::new(
            RefreshedToken::new("initial").with_expires_at(near),
            Arc::new(StubRefresher { calls }),
        );
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        OpenShellClient {
            channel,
            interceptor,
            token_source: Some(source),
            bearer_slot,
        }
    }

    fn slot_token(slot: &BearerSlot) -> String {
        slot.read()
            .unwrap()
            .clone()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn raw_grpc_does_not_refresh() {
        // Regression (P1): the plain raw accessor must not be relied on for
        // rotation — it hands back a client bound to the current token.
        let calls = Arc::new(AtomicUsize::new(0));
        let client = oidc_client_with_refresher(Arc::clone(&calls));
        let _raw = client.raw_grpc();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "raw_grpc must not refresh");
        assert_eq!(
            slot_token(client.bearer_slot.as_ref().unwrap()),
            "Bearer initial"
        );
    }

    #[tokio::test]
    async fn raw_grpc_fresh_refreshes_near_expiry() {
        // Regression (P1): the _fresh accessor proactively rotates a
        // near-expiry token into the shared slot before returning a client.
        let calls = Arc::new(AtomicUsize::new(0));
        let client = oidc_client_with_refresher(Arc::clone(&calls));
        let _raw = client.raw_grpc_fresh().await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "raw_grpc_fresh must refresh a near-expiry token"
        );
        assert_eq!(
            slot_token(client.bearer_slot.as_ref().unwrap()),
            "Bearer token-1",
            "refreshed token must reach the live slot"
        );
    }

    #[tokio::test]
    async fn force_refresh_rotates_and_reports_wired() {
        // Regression (P1): reactive recovery path for raw callers.
        let calls = Arc::new(AtomicUsize::new(0));
        let client = oidc_client_with_refresher(Arc::clone(&calls));
        let refreshed = client.force_refresh().await.unwrap();
        assert!(refreshed, "force_refresh reports a wired refresher");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            slot_token(client.bearer_slot.as_ref().unwrap()),
            "Bearer token-1"
        );
    }

    #[test]
    fn store_bearer_rejects_malformed_token_and_keeps_previous() {
        let slot: BearerSlot = Arc::new(RwLock::new(None));
        store_bearer(&slot, "good-token").expect("a valid token should store");

        // A token with a control character can't be gRPC metadata; the slot
        // must keep its previous value and the error must surface.
        assert!(store_bearer(&slot, "bad\nvalue").is_err());
        let current = slot.read().unwrap().clone().unwrap();
        assert_eq!(current.to_str().unwrap(), "Bearer good-token");
    }
}
