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
    pub fn raw_grpc(&self) -> AuthedGrpcClient {
        proto::open_shell_client::OpenShellClient::with_interceptor(
            self.channel.clone(),
            self.interceptor.clone(),
        )
    }

    /// Authenticated gRPC client for the inference service.
    pub fn raw_inference(&self) -> AuthedInferenceClient {
        proto::inference_client::InferenceClient::with_interceptor(
            self.channel.clone(),
            self.interceptor.clone(),
        )
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
            store_bearer(slot, &token);
        }
        Ok(())
    }

    /// Reactive refresh: force a new token (used on `Unauthenticated`) and
    /// store it in the live slot. Returns `false` when no refresher is wired,
    /// signalling the caller to surface the original error.
    async fn refresh_on_unauthorized(&self) -> Result<bool> {
        if let (Some(source), Some(slot)) = (&self.token_source, &self.bearer_slot) {
            let token = source.refresh_now().await?;
            store_bearer(slot, &token);
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
    if let Some(exp) = expires_at {
        initial = initial.with_expires_at(*exp);
    }
    Some(TokenSource::new(initial, Arc::clone(refresher)))
}

/// Overwrite the live bearer slot with a freshly minted token. A malformed
/// token value is dropped (the slot keeps its previous value); the next
/// request then fails auth and surfaces a clear error.
fn store_bearer(slot: &BearerSlot, token: &str) {
    if let Ok(value) = bearer_metadata(token)
        && let Ok(mut guard) = slot.write()
    {
        *guard = Some(value);
    }
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
