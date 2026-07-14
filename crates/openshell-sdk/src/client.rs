// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! High-level async client over the gateway gRPC surface.
//!
//! Covers the sandbox-focused MVP slice: health, sandbox CRUD, readiness /
//! deletion waits, and non-streaming exec. Other RPCs (inference, providers,
//! policy, logs, settings, SSH, forwarding) are reachable via
//! [`OpenShellClient::raw_grpc`] / [`OpenShellClient::raw_inference`].

use crate::auth::EdgeAuthInterceptor;
use crate::config::{AuthConfig, ClientConfig};
use crate::error::{Result, SdkError};
use crate::raw::{AuthedGrpcClient, AuthedInferenceClient};
use crate::transport;
use crate::types::{
    ExecOptions, ExecResult, Health, ListOptions, SandboxPhase, SandboxRef, SandboxSpec,
};
use futures::StreamExt;
use openshell_core::proto;
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
}

impl OpenShellClient {
    /// Open a connection to the gateway described by `config`.
    ///
    /// Performs the gRPC channel handshake immediately; subsequent RPCs reuse
    /// the connection.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let channel = transport::build_channel(&config).await?;
        let interceptor = interceptor_from_config(&config)?;
        Ok(Self {
            channel,
            interceptor,
        })
    }

    /// Construct from an already-built [`Channel`] and interceptor.
    ///
    /// Use when the caller needs to customize channel construction beyond
    /// what [`ClientConfig`] exposes.
    pub fn from_parts(channel: Channel, interceptor: EdgeAuthInterceptor) -> Self {
        Self {
            channel,
            interceptor,
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
        let mut grpc = self.raw_grpc();
        let resp = grpc
            .health(proto::HealthRequest {})
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(Health {
            status: resp.status.into(),
            version: resp.version,
        })
    }

    /// Create a new sandbox from a curated [`SandboxSpec`].
    pub async fn create_sandbox(&self, spec: SandboxSpec) -> Result<SandboxRef> {
        let request = create_sandbox_request(spec);
        let mut grpc = self.raw_grpc();
        let response = grpc
            .create_sandbox(request)
            .await
            .map_err(map_status)?
            .into_inner();
        sandbox_from_response(response.sandbox)
    }

    /// Fetch a sandbox by name.
    pub async fn get_sandbox(&self, name: &str) -> Result<SandboxRef> {
        let mut grpc = self.raw_grpc();
        let response = grpc
            .get_sandbox(proto::GetSandboxRequest {
                name: name.to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner();
        sandbox_from_response(response.sandbox)
    }

    /// List sandboxes.
    pub async fn list_sandboxes(&self, opts: ListOptions) -> Result<Vec<SandboxRef>> {
        let mut grpc = self.raw_grpc();
        let response = grpc
            .list_sandboxes(proto::ListSandboxesRequest {
                limit: opts.limit,
                offset: opts.offset,
                label_selector: opts.label_selector.unwrap_or_default(),
            })
            .await
            .map_err(map_status)?
            .into_inner();
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
        let mut grpc = self.raw_grpc();
        let response = grpc
            .delete_sandbox(proto::DeleteSandboxRequest {
                name: name.to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner();
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

        let mut grpc = self.raw_grpc();
        let mut stream = grpc
            .exec_sandbox(request)
            .await
            .map_err(map_status)?
            .into_inner();

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
        Some(AuthConfig::Oidc(token)) => EdgeAuthInterceptor::new(Some(token), None),
        Some(AuthConfig::EdgeJwt(token)) => EdgeAuthInterceptor::new(None, Some(token)),
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
    let resource_requirements = gpu.then(|| proto::ResourceRequirements {
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
