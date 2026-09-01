// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod signer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use openshell_core::middleware::{HttpRequestResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_request_pre_credentials_server::{
    HttpRequestPreCredentials, HttpRequestPreCredentialsServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, Finding, HttpRequestBodyMode, HttpRequestBodyResult, HttpRequestBodyTransform,
    HttpRequestEvent, HttpRequestEventResult, HttpRequestPreflight, HttpRequestPreflightInspect,
    HttpRequestPreflightResult, HttpRequestPreflightSkip, HttpRequestResult, MiddlewareBinding,
    MiddlewareManifest, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent, http_request_body_result,
    http_request_body_transform, http_request_body_unit, http_request_event,
    http_request_event_result, http_request_preflight_result,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::signer::GitSigner;

const MANIFEST_NAME: &str = "example/git-commit-signing";
const OPERATION: SupervisorMiddlewareOperation = SupervisorMiddlewareOperation::HttpRequest;
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Sign commits in Git smart-HTTP pushes outside an OpenShell sandbox")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,

    /// Local SSH private key used by ssh-keygen. This path is never sent to the sandbox.
    #[arg(long)]
    signing_key: PathBuf,
}

#[derive(Clone)]
struct GitSigningMiddleware {
    signer: Arc<GitSigner>,
}

impl GitSigningMiddleware {
    fn new(signing_key: PathBuf) -> Result<Self, String> {
        Ok(Self {
            signer: Arc::new(GitSigner::new(signing_key)?),
        })
    }

    fn request_stream(
        &self,
        mut events: tonic::Streaming<HttpRequestEvent>,
    ) -> HttpRequestResultStream {
        let signer = Arc::clone(&self.signer);
        let (results_tx, results_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let mut selected = None;
            let mut body_complete = false;

            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = results_tx.send(Err(error)).await;
                        break;
                    }
                };
                let result = match event.event {
                    Some(http_request_event::Event::Preflight(preflight))
                        if selected.is_none() && !body_complete =>
                    {
                        match select_request(&preflight) {
                            Ok(None) => {
                                selected = Some(Selection::Skipped);
                                Ok(Some(preflight_skip()))
                            }
                            Ok(Some(selection)) => {
                                selected = Some(selection);
                                Ok(Some(preflight_whole_body()))
                            }
                            Err(status) => Err(status),
                        }
                    }
                    Some(http_request_event::Event::Body(body)) => {
                        let Some(Selection::Sign {
                            upstream_url,
                            request_id,
                        }) = selected.as_ref()
                        else {
                            return send_stream_error(
                                &results_tx,
                                Status::failed_precondition("unexpected request body event"),
                            )
                            .await;
                        };
                        if body_complete || body.sequence != 1 {
                            Err(Status::invalid_argument(
                                "whole-body signing expects sequence 1 exactly once",
                            ))
                        } else {
                            let Some(http_request_body_unit::Payload::Data(data)) = body.payload
                            else {
                                return send_stream_error(
                                    &results_tx,
                                    Status::invalid_argument("request body data is required"),
                                )
                                .await;
                            };
                            body_complete = true;
                            sign_body(
                                Arc::clone(&signer),
                                data,
                                upstream_url.clone(),
                                request_id.clone(),
                                body.sequence,
                            )
                            .await
                            .map(Some)
                        }
                    }
                    Some(http_request_event::Event::BodyEnd(end))
                        if matches!(selected, Some(Selection::Sign { .. }))
                            && body_complete
                            && end.final_sequence == 1 =>
                    {
                        Ok(None)
                    }
                    Some(http_request_event::Event::SessionEnd(_)) if selected.is_some() => break,
                    _ => Err(Status::failed_precondition(
                        "invalid Git signing request stream lifecycle",
                    )),
                };

                match result {
                    Ok(Some(result)) => {
                        if results_tx.send(Ok(result)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = results_tx.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        Box::pin(ReceiverStream::new(results_rx))
    }
}

enum Selection {
    Skipped,
    Sign {
        upstream_url: String,
        request_id: String,
    },
}

#[tonic::async_trait]
impl SupervisorMiddleware for GitSigningMiddleware {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: OPERATION as i32,
                phase: PHASE as i32,
                max_payload_bytes: MAX_BODY_BYTES,
                timeout: "30s".into(),
            }],
            expected_audience: String::new(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let unknown = request
            .config
            .as_ref()
            .and_then(|config| config.fields.keys().next())
            .cloned();
        Ok(Response::new(match unknown {
            None => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Some(field) => ValidateConfigResponse {
                valid: false,
                reason: format!("unsupported config field '{field}'"),
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<openshell_core::proto::HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Err(Status::unimplemented(
            "git signer requires HttpRequestPreCredentials.Evaluate",
        ))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "WebSocket middleware is not supported",
        ))
    }
}

#[tonic::async_trait]
impl HttpRequestPreCredentials for GitSigningMiddleware {
    type EvaluateStream = HttpRequestResultStream;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpRequestEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        Ok(Response::new(self.request_stream(request.into_inner())))
    }
}

fn select_request(preflight: &HttpRequestPreflight) -> Result<Option<Selection>, Status> {
    if !is_receive_pack_request(preflight) {
        return Ok(None);
    }
    let target = preflight
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Git push request has no target"))?;
    Ok(Some(Selection::Sign {
        upstream_url: github_upstream_url(target)?,
        request_id: preflight
            .context
            .as_ref()
            .map(|context| context.request_id.clone())
            .unwrap_or_default(),
    }))
}

fn preflight_skip() -> HttpRequestEventResult {
    HttpRequestEventResult {
        result: Some(http_request_event_result::Result::PreflightResult(
            HttpRequestPreflightResult {
                decision: Decision::Allow as i32,
                action: Some(http_request_preflight_result::Action::Skip(
                    HttpRequestPreflightSkip {},
                )),
                reason_code: "not_git_receive_pack".into(),
                ..Default::default()
            },
        )),
    }
}

fn preflight_whole_body() -> HttpRequestEventResult {
    HttpRequestEventResult {
        result: Some(http_request_event_result::Result::PreflightResult(
            HttpRequestPreflightResult {
                decision: Decision::Allow as i32,
                action: Some(http_request_preflight_result::Action::Inspect(
                    HttpRequestPreflightInspect {
                        body_mode: HttpRequestBodyMode::WholeBodyBytes as i32,
                        header_mutations: Vec::new(),
                    },
                )),
                reason_code: "git_receive_pack_selected".into(),
                ..Default::default()
            },
        )),
    }
}

fn body_transform(sequence: u64, body: Vec<u8>, signed_commits: u32) -> HttpRequestEventResult {
    HttpRequestEventResult {
        result: Some(http_request_event_result::Result::BodyResult(
            HttpRequestBodyResult {
                sequence,
                decision: Decision::Allow as i32,
                action: Some(http_request_body_result::Action::Transform(
                    HttpRequestBodyTransform {
                        replacement: Some(http_request_body_transform::Replacement::Data(body)),
                    },
                )),
                findings: vec![Finding {
                    r#type: "git.commit.signed".into(),
                    label: "outgoing Git commits signed".into(),
                    count: signed_commits,
                    confidence: "high".into(),
                    severity: "informational".into(),
                }],
                metadata: HashMap::from([(
                    "signed_commit_count".into(),
                    signed_commits.to_string(),
                )]),
                reason_code: "git_commits_signed".into(),
                ..Default::default()
            },
        )),
    }
}

async fn sign_body(
    signer: Arc<GitSigner>,
    data: Vec<u8>,
    upstream_url: String,
    request_id: String,
    sequence: u64,
) -> Result<HttpRequestEventResult, Status> {
    let log_upstream = upstream_url.clone();
    let log_request_id = request_id.clone();
    let signed =
        tokio::task::spawn_blocking(move || signer.sign_receive_pack(&data, Some(&upstream_url)))
            .await
            .map_err(|_| Status::internal("git signing worker failed"))?
            .map_err(|error| {
                warn!(
                    request_id = log_request_id,
                    upstream = %log_upstream,
                    error = %error,
                    "outgoing Git push could not be signed"
                );
                Status::failed_precondition(error.public_message())
            })?;
    info!(
        request_id,
        upstream = %log_upstream,
        signed_commits = signed.signed_commits,
        "signed outgoing Git push"
    );
    Ok(body_transform(sequence, signed.body, signed.signed_commits))
}

async fn send_stream_error(
    sender: &tokio::sync::mpsc::Sender<Result<HttpRequestEventResult, Status>>,
    status: Status,
) {
    let _ = sender.send(Err(status)).await;
}

fn github_upstream_url(
    target: &openshell_core::proto::HttpRequestTarget,
) -> Result<String, Status> {
    if target.scheme != "https" || target.host != "github.com" || target.port != 443 {
        return Err(Status::invalid_argument(
            "prototype supports HTTPS pushes to github.com only",
        ));
    }
    let repository_path = target
        .path
        .strip_suffix("/git-receive-pack")
        .ok_or_else(|| Status::invalid_argument("invalid Git receive-pack path"))?;
    let segments = repository_path
        .strip_prefix('/')
        .and_then(|path| path.strip_suffix(".git"))
        .map(|path| path.split('/').collect::<Vec<_>>())
        .ok_or_else(|| Status::invalid_argument("invalid GitHub repository path"))?;
    if segments.len() != 2
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(Status::invalid_argument("invalid GitHub repository path"));
    }
    Ok(format!("https://github.com{repository_path}"))
}

fn is_receive_pack_request(request: &HttpRequestPreflight) -> bool {
    let Some(target) = request.target.as_ref() else {
        return false;
    };
    target.method == "POST"
        && target.path.ends_with("/git-receive-pack")
        && request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && header
                    .value
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim() == "application/x-git-receive-pack-request")
        })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let middleware = GitSigningMiddleware::new(cli.signing_key)
        .map_err(|error| format!("invalid signing configuration: {error}"))?;
    info!(bind = %cli.bind, "starting Git commit signing middleware");
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(middleware.clone()))
        .add_service(HttpRequestPreCredentialsServer::new(middleware))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{HttpHeader, HttpRequestTarget};

    #[test]
    fn recognizes_git_receive_pack_only() {
        let request = HttpRequestPreflight {
            target: Some(HttpRequestTarget {
                method: "POST".into(),
                path: "/NVIDIA/OpenShell.git/git-receive-pack".into(),
                ..Default::default()
            }),
            headers: vec![HttpHeader {
                name: "content-type".into(),
                value: "application/x-git-receive-pack-request".into(),
            }],
            ..Default::default()
        };
        assert!(is_receive_pack_request(&request));

        let mut fetch = request;
        fetch.target.as_mut().unwrap().path = "/NVIDIA/OpenShell.git/git-upload-pack".into();
        assert!(!is_receive_pack_request(&fetch));
    }

    #[test]
    fn derives_a_bounded_github_upstream_url() {
        let target = openshell_core::proto::HttpRequestTarget {
            scheme: "https".into(),
            host: "github.com".into(),
            port: 443,
            path: "/NVIDIA/OpenShell.git/git-receive-pack".into(),
            ..Default::default()
        };
        assert_eq!(
            github_upstream_url(&target).unwrap(),
            "https://github.com/NVIDIA/OpenShell.git"
        );

        let mut traversal = target;
        traversal.path = "/NVIDIA/../OpenShell.git/git-receive-pack".into();
        assert!(github_upstream_url(&traversal).is_err());
    }
}
