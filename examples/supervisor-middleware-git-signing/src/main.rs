// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod signer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    MiddlewareManifest, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    ValidateConfigRequest, ValidateConfigResponse,
};
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
}

#[tonic::async_trait]
impl SupervisorMiddleware for GitSigningMiddleware {
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
                max_body_bytes: MAX_BODY_BYTES,
                timeout: "30s".into(),
            }],
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
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        if request.phase != PHASE as i32 {
            return Err(Status::invalid_argument("unsupported middleware phase"));
        }

        if !is_receive_pack_request(&request) {
            return Ok(Response::new(allow_unchanged()));
        }

        let target = request
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Git push request has no target"))?;
        let upstream_url = github_upstream_url(target)?;
        let request_id = request
            .context
            .as_ref()
            .map(|context| context.request_id.clone())
            .unwrap_or_default();
        let signer = Arc::clone(&self.signer);
        let log_upstream = upstream_url.clone();
        let signed = tokio::task::spawn_blocking(move || {
            signer.sign_receive_pack(&request.body, Some(&upstream_url))
        })
        .await
        .map_err(|_| Status::internal("git signing worker failed"))?
        .map_err(|error| {
            warn!(
                request_id,
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

        Ok(Response::new(HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: signed.body,
            has_body: true,
            header_mutations: Vec::new(),
            findings: vec![Finding {
                r#type: "git.commit.signed".into(),
                label: "outgoing Git commits signed".into(),
                count: signed.signed_commits,
                confidence: "high".into(),
                severity: "informational".into(),
            }],
            metadata: HashMap::from([(
                "signed_commit_count".into(),
                signed.signed_commits.to_string(),
            )]),
            reason_code: String::new(),
        }))
    }
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

fn is_receive_pack_request(request: &HttpRequestEvaluation) -> bool {
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

fn allow_unchanged() -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Allow as i32,
        reason: String::new(),
        body: Vec::new(),
        has_body: false,
        header_mutations: Vec::new(),
        findings: Vec::new(),
        metadata: HashMap::new(),
        reason_code: String::new(),
    }
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
        .add_service(SupervisorMiddlewareServer::new(middleware))
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
        let request = HttpRequestEvaluation {
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
