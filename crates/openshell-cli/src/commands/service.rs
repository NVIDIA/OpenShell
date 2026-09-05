// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::color::Colorize;
use crate::commands::common::phase_name;
use crate::tls::{TlsOptions, grpc_client};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_core::ObjectId;
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_core::proto::{
    CreateSshSessionRequest, DeleteServiceRequest, ExposeServiceRequest, GetSandboxRequest,
    GetServiceRequest, ListServicesRequest, RevokeSshSessionRequest, Sandbox, SandboxPhase,
    ServiceEndpointResponse, TcpForwardFrame, TcpForwardInit, TcpRelayTarget, tcp_forward_init,
};
use std::time::Duration;
use tonic::{Code, Status};

pub async fn service_forward_tcp(
    server: &str,
    name: &str,
    local: Option<&str>,
    target_host: &str,
    target_port: u16,
    tls: &TlsOptions,
    workspace: &str,
) -> Result<()> {
    let (bind_addr, bind_port) = parse_tcp_forward_spec(local, target_port)?;
    let mut client = grpc_client(server, tls).await?;

    let sandbox = fetch_ready_sandbox_for_forward(&mut client, name, workspace).await?;

    let listener = tokio::net::TcpListener::bind((bind_addr.as_str(), bind_port))
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind local forward on {bind_addr}:{bind_port}"))?;
    let local_addr = listener
        .local_addr()
        .into_diagnostic()
        .wrap_err("failed to read local forward address")?;
    eprintln!(
        "{} Forwarding {} -> {}:{} in sandbox {} via gRPC",
        "✓".green().bold(),
        local_addr,
        target_host,
        target_port,
        name,
    );

    let sandbox_id = sandbox.object_id().to_string();
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::channel::<String>(1);
    let mut health_check = tokio::time::interval(Duration::from_secs(2));
    health_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(reason) = fatal_rx.recv() => {
                return Err(miette::miette!("service forward stopped: {reason}"));
            }

            _ = health_check.tick() => {
                fetch_ready_sandbox_for_forward(&mut client, name, workspace).await?;
            }

            accepted = listener.accept() => {
                let (socket, peer) = accepted
                    .into_diagnostic()
                    .wrap_err("failed to accept local forward connection")?;
                set_tcp_nodelay_best_effort(&socket);
                let mut client = client.clone();
                let sandbox_id = sandbox_id.clone();
                let target_host = target_host.to_string();
                let service_id = format!("service-forward:{name}:{target_host}:{target_port}");
                let fatal_tx = fatal_tx.clone();
                tokio::spawn(async move {
                    let token = match create_forward_session_token(&mut client, &sandbox_id).await {
                        Ok(token) => token,
                        Err(err) => {
                            tracing::warn!(peer = %peer, error = %err, "service forward session creation failed");
                            if err.fatal {
                                let _ = fatal_tx.send(err.message).await;
                            }
                            return;
                        }
                    };
                    if let Err(err) = forward_one_tcp_connection(
                        &mut client,
                        socket,
                        sandbox_id,
                        target_host,
                        target_port,
                        service_id,
                        token.clone(),
                    )
                    .await
                    {
                        tracing::warn!(peer = %peer, error = %err, "service forward connection failed");
                        if err.fatal {
                            let _ = fatal_tx.send(err.message).await;
                        }
                    }
                    let _ = client
                        .revoke_ssh_session(RevokeSshSessionRequest { token })
                        .await;
                });
            }
        }
    }
}

async fn create_forward_session_token(
    client: &mut crate::tls::GrpcClient,
    sandbox_id: &str,
) -> std::result::Result<String, ForwardTcpConnectionError> {
    let response = client
        .create_ssh_session(CreateSshSessionRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .map_err(ForwardTcpConnectionError::from_status)?;
    Ok(response.into_inner().token)
}

async fn fetch_ready_sandbox_for_forward(
    client: &mut crate::tls::GrpcClient,
    name: &str,
    workspace: &str,
) -> Result<Sandbox> {
    let response = match client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => response,
        Err(status) if status.code() == Code::NotFound => {
            return Err(miette::miette!(
                "sandbox '{name}' no longer exists; stopping service forward"
            ));
        }
        Err(status) => return Err(status).into_diagnostic(),
    };

    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox '{name}' not found"))?;

    if SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready) {
        return Err(miette::miette!(
            "sandbox '{}' is no longer ready (phase: {}); stopping service forward",
            name,
            phase_name(sandbox.phase())
        ));
    }

    Ok(sandbox)
}

#[derive(Debug)]
struct ForwardTcpConnectionError {
    message: String,
    fatal: bool,
}

impl ForwardTcpConnectionError {
    fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: false,
        }
    }

    fn from_status(status: Status) -> Self {
        let fatal = matches!(status.code(), Code::NotFound | Code::FailedPrecondition);
        Self {
            message: status.to_string(),
            fatal,
        }
    }
}

impl std::fmt::Display for ForwardTcpConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ForwardTcpConnectionError {}

fn parse_tcp_forward_spec(local: Option<&str>, default_port: u16) -> Result<(String, u16)> {
    let Some(spec) = local else {
        return Ok(("127.0.0.1".to_string(), default_port));
    };

    if let Some(pos) = spec.rfind(':') {
        let addr = &spec[..pos];
        let port_str = &spec[pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            if addr.is_empty() {
                return Err(miette::miette!("bind address is required before ':'"));
            }
            return Ok((addr.to_string(), port));
        }
    }

    let port: u16 = spec.parse().map_err(|_| {
        miette::miette!("invalid local forward spec '{spec}': expected [bind_address:]port")
    })?;
    Ok(("127.0.0.1".to_string(), port))
}

async fn forward_one_tcp_connection(
    client: &mut crate::tls::GrpcClient,
    socket: tokio::net::TcpStream,
    sandbox_id: String,
    target_host: String,
    target_port: u16,
    service_id: String,
    authorization_token: String,
) -> std::result::Result<(), ForwardTcpConnectionError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = tokio::sync::mpsc::channel::<TcpForwardFrame>(16);
    tx.send(TcpForwardFrame {
        payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Init(
            TcpForwardInit {
                sandbox_id,
                service_id,
                target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                    host: target_host,
                    port: u32::from(target_port),
                })),
                authorization_token,
            },
        )),
    })
    .await
    .map_err(|_| ForwardTcpConnectionError::transient("failed to initialize forward stream"))?;

    let mut response = match client.forward_tcp(ReceiverStream::new(rx)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            let err = ForwardTcpConnectionError::from_status(status);
            drain_and_shutdown_local_socket(socket).await;
            return Err(err);
        }
    };

    let (mut local_read, mut local_write) = socket.into_split();

    let to_gateway = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if tx
                .send(TcpForwardFrame {
                    payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Data(
                        buf[..n].to_vec(),
                    )),
                })
                .await
                .is_err()
            {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    });

    while let Some(frame) = response
        .message()
        .await
        .map_err(ForwardTcpConnectionError::from_status)?
    {
        let Some(openshell_core::proto::tcp_forward_frame::Payload::Data(data)) = frame.payload
        else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        local_write
            .write_all(&data)
            .await
            .map_err(|err| ForwardTcpConnectionError::transient(err.to_string()))?;
    }

    let _ = local_write.shutdown().await;
    to_gateway.abort();
    Ok(())
}

async fn drain_and_shutdown_local_socket(mut socket: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 4096];
    while matches!(
        tokio::time::timeout(Duration::from_millis(25), socket.read(&mut buf)).await,
        Ok(Ok(n)) if n != 0
    ) {}
    let _ = socket.shutdown().await;
}

pub async fn service_expose(
    server: &str,
    sandbox: &str,
    service: &str,
    target_port: u16,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .expose_service(ExposeServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            target_port: u32::from(target_port),
            domain: true,
            workspace: workspace.to_string(),
        })
        .await
        .map_err(service_expose_status_error)?
        .into_inner();

    if service.is_empty() {
        println!(
            "{} Exposed sandbox {} -> 127.0.0.1:{}",
            "✓".green().bold(),
            sandbox.bold(),
            target_port,
        );
    } else {
        println!(
            "{} Exposed service {} on sandbox {} -> 127.0.0.1:{}",
            "✓".green().bold(),
            service.bold(),
            sandbox.bold(),
            target_port,
        );
    }
    if !response.url.is_empty() {
        let url = service_url_for_gateway(&response.url, server);
        println!("  URL: {}", url.cyan());
    }
    Ok(())
}

fn service_expose_status_error(status: Status) -> miette::Report {
    service_status_error("expose service", "sandbox:write", status)
}

#[allow(clippy::too_many_arguments)] // user-facing CLI command
pub async fn service_list(
    server: &str,
    sandbox: Option<&str>,
    limit: u32,
    offset: u32,
    workspace: &str,
    all_workspaces: bool,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_services(ListServicesRequest {
            sandbox: sandbox.unwrap_or_default().to_string(),
            limit,
            offset,
            workspace: if all_workspaces {
                String::new()
            } else {
                workspace.to_string()
            },
            all_workspaces,
        })
        .await
        .map_err(|status| service_status_error("list services", "sandbox:read", status))?
        .into_inner();

    let services = response
        .services
        .iter()
        .filter_map(|response| service_endpoint_to_json(response, server))
        .collect::<Vec<_>>();
    if crate::output::print_output_collection(output, &services, Clone::clone)? {
        return Ok(());
    }

    if response.services.is_empty() {
        if let Some(sandbox) = sandbox {
            println!("No services exposed for sandbox {sandbox}.");
        } else {
            println!("No services exposed.");
        }
        return Ok(());
    }

    print_service_endpoint_table(&response.services, server, all_workspaces);
    Ok(())
}

pub async fn service_get(
    server: &str,
    sandbox: &str,
    service: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_service(GetServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .map_err(|status| service_status_error("get service", "sandbox:read", status))?
        .into_inner();

    print_service_endpoint_table(&[response], server, false);
    Ok(())
}

pub async fn service_delete(
    server: &str,
    sandbox: &str,
    service: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .delete_service(DeleteServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .map_err(|status| service_status_error("delete service", "sandbox:write", status))?
        .into_inner();

    if !response.deleted {
        return Err(miette!("delete service failed: service endpoint not found"));
    }

    if service.is_empty() {
        println!(
            "{} Deleted exposed sandbox {}",
            "✓".green().bold(),
            sandbox.bold(),
        );
    } else {
        println!(
            "{} Deleted service {} on sandbox {}",
            "✓".green().bold(),
            service.bold(),
            sandbox.bold(),
        );
    }
    Ok(())
}

fn service_status_error(action: &str, required_scope: &str, status: Status) -> miette::Report {
    let message = status.message();
    match status.code() {
        Code::PermissionDenied => {
            miette!("{action} failed: permission denied (requires {required_scope})")
        }
        Code::Unauthenticated => miette!("{action} failed: authentication required"),
        Code::NotFound if message == "sandbox not found" => {
            miette!("{action} failed: sandbox not found")
        }
        Code::NotFound if message == "service endpoint not found" => {
            miette!("{action} failed: service endpoint not found")
        }
        Code::InvalidArgument if !message.is_empty() => {
            miette!("{action} failed: invalid request: {message}")
        }
        _ => miette!("{action} failed: {status}"),
    }
}

fn print_service_endpoint_table(
    services: &[ServiceEndpointResponse],
    gateway_endpoint: &str,
    all_workspaces: bool,
) {
    let rows = services
        .iter()
        .filter_map(|response| {
            let endpoint = response.endpoint.as_ref()?;
            let workspace = endpoint
                .metadata
                .as_ref()
                .map_or("", |m| m.workspace.as_str());
            let service = service_display_name(&endpoint.service_name).to_string();
            let target = format!("127.0.0.1:{}", endpoint.target_port);
            let url = if response.url.is_empty() {
                String::new()
            } else {
                service_url_for_gateway(&response.url, gateway_endpoint)
            };
            Some((
                workspace.to_string(),
                endpoint.sandbox_name.clone(),
                service,
                target,
                url,
            ))
        })
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return;
    }

    let ws_width = if all_workspaces {
        rows.iter()
            .map(|(ws, _, _, _, _)| ws.len())
            .max()
            .unwrap_or(9)
            .max(9)
    } else {
        0
    };
    let sandbox_width = rows
        .iter()
        .map(|(_, sandbox, _, _, _)| sandbox.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let service_width = rows
        .iter()
        .map(|(_, _, service, _, _)| service.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let target_width = rows
        .iter()
        .map(|(_, _, _, target, _)| target.len())
        .max()
        .unwrap_or(6)
        .max(6);

    if all_workspaces {
        println!(
            "{:<ws_width$}  {:<sandbox_width$}  {:<service_width$}  {:<target_width$}  {}",
            "WORKSPACE".bold(),
            "SANDBOX".bold(),
            "SERVICE".bold(),
            "TARGET".bold(),
            "URL".bold(),
        );
    } else {
        println!(
            "{:<sandbox_width$}  {:<service_width$}  {:<target_width$}  {}",
            "SANDBOX".bold(),
            "SERVICE".bold(),
            "TARGET".bold(),
            "URL".bold(),
        );
    }

    for (workspace, sandbox, service, target, url) in rows {
        if all_workspaces {
            println!(
                "{workspace:<ws_width$}  {sandbox:<sandbox_width$}  {service:<service_width$}  {target:<target_width$}  {url}"
            );
        } else {
            println!(
                "{sandbox:<sandbox_width$}  {service:<service_width$}  {target:<target_width$}  {url}"
            );
        }
    }
}

fn service_endpoint_to_json(
    response: &ServiceEndpointResponse,
    gateway_endpoint: &str,
) -> Option<serde_json::Value> {
    let endpoint = response.endpoint.as_ref()?;
    let workspace = endpoint
        .metadata
        .as_ref()
        .map_or("", |metadata| metadata.workspace.as_str());
    let url = if response.url.is_empty() {
        String::new()
    } else {
        service_url_for_gateway(&response.url, gateway_endpoint)
    };

    Some(serde_json::json!({
        "workspace": workspace,
        "sandbox": endpoint.sandbox_name,
        "service": endpoint.service_name,
        "target_port": endpoint.target_port,
        "url": url,
    }))
}

fn service_display_name(service: &str) -> &str {
    if service.is_empty() { "-" } else { service }
}

fn service_url_for_gateway(service_url: &str, gateway_endpoint: &str) -> String {
    let (Ok(mut service_url), Ok(gateway_endpoint)) = (
        url::Url::parse(service_url),
        url::Url::parse(gateway_endpoint),
    ) else {
        return service_url.to_string();
    };

    if service_url
        .set_port(gateway_endpoint.port_or_known_default())
        .is_err()
    {
        return service_url.to_string();
    }

    service_url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{ServiceEndpoint, datamodel::v1::ObjectMeta};

    #[test]
    fn service_endpoint_json_has_raw_fields_and_normalized_url() {
        let response = ServiceEndpointResponse {
            endpoint: Some(ServiceEndpoint {
                metadata: Some(ObjectMeta {
                    workspace: "team-a".to_string(),
                    ..Default::default()
                }),
                sandbox_name: "api".to_string(),
                service_name: String::new(),
                target_port: 8080,
                ..Default::default()
            }),
            url: "https://api.openshell.localhost:3000/".to_string(),
        };

        let value = service_endpoint_to_json(&response, "https://gateway.example:17670")
            .expect("service endpoint JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "workspace": "team-a",
                "sandbox": "api",
                "service": "",
                "target_port": 8080,
                "url": "https://api.openshell.localhost:17670/",
            })
        );
        assert!(service_endpoint_to_json(&ServiceEndpointResponse::default(), "unused").is_none());
    }

    #[test]
    fn service_url_for_gateway_uses_external_gateway_port() {
        assert_eq!(
            service_url_for_gateway(
                "https://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://127.0.0.1:31886"
            ),
            "https://quiet-flamingo--notebook.navigator.openshell.localhost:31886/"
        );
    }

    #[test]
    fn service_url_for_gateway_omits_default_external_port() {
        assert_eq!(
            service_url_for_gateway(
                "https://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://gateway.example.com"
            ),
            "https://quiet-flamingo--notebook.navigator.openshell.localhost/"
        );
    }

    #[test]
    fn service_url_for_gateway_preserves_service_scheme() {
        assert_eq!(
            service_url_for_gateway(
                "http://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://127.0.0.1:31886"
            ),
            "http://quiet-flamingo--notebook.navigator.openshell.localhost:31886/"
        );
    }

    #[test]
    fn service_url_for_gateway_uses_gateway_default_port() {
        assert_eq!(
            service_url_for_gateway(
                "http://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://gateway.example.com"
            ),
            "http://quiet-flamingo--notebook.navigator.openshell.localhost:443/"
        );
    }

    #[test]
    fn service_expose_status_error_mentions_required_scope() {
        let report = service_expose_status_error(Status::permission_denied(
            "scope 'sandbox:write' required",
        ));

        assert_eq!(
            report.to_string(),
            "expose service failed: permission denied (requires sandbox:write)"
        );
    }

    #[test]
    fn tcp_forward_spec_parses_defaults_and_explicit_bind_addresses() {
        assert_eq!(
            parse_tcp_forward_spec(None, 8080).expect("default forward"),
            ("127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            parse_tcp_forward_spec(Some("9090"), 8080).expect("port-only forward"),
            ("127.0.0.1".to_string(), 9090)
        );
        assert_eq!(
            parse_tcp_forward_spec(Some("0.0.0.0:7070"), 8080).expect("explicit bind"),
            ("0.0.0.0".to_string(), 7070)
        );
        assert!(parse_tcp_forward_spec(Some(":7070"), 8080).is_err());
        assert!(parse_tcp_forward_spec(Some("not-a-port"), 8080).is_err());
    }

    #[test]
    fn forward_connection_errors_classify_terminal_sandbox_states_as_fatal() {
        for code in [Code::NotFound, Code::FailedPrecondition] {
            assert!(ForwardTcpConnectionError::from_status(Status::new(code, "terminal")).fatal);
        }
        for code in [Code::Unavailable, Code::Internal, Code::PermissionDenied] {
            assert!(!ForwardTcpConnectionError::from_status(Status::new(code, "retryable")).fatal);
        }
    }
}
