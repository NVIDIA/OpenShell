// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI-side credential authority for deferred provider secrets.
//!
//! When a sandbox uses deferred providers, the CLI opens a bidirectional gRPC
//! stream to the gateway (`RegisterCredentialAuthority`). The gateway relays
//! credential requests from sandbox supervisors; the CLI prompts the user via
//! an OS-native dialog and responds with the secret read from local env vars.

use std::collections::HashMap;

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{CredentialRequest, CredentialResponse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codec::Streaming;
use tracing::{debug, info, warn};

use crate::tls::GrpcClient;

#[derive(Clone, Debug)]
enum ApprovalDecision {
    Once(String),
    Always(String),
    Deny,
}

/// Spawn the credential authority in the background (fire-and-forget).
pub fn spawn_credential_authority(client: GrpcClient) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_credential_authority(client).await {
            tracing::debug!("Credential authority exited: {e}");
        }
    })
}

/// Run the credential authority event loop.
///
/// Opens a bidirectional `RegisterCredentialAuthority` stream to the gateway
/// and handles incoming credential requests by prompting the user. This blocks
/// until the stream is closed (Ctrl-C or gateway disconnect).
pub async fn run_credential_authority(mut client: GrpcClient) -> Result<()> {
    let (resp_tx, resp_rx) = mpsc::channel::<CredentialResponse>(16);

    // Seed the client→server stream so the HTTP/2 body has an initial DATA
    // frame. Without this, the empty stream is dropped by intermediaries
    // (NodePort, Docker port mapping) before real traffic arrives.
    resp_tx
        .send(CredentialResponse {
            request_id: String::new(),
            approved: false,
            value: String::new(),
        })
        .await
        .into_diagnostic()?;

    let response_stream = ReceiverStream::new(resp_rx);

    let mut request_stream: Streaming<CredentialRequest> = client
        .register_credential_authority(response_stream)
        .await
        .into_diagnostic()?
        .into_inner();

    let mut approval_cache: HashMap<String, ApprovalDecision> = HashMap::new();

    info!("Listening for credential requests... (Ctrl-C to detach)");

    while let Some(req) = request_stream
        .message()
        .await
        .into_diagnostic()?
    {
        debug!(
            env_key = %req.env_key,
            destination_host = %req.destination_host,
            sandbox_name = %req.sandbox_name,
            "Credential request received"
        );

        let decision = if let Some(cached) = approval_cache.get(&req.env_key) {
            cached.clone()
        } else {
            prompt_user(&req.sandbox_name, &req.env_key, &req.destination_host)?
        };

        let response = match &decision {
            ApprovalDecision::Always(value) => {
                approval_cache
                    .insert(req.env_key.clone(), ApprovalDecision::Always(value.clone()));
                CredentialResponse {
                    request_id: req.request_id,
                    approved: true,
                    value: value.clone(),
                }
            }
            ApprovalDecision::Once(value) => CredentialResponse {
                request_id: req.request_id,
                approved: true,
                value: value.clone(),
            },
            ApprovalDecision::Deny => {
                approval_cache.insert(req.env_key.clone(), ApprovalDecision::Deny);
                CredentialResponse {
                    request_id: req.request_id,
                    approved: false,
                    value: String::new(),
                }
            }
        };

        if resp_tx.send(response).await.is_err() {
            warn!("Gateway stream closed, exiting credential authority");
            break;
        }
    }

    Ok(())
}

/// Show an OS-native dialog and read the secret from a local env var.
fn prompt_user(
    sandbox_name: &str,
    env_key: &str,
    destination_host: &str,
) -> Result<ApprovalDecision> {
    let choice = show_native_dialog(sandbox_name, env_key, destination_host)?;

    match choice.as_str() {
        "Once" | "Always" => {
            let value = std::env::var(env_key).map_err(|_| {
                miette::miette!(
                    "{env_key} is not set in the local environment. \
                     Set it and retry, or deny the request."
                )
            })?;
            if choice == "Always" {
                Ok(ApprovalDecision::Always(value))
            } else {
                Ok(ApprovalDecision::Once(value))
            }
        }
        _ => Ok(ApprovalDecision::Deny),
    }
}

/// Display an OS-native dialog asking the user to approve credential sharing.
///
/// Returns "Once", "Always", or "Deny".
fn show_native_dialog(
    sandbox_name: &str,
    env_key: &str,
    destination_host: &str,
) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display dialog "Sandbox '{}' requests {}\nDestination: {}" buttons {{"Deny", "Once", "Always"}} default button "Once" with title "OpenShell Credential Request""#,
            sandbox_name, env_key, destination_host
        );
        let output = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .into_diagnostic()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Always") {
            Ok("Always".to_string())
        } else if stdout.contains("Once") {
            Ok("Once".to_string())
        } else {
            Ok("Deny".to_string())
        }
    }

    #[cfg(all(not(target_os = "macos"), target_os = "linux"))]
    {
        let text = format!(
            "Sandbox '{}' requests {}\nDestination: {}",
            sandbox_name, env_key, destination_host
        );
        let output = std::process::Command::new("zenity")
            .args([
                "--list",
                "--radiolist",
                "--title=OpenShell Credential Request",
                &format!("--text={text}"),
                "--column=",
                "--column=Choice",
                "TRUE",
                "Once",
                "FALSE",
                "Always",
                "FALSE",
                "Deny",
            ])
            .output()
            .into_diagnostic()?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout == "Always" || stdout == "Once" {
            Ok(stdout)
        } else {
            Ok("Deny".to_string())
        }
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
    {
        warn!("No native dialog available on this platform, defaulting to Deny");
        Ok("Deny".to_string())
    }
}
