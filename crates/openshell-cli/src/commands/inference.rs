// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::color::Colorize;
use crate::tls::{TlsOptions, grpc_inference_client};
use indicatif::{ProgressBar, ProgressStyle};
use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{
    DeleteInferenceRouteRequest, GetInferenceRouteRequest, SetInferenceRouteRequest,
};
use std::io::IsTerminal;
use std::time::Duration;
use tonic::{Code, Status};

#[allow(clippy::too_many_arguments)]
pub async fn gateway_inference_set(
    server: &str,
    provider_name: &str,
    model_id: &str,
    route_name: &str,
    no_verify: bool,
    timeout_secs: u64,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let progress = if std::io::stdout().is_terminal() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Configuring inference...");
        spinner.enable_steady_tick(Duration::from_millis(120));
        Some(spinner)
    } else {
        None
    };

    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .set_inference_route(SetInferenceRouteRequest {
            provider_name: provider_name.to_string(),
            model_id: model_id.to_string(),
            route_name: route_name.to_string(),
            verify: false,
            no_verify,
            timeout_secs,
            workspace: workspace.to_string(),
        })
        .await;

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }

    let response = response.map_err(format_inference_status)?;

    let configured = response.into_inner();
    let label = if configured.route_name == "sandbox-system" {
        "System inference configured:"
    } else {
        "Inference configured:"
    };
    println!("{}", label.cyan().bold());
    println!();
    println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
    println!("  {} {}", "Route:".dimmed(), configured.route_name);
    println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
    println!("  {} {}", "Model:".dimmed(), configured.model_id);
    println!("  {} {}", "Version:".dimmed(), configured.version);
    print_timeout(configured.timeout_secs);
    if configured.validation_performed {
        println!("  {}", "Validated Endpoints:".dimmed());
        for endpoint in configured.validated_endpoints {
            println!("    - {} ({})", endpoint.url, endpoint.protocol);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn gateway_inference_update(
    server: &str,
    provider_name: Option<&str>,
    model_id: Option<&str>,
    route_name: &str,
    no_verify: bool,
    timeout_secs: Option<u64>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if provider_name.is_none() && model_id.is_none() && timeout_secs.is_none() {
        return Err(miette::miette!(
            "at least one of --provider, --model, or --timeout must be specified"
        ));
    }

    let mut client = grpc_inference_client(server, tls).await?;

    // Fetch current config to use as base for the partial update.
    let current = client
        .get_inference_route(GetInferenceRouteRequest {
            route_name: route_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let provider = provider_name.unwrap_or(&current.provider_name);
    let model = model_id.unwrap_or(&current.model_id);
    let timeout = timeout_secs.unwrap_or(current.timeout_secs);

    let progress = if std::io::stdout().is_terminal() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Configuring inference...");
        spinner.enable_steady_tick(Duration::from_millis(120));
        Some(spinner)
    } else {
        None
    };

    let response = client
        .set_inference_route(SetInferenceRouteRequest {
            provider_name: provider.to_string(),
            model_id: model.to_string(),
            route_name: route_name.to_string(),
            verify: false,
            no_verify,
            timeout_secs: timeout,
            workspace: workspace.to_string(),
        })
        .await;

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }

    let response = response.map_err(format_inference_status)?;

    let configured = response.into_inner();
    let label = if configured.route_name == "sandbox-system" {
        "System inference updated:"
    } else {
        "Inference updated:"
    };
    println!("{}", label.cyan().bold());
    println!();
    println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
    println!("  {} {}", "Route:".dimmed(), configured.route_name);
    println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
    println!("  {} {}", "Model:".dimmed(), configured.model_id);
    println!("  {} {}", "Version:".dimmed(), configured.version);
    print_timeout(configured.timeout_secs);
    if configured.validation_performed {
        println!("  {}", "Validated Endpoints:".dimmed());
        for endpoint in configured.validated_endpoints {
            println!("    - {} ({})", endpoint.url, endpoint.protocol);
        }
    }
    Ok(())
}

pub async fn gateway_inference_get(
    server: &str,
    route_name: Option<&str>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;

    if let Some(name) = route_name {
        // Show a single route (--system was specified).
        let response = client
            .get_inference_route(GetInferenceRouteRequest {
                route_name: name.to_string(),
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?;

        let configured = response.into_inner();
        let label = if name == "sandbox-system" {
            "System inference:"
        } else {
            "Inference:"
        };
        println!("{}", label.cyan().bold());
        println!();
        println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
        println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
        println!("  {} {}", "Model:".dimmed(), configured.model_id);
        println!("  {} {}", "Version:".dimmed(), configured.version);
        print_timeout(configured.timeout_secs);
    } else {
        // Show both routes by default.
        print_inference_route(&mut client, "Inference", "", workspace).await;
        println!();
        print_inference_route(&mut client, "System inference", "sandbox-system", workspace).await;
    }
    Ok(())
}

pub async fn gateway_inference_delete(
    server: &str,
    route_name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;

    let response = client
        .delete_inference_route(DeleteInferenceRouteRequest {
            route_name: route_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let label = if route_name == "sandbox-system" {
        "System inference route"
    } else {
        "Inference route"
    };

    if response.into_inner().deleted {
        println!("{label} deleted.");
    } else {
        println!("{label} not found (already deleted).");
    }
    Ok(())
}

async fn print_inference_route(
    client: &mut crate::tls::GrpcInferenceClient,
    label: &str,
    route_name: &str,
    workspace: &str,
) {
    match client
        .get_inference_route(GetInferenceRouteRequest {
            route_name: route_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => {
            let configured = response.into_inner();
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
            println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
            println!("  {} {}", "Model:".dimmed(), configured.model_id);
            println!("  {} {}", "Version:".dimmed(), configured.version);
            print_timeout(configured.timeout_secs);
        }
        Err(e) if e.code() == Code::NotFound => {
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {}", "Not configured".dimmed());
        }
        Err(e) => {
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {} {}", "Error:".red(), e.message());
        }
    }
}

fn print_timeout(timeout_secs: u64) {
    if timeout_secs == 0 {
        println!("  {} {}s (default)", "Timeout:".dimmed(), 60);
    } else {
        println!("  {} {}s", "Timeout:".dimmed(), timeout_secs);
    }
}

fn format_inference_status(status: Status) -> miette::Report {
    let message = status.message().trim();

    if message.is_empty() {
        return miette::miette!("inference configuration failed ({})", status.code());
    }

    miette::miette!("{message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_status_preserves_actionable_server_messages() {
        let err = format_inference_status(Status::invalid_argument("provider is missing"));
        assert_eq!(err.to_string(), "provider is missing");
    }

    #[test]
    fn inference_status_falls_back_to_the_status_code_for_empty_messages() {
        let err = format_inference_status(Status::new(Code::Unavailable, ""));
        let message = err.to_string();
        assert!(message.contains("inference configuration failed"));
        assert!(message.to_lowercase().contains("unavailable"));
    }
}
