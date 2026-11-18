// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell secret`: workspace secrets used as shared minting material.
//!
//! Values are read from an environment variable or a file, never from a
//! command-line argument, and the gateway never returns them to this CLI.

use crate::color::Colorize;
use crate::commands::common::{format_epoch_ms, parse_key_value_pairs};
use crate::tls::{TlsOptions, grpc_client};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_core::proto::{
    CreateSecretRequest, DeleteSecretRequest, GetSecretRequest, ListSecretsRequest, Secret,
    SecretLabels, UpdateSecretRequest, workspace_selector,
};
use std::path::Path;

/// Where a secret value comes from. At most one source may be given.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecretValueSource<'a> {
    pub env: Option<&'a str>,
    pub file: Option<&'a Path>,
}

impl SecretValueSource<'_> {
    fn read(self) -> Result<Option<String>> {
        match (self.env, self.file) {
            (Some(_), Some(_)) => Err(miette!("pass only one of --value-env and --value-file")),
            (Some(var), None) => {
                let value = std::env::var(var)
                    .map_err(|_| miette!("--value-env requires local env var '{var}' to be set"))?;
                if value.is_empty() {
                    return Err(miette!("local env var '{var}' is empty"));
                }
                Ok(Some(value))
            }
            (None, Some(path)) => {
                let mut value = std::fs::read_to_string(path)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to read {}", path.display()))?;
                // Files written by editors and `echo` end with a newline that
                // is not part of the secret.
                if value.ends_with('\n') {
                    value.pop();
                    if value.ends_with('\r') {
                        value.pop();
                    }
                }
                if value.is_empty() {
                    return Err(miette!("{} is empty", path.display()));
                }
                Ok(Some(value))
            }
            (None, None) => Ok(None),
        }
    }
}

pub struct SecretCreateInput<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub value: SecretValueSource<'a>,
    pub allowed_endpoints: &'a [String],
    pub labels: &'a [String],
}

pub async fn secret_create(
    server: &str,
    input: SecretCreateInput<'_>,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let value = input
        .value
        .read()?
        .ok_or_else(|| miette!("pass --value-env or --value-file"))?;
    let labels = parse_key_value_pairs(input.labels, "--label")?;
    let mut client = grpc_client(server, tls).await?;
    let secret = client
        .create_secret(CreateSecretRequest {
            workspace_scope: Some(workspace_selector(workspace.to_string())),
            name: input.name.to_string(),
            description: input.description.to_string(),
            value,
            allowed_endpoints: input.allowed_endpoints.to_vec(),
            labels,
            request_id: String::new(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .secret
        .ok_or_else(|| miette!("secret missing from response"))?;
    if crate::output::print_output_single(output, &secret, secret_to_json)? {
        return Ok(());
    }
    println!(
        "{} Created secret {}",
        "✓".green().bold(),
        secret_name(&secret)
    );
    Ok(())
}

pub struct SecretUpdateInput<'a> {
    pub name: &'a str,
    pub value: SecretValueSource<'a>,
    pub description: Option<&'a str>,
    pub labels: Option<&'a [String]>,
}

pub async fn secret_update(
    server: &str,
    input: SecretUpdateInput<'_>,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let value = input.value.read()?;
    let labels = input
        .labels
        .map(|labels| parse_key_value_pairs(labels, "--label"))
        .transpose()?
        .map(|labels| SecretLabels { labels });
    if value.is_none() && input.description.is_none() && labels.is_none() {
        return Err(miette!(
            "nothing to update; pass --value-env, --value-file, --description, or --label"
        ));
    }
    let mut client = grpc_client(server, tls).await?;
    let secret = client
        .update_secret(UpdateSecretRequest {
            workspace_scope: Some(workspace_selector(workspace.to_string())),
            name: input.name.to_string(),
            value,
            description: input.description.map(str::to_string),
            labels,
            expected_resource_version: None,
            request_id: String::new(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .secret
        .ok_or_else(|| miette!("secret missing from response"))?;
    if crate::output::print_output_single(output, &secret, secret_to_json)? {
        return Ok(());
    }
    println!(
        "{} Updated secret {}",
        "✓".green().bold(),
        secret_name(&secret)
    );
    Ok(())
}

pub async fn secret_get(
    server: &str,
    name: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let secret = client
        .get_secret(GetSecretRequest {
            workspace_scope: Some(workspace_selector(workspace.to_string())),
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .secret
        .ok_or_else(|| miette!("secret missing from response"))?;
    if crate::output::print_output_single(output, &secret, secret_to_json)? {
        return Ok(());
    }
    println!("{}", "Secret:".cyan().bold());
    println!();
    println!("  {} {}", "Name:".dimmed(), secret_name(&secret));
    if !secret.description.is_empty() {
        println!("  {} {}", "Description:".dimmed(), secret.description);
    }
    println!(
        "  {} {}",
        "Allowed endpoints:".dimmed(),
        secret.allowed_endpoints.join(", ")
    );
    println!("  {} {}", "Value updated:".dimmed(), value_updated(&secret));
    if let Some(meta) = &secret.metadata
        && !meta.labels.is_empty()
    {
        let mut labels: Vec<_> = meta
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        labels.sort();
        println!("  {} {}", "Labels:".dimmed(), labels.join(", "));
    }
    Ok(())
}

pub async fn secret_list(
    server: &str,
    page_size: i32,
    page_token: &str,
    label_selector: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_secrets(ListSecretsRequest {
            workspace_scope: Some(workspace_selector(workspace.to_string())),
            page_size,
            page_token: page_token.to_string(),
            label_selector: label_selector.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();
    if crate::output::print_paginated_output_collection(
        output,
        "secrets",
        &response.secrets,
        &response.next_page_token,
        secret_to_json,
    )? {
        return Ok(());
    }
    crate::output::print_next_page_token(&response.next_page_token);
    if response.secrets.is_empty() {
        println!("No secrets found.");
        return Ok(());
    }
    let name_width = response
        .secrets
        .iter()
        .map(|secret| secret_name(secret).len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "{:<name_width$}  {:<20}  {}",
        "NAME".bold(),
        "VALUE UPDATED".bold(),
        "ALLOWED ENDPOINTS".bold(),
    );
    for secret in &response.secrets {
        println!(
            "{:<name_width$}  {:<20}  {}",
            secret_name(secret),
            value_updated(secret),
            secret.allowed_endpoints.join(", ")
        );
    }
    Ok(())
}

pub async fn secret_delete(
    server: &str,
    names: &[String],
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    for name in names {
        let response = client
            .delete_secret(DeleteSecretRequest {
                workspace_scope: Some(workspace_selector(workspace.to_string())),
                name: name.clone(),
                allow_missing: true,
                request_id: String::new(),
            })
            .await
            .into_diagnostic()?
            .into_inner();
        if crate::run::deletion_completed(response.outcome)? {
            println!("{} Deleted secret {name}", "✓".green().bold());
        } else {
            println!("Secret '{name}' not found.");
        }
    }
    Ok(())
}

fn secret_name(secret: &Secret) -> &str {
    secret
        .metadata
        .as_ref()
        .map_or("", |meta| meta.name.as_str())
}

fn value_updated(secret: &Secret) -> String {
    secret
        .value_update_time
        .as_ref()
        .and_then(|time| openshell_core::time::timestamp_to_millis(time).ok())
        .map_or_else(|| "-".to_string(), format_epoch_ms)
}

fn secret_to_json(secret: &Secret) -> serde_json::Value {
    let meta = secret.metadata.clone().unwrap_or_default();
    serde_json::json!({
        "name": meta.name,
        "id": meta.id,
        "workspace": meta.workspace,
        "resource_version": meta.resource_version,
        "labels": meta.labels,
        "description": secret.description,
        "allowed_endpoints": secret.allowed_endpoints,
        "value_updated_at": secret
            .value_update_time
            .as_ref()
            .and_then(|time| openshell_core::time::timestamp_to_millis(time).ok())
            .map(format_epoch_ms),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_sources_are_exclusive_and_trim_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "s3cret\r\n").unwrap();
        let file = SecretValueSource {
            env: None,
            file: Some(&path),
        };
        assert_eq!(file.read().unwrap().as_deref(), Some("s3cret"));

        let both = SecretValueSource {
            env: Some("OPENSHELL_UNUSED"),
            file: Some(&path),
        };
        assert!(both.read().is_err());
        assert!(SecretValueSource::default().read().unwrap().is_none());

        std::fs::write(&path, "\n").unwrap();
        assert!(file.read().is_err(), "an empty value is rejected");
    }

    #[test]
    fn json_output_never_carries_a_value_field() {
        let json = secret_to_json(&Secret::default());
        assert!(json.get("value").is_none());
    }
}
