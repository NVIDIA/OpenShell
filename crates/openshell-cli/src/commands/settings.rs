// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::color::Colorize;
use crate::commands::common::{
    confirm_global_setting_delete, confirm_global_setting_takeover, format_setting_value,
    parse_cli_setting_value,
};
use crate::tls::{TlsOptions, grpc_client};
use miette::{IntoDiagnostic, Result};
use openshell_core::ObjectId;
use openshell_core::proto::{
    GetGatewayConfigRequest, GetSandboxConfigRequest, GetSandboxConfigResponse, GetSandboxRequest,
    PolicySource, SettingScope, UpdateConfigRequest,
};

pub async fn sandbox_settings_get(
    server: &str,
    name: &str,
    json: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    let response = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox.object_id().to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if json {
        let obj = settings_to_json_sandbox(name, workspace, &response);
        println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
        return Ok(());
    }

    let policy_source = if response.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };

    println!("Sandbox:       {name}");
    println!("Config Rev:    {}", response.config_revision);
    println!("Policy Source: {policy_source}");
    println!("Policy Hash:   {}", response.policy_hash);

    if response.settings.is_empty() {
        println!("Settings:      No settings available.");
        return Ok(());
    }

    println!("Settings:");
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            let scope = match SettingScope::try_from(setting.scope) {
                Ok(SettingScope::Global) => "global",
                Ok(SettingScope::Sandbox) => "sandbox",
                _ => "unset",
            };
            println!(
                "  {} = {} ({})",
                key,
                format_setting_value(setting.value.as_ref()),
                scope
            );
        }
    }

    Ok(())
}

pub async fn gateway_settings_get(server: &str, json: bool, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_gateway_config(GetGatewayConfigRequest {})
        .await
        .into_diagnostic()?
        .into_inner();

    if json {
        let obj = settings_to_json_global(&response);
        println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
        return Ok(());
    }

    println!("Scope:         global");
    println!("Settings Rev:  {}", response.settings_revision);

    if response.settings.is_empty() {
        println!("Settings:      No settings available.");
        return Ok(());
    }

    println!("Settings:");
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            println!("  {} = {}", key, format_setting_value(Some(setting)));
        }
    }
    Ok(())
}

fn settings_to_json_sandbox(
    name: &str,
    workspace: &str,
    response: &GetSandboxConfigResponse,
) -> serde_json::Value {
    let policy_source = if response.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };

    let mut settings = serde_json::Map::new();
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            let scope = match SettingScope::try_from(setting.scope) {
                Ok(SettingScope::Global) => "global",
                Ok(SettingScope::Sandbox) => "sandbox",
                _ => "unset",
            };
            settings.insert(
                key,
                serde_json::json!({
                    "value": format_setting_value(setting.value.as_ref()),
                    "scope": scope,
                }),
            );
        }
    }

    serde_json::json!({
        "sandbox": name,
        "workspace": workspace,
        "config_revision": response.config_revision,
        "policy_source": policy_source,
        "policy_hash": response.policy_hash,
        "settings": settings,
    })
}

fn settings_to_json_global(
    response: &openshell_core::proto::GetGatewayConfigResponse,
) -> serde_json::Value {
    let mut settings = serde_json::Map::new();
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            settings.insert(key, serde_json::json!(format_setting_value(Some(setting))));
        }
    }

    serde_json::json!({
        "scope": "global",
        "settings_revision": response.settings_revision,
        "settings": settings,
    })
}

pub async fn gateway_setting_set(
    server: &str,
    key: &str,
    value: &str,
    yes: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let setting_value = parse_cli_setting_value(key, value)?;
    confirm_global_setting_takeover(key, yes)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            setting_key: key.to_string(),
            setting_value: Some(setting_value),
            global: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    println!(
        "{} Set global setting {}={} (revision {})",
        "✓".green().bold(),
        key,
        value,
        response.settings_revision
    );
    Ok(())
}

pub async fn sandbox_setting_set(
    server: &str,
    name: &str,
    key: &str,
    value: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let setting_value = parse_cli_setting_value(key, value)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            setting_key: key.to_string(),
            setting_value: Some(setting_value),
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    println!(
        "{} Set sandbox setting {}={} for {} (revision {})",
        "✓".green().bold(),
        key,
        value,
        name,
        response.settings_revision
    );
    Ok(())
}

pub async fn gateway_setting_delete(
    server: &str,
    key: &str,
    yes: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    confirm_global_setting_delete(key, yes)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            setting_key: key.to_string(),
            delete_setting: true,
            global: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted global setting {} (revision {})",
            "✓".green().bold(),
            key,
            response.settings_revision
        );
    } else {
        println!("{} Global setting {} not found", "!".yellow(), key);
    }
    Ok(())
}

pub async fn sandbox_setting_delete(
    server: &str,
    name: &str,
    key: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            setting_key: key.to_string(),
            delete_setting: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted sandbox setting {} for {} (revision {})",
            "✓".green().bold(),
            key,
            name,
            response.settings_revision
        );
    } else {
        println!(
            "{} Sandbox setting {} not found for {}",
            "!".yellow(),
            key,
            name,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        EffectiveSetting, GetGatewayConfigResponse, SettingValue, setting_value,
    };
    use std::collections::HashMap;

    fn bool_setting(value: bool) -> SettingValue {
        SettingValue {
            value: Some(setting_value::Value::BoolValue(value)),
        }
    }

    #[test]
    fn sandbox_settings_json_preserves_effective_scope_and_metadata() {
        let response = GetSandboxConfigResponse {
            settings: HashMap::from([(
                "ocsf_json_enabled".to_string(),
                EffectiveSetting {
                    value: Some(bool_setting(true)),
                    scope: SettingScope::Global as i32,
                },
            )]),
            config_revision: 7,
            policy_source: PolicySource::Global as i32,
            policy_hash: "policy-hash".to_string(),
            ..Default::default()
        };

        assert_eq!(
            settings_to_json_sandbox("dev", "team-a", &response),
            serde_json::json!({
                "sandbox": "dev",
                "workspace": "team-a",
                "config_revision": 7,
                "policy_source": "global",
                "policy_hash": "policy-hash",
                "settings": {
                    "ocsf_json_enabled": {
                        "value": "true",
                        "scope": "global",
                    }
                },
            })
        );
    }

    #[test]
    fn gateway_settings_json_preserves_revision_and_values() {
        let response = GetGatewayConfigResponse {
            settings: HashMap::from([("ocsf_json_enabled".to_string(), bool_setting(false))]),
            settings_revision: 9,
        };

        assert_eq!(
            settings_to_json_global(&response),
            serde_json::json!({
                "scope": "global",
                "settings_revision": 9,
                "settings": {"ocsf_json_enabled": "false"},
            })
        );
    }
}
