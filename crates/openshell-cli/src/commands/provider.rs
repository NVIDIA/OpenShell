// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::color::Colorize;
use crate::commands::common::{
    format_epoch_ms, format_optional_epoch_ms, parse_credential_expiry_pairs,
    parse_credential_pairs, parse_key_value_pairs, parse_secret_material_env_pairs,
    truncate_display, truncate_status_field,
};
use crate::tls::{TlsOptions, grpc_client};
use dialoguer::Confirm;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_core::proto::ProviderProfileCategory;
use openshell_core::proto::{
    AttachSandboxProviderRequest, ConfigureProviderRefreshRequest, CreateProviderRequest,
    DeleteProviderProfileRequest, DeleteProviderRefreshRequest, DeleteProviderRequest,
    DetachSandboxProviderRequest, GetProviderProfileRequest, GetProviderRefreshStatusRequest,
    GetProviderRequest, GetSandboxRequest, ImportProviderProfilesRequest,
    LintProviderProfilesRequest, ListProviderProfilesRequest, ListProvidersRequest,
    ListSandboxProvidersRequest, Provider, ProviderCredentialRefreshRecoveryAction,
    ProviderCredentialRefreshStatus, ProviderCredentialRefreshStrategy,
    ProviderCredentialTokenGrantType, ProviderProfile, ProviderProfileDiagnostic,
    ProviderProfileImportItem, RotateProviderCredentialRequest, UpdateProviderProfilesRequest,
    UpdateProviderRequest,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use openshell_providers::{
    ProviderTypeProfile, RealDiscoveryContext, detect_provider_from_command, discover_from_profile,
    normalize_profile_id, normalize_provider_type, parse_profile_json, parse_profile_yaml,
    profile_to_json, profile_to_yaml, profiles_to_json, profiles_to_yaml,
};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tonic::{Code, Status};

fn aggregate_delete_failures(resource: &str, failures: &[String]) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(miette!(
            "failed to delete {} {}{}: {}",
            failures.len(),
            resource,
            if failures.len() == 1 { "" } else { "s" },
            failures.join(", ")
        ))
    }
}

pub async fn sandbox_provider_list(
    server: &str,
    name: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_sandbox_providers(ListSandboxProvidersRequest {
            sandbox_name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;
    let providers = response.into_inner().providers;

    if crate::output::print_output_collection(output, &providers, attached_provider_to_json)? {
        return Ok(());
    }

    if providers.is_empty() {
        println!("No providers attached to sandbox {name}.");
        return Ok(());
    }

    print_provider_attachment_table(&providers);
    Ok(())
}

pub async fn sandbox_provider_attach(
    server: &str,
    name: &str,
    provider: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    // Fetch current sandbox to get resource_version for CAS
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

    let resource_version = sandbox.metadata.as_ref().map_or(0, |m| m.resource_version);

    let response = match client
        .attach_sandbox_provider(AttachSandboxProviderRequest {
            sandbox_name: name.to_string(),
            provider_name: provider.to_string(),
            expected_resource_version: resource_version,
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == Code::Aborted => {
            return Err(miette::miette!(
                "Failed to attach provider: sandbox was modified by another operation.\n\
                 Please retry the command."
            )
            .with_source_code(status.message().to_string()));
        }
        Err(e) => return Err(e).into_diagnostic(),
    };

    if response.attached {
        println!(
            "{} Attached provider {} to sandbox {}",
            "✓".green().bold(),
            provider,
            name
        );
    } else {
        println!("Provider {provider} is already attached to sandbox {name}.");
    }
    Ok(())
}

pub async fn sandbox_provider_detach(
    server: &str,
    name: &str,
    provider: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    // Fetch current sandbox to get resource_version for CAS
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

    let resource_version = sandbox.metadata.as_ref().map_or(0, |m| m.resource_version);

    let response = match client
        .detach_sandbox_provider(DetachSandboxProviderRequest {
            sandbox_name: name.to_string(),
            provider_name: provider.to_string(),
            expected_resource_version: resource_version,
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == Code::Aborted => {
            return Err(miette::miette!(
                "Failed to detach provider: sandbox was modified by another operation.\n\
                 Please retry the command."
            )
            .with_source_code(status.message().to_string()));
        }
        Err(e) => return Err(e).into_diagnostic(),
    };

    if response.detached {
        println!(
            "{} Detached provider {} from sandbox {}",
            "✓".green().bold(),
            provider,
            name
        );
    } else {
        println!("Provider {provider} was not attached to sandbox {name}.");
    }
    Ok(())
}

fn print_provider_attachment_table(providers: &[Provider]) {
    print!("{}", format_provider_attachment_table(providers, true));
}

fn attached_provider_to_json(provider: &Provider) -> serde_json::Value {
    let mut config_keys = provider.config.keys().cloned().collect::<Vec<_>>();
    config_keys.sort();

    serde_json::json!({
        "name": provider.object_name(),
        "type": provider.r#type,
        "credential_keys": provider_credential_keys(provider),
        "config_keys": config_keys,
    })
}

fn format_provider_attachment_table(providers: &[Provider], color: bool) -> String {
    use std::fmt::Write as _;

    let name_width = providers
        .iter()
        .map(|provider| provider.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let type_width = providers
        .iter()
        .map(|provider| provider.r#type.len())
        .max()
        .unwrap_or(4)
        .max(4);

    let name_header = if color {
        "NAME".bold().to_string()
    } else {
        "NAME".to_string()
    };
    let type_header = if color {
        "TYPE".bold().to_string()
    } else {
        "TYPE".to_string()
    };
    let credential_keys_header = if color {
        "CREDENTIAL_KEYS".bold().to_string()
    } else {
        "CREDENTIAL_KEYS".to_string()
    };
    let config_keys_header = if color {
        "CONFIG_KEYS".bold().to_string()
    } else {
        "CONFIG_KEYS".to_string()
    };

    let mut output = String::new();
    let _ = writeln!(
        output,
        "{name_header:<name_width$}  {type_header:<type_width$}  {credential_keys_header:<16}  {config_keys_header}",
    );

    for provider in providers {
        let provider_name = provider.object_name();
        let provider_type = &provider.r#type;
        let credential_keys = provider_credential_keys(provider).len();
        let config_keys = provider.config.len();
        let _ = writeln!(
            output,
            "{provider_name:<name_width$}  {provider_type:<type_width$}  {credential_keys:<16}  {config_keys}",
        );
    }
    output
}

/// Return the provider type inferred from the trailing command, if any.
pub fn inferred_provider_type(command: &[String]) -> Option<String> {
    detect_provider_from_command(command).map(str::to_string)
}

/// Ensure all required providers exist.
///
/// `explicit_names` are provider **names** supplied via `--provider`. They are
/// passed through directly; the server validates they exist at sandbox creation.
///
/// `inferred_types` are provider **types** inferred from the trailing command
/// (e.g. `claude` -> type `"claude-code"`). These are resolved to provider names via
/// a type→name lookup, and missing types may be auto-created interactively.
///
/// Returns a deduplicated list of provider **names** suitable for
/// `SandboxSpec.providers`.
pub async fn ensure_required_providers(
    client: &mut crate::tls::GrpcClient,
    explicit_names: &[String],
    inferred_types: &[String],
    auto_providers_override: Option<bool>,
    workspace: &str,
) -> Result<Vec<String>> {
    if explicit_names.is_empty() && inferred_types.is_empty() {
        return Ok(Vec::new());
    }

    let mut configured_names: Vec<String> = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    // ── Fetch all existing providers ─────────────────────────────────────
    // Build both a name set (for explicit --provider lookups) and a
    // type-to-name map (for inferred provider resolution).
    let mut known_names: HashSet<String> = HashSet::new();
    let mut type_to_name: HashMap<String, String> = HashMap::new();
    {
        let mut offset = 0_u32;
        let limit = 100_u32;
        loop {
            let response = client
                .list_providers(ListProvidersRequest {
                    limit,
                    offset,
                    workspace: workspace.to_string(),
                    all_workspaces: false,
                })
                .await
                .into_diagnostic()?;
            let providers = response.into_inner().providers;
            for provider in &providers {
                known_names.insert(provider.object_name().to_string());
                if !provider.r#type.is_empty() {
                    let type_lower = provider.r#type.to_ascii_lowercase();
                    type_to_name
                        .entry(type_lower)
                        .or_insert_with(|| provider.object_name().to_string());
                }
            }
            if providers.len() < limit as usize {
                break;
            }
            offset = offset.saturating_add(limit);
        }
    }

    // ── Explicit provider names ──────────────────────────────────────────
    // If the name exists on the server, use it directly. Otherwise, if the
    // name matches a known provider type, auto-create a provider of that
    // type with the requested name.
    for name in explicit_names {
        if known_names.contains(name) {
            if seen_names.insert(name.clone()) {
                configured_names.push(name.clone());
            }
        } else {
            let profile_id = name.trim();
            let profile = fetch_provider_profile(client, profile_id, workspace)
                .await
                .map_err(|_| {
                    miette::miette!(
                        "provider '{name}' not found and no provider profile named '{profile_id}' is available. \
                         Create or import the profile first, then create the provider"
                    )
                })?;
            let provider_type = profile.id;
            auto_create_provider(
                client,
                &provider_type,
                Some(name),
                auto_providers_override,
                &mut seen_names,
                &mut configured_names,
                workspace,
            )
            .await?;
            // Record the type mapping so the inferred-types pass below
            // doesn't attempt to create a duplicate provider.
            type_to_name
                .entry(provider_type.to_ascii_lowercase())
                .or_insert_with(|| name.clone());
        }
    }

    // ── Resolve inferred provider types ──────────────────────────────────
    if !inferred_types.is_empty() {
        // Collect resolved names for types that already have a provider.
        for t in inferred_types {
            if let Some(name) = type_to_name.get(&t.to_ascii_lowercase())
                && seen_names.insert(name.clone())
            {
                configured_names.push(name.clone());
            }
        }

        let missing = inferred_types
            .iter()
            .filter(|t| !type_to_name.contains_key(&t.to_ascii_lowercase()))
            .cloned()
            .collect::<Vec<_>>();

        for provider_type in missing {
            auto_create_provider(
                client,
                &provider_type,
                None,
                auto_providers_override,
                &mut seen_names,
                &mut configured_names,
                workspace,
            )
            .await?;
        }
    }

    Ok(configured_names)
}

/// Prompt for (or auto-confirm) creation of a provider from local credentials.
///
/// When `preferred_name` is `Some`, the provider is created with that exact
/// name (used for explicit `--provider <name>` values). When `None`, the name
/// defaults to the type and retries with suffixes on conflict (used for
/// inferred provider types).
async fn auto_create_provider(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
    preferred_name: Option<&str>,
    auto_providers_override: Option<bool>,
    seen_names: &mut HashSet<String>,
    configured_names: &mut Vec<String>,
    workspace: &str,
) -> Result<()> {
    eprintln!("Missing provider: {provider_type}");

    // --no-auto-providers: skip silently.
    if auto_providers_override == Some(false) {
        eprintln!(
            "{} Skipping provider '{provider_type}' (--no-auto-providers)",
            "!".yellow(),
        );
        eprintln!();
        return Ok(());
    }

    // No override and non-interactive: error.
    if auto_providers_override.is_none() && !std::io::stdin().is_terminal() {
        return Err(miette::miette!(
            "missing required provider '{provider_type}'. Create it first with \
             `openshell provider create --type {provider_type} --name {provider_type} --from-existing`, \
             pass --auto-providers to auto-create, or set it up manually from inside the sandbox"
        ));
    }

    // --auto-providers: auto-confirm; otherwise prompt.
    let should_create = if auto_providers_override == Some(true) {
        true
    } else {
        Confirm::new()
            .with_prompt("Create from local credentials?")
            .default(true)
            .interact()
            .into_diagnostic()?
    };

    if !should_create {
        eprintln!("{} Skipping provider '{provider_type}'", "!".yellow());
        eprintln!();
        return Ok(());
    }

    let profile = fetch_provider_profile(client, provider_type, workspace).await?;
    let discovered = discover_existing_provider_data(client, provider_type, workspace)
        .await
        .map_err(|err| miette::miette!("failed to discover provider '{provider_type}': {err}"))?;
    let discovered = match discovered {
        Some(discovered) => discovered,
        None if provider_profile_allows_empty_credentials(&profile) => {
            openshell_providers::DiscoveredProvider::default()
        }
        None => {
            return Err(miette::miette!(
                "no existing local credentials found for provider profile '{provider_type}'. \
                 Create it first with `openshell provider create --type {provider_type} --name {provider_type} --credential <KEY>`"
            ));
        }
    };

    if let Some(exact_name) = preferred_name {
        // Explicit name: create with exactly that name, no retries.
        let request = CreateProviderRequest {
            provider: Some(Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: exact_name.to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: workspace.to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: provider_type.to_string(),
                credentials: discovered.credentials.clone(),
                config: discovered.config.clone(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: workspace.to_string(),
                credential_handles: HashMap::new(),
            }),
            workspace: workspace.to_string(),
        };

        let response = client.create_provider(request).await.map_err(|status| {
            miette::miette!("failed to create provider '{exact_name}': {status}")
        })?;
        let provider = response
            .into_inner()
            .provider
            .ok_or_else(|| miette::miette!("provider missing from response"))?;
        eprintln!(
            "{} Created provider {} ({}) from existing local state",
            "✓".green().bold(),
            provider.object_name(),
            provider.r#type
        );
        if seen_names.insert(provider.object_name().to_string()) {
            configured_names.push(provider.object_name().to_string());
        }
    } else {
        // Inferred type: try type as name, then suffixed variants.
        let mut created = false;
        for attempt in 0..5 {
            let name = if attempt == 0 {
                provider_type.to_string()
            } else {
                format!("{provider_type}-{attempt}")
            };

            let request = CreateProviderRequest {
                provider: Some(Provider {
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: name.clone(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        workspace: workspace.to_string(),
                        deletion_timestamp_ms: 0,
                    }),
                    r#type: provider_type.to_string(),
                    credentials: discovered.credentials.clone(),
                    config: discovered.config.clone(),
                    credential_expires_at_ms: HashMap::new(),
                    profile_workspace: workspace.to_string(),
                    credential_handles: HashMap::new(),
                }),
                workspace: workspace.to_string(),
            };

            match client.create_provider(request).await {
                Ok(response) => {
                    let provider = response
                        .into_inner()
                        .provider
                        .ok_or_else(|| miette::miette!("provider missing from response"))?;
                    eprintln!(
                        "{} Created provider {} ({}) from existing local state",
                        "✓".green().bold(),
                        provider.object_name(),
                        provider.r#type
                    );
                    if seen_names.insert(provider.object_name().to_string()) {
                        configured_names.push(provider.object_name().to_string());
                    }
                    created = true;
                    break;
                }
                Err(status) if status.code() == Code::AlreadyExists => {}
                Err(status) => {
                    return Err(miette::miette!(
                        "failed to create provider for type '{provider_type}': {status}"
                    ));
                }
            }
        }

        if !created {
            return Err(miette::miette!(
                "failed to create provider for type '{provider_type}' after name retries"
            ));
        }
    }

    eprintln!();
    Ok(())
}

fn read_gcloud_adc() -> Result<(String, String, String)> {
    let path = if let Some(env_path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .ok()
        .filter(|v| !v.is_empty())
    {
        PathBuf::from(env_path)
    } else if let Some(config_dir) = std::env::var("CLOUDSDK_CONFIG")
        .ok()
        .filter(|v| !v.is_empty())
    {
        PathBuf::from(config_dir).join("application_default_credentials.json")
    } else {
        let home = std::env::var("HOME")
            .map_err(|_| miette::miette!("HOME is not set; cannot locate gcloud ADC file"))?;
        PathBuf::from(home)
            .join(".config")
            .join("gcloud")
            .join("application_default_credentials.json")
    };

    let content = std::fs::read_to_string(&path).map_err(|err| {
        miette::miette!(
            "failed to read gcloud ADC file at {}: {}. \
             Run: gcloud auth application-default login",
            path.display(),
            err
        )
    })?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|err| miette::miette!("failed to parse gcloud ADC file: {err}"))?;

    let cred_type = json.get("type").and_then(|v| v.as_str());
    match cred_type {
        Some("service_account") => {
            return Err(miette::miette!(
                "Application Default Credentials are a service account key, not user credentials. \
                 To use a service account, create the provider with the service account JSON key \
                 and configure gateway-managed refresh for 'GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN'. \
                 See: openshell provider create --help"
            ));
        }
        Some("authorized_user") => {}
        Some(other) => {
            return Err(miette::miette!(
                "Application Default Credentials have unsupported type '{other}' \
                 (expected 'authorized_user'). \
                 Run: gcloud auth application-default login"
            ));
        }
        None => {
            return Err(miette::miette!(
                "gcloud ADC file is missing the 'type' field. \
                 The file may be malformed. \
                 Run: gcloud auth application-default login"
            ));
        }
    }

    let client_id = json
        .get("client_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| miette::miette!("gcloud ADC file is missing 'client_id'"))?
        .to_string();

    let client_secret = json
        .get("client_secret")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| miette::miette!("gcloud ADC file is missing 'client_secret'"))?
        .to_string();

    let refresh_token = json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| miette::miette!("gcloud ADC file is missing 'refresh_token'"))?
        .to_string();

    Ok((client_id, client_secret, refresh_token))
}

async fn rollback_provider_create_after_gcloud_adc_failure(
    client: &mut crate::tls::GrpcClient,
    provider_name: &str,
    stage: &str,
    source: &Status,
    workspace: &str,
) -> Result<()> {
    match client
        .delete_provider(DeleteProviderRequest {
            name: provider_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(_) => Err(miette!(
            "failed to {stage} credentials from gcloud ADC for provider '{provider_name}': {source}. \
             The provider was rolled back successfully."
        )),
        Err(cleanup_err) => {
            eprintln!(
                "{} Failed to clean up provider '{}' after {} failed: {}. \
                 Run 'openshell provider delete {}' to remove it manually.",
                "⚠".yellow(),
                provider_name,
                stage,
                cleanup_err,
                provider_name
            );
            Err(miette!(
                "failed to {stage} credentials from gcloud ADC for provider '{provider_name}': {source}. \
                 Cleanup also failed, so the provider may still exist. \
                 Run 'openshell provider delete {provider_name}' to remove it manually."
            ))
        }
    }
}

async fn fetch_provider_profile(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
    workspace: &str,
) -> Result<ProviderProfile> {
    let requested = provider_type.trim();
    let response = match fetch_provider_profile_exact(client, requested, workspace).await {
        Ok(response) => response,
        Err(status) if status.code() == Code::NotFound => {
            let Some(alias) = normalize_provider_type(requested)
                .filter(|alias| normalize_profile_id(requested).as_deref() != Some(*alias))
            else {
                return Err(miette::miette!(
                    "provider profile '{requested}' not found; import a matching profile before using this provider type"
                ));
            };
            fetch_provider_profile_exact(client, alias, workspace)
                .await
                .map_err(|fallback_status| {
                    if fallback_status.code() == Code::NotFound {
                        miette::miette!(
                            "provider profile '{requested}' not found; import a matching profile before using this provider type"
                        )
                    } else {
                        miette::miette!(fallback_status.to_string())
                    }
                })?
        }
        Err(status) => return Err(miette::miette!(status.to_string())),
    };

    Ok(response)
}

async fn fetch_provider_profile_exact(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
    workspace: &str,
) -> std::result::Result<ProviderProfile, Status> {
    client
        .get_provider_profile(GetProviderProfileRequest {
            id: provider_type.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .and_then(|response| {
            response
                .into_inner()
                .profile
                .ok_or_else(|| Status::internal("provider profile missing from response"))
        })
}

async fn discover_existing_provider_data(
    client: &mut crate::tls::GrpcClient,
    provider_type: &str,
    workspace: &str,
) -> Result<Option<openshell_providers::DiscoveredProvider>> {
    let profile = fetch_provider_profile(client, provider_type, workspace).await?;
    let profile = ProviderTypeProfile::from_proto(&profile);
    let discovered = discover_from_profile(&profile, &RealDiscoveryContext).map_err(|err| {
        miette::miette!("failed to discover existing provider data from profile: {err}")
    })?;

    Ok(discovered)
}

/// Canonical provider type string for Google Vertex AI.
const VERTEX_AI_PROVIDER_TYPE: &str = "google-vertex-ai";

/// Canonical provider type string for Google Cloud (GCP APIs).
const GOOGLE_CLOUD_PROVIDER_TYPE: &str = "google-cloud";

fn missing_credentials_error(provider_type: &str) -> miette::Report {
    if provider_type == VERTEX_AI_PROVIDER_TYPE {
        return miette::miette!(
            "no credentials resolved for provider type '{provider_type}'. \
             Set GOOGLE_VERTEX_AI_TOKEN, VERTEX_AI_TOKEN, \
             GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN, or VERTEX_AI_SERVICE_ACCOUNT_TOKEN; \
             or use --from-gcloud-adc or --from-existing with those env vars set."
        );
    }

    if provider_type == GOOGLE_CLOUD_PROVIDER_TYPE {
        return miette::miette!(
            "no credentials resolved for provider type '{provider_type}'. \
             Set GCP_ADC_ACCESS_TOKEN or GCP_SA_ACCESS_TOKEN; \
             or use --from-gcloud-adc / --from-existing with those env vars set."
        );
    }

    miette::miette!(
        "no credentials resolved for provider type '{provider_type}'. \
         Use --credential KEY[=VALUE], --runtime-credentials for runtime-resolved profile credentials, or --from-existing \
         with the appropriate env vars set."
    )
}

async fn provider_credential_from_oidc_token(
    credentials: &[String],
    profile: Option<&ProviderProfile>,
    tls: &TlsOptions,
) -> Result<(HashMap<String, String>, HashMap<String, i64>)> {
    let credential_key = oidc_subject_credential_key(credentials, profile)?;

    let gateway_name = tls.gateway_name().ok_or_else(|| {
        miette::miette!("--from-oidc-token requires an active named OIDC gateway")
    })?;
    let bundle =
        crate::oidc_auth::ensure_valid_oidc_token_bundle(gateway_name, tls.gateway_insecure)
            .await
            .map_err(|err| {
                miette::miette!(
                    "failed to load or refresh OIDC token for gateway '{gateway_name}' while preparing provider credential: {err}"
                )
            })?;

    let mut credential_map = HashMap::new();
    credential_map.insert(credential_key.clone(), bundle.access_token);

    let mut credential_expires_at_ms = HashMap::new();
    if let Some(expires_at) = bundle.expires_at {
        let expires_at_ms = i64::try_from(expires_at)
            .unwrap_or(i64::MAX / 1000)
            .saturating_mul(1000);
        credential_expires_at_ms.insert(credential_key, expires_at_ms);
    }

    Ok((credential_map, credential_expires_at_ms))
}

fn oidc_subject_credential_key(
    credentials: &[String],
    profile: Option<&ProviderProfile>,
) -> Result<String> {
    if credentials.len() > 1 {
        return Err(miette::miette!(
            "--from-oidc-token accepts at most one --credential KEY destination"
        ));
    }

    if let Some(credential) = credentials.first() {
        let credential = credential.trim();
        if credential.is_empty() || credential.contains('=') {
            return Err(miette::miette!(
                "--from-oidc-token requires --credential KEY without an inline value"
            ));
        }
        if let Some(profile) = profile {
            ensure_profile_declares_subject_credential(profile, credential)?;
        }
        return Ok(credential.to_string());
    }

    let Some(profile) = profile else {
        return Err(miette::miette!(
            "--from-oidc-token requires --credential KEY when the provider profile is unavailable"
        ));
    };

    infer_oidc_subject_credential_from_profile(profile)
}

fn ensure_profile_declares_subject_credential(
    profile: &ProviderProfile,
    credential: &str,
) -> Result<()> {
    let matches = token_exchange_subject_credentials(profile);
    if matches.iter().any(|candidate| candidate == credential) {
        return Ok(());
    }
    Err(miette::miette!(
        "credential '{credential}' is not declared as a token-exchange subject credential in provider profile '{}'; expected one of: {}",
        profile.id,
        matches.join(", ")
    ))
}

fn infer_oidc_subject_credential_from_profile(profile: &ProviderProfile) -> Result<String> {
    let matches = token_exchange_subject_credentials(profile);
    match matches.as_slice() {
        [credential] => Ok(credential.clone()),
        [] => Err(miette::miette!(
            "provider profile '{}' does not declare a token-exchange subject credential; pass --credential KEY",
            profile.id
        )),
        _ => Err(miette::miette!(
            "provider profile '{}' declares multiple token-exchange subject credentials ({}); pass --credential KEY",
            profile.id,
            matches.join(", ")
        )),
    }
}

fn token_exchange_subject_credentials(profile: &ProviderProfile) -> Vec<String> {
    let mut matches = Vec::new();
    for credential in &profile.credentials {
        let Some(token_grant) = credential.token_grant.as_ref() else {
            continue;
        };
        if ProviderCredentialTokenGrantType::try_from(token_grant.grant_type).ok()
            != Some(ProviderCredentialTokenGrantType::TokenExchange)
        {
            continue;
        }
        let Some(subject_token) = token_grant.subject_token.as_ref() else {
            continue;
        };
        if subject_token.source != "provider_credential" || subject_token.credential.is_empty() {
            continue;
        }
        if !matches.contains(&subject_token.credential) {
            matches.push(subject_token.credential.clone());
        }
    }
    matches
}

#[allow(clippy::too_many_arguments)]
pub async fn provider_create(
    server: &str,
    name: &str,
    provider_type: &str,
    from_existing: bool,
    credentials: &[String],
    from_gcloud_adc: bool,
    config: &[String],
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let credential_source = match (from_existing, from_gcloud_adc) {
        (true, true) => {
            return Err(miette::miette!(
                "--from-gcloud-adc cannot be combined with --from-existing, --from-oidc-token, or --credential; it also cannot be combined with --runtime-credentials"
            ));
        }
        (true, false) => ProviderCreateCredentialSource::Existing,
        (false, true) => ProviderCreateCredentialSource::GcloudAdc,
        (false, false) => ProviderCreateCredentialSource::ExplicitCredentials,
    };
    provider_create_with_options(ProviderCreateOptions {
        server,
        name,
        provider_type,
        credentials,
        credential_source,
        config,
        workspace,
        profile_workspace: workspace,
        tls,
    })
    .await
}

pub struct ProviderCreateOptions<'a> {
    pub server: &'a str,
    pub name: &'a str,
    pub provider_type: &'a str,
    pub credentials: &'a [String],
    pub credential_source: ProviderCreateCredentialSource,
    pub config: &'a [String],
    pub workspace: &'a str,
    pub profile_workspace: &'a str,
    pub tls: &'a TlsOptions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCreateCredentialSource {
    ExplicitCredentials,
    Existing,
    GcloudAdc,
    OidcToken,
    Runtime,
}

pub async fn provider_create_with_options(options: ProviderCreateOptions<'_>) -> Result<()> {
    let ProviderCreateOptions {
        server,
        name,
        provider_type,
        credentials,
        credential_source,
        config,
        workspace,
        profile_workspace,
        tls,
    } = options;

    let from_existing = credential_source == ProviderCreateCredentialSource::Existing;
    let from_gcloud_adc = credential_source == ProviderCreateCredentialSource::GcloudAdc;
    let from_oidc_token = credential_source == ProviderCreateCredentialSource::OidcToken;
    let runtime_credentials = credential_source == ProviderCreateCredentialSource::Runtime;

    if from_gcloud_adc && !credentials.is_empty() {
        return Err(miette::miette!(
            "--from-gcloud-adc cannot be combined with --from-existing, --from-oidc-token, or --credential; it also cannot be combined with --runtime-credentials"
        ));
    }
    if from_existing && !credentials.is_empty() {
        return Err(miette::miette!(
            "--from-existing cannot be combined with --credential"
        ));
    }
    if runtime_credentials && !credentials.is_empty() {
        return Err(miette::miette!(
            "--runtime-credentials cannot be combined with --credential"
        ));
    }

    let mut client = grpc_client(server, tls).await?;

    let profile_id = provider_type.trim();
    if profile_id.is_empty() {
        return Err(miette::miette!("provider type is required"));
    }
    let provider_profile = fetch_provider_profile(&mut client, profile_id, profile_workspace)
        .await
        .map_err(|err| {
            miette::miette!("unsupported provider type or profile: {profile_id} ({err})")
        })?;
    let provider_type = provider_profile.id.clone();

    let adc_credential_key = if from_gcloud_adc {
        let profile = ProviderTypeProfile::from_proto(&provider_profile);
        let adc_cred = profile.adc_credential().ok_or_else(|| {
            miette::miette!(
                "--from-gcloud-adc is not supported for '{provider_type}' providers \
                 (no ADC-compatible credential in the provider profile)"
            )
        })?;
        Some(
            adc_cred
                .env_vars
                .first()
                .ok_or_else(|| {
                    miette::miette!(
                        "ADC credential in '{provider_type}' profile has no env_vars declared"
                    )
                })?
                .clone(),
        )
    } else {
        None
    };

    let oidc_profile = if from_oidc_token {
        Some(provider_profile.clone())
    } else {
        None
    };

    let (mut credential_map, oidc_credential_expires_at_ms) = if from_oidc_token {
        provider_credential_from_oidc_token(credentials, oidc_profile.as_ref(), tls).await?
    } else {
        (parse_credential_pairs(credentials)?, HashMap::new())
    };
    let mut config_map = parse_key_value_pairs(config, "--config")?;

    if from_existing {
        let discovered =
            discover_existing_provider_data(&mut client, &provider_type, profile_workspace).await?;
        let Some(discovered) = discovered else {
            return Err(miette::miette!(
                "no existing local credentials/config found for provider type '{provider_type}'"
            ));
        };

        for (key, value) in discovered.credentials {
            credential_map.entry(key).or_insert(value);
        }
        for (key, value) in discovered.config {
            config_map.entry(key).or_insert(value);
        }
    }

    if credential_map.is_empty() {
        if from_existing {
            return Err(missing_credentials_error(&provider_type));
        }
        if runtime_credentials && !provider_profile_allows_runtime_credentials(&provider_profile) {
            return Err(miette::miette!(
                "--runtime-credentials is only valid for provider profiles whose required credentials are resolved at runtime"
            ));
        }
        if !provider_profile_allows_empty_credentials(&provider_profile) {
            return Err(missing_credentials_error(&provider_type));
        }
    }

    // Validate and read the ADC file BEFORE creating the provider so that
    // a bad/missing ADC does not leave an orphan provider behind. Bundle the
    // credential key with the material so they stay coupled.
    let gcloud_adc_bootstrap = if from_gcloud_adc {
        let (client_id, client_secret, refresh_token) = read_gcloud_adc()?;
        let key = adc_credential_key.expect("set when from_gcloud_adc is true");
        Some((key, client_id, client_secret, refresh_token))
    } else {
        None
    };

    let response = client
        .create_provider(CreateProviderRequest {
            provider: Some(Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: name.to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: workspace.to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: provider_type.clone(),
                credentials: credential_map,
                config: config_map,
                credential_expires_at_ms: oidc_credential_expires_at_ms,
                profile_workspace: profile_workspace.to_string(),
                credential_handles: HashMap::new(),
            }),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;
    let provider_name = provider.object_name().to_string();

    if let Some((adc_credential_key, client_id, client_secret, refresh_token)) =
        gcloud_adc_bootstrap
    {
        let mut material = HashMap::new();
        material.insert("client_id".to_string(), client_id);
        material.insert("client_secret".to_string(), client_secret);
        material.insert("refresh_token".to_string(), refresh_token);

        if let Err(configure_err) = client
            .configure_provider_refresh(ConfigureProviderRefreshRequest {
                provider: provider_name.clone(),
                credential_key: adc_credential_key.clone(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                material,
                secret_material_keys: vec![
                    "client_secret".to_string(),
                    "refresh_token".to_string(),
                ],
                expires_at_ms: None,
                workspace: workspace.to_string(),
            })
            .await
        {
            return rollback_provider_create_after_gcloud_adc_failure(
                &mut client,
                &provider_name,
                "configure",
                &configure_err,
                workspace,
            )
            .await;
        }

        if let Err(rotate_err) = client
            .rotate_provider_credential(RotateProviderCredentialRequest {
                provider: provider_name.clone(),
                credential_key: adc_credential_key,
                workspace: workspace.to_string(),
            })
            .await
        {
            return rollback_provider_create_after_gcloud_adc_failure(
                &mut client,
                &provider_name,
                "mint the initial access token for",
                &rotate_err,
                workspace,
            )
            .await;
        }

        println!("{} Created provider {}", "✓".green().bold(), provider_name);
        println!("Configured GCP credentials from gcloud ADC and minted the initial access token");
        return Ok(());
    }

    println!("{} Created provider {}", "✓".green().bold(), provider_name);
    Ok(())
}

fn provider_profile_allows_empty_credentials(profile: &ProviderProfile) -> bool {
    ProviderTypeProfile::from_proto(profile).allows_empty_provider_credentials()
}

fn provider_profile_allows_runtime_credentials(profile: &ProviderProfile) -> bool {
    ProviderTypeProfile::from_proto(profile).allows_runtime_provider_credentials()
}

pub async fn provider_get(
    server: &str,
    name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_provider(GetProviderRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;

    let credential_keys = provider_credential_keys(&provider);
    let config_keys = provider.config.keys().cloned().collect::<Vec<_>>();

    println!("{}", "Provider:".cyan().bold());
    println!();
    println!("  {} {}", "Id:".dimmed(), provider.object_id());
    println!("  {} {}", "Name:".dimmed(), provider.object_name());
    println!("  {} {}", "Type:".dimmed(), provider.r#type);
    println!(
        "  {} {}",
        "Resource version:".dimmed(),
        provider.metadata.as_ref().map_or(0, |m| m.resource_version)
    );
    println!(
        "  {} {}",
        "Credential keys:".dimmed(),
        if credential_keys.is_empty() {
            "<none>".to_string()
        } else {
            credential_keys.join(", ")
        }
    );
    println!(
        "  {} {}",
        "Config keys:".dimmed(),
        if config_keys.is_empty() {
            "<none>".to_string()
        } else {
            config_keys.join(", ")
        }
    );

    Ok(())
}

fn provider_to_json(provider: &Provider) -> serde_json::Value {
    let mut obj = serde_json::Map::new();

    // Core fields
    obj.insert("id".to_string(), serde_json::json!(provider.object_id()));
    obj.insert(
        "name".to_string(),
        serde_json::json!(provider.object_name()),
    );
    obj.insert(
        "workspace".to_string(),
        serde_json::json!(provider.object_workspace()),
    );
    obj.insert("type".to_string(), serde_json::json!(provider.r#type));

    // Credential keys (NEVER values - security)
    let credential_keys = provider_credential_keys(provider);
    obj.insert(
        "credential_keys".to_string(),
        serde_json::json!(credential_keys),
    );

    // Config keys (keys only, not values)
    if !provider.config.is_empty() {
        let config_keys: Vec<String> = provider.config.keys().cloned().collect();
        obj.insert("config_keys".to_string(), serde_json::json!(config_keys));
    }

    // Metadata fields (only if metadata exists)
    if let Some(meta) = &provider.metadata {
        if !meta.labels.is_empty() {
            obj.insert("labels".to_string(), serde_json::json!(meta.labels));
        }
        if meta.resource_version != 0 {
            obj.insert(
                "resource_version".to_string(),
                serde_json::json!(meta.resource_version),
            );
        }
        if meta.created_at_ms != 0 {
            obj.insert(
                "created_at".to_string(),
                serde_json::json!(format_epoch_ms(meta.created_at_ms)),
            );
        }
    }

    // Credential expiration times (only if present)
    if !provider.credential_expires_at_ms.is_empty() {
        obj.insert(
            "credential_expires_at_ms".to_string(),
            serde_json::json!(provider.credential_expires_at_ms),
        );
    }

    serde_json::Value::Object(obj)
}

fn provider_credential_keys(provider: &Provider) -> Vec<String> {
    let mut keys: Vec<String> = provider
        .credentials
        .keys()
        .chain(provider.credential_handles.keys())
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

#[allow(clippy::too_many_arguments)]
pub async fn provider_list(
    server: &str,
    limit: u32,
    offset: u32,
    names_only: bool,
    output: &str,
    workspace: &str,
    all_workspaces: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_providers(ListProvidersRequest {
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
        .into_diagnostic()?;
    let providers = response.into_inner().providers;

    // Handle structured output formats (json, yaml)
    if crate::output::print_output_collection(output, &providers, provider_to_json)? {
        return Ok(());
    }

    if providers.is_empty() {
        if !names_only {
            println!("No providers found.");
        }
        return Ok(());
    }

    if names_only {
        for provider in &providers {
            if all_workspaces {
                println!("{}/{}", provider.object_workspace(), provider.object_name());
            } else {
                println!("{}", provider.object_name());
            }
        }
        return Ok(());
    }

    let ws_width = if all_workspaces {
        providers
            .iter()
            .map(|p| p.object_workspace().len())
            .max()
            .unwrap_or(9)
            .max(9)
    } else {
        0
    };
    let name_width = providers
        .iter()
        .map(|provider| provider.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let type_width = providers
        .iter()
        .map(|provider| provider.r#type.len())
        .max()
        .unwrap_or(4)
        .max(4);

    if all_workspaces {
        println!(
            "{:<ws_width$}  {:<name_width$}  {:<type_width$}  {:<16}  {}",
            "WORKSPACE".bold(),
            "NAME".bold(),
            "TYPE".bold(),
            "CREDENTIAL_KEYS".bold(),
            "CONFIG_KEYS".bold(),
        );
    } else {
        println!(
            "{:<name_width$}  {:<type_width$}  {:<16}  {}",
            "NAME".bold(),
            "TYPE".bold(),
            "CREDENTIAL_KEYS".bold(),
            "CONFIG_KEYS".bold(),
        );
    }

    for provider in providers {
        if all_workspaces {
            println!(
                "{:<ws_width$}  {:<name_width$}  {:<type_width$}  {:<16}  {}",
                provider.object_workspace(),
                provider.object_name().to_string(),
                provider.r#type,
                provider.credentials.len(),
                provider.config.len(),
            );
        } else {
            println!(
                "{:<name_width$}  {:<type_width$}  {:<16}  {}",
                provider.object_name().to_string(),
                provider.r#type,
                provider.credentials.len(),
                provider.config.len(),
            );
        }
    }

    Ok(())
}

pub async fn provider_list_profiles(
    server: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_provider_profiles(ListProviderProfilesRequest {
            limit: 100,
            offset: 0,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;
    let mut profiles = response.into_inner().profiles;
    profiles.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.id.cmp(&right.id))
    });
    let dto_profiles = profiles
        .iter()
        .map(ProviderTypeProfile::from_proto)
        .collect::<Vec<_>>();

    if crate::output::print_output_direct(
        output,
        || profiles_to_json(&dto_profiles).into_diagnostic(),
        || profiles_to_yaml(&dto_profiles).into_diagnostic(),
    )? {
        return Ok(());
    }

    if profiles.is_empty() {
        println!("No provider profiles found.");
        return Ok(());
    }

    println!("{}", "Available Provider Profiles:".cyan().bold());
    let id_width = provider_profile_id_width(&profiles);
    let display_width = provider_profile_display_width(&profiles);
    let source_width = provider_profile_source_width(&profiles);
    let scope_width = provider_profile_scope_width(&profiles);
    let mut current_category = i32::MIN;
    for profile in &profiles {
        if profile.category != current_category {
            current_category = profile.category;
            println!();
            println!("  {}", display_provider_category(current_category).bold());
            print_provider_type_header(id_width, scope_width, source_width, display_width);
        }
        print_provider_type_row(profile, id_width, scope_width, source_width, display_width);
    }

    Ok(())
}

pub async fn provider_profile_export(
    server: &str,
    id: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let rendered = provider_profile_export_text(server, id, output, workspace, tls).await?;
    if output == "json" {
        println!("{rendered}");
    } else {
        print!("{rendered}");
    }
    Ok(())
}

pub async fn provider_profile_export_text(
    server: &str,
    id: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<String> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_provider_profile(GetProviderProfileRequest {
            id: id.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;
    let profile = response
        .into_inner()
        .profile
        .ok_or_else(|| miette!("provider profile '{id}' not found"))?;
    let profile = ProviderTypeProfile::from_proto(&profile);

    match output {
        "json" => profile_to_json(&profile).into_diagnostic(),
        "yaml" => profile_to_yaml(&profile).into_diagnostic(),
        "table" => Err(miette!(
            "profile export supports '-o yaml' and '-o json'; table output is not supported"
        )),
        _ => Err(miette!("unsupported output format: {output}")),
    }
}

pub async fn provider_profile_import(
    server: &str,
    file: Option<&Path>,
    from: Option<&Path>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let (items, mut diagnostics) = load_profile_import_items(file, from)?;
    if items.is_empty() && diagnostics.is_empty() {
        return Err(miette!("no provider profile files found"));
    }
    if profile_diagnostics_have_errors(&diagnostics) {
        print_profile_diagnostics(&diagnostics);
        return Err(miette!("provider profile import failed"));
    }

    let mut client = grpc_client(server, tls).await?;
    if !items.is_empty() {
        let response = client
            .import_provider_profiles(ImportProviderProfilesRequest {
                profiles: items,
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?
            .into_inner();
        diagnostics.extend(response.diagnostics);
        if response.imported {
            println!(
                "Imported {} provider profile{}.",
                response.profiles.len(),
                if response.profiles.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
            return Ok(());
        }
    }

    print_profile_diagnostics(&diagnostics);
    Err(miette!("provider profile import failed"))
}

pub async fn provider_profile_update(
    server: &str,
    id: &str,
    file: &Path,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let (mut items, mut diagnostics) = load_profile_import_items(Some(file), None)?;
    if items.is_empty() && diagnostics.is_empty() {
        return Err(miette!("no provider profile files found"));
    }
    if profile_diagnostics_have_errors(&diagnostics) {
        print_profile_diagnostics(&diagnostics);
        return Err(miette!("provider profile update failed"));
    }

    let mut client = grpc_client(server, tls).await?;
    if let Some(item) = items.pop() {
        let expected_resource_version = item
            .profile
            .as_ref()
            .map_or(0, |profile| profile.resource_version);
        let response = client
            .update_provider_profiles(UpdateProviderProfilesRequest {
                profile: Some(item),
                expected_resource_version,
                id: id.to_string(),
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?
            .into_inner();
        diagnostics.extend(response.diagnostics);
        if response.updated {
            println!("Updated provider profile.");
            return Ok(());
        }
    }

    print_profile_diagnostics(&diagnostics);
    Err(miette!("provider profile update failed"))
}

pub async fn provider_profile_lint(
    server: &str,
    file: Option<&Path>,
    from: Option<&Path>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let (items, mut diagnostics) = load_profile_import_items(file, from)?;
    if items.is_empty() && diagnostics.is_empty() {
        return Err(miette!("no provider profile files found"));
    }

    if !items.is_empty() {
        let mut client = grpc_client(server, tls).await?;
        let response = client
            .lint_provider_profiles(LintProviderProfilesRequest {
                profiles: items,
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?
            .into_inner();
        diagnostics.extend(response.diagnostics);
    }

    if profile_diagnostics_have_errors(&diagnostics) {
        print_profile_diagnostics(&diagnostics);
        return Err(miette!("provider profile lint failed"));
    }

    println!("Provider profile lint passed.");
    Ok(())
}

pub async fn provider_profile_delete(
    server: &str,
    ids: &[String],
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let mut failures = Vec::new();
    for id in ids {
        let response = match client
            .delete_provider_profile(DeleteProviderProfileRequest {
                id: id.clone(),
                workspace: workspace.to_string(),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) => {
                eprintln!(
                    "{} Failed to delete provider profile {id}: {status}",
                    "!".red().bold()
                );
                failures.push(id.clone());
                continue;
            }
        };
        if response.deleted {
            println!("{} Deleted provider profile {id}", "✓".green().bold());
        } else {
            println!("{} Provider profile {id} not found", "!".yellow());
        }
    }
    aggregate_delete_failures("provider profile", &failures)
}

pub async fn provider_refresh_status(
    server: &str,
    name: &str,
    credential_key: Option<&str>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_provider_refresh_status(GetProviderRefreshStatusRequest {
            provider: name.to_string(),
            credential_key: credential_key.unwrap_or_default().to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.credentials.is_empty() {
        if let Some(credential_key) = credential_key {
            println!(
                "No refresh configuration found for provider '{name}' credential '{credential_key}'."
            );
        } else {
            println!("No refresh configurations found for provider '{name}'.");
        }
        return Ok(());
    }

    println!("{}", refresh_status_header());
    for status in response.credentials {
        print_refresh_status_row(&status);
    }
    Ok(())
}

fn refresh_status_header() -> String {
    format!(
        "{:<24}  {:<28}  {:<28}  {:<24}  {:<18}  {:<20}  {:<20}  {:<20}  {:<44}  {}",
        "PROVIDER".bold(),
        "CREDENTIAL_KEY".bold(),
        "STRATEGY".bold(),
        "STATUS".bold(),
        "RECOVERY".bold(),
        "EXPIRES_AT".bold(),
        "NEXT_REFRESH".bold(),
        "LAST_REFRESH".bold(),
        "FAILURE_CODE".bold(),
        "LAST_ERROR".bold(),
    )
}

pub struct ProviderRefreshConfigInput<'a> {
    pub name: &'a str,
    pub credential_key: &'a str,
    pub strategy: &'a str,
    pub material: &'a [String],
    pub secret_material_env: &'a [String],
    pub secret_material_keys: &'a [String],
    pub credential_expires_at_ms: Option<i64>,
}

pub async fn provider_refresh_config(
    server: &str,
    input: ProviderRefreshConfigInput<'_>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let strategy = provider_refresh_strategy(input.strategy)?;
    let mut material = parse_key_value_pairs(input.material, "--material")?;
    let mut secret_material_keys = input.secret_material_keys.to_vec();
    // Env-resolved secrets are auto-marked secret; duplicate keys are an
    // error rather than a precedence order.
    for (key, value) in parse_secret_material_env_pairs(input.secret_material_env)? {
        if material.contains_key(&key) {
            return Err(miette!(
                "duplicate material key '{key}': supplied via both --material and --secret-material-env"
            ));
        }
        if !secret_material_keys.contains(&key) {
            secret_material_keys.push(key.clone());
        }
        material.insert(key, value);
    }
    let mut client = grpc_client(server, tls).await?;
    let status = client
        .configure_provider_refresh(ConfigureProviderRefreshRequest {
            provider: input.name.to_string(),
            credential_key: input.credential_key.to_string(),
            strategy: strategy as i32,
            material,
            secret_material_keys,
            expires_at_ms: input.credential_expires_at_ms,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .status
        .ok_or_else(|| miette!("provider refresh status missing from response"))?;

    println!(
        "{} Configured refresh for {} {}",
        "✓".green().bold(),
        status.provider_name,
        status.credential_key
    );
    Ok(())
}

pub async fn provider_rotate(
    server: &str,
    name: &str,
    credential_key: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let status = client
        .rotate_provider_credential(RotateProviderCredentialRequest {
            provider: name.to_string(),
            credential_key: credential_key.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .status
        .ok_or_else(|| miette!("provider refresh status missing from response"))?;

    if status.last_error.is_empty() {
        println!(
            "{} Rotation requested for {} {} ({})",
            "✓".green().bold(),
            status.provider_name,
            status.credential_key,
            status.status
        );
    } else {
        println!(
            "Rotation request recorded for {} {} ({}): {}",
            status.provider_name, status.credential_key, status.status, status.last_error
        );
    }
    Ok(())
}

pub async fn provider_refresh_delete(
    server: &str,
    name: &str,
    credential_key: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .delete_provider_refresh(DeleteProviderRefreshRequest {
            provider: name.to_string(),
            credential_key: credential_key.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted refresh config for {} {}",
            "✓".green().bold(),
            name,
            credential_key
        );
    } else {
        println!("No refresh config found for provider '{name}' credential '{credential_key}'.");
    }
    Ok(())
}

fn provider_refresh_strategy(strategy: &str) -> Result<ProviderCredentialRefreshStrategy> {
    match strategy {
        "oauth2_refresh_token" => Ok(ProviderCredentialRefreshStrategy::Oauth2RefreshToken),
        "oauth2_client_credentials" => {
            Ok(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials)
        }
        "google_service_account_jwt" => {
            Ok(ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt)
        }
        "aws_sts_assume_role" => Ok(ProviderCredentialRefreshStrategy::AwsStsAssumeRole),
        _ => Err(miette!("unsupported provider refresh strategy: {strategy}")),
    }
}

fn print_refresh_status_row(status: &ProviderCredentialRefreshStatus) {
    println!("{}", refresh_status_row(status));
}

fn refresh_status_row(status: &ProviderCredentialRefreshStatus) -> String {
    let strategy = ProviderCredentialRefreshStrategy::try_from(status.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    let recovery_action = ProviderCredentialRefreshRecoveryAction::try_from(status.recovery_action)
        .unwrap_or(ProviderCredentialRefreshRecoveryAction::Unspecified);
    format!(
        "{:<24}  {:<28}  {:<28}  {:<24}  {:<18}  {:<20}  {:<20}  {:<20}  {:<44}  {}",
        status.provider_name,
        status.credential_key,
        provider_refresh_strategy_name(strategy),
        status.status,
        provider_refresh_recovery_action_name(recovery_action),
        format_optional_epoch_ms(status.expires_at_ms),
        format_refresh_next_at_ms(status.next_refresh_at_ms),
        format_optional_epoch_ms(status.last_refresh_at_ms),
        status.failure_code,
        truncate_status_field(&status.last_error, 72),
    )
}

fn format_refresh_next_at_ms(next_refresh_at_ms: i64) -> String {
    if next_refresh_at_ms == i64::MAX {
        "-".to_string()
    } else {
        format_optional_epoch_ms(next_refresh_at_ms)
    }
}

fn provider_refresh_recovery_action_name(
    action: ProviderCredentialRefreshRecoveryAction,
) -> &'static str {
    match action {
        ProviderCredentialRefreshRecoveryAction::Retry => "retry",
        ProviderCredentialRefreshRecoveryAction::Reauthorize => "reauthorize",
        ProviderCredentialRefreshRecoveryAction::FixConfiguration => "fix_configuration",
        ProviderCredentialRefreshRecoveryAction::Investigate => "investigate",
        ProviderCredentialRefreshRecoveryAction::Unspecified => "-",
    }
}

fn provider_refresh_strategy_name(strategy: ProviderCredentialRefreshStrategy) -> &'static str {
    match strategy {
        ProviderCredentialRefreshStrategy::Static => "static",
        ProviderCredentialRefreshStrategy::External => "external",
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => "oauth2_refresh_token",
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => "oauth2_client_credentials",
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => "google_service_account_jwt",
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => "aws_sts_assume_role",
        ProviderCredentialRefreshStrategy::Unspecified => "unspecified",
    }
}

fn load_profile_import_items(
    file: Option<&Path>,
    from: Option<&Path>,
) -> Result<(
    Vec<ProviderProfileImportItem>,
    Vec<ProviderProfileDiagnostic>,
)> {
    let paths = profile_source_paths(file, from)?;
    let mut items = Vec::new();
    let mut diagnostics = Vec::new();
    for path in paths {
        match load_profile_import_item(&path) {
            Ok(item) => items.push(item),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }
    Ok((items, diagnostics))
}

fn profile_source_paths(file: Option<&Path>, from: Option<&Path>) -> Result<Vec<PathBuf>> {
    if let Some(file) = file {
        return Ok(vec![file.to_path_buf()]);
    }
    let Some(from) = from else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(from)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read profile directory {}", from.display()))?
    {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        if path.is_file() && profile_extension_supported(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn profile_extension_supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yaml" | "yml" | "json")
    )
}

fn load_profile_import_item(
    path: &Path,
) -> Result<ProviderProfileImportItem, ProviderProfileDiagnostic> {
    let source = path.display().to_string();
    let input = std::fs::read_to_string(path).map_err(|err| {
        profile_file_diagnostic(
            &source,
            format!("failed to read provider profile file: {err}"),
        )
    })?;
    let profile = match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml" | "yml") => parse_profile_yaml(&input),
        Some("json") => parse_profile_json(&input),
        _ => {
            return Err(profile_file_diagnostic(
                &source,
                "unsupported provider profile file format".to_string(),
            ));
        }
    }
    .map_err(|err| profile_file_diagnostic(&source, err.to_string()))?;

    let pre_lower = profile.validate_before_lowering(&source);
    if let Some(diag) = pre_lower.into_iter().find(|d| d.severity == "error") {
        return Err(ProviderProfileDiagnostic {
            source: diag.source,
            profile_id: diag.profile_id,
            field: diag.field,
            message: diag.message,
            severity: diag.severity,
        });
    }

    Ok(ProviderProfileImportItem {
        profile: Some(profile.to_proto()),
        source,
    })
}

fn profile_file_diagnostic(source: &str, message: String) -> ProviderProfileDiagnostic {
    ProviderProfileDiagnostic {
        source: source.to_string(),
        profile_id: String::new(),
        field: "file".to_string(),
        message,
        severity: "error".to_string(),
    }
}

fn print_profile_diagnostics(diagnostics: &[ProviderProfileDiagnostic]) {
    if diagnostics.is_empty() {
        return;
    }
    eprintln!("{}", "Provider profile diagnostics:".red().bold());
    for diagnostic in diagnostics {
        let source = if diagnostic.source.is_empty() {
            "<input>"
        } else {
            &diagnostic.source
        };
        let profile = if diagnostic.profile_id.is_empty() {
            "-".to_string()
        } else {
            diagnostic.profile_id.clone()
        };
        eprintln!(
            "  {} {} profile={} field={} {}",
            diagnostic.severity.as_str().red(),
            source,
            profile,
            diagnostic.field,
            diagnostic.message
        );
    }
}

fn profile_diagnostics_have_errors(diagnostics: &[ProviderProfileDiagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "error")
}

fn display_provider_category(category: i32) -> &'static str {
    match ProviderProfileCategory::try_from(category).unwrap_or(ProviderProfileCategory::Other) {
        ProviderProfileCategory::Inference => "INFERENCE",
        ProviderProfileCategory::Agent => "AGENT",
        ProviderProfileCategory::SourceControl => "SOURCE CONTROL",
        ProviderProfileCategory::Messaging => "MESSAGING",
        ProviderProfileCategory::Data => "DATA",
        ProviderProfileCategory::Knowledge => "KNOWLEDGE",
        ProviderProfileCategory::Other | ProviderProfileCategory::Unspecified => "OTHER",
    }
}

const PROVIDER_PROFILE_ID_MAX_WIDTH: usize = 32;
const PROVIDER_PROFILE_DISPLAY_MAX_WIDTH: usize = 40;
const PROVIDER_PROFILE_SOURCE_MAX_WIDTH: usize = 24;

fn provider_profile_id_width(profiles: &[ProviderProfile]) -> usize {
    profiles
        .iter()
        .map(|profile| {
            profile
                .id
                .chars()
                .count()
                .min(PROVIDER_PROFILE_ID_MAX_WIDTH)
        })
        .max()
        .unwrap_or(2)
        .max(2)
}

fn provider_profile_display_width(profiles: &[ProviderProfile]) -> usize {
    profiles
        .iter()
        .map(|profile| {
            profile
                .display_name
                .chars()
                .count()
                .min(PROVIDER_PROFILE_DISPLAY_MAX_WIDTH)
        })
        .max()
        .unwrap_or(4)
        .max(4)
}

fn provider_profile_scope_width(profiles: &[ProviderProfile]) -> usize {
    profiles
        .iter()
        .map(|profile| profile.scope.chars().count())
        .max()
        .unwrap_or(5)
        .max(5)
}

fn provider_profile_source_width(profiles: &[ProviderProfile]) -> usize {
    profiles
        .iter()
        .map(|profile| {
            profile
                .source
                .chars()
                .count()
                .min(PROVIDER_PROFILE_SOURCE_MAX_WIDTH)
        })
        .max()
        .unwrap_or(6)
        .max(6)
}

fn print_provider_type_header(
    id_width: usize,
    scope_width: usize,
    source_width: usize,
    display_width: usize,
) {
    let endpoints = "ENDPOINTS";
    println!(
        "    {:<id_width$}  {:<scope_width$}  {:<source_width$}  {:<display_width$}  {endpoints}",
        "ID", "SCOPE", "SOURCE", "NAME"
    );
}

fn print_provider_type_row(
    profile: &ProviderProfile,
    id_width: usize,
    scope_width: usize,
    source_width: usize,
    display_width: usize,
) {
    let inference = if profile.inference_capable {
        " inference"
    } else {
        ""
    };
    let id = truncate_display(&profile.id, PROVIDER_PROFILE_ID_MAX_WIDTH);
    let scope = &profile.scope;
    let source = truncate_display(&profile.source, PROVIDER_PROFILE_SOURCE_MAX_WIDTH);
    let display_name = truncate_display(&profile.display_name, PROVIDER_PROFILE_DISPLAY_MAX_WIDTH);
    println!(
        "    {id:<id_width$}  {scope:<scope_width$}  {source:<source_width$}  {display_name:<display_width$}  {:<2}{}",
        profile.endpoints.len(),
        inference
    );
}

pub struct ProviderUpdateOptions<'a> {
    pub server: &'a str,
    pub name: &'a str,
    pub from_existing: bool,
    pub from_oidc_token: bool,
    pub credentials: &'a [String],
    pub config: &'a [String],
    pub credential_expires_at: &'a [String],
    pub workspace: &'a str,
    pub tls: &'a TlsOptions,
}

pub async fn provider_update(options: ProviderUpdateOptions<'_>) -> Result<()> {
    let ProviderUpdateOptions {
        server,
        name,
        from_existing,
        from_oidc_token,
        credentials,
        config,
        credential_expires_at,
        workspace,
        tls,
    } = options;

    if from_existing && !credentials.is_empty() {
        return Err(miette::miette!(
            "--from-existing cannot be combined with --credential"
        ));
    }
    if from_existing && from_oidc_token {
        return Err(miette::miette!(
            "--from-existing cannot be combined with --from-oidc-token"
        ));
    }

    let mut client = grpc_client(server, tls).await?;

    // Look up the stored provider so the update can carry its type and profile
    // workspace. Policy interceptors evaluate the request before the gateway
    // merges it with stored state, so an update that omits them cannot be
    // authorized against the profile that owns the provider.
    //
    // The read is best-effort. A caller holding `provider:write` without
    // `provider:read` must still be able to rotate credentials, so a denied
    // read keeps the previous behavior of sending empty metadata rather than
    // failing the update. `--from-existing` and `--from-oidc-token` need the
    // stored type, so they surface the error instead.
    let existing = match client
        .get_provider(GetProviderRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => response.into_inner().provider,
        Err(status)
            if status.code() == Code::PermissionDenied && !from_existing && !from_oidc_token =>
        {
            None
        }
        Err(status) => return Err(status).into_diagnostic(),
    };

    if existing.is_none() && (from_existing || from_oidc_token) {
        return Err(miette::miette!("provider '{name}' not found"));
    }

    let oidc_profile = if from_oidc_token {
        let existing = existing.as_ref().expect("checked above");
        Some(
            fetch_provider_profile(&mut client, &existing.r#type, &existing.profile_workspace)
                .await?,
        )
    } else {
        None
    };

    let (mut credential_map, oidc_credential_expires_at_ms) = if from_oidc_token {
        provider_credential_from_oidc_token(credentials, oidc_profile.as_ref(), tls).await?
    } else {
        (parse_credential_pairs(credentials)?, HashMap::new())
    };
    let mut config_map = parse_key_value_pairs(config, "--config")?;
    let mut credential_expires_at_ms = parse_credential_expiry_pairs(credential_expires_at)?;
    credential_expires_at_ms.extend(oidc_credential_expires_at_ms);

    if from_existing {
        let stored = existing.as_ref().expect("checked above");
        let provider_type = stored.r#type.clone();
        let discovered =
            discover_existing_provider_data(&mut client, &provider_type, &stored.profile_workspace)
                .await?;
        let Some(discovered) = discovered else {
            return Err(miette::miette!(
                "no existing local credentials/config found for provider type '{provider_type}'"
            ));
        };

        for (key, value) in discovered.credentials {
            credential_map.entry(key).or_insert(value);
        }
        for (key, value) in discovered.config {
            config_map.entry(key).or_insert(value);
        }
    }

    let response = client
        .update_provider(UpdateProviderRequest {
            provider: Some(Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: name.to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: workspace.to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: existing
                    .as_ref()
                    .map(|provider| provider.r#type.clone())
                    .unwrap_or_default(),
                credentials: credential_map,
                config: config_map,
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: existing
                    .as_ref()
                    .map(|provider| provider.profile_workspace.clone())
                    .unwrap_or_default(),
                credential_handles: HashMap::new(),
            }),
            credential_expires_at_ms,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let provider = response
        .into_inner()
        .provider
        .ok_or_else(|| miette::miette!("provider missing from response"))?;

    println!(
        "{} Updated provider {}",
        "✓".green().bold(),
        provider.object_name()
    );
    Ok(())
}

pub async fn provider_delete(
    server: &str,
    names: &[String],
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let mut failures = Vec::new();
    for name in names {
        let response = match client
            .delete_provider(DeleteProviderRequest {
                name: name.clone(),
                workspace: workspace.to_string(),
            })
            .await
        {
            Ok(response) => response,
            Err(status) => {
                eprintln!(
                    "{} Failed to delete provider {name}: {status}",
                    "!".red().bold()
                );
                failures.push(name.clone());
                continue;
            }
        };
        if response.into_inner().deleted {
            println!("{} Deleted provider {name}", "✓".green().bold());
        } else {
            println!("{} Provider {name} not found", "!".yellow());
        }
    }
    aggregate_delete_failures("provider", &failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_ENV_LOCK;
    use crate::test_utils::EnvVarGuard;
    use std::fs;
    use std::io::Write;

    use openshell_core::proto::{
        CredentialHandle, Provider, ProviderCredentialRefresh,
        ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStatus,
        ProviderCredentialRefreshStrategy, ProviderCredentialTokenGrant, ProviderProfile,
        ProviderProfileCredential, datamodel::v1::ObjectMeta,
    };

    #[test]
    fn attached_provider_json_is_sorted_and_secret_safe() {
        let provider = Provider {
            metadata: Some(ObjectMeta {
                name: "github".to_string(),
                ..Default::default()
            }),
            r#type: "github".to_string(),
            credentials: HashMap::from([
                ("Z_TOKEN".to_string(), "inline-secret".to_string()),
                ("SHARED".to_string(), "shared-secret".to_string()),
            ]),
            config: HashMap::from([
                ("Z_URL".to_string(), "https://secret.example".to_string()),
                ("A_MODE".to_string(), "sensitive-config".to_string()),
            ]),
            credential_expires_at_ms: HashMap::from([("Z_TOKEN".to_string(), 123)]),
            profile_workspace: "internal".to_string(),
            credential_handles: HashMap::from([
                (
                    "A_HANDLE".to_string(),
                    CredentialHandle {
                        driver: "vault".to_string(),
                        handle: "opaque-secret-handle".to_string(),
                        metadata: HashMap::from([(
                            "internal".to_string(),
                            "metadata-value".to_string(),
                        )]),
                    },
                ),
                ("SHARED".to_string(), CredentialHandle::default()),
            ]),
        };

        let value = attached_provider_to_json(&provider);
        assert_eq!(
            value,
            serde_json::json!({
                "name": "github",
                "type": "github",
                "credential_keys": ["A_HANDLE", "SHARED", "Z_TOKEN"],
                "config_keys": ["A_MODE", "Z_URL"],
            })
        );
        let serialized = value.to_string();
        for secret in [
            "inline-secret",
            "shared-secret",
            "https://secret.example",
            "sensitive-config",
            "opaque-secret-handle",
            "metadata-value",
            "internal",
            "123",
        ] {
            assert!(!serialized.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn provider_attachment_table_formats_provider_counts() {
        let output = format_provider_attachment_table(
            &[Provider {
                metadata: Some(ObjectMeta {
                    name: "work-custom".to_string(),
                    ..Default::default()
                }),
                r#type: "custom-api".to_string(),
                credentials: [
                    ("CUSTOM_API_KEY".to_string(), "REDACTED".to_string()),
                    ("CUSTOM_API_SECRET".to_string(), "REDACTED".to_string()),
                ]
                .into_iter()
                .collect(),
                config: std::iter::once((
                    "BASE_URL".to_string(),
                    "https://api.custom.example".to_string(),
                ))
                .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: String::new(),
                credential_handles: HashMap::new(),
            }],
            false,
        );

        assert!(output.contains("NAME"));
        assert!(output.contains("TYPE"));
        assert!(output.contains("CREDENTIAL_KEYS"));
        assert!(output.contains("CONFIG_KEYS"));
        assert!(output.contains("work-custom"));
        assert!(output.contains("custom-api"));
        assert!(output.contains('2'));
        assert!(output.contains('1'));
    }

    #[test]
    fn refresh_status_table_includes_operational_fields() {
        let header = refresh_status_header();
        assert!(header.contains("NEXT_REFRESH"));
        assert!(header.contains("LAST_REFRESH"));
        assert!(header.contains("RECOVERY"));
        assert!(header.contains("FAILURE_CODE"));
        assert!(header.contains("LAST_ERROR"));

        let row = refresh_status_row(&ProviderCredentialRefreshStatus {
            provider_name: "my-graph".to_string(),
            provider_id: "provider-id".to_string(),
            credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            status: "error".to_string(),
            expires_at_ms: 1_767_225_600_000,
            next_refresh_at_ms: i64::MAX,
            last_refresh_at_ms: 1_767_225_000_000,
            last_error: "token endpoint returned a very long error message that should be truncated for table readability"
                .to_string(),
            recovery_action: ProviderCredentialRefreshRecoveryAction::Reauthorize as i32,
            failure_code: "oauth_rotated_refresh_token_handle_missing".to_string(),
            provider_error_subtype: "invalid_rapt".to_string(),
            last_error_at_ms: 1_767_225_000_000,
        });

        assert!(row.contains("my-graph"));
        assert!(row.contains("MS_GRAPH_ACCESS_TOKEN"));
        assert!(row.contains("oauth2_client_credentials"));
        assert!(row.contains("error"));
        assert!(row.contains("reauthorize"));
        assert!(row.contains("oauth_rotated_refresh_token_handle_missing"));
        assert!(row.contains("2026-01-01 00:00:00"));
        assert!(!row.contains("292278994"));
        assert!(row.contains("..."));
    }

    #[test]
    fn empty_provider_credentials_require_all_required_credentials_to_be_runtime_resolvable() {
        let refresh_token_profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                name: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                required: true,
                refresh: Some(ProviderCredentialRefresh {
                    strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(provider_profile_allows_empty_credentials(
            &refresh_token_profile
        ));

        let token_grant_profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                name: "ACCESS_TOKEN".to_string(),
                required: true,
                token_grant: Some(ProviderCredentialTokenGrant {
                    token_endpoint: "https://auth.example.com/token".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(provider_profile_allows_empty_credentials(
            &token_grant_profile
        ));

        let mixed_static_profile = ProviderProfile {
            credentials: vec![
                ProviderProfileCredential {
                    name: "ACCESS_TOKEN".to_string(),
                    required: true,
                    refresh: Some(ProviderCredentialRefresh {
                        strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ProviderProfileCredential {
                    name: "STATIC_API_KEY".to_string(),
                    required: true,
                    refresh: None,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(!provider_profile_allows_empty_credentials(
            &mixed_static_profile
        ));

        let optional_refresh_profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                name: "OPTIONAL_TOKEN".to_string(),
                required: false,
                refresh: Some(ProviderCredentialRefresh {
                    strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(provider_profile_allows_empty_credentials(
            &optional_refresh_profile
        ));
    }

    #[test]
    fn inferred_provider_type_returns_type_for_known_command() {
        let result = inferred_provider_type(&["claude".to_string(), "--help".to_string()]);
        assert_eq!(result, Some("claude-code".to_string()));
    }

    #[test]
    fn inferred_provider_type_returns_none_for_unknown_command() {
        let result = inferred_provider_type(&["bash".to_string()]);
        assert_eq!(result, None);
    }

    #[test]
    fn inferred_provider_type_returns_none_for_empty_command() {
        let result = inferred_provider_type(&[]);
        assert_eq!(result, None);
    }

    #[test]
    fn inferred_provider_type_normalizes_aliases() {
        // Retired legacy types are not inferred, even when a custom profile
        // with the same ID could be imported and attached explicitly.
        let result = inferred_provider_type(&["glab".to_string()]);
        assert_eq!(result, None);

        // `gh` should resolve to `github`
        let result = inferred_provider_type(&["gh".to_string()]);
        assert_eq!(result, Some("github".to_string()));
    }

    #[test]
    fn inferred_provider_type_handles_full_path() {
        let result = inferred_provider_type(&["/usr/local/bin/claude".to_string()]);
        assert_eq!(result, Some("claude-code".to_string()));
    }

    #[test]
    fn read_gcloud_adc_missing_file_errors() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/nonexistent/path/to/adc.json",
        );
        let err = read_gcloud_adc().expect_err("missing file should error");
        assert!(
            err.to_string().contains("failed to read gcloud ADC file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_gcloud_adc_wrong_type_errors() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let json = serde_json::json!({
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "key123"
        });
        Write::write_all(&mut tmp.as_file(), json.to_string().as_bytes()).expect("write tempfile");
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().expect("tempfile path"),
        );
        let err = read_gcloud_adc().expect_err("wrong type should error");
        // The service_account type gets a targeted message directing the user
        // to the real Vertex service-account credential flow instead of the
        // generic authorized_user hint.
        assert!(
            err.to_string()
                .contains("GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN"),
            "error should mention the service-account token key, got: {err}"
        );
    }

    #[test]
    fn read_gcloud_adc_parses_user_creds() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "test-client-id.apps.googleusercontent.com",
            "client_secret": "test-client-secret",
            "refresh_token": "test-refresh-token"
        });
        Write::write_all(&mut tmp.as_file(), json.to_string().as_bytes()).expect("write tempfile");
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().expect("tempfile path"),
        );
        let (client_id, client_secret, refresh_token) =
            read_gcloud_adc().expect("valid ADC should parse");
        assert_eq!(client_id, "test-client-id.apps.googleusercontent.com");
        assert_eq!(client_secret, "test-client-secret");
        assert_eq!(refresh_token, "test-refresh-token");
    }

    #[test]
    fn read_gcloud_adc_uses_cloudsdk_config_fallback() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let adc_path = dir.path().join("application_default_credentials.json");
        let json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "cloudsdk-client-id.apps.googleusercontent.com",
            "client_secret": "cloudsdk-client-secret",
            "refresh_token": "cloudsdk-refresh-token"
        });
        fs::write(&adc_path, json.to_string()).expect("write adc file");
        let _adc_guard = EnvVarGuard::unset("GOOGLE_APPLICATION_CREDENTIALS");
        let _cloudsdk_guard =
            EnvVarGuard::set("CLOUDSDK_CONFIG", dir.path().to_str().expect("config path"));

        let (client_id, client_secret, refresh_token) =
            read_gcloud_adc().expect("valid CLOUDSDK_CONFIG ADC should parse");
        assert_eq!(client_id, "cloudsdk-client-id.apps.googleusercontent.com");
        assert_eq!(client_secret, "cloudsdk-client-secret");
        assert_eq!(refresh_token, "cloudsdk-refresh-token");
    }

    #[test]
    fn read_gcloud_adc_malformed_json_errors() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        Write::write_all(&mut tmp.as_file(), b"not valid json at all {{{{")
            .expect("write tempfile");
        let _guard = EnvVarGuard::set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().expect("tempfile path"),
        );
        let result = read_gcloud_adc();
        assert!(
            result.is_err(),
            "malformed JSON should produce an error, got: {result:?}"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("parse")
                || msg.contains("JSON")
                || msg.contains("json")
                || msg.contains("invalid")
                || msg.contains("failed"),
            "error message should mention parse/JSON failure, got: {msg}"
        );
    }

    #[test]
    fn empty_provider_credentials_allow_oauth2_refresh_token() {
        use openshell_core::proto::{
            ProviderCredentialRefresh, ProviderCredentialRefreshStrategy, ProviderProfile,
            ProviderProfileCredential,
        };

        let strategy = ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32;
        let profile = ProviderProfile {
            credentials: vec![ProviderProfileCredential {
                required: true,
                refresh: Some(ProviderCredentialRefresh {
                    strategy,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            provider_profile_allows_empty_credentials(&profile),
            "Oauth2RefreshToken should be allowed for refresh bootstrap"
        );
    }

    #[test]
    fn provider_to_json_includes_core_fields() {
        let metadata = ObjectMeta {
            id: "prov-123".to_string(),
            name: "test-provider".to_string(),
            ..Default::default()
        };

        let provider = Provider {
            metadata: Some(metadata),
            r#type: "anthropic".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);

        assert_eq!(json["id"], "prov-123");
        assert_eq!(json["name"], "test-provider");
        assert_eq!(json["workspace"], "");
        assert_eq!(json["type"], "anthropic");
    }

    #[test]
    fn provider_to_json_exposes_credential_keys_not_values() {
        let mut credentials = HashMap::new();
        credentials.insert("ANTHROPIC_API_KEY".to_string(), "secret-value".to_string());
        credentials.insert("OTHER_KEY".to_string(), "other-secret".to_string());

        let provider = Provider {
            metadata: Some(ObjectMeta::default()),
            r#type: "anthropic".to_string(),
            credentials,
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);
        let json_str = json.to_string();

        // Assert credential keys are present
        let keys = json["credential_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.as_str() == Some("ANTHROPIC_API_KEY")));
        assert!(keys.iter().any(|k| k.as_str() == Some("OTHER_KEY")));

        // Assert credential values are NOT in the output (SECURITY)
        assert!(
            !json_str.contains("secret-value"),
            "credential values must not be exposed"
        );
        assert!(
            !json_str.contains("other-secret"),
            "credential values must not be exposed"
        );
    }

    #[test]
    fn provider_to_json_exposes_config_keys_not_values() {
        let mut config = HashMap::new();
        config.insert("region".to_string(), "us-west".to_string());
        config.insert(
            "endpoint".to_string(),
            "https://api.example.com".to_string(),
        );

        let provider = Provider {
            metadata: Some(ObjectMeta::default()),
            r#type: "custom".to_string(),
            credentials: HashMap::new(),
            config,
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);
        let json_str = json.to_string();

        // Assert config keys are present
        let keys = json["config_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.as_str() == Some("region")));
        assert!(keys.iter().any(|k| k.as_str() == Some("endpoint")));

        // Assert config values are NOT in the output (SECURITY)
        assert!(
            !json_str.contains("us-west"),
            "config values must not be exposed"
        );
        assert!(
            !json_str.contains("https://api.example.com"),
            "config values must not be exposed"
        );
    }

    #[test]
    fn provider_to_json_omits_empty_config() {
        let provider = Provider {
            metadata: Some(ObjectMeta::default()),
            r#type: "anthropic".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(), // Empty config
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);

        assert!(
            json.get("config_keys").is_none(),
            "empty config_keys should be omitted"
        );
    }

    #[test]
    fn provider_to_json_includes_metadata_fields_when_present() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let metadata = ObjectMeta {
            id: "prov-123".to_string(),
            name: "test-provider".to_string(),
            resource_version: 42,
            created_at_ms: 1_234_567_890_000,
            labels,
            annotations: HashMap::new(),
            workspace: String::new(),
            deletion_timestamp_ms: 0,
        };

        let provider = Provider {
            metadata: Some(metadata),
            r#type: "anthropic".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);

        assert_eq!(json["resource_version"], 42);
        assert_eq!(json["created_at"], "2009-02-13 23:31:30");
        assert_eq!(json["labels"]["env"], "prod");
    }

    #[test]
    fn provider_to_json_omits_zero_metadata_fields() {
        let metadata = ObjectMeta {
            id: "prov-123".to_string(),
            name: "test-provider".to_string(),
            // resource_version and created_at_ms are 0
            // labels is empty
            ..Default::default()
        };

        let provider = Provider {
            metadata: Some(metadata),
            r#type: "anthropic".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);

        assert!(
            json.get("resource_version").is_none(),
            "zero resource_version should be omitted"
        );
        assert!(
            json.get("created_at").is_none(),
            "zero created_at should be omitted"
        );
        assert!(
            json.get("labels").is_none(),
            "empty labels should be omitted"
        );
    }

    #[test]
    fn provider_to_json_includes_credential_expiration() {
        let mut credential_expires_at_ms = HashMap::new();
        credential_expires_at_ms.insert("ACCESS_TOKEN".to_string(), 1_234_567_890);

        let provider = Provider {
            metadata: Some(ObjectMeta::default()),
            r#type: "oauth".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms,
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);

        assert_eq!(
            json["credential_expires_at_ms"]["ACCESS_TOKEN"],
            1_234_567_890
        );
    }

    #[test]
    fn provider_to_json_formats_created_at_as_human_readable() {
        let metadata = ObjectMeta {
            id: "prov-123".to_string(),
            name: "test-provider".to_string(),
            created_at_ms: 1_609_459_200_000, // 2021-01-01 00:00:00
            ..Default::default()
        };

        let provider = Provider {
            metadata: Some(metadata),
            r#type: "anthropic".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let json = provider_to_json(&provider);

        // Should format as human-readable datetime, not raw milliseconds
        assert_eq!(json["created_at"], "2021-01-01 00:00:00");
        assert!(
            json.get("created_at_ms").is_none(),
            "raw milliseconds field should not exist"
        );
    }
}
