// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::tls::{
    TlsOptions, build_insecure_rustls_config, build_rustls_config, grpc_client,
    require_tls_materials,
};
use bytes::Bytes;
use dialoguer::{Select, theme::ColorfulTheme};
use http_body_util::Full;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_bootstrap::{
    GatewayMetadata, clear_active_gateway, extract_host_from_ssh_destination,
    gateway_metadata_source, get_gateway_metadata, list_gateways, list_gateways_with_source,
    load_active_gateway, load_user_active_gateway, remove_gateway_metadata, resolve_ssh_hostname,
    save_active_gateway, store_gateway_metadata,
};
use openshell_bootstrap::{GatewayMetadataSource, ListedGateway};
use openshell_core::proto::{GetGatewayInfoRequest, HealthRequest, ServiceStatus};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::path::PathBuf;
use tonic::{Code, Status};

#[derive(Debug, Clone)]
struct GatewayInfoView {
    gateway: String,
    server: String,
    auth: Option<&'static str>,
    status: String,
    version: String,
    compute_drivers: Vec<ComputeDriverInfoView>,
}

#[derive(Debug, Clone)]
struct ComputeDriverInfoView {
    name: String,
    capabilities: ComputeDriverCapabilitiesView,
}

#[derive(Debug, Clone)]
struct ComputeDriverCapabilitiesView {
    driver_name: String,
    driver_version: String,
}

/// Show gateway status.
#[allow(clippy::branches_sharing_code)]
pub async fn gateway_status(
    gateway_name: &str,
    server: &str,
    output: &str,
    tls: &TlsOptions,
    auth_preparation_error: Option<&str>,
) -> Result<()> {
    // Build status data before any output.
    let is_bearer = tls.is_bearer_auth();
    let (status_str, version, error, http_status, authentication): (
        &str,
        Option<String>,
        Option<String>,
        Option<String>,
        GatewayAuthenticationState,
    ) = match grpc_client(server, tls).await {
        Ok(mut client) => match client.health(HealthRequest {}).await {
            Ok(response) => {
                let health = response.into_inner();
                let auth = match auth_preparation_error {
                    Some(e) => GatewayAuthenticationState::Failed(e.to_string()),
                    None => gateway_authentication_state(
                        client
                            .get_gateway_info(GetGatewayInfoRequest {})
                            .await
                            .map(|_| ()),
                        tls,
                        server,
                    ),
                };
                ("connected", Some(health.version), None, None, auth)
            }
            Err(e) => {
                let auth = auth_preparation_error.map_or_else(
                    || {
                        GatewayAuthenticationState::Unverified(
                            "gRPC health check failed".to_string(),
                        )
                    },
                    |err| GatewayAuthenticationState::Failed(err.to_string()),
                );
                http_health_check(server, tls).await?.map_or_else(
                    || ("error", None, Some(e.to_string()), None, auth.clone()),
                    |http| {
                        let hs = Some(http.to_string());
                        if http.is_success() {
                            (
                                "connected_http",
                                None,
                                Some(e.to_string()),
                                hs,
                                auth.clone(),
                            )
                        } else {
                            ("error", None, Some(e.to_string()), hs, auth.clone())
                        }
                    },
                )
            }
        },
        Err(e) => {
            let auth = auth_preparation_error.map_or_else(
                || GatewayAuthenticationState::Unverified("gateway unreachable".to_string()),
                |err| GatewayAuthenticationState::Failed(err.to_string()),
            );
            http_health_check(server, tls).await?.map_or_else(
                || {
                    (
                        "disconnected",
                        None,
                        Some(e.to_string()),
                        None,
                        auth.clone(),
                    )
                },
                |http| {
                    let hs = Some(http.to_string());
                    if http.is_success() {
                        (
                            "connected_http",
                            None,
                            Some(e.to_string()),
                            hs,
                            auth.clone(),
                        )
                    } else {
                        ("disconnected", None, Some(e.to_string()), hs, auth.clone())
                    }
                },
            )
        }
    };

    let json_data = status_to_json(
        gateway_name,
        server,
        is_bearer,
        status_str,
        &version,
        &error,
        &http_status,
        &authentication,
    );
    if crate::output::print_output_single(output, &json_data, Clone::clone)? {
        return Ok(());
    }

    // Human-readable output.
    println!("{}", "Server Status".cyan().bold());
    println!();
    println!("  {} {}", "Gateway:".dimmed(), gateway_name);
    println!("  {} {}", "Server:".dimmed(), server);

    match status_str {
        "connected" => {
            println!("  {} {}", "Status:".dimmed(), "Connected".green());
            print_gateway_authentication_state(&authentication);
            if let Some(ref v) = version {
                println!("  {} {}", "Version:".dimmed(), v);
            }
        }
        "connected_http" => {
            println!("  {} {}", "Status:".dimmed(), "Connected (HTTP)".yellow());
            if let Some(ref hs) = http_status {
                println!("  {} {}", "HTTP: ".dimmed(), hs);
            }
            if let Some(ref e) = error {
                println!("  {} {}", "gRPC error:".dimmed(), e);
            }
            print_gateway_authentication_state(&authentication);
        }
        "error" => {
            println!("  {} {}", "Status:".dimmed(), "Error".red());
            if let Some(ref hs) = http_status {
                println!("  {} {}", "HTTP:".dimmed(), hs);
                if let Some(ref e) = error {
                    println!("  {} {}", "gRPC error:".dimmed(), e);
                }
            } else if let Some(ref e) = error {
                println!("  {} {}", "Error:".dimmed(), e);
            }
            print_gateway_authentication_state(&authentication);
        }
        _ => {
            println!("  {} {}", "Status:".dimmed(), "Disconnected".red());
            if let Some(ref hs) = http_status {
                println!("  {} {}", "HTTP:".dimmed(), hs);
            }
            if let Some(ref e) = error {
                println!("  {} {}", "Error:".dimmed(), e);
            }
            print_gateway_authentication_state(&authentication);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GatewayAuthenticationState {
    Authenticated(&'static str),
    NotRequired(&'static str),
    Failed(String),
    Unverified(String),
}

fn gateway_authentication_state(
    result: std::result::Result<(), Status>,
    tls: &TlsOptions,
    server: &str,
) -> GatewayAuthenticationState {
    match result {
        Ok(()) if tls.oidc_token.is_some() => GatewayAuthenticationState::Authenticated("OIDC"),
        Ok(()) if tls.edge_token.is_some() => GatewayAuthenticationState::Authenticated("edge"),
        Ok(()) if server.starts_with("https://") => {
            GatewayAuthenticationState::Authenticated("mTLS transport")
        }
        Ok(()) => GatewayAuthenticationState::NotRequired("gateway"),
        Err(status) if status.code() == Code::Unauthenticated => {
            GatewayAuthenticationState::Failed(status.message().to_string())
        }
        Err(status) if status.code() == Code::PermissionDenied => {
            let provider = if tls.oidc_token.is_some() {
                "OIDC; authorization denied"
            } else if tls.edge_token.is_some() {
                "edge; authorization denied"
            } else if server.starts_with("https://") {
                "mTLS transport; authorization denied"
            } else {
                "authorization denied"
            };
            GatewayAuthenticationState::Authenticated(provider)
        }
        Err(status) if status.code() == Code::Unimplemented && tls.edge_token.is_some() => {
            GatewayAuthenticationState::Authenticated("edge")
        }
        Err(status)
            if status.code() == Code::Unimplemented
                && !tls.is_bearer_auth()
                && server.starts_with("http://") =>
        {
            GatewayAuthenticationState::NotRequired("gateway")
        }
        Err(status)
            if status.code() == Code::Unimplemented
                && !tls.is_bearer_auth()
                && server.starts_with("https://") =>
        {
            GatewayAuthenticationState::Authenticated("mTLS transport")
        }
        Err(status) if status.code() == Code::Unimplemented => {
            GatewayAuthenticationState::Unverified(
                "gateway does not support authentication checks".to_string(),
            )
        }
        Err(status) => GatewayAuthenticationState::Unverified(status.message().to_string()),
    }
}

fn print_gateway_authentication_state(state: &GatewayAuthenticationState) {
    match state {
        GatewayAuthenticationState::Authenticated(provider) => println!(
            "  {} {} ({provider})",
            "Authentication:".dimmed(),
            "Authenticated".green()
        ),
        GatewayAuthenticationState::NotRequired(mode) => println!(
            "  {} {} ({mode})",
            "Authentication:".dimmed(),
            "Not required".green()
        ),
        GatewayAuthenticationState::Failed(error) => println!(
            "  {} {} ({error})",
            "Authentication:".dimmed(),
            "Failed".red()
        ),
        GatewayAuthenticationState::Unverified(reason) => println!(
            "  {} {} ({reason})",
            "Authentication:".dimmed(),
            "Unverified".yellow()
        ),
    }
}

fn authentication_state_to_json(state: &GatewayAuthenticationState) -> serde_json::Value {
    match state {
        GatewayAuthenticationState::Authenticated(provider) => serde_json::json!({
            "status": "authenticated",
            "provider": provider,
        }),
        GatewayAuthenticationState::NotRequired(mode) => serde_json::json!({
            "status": "not_required",
            "mode": mode,
        }),
        GatewayAuthenticationState::Failed(error) => serde_json::json!({
            "status": "failed",
            "error": error,
        }),
        GatewayAuthenticationState::Unverified(reason) => serde_json::json!({
            "status": "unverified",
            "reason": reason,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn status_to_json(
    gateway_name: &str,
    server: &str,
    is_bearer: bool,
    status: &str,
    version: &Option<String>,
    error: &Option<String>,
    http_status: &Option<String>,
    authentication: &GatewayAuthenticationState,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "gateway": gateway_name,
        "server": server,
        "status": status,
        "authentication": authentication_state_to_json(authentication),
    });
    let map = obj.as_object_mut().expect("json! returns object");
    if is_bearer {
        map.insert("auth".into(), serde_json::json!("edge_bearer"));
    }
    if let Some(v) = version {
        map.insert("version".into(), serde_json::json!(v));
    }
    if let Some(hs) = http_status {
        map.insert("http_status".into(), serde_json::json!(hs));
    }
    if let Some(e) = error {
        map.insert("error".into(), serde_json::json!(e));
    }
    obj
}

fn gateway_service_status_name(status: i32) -> &'static str {
    match ServiceStatus::try_from(status) {
        Ok(ServiceStatus::Healthy) => "healthy",
        Ok(ServiceStatus::Degraded) => "degraded",
        Ok(ServiceStatus::Unhealthy) => "unhealthy",
        Ok(ServiceStatus::Unspecified) | Err(_) => "unknown",
    }
}

/// Show elevated gateway runtime information.
pub async fn gateway_info(
    gateway_name: &str,
    server: &str,
    tls: &TlsOptions,
    output: &str,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let info = client
        .get_gateway_info(GetGatewayInfoRequest {})
        .await
        .map_err(|err| match err.code() {
            Code::Unimplemented => {
                miette!("gateway info is not supported by this gateway version")
            }
            Code::PermissionDenied => miette!("gateway info requires admin privileges: {err}"),
            _ => miette!("get_gateway_info failed: {err}"),
        })?
        .into_inner();

    let view = GatewayInfoView {
        gateway: gateway_name.to_string(),
        server: server.to_string(),
        auth: tls.is_bearer_auth().then_some("bearer"),
        status: gateway_service_status_name(info.status).to_string(),
        version: info.gateway_version,
        compute_drivers: info
            .compute_drivers
            .into_iter()
            .map(|driver| {
                let capabilities = driver.capabilities.unwrap_or_default();
                ComputeDriverInfoView {
                    name: driver.name,
                    capabilities: ComputeDriverCapabilitiesView {
                        driver_name: capabilities.driver_name,
                        driver_version: capabilities.driver_version,
                    },
                }
            })
            .collect(),
    };

    print_gateway_info(&view, output)
}

pub fn gateway_info_not_configured() -> Result<()> {
    Err(miette!(
        "No gateway configured.\nRegister a gateway with: openshell gateway add <endpoint>"
    ))
}

fn print_gateway_info(view: &GatewayInfoView, output: &str) -> Result<()> {
    if crate::output::print_output_single(output, view, gateway_info_to_json)? {
        return Ok(());
    }

    println!("{}", "Gateway Info".cyan().bold());
    println!();
    println!("  {} {}", "Gateway:".dimmed(), view.gateway);
    println!("  {} {}", "Server:".dimmed(), view.server);
    if view.auth.is_some() {
        println!("  {} Edge (bearer token)", "Auth:".dimmed());
    }
    println!("  {} {}", "Status:".dimmed(), view.status);
    println!("  {} {}", "Version:".dimmed(), view.version);
    print_compute_driver_info(&view.compute_drivers);

    Ok(())
}

fn print_compute_driver_info(drivers: &[ComputeDriverInfoView]) {
    if drivers.is_empty() {
        return;
    }

    println!("  {}", "Compute drivers:".dimmed());
    for driver in drivers {
        println!("    {}", driver.name);
        if driver.capabilities.driver_name != driver.name {
            println!(
                "      {} {}",
                "Driver name:".dimmed(),
                driver.capabilities.driver_name
            );
        }
        println!(
            "      {} {}",
            "Driver version:".dimmed(),
            driver.capabilities.driver_version
        );
    }
}

fn gateway_info_to_json(view: &GatewayInfoView) -> serde_json::Value {
    serde_json::json!({
        "gateway": &view.gateway,
        "server": &view.server,
        "auth": view.auth,
        "status": &view.status,
        "version": &view.version,
        "compute_drivers": view
            .compute_drivers
            .iter()
            .map(|driver| serde_json::json!({
                "name": &driver.name,
                "capabilities": {
                    "driver_name": &driver.capabilities.driver_name,
                    "driver_version": &driver.capabilities.driver_version,
                },
            }))
            .collect::<Vec<_>>(),
    })
}

/// Set the active gateway.
pub fn gateway_use(name: &str) -> Result<()> {
    // Verify the gateway exists
    get_gateway_metadata(name).ok_or_else(|| {
        miette::miette!(
            "No gateway metadata found for '{name}'.\n\
              Register it first with: openshell gateway add <endpoint> --name {name}\n\
              Or list available gateways: openshell gateway select"
        )
    })?;

    save_active_gateway(name)?;
    eprintln!("{} Active gateway set to '{name}'", "✓".green().bold());
    if let Some(warning) = gateway_env_override_warning(name) {
        eprintln!("{} {warning}", "⚠".yellow().bold());
    }
    Ok(())
}

fn gateway_env_override_warning(selected_name: &str) -> Option<String> {
    let env_name = std::env::var("OPENSHELL_GATEWAY").ok()?;
    if env_name.is_empty() || env_name == selected_name {
        return None;
    }

    Some(format!(
        "OPENSHELL_GATEWAY={env_name} is set and will override this selection.\n  Unset it or run: export OPENSHELL_GATEWAY={selected_name}"
    ))
}

pub fn gateway_select(name: Option<&str>, gateway_flag: &Option<String>) -> Result<()> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    gateway_select_with(name, gateway_flag, interactive, |gateways, default| {
        let prompt = format!(
            "Select a gateway\n{}",
            format_gateway_select_header(gateways)
        );
        let items = format_gateway_select_items(gateways);
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(&items)
            .default(default)
            .report(false)
            .interact_opt()
            .into_diagnostic()
            .map(|selection| selection.map(|index| gateways[index].name.clone()))
    })
}

fn format_gateway_select_header(gateways: &[GatewayMetadata]) -> String {
    let (name_width, endpoint_width, type_width) = gateway_select_column_widths(gateways);
    format!(
        "  {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {}",
        "NAME".bold(),
        "ENDPOINT".bold(),
        "TYPE".bold(),
        "AUTH".bold(),
    )
}

fn format_gateway_select_items(gateways: &[GatewayMetadata]) -> Vec<String> {
    let (name_width, endpoint_width, type_width) = gateway_select_column_widths(gateways);

    gateways
        .iter()
        .map(|gateway| {
            format!(
                "{:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {}",
                gateway.name,
                gateway.gateway_endpoint,
                gateway_type_label(gateway),
                gateway_auth_label(gateway),
            )
        })
        .collect()
}

fn gateway_select_column_widths(gateways: &[GatewayMetadata]) -> (usize, usize, usize) {
    let name_width = gateways
        .iter()
        .map(|gateway| gateway.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let endpoint_width = gateways
        .iter()
        .map(|gateway| gateway.gateway_endpoint.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let type_width = gateways
        .iter()
        .map(|gateway| gateway_type_label(gateway).len())
        .max()
        .unwrap_or(4)
        .max(4);

    (name_width, endpoint_width, type_width)
}

fn gateway_type_label(gateway: &GatewayMetadata) -> &'static str {
    match gateway.auth_mode.as_deref() {
        Some("cloudflare_jwt") => "cloud",
        _ if gateway.is_remote => "remote",
        _ => "local",
    }
}

fn gateway_auth_label(gateway: &GatewayMetadata) -> &str {
    match gateway.auth_mode.as_deref() {
        Some(auth_mode) => auth_mode,
        None if gateway.gateway_endpoint.starts_with("http://") => "plaintext",
        None => "mtls",
    }
}

fn is_loopback_gateway_endpoint(endpoint: &str) -> bool {
    let Ok(parsed) = url::Url::parse(endpoint) else {
        return false;
    };

    match parsed.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Check whether mTLS client certs exist on disk for a gateway name.
fn mtls_certs_exist_for_gateway(name: &str) -> bool {
    openshell_core::paths::xdg_config_dir().is_ok_and(|d| {
        let mtls = d.join("openshell").join("gateways").join(name).join("mtls");
        mtls.join("ca.crt").is_file()
            && mtls.join("tls.crt").is_file()
            && mtls.join("tls.key").is_file()
    })
}

fn package_managed_tls_dirs() -> Vec<PathBuf> {
    if let Some(path) = std::env::var_os("OPENSHELL_LOCAL_TLS_DIR") {
        return vec![PathBuf::from(path)];
    }

    let mut dirs = Vec::new();

    if cfg!(target_os = "macos") {
        dirs.push(PathBuf::from("/opt/homebrew/var/openshell/tls"));
        dirs.push(PathBuf::from("/usr/local/var/openshell/tls"));
    }

    let state_dir = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    if let Some(state_dir) = state_dir {
        dirs.push(state_dir.join("openshell/tls"));
    }

    dirs
}

fn import_local_package_mtls_bundle(name: &str) -> Result<Option<PathBuf>> {
    for dir in package_managed_tls_dirs() {
        let ca = dir.join("ca.crt");
        let cert = dir.join("client/tls.crt");
        let key = dir.join("client/tls.key");
        if !(ca.is_file() && cert.is_file() && key.is_file()) {
            continue;
        }

        let bundle = openshell_bootstrap::pki::PkiBundle {
            ca_cert_pem: std::fs::read_to_string(&ca)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", ca.display()))?,
            ca_key_pem: String::new(),
            server_cert_pem: String::new(),
            server_key_pem: String::new(),
            client_cert_pem: std::fs::read_to_string(&cert)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", cert.display()))?,
            client_key_pem: std::fs::read_to_string(&key)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", key.display()))?,
            // CLI never holds the gateway's JWT signing material — only the
            // gateway needs it. Fill the JWT fields with placeholders.
            jwt_signing_key_pem: String::new(),
            jwt_public_key_pem: String::new(),
            jwt_key_id: String::new(),
        };
        openshell_bootstrap::mtls::store_pki_bundle(name, &bundle)
            .wrap_err_with(|| format!("failed to store mTLS bundle for gateway '{name}'"))?;

        return Ok(Some(dir));
    }

    Ok(None)
}

fn plaintext_gateway_is_remote(endpoint: &str, remote: Option<&str>, local: bool) -> bool {
    if local {
        return false;
    }
    if remote.is_some() {
        return true;
    }
    !is_loopback_gateway_endpoint(endpoint)
}

fn plaintext_gateway_metadata(
    name: &str,
    endpoint: &str,
    remote: Option<&str>,
    local: bool,
) -> GatewayMetadata {
    let (remote_host, resolved_host) = remote.map_or((None, None), |dest| {
        let ssh_host = extract_host_from_ssh_destination(dest);
        let resolved = resolve_ssh_hostname(&ssh_host);
        (Some(dest.to_string()), Some(resolved))
    });

    GatewayMetadata {
        name: name.to_string(),
        gateway_endpoint: endpoint.to_string(),
        is_remote: plaintext_gateway_is_remote(endpoint, remote, local),
        gateway_port: 0,
        remote_host,
        resolved_host,
        auth_mode: Some("plaintext".to_string()),
        ..Default::default()
    }
}

fn gateway_select_with<F>(
    name: Option<&str>,
    gateway_flag: &Option<String>,
    interactive: bool,
    choose_gateway: F,
) -> Result<()>
where
    F: FnOnce(&[GatewayMetadata], usize) -> Result<Option<String>>,
{
    if let Some(name) = name {
        return gateway_use(name);
    }

    let gateways = list_gateways()?;
    if gateways.is_empty() || !interactive {
        gateway_list(gateway_flag, "table")?;
        if !gateways.is_empty() {
            eprintln!();
            eprintln!(
                "Select a gateway with: {}",
                "openshell gateway select <name>".dimmed()
            );
        }
        return Ok(());
    }

    let active = gateway_flag.clone().or_else(load_active_gateway);
    let default = active
        .as_deref()
        .and_then(|name| gateways.iter().position(|gateway| gateway.name == name))
        .unwrap_or(0);

    if let Some(name) = choose_gateway(&gateways, default)? {
        gateway_use(&name)?;
    } else {
        eprintln!("{} Gateway selection cancelled", "!".yellow());
    }

    Ok(())
}

/// Register an existing gateway.
///
/// An `http://...` endpoint is registered as a direct plaintext gateway with
/// no mTLS certificate lookup or browser authentication.
///
/// Without extra flags, an `https://...` endpoint is treated as an
/// edge-authenticated (cloud) gateway and a browser is opened for
/// authentication.
///
/// Pass `remote` (SSH destination) to register a remote mTLS gateway, or
/// `local = true` for a local mTLS gateway. In both cases mTLS certificates
/// must already exist in the gateway config directory.
///
/// An `ssh://` endpoint (e.g., `ssh://user@host:8080`) is shorthand for
/// `--remote user@host` with the gateway endpoint derived from the URL.
#[allow(clippy::too_many_arguments)]
pub async fn gateway_add(
    endpoint: &str,
    name: Option<&str>,
    remote: Option<&str>,
    local: bool,
    oidc_issuer: Option<&str>,
    oidc_client_id: &str,
    oidc_audience: Option<&str>,
    oidc_scopes: Option<&str>,
    gateway_insecure: bool,
) -> Result<()> {
    // If the endpoint starts with ssh://, parse it into an SSH destination
    // and a gateway endpoint automatically.  The host is resolved via
    // `ssh -G` so that SSH config aliases map to the real hostname/IP.
    // e.g. ssh://drew@spark:8080 -> remote="drew@spark", endpoint="https://<resolved>:8080"
    let (endpoint, remote) = if endpoint.starts_with("ssh://") {
        if local {
            return Err(miette::miette!(
                "Cannot use --local with an ssh:// endpoint.\n\
                 ssh:// implies a remote gateway."
            ));
        }
        if remote.is_some() {
            return Err(miette::miette!(
                "Cannot use --remote with an ssh:// endpoint.\n\
                 The SSH destination is already embedded in the URL."
            ));
        }
        let parsed = url::Url::parse(endpoint)
            .map_err(|e| miette::miette!("Invalid ssh:// URL '{endpoint}': {e}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| miette::miette!("ssh:// URL must include a hostname: {endpoint}"))?;
        let port = parsed
            .port()
            .ok_or_else(|| miette::miette!("ssh:// URL must include a port: {endpoint}"))?;

        let ssh_dest = if parsed.username().is_empty() {
            host.to_string()
        } else {
            format!("{}@{host}", parsed.username())
        };
        // Resolve the SSH host alias (e.g. ~/.ssh/config HostName) so the
        // endpoint uses the actual hostname/IP that matches the TLS certificate
        // SANs.
        let resolved = resolve_ssh_hostname(host);
        let https_endpoint = format!("https://{resolved}:{port}");

        (https_endpoint, Some(ssh_dest))
    } else {
        // Normalise the endpoint: ensure it has a scheme.
        let endpoint = if endpoint.contains("://") {
            endpoint.to_string()
        } else {
            format!("https://{endpoint}")
        };
        (endpoint, remote.map(String::from))
    };
    let remote = remote.as_deref();

    // Derive a gateway name from the hostname when none is provided.
    // Loopback endpoints use the canonical "openshell" name, matching the
    // convention in local cert generation and default_tls_dir.
    let derived_name;
    let name = if let Some(n) = name {
        n
    } else if is_loopback_gateway_endpoint(&endpoint) {
        derived_name = "openshell".to_string();
        &derived_name
    } else {
        // Parse out just the host portion of the URL.
        derived_name = url::Url::parse(&endpoint)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| endpoint.clone());
        &derived_name
    };

    match gateway_metadata_source(name)? {
        Some(GatewayMetadataSource::User) => {
            return Err(miette::miette!(
                "Gateway '{}' already exists.\n\
                 Remove it first with: openshell gateway remove {}\n\
                 Or choose a different name with: --name <name>",
                name,
                name,
            ));
        }
        Some(GatewayMetadataSource::System) | None => {}
    }

    // OIDC takes precedence over plaintext/mTLS/edge detection — the user
    // explicitly opted in with --oidc-issuer regardless of scheme.
    if let Some(issuer) = oidc_issuer {
        let previous_active = load_user_active_gateway();

        let metadata = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.clone(),
            is_remote: !local,
            auth_mode: Some("oidc".to_string()),
            oidc_issuer: Some(issuer.to_string()),
            oidc_client_id: Some(oidc_client_id.to_string()),
            oidc_audience: oidc_audience.map(String::from),
            oidc_scopes: oidc_scopes.map(String::from),
            ..Default::default()
        };

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!("  {} oidc", "Auth:".dimmed());
        eprintln!();

        let auth_skipped = is_browser_suppressed();

        // Check for client_credentials env var (CI mode).
        let auth_ok = if std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").is_ok() {
            match crate::oidc_auth::oidc_client_credentials_flow(
                issuer,
                oidc_client_id,
                oidc_audience,
                oidc_scopes,
                gateway_insecure,
            )
            .await
            {
                Ok(bundle) => {
                    openshell_bootstrap::oidc_token::store_oidc_token(name, &bundle)?;
                    eprintln!(
                        "{} Authenticated via client credentials",
                        "✓".green().bold()
                    );
                    true
                }
                Err(e) => {
                    eprintln!("{} Authentication failed: {e}", "!".yellow());
                    false
                }
            }
        } else {
            match crate::oidc_auth::oidc_browser_auth_flow(
                issuer,
                oidc_client_id,
                oidc_audience,
                oidc_scopes,
                gateway_insecure,
            )
            .await
            {
                Ok(bundle) => {
                    openshell_bootstrap::oidc_token::store_oidc_token(name, &bundle)?;
                    eprintln!("{} Authenticated successfully", "✓".green().bold());
                    true
                }
                Err(e) => {
                    eprintln!("{} Authentication failed: {e}", "!".yellow());
                    false
                }
            }
        };

        if !auth_ok && !auth_skipped {
            rollback_gateway_registration(name, previous_active.as_deref());
        }

        return Ok(());
    }

    if endpoint.starts_with("http://") {
        // Warn if mTLS certs exist for this gateway — the user likely
        // meant to use https:// instead of http://.
        let has_mtls_certs = mtls_certs_exist_for_gateway(name);

        if has_mtls_certs {
            let https_endpoint = endpoint.replacen("http://", "https://", 1);
            let suggestion = if is_loopback_gateway_endpoint(&endpoint) {
                format!("openshell gateway add --local {https_endpoint}")
            } else {
                format!("openshell gateway add {https_endpoint}")
            };
            eprintln!(
                "{} mTLS certificates found for gateway '{name}'. Did you mean to use https?",
                "⚠".yellow().bold(),
            );
            eprintln!("  Try: {suggestion}");
        }

        let metadata = plaintext_gateway_metadata(name, &endpoint, remote, local);
        let gateway_type = gateway_type_label(&metadata);
        let gateway_auth = gateway_auth_label(&metadata);

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        // Verify the gateway is reachable.
        let tls = TlsOptions::default();
        if !gateway_reachable(&endpoint, &tls).await {
            eprintln!(
                "{} Gateway is not reachable at {endpoint}",
                "⚠".yellow().bold(),
            );
            if !has_mtls_certs {
                eprintln!("  Verify the gateway is running and the endpoint is correct.");
            }
        }

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!("  {} {}", "Type:".dimmed(), gateway_type);
        eprintln!("  {} {}", "Auth:".dimmed(), gateway_auth);

        return Ok(());
    }

    if remote.is_some() || local {
        // mTLS gateway (remote or local).
        let imported_mtls_dir = if local {
            import_local_package_mtls_bundle(name)?
        } else {
            None
        };
        let certs_on_disk = imported_mtls_dir.is_some() || mtls_certs_exist_for_gateway(name);
        if !certs_on_disk {
            return Err(miette::miette!(
                "mTLS certificates for gateway '{name}' were not found.\n\
                 Expected them under the default gateway config directory.\n\
                 Start the gateway package first so it provisions client TLS material, \
                 then retry: openshell gateway add {endpoint}{}",
                if local { " --local" } else { "" },
            ));
        }

        let (remote_host, resolved_host) = remote.map_or((None, None), |dest| {
            let ssh_host = extract_host_from_ssh_destination(dest);
            let resolved = resolve_ssh_hostname(&ssh_host);
            (Some(dest.to_string()), Some(resolved))
        });

        let metadata = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.clone(),
            is_remote: !local,
            gateway_port: 0,
            remote_host,
            resolved_host,
            auth_mode: Some("mtls".to_string()),
            ..Default::default()
        };

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        // Verify the gateway is reachable over mTLS.
        let tls = TlsOptions::default().with_gateway_name(name);
        if !gateway_reachable(&endpoint, &tls).await {
            eprintln!(
                "{} Gateway is not reachable at {endpoint}. Verify the gateway is running.",
                "⚠".yellow().bold(),
            );
        }

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!(
            "  {} {}",
            "Type:".dimmed(),
            if local { "local" } else { "remote" },
        );
        eprintln!("{} TLS certificates present", "✓".green().bold());
    } else {
        // Cloud (edge-authenticated) gateway.
        let previous_active = load_user_active_gateway();

        let metadata = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.clone(),
            is_remote: true,
            auth_mode: Some("cloudflare_jwt".to_string()),
            ..Default::default()
        };

        store_gateway_metadata(name, &metadata)?;
        save_active_gateway(name)?;

        eprintln!(
            "{} Gateway '{}' added and set as active",
            "✓".green().bold(),
            name,
        );
        eprintln!("  {} {}", "Endpoint:".dimmed(), endpoint);
        eprintln!("  {} cloud", "Type:".dimmed());
        eprintln!();

        let auth_skipped = is_browser_suppressed();

        let auth_ok = match crate::auth::browser_auth_flow(&endpoint).await {
            Ok(token) => {
                openshell_bootstrap::edge_token::store_edge_token(name, &token)?;
                eprintln!("{} Authenticated successfully", "✓".green().bold());
                true
            }
            Err(e) => {
                eprintln!("{} Authentication failed: {e}", "!".yellow());
                false
            }
        };

        if !auth_ok && !auth_skipped {
            rollback_gateway_registration(name, previous_active.as_deref());
        }
    }

    Ok(())
}

/// Re-authenticate with an edge-authenticated or OIDC gateway.
///
/// Dispatches to the appropriate auth flow based on `auth_mode`.
pub async fn gateway_login(name: &str, gateway_insecure: bool) -> Result<()> {
    let metadata = openshell_bootstrap::load_gateway_metadata(name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             List available gateways: openshell gateway select"
        )
    })?;

    match metadata.auth_mode.as_deref() {
        Some("cloudflare_jwt") => {
            let token = crate::auth::browser_auth_flow(&metadata.gateway_endpoint).await?;
            openshell_bootstrap::edge_token::store_edge_token(name, &token)?;
            eprintln!("{} Authenticated to gateway '{name}'", "✓".green().bold());
        }
        Some("oidc") => {
            let issuer = metadata.oidc_issuer.as_deref().ok_or_else(|| {
                miette::miette!("Gateway '{name}' has OIDC auth but no issuer URL in metadata")
            })?;
            let client_id = metadata
                .oidc_client_id
                .as_deref()
                .unwrap_or("openshell-cli");
            let audience = metadata.oidc_audience.as_deref();
            let scopes = metadata.oidc_scopes.as_deref();

            let bundle = if std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").is_ok() {
                crate::oidc_auth::oidc_client_credentials_flow(
                    issuer,
                    client_id,
                    audience,
                    scopes,
                    gateway_insecure,
                )
                .await?
            } else {
                crate::oidc_auth::oidc_browser_auth_flow(
                    issuer,
                    client_id,
                    audience,
                    scopes,
                    gateway_insecure,
                )
                .await?
            };

            let username = jwt_preferred_username(&bundle.access_token);
            openshell_bootstrap::oidc_token::store_oidc_token(name, &bundle)?;

            if let Some(user) = username {
                eprintln!(
                    "{} Authenticated to gateway '{name}' as {user}",
                    "✓".green().bold(),
                );
            } else {
                eprintln!("{} Authenticated to gateway '{name}'", "✓".green().bold());
            }
        }
        _ => {
            return Err(miette::miette!(
                "Gateway '{name}' does not use edge or OIDC authentication.\n\
                 Only edge-authenticated and OIDC gateways support browser login."
            ));
        }
    }

    Ok(())
}

/// Extract `preferred_username` from a JWT payload without signature verification.
fn jwt_preferred_username(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Clear stored authentication credentials for a gateway.
pub fn gateway_logout(name: &str) -> Result<()> {
    let metadata = openshell_bootstrap::load_gateway_metadata(name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             List available gateways: openshell gateway select"
        )
    })?;

    match metadata.auth_mode.as_deref() {
        Some("oidc") => {
            openshell_bootstrap::oidc_token::remove_oidc_token(name)?;
        }
        Some("cloudflare_jwt") => {
            openshell_bootstrap::edge_token::remove_edge_token(name)?;
        }
        _ => {
            return Err(miette::miette!(
                "Gateway '{name}' uses {} authentication — no stored credentials to clear.",
                metadata.auth_mode.as_deref().unwrap_or("mtls")
            ));
        }
    }

    eprintln!("{} Logged out of gateway '{name}'", "✓".green().bold());
    Ok(())
}

/// List all registered gateways.
pub fn gateway_list(gateway_flag: &Option<String>, output: &str) -> Result<()> {
    let gateways = list_gateways_with_source()?;
    let active = gateway_flag.clone().or_else(load_active_gateway);

    if crate::output::print_output_collection(output, &gateways, |g| gateway_to_json(g, &active))? {
        return Ok(());
    }

    if gateways.is_empty() {
        println!("No gateways found.");
        println!();
        println!(
            "Register a gateway with: {}",
            "openshell gateway add <endpoint>".dimmed()
        );
        return Ok(());
    }

    // Calculate column widths
    let name_width = gateways
        .iter()
        .map(|g| g.metadata.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let endpoint_width = gateways
        .iter()
        .map(|g| g.metadata.gateway_endpoint.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let type_width = gateways
        .iter()
        .map(|g| gateway_type_label(&g.metadata).len())
        .max()
        .unwrap_or(4)
        .max(4);
    let source_width = gateways
        .iter()
        .map(|g| g.source.label().len())
        .max()
        .unwrap_or(6)
        .max(6);
    let auth_width = gateways
        .iter()
        .map(|g| gateway_auth_label(&g.metadata).len())
        .max()
        .unwrap_or(4)
        .max(4);
    let remote_labels: Vec<Option<String>> = gateways
        .iter()
        .map(|g| gateway_remote_label(&g.metadata))
        .collect();
    let show_remote = remote_labels.iter().any(Option::is_some);
    let remote_width = remote_labels
        .iter()
        .filter_map(|label| label.as_ref().map(String::len))
        .max()
        .unwrap_or(6)
        .max(6);

    // Print header
    if show_remote {
        println!(
            "  {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {:<source_width$}  {:<auth_width$}  {:<remote_width$}",
            "NAME".bold(),
            "ENDPOINT".bold(),
            "TYPE".bold(),
            "SOURCE".bold(),
            "AUTH".bold(),
            "REMOTE".bold(),
        );
    } else {
        println!(
            "  {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {:<source_width$}  {}",
            "NAME".bold(),
            "ENDPOINT".bold(),
            "TYPE".bold(),
            "SOURCE".bold(),
            "AUTH".bold(),
        );
    }

    // Print rows
    for (gateway, remote_label) in gateways.iter().zip(remote_labels.iter()) {
        let metadata = &gateway.metadata;
        let is_active = active.as_deref() == Some(&metadata.name);
        let marker = if is_active { "*" } else { " " };
        let gw_type = gateway_type_label(metadata);
        let gw_auth = gateway_auth_label(metadata);
        let line = if show_remote {
            let remote_label = remote_label.as_deref().unwrap_or("-");
            format!(
                "{marker} {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {:<source_width$}  {:<auth_width$}  {:<remote_width$}",
                metadata.name,
                metadata.gateway_endpoint,
                gw_type,
                gateway.source.label(),
                gw_auth,
                remote_label,
            )
        } else {
            format!(
                "{marker} {:<name_width$}  {:<endpoint_width$}  {:<type_width$}  {:<source_width$}  {gw_auth}",
                metadata.name,
                metadata.gateway_endpoint,
                gw_type,
                gateway.source.label(),
            )
        };
        if is_active {
            println!("{}", line.green());
        } else {
            println!("{line}");
        }
    }

    Ok(())
}

fn gateway_to_json(gateway: &ListedGateway, active: &Option<String>) -> serde_json::Value {
    let metadata = &gateway.metadata;
    serde_json::json!({
        "name": metadata.name,
        "endpoint": metadata.gateway_endpoint,
        "type": gateway_type_label(metadata),
        "source": gateway.source.label(),
        "auth": gateway_auth_label(metadata),
        "active": active.as_deref() == Some(&metadata.name),
        "is_remote": metadata.is_remote,
        "remote_host": &metadata.remote_host,
        "resolved_host": &metadata.resolved_host,
    })
}

fn gateway_remote_label(gateway: &GatewayMetadata) -> Option<String> {
    match (&gateway.remote_host, &gateway.resolved_host) {
        (Some(remote), Some(resolved)) if remote != resolved => {
            Some(format!("{remote} -> {resolved}"))
        }
        (Some(remote), _) => Some(remote.clone()),
        (None, Some(resolved)) => Some(resolved.clone()),
        (None, None) => None,
    }
}

async fn http_health_check(server: &str, tls: &TlsOptions) -> Result<Option<StatusCode>> {
    let base = server.trim_end_matches('/');
    let uri: hyper::Uri = format!("{base}/healthz").parse().into_diagnostic()?;

    let scheme = uri.scheme_str().unwrap_or("https");
    let https = if tls.gateway_insecure && scheme.eq_ignore_ascii_case("https") {
        let insecure_config = build_insecure_rustls_config()?;
        HttpsConnectorBuilder::new()
            .with_tls_config(insecure_config)
            .https_or_http()
            .enable_http1()
            .build()
    } else if scheme.eq_ignore_ascii_case("http") || tls.is_bearer_auth() {
        HttpsConnectorBuilder::new()
            .with_native_roots()
            .into_diagnostic()?
            .https_or_http()
            .enable_http1()
            .build()
    } else {
        let materials = require_tls_materials(server, tls)?;
        let tls_config = build_rustls_config(&materials)?;
        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build()
    };
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let mut req_builder = Request::builder().method("GET").uri(uri);
    // Inject edge authentication headers when an edge token is configured.
    if let Some(ref token) = tls.edge_token {
        req_builder = req_builder
            .header("Cf-Access-Jwt-Assertion", token.as_str())
            .header("Cookie", format!("CF_Authorization={token}"));
    }
    let req = req_builder
        .body(Full::new(Bytes::new()))
        .into_diagnostic()?;
    let resp = client.request(req).await.into_diagnostic()?;
    Ok(Some(resp.status()))
}

async fn gateway_reachable(server: &str, tls: &TlsOptions) -> bool {
    if let Ok(mut client) = grpc_client(server, tls).await
        && client.health(HealthRequest {}).await.is_ok()
    {
        return true;
    }

    matches!(http_health_check(server, tls).await, Ok(Some(status)) if status.is_success())
}

fn is_browser_suppressed() -> bool {
    std::env::var("OPENSHELL_NO_BROWSER").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn rollback_gateway_registration(name: &str, previous_active: Option<&str>) {
    remove_gateway_registration(name);
    if let Some(prev) = previous_active
        && let Err(e) = save_active_gateway(prev)
    {
        tracing::warn!("failed to restore previous active gateway '{prev}': {e}");
        eprintln!(
            "{} Failed to restore previous active gateway '{}': {e}",
            "!".yellow(),
            prev,
        );
    }
    eprintln!(
        "{} Registration for '{}' removed. Fix the issue and retry gateway add.",
        "!".yellow(),
        name,
    );
}

fn remove_gateway_registration(name: &str) {
    if let Err(err) = openshell_bootstrap::edge_token::remove_edge_token(name) {
        tracing::debug!("failed to remove edge token: {err}");
    }
    if let Err(err) = openshell_bootstrap::oidc_token::remove_oidc_token(name) {
        tracing::debug!("failed to remove oidc token: {err}");
    }
    if let Err(err) = remove_gateway_metadata(name) {
        tracing::debug!("failed to remove gateway metadata: {err}");
    }
    if load_active_gateway().as_deref() == Some(name)
        && let Err(err) = clear_active_gateway()
    {
        tracing::debug!("failed to clear active gateway: {err}");
    }
}

/// Remove a local gateway registration without touching the gateway service.
pub fn gateway_remove(name: &str) -> Result<()> {
    match gateway_metadata_source(name)? {
        Some(GatewayMetadataSource::User) => {}
        Some(GatewayMetadataSource::System) => {
            return Err(miette::miette!(
                "Gateway registration '{name}' is installed by the system and cannot be removed from user config.\n\
                 Register a per-user gateway with the same name to override it, or select another gateway."
            ));
        }
        None => {
            return Err(miette::miette!(
                "No gateway metadata found for '{name}'.\n\
                 List available gateways: openshell gateway select"
            ));
        }
    }

    remove_gateway_registration(name);
    eprintln!(
        "{} Gateway registration '{name}' removed.",
        "✓".green().bold()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ComputeDriverCapabilitiesView, ComputeDriverInfoView, GatewayAuthenticationState,
        GatewayInfoView, TlsOptions, format_gateway_select_header, format_gateway_select_items,
        gateway_add, gateway_auth_label, gateway_authentication_state,
        gateway_env_override_warning, gateway_info_to_json, gateway_remote_label,
        gateway_select_with, gateway_to_json, gateway_type_label, http_health_check,
        import_local_package_mtls_bundle, mtls_certs_exist_for_gateway, package_managed_tls_dirs,
        plaintext_gateway_is_remote,
    };
    use crate::TEST_ENV_LOCK;
    use crate::test_utils::{EnvVarGuard, with_tmp_xdg};
    use hyper::StatusCode;
    use openshell_bootstrap::{
        GatewayMetadata, GatewayMetadataSource, ListedGateway, load_active_gateway,
        load_gateway_metadata, load_user_active_gateway, store_gateway_metadata,
    };
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::thread;
    use tonic::Status;

    fn with_tmp_xdg_and_system<F: FnOnce()>(tmp: &Path, system: &Path, f: F) {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let xdg_guard = EnvVarGuard::set(
            "XDG_CONFIG_HOME",
            tmp.to_str().expect("temp path should be utf-8"),
        );
        let system_guard = EnvVarGuard::set(
            "OPENSHELL_SYSTEM_GATEWAY_DIR",
            system.to_str().expect("system path should be utf-8"),
        );
        f();
        drop(system_guard);
        drop(xdg_guard);
    }

    fn edge_registration(name: &str, endpoint: &str) -> GatewayMetadata {
        GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.to_string(),
            is_remote: true,
            auth_mode: Some("cloudflare_jwt".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn gateway_status_reports_authenticated_oidc_probe() {
        let mut tls = TlsOptions::default();
        tls.oidc_token = Some("token".to_string());

        let state = gateway_authentication_state(Ok(()), &tls, "https://gateway.example.com");

        assert_eq!(state, GatewayAuthenticationState::Authenticated("OIDC"));
    }

    #[test]
    fn gateway_status_treats_authorization_denial_as_authenticated() {
        let mut tls = TlsOptions::default();
        tls.oidc_token = Some("token".to_string());

        let state = gateway_authentication_state(
            Err(Status::permission_denied("role 'openshell-admin' required")),
            &tls,
            "https://gateway.example.com",
        );

        assert_eq!(
            state,
            GatewayAuthenticationState::Authenticated("OIDC; authorization denied")
        );
    }

    #[test]
    fn gateway_status_reports_rejected_bearer_token() {
        let mut tls = TlsOptions::default();
        tls.oidc_token = Some("expired".to_string());

        let state = gateway_authentication_state(
            Err(Status::unauthenticated("invalid token: ExpiredSignature")),
            &tls,
            "https://gateway.example.com",
        );

        assert_eq!(
            state,
            GatewayAuthenticationState::Failed("invalid token: ExpiredSignature".to_string())
        );
    }

    #[test]
    fn gateway_status_marks_oidc_unverified_on_older_gateway() {
        let mut tls = TlsOptions::default();
        tls.oidc_token = Some("token".to_string());

        let state = gateway_authentication_state(
            Err(Status::unimplemented("unknown service")),
            &tls,
            "https://gateway.example.com",
        );

        assert_eq!(
            state,
            GatewayAuthenticationState::Unverified(
                "gateway does not support authentication checks".to_string()
            )
        );
    }

    #[test]
    fn gateway_status_reports_local_plaintext_auth_not_required() {
        let state =
            gateway_authentication_state(Ok(()), &TlsOptions::default(), "http://127.0.0.1:8080");

        assert_eq!(state, GatewayAuthenticationState::NotRequired("gateway"));
    }
    #[test]
    fn gateway_select_uses_explicit_name_without_prompting() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_registration("alpha", "https://alpha.example.com"),
            )
            .expect("store gateway");

            let mut prompted = false;
            gateway_select_with(Some("alpha"), &None, true, |_, _| {
                prompted = true;
                Ok(None)
            })
            .expect("select explicit gateway");

            assert_eq!(load_active_gateway().as_deref(), Some("alpha"));
            assert!(!prompted, "explicit gateway should skip prompting");
        });
    }

    #[test]
    fn gateway_env_override_warning_mentions_masked_selection() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::set("OPENSHELL_GATEWAY", "openshell");

        let warning = gateway_env_override_warning("docker-dev").expect("env override should warn");

        assert!(
            warning.contains("OPENSHELL_GATEWAY=openshell"),
            "warning should name the overriding env var: {warning}"
        );
        assert!(
            warning.contains("export OPENSHELL_GATEWAY=docker-dev"),
            "warning should suggest updating the env var: {warning}"
        );
    }

    #[test]
    fn gateway_env_override_warning_skips_matching_gateway() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::set("OPENSHELL_GATEWAY", "docker-dev");

        assert_eq!(gateway_env_override_warning("docker-dev"), None);
    }

    #[test]
    fn gateway_select_prefers_active_gateway_as_default_choice() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_registration("alpha", "https://alpha.example.com"),
            )
            .expect("store alpha");
            store_gateway_metadata(
                "beta",
                &edge_registration("beta", "https://beta.example.com"),
            )
            .expect("store beta");
            super::save_active_gateway("beta").expect("save active gateway");

            let mut seen_default = None;
            gateway_select_with(None, &None, true, |gateways, default| {
                seen_default = Some(default);
                Ok(Some(gateways[default].name.clone()))
            })
            .expect("interactive selection");

            assert_eq!(seen_default, Some(1));
            assert_eq!(load_active_gateway().as_deref(), Some("beta"));
        });
    }

    #[test]
    fn gateway_select_non_interactive_lists_gateways_without_prompting() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_registration("alpha", "https://alpha.example.com"),
            )
            .expect("store gateway");

            let mut prompted = false;
            gateway_select_with(None, &None, false, |_, _| {
                prompted = true;
                Ok(None)
            })
            .expect("non-interactive selection");

            assert!(!prompted, "non-interactive mode should not prompt");
            assert_eq!(load_active_gateway(), None);
        });
    }

    #[test]
    fn gateway_select_items_include_endpoint_and_type() {
        let gateways = vec![
            edge_registration("alpha", "https://edge.example.com"),
            GatewayMetadata {
                name: "local".to_string(),
                gateway_endpoint: "http://127.0.0.1:8080".to_string(),
                gateway_port: 8080,
                ..Default::default()
            },
        ];

        let items = format_gateway_select_items(&gateways);
        let header = format_gateway_select_header(&gateways);

        assert_eq!(gateway_type_label(&gateways[0]), "cloud");
        assert_eq!(gateway_type_label(&gateways[1]), "local");
        assert_eq!(gateway_auth_label(&gateways[0]), "cloudflare_jwt");
        assert_eq!(gateway_auth_label(&gateways[1]), "plaintext");
        assert!(header.contains("NAME"));
        assert!(header.contains("ENDPOINT"));
        assert!(header.contains("TYPE"));
        assert!(header.contains("AUTH"));
        assert!(items[0].contains("alpha"));
        assert!(items[0].contains("https://edge.example.com"));
        assert!(items[0].contains("cloud"));
        assert!(items[0].contains("cloudflare_jwt"));
        assert!(items[1].contains("local"));
        assert!(items[1].contains("plaintext"));
        assert!(items[1].contains("http://127.0.0.1:8080"));
    }

    #[test]
    fn gateway_to_json_includes_config_source() {
        let gateway = ListedGateway {
            metadata: GatewayMetadata {
                name: "local-vm".to_string(),
                gateway_endpoint: "http://127.0.0.1:17670".to_string(),
                auth_mode: Some("plaintext".to_string()),
                ..Default::default()
            },
            source: GatewayMetadataSource::System,
        };

        let json = gateway_to_json(&gateway, &Some("local-vm".to_string()));

        assert_eq!(json["source"], "system");
        assert_eq!(json["type"], "local");
        assert_eq!(json["auth"], "plaintext");
        assert_eq!(json["active"], true);
    }

    #[test]
    fn gateway_to_json_includes_remote_registration_details() {
        let gateway = ListedGateway {
            metadata: GatewayMetadata {
                name: "remote-vm".to_string(),
                gateway_endpoint: "https://127.0.0.1:17670".to_string(),
                is_remote: true,
                remote_host: Some("user@gateway-alias".to_string()),
                resolved_host: Some("10.0.0.5".to_string()),
                auth_mode: Some("mtls".to_string()),
                ..Default::default()
            },
            source: GatewayMetadataSource::User,
        };

        let json = gateway_to_json(&gateway, &Some("local-vm".to_string()));

        assert_eq!(json["source"], "user");
        assert_eq!(json["type"], "remote");
        assert_eq!(json["auth"], "mtls");
        assert_eq!(json["active"], false);
        assert_eq!(json["is_remote"], true);
        assert_eq!(json["remote_host"], "user@gateway-alias");
        assert_eq!(json["resolved_host"], "10.0.0.5");
        assert_eq!(
            gateway_remote_label(&gateway.metadata).as_deref(),
            Some("user@gateway-alias -> 10.0.0.5")
        );
    }

    #[test]
    fn gateway_info_json_includes_compute_drivers_when_available() {
        let view = GatewayInfoView {
            gateway: "openshell".to_string(),
            server: "https://127.0.0.1:17670".to_string(),
            auth: Some("bearer"),
            status: "healthy".to_string(),
            version: "0.0.75".to_string(),
            compute_drivers: vec![ComputeDriverInfoView {
                name: "podman".to_string(),
                capabilities: ComputeDriverCapabilitiesView {
                    driver_name: "podman".to_string(),
                    driver_version: "0.0.75".to_string(),
                },
            }],
        };

        let json = gateway_info_to_json(&view);

        assert_eq!(json["gateway"], "openshell");
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["version"], "0.0.75");
        assert_eq!(json["compute_drivers"][0]["name"], "podman");
        assert_eq!(
            json["compute_drivers"][0]["capabilities"]["driver_name"],
            "podman"
        );
        assert_eq!(
            json["compute_drivers"][0]["capabilities"]["driver_version"],
            "0.0.75"
        );
    }

    #[test]
    fn gateway_info_json_includes_empty_compute_driver_list() {
        let view = GatewayInfoView {
            gateway: "openshell".to_string(),
            server: "https://127.0.0.1:17670".to_string(),
            auth: None,
            status: "healthy".to_string(),
            version: "0.0.74".to_string(),
            compute_drivers: Vec::new(),
        };

        let json = gateway_info_to_json(&view);

        assert!(
            json["compute_drivers"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn gateway_auth_label_defaults_https_gateways_to_mtls() {
        let gateway = GatewayMetadata {
            name: "local".to_string(),
            gateway_endpoint: "https://127.0.0.1:8080".to_string(),
            gateway_port: 8080,
            ..Default::default()
        };

        assert_eq!(gateway_auth_label(&gateway), "mtls");
    }

    #[test]
    fn package_managed_tls_dirs_respects_override() {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _tls_dir = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", "/tmp/openshell-test-tls");

        assert_eq!(
            package_managed_tls_dirs(),
            vec![PathBuf::from("/tmp/openshell-test-tls")],
        );
    }

    #[test]
    fn import_local_package_mtls_bundle_copies_client_materials() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let package_tls = tmpdir.path().join("package-tls");
        fs::create_dir_all(package_tls.join("client")).expect("create package tls dir");
        fs::write(package_tls.join("ca.crt"), "ca").expect("write ca");
        fs::write(package_tls.join("client/tls.crt"), "client cert").expect("write cert");
        fs::write(package_tls.join("client/tls.key"), "client key").expect("write key");

        with_tmp_xdg(tmpdir.path(), || {
            let _tls_dir = EnvVarGuard::set(
                "OPENSHELL_LOCAL_TLS_DIR",
                package_tls.to_str().expect("temp path should be utf-8"),
            );

            let imported =
                import_local_package_mtls_bundle("openshell").expect("import local bundle");

            assert_eq!(imported.as_deref(), Some(package_tls.as_path()));

            let mtls = tmpdir.path().join("openshell/gateways/openshell/mtls");
            assert_eq!(fs::read_to_string(mtls.join("ca.crt")).unwrap(), "ca");
            assert_eq!(
                fs::read_to_string(mtls.join("tls.crt")).unwrap(),
                "client cert",
            );
            assert_eq!(
                fs::read_to_string(mtls.join("tls.key")).unwrap(),
                "client key",
            );
        });
    }

    #[test]
    fn mtls_certs_exist_for_gateway_uses_explicit_name_for_loopback_endpoint() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let mtls = tmpdir.path().join("openshell/gateways/k8s/mtls");
        fs::create_dir_all(&mtls).expect("create mtls dir");
        fs::write(mtls.join("ca.crt"), "ca").expect("write ca");
        fs::write(mtls.join("tls.crt"), "client cert").expect("write cert");
        fs::write(mtls.join("tls.key"), "client key").expect("write key");

        with_tmp_xdg(tmpdir.path(), || {
            assert!(mtls_certs_exist_for_gateway("k8s"));
            assert!(!mtls_certs_exist_for_gateway("openshell"));
        });
    }

    #[test]
    fn plaintext_gateway_locality_infers_loopback_endpoints_as_local() {
        assert!(!plaintext_gateway_is_remote(
            "http://127.0.0.1:8080",
            None,
            false,
        ));
        assert!(!plaintext_gateway_is_remote(
            "http://localhost:8080",
            None,
            false,
        ));
        assert!(!plaintext_gateway_is_remote(
            "http://[::1]:8080",
            None,
            false,
        ));
    }

    #[test]
    fn plaintext_gateway_locality_treats_non_loopback_endpoints_as_remote_without_local_flag() {
        assert!(plaintext_gateway_is_remote(
            "http://gateway.example.com:8080",
            None,
            false,
        ));
        assert!(plaintext_gateway_is_remote(
            "http://10.0.0.5:8080",
            None,
            false,
        ));
    }

    #[test]
    fn gateway_add_registers_plaintext_loopback_gateway_without_local_flag() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");
            runtime.block_on(async {
                gateway_add(
                    "http://127.0.0.1:8080",
                    None,
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register plaintext gateway");
            });

            // Loopback endpoints derive the canonical "openshell" gateway
            // name, matching local cert generation and default_tls_dir conventions.
            let metadata = load_gateway_metadata("openshell").expect("load stored gateway");
            assert_eq!(metadata.auth_mode.as_deref(), Some("plaintext"));
            assert!(!metadata.is_remote);
            assert_eq!(metadata.gateway_endpoint, "http://127.0.0.1:8080");
            assert_eq!(load_active_gateway().as_deref(), Some("openshell"));
        });
    }

    #[test]
    fn gateway_add_respects_local_flag_for_plaintext_registrations() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");
            runtime.block_on(async {
                gateway_add(
                    "http://gateway.example.com:8080",
                    Some("dev-http"),
                    None,
                    true,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register plaintext gateway");
            });

            let metadata = load_gateway_metadata("dev-http").expect("load stored gateway");
            assert_eq!(metadata.auth_mode.as_deref(), Some("plaintext"));
            assert!(!metadata.is_remote);
            assert_eq!(metadata.gateway_endpoint, "http://gateway.example.com:8080");
            assert_eq!(load_active_gateway().as_deref(), Some("dev-http"));
        });
    }

    #[tokio::test]
    async fn http_health_check_supports_plain_http_endpoints() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).expect("read request");
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Length: 2\r\n",
                "Content-Type: text/plain\r\n",
                "Connection: close\r\n\r\n",
                "ok"
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        let status = http_health_check(&format!("http://{addr}"), &TlsOptions::default())
            .await
            .expect("health check");

        server.join().expect("server thread");
        assert_eq!(status, Some(StatusCode::OK));
    }

    #[test]
    fn gateway_add_oidc_rolls_back_on_auth_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");

            // Register a working plaintext gateway first so we can verify
            // the active gateway is restored after rollback.
            runtime.block_on(async {
                gateway_add(
                    "http://127.0.0.1:9999",
                    Some("existing-gw"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register seed gateway");
            });
            assert_eq!(load_active_gateway().as_deref(), Some("existing-gw"));

            // Attempt OIDC gateway add against an unreachable issuer.
            // Auth will fail (connection refused), triggering rollback.
            runtime.block_on(async {
                gateway_add(
                    "https://gateway.example.com",
                    Some("oidc-fail"),
                    None,
                    false,
                    Some("http://127.0.0.1:1/realms/nonexistent"),
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("gateway_add should not return Err on auth failure");
            });

            // The failed registration should have been rolled back.
            assert!(
                load_gateway_metadata("oidc-fail").is_err(),
                "failed OIDC gateway should be removed after auth failure"
            );
            // The previously active gateway should be restored.
            assert_eq!(
                load_active_gateway().as_deref(),
                Some("existing-gw"),
                "active gateway should be restored after rollback"
            );
        });
    }
    #[test]
    fn gateway_add_oidc_rollback_keeps_system_active_fallback_userless() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let user = tempfile::tempdir().expect("create user tmpdir");
        let system = tempfile::tempdir().expect("create system tmpdir");
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            fs::write(system.path().join("active_gateway"), "system-default")
                .expect("write system active gateway");
            assert_eq!(load_user_active_gateway(), None);
            assert_eq!(load_active_gateway().as_deref(), Some("system-default"));

            let runtime = tokio::runtime::Runtime::new().expect("create runtime");
            runtime.block_on(async {
                gateway_add(
                    "https://gateway.example.com",
                    Some("oidc-fail"),
                    None,
                    false,
                    Some("http://127.0.0.1:1/realms/nonexistent"),
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("gateway_add should not return Err on auth failure");
            });

            assert!(
                load_gateway_metadata("oidc-fail").is_err(),
                "failed OIDC gateway should be removed after auth failure"
            );
            assert_eq!(
                load_user_active_gateway(),
                None,
                "rollback should not persist the system fallback into user config"
            );
            assert_eq!(load_active_gateway().as_deref(), Some("system-default"));
        });
    }

    #[test]
    fn gateway_add_cloud_rolls_back_on_auth_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        with_tmp_xdg(tmpdir.path(), || {
            let _no_browser = EnvVarGuard::set("OPENSHELL_NO_BROWSER", "0");
            let _browser_auth_failure = EnvVarGuard::set("OPENSHELL_TEST_BROWSER_AUTH_FAIL", "1");
            let runtime = tokio::runtime::Runtime::new().expect("create runtime");

            // Register a working plaintext gateway first.
            runtime.block_on(async {
                gateway_add(
                    "http://127.0.0.1:9999",
                    Some("existing-gw"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("register seed gateway");
            });
            assert_eq!(load_active_gateway().as_deref(), Some("existing-gw"));

            // Attempt cloud gateway add. Keep browser suppression disabled so
            // auth failure still rolls back the registration, but use the
            // test-only auth failure hook instead of opening the OS browser.
            runtime.block_on(async {
                gateway_add(
                    "https://127.0.0.1:1",
                    Some("cloud-fail"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("gateway_add should not return Err on auth failure");
            });

            // The failed registration should have been rolled back.
            assert!(
                load_gateway_metadata("cloud-fail").is_err(),
                "failed cloud gateway should be removed after auth failure"
            );
            assert_eq!(
                load_active_gateway().as_deref(),
                Some("existing-gw"),
                "active gateway should be restored after rollback"
            );
        });
    }
    #[test]
    fn gateway_add_cloud_rollback_keeps_system_active_fallback_userless() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let user = tempfile::tempdir().expect("create user tmpdir");
        let system = tempfile::tempdir().expect("create system tmpdir");
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let _no_browser = EnvVarGuard::set("OPENSHELL_NO_BROWSER", "0");
            let _browser_auth_failure = EnvVarGuard::set("OPENSHELL_TEST_BROWSER_AUTH_FAIL", "1");
            fs::write(system.path().join("active_gateway"), "system-default")
                .expect("write system active gateway");
            assert_eq!(load_user_active_gateway(), None);
            assert_eq!(load_active_gateway().as_deref(), Some("system-default"));

            let runtime = tokio::runtime::Runtime::new().expect("create runtime");
            runtime.block_on(async {
                gateway_add(
                    "https://127.0.0.1:1",
                    Some("cloud-fail"),
                    None,
                    false,
                    None,
                    "openshell-cli",
                    None,
                    None,
                    false,
                )
                .await
                .expect("gateway_add should not return Err on auth failure");
            });

            assert!(
                load_gateway_metadata("cloud-fail").is_err(),
                "failed cloud gateway should be removed after auth failure"
            );
            assert_eq!(
                load_user_active_gateway(),
                None,
                "rollback should not persist the system fallback into user config"
            );
            assert_eq!(load_active_gateway().as_deref(), Some("system-default"));
        });
    }
    #[test]
    fn status_to_json_connected() {
        let auth = GatewayAuthenticationState::Authenticated("mTLS transport");
        let json = super::status_to_json(
            "my-gw",
            "http://127.0.0.1:8090",
            false,
            "connected",
            &Some("1.2.3".to_string()),
            &None,
            &None,
            &auth,
        );

        assert_eq!(json["gateway"], "my-gw");
        assert_eq!(json["server"], "http://127.0.0.1:8090");
        assert_eq!(json["status"], "connected");
        assert_eq!(json["version"], "1.2.3");
        assert_eq!(json["authentication"]["status"], "authenticated");
        assert!(json.get("auth").is_none());
        assert!(json.get("error").is_none());
        assert!(json.get("http_status").is_none());
    }

    #[test]
    fn status_to_json_disconnected_with_error() {
        let auth = GatewayAuthenticationState::Unverified("gateway unreachable".to_string());
        let json = super::status_to_json(
            "broken-gw",
            "http://10.0.0.1:8090",
            false,
            "disconnected",
            &None,
            &Some("connection refused".to_string()),
            &None,
            &auth,
        );

        assert_eq!(json["status"], "disconnected");
        assert_eq!(json["error"], "connection refused");
        assert_eq!(json["authentication"]["status"], "unverified");
        assert!(json.get("version").is_none());
    }

    #[test]
    fn status_to_json_connected_http_with_bearer() {
        let auth = GatewayAuthenticationState::Failed("token expired".to_string());
        let json = super::status_to_json(
            "edge-gw",
            "https://edge.example.com",
            true,
            "connected_http",
            &None,
            &Some("gRPC unavailable".to_string()),
            &Some("200 OK".to_string()),
            &auth,
        );

        assert_eq!(json["status"], "connected_http");
        assert_eq!(json["auth"], "edge_bearer");
        assert_eq!(json["error"], "gRPC unavailable");
        assert_eq!(json["http_status"], "200 OK");
        assert_eq!(json["authentication"]["status"], "failed");
        assert!(json.get("version").is_none());
    }
}
