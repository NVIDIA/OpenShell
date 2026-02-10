use crate::constants::{
    CLI_SECRET_NAME, HELMCHART_MANIFEST_PATHS, NAV_GATEWAY_TLS_ENABLED_ENV, container_name,
};
use crate::paths::xdg_config_dir;
use crate::runtime::{exec_capture, exec_capture_with_exit, fetch_recent_logs};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bollard::Docker;
use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::PathBuf;
use std::time::Duration;

struct CliMtlsBundle {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
}

pub async fn fetch_and_store_cli_mtls(docker: &Docker, name: &str) -> Result<()> {
    let attempts = 90;
    let backoff = Duration::from_secs(2);

    if !gateway_tls_enabled(docker, name).await? {
        return Ok(());
    }

    let cname = container_name(name);
    for attempt in 0..attempts {
        // Check if container is still running before polling
        if let Err(status_err) = crate::docker::check_container_running(docker, &cname).await {
            let logs = fetch_recent_logs(docker, &cname, 20).await;
            return Err(miette::miette!(
                "cluster container is not running while waiting for mTLS secret: {status_err}\n{logs}"
            ));
        }

        match fetch_cli_mtls_bundle(docker, name).await {
            Ok(Some(bundle)) => {
                store_cli_mtls_bundle(name, bundle)?;
                return Ok(());
            }
            Ok(None) if attempt + 1 < attempts => {
                tokio::time::sleep(backoff).await;
            }
            Ok(None) => {
                let logs = fetch_recent_logs(docker, &cname, 20).await;
                return Err(miette::miette!(
                    "timed out waiting for CLI mTLS secret {CLI_SECRET_NAME}\n{logs}"
                ));
            }
            Err(err) => {
                let logs = fetch_recent_logs(docker, &cname, 20).await;
                return Err(miette::miette!(
                    "failed to fetch CLI mTLS secret {CLI_SECRET_NAME}: {err}\n{logs}"
                ));
            }
        }
    }

    let logs = fetch_recent_logs(docker, &cname, 20).await;
    Err(miette::miette!(
        "timed out waiting for CLI mTLS secret {CLI_SECRET_NAME}\n{logs}"
    ))
}

async fn gateway_tls_enabled(docker: &Docker, name: &str) -> Result<bool> {
    if let Ok(value) = std::env::var(NAV_GATEWAY_TLS_ENABLED_ENV) {
        return parse_bool_env(&value)
            .wrap_err_with(|| format!("{NAV_GATEWAY_TLS_ENABLED_ENV} must be true or false"));
    }

    let container_name = container_name(name);
    for path in HELMCHART_MANIFEST_PATHS {
        if let Some(contents) = read_container_file(docker, &container_name, path).await?
            && let Some(enabled) = parse_gateway_tls_enabled_from_helmchart(&contents)?
        {
            return Ok(enabled);
        }
    }

    Err(miette::miette!(
        "failed to determine gateway TLS configuration from {NAV_GATEWAY_TLS_ENABLED_ENV} or HelmChart manifest"
    ))
}

async fn read_container_file(
    docker: &Docker,
    container_name: &str,
    path: &str,
) -> Result<Option<String>> {
    let (output, status) = exec_capture_with_exit(
        docker,
        container_name,
        vec!["cat".to_string(), path.to_string()],
    )
    .await?;
    if status != 0 {
        return Ok(None);
    }
    Ok(Some(output))
}

fn parse_gateway_tls_enabled_from_helmchart(contents: &str) -> Result<Option<bool>> {
    let helmchart: serde_yaml::Value = serde_yaml::from_str(contents)
        .into_diagnostic()
        .wrap_err("failed to parse HelmChart manifest")?;
    let values_content = helmchart
        .get("spec")
        .and_then(|value| value.get("valuesContent"))
        .and_then(|value| value.as_str());
    let Some(values_content) = values_content else {
        return Ok(None);
    };
    parse_gateway_tls_enabled_from_values(values_content).map(Some)
}

fn parse_gateway_tls_enabled_from_values(values_content: &str) -> Result<bool> {
    let values: serde_yaml::Value = serde_yaml::from_str(values_content)
        .into_diagnostic()
        .wrap_err("failed to parse Helm values")?;
    let enabled = values
        .get("gateway")
        .and_then(|value| value.get("tls"))
        .and_then(|value| value.get("enabled"));
    enabled.map_or_else(
        || Ok(false),
        |value| parse_bool_value(value).wrap_err("failed to read gateway.tls.enabled"),
    )
}

fn parse_bool_value(value: &serde_yaml::Value) -> Result<bool> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    let Some(value) = value.as_str() else {
        return Err(miette::miette!("expected a boolean"));
    };
    parse_bool_env(value)
}

fn parse_bool_env(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(miette::miette!("expected a boolean")),
    }
}

async fn fetch_cli_mtls_bundle(docker: &Docker, name: &str) -> Result<Option<CliMtlsBundle>> {
    let container_name = container_name(name);
    let jsonpath = r#"{.data.ca\.crt}{"\n"}{.data.tls\.crt}{"\n"}{.data.tls\.key}"#;
    let output = exec_capture(
        docker,
        &container_name,
        vec![
            "kubectl".to_string(),
            "-n".to_string(),
            "navigator".to_string(),
            "get".to_string(),
            "secret".to_string(),
            CLI_SECRET_NAME.to_string(),
            "-o".to_string(),
            format!("jsonpath={jsonpath}"),
        ],
    )
    .await?;
    if output.trim().is_empty()
        || output.contains("NotFound")
        || output.contains("not found")
        || output.contains("Error from server")
    {
        return Ok(None);
    }

    let mut lines = output.lines();
    let ca_b64 = lines.next().unwrap_or("").trim();
    let cert_b64 = lines.next().unwrap_or("").trim();
    let key_b64 = lines.next().unwrap_or("").trim();
    if ca_b64.is_empty() || cert_b64.is_empty() || key_b64.is_empty() {
        return Ok(None);
    }

    let ca = STANDARD.decode(ca_b64).into_diagnostic()?;
    let cert = STANDARD.decode(cert_b64).into_diagnostic()?;
    let key = STANDARD.decode(key_b64).into_diagnostic()?;

    Ok(Some(CliMtlsBundle { ca, cert, key }))
}

fn cli_mtls_dir(name: &str) -> Result<PathBuf> {
    Ok(xdg_config_dir()?
        .join("navigator")
        .join("clusters")
        .join(name)
        .join("mtls"))
}

fn cli_mtls_temp_dir(name: &str) -> Result<PathBuf> {
    Ok(cli_mtls_dir(name)?.with_extension("tmp"))
}

fn cli_mtls_backup_dir(name: &str) -> Result<PathBuf> {
    Ok(cli_mtls_dir(name)?.with_extension("bak"))
}

fn store_cli_mtls_bundle(name: &str, bundle: CliMtlsBundle) -> Result<()> {
    let dir = cli_mtls_dir(name)?;
    let temp_dir = cli_mtls_temp_dir(name)?;
    let backup_dir = cli_mtls_backup_dir(name)?;

    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", temp_dir.display()))?;
    }

    std::fs::create_dir_all(&temp_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", temp_dir.display()))?;

    std::fs::write(temp_dir.join("ca.crt"), bundle.ca)
        .into_diagnostic()
        .wrap_err("failed to write ca.crt")?;
    std::fs::write(temp_dir.join("tls.crt"), bundle.cert)
        .into_diagnostic()
        .wrap_err("failed to write tls.crt")?;
    std::fs::write(temp_dir.join("tls.key"), bundle.key)
        .into_diagnostic()
        .wrap_err("failed to write tls.key")?;

    validate_cli_mtls_bundle_dir(&temp_dir)?;

    let had_backup = if dir.exists() {
        if backup_dir.exists() {
            std::fs::remove_dir_all(&backup_dir)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove {}", backup_dir.display()))?;
        }
        std::fs::rename(&dir, &backup_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to rename {}", dir.display()))?;
        true
    } else {
        false
    };

    if let Err(err) = std::fs::rename(&temp_dir, &dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to move {}", temp_dir.display()))
    {
        if had_backup {
            let _ = std::fs::rename(&backup_dir, &dir);
        }
        return Err(err);
    }

    if had_backup {
        std::fs::remove_dir_all(&backup_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", backup_dir.display()))?;
    }
    Ok(())
}

fn validate_cli_mtls_bundle_dir(dir: &std::path::Path) -> Result<()> {
    for name in ["ca.crt", "tls.crt", "tls.key"] {
        let path = dir.join(name);
        let metadata = std::fs::metadata(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        if metadata.len() == 0 {
            return Err(miette::miette!("{} is empty", path.display()));
        }
    }
    Ok(())
}
