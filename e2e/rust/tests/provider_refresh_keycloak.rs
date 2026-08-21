// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

//! End-to-end coverage for provider OAuth refresh recovery against Keycloak.
//!
//! OpenShell itself uses the local gateway's mTLS authentication. Keycloak is
//! only the provider token issuer: the test refreshes a valid grant, revokes
//! its Keycloak session, and verifies that the gateway reports the next
//! refresh as requiring user reauthorization.

use std::io::Write as _;
use std::process::{Output, Stdio};

use openshell_e2e::harness::binary::openshell_cmd;
use serde_json::Value;
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

const PROVIDER_NAME: &str = "e2e-keycloak-refresh";
const PROFILE_ID: &str = "e2e-keycloak-refresh";
const CREDENTIAL_KEY: &str = "KEYCLOAK_ACCESS_TOKEN";

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

async fn run_cli(args: &[&str], env: &[(&str, &str)]) -> Result<Output, String> {
    openshell_cmd()
        .args(args)
        .env("NO_COLOR", "1")
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| format!("run openshell command: {error}"))
}

async fn run_cli_success(args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
    let output = run_cli(args, env).await?;
    let combined = combined_output(&output);
    if !output.status.success() {
        return Err(format!(
            "openshell command failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }
    Ok(combined)
}

async fn acquire_keycloak_grant(
    issuer: &str,
    username: &str,
    password: &str,
) -> Result<(String, String), String> {
    let token_endpoint = format!("{issuer}/protocol/openid-connect/token");
    let username_form = format!("username={username}");
    let password_form = format!("password={password}");
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--request",
            "POST",
            &token_endpoint,
            "--data-urlencode",
            "grant_type=password",
            "--data-urlencode",
            "client_id=openshell-cli",
            "--data-urlencode",
            &username_form,
            "--data-urlencode",
            &password_form,
            "--data-urlencode",
            "scope=openid",
        ])
        .output()
        .await
        .map_err(|error| format!("request Keycloak grant: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Keycloak grant request failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode Keycloak grant response: {error}"))?;
    let access_token = response
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Keycloak grant response omitted access_token".to_string())?;
    let refresh_token = response
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Keycloak grant response omitted refresh_token".to_string())?;
    Ok((access_token.to_string(), refresh_token.to_string()))
}

async fn revoke_keycloak_grant(issuer: &str, refresh_token: &str) -> Result<(), String> {
    let logout_endpoint = format!("{issuer}/protocol/openid-connect/logout");
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--request",
            "POST",
            &logout_endpoint,
            "--data-urlencode",
            "client_id=openshell-cli",
            "--data-urlencode",
            "refresh_token@-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start Keycloak logout request: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "Keycloak logout stdin was not piped".to_string())?
        .write_all(refresh_token.as_bytes())
        .await
        .map_err(|error| format!("write Keycloak logout request: {error}"))?;
    let output = child
        .wait_with_output()
        .await
        .map_err(|error| format!("wait for Keycloak logout request: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Keycloak logout failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn write_profile(issuer: &str) -> Result<NamedTempFile, String> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create provider profile: {error}"))?;
    let profile = format!(
        r#"id: {PROFILE_ID}
display_name: Keycloak provider refresh E2E
category: other
credentials:
  - name: access_token
    env_vars: [{CREDENTIAL_KEY}]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: oauth2_refresh_token
      token_url: {issuer}/protocol/openid-connect/token
      scopes: [openid]
      refresh_before_seconds: 60
      max_lifetime_seconds: 3600
      material:
        - name: client_id
          required: true
        - name: refresh_token
          required: true
          secret: true
endpoints:
  - host: keycloak.test.invalid
    port: 443
    protocol: rest
    access: read-only
    enforcement: enforce
binaries:
  - /usr/bin/curl
"#
    );
    file.write_all(profile.as_bytes())
        .map_err(|error| format!("write provider profile: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush provider profile: {error}"))?;
    Ok(file)
}

async fn delete_provider_resources() {
    let _ = run_cli(&["provider", "delete", PROVIDER_NAME], &[]).await;
    let _ = run_cli(&["provider", "profile", "delete", PROFILE_ID], &[]).await;
}

async fn read_providers_v2_setting() -> Result<Option<String>, String> {
    let output = run_cli(&["settings", "get", "--global", "--json"], &[]).await?;
    if !output.status.success() {
        return Err(format!(
            "read global settings failed (exit {:?}):\n{}",
            output.status.code(),
            combined_output(&output)
        ));
    }
    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode global settings: {error}"))?;
    let value = response
        .get("settings")
        .and_then(|settings| settings.get("providers_v2_enabled"))
        .and_then(Value::as_str)
        .filter(|value| *value != "<unset>")
        .map(ToString::to_string);
    Ok(value)
}

async fn restore_providers_v2_setting(previous: Option<&str>) -> Result<(), String> {
    if let Some(value) = previous {
        run_cli_success(
            &[
                "settings",
                "set",
                "--global",
                "--key",
                "providers_v2_enabled",
                "--value",
                value,
                "--yes",
            ],
            &[],
        )
        .await?;
    } else {
        run_cli_success(
            &[
                "settings",
                "delete",
                "--global",
                "--key",
                "providers_v2_enabled",
                "--yes",
            ],
            &[],
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn revoked_refresh_grant_requires_user_reauthorization() -> Result<(), String> {
    let issuer = std::env::var("OPENSHELL_E2E_OIDC_ISSUER")
        .map_err(|_| "OPENSHELL_E2E_OIDC_ISSUER is required".to_string())?;
    let username = std::env::var("OPENSHELL_E2E_OIDC_USERNAME")
        .map_err(|_| "OPENSHELL_E2E_OIDC_USERNAME is required".to_string())?;
    let password = std::env::var("OPENSHELL_E2E_OIDC_PASSWORD")
        .map_err(|_| "OPENSHELL_E2E_OIDC_PASSWORD is required".to_string())?;
    let previous_providers_v2_setting = read_providers_v2_setting().await?;
    let (access_token, refresh_token) =
        acquire_keycloak_grant(&issuer, &username, &password).await?;
    let profile = write_profile(&issuer)?;
    let profile_path = profile.path().to_string_lossy().into_owned();

    delete_provider_resources().await;
    let result = async {
        run_cli_success(
            &[
                "settings",
                "set",
                "--global",
                "--key",
                "providers_v2_enabled",
                "--value",
                "true",
                "--yes",
            ],
            &[],
        )
        .await?;
        run_cli_success(
            &["provider", "profile", "import", "--file", &profile_path],
            &[],
        )
        .await?;
        run_cli_success(
            &[
                "provider",
                "create",
                "--name",
                PROVIDER_NAME,
                "--type",
                PROFILE_ID,
                "--credential",
                CREDENTIAL_KEY,
            ],
            &[(CREDENTIAL_KEY, &access_token)],
        )
        .await?;
        run_cli_success(
            &[
                "provider",
                "refresh",
                "configure",
                PROVIDER_NAME,
                "--credential-key",
                CREDENTIAL_KEY,
                "--strategy",
                "oauth2-refresh-token",
                "--material",
                "client_id=openshell-cli",
                "--secret-material-env",
                "refresh_token=KEYCLOAK_REFRESH_TOKEN",
            ],
            &[("KEYCLOAK_REFRESH_TOKEN", &refresh_token)],
        )
        .await?;

        run_cli_success(
            &[
                "provider",
                "refresh",
                "rotate",
                PROVIDER_NAME,
                "--credential-key",
                CREDENTIAL_KEY,
            ],
            &[],
        )
        .await?;
        let valid_status = run_cli_success(
            &[
                "provider",
                "refresh",
                "status",
                PROVIDER_NAME,
                "--credential-key",
                CREDENTIAL_KEY,
            ],
            &[],
        )
        .await?;
        if !valid_status.contains("refreshed") {
            return Err(format!(
                "valid Keycloak refresh did not reach refreshed state:\n{valid_status}"
            ));
        }

        revoke_keycloak_grant(&issuer, &refresh_token).await?;
        let failed_rotation = run_cli(
            &[
                "provider",
                "refresh",
                "rotate",
                PROVIDER_NAME,
                "--credential-key",
                CREDENTIAL_KEY,
            ],
            &[],
        )
        .await?;
        let failed_rotation_output = combined_output(&failed_rotation);
        if failed_rotation.status.success() || !failed_rotation_output.contains("invalid_grant") {
            return Err(format!(
                "revoked Keycloak refresh did not fail with invalid_grant:\n{failed_rotation_output}"
            ));
        }

        let revoked_status = run_cli_success(
            &[
                "provider",
                "refresh",
                "status",
                PROVIDER_NAME,
                "--credential-key",
                CREDENTIAL_KEY,
            ],
            &[],
        )
        .await?;
        for expected in [
            "reauthorization_required",
            "reauthorize",
            "oauth_invalid_grant",
        ] {
            if !revoked_status.contains(expected) {
                return Err(format!(
                    "revoked refresh status omitted {expected}:\n{revoked_status}"
                ));
            }
        }
        if revoked_status.contains("292278994") {
            return Err(format!(
                "parked refresh rendered the i64::MAX scheduling sentinel as a date:\n{revoked_status}"
            ));
        }
        Ok(())
    }
    .await;

    delete_provider_resources().await;
    let cleanup_result =
        restore_providers_v2_setting(previous_providers_v2_setting.as_deref()).await;
    match (result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(test_error), Ok(())) => Err(test_error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(test_error), Err(cleanup_error)) => Err(format!(
            "{test_error}\ncleanup also failed: {cleanup_error}"
        )),
    }
}
