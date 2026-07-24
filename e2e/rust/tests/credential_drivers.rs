// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-credential-drivers")]

use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

const CREDENTIAL_KEY: &str = "OPENAI_API_KEY";
const VAULT_POLICY: &str = r#"path "secret/data/openshell/provider-credentials/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/openshell/provider-credentials/*" {
  capabilities = ["read", "delete", "list"]
}
"#;

fn unique_suffix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{}-{millis}", std::process::id())
}

fn namespace() -> String {
    std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".to_string())
}

fn credential_driver() -> String {
    std::env::var("OPENSHELL_E2E_CREDENTIAL_DRIVER")
        .unwrap_or_else(|_| "kubernetes-secrets".to_string())
}

fn vault_namespace() -> String {
    std::env::var("OPENSHELL_E2E_VAULT_NAMESPACE").unwrap_or_else(|_| "vault".to_string())
}

fn vault_pod() -> String {
    std::env::var("OPENSHELL_E2E_VAULT_POD").unwrap_or_else(|_| "vault-0".to_string())
}

fn vault_token() -> String {
    std::env::var("OPENSHELL_E2E_VAULT_TOKEN").unwrap_or_else(|_| "root".to_string())
}

fn managed_kubernetes_secret_name(provider_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider_name.as_bytes());
    hasher.update([0]);
    hasher.update(CREDENTIAL_KEY.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    format!("openshell-cred-{}", &hex[..40])
}

fn managed_vault_path(provider_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider_name.as_bytes());
    hasher.update([0]);
    hasher.update(CREDENTIAL_KEY.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    format!("openshell/provider-credentials/{}", &hex[..40])
}

fn contains_placeholder_for_env_key(output: &str, key: &str) -> bool {
    let legacy = format!("openshell:resolve:env:{key}");
    let revision_prefix = "openshell:resolve:env:v";
    let revision_suffix = format!("_{key}");
    output.split_whitespace().any(|token| {
        token == legacy || (token.starts_with(revision_prefix) && token.ends_with(&revision_suffix))
    })
}

fn kubectl_command() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        && !context.trim().is_empty()
    {
        cmd.arg("--context").arg(context);
    }
    cmd
}

async fn kubectl(args: &[&str]) -> Result<String, String> {
    let output = kubectl_command()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|err| format!("failed to spawn kubectl {args:?}: {err}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(format!(
            "kubectl {args:?} failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }
    Ok(combined)
}

async fn bao(args: &[&str]) -> Result<String, String> {
    let namespace = vault_namespace();
    let pod = vault_pod();
    let token = vault_token();
    let token_env = format!("BAO_TOKEN={token}");
    let mut command = kubectl_command();
    command.args(["-n", &namespace, "exec", &pod, "--", "env", &token_env, "bao"]);
    command.args(args);
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|err| format!("failed to spawn bao {args:?}: {err}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(format!(
            "bao {args:?} failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }
    Ok(combined)
}

async fn bao_with_stdin(args: &[&str], stdin: &str) -> Result<String, String> {
    let namespace = vault_namespace();
    let pod = vault_pod();
    let token = vault_token();
    let token_env = format!("BAO_TOKEN={token}");
    let mut command = kubectl_command();
    command.args([
        "-n", &namespace, "exec", "-i", &pod, "--", "env", &token_env, "bao",
    ]);
    command.args(args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to spawn bao {args:?}: {err}"))?;
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open bao stdin".to_string())?;
    child_stdin
        .write_all(stdin.as_bytes())
        .await
        .map_err(|err| format!("failed to write bao stdin: {err}"))?;
    drop(child_stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|err| format!("failed to wait for bao {args:?}: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(format!(
            "bao {args:?} failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }
    Ok(combined)
}

async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

async fn create_provider(name: &str, secret_value: &str) -> Result<String, String> {
    let credential = format!("{CREDENTIAL_KEY}={secret_value}");
    let (output, code) = run_cli(&[
        "provider",
        "create",
        "--name",
        name,
        "--type",
        "openai",
        "--credential",
        &credential,
    ])
    .await;
    let clean = strip_ansi(&output);
    if code != 0 {
        return Err(format!("provider create {name} failed (exit {code}):\n{clean}"));
    }
    Ok(clean)
}

async fn assert_provider_get_does_not_expose_secret(
    provider_name: &str,
    secret_value: &str,
) -> Result<(), String> {
    let (output, code) = run_cli(&["provider", "get", provider_name]).await;
    let clean = strip_ansi(&output);
    if code != 0 {
        return Err(format!(
            "provider get {provider_name} failed (exit {code}):\n{clean}"
        ));
    }
    if clean.contains(secret_value) {
        return Err(format!(
            "provider get {provider_name} exposed credential material:\n{clean}"
        ));
    }
    Ok(())
}

async fn assert_provider_placeholder_available_in_sandbox(
    provider_name: &str,
    sandbox_name: &str,
    secret_value: &str,
) -> Result<(), String> {
    let guard = SandboxGuard::create(&[
        "--name",
        sandbox_name,
        "--provider",
        provider_name,
        "--no-keep",
        "--no-auto-providers",
        "--no-tty",
        "--",
        "bash",
        "-lc",
        r#"printf '%s\n' "$OPENAI_API_KEY""#,
    ])
    .await?;
    let clean = strip_ansi(&guard.create_output);
    if !contains_placeholder_for_env_key(&clean, CREDENTIAL_KEY) {
        return Err(format!(
            "sandbox {sandbox_name} did not receive provider credential placeholder:\n{clean}"
        ));
    }
    if clean.contains(secret_value) {
        return Err(format!(
            "sandbox {sandbox_name} output exposed credential material:\n{clean}"
        ));
    }
    Ok(())
}

async fn configure_vault_storage() -> Result<(), String> {
    let _ = bao(&["secrets", "enable", "-path=secret", "kv-v2"]).await;
    let _ = bao(&["auth", "enable", "kubernetes"]).await;
    bao(&[
        "write",
        "auth/kubernetes/config",
        "kubernetes_host=https://kubernetes.default.svc",
        "kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    ])
    .await?;
    bao_with_stdin(
        &["policy", "write", "openshell-provider-storage", "-"],
        VAULT_POLICY,
    )
    .await?;
    bao(&[
        "write",
        "auth/kubernetes/role/openshell-gateway",
        "bound_service_account_names=openshell",
        &format!("bound_service_account_namespaces={}", namespace()),
        "policies=openshell-provider-storage",
        "ttl=1h",
    ])
    .await?;
    Ok(())
}

async fn assert_kubernetes_secret_stored(
    provider_name: &str,
    secret_value: &str,
) -> Result<(), String> {
    let namespace = namespace();
    let secret_name = managed_kubernetes_secret_name(provider_name);
    let encoded = kubectl(&[
        "-n",
        &namespace,
        "get",
        "secret",
        &secret_name,
        "-o",
        &format!("jsonpath={{.data.{CREDENTIAL_KEY}}}"),
    ])
    .await?;
    let decoded = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|err| format!("failed to decode Kubernetes Secret value: {err}"))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|err| format!("Kubernetes Secret value was not UTF-8: {err}"))?;
    if decoded != secret_value {
        return Err("Kubernetes Secret stored an unexpected credential value".to_string());
    }
    Ok(())
}

async fn assert_kubernetes_secret_deleted(provider_name: &str) -> Result<(), String> {
    let namespace = namespace();
    let secret_name = managed_kubernetes_secret_name(provider_name);
    match kubectl(&["-n", &namespace, "get", "secret", &secret_name]).await {
        Ok(output) => Err(format!(
            "Kubernetes Secret '{secret_name}' still exists after provider deletion:\n{output}"
        )),
        Err(_) => Ok(()),
    }
}

async fn assert_vault_secret_stored(
    provider_name: &str,
    secret_value: &str,
) -> Result<(), String> {
    let logical_path = managed_vault_path(provider_name);
    let output = bao(&[
        "kv",
        "get",
        "-field=value",
        &format!("secret/{logical_path}"),
    ])
    .await?;
    if output.trim() != secret_value {
        return Err("Vault stored an unexpected credential value".to_string());
    }
    Ok(())
}

async fn assert_vault_secret_deleted(provider_name: &str) -> Result<(), String> {
    let logical_path = managed_vault_path(provider_name);
    match bao(&[
        "kv",
        "get",
        "-field=value",
        &format!("secret/{logical_path}"),
    ])
    .await
    {
        Ok(output) => Err(format!(
            "Vault secret '{logical_path}' still exists after provider deletion:\n{output}"
        )),
        Err(_) => Ok(()),
    }
}

async fn assert_backend_stored(
    driver: &str,
    provider_name: &str,
    secret_value: &str,
) -> Result<(), String> {
    match driver {
        "kubernetes-secrets" => assert_kubernetes_secret_stored(provider_name, secret_value).await,
        "vault" => assert_vault_secret_stored(provider_name, secret_value).await,
        other => Err(format!("unsupported credential driver '{other}'")),
    }
}

async fn assert_backend_deleted(driver: &str, provider_name: &str) -> Result<(), String> {
    match driver {
        "kubernetes-secrets" => assert_kubernetes_secret_deleted(provider_name).await,
        "vault" => assert_vault_secret_deleted(provider_name).await,
        other => Err(format!("unsupported credential driver '{other}'")),
    }
}

#[tokio::test]
async fn provider_credentials_are_stored_in_configured_backend() {
    assert!(
        matches!(
            std::env::var("OPENSHELL_E2E_CREDENTIAL_DRIVERS").as_deref(),
            Ok("1")
        ),
        "run with `mise run e2e:kubernetes:credential-drivers` so the Kubernetes wrapper enables a credential storage driver"
    );

    let driver = credential_driver();
    let suffix = unique_suffix();
    let driver_slug = driver.replace('-', "");
    let provider_name = format!("cred-storage-{driver_slug}-{suffix}");
    let sandbox_name = format!("cred-storage-sandbox-{driver_slug}-{suffix}");
    let secret_value = format!("example-e2e-{driver_slug}-{suffix}");

    delete_provider(&provider_name).await;
    if driver == "vault" {
        configure_vault_storage()
            .await
            .expect("configure Vault storage fixture");
    }

    let result: Result<(), String> = async {
        create_provider(&provider_name, &secret_value).await?;
        assert_provider_get_does_not_expose_secret(&provider_name, &secret_value).await?;
        assert_backend_stored(&driver, &provider_name, &secret_value).await?;
        assert_provider_placeholder_available_in_sandbox(
            &provider_name,
            &sandbox_name,
            &secret_value,
        )
        .await?;
        Ok(())
    }
    .await;

    delete_provider(&provider_name).await;
    assert_backend_deleted(&driver, &provider_name)
        .await
        .expect("credential backend object should be deleted with provider");
    result.expect("credential storage e2e failed");
}
