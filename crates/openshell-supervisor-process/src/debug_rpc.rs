// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One-shot debug RPCs exposed via `openshell-sandbox debug-rpc`.
//!
//! Designed for end-to-end verification of the per-sandbox identity
//! flow (issue #1354). A `docker exec` (or `kubectl exec`) into a
//! running sandbox can issue raw sandbox-class gRPC calls without
//! standing up a custom binary inside the sandbox image — useful for
//! confirming the cross-sandbox IDOR guard and renewal semantics.
//!
//! Subcommands:
//! - `get-sandbox-config --sandbox-id <id>` — call `GetSandboxConfig`
//! - `refresh` — call `RefreshSandboxToken`
//! - `show-token` — print a token fingerprint and expiry, never the bearer
//! - `show-principal` — pretty-print the decoded JWT claims
//!   (no signature verification — the supervisor already trusts the
//!   token's origin)

use base64::Engine as _;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::{
    GetSandboxConfigRequest, RefreshSandboxTokenRequest, open_shell_client::OpenShellClient,
};
use sha2::{Digest, Sha256};

use openshell_core::grpc_client::{AuthedChannel, connect_channel_pub};

/// Entry point for the `debug-rpc` subcommand. Returns the process exit
/// code; `main` propagates it.
pub async fn run(args: &[String]) -> Result<i32> {
    let cmd = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| miette::miette!("{}", USAGE))?;

    match cmd {
        "get-sandbox-config" => run_get_sandbox_config(&args[1..]).await,
        "refresh" => run_refresh().await,
        "show-token" => run_show_token(),
        "show-principal" => run_show_principal(),
        "--help" | "-h" => {
            println!("{USAGE}");
            Ok(0)
        }
        other => Err(miette::miette!(
            "unknown debug-rpc command '{other}'\n\n{USAGE}"
        )),
    }
}

const USAGE: &str = "\
usage: openshell-sandbox debug-rpc <command> [options]

commands:
  get-sandbox-config --sandbox-id <UUID>  call GetSandboxConfig
  refresh                                 renew the gateway JWT
  show-token                              print JWT fingerprint and expiry
  show-principal                          print decoded JWT claims

requires: OPENSHELL_ENDPOINT in env, plus one of OPENSHELL_SANDBOX_TOKEN,
OPENSHELL_SANDBOX_TOKEN_FILE, or OPENSHELL_K8S_SA_TOKEN_FILE so the
supervisor's normal token-acquisition path can resolve a JWT.";

async fn open_client() -> Result<OpenShellClient<AuthedChannel>> {
    let endpoint = std::env::var(openshell_core::sandbox_env::ENDPOINT)
        .into_diagnostic()
        .wrap_err("OPENSHELL_ENDPOINT must be set")?;
    let channel = connect_channel_pub(&endpoint).await?;
    Ok(OpenShellClient::new(channel))
}

async fn run_get_sandbox_config(args: &[String]) -> Result<i32> {
    let sandbox_id = parse_flag(args, "--sandbox-id")
        .ok_or_else(|| miette::miette!("get-sandbox-config: --sandbox-id <UUID> is required"))?;
    let mut client = open_client().await?;
    let resp = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await;
    match resp {
        Ok(r) => {
            let inner = r.into_inner();
            println!(
                "version={} policy_hash={} config_revision={}",
                inner.version, inner.policy_hash, inner.config_revision
            );
            Ok(0)
        }
        Err(status) => {
            eprintln!("{}: {}", code_name(status.code()), status.message());
            // Map gRPC status to a non-zero exit so callers can branch
            // (e.g. expect-permission-denied in a shell test).
            Ok(match status.code() {
                tonic::Code::PermissionDenied => 7,
                tonic::Code::Unauthenticated => 16,
                tonic::Code::NotFound => 5,
                _ => 1,
            })
        }
    }
}

async fn run_refresh() -> Result<i32> {
    let mut client = open_client().await?;
    let resp = client
        .refresh_sandbox_token(RefreshSandboxTokenRequest {})
        .await;
    match resp {
        Ok(r) => {
            let inner = r.into_inner();
            print_token_summary(&inner.token, Some(inner.expires_at_ms));
            Ok(0)
        }
        Err(status) => {
            eprintln!("{}: {}", code_name(status.code()), status.message());
            Ok(1)
        }
    }
}

fn run_show_token() -> Result<i32> {
    let token = read_local_token()?;
    print_token_summary(&token, None);
    Ok(0)
}

fn run_show_principal() -> Result<i32> {
    let token = read_local_token()?;
    let claims = decode_token_claims(&token)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&claims).into_diagnostic()?
    );
    Ok(0)
}

fn decode_token_claims(token: &str) -> Result<serde_json::Value> {
    let payload_b64 = token
        .split('.')
        .nth(1)
        .ok_or_else(|| miette::miette!("token has no payload segment"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .into_diagnostic()
        .wrap_err("failed to base64-decode token payload")?;
    serde_json::from_slice(&payload)
        .into_diagnostic()
        .wrap_err("failed to parse token payload as JSON")
}

fn print_token_summary(token: &str, expires_at_ms: Option<i64>) {
    let claims = decode_token_claims(token).unwrap_or(serde_json::Value::Null);
    let fingerprint = token_fingerprint(token);
    let expires_at_ms = expires_at_ms
        .or_else(|| {
            claims
                .get("exp")
                .and_then(serde_json::Value::as_i64)
                .map(|s| s.saturating_mul(1000))
        })
        .unwrap_or_default();
    let sandbox_id = claims
        .get("sandbox_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let subject = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let issuer = claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    println!(
        "fingerprint={fingerprint}\nexpires_at_ms={expires_at_ms}\nsandbox_id={sandbox_id}\nsubject={subject}\nissuer={issuer}"
    );
}

fn token_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("sha256:{}", &hex::encode(digest)[..16])
}

/// Read the token from the env/file/SA-bootstrap chain, but only the
/// "already a gateway JWT" paths — show-token / show-principal don't
/// want to actually exchange an SA token.
fn read_local_token() -> Result<String> {
    if let Ok(t) = std::env::var(openshell_core::sandbox_env::SANDBOX_TOKEN)
        && !t.is_empty()
    {
        return Ok(t);
    }
    if let Ok(path) = std::env::var(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE)
        && !path.is_empty()
    {
        return Ok(std::fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox token from {path}"))?
            .trim()
            .to_string());
    }
    Err(miette::miette!(
        "no in-process gateway JWT available — set OPENSHELL_SANDBOX_TOKEN or \
         OPENSHELL_SANDBOX_TOKEN_FILE. The K8s SA-bootstrap path is intentionally \
         excluded from `show-token` / `show-principal` to avoid issuing a fresh \
         token just for inspection."
    ))
}

fn parse_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == name {
            return iter.next().map(String::as_str);
        }
        if let Some(rest) = a.strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
    }
    None
}

fn code_name(c: tonic::Code) -> &'static str {
    match c {
        tonic::Code::Ok => "OK",
        tonic::Code::Cancelled => "Cancelled",
        tonic::Code::Unknown => "Unknown",
        tonic::Code::InvalidArgument => "InvalidArgument",
        tonic::Code::DeadlineExceeded => "DeadlineExceeded",
        tonic::Code::NotFound => "NotFound",
        tonic::Code::AlreadyExists => "AlreadyExists",
        tonic::Code::PermissionDenied => "PermissionDenied",
        tonic::Code::ResourceExhausted => "ResourceExhausted",
        tonic::Code::FailedPrecondition => "FailedPrecondition",
        tonic::Code::Aborted => "Aborted",
        tonic::Code::OutOfRange => "OutOfRange",
        tonic::Code::Unimplemented => "Unimplemented",
        tonic::Code::Internal => "Internal",
        tonic::Code::Unavailable => "Unavailable",
        tonic::Code::DataLoss => "DataLoss",
        tonic::Code::Unauthenticated => "Unauthenticated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flag_handles_space_separated() {
        let args: Vec<String> = ["--sandbox-id", "abc-123"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(parse_flag(&args, "--sandbox-id"), Some("abc-123"));
    }

    #[test]
    fn parse_flag_handles_equals_separated() {
        let args: Vec<String> = ["--sandbox-id=abc-123".to_string()].to_vec();
        assert_eq!(parse_flag(&args, "--sandbox-id"), Some("abc-123"));
    }

    #[test]
    fn parse_flag_returns_none_when_missing() {
        let args: Vec<String> = ["--other".to_string(), "x".to_string()].to_vec();
        assert!(parse_flag(&args, "--sandbox-id").is_none());
    }
}
