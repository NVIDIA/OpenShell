// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated negative-path client for the governance example smoke suite.

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openshell_core::proto::{
    GetSandboxConfigRequest, NetworkActivitySummary, PolicyChunk, SubmitPolicyAnalysisRequest,
    UpdateConfigRequest, open_shell_client::OpenShellClient,
};
use serde::Serialize;
use tonic::Code;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

#[derive(Serialize)]
struct SandboxJwtClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    sandbox_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: governance-smoke-client <endpoint> <sandbox-name> <sandbox-id> \
        <gateway-signing-key> <gateway-kid> <gateway-id>";
    let endpoint = args.next().ok_or(usage)?;
    let sandbox_name = args.next().ok_or(usage)?;
    let sandbox_id = args.next().ok_or(usage)?;
    let signing_key_path = args.next().ok_or(usage)?;
    let gateway_kid = args.next().ok_or(usage)?;
    let gateway_id = args.next().ok_or(usage)?;
    if args.next().is_some() {
        return Err(usage.into());
    }

    let token = mint_sandbox_token(
        &std::fs::read(signing_key_path)?,
        &gateway_kid,
        &gateway_id,
        &sandbox_id,
    )?;
    let channel = Channel::from_shared(endpoint)?.connect().await?;
    let bearer = AsciiMetadataValue::try_from(format!("Bearer {token}"))?;
    let interceptor = move |mut request: tonic::Request<()>| {
        request
            .metadata_mut()
            .insert("authorization", bearer.clone());
        Ok(request)
    };
    let mut client = OpenShellClient::new(InterceptedService::new(channel, interceptor));

    let before = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox_id.clone(),
        })
        .await?
        .into_inner();
    let mut widened_policy = before
        .policy
        .clone()
        .ok_or("governed sandbox did not have an active policy")?;
    let mut added_rule = widened_policy
        .network_policies
        .values()
        .next()
        .cloned()
        .ok_or("governed policy did not contain a network rule to clone")?;
    added_rule.name = "sandbox-added".to_string();
    let endpoint_to_change = added_rule
        .endpoints
        .first_mut()
        .ok_or("governed policy network rule did not contain an endpoint")?;
    endpoint_to_change.host = "sandbox-added.example".to_string();
    widened_policy
        .network_policies
        .insert("sandbox_added".to_string(), added_rule.clone());

    let policy_result = client
        .update_config(UpdateConfigRequest {
            name: sandbox_name.clone(),
            policy: Some(widened_policy),
            ..Default::default()
        })
        .await;
    expect_permission_denied(policy_result, "unsigned sandbox policy widening")?;

    let proposal_result = client
        .submit_policy_analysis(SubmitPolicyAnalysisRequest {
            name: sandbox_name.clone(),
            proposed_chunks: vec![PolicyChunk {
                rule_name: "sandbox_added".to_string(),
                proposed_rule: Some(added_rule),
                rationale: "authenticated governance bypass regression".to_string(),
                ..Default::default()
            }],
            analysis_mode: "agent_authored".to_string(),
            ..Default::default()
        })
        .await;
    expect_permission_denied(proposal_result, "sandbox-authored policy proposal")?;

    client
        .submit_policy_analysis(SubmitPolicyAnalysisRequest {
            name: sandbox_name,
            network_activity_summaries: vec![NetworkActivitySummary {
                network_activity_count: 1,
                ..Default::default()
            }],
            analysis_mode: "activity".to_string(),
            ..Default::default()
        })
        .await
        .map_err(|status| format!("telemetry-only policy analysis was denied: {status}"))?;

    let after = client
        .get_sandbox_config(GetSandboxConfigRequest { sandbox_id })
        .await?
        .into_inner();
    if after.version != before.version || after.policy_hash != before.policy_hash {
        return Err(format!(
            "denied sandbox requests changed active policy: before version/hash={}/{}, after={}/{}",
            before.version, before.policy_hash, after.version, after.policy_hash
        )
        .into());
    }

    println!("authenticated governance bypasses denied; telemetry accepted; policy unchanged");
    Ok(())
}

fn mint_sandbox_token(
    signing_key_pem: &[u8],
    kid: &str,
    gateway_id: &str,
    sandbox_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let identity = format!("openshell-gateway:{gateway_id}");
    let claims = SandboxJwtClaims {
        sub: format!("spiffe://openshell/sandbox/{sandbox_id}"),
        iss: identity.clone(),
        aud: identity,
        iat: 0,
        exp: 0,
        sandbox_id: sandbox_id.to_string(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_ed_pem(signing_key_pem)?;
    Ok(encode(&header, &claims, &key)?)
}

fn expect_permission_denied<T>(
    result: Result<tonic::Response<T>, tonic::Status>,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(status) if status.code() == Code::PermissionDenied => Ok(()),
        Err(status) => Err(format!(
            "{operation} failed with {}, expected permission denied: {}",
            status.code(),
            status.message()
        )
        .into()),
        Ok(_) => Err(format!("{operation} unexpectedly succeeded").into()),
    }
}
