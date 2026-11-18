// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! An mTLS gateway's user boundary. The gateway accepts TLS clients without
//! a certificate, so supervisors can authenticate with sandbox tokens, but
//! only a client certificate from the gateway's CA makes a caller a user.
//! Health stays public.
//!
//! Ported from `e2e/python/test_security_tls.py`. The suite needs a gateway
//! registered with mTLS, such as the packaged gateway or the one
//! `e2e/with-docker-gateway.sh` starts.

use std::path::{Path, PathBuf};

use testkit::sdk::raw::proto;
use testkit::sdk::{AuthConfig, ClientConfig, ClientIdentity, OpenShellClient, ServiceStatus};
use testkit::{Context, Error, Gateway, GrpcCode, Result, ResultExt as _};

/// A client with the CLI's certificate calls Health and a user RPC.
#[testkit::test]
async fn client_certificate_authenticates_user(_cx: &mut Context) -> testkit::Result {
    let (gateway, dir) = mtls_gateway()?;
    let mut config = ClientConfig::new(gateway.endpoint.clone());
    config.ca_cert = Some(read(&dir.join("ca.crt"))?);
    config.client_identity = Some(ClientIdentity::new(
        read(&dir.join("tls.crt"))?,
        read(&dir.join("tls.key"))?,
    ));
    let client = connect(config).await?;
    expect_healthy(&client).await?;
    list_sandboxes(&client, &gateway.workspace)
        .await
        .context("list sandboxes with the client certificate")?;
    Ok(())
}

/// A client that trusts the gateway's CA but has no certificate reaches
/// Health, but a user RPC is unauthenticated, with or without a bearer
/// token the gateway can't verify.
#[testkit::test]
async fn ca_only_client_is_not_a_user(_cx: &mut Context) -> testkit::Result {
    let (gateway, dir) = mtls_gateway()?;
    let ca = read(&dir.join("ca.crt"))?;

    let mut anonymous = ClientConfig::new(gateway.endpoint.clone());
    anonymous.ca_cert = Some(ca.clone());
    let client = connect(anonymous).await?;
    expect_healthy(&client).await?;
    expect_unauthenticated(&client, &gateway.workspace, "without a certificate").await?;

    let mut bearer = ClientConfig::new(gateway.endpoint.clone());
    bearer.ca_cert = Some(ca);
    bearer.auth = Some(AuthConfig::oidc("invalid-token"));
    let client = connect(bearer).await?;
    expect_unauthenticated(
        &client,
        &gateway.workspace,
        "with an unverifiable bearer token",
    )
    .await
}

/// The gateway refuses the TLS handshake of a client whose certificate
/// another CA signed, so not even Health answers.
#[testkit::test]
async fn foreign_client_certificate_is_rejected(_cx: &mut Context) -> testkit::Result {
    let (gateway, dir) = mtls_gateway()?;
    let rogue =
        openshell_crypto::pki::generate_simple_self_signed(vec!["rogue-client".to_string()])
            .map_err(|error| Error::msg(error.to_string()))
            .context("generate a self-signed client certificate")?;
    let key = rogue
        .key_pair
        .serialize_pem()
        .map_err(|error| Error::msg(error.to_string()))
        .context("encode the rogue key")?;
    let mut config = ClientConfig::new(gateway.endpoint.clone());
    config.ca_cert = Some(read(&dir.join("ca.crt"))?);
    config.client_identity = Some(ClientIdentity::new(rogue.cert.pem(), key));
    expect_refused(
        &gateway,
        &dir,
        config,
        "a client certificate from another CA",
    )
    .await
}

/// The gateway's port doesn't answer gRPC over plaintext.
#[testkit::test]
async fn plaintext_client_is_rejected(_cx: &mut Context) -> testkit::Result {
    let (gateway, dir) = mtls_gateway()?;
    let endpoint = gateway
        .endpoint
        .strip_prefix("https://")
        .map(|rest| format!("http://{rest}"))
        .ok_or_else(|| Error::msg(format!("{} isn't an https endpoint", gateway.endpoint)))?;
    expect_refused(
        &gateway,
        &dir,
        ClientConfig::new(endpoint),
        "a plaintext connection",
    )
    .await
}

/// The gateway under test, which must be an mTLS gateway, and its mTLS
/// directory.
fn mtls_gateway() -> Result<(Gateway, PathBuf)> {
    let gateway = Gateway::from_env()?;
    let dir = gateway.mtls_dir().map(Path::to_path_buf).ok_or_else(|| {
        Error::msg(format!(
            "this suite needs an mTLS gateway; {}",
            gateway.describe()
        ))
    })?;
    Ok((gateway, dir))
}

async fn connect(config: ClientConfig) -> Result<OpenShellClient> {
    let endpoint = config.gateway.clone();
    OpenShellClient::connect(config)
        .await
        .context(format!("connect to {endpoint}"))
}

async fn expect_healthy(client: &OpenShellClient) -> Result {
    let health = client.health().await.context("health")?;
    testkit::ensure!(
        health.status == ServiceStatus::Healthy,
        "gateway reports {:?}",
        health.status
    );
    Ok(())
}

/// List the workspace's sandboxes, keeping the gateway's status code on
/// failure.
async fn list_sandboxes(client: &OpenShellClient, workspace: &str) -> Result {
    client
        .raw_grpc()
        .list_sandboxes(proto::ListSandboxesRequest {
            workspace_scope: Some(proto::workspace_selector(workspace)),
            ..proto::ListSandboxesRequest::default()
        })
        .await
        .map(drop)
        .map_err(Error::from)
}

async fn expect_unauthenticated(client: &OpenShellClient, workspace: &str, how: &str) -> Result {
    match list_sandboxes(client, workspace).await {
        Ok(()) => Err(Error::msg(format!(
            "the gateway listed sandboxes for a client {how}"
        ))),
        Err(error) if error.grpc_code() == Some(GrpcCode::Unauthenticated) => Ok(()),
        Err(error) => Err(error.context(format!("expected unauthenticated for a client {how}"))),
    }
}

/// Fail unless a client with `config` is refused at the transport: it can't
/// connect, or its Health call fails with a transport error rather than a
/// gRPC answer from the gateway. A CA-only client first reaches Health, so a
/// wrong port or a stopped gateway fails the test instead of passing it.
async fn expect_refused(gateway: &Gateway, dir: &Path, config: ClientConfig, what: &str) -> Result {
    let mut control = ClientConfig::new(gateway.endpoint.clone());
    control.ca_cert = Some(read(&dir.join("ca.crt"))?);
    expect_healthy(&connect(control).await?)
        .await
        .context("the gateway should answer a client that trusts its CA")?;

    let client = match OpenShellClient::connect(config).await {
        Ok(client) => client,
        Err(error) => return expect_transport_error(&error.to_string(), what),
    };
    match client
        .raw_grpc()
        .health(proto::HealthRequest::default())
        .await
    {
        Ok(_) => Err(Error::msg(format!(
            "the gateway answered Health over {what}"
        ))),
        Err(status) => expect_transport_error(&format!("{status:?}"), what),
    }
}

/// Fail unless `error` describes a failed transport, not a gRPC status the
/// gateway chose. A refused TLS handshake and a plaintext request to a TLS
/// port both close the connection, so tonic reports them as transport errors.
fn expect_transport_error(error: &str, what: &str) -> Result {
    let error_lower = error.to_lowercase();
    testkit::ensure!(
        ["transport error", "connection closed", "tls", "handshake"]
            .iter()
            .any(|marker| error_lower.contains(marker)),
        "expected a transport refusal for {what}; got: {error}"
    );
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).context(format!("read {}", path.display()))
}
