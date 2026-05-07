// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `generate-certs` subcommand: bootstrap mTLS PKI as Kubernetes Secrets.
//!
//! Invoked by the Helm pre-install/pre-upgrade hook to create the gateway's
//! server and client TLS Secrets. Replaces the previous alpine + openssl
//! shell job by reusing [`openshell_bootstrap::pki::generate_pki`].
//!
//! Idempotency:
//! - Both target Secrets exist → log and exit 0.
//! - Exactly one exists → error with a `kubectl delete` recovery hint.
//! - Neither exists → generate PKI and POST both Secrets.

use clap::Args;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_bootstrap::pki::{PkiBundle, generate_pki};
use std::collections::BTreeMap;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Args, Debug)]
pub struct CertgenArgs {
    /// Kubernetes namespace to create Secrets in.
    /// Default comes from `POD_NAMESPACE`, which the Helm hook injects via
    /// the downward API.
    #[arg(long, env = "POD_NAMESPACE")]
    namespace: String,

    /// Name of the server TLS Secret (`kubernetes.io/tls`) to create.
    #[arg(long)]
    server_secret_name: String,

    /// Name of the client TLS Secret (`kubernetes.io/tls`) to create.
    #[arg(long)]
    client_secret_name: String,

    /// Extra Subject Alternative Name for the server certificate. Repeatable.
    /// Auto-detected as an IP address or DNS name.
    #[arg(long = "server-san", value_name = "SAN")]
    server_sans: Vec<String>,

    /// Print the generated PEM materials to stdout instead of creating
    /// Kubernetes Secrets. For local debugging.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    SkipExists,
    PartialState,
    Create,
}

fn decide(server_exists: bool, client_exists: bool) -> Action {
    match (server_exists, client_exists) {
        (true, true) => Action::SkipExists,
        (false, false) => Action::Create,
        _ => Action::PartialState,
    }
}

pub async fn run(args: CertgenArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bundle = generate_pki(&args.server_sans)?;

    if args.dry_run {
        print_bundle(&bundle);
        return Ok(());
    }

    let client = Client::try_default()
        .await
        .into_diagnostic()
        .wrap_err("failed to construct in-cluster Kubernetes client")?;
    let api: Api<Secret> = Api::namespaced(client, &args.namespace);

    let server_exists = api
        .get_opt(&args.server_secret_name)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read secret {}", args.server_secret_name))?
        .is_some();
    let client_exists = api
        .get_opt(&args.client_secret_name)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read secret {}", args.client_secret_name))?
        .is_some();

    match decide(server_exists, client_exists) {
        Action::SkipExists => {
            info!(
                namespace = %args.namespace,
                server = %args.server_secret_name,
                client = %args.client_secret_name,
                "PKI secrets already exist, skipping."
            );
            return Ok(());
        }
        Action::PartialState => {
            return Err(miette::miette!(
                "partial PKI state in namespace {ns}: exactly one of {server} / {client} \
                 exists. Recover with: kubectl delete secret -n {ns} {server} {client}",
                ns = args.namespace,
                server = args.server_secret_name,
                client = args.client_secret_name,
            ));
        }
        Action::Create => {}
    }

    let server_secret = tls_secret(
        &args.server_secret_name,
        &bundle.server_cert_pem,
        &bundle.server_key_pem,
        &bundle.ca_cert_pem,
    );
    let client_secret = tls_secret(
        &args.client_secret_name,
        &bundle.client_cert_pem,
        &bundle.client_key_pem,
        &bundle.ca_cert_pem,
    );

    api.create(&PostParams::default(), &server_secret)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create secret {}", args.server_secret_name))?;
    api.create(&PostParams::default(), &client_secret)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create secret {}", args.client_secret_name))?;

    info!(
        namespace = %args.namespace,
        server = %args.server_secret_name,
        client = %args.client_secret_name,
        "PKI secrets created."
    );
    Ok(())
}

fn tls_secret(name: &str, crt_pem: &str, key_pem: &str, ca_pem: &str) -> Secret {
    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        ByteString(crt_pem.as_bytes().to_vec()),
    );
    data.insert(
        "tls.key".to_string(),
        ByteString(key_pem.as_bytes().to_vec()),
    );
    data.insert("ca.crt".to_string(), ByteString(ca_pem.as_bytes().to_vec()));
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".to_string()),
        data: Some(data),
        ..Default::default()
    }
}

fn print_bundle(bundle: &PkiBundle) {
    println!("# CA certificate\n{}", bundle.ca_cert_pem);
    println!("# Server certificate\n{}", bundle.server_cert_pem);
    println!("# Server key\n{}", bundle.server_key_pem);
    println!("# Client certificate\n{}", bundle.client_cert_pem);
    println!("# Client key\n{}", bundle.client_key_pem);
}

#[cfg(test)]
mod tests {
    use super::{Action, decide, tls_secret};

    #[test]
    fn decide_skip_when_both_exist() {
        assert_eq!(decide(true, true), Action::SkipExists);
    }

    #[test]
    fn decide_create_when_neither_exists() {
        assert_eq!(decide(false, false), Action::Create);
    }

    #[test]
    fn decide_partial_when_only_server_exists() {
        assert_eq!(decide(true, false), Action::PartialState);
    }

    #[test]
    fn decide_partial_when_only_client_exists() {
        assert_eq!(decide(false, true), Action::PartialState);
    }

    #[test]
    fn tls_secret_has_kubernetes_io_tls_type_and_three_keys() {
        let s = tls_secret("foo", "CRT-PEM", "KEY-PEM", "CA-PEM");
        assert_eq!(s.metadata.name.as_deref(), Some("foo"));
        assert_eq!(s.type_.as_deref(), Some("kubernetes.io/tls"));
        let data = s.data.expect("data set");
        assert_eq!(data.len(), 3);
        assert_eq!(data["tls.crt"].0, b"CRT-PEM");
        assert_eq!(data["tls.key"].0, b"KEY-PEM");
        assert_eq!(data["ca.crt"].0, b"CA-PEM");
    }
}
