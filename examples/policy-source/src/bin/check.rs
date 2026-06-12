// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use hyper_util::rt::TokioIo;
use openshell_core::proto::policy_source::v1::policy_source_client::PolicySourceClient;
use openshell_core::proto::policy_source::v1::{GetDocumentRequest, ListDocumentsRequest};
use tokio::net::UnixStream;
use tonic::transport::Endpoint;
use tower::service_fn;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args =
        Args::parse().map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let mut client = connect(args.socket.clone()).await?;

    let policies = client
        .list_policies(ListDocumentsRequest {})
        .await?
        .into_inner()
        .names;
    for expected in &args.expected_policies {
        if !policies.iter().any(|name| name == expected) {
            return Err(format!("missing policy '{expected}' in {policies:?}").into());
        }
        let document = client
            .get_policy(GetDocumentRequest {
                name: expected.clone(),
            })
            .await?
            .into_inner()
            .document;
        if document.is_empty() {
            return Err(format!("policy '{expected}' returned an empty document").into());
        }
        std::str::from_utf8(&document)?;
        eprintln!("policy {expected}: {} bytes", document.len());
    }

    let providers = client
        .list_providers(ListDocumentsRequest {})
        .await?
        .into_inner()
        .names;
    for expected in &args.expected_providers {
        if !providers.iter().any(|name| name == expected) {
            return Err(format!("missing provider '{expected}' in {providers:?}").into());
        }
        let document = client
            .get_provider(GetDocumentRequest {
                name: expected.clone(),
            })
            .await?
            .into_inner()
            .document;
        if document.is_empty() {
            return Err(format!("provider '{expected}' returned an empty document").into());
        }
        std::str::from_utf8(&document)?;
        eprintln!("provider {expected}: {} bytes", document.len());
    }

    Ok(())
}

async fn connect(
    socket_path: PathBuf,
) -> Result<PolicySourceClient<tonic::transport::Channel>, tonic::transport::Error> {
    let connector_path = socket_path.clone();
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = connector_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await?;
    Ok(PolicySourceClient::new(channel))
}

#[derive(Debug)]
struct Args {
    socket: PathBuf,
    expected_policies: Vec<String>,
    expected_providers: Vec<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut socket = PathBuf::from("/tmp/openshell-policy-source.sock");
        let mut expected_policies = Vec::new();
        let mut expected_providers = Vec::new();
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => {
                    let Some(path) = args.next() else {
                        return Err("--socket requires a path".to_string());
                    };
                    socket = PathBuf::from(path);
                }
                "--expect-policy" => {
                    let Some(name) = args.next() else {
                        return Err("--expect-policy requires a name".to_string());
                    };
                    expected_policies.push(name);
                }
                "--expect-provider" => {
                    let Some(name) = args.next() else {
                        return Err("--expect-provider requires a name".to_string());
                    };
                    expected_providers.push(name);
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument: {arg}")),
            }
        }

        Ok(Self {
            socket,
            expected_policies,
            expected_providers,
        })
    }
}

fn print_usage() {
    eprintln!(
        "usage: policy-source-check [--socket PATH] \\
         [--expect-policy NAME ...] [--expect-provider NAME ...]"
    );
}
