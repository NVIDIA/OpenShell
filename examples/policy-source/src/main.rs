// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use openshell_core::proto::policy_source::v1::policy_source_server::{
    PolicySource, PolicySourceServer,
};
use openshell_core::proto::policy_source::v1::{
    Document, GetDocumentRequest, ListDocumentsRequest, ListDocumentsResponse,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

#[derive(Debug, Clone)]
struct FilePolicySource {
    root: PathBuf,
}

#[tonic::async_trait]
impl PolicySource for FilePolicySource {
    async fn list_policies(
        &self,
        _request: Request<ListDocumentsRequest>,
    ) -> Result<Response<ListDocumentsResponse>, Status> {
        Ok(Response::new(ListDocumentsResponse {
            names: list_yaml_documents(&self.root.join("policies")).await?,
        }))
    }

    async fn get_policy(
        &self,
        request: Request<GetDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        Ok(Response::new(Document {
            document: read_yaml_document(&self.root.join("policies"), &request.into_inner().name)
                .await?,
        }))
    }

    async fn list_providers(
        &self,
        _request: Request<ListDocumentsRequest>,
    ) -> Result<Response<ListDocumentsResponse>, Status> {
        Ok(Response::new(ListDocumentsResponse {
            names: list_yaml_documents(&self.root.join("providers")).await?,
        }))
    }

    async fn get_provider(
        &self,
        request: Request<GetDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        Ok(Response::new(Document {
            document: read_yaml_document(&self.root.join("providers"), &request.into_inner().name)
                .await?,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args =
        Args::parse().map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    prepare_socket_path(&args.socket).await?;
    let listener = UnixListener::bind(&args.socket)?;
    let incoming = UnixListenerStream::new(listener);

    eprintln!(
        "serving openshell.policy_source.v1.PolicySource on {} from {}",
        args.socket.display(),
        args.root.display()
    );

    Server::builder()
        .add_service(PolicySourceServer::new(FilePolicySource {
            root: args.root,
        }))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await?;

    let _ = tokio::fs::remove_file(&args.socket).await;
    Ok(())
}

#[derive(Debug)]
struct Args {
    socket: PathBuf,
    root: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut socket = PathBuf::from("/tmp/openshell-policy-source.sock");
        let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundle");
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => {
                    let Some(path) = args.next() else {
                        return Err("--socket requires a path".to_string());
                    };
                    socket = PathBuf::from(path);
                }
                "--root" => {
                    let Some(path) = args.next() else {
                        return Err("--root requires a directory".to_string());
                    };
                    root = PathBuf::from(path);
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => {
                    return Err(format!("unknown argument: {arg}"));
                }
            }
        }

        Ok(Self { socket, root })
    }
}

async fn list_yaml_documents(directory: &Path) -> Result<Vec<String>, Status> {
    let mut entries = tokio::fs::read_dir(directory).await.map_err(|err| {
        Status::internal(format!(
            "failed to read directory {}: {err}",
            directory.display()
        ))
    })?;
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(|err| {
        Status::internal(format!(
            "failed to read directory {}: {err}",
            directory.display()
        ))
    })? {
        let path = entry.path();
        if !is_yaml_path(&path) {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            return Err(Status::internal(format!(
                "file {} does not have a valid UTF-8 stem",
                path.display()
            )));
        };
        validate_document_name(name)?;
        names.push(name.to_string());
    }
    names.sort();
    names.dedup();
    Ok(names)
}

async fn read_yaml_document(directory: &Path, name: &str) -> Result<Vec<u8>, Status> {
    validate_document_name(name)?;
    let mut matches = Vec::new();
    for extension in ["yaml", "yml"] {
        let path = directory.join(format!("{name}.{extension}"));
        match tokio::fs::metadata(&path).await {
            Ok(metadata) if metadata.is_file() => matches.push(path),
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(Status::internal(format!(
                    "failed to inspect {}: {err}",
                    path.display()
                )));
            }
        }
    }
    match matches.as_slice() {
        [] => Err(Status::not_found(format!("document '{name}' not found"))),
        [path] => tokio::fs::read(path)
            .await
            .map_err(|err| Status::internal(format!("failed to read {}: {err}", path.display()))),
        _ => Err(Status::failed_precondition(format!(
            "document '{name}' exists as both .yaml and .yml"
        ))),
    }
}

async fn prepare_socket_path(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            tokio::fs::remove_file(path).await?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a Unix socket", path.display()),
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    Ok(())
}

fn validate_document_name(name: &str) -> Result<(), Status> {
    if name.is_empty() || name.trim() != name {
        return Err(Status::invalid_argument(
            "document name must be non-empty and trimmed",
        ));
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(Status::invalid_argument(format!(
            "document name '{name}' must not contain path separators"
        )));
    }
    Ok(())
}

fn is_yaml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "yaml" || extension == "yml")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn print_usage() {
    eprintln!(
        "usage: openshell-policy-source-example [--socket PATH] [--root DIR]\n\n\
         Defaults:\n  --socket /tmp/openshell-policy-source.sock\n  --root {}/bundle",
        env!("CARGO_MANIFEST_DIR")
    );
}
