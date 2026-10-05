// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public gateway gRPC reflection service.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use prost_reflect::{DescriptorError, DescriptorPool, FileDescriptor};
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::server_reflection_response::MessageResponse;
use tonic_reflection::pb::v1::server_reflection_server::{
    ServerReflection, ServerReflectionServer,
};
use tonic_reflection::pb::v1::{
    ErrorResponse, ExtensionNumberResponse, FileDescriptorResponse, ListServiceResponse,
    ServerReflectionRequest, ServerReflectionResponse, ServiceResponse,
};

use openshell_core::Config;

use crate::multiplex::GrpcRateLimiter;

const REFLECTED_PROTO_ROOTS: &[&str] = &["openshell.proto"];
const ADVERTISED_SERVICES: &[&str] = &["openshell.v1.OpenShell"];

pub type GatewayReflectionServer = ServerReflectionServer<GatewayReflectionService>;

/// Decode and filter the compiled descriptors to the public gateway schema.
pub fn gateway_reflection_descriptors() -> Result<Vec<FileDescriptor>, DescriptorError> {
    let descriptor_pool = DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)?;
    let mut included: BTreeSet<String> = REFLECTED_PROTO_ROOTS
        .iter()
        .map(|name| (*name).to_string())
        .collect();

    loop {
        let before = included.len();
        for file in descriptor_pool.files() {
            if included.contains(file.name()) {
                included.extend(
                    file.dependencies()
                        .map(|dependency| dependency.name().to_string()),
                );
            }
        }
        if included.len() == before {
            break;
        }
    }

    Ok(descriptor_pool
        .files()
        .filter(|file| included.contains(file.name()))
        .collect())
}

/// Build the immutable reflection index once at gateway service startup.
pub fn build_gateway_reflection_service(
    config: &Config,
) -> Result<GatewayReflectionServer, DescriptorError> {
    let mut descriptors = gateway_reflection_descriptors()?;
    descriptors
        .extend(DescriptorPool::decode(tonic_reflection::pb::v1::FILE_DESCRIPTOR_SET)?.files());

    let state = ReflectionState::new(descriptors);
    Ok(ServerReflectionServer::new(GatewayReflectionService {
        state: Arc::new(state),
        limiter: GrpcRateLimiter::from_config(config),
    }))
}

#[derive(Debug)]
struct ReflectionState {
    files: HashMap<String, Arc<ReflectionFile>>,
    symbols: HashMap<String, Arc<ReflectionFile>>,
}

#[derive(Debug)]
struct ReflectionFile {
    descriptor: FileDescriptorProto,
    encoded: Vec<u8>,
}

impl ReflectionState {
    fn new(descriptors: Vec<FileDescriptor>) -> Self {
        let mut state = Self {
            files: HashMap::new(),
            symbols: HashMap::new(),
        };
        for descriptor in descriptors {
            let name = descriptor.name().to_string();
            let descriptor = Arc::new(ReflectionFile {
                descriptor: descriptor.file_descriptor_proto().clone(),
                encoded: descriptor.encode_to_vec(),
            });
            state.process_file(descriptor.clone());
            state.files.insert(name, descriptor);
        }
        state
    }

    fn process_file(&mut self, file: Arc<ReflectionFile>) {
        let prefix = file
            .descriptor
            .package
            .as_deref()
            .unwrap_or_default()
            .to_string();
        for message in &file.descriptor.message_type {
            self.process_message(file.clone(), &prefix, message);
        }
        for enumeration in &file.descriptor.enum_type {
            self.process_enum(file.clone(), &prefix, enumeration);
        }
        for service in &file.descriptor.service {
            let Some(name) = service.name.as_deref() else {
                continue;
            };
            let service_name = qualified_name(&prefix, name);
            self.symbols.insert(service_name.clone(), file.clone());
            for method in &service.method {
                if let Some(name) = method.name.as_deref() {
                    self.symbols
                        .insert(qualified_name(&service_name, name), file.clone());
                }
            }
        }
    }

    fn process_message(
        &mut self,
        file: Arc<ReflectionFile>,
        prefix: &str,
        message: &DescriptorProto,
    ) {
        let Some(name) = message.name.as_deref() else {
            return;
        };
        let message_name = qualified_name(prefix, name);
        self.symbols.insert(message_name.clone(), file.clone());
        for nested in &message.nested_type {
            self.process_message(file.clone(), &message_name, nested);
        }
        for enumeration in &message.enum_type {
            self.process_enum(file.clone(), &message_name, enumeration);
        }
        for field in &message.field {
            if let Some(name) = field.name.as_deref() {
                self.symbols
                    .insert(qualified_name(&message_name, name), file.clone());
            }
        }
        for oneof in &message.oneof_decl {
            if let Some(name) = oneof.name.as_deref() {
                self.symbols
                    .insert(qualified_name(&message_name, name), file.clone());
            }
        }
    }

    fn process_enum(
        &mut self,
        file: Arc<ReflectionFile>,
        prefix: &str,
        enumeration: &EnumDescriptorProto,
    ) {
        let Some(name) = enumeration.name.as_deref() else {
            return;
        };
        let enum_name = qualified_name(prefix, name);
        self.symbols.insert(enum_name.clone(), file.clone());
        for value in &enumeration.value {
            if let Some(name) = value.name.as_deref() {
                self.symbols
                    .insert(qualified_name(&enum_name, name), file.clone());
            }
        }
    }

    fn file_by_name(&self, name: &str) -> Result<Arc<ReflectionFile>, Status> {
        self.files
            .get(name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("file '{name}' not found")))
    }

    fn file_by_symbol(&self, symbol: &str) -> Result<Arc<ReflectionFile>, Status> {
        self.symbols
            .get(symbol)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("symbol '{symbol}' not found")))
    }

    fn file_with_dependencies(
        &self,
        file: Arc<ReflectionFile>,
        sent: &mut BTreeSet<String>,
    ) -> Result<Vec<Vec<u8>>, Status> {
        let mut descriptors = Vec::new();
        self.collect_file_with_dependencies(file, sent, &mut descriptors)?;
        Ok(descriptors)
    }

    fn collect_file_with_dependencies(
        &self,
        file: Arc<ReflectionFile>,
        sent: &mut BTreeSet<String>,
        descriptors: &mut Vec<Vec<u8>>,
    ) -> Result<(), Status> {
        let name = file
            .descriptor
            .name
            .as_deref()
            .ok_or_else(|| Status::internal("reflection descriptor is missing its filename"))?;
        if !sent.insert(name.to_string()) {
            return Ok(());
        }

        for dependency in &file.descriptor.dependency {
            let dependency = self.files.get(dependency).cloned().ok_or_else(|| {
                Status::internal(format!(
                    "reflection descriptor '{name}' has unavailable dependency '{dependency}'"
                ))
            })?;
            self.collect_file_with_dependencies(dependency, sent, descriptors)?;
        }
        descriptors.push(file.encoded.clone());
        Ok(())
    }
}

fn qualified_name(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}.{name}")
    }
}

/// Reflection implementation with a quota charged for every stream message.
#[derive(Clone, Debug)]
pub struct GatewayReflectionService {
    state: Arc<ReflectionState>,
    limiter: Option<GrpcRateLimiter>,
}

#[tonic::async_trait]
impl ServerReflection for GatewayReflectionService {
    type ServerReflectionInfoStream = ReflectionResponseStream;

    async fn server_reflection_info(
        &self,
        request: Request<Streaming<ServerReflectionRequest>>,
    ) -> Result<Response<Self::ServerReflectionInfoStream>, Status> {
        let mut requests = request.into_inner();
        let (responses_tx, responses_rx) = mpsc::channel(1);
        let state = self.state.clone();
        let limiter = self.limiter.clone();

        tokio::spawn(async move {
            let mut sent_descriptors = BTreeSet::new();
            while let Some(request) = requests.next().await {
                let Ok(request) = request else {
                    return;
                };
                if limiter.as_ref().is_some_and(|limiter| !limiter.allow()) {
                    let _ = responses_tx
                        .send(Err(Status::resource_exhausted(
                            "gRPC reflection query rate limit exceeded",
                        )))
                        .await;
                    return;
                }

                let response = match request.message_request.as_ref() {
                    Some(MessageRequest::FileByFilename(name)) => state
                        .file_by_name(name)
                        .and_then(|descriptor| {
                            state.file_with_dependencies(descriptor, &mut sent_descriptors)
                        })
                        .map(|descriptors| {
                            MessageResponse::FileDescriptorResponse(FileDescriptorResponse {
                                file_descriptor_proto: descriptors,
                            })
                        }),
                    Some(MessageRequest::FileContainingSymbol(symbol)) => state
                        .file_by_symbol(symbol)
                        .and_then(|descriptor| {
                            state.file_with_dependencies(descriptor, &mut sent_descriptors)
                        })
                        .map(|descriptors| {
                            MessageResponse::FileDescriptorResponse(FileDescriptorResponse {
                                file_descriptor_proto: descriptors,
                            })
                        }),
                    Some(MessageRequest::FileContainingExtension(_)) => {
                        Err(Status::not_found("extensions are not supported"))
                    }
                    Some(MessageRequest::AllExtensionNumbersOfType(_)) => {
                        Ok(MessageResponse::AllExtensionNumbersResponse(
                            ExtensionNumberResponse::default(),
                        ))
                    }
                    Some(MessageRequest::ListServices(_)) => {
                        Ok(MessageResponse::ListServicesResponse(ListServiceResponse {
                            service: ADVERTISED_SERVICES
                                .iter()
                                .map(|name| ServiceResponse {
                                    name: (*name).to_string(),
                                })
                                .collect(),
                        }))
                    }
                    None => Err(Status::invalid_argument("invalid MessageRequest")),
                };

                match response {
                    Ok(message_response) => {
                        let response = ServerReflectionResponse {
                            valid_host: request.host.clone(),
                            original_request: Some(request),
                            message_response: Some(message_response),
                        };
                        if responses_tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                    Err(status) => {
                        let response = ServerReflectionResponse {
                            valid_host: request.host.clone(),
                            original_request: Some(request),
                            message_response: Some(MessageResponse::ErrorResponse(ErrorResponse {
                                error_code: status.code() as i32,
                                error_message: status.message().to_string(),
                            })),
                        };
                        if responses_tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReflectionResponseStream {
            inner: tokio_stream::wrappers::ReceiverStream::new(responses_rx),
        }))
    }
}

pub struct ReflectionResponseStream {
    inner: tokio_stream::wrappers::ReceiverStream<Result<ServerReflectionResponse, Status>>,
}

impl Stream for ReflectionResponseStream {
    type Item = Result<ServerReflectionResponse, Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}
