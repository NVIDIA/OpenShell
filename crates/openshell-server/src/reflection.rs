// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public gateway gRPC reflection service.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use prost::Message;
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto, FileDescriptorSet};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::server_reflection_response::MessageResponse;
use tonic_reflection::pb::v1::server_reflection_server::{
    ServerReflection, ServerReflectionServer,
};
use tonic_reflection::pb::v1::{
    ExtensionNumberResponse, FileDescriptorResponse, ListServiceResponse, ServerReflectionRequest,
    ServerReflectionResponse, ServiceResponse,
};

use openshell_core::Config;

use crate::multiplex::GrpcRateLimiter;

const REFLECTED_PROTO_ROOTS: &[&str] = &["openshell.proto"];
const ADVERTISED_SERVICES: &[&str] = &["openshell.v1.OpenShell"];

pub type GatewayReflectionServer = ServerReflectionServer<GatewayReflectionService>;

/// Decode and filter the compiled descriptors to the public gateway schema.
pub fn gateway_reflection_descriptor_set() -> Result<FileDescriptorSet, prost::DecodeError> {
    let mut descriptor_set = FileDescriptorSet::decode(openshell_core::FILE_DESCRIPTOR_SET)?;
    let mut included: BTreeSet<String> = REFLECTED_PROTO_ROOTS
        .iter()
        .map(|name| (*name).to_string())
        .collect();

    loop {
        let before = included.len();
        for file in &descriptor_set.file {
            if file
                .name
                .as_ref()
                .is_some_and(|name| included.contains(name))
            {
                included.extend(file.dependency.iter().cloned());
            }
        }
        if included.len() == before {
            break;
        }
    }

    descriptor_set.file.retain(|file| {
        file.name
            .as_ref()
            .is_some_and(|name| included.contains(name))
    });
    Ok(descriptor_set)
}

/// Build the immutable reflection index once at gateway service startup.
pub fn build_gateway_reflection_service(
    config: &Config,
) -> Result<GatewayReflectionServer, prost::DecodeError> {
    let mut descriptors = gateway_reflection_descriptor_set()?;
    descriptors
        .file
        .extend(FileDescriptorSet::decode(tonic_reflection::pb::v1::FILE_DESCRIPTOR_SET)?.file);

    let state = ReflectionState::new(descriptors);
    Ok(ServerReflectionServer::new(GatewayReflectionService {
        state: Arc::new(state),
        limiter: GrpcRateLimiter::from_config(config),
    }))
}

#[derive(Debug)]
struct ReflectionState {
    files: HashMap<String, Arc<FileDescriptorProto>>,
    symbols: HashMap<String, Arc<FileDescriptorProto>>,
}

impl ReflectionState {
    fn new(descriptors: FileDescriptorSet) -> Self {
        let mut state = Self {
            files: HashMap::new(),
            symbols: HashMap::new(),
        };
        for descriptor in descriptors.file {
            let Some(name) = descriptor.name.clone() else {
                continue;
            };
            let descriptor = Arc::new(descriptor);
            state.process_file(descriptor.clone());
            state.files.insert(name, descriptor);
        }
        state
    }

    fn process_file(&mut self, file: Arc<FileDescriptorProto>) {
        let prefix = file.package.as_deref().unwrap_or_default().to_string();
        for message in &file.message_type {
            self.process_message(file.clone(), &prefix, message);
        }
        for enumeration in &file.enum_type {
            self.process_enum(file.clone(), &prefix, enumeration);
        }
        for service in &file.service {
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
        file: Arc<FileDescriptorProto>,
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
        file: Arc<FileDescriptorProto>,
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

    fn encode_file(file: &FileDescriptorProto) -> Result<Vec<u8>, Status> {
        let mut encoded = Vec::new();
        file.encode(&mut encoded)
            .map_err(|_| Status::internal("failed to encode reflection descriptor"))?;
        Ok(encoded)
    }

    fn file_by_name(&self, name: &str) -> Result<Vec<u8>, Status> {
        self.files.get(name).map_or_else(
            || Err(Status::not_found(format!("file '{name}' not found"))),
            |file| Self::encode_file(file),
        )
    }

    fn file_by_symbol(&self, symbol: &str) -> Result<Vec<u8>, Status> {
        self.symbols.get(symbol).map_or_else(
            || Err(Status::not_found(format!("symbol '{symbol}' not found"))),
            |file| Self::encode_file(file),
        )
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
                    Some(MessageRequest::FileByFilename(name)) => {
                        state.file_by_name(name).map(|descriptor| {
                            MessageResponse::FileDescriptorResponse(FileDescriptorResponse {
                                file_descriptor_proto: vec![descriptor],
                            })
                        })
                    }
                    Some(MessageRequest::FileContainingSymbol(symbol)) => {
                        state.file_by_symbol(symbol).map(|descriptor| {
                            MessageResponse::FileDescriptorResponse(FileDescriptorResponse {
                                file_descriptor_proto: vec![descriptor],
                            })
                        })
                    }
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
                        let _ = responses_tx.send(Err(status)).await;
                        return;
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
