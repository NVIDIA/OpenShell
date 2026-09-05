// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated OTLP exporter for relayed telemetry from supervisors.
//!
//! Uses a separate gRPC client to forward pre-enriched trace data to the
//! configured OTLP collector, bypassing the gateway's own `SdkTracerProvider`
//! which would overwrite resource attributes.

use std::sync::Arc;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use tonic::transport::Channel;
use tracing::{debug, info};

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;

/// Exporter that forwards raw protobuf-encoded trace data to an OTLP collector.
#[derive(Debug, Clone)]
pub struct OtelRelayExporter {
    client: TraceServiceClient<Channel>,
}

impl OtelRelayExporter {
    /// Connect to the OTLP collector at the given gRPC endpoint.
    pub async fn connect(endpoint: &str) -> Result<Self, ConnectError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| ConnectError::InvalidUri(e.to_string()))?
            .connect()
            .await
            .map_err(ConnectError::Transport)?;
        Ok(Self {
            client: TraceServiceClient::new(channel),
        })
    }

    /// Export raw protobuf-encoded `ExportTraceServiceRequest` bytes.
    pub async fn export_raw(&self, trace_data: Vec<u8>) -> Result<(), ExportError> {
        let request = ExportTraceServiceRequest::decode(trace_data.as_slice())
            .map_err(ExportError::Decode)?;

        let mut client = self.client.clone();
        client
            .export(tonic::Request::new(request))
            .await
            .map_err(ExportError::Grpc)?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("failed to decode trace data: {0}")]
    Decode(prost::DecodeError),
    #[error("gRPC export failed: {0}")]
    Grpc(tonic::Status),
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid OTLP endpoint URI: {0}")]
    InvalidUri(String),
    #[error("transport error: {0}")]
    Transport(tonic::transport::Error),
}

/// Create a relay exporter from the gateway's OTLP config, if configured.
pub async fn try_create_exporter(
    config_file: Option<&crate::config_file::ConfigFile>,
) -> Option<Arc<OtelRelayExporter>> {
    let Some(cf) = config_file else {
        debug!("no config file; OTEL relay disabled");
        return None;
    };
    let Some(otlp) = cf.openshell.gateway.otlp.as_ref() else {
        debug!("no [openshell.gateway.otlp] section in config; OTEL relay disabled");
        return None;
    };
    match OtelRelayExporter::connect(&otlp.endpoint).await {
        Ok(exporter) => {
            info!(endpoint = %otlp.endpoint, "OTEL relay exporter connected");
            Some(Arc::new(exporter))
        }
        Err(e) => {
            tracing::warn!(
                endpoint = %otlp.endpoint,
                error = %e,
                "failed to connect OTEL relay exporter; relay disabled"
            );
            None
        }
    }
}
