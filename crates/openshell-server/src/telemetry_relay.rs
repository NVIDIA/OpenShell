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
use tracing::debug;

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;

/// Exporter that forwards raw protobuf-encoded trace data to an OTLP collector.
#[derive(Debug, Clone)]
pub struct TelemetryRelayExporter {
    client: TraceServiceClient<Channel>,
}

impl TelemetryRelayExporter {
    /// Connect to the OTLP collector at the given gRPC endpoint.
    pub async fn connect(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Channel::from_shared(endpoint.to_string())
            .expect("valid OTLP endpoint URL")
            .connect()
            .await?;
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

/// Create a relay exporter from the gateway's OTLP config, if configured.
pub async fn try_create_exporter(
    config_file: Option<&crate::config_file::ConfigFile>,
) -> Option<Arc<TelemetryRelayExporter>> {
    let otlp = config_file?.openshell.gateway.otlp.as_ref()?;
    match TelemetryRelayExporter::connect(&otlp.endpoint).await {
        Ok(exporter) => {
            debug!(endpoint = %otlp.endpoint, "telemetry relay exporter connected");
            Some(Arc::new(exporter))
        }
        Err(e) => {
            tracing::warn!(
                endpoint = %otlp.endpoint,
                error = %e,
                "failed to connect telemetry relay exporter; relay disabled"
            );
            None
        }
    }
}
