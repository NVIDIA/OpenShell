// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/gRPC log export support.

use opentelemetry_otlp::LogExporter;

use crate::{OtlpTarget, SetupError};

impl OtlpTarget {
    /// Build a log exporter for this target. Callers attach
    /// [`Self::resource`] to it.
    pub fn log_exporter(&self) -> Result<LogExporter, SetupError> {
        Ok(self
            .configure(LogExporter::builder().with_tonic())
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{OtlpExportConfig, OtlpTarget, ServiceName, SetupError};

    fn config(endpoint: &str) -> OtlpExportConfig<'_> {
        OtlpExportConfig {
            endpoint,
            service_name: ServiceName::Fixed("openshell-gateway"),
            service_version: Some("1.2.3"),
            resource_attributes: Vec::new(),
        }
    }

    #[test]
    fn empty_endpoint_is_rejected() {
        assert!(matches!(
            OtlpTarget::new(&config("  ")),
            Err(SetupError::EmptyEndpoint)
        ));
    }

    #[test]
    fn malformed_endpoint_is_rejected() {
        assert!(matches!(
            OtlpTarget::new(&config("not a uri")),
            Err(SetupError::InvalidEndpoint { .. })
        ));
    }

    #[tokio::test]
    async fn every_signal_shares_the_target_resource() {
        let target = OtlpTarget::new(&config("http://127.0.0.1:4317")).unwrap();
        target.log_exporter().expect("log exporter");
        target.tracer_provider().expect("tracer provider");
        let value = |key| {
            target
                .resource()
                .get(&opentelemetry::Key::from_static_str(key))
                .map(|value| value.to_string())
        };
        assert_eq!(value("service.name").as_deref(), Some("openshell-gateway"));
        assert_eq!(value("service.version").as_deref(), Some("1.2.3"));
    }
}
