// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry trace exporting.

use openshell_otel::{OtlpTraceConfig, SdkTracerProvider, ServiceName, SetupError};
pub use openshell_otel::{compute_driver_rpc_layer, compute_driver_rpc_operation};
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;

const SERVICE_NAME: &str = "openshell-driver-vm";
const INSTRUMENTATION_SCOPE: &str = "openshell-driver-vm";

/// Build a tracer provider for the configured OTLP/gRPC endpoint and gateway.
#[must_use]
pub fn provider_for(
    endpoint: Option<&str>,
    gateway_name: Option<&str>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(endpoint.map(|endpoint| {
        OtlpTraceConfig {
            endpoint,
            service_name: ServiceName::Fixed(SERVICE_NAME),
            service_version: Some(openshell_core::VERSION),
            resource_attributes: gateway_name
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| {
                    vec![opentelemetry::KeyValue::new(
                        "openshell.gateway.name",
                        name.to_string(),
                    )]
                })
                .unwrap_or_default(),
        }
    }))
}

/// Build the tracing layer that exports VM-driver spans.
pub fn layer<S>(provider: &SdkTracerProvider) -> openshell_otel::OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer(provider, INSTRUMENTATION_SCOPE)
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::OtlpTestServer;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn compute_driver_rpc_names_are_explicitly_mapped_and_schema_bounded() {
        for (rpc, operation, method) in [
            (
                "GetCapabilities",
                "driver.get_capabilities",
                "get_capabilities",
            ),
            (
                "GetGatewayListenerRequirements",
                "driver.get_gateway_listener_requirements",
                "get_gateway_listener_requirements",
            ),
            (
                "ValidateSandboxCreate",
                "driver.validate_sandbox_create",
                "validate_sandbox_create",
            ),
            ("CreateSandbox", "driver.create_sandbox", "create_sandbox"),
            ("GetSandbox", "driver.get_sandbox", "get_sandbox"),
            ("ListSandboxes", "driver.list_sandboxes", "list_sandboxes"),
            ("StopSandbox", "driver.stop_sandbox", "stop_sandbox"),
            ("StartSandbox", "driver.start_sandbox", "start_sandbox"),
            ("DeleteSandbox", "driver.delete_sandbox", "delete_sandbox"),
            (
                "WatchSandboxes",
                "driver.watch_sandboxes",
                "watch_sandboxes",
            ),
        ] {
            assert_eq!(
                super::compute_driver_rpc_operation(&format!(
                    "/openshell.compute.v1.ComputeDriver/{rpc}"
                )),
                (operation, method),
                "{rpc} must keep an explicit low-cardinality span identity"
            );
        }
        assert_eq!(
            super::compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/AttackerControlled12345"
            ),
            ("driver.unknown", "unknown"),
            "paths absent from the protobuf schema must not create span names"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vm_driver_spans_reach_otlp_collector_with_resource_identity() {
        let collector = OtlpTestServer::start().await;

        let (provider, error) =
            super::provider_for(Some(collector.endpoint()), Some("production-us-west"));
        assert!(error.is_none(), "valid OTLP endpoint should configure");
        let provider = provider.expect("provider");
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("vm.provision", sandbox.id = "sb-otlp");
            drop(span.enter());
            drop(span);
        });
        provider.force_flush().unwrap();
        collector.wait_for_export().await;
        provider.shutdown().unwrap();
        let received = collector.shutdown().await;

        received
            .spans
            .iter()
            .find(|span| span.name == "vm.provision")
            .expect("VM span should reach collector");
        assert!(
            received
                .service_names
                .iter()
                .any(|name| name == "openshell-driver-vm"),
            "VM spans should use a distinct service name, got {:?}",
            received.service_names
        );
        assert_eq!(received.gateway_names, ["production-us-west"]);
    }
}
