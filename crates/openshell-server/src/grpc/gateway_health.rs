// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standard gRPC health checking ([`grpc.health.v1.Health`]) for the `OpenShell` gateway.
//!
//! # What this means today (process liveness only)
//!
//! Both the legacy `openshell.v1.OpenShell/Health` RPC and
//! `grpc.health.v1.Health/Check` answer **process
//! liveness**: the gateway process is running and accepting gRPC. They do **not** prove database
//! connectivity, compute-driver readiness, inference route configuration, or per-subsystem
//! degradation.
//!
//! # `Watch`
//!
//! `Health::watch` is intentionally [`tonic::Code::Unimplemented`].
//! A future implementation backed by [`tonic_health::server::HealthReporter`] would still be
//! **compatibility-only** until real readiness signals exist (it would emit `SERVING` once and
//! idle, or mirror `Check` without meaningful transitions).
//!
//! # Toward “real” health
//!
//! When the product needs accurate readiness: define criteria (e.g. store ping, driver health),
//! decide per-service vs global status (`openshell.v1.OpenShell` vs `openshell.inference.v1.Inference`),
//! centralize transitions (e.g. `HealthReporter`), then consider implementing `Watch`.

use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_health::pb::{HealthCheckRequest, HealthCheckResponse};

/// Fully-qualified gRPC service name for the main `OpenShell` API (matches generated tonic paths).
pub const OPENSHELL_SERVICE_NAME: &str = "openshell.v1.OpenShell";

/// Fully-qualified gRPC service name for the Inference API multiplexed on the same port.
pub const INFERENCE_SERVICE_NAME: &str = "openshell.inference.v1.Inference";

/// Empty `CheckRequest.service` value: aggregate / process-level probe (not a separate proto service).
const AGGREGATE_SERVICE_NAME: &str = "";

/// Services reported as [`ServingStatus::Serving`] while [`gateway_process_accepting_rpc`] is true.
const KNOWN_SERVICES: &[&str] = &[
    AGGREGATE_SERVICE_NAME,
    OPENSHELL_SERVICE_NAME,
    INFERENCE_SERVICE_NAME,
];

fn is_registered_service(name: &str) -> bool {
    KNOWN_SERVICES.contains(&name)
}

/// Shared process-level gate used by legacy `OpenShell/Health` and standard `grpc.health.v1` `Check`.
///
/// Currently always `true` whenever the handler runs; keep this as the single hook if the gateway
/// ever needs to report not ready while still listening (e.g. draining).
#[must_use]
pub fn gateway_process_accepting_rpc() -> bool {
    true
}

/// Minimal [`Health`] implementation: `Check` mirrors legacy liveness; `Watch` is unimplemented.
#[derive(Clone, Copy, Debug, Default)]
pub struct GatewayStandardHealth;

impl GatewayStandardHealth {
    /// Build a [`HealthServer`] with the same decoding cap as other gateway gRPC services.
    #[must_use]
    pub fn server(max_decoding_message_size: usize) -> HealthServer<Self> {
        HealthServer::new(Self).max_decoding_message_size(max_decoding_message_size)
    }
}

#[tonic::async_trait]
impl Health for GatewayStandardHealth {
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let service = request.into_inner().service;
        if !is_registered_service(&service) {
            // Match `tonic_health::server::HealthService`: unknown service name → `NOT_FOUND`.
            return Err(Status::not_found("service not registered"));
        }
        if !gateway_process_accepting_rpc() {
            return Ok(Response::new(HealthCheckResponse {
                status: ServingStatus::NotServing as i32,
            }));
        }
        Ok(Response::new(HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        }))
    }

    type WatchStream =
        Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send + 'static>>;

    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        Err(Status::unimplemented(
            "grpc.health.v1.Health.Watch is not yet supported in OpenShell; use Check",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[tokio::test]
    async fn check_serving_for_openshell_and_aggregate() {
        let h = GatewayStandardHealth;
        let r = h
            .check(Request::new(HealthCheckRequest {
                service: OPENSHELL_SERVICE_NAME.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.status, ServingStatus::Serving as i32);

        let r = h
            .check(Request::new(HealthCheckRequest {
                service: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.status, ServingStatus::Serving as i32);
    }

    #[tokio::test]
    async fn check_not_found_for_unknown_service() {
        let h = GatewayStandardHealth;
        let e = h
            .check(Request::new(HealthCheckRequest {
                service: "no.such.Service".to_string(),
            }))
            .await
            .expect_err("unknown service");
        assert_eq!(e.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn watch_unimplemented() {
        let h = GatewayStandardHealth;
        let res = h.watch(Request::new(HealthCheckRequest::default())).await;
        let Err(e) = res else {
            panic!("expected Watch to return an error");
        };
        assert_eq!(e.code(), Code::Unimplemented);
    }
}
