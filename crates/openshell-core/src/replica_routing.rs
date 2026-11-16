// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metadata that lets an edge proxy send a sandbox's long-lived connections
//! straight to the gateway replica holding its supervisor session.

use tonic::metadata::AsciiMetadataValue;

/// Response metadata naming the replica that owns a sandbox's supervisor session.
pub const OWNER_REPLICA_HEADER: &str = "x-openshell-owner";

/// Request metadata asking the gateway to report the owner replica.
pub const OWNER_REQUEST_HEADER: &str = "x-openshell-want-owner";

/// Request metadata asking the edge proxy to route to a specific replica.
pub const ROUTE_REPLICA_HEADER: &str = "x-openshell-replica";

/// Gateway replica that owns the sandbox named in `response`, when it says.
pub fn owner_replica<T>(response: &tonic::Response<T>) -> Option<AsciiMetadataValue> {
    response.metadata().get(OWNER_REPLICA_HEADER).cloned()
}

pub fn with_owner_hint<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert(OWNER_REQUEST_HEADER, AsciiMetadataValue::from_static("1"));
    request
}

/// Wrap `message` so the edge proxy can route it straight to `replica`.
pub fn routed_to<T>(message: T, replica: Option<&AsciiMetadataValue>) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if let Some(replica) = replica {
        request
            .metadata_mut()
            .insert(ROUTE_REPLICA_HEADER, replica.clone());
    }
    request
}

/// A routed call is retried once without routing only when no gateway
/// received it.
///
/// Envoy Gateway answers a replica route whose Service has no ready endpoints
/// with `grpc-status: 14` and no `grpc-message`, while gateway errors and
/// mid-request resets always carry a message.
pub fn retry_unrouted(replica: Option<&AsciiMetadataValue>, status: &tonic::Status) -> bool {
    let message = status.message();
    replica.is_some()
        && status.code() == tonic::Code::Unavailable
        && (message.is_empty()
            || message.contains("no healthy upstream")
            || message.contains("connection failure"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_hint_is_requested_explicitly() {
        assert!(
            with_owner_hint(())
                .metadata()
                .contains_key(OWNER_REQUEST_HEADER)
        );
    }

    #[test]
    fn owner_replica_is_carried_to_the_routed_request() {
        let mut response = tonic::Response::new(());
        response
            .metadata_mut()
            .insert(OWNER_REPLICA_HEADER, "openshell-1".parse().unwrap());
        let replica = owner_replica(&response);
        let request = routed_to((), replica.as_ref());
        assert_eq!(
            request.metadata().get(ROUTE_REPLICA_HEADER).unwrap(),
            "openshell-1"
        );
    }

    #[test]
    fn requests_without_a_known_owner_are_not_routed() {
        let replica = owner_replica(&tonic::Response::new(()));
        assert!(replica.is_none());
        let request = routed_to((), replica.as_ref());
        assert!(request.metadata().get(ROUTE_REPLICA_HEADER).is_none());
    }

    #[test]
    fn only_unavailable_routed_calls_are_retried() {
        let replica = "openshell-1".parse().unwrap();
        let unavailable = tonic::Status::unavailable("no healthy upstream");
        assert!(retry_unrouted(Some(&replica), &unavailable));
        assert!(!retry_unrouted(None, &unavailable));
        assert!(!retry_unrouted(
            Some(&replica),
            &tonic::Status::permission_denied("denied")
        ));
    }

    #[test]
    fn calls_are_retried_only_when_no_gateway_received_them() {
        let replica = "openshell-1".parse().unwrap();
        for never_arrived in [
            "",
            "no healthy upstream",
            "upstream connect error or disconnect/reset before headers. reset reason: connection failure, transport failure reason: delayed connect error: Connection refused",
        ] {
            assert!(retry_unrouted(
                Some(&replica),
                &tonic::Status::unavailable(never_arrived)
            ));
        }
        for may_have_started in [
            "supervisor session not connected",
            "upstream connect error or disconnect/reset before headers. reset reason: connection termination",
        ] {
            assert!(!retry_unrouted(
                Some(&replica),
                &tonic::Status::unavailable(may_have_started)
            ));
        }
    }
}
