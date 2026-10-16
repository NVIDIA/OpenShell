// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared data validation; lifecycle and process behavior are tested over RPC.
use openshell_isolation_interface::contract::*;
use std::collections::BTreeMap;

fn workload_identity() -> ResolvedWorkloadIdentity {
    ResolvedWorkloadIdentity::new(
        1000,
        1000,
        vec![1000],
        "policy".to_string(),
        "sha256:test".to_string(),
    )
    .unwrap()
}

fn complete_outer_fence(generation: &str, evidence: &[u8]) -> OuterFenceGuarantees {
    OuterFenceGuarantees::from_enforcement_evidence(
        generation,
        [
            OuterFenceGuarantee::DefaultDenyEgress,
            OuterFenceGuarantee::NoUnmanagedEgressPath,
            OuterFenceGuarantee::RevocationVerified,
            OuterFenceGuarantee::ControllerLossFailsClosed,
        ],
        evidence,
    )
    .unwrap()
}

fn confirmation() -> BoundaryConfirmation {
    BoundaryConfirmation {
        generation: "generation-1".to_string(),
        identity: workload_identity(),
        properties: BoundaryProperties {
            filesystem_confinement: EnforcedProperty::new(true, "mock-filesystem"),
            egress_interception: EnforcedProperty::new(true, "mock-egress"),
            request_attribution: EnforcedProperty::new(true, "mock-attribution"),
            privilege_floor: EnforcedProperty::new(true, "mock-privilege-floor"),
        },
        authenticated_supervisor: true,
        session_id: SandboxSessionId::new(),
        outer_fence: complete_outer_fence("generation-1", b"mock-fence-evidence"),
        runtime_exit_terminates_workload: true,
        resource_claims: BTreeMap::new(),
        backend_audit: serde_json::json!({"backend": "mock"}),
    }
}

#[test]
fn outer_fence_guarantees_are_backend_neutral_and_fail_closed() {
    let fence = complete_outer_fence("generation-1", b"native-driver-evidence");
    assert!(fence.validate("generation-1").is_ok());
    assert_ne!(
        fence.evidence_digest,
        complete_outer_fence("generation-2", b"native-driver-evidence").evidence_digest
    );

    let mut wrong_generation = fence.clone();
    wrong_generation.generation = "generation-2".to_string();
    assert!(wrong_generation.validate("generation-1").is_err());

    for guarantee in [
        OuterFenceGuarantee::DefaultDenyEgress,
        OuterFenceGuarantee::NoUnmanagedEgressPath,
        OuterFenceGuarantee::RevocationVerified,
        OuterFenceGuarantee::ControllerLossFailsClosed,
    ] {
        let mut incomplete = fence.clone();
        incomplete.established.remove(&guarantee);
        assert!(incomplete.validate("generation-1").is_err());
    }

    assert!(OuterFenceGuarantees::from_enforcement_evidence("", [], b"evidence").is_err());
    assert!(OuterFenceGuarantees::from_enforcement_evidence("generation-1", [], b"").is_err());

    let unproven = OuterFenceGuarantees::from_enforcement_evidence(
        "generation-1",
        [OuterFenceGuarantee::DefaultDenyEgress],
        b"native-driver-evidence",
    )
    .unwrap();
    assert!(unproven.validate("generation-1").is_err());
}

#[test]
fn sha256_digest_rejects_signed_hex_chunks() {
    let signed = format!("+0{}", "00".repeat(31));
    assert!(signed.parse::<Sha256Digest>().is_err());
    assert!("00".repeat(32).parse::<Sha256Digest>().is_ok());
}

#[test]
fn workload_identity_rejects_root_and_normalizes_groups() {
    assert!(
        ResolvedWorkloadIdentity::new(0, 1000, vec![], "policy".into(), "digest".into()).is_err()
    );
    let identity = ResolvedWorkloadIdentity::new(
        1000,
        1001,
        vec![1003, 1001, 1002, 1003],
        "policy".into(),
        "digest".into(),
    )
    .unwrap();
    assert_eq!(identity.supplementary_gids, vec![1002, 1003]);
}

#[test]
fn confirmation_rejects_identity_or_property_drift() {
    let expected = workload_identity();
    let baseline = confirmation();
    baseline.validate(&expected).unwrap();

    let mut drifted = confirmation();
    drifted.properties.privilege_floor.enforced = false;
    assert!(drifted.validate(&expected).is_err());

    let mut unmanaged = confirmation();
    unmanaged.runtime_exit_terminates_workload = false;
    assert!(unmanaged.validate(&expected).is_err());

    let different = ResolvedWorkloadIdentity::new(
        1002,
        1000,
        vec![1000],
        "policy".into(),
        "sha256:test".into(),
    )
    .unwrap();
    assert!(baseline.validate(&different).is_err());
}

#[test]
fn error_kinds_map_to_supervisor_status_classes() {
    assert_eq!(
        BackendError::Descriptor("x".into()).kind(),
        BackendErrorKind::Invalid
    );
    assert_eq!(
        BackendError::NotRegistered("x".into()).kind(),
        BackendErrorKind::Invalid
    );
    assert_eq!(
        BackendError::Denied("x".into()).kind(),
        BackendErrorKind::Denied
    );
    assert_eq!(
        BackendError::Unavailable("x".into()).kind(),
        BackendErrorKind::Unavailable
    );
    assert_eq!(
        BackendError::Unsupported("x".into()).kind(),
        BackendErrorKind::Unsupported
    );
    assert_eq!(
        BackendError::Attach("x".into()).kind(),
        BackendErrorKind::Failed
    );
    assert_eq!(
        BackendError::Confirm("x".into()).kind(),
        BackendErrorKind::Failed
    );
    assert_eq!(
        BackendError::Terminated("x".into()).kind(),
        BackendErrorKind::Terminated
    );
}

#[tokio::test]
async fn port_forward_rejects_non_loopback() {
    let target = LoopbackTarget::new("8.8.8.8".parse().unwrap(), 53);
    assert!(target.is_err());
    let loopback = LoopbackTarget::new("127.0.0.1".parse().unwrap(), 8080).expect("loopback ok");
    assert_eq!(loopback.port(), 8080);
}
