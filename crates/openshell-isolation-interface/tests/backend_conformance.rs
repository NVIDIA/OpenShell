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

fn provisioning_evidence(generation: &str, evidence: &[u8]) -> ProvisioningEvidence {
    ProvisioningEvidence::from_enforcement_evidence(generation, evidence).unwrap()
}

fn confirmation() -> BoundaryConfirmation {
    BoundaryConfirmation {
        generation: "generation-1".to_string(),
        identity: workload_identity(),

        session_id: SandboxSessionId::new(),
        provisioning_evidence_digest: provisioning_evidence("generation-1", b"mock-fence-evidence")
            .evidence_digest,
        resource_claims: BTreeMap::new(),
        backend_audit: serde_json::json!({"backend": "mock"}),
    }
}

#[test]
fn provisioning_evidence_binds_native_facts_to_the_generation() {
    let fence = provisioning_evidence("generation-1", b"native-driver-evidence");
    assert!(fence.validate("generation-1").is_ok());
    assert_ne!(
        fence.evidence_digest,
        provisioning_evidence("generation-2", b"native-driver-evidence").evidence_digest
    );

    let mut wrong_generation = fence.clone();
    wrong_generation.generation = "generation-2".to_string();
    assert!(wrong_generation.validate("generation-1").is_err());

    assert!(ProvisioningEvidence::from_enforcement_evidence("", b"evidence").is_err());
    assert!(ProvisioningEvidence::from_enforcement_evidence("generation-1", b"").is_err());
    assert_ne!(
        fence.evidence_digest,
        provisioning_evidence("generation-1", b"different-native-evidence").evidence_digest,
    );
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
fn confirmation_rejects_missing_generation_or_identity_drift() {
    let expected = workload_identity();
    let baseline = confirmation();
    baseline.validate(&expected).unwrap();

    let mut missing = confirmation();
    missing.generation.clear();
    assert!(missing.validate(&expected).is_err());

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
