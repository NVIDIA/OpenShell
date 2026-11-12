// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_isolation_interface::contract::{ProvisioningEvidence, ResolvedWorkloadIdentity};
use openshell_sandbox_backend::boundary_protocol::{
    SandboxRuntimeDescriptor, SandboxTlsClientConfig, SandboxTransport,
    generate_sandbox_tls_material,
};
use openshell_supervisor_control::PreparedRuntimeRegistration;

fn prepared(route: &str) -> PreparedRuntimeRegistration {
    let session_id = openshell_core::SandboxSessionId::new();
    let tls = generate_sandbox_tls_material(session_id).unwrap();
    PreparedRuntimeRegistration {
        route: route.to_string(),
        runtime_descriptor: SandboxRuntimeDescriptor {
            boundary_id: String::new(),
            generation: "generation-1".to_string(),
            session_id,
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                vec![],
                "test".into(),
                "a".repeat(64),
            )
            .unwrap(),
            transport: SandboxTransport::RuntimeInitiatedRouted {
                authority: "supervisor:5500".into(),
                route: route.to_string(),
            },
            tls: SandboxTlsClientConfig {
                server_name: tls.server_name,
                trust_anchor_pem: tls.trust_anchor_pem,
            },
            host_gateway_ip: None,
            resource_claims: BTreeMap::from([(
                "kubernetes.workload_pod_uid".into(),
                "pod-1".into(),
            )]),
            provisioning_evidence: ProvisioningEvidence::from_enforcement_evidence(
                "generation-1",
                b"test-fence",
            )
            .unwrap(),
        },
    }
}

fn host(root: &Path) -> Arc<SharedHost> {
    SharedHost::start(SharedHostConfig {
        gateway_endpoint: "https://gateway.invalid".into(),
        instance_root: root.join("instances"),
        runtime_listen: "127.0.0.1:0".parse().unwrap(),
        removal_grace: Duration::from_secs(1),
        attach_request_timeout: Duration::from_mins(5),
        pool: PoolIdentity {
            member_id: "member-1".into(),
            runtime_address: "127.0.0.1:5500".parse().unwrap(),
        },
    })
    .unwrap()
}

fn snapshot(instances: Vec<SandboxInstanceAssignment>) -> AssignmentSnapshot {
    AssignmentSnapshot {
        revision: 1,
        pool: true,
        instances,
        ..Default::default()
    }
}

fn activation(prepared: &PreparedRuntimeRegistration) -> SandboxInstanceRegistration {
    let mut descriptor = prepared.runtime_descriptor.clone();
    descriptor.boundary_id = "claimed-sandbox".into();
    let tls = generate_sandbox_tls_material(descriptor.session_id).unwrap();
    SandboxInstanceRegistration {
        route: prepared.route.clone(),
        sandbox_id: descriptor.boundary_id.clone(),
        sandbox_name: "claimed".into(),
        auth: serde_json::from_value(serde_json::json!({
            "session_id": descriptor.session_id,
            "runtime_generation": descriptor.generation,
            "session_rotation": 1,
            "auth_epoch": 1,
            "gateway_token": "test-gateway-token",
            "gateway_expires_at": 0,
            "sandbox_token": "test-bound-sandbox-token",
            "sandbox_expires_at": 0
        }))
        .unwrap(),
        runtime_descriptor: descriptor,
        main_process_spec: serde_json::to_string(
            &openshell_core::sandbox_env::MainProcessConfig::scratch(),
        )
        .unwrap(),
        workdir: None,
        container_image: String::new(),
        proxy_ca: openshell_supervisor_control::ProxyCaMaterial {
            certificate_pem: tls.certificate_chain_pem,
            private_key_pem: openshell_supervisor_control::SecretPem::new(tls.private_key_pem),
        },
        trace_context: None,
    }
}

#[test]
fn prepared_assignments_reject_conflicting_envelopes_and_operational_material() {
    let registration = prepared("rt-prepared-0123456789");
    let valid = registration.to_assignment().unwrap();
    assert_eq!(
        PreparedRuntimeRegistration::from_assignment(&valid).unwrap(),
        registration
    );
    for changed in [
        SandboxInstanceAssignment {
            prepared: false,
            ..valid.clone()
        },
        SandboxInstanceAssignment {
            sandbox_id: "sandbox".into(),
            ..valid.clone()
        },
        SandboxInstanceAssignment {
            generation: "other-generation".into(),
            ..valid.clone()
        },
        SandboxInstanceAssignment {
            route: "rt-another-0123456789".into(),
            ..valid.clone()
        },
        SandboxInstanceAssignment {
            takeover: Some(SandboxInstanceTakeover::default()),
            ..valid.clone()
        },
        SandboxInstanceAssignment {
            launch_material: vec![
                b' ';
                openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES + 1
            ],
            ..valid.clone()
        },
    ] {
        assert!(PreparedRuntimeRegistration::from_assignment(&changed).is_err());
    }
    let active = activation(&registration).to_assignment().unwrap();
    assert!(
        PreparedRuntimeRegistration::from_assignment(&SandboxInstanceAssignment {
            prepared: true,
            sandbox_id: String::new(),
            ..active
        })
        .is_err()
    );
    assert!(SandboxInstanceRegistration::from_assignment(&valid).is_err());
    let mut missing_binding = registration.clone();
    missing_binding.runtime_descriptor.resource_claims.clear();
    assert!(missing_binding.to_assignment().is_err());
    let mut already_assigned = registration;
    already_assigned.runtime_descriptor.boundary_id = "sandbox".into();
    assert!(already_assigned.to_assignment().is_err());
}

#[tokio::test]
async fn leaving_waits_for_prepared_reservations_to_be_released() {
    let root = tempfile::tempdir().unwrap();
    let host = host(root.path());
    host.reconcile(&snapshot(vec![
        prepared("rt-prepared-0123456789").to_assignment().unwrap(),
    ]))
    .await
    .unwrap();
    host.gateway_connected.send_replace(true);
    let leaving = host.leave(Duration::from_secs(5));
    tokio::pin!(leaving);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut leaving)
            .await
            .is_err()
    );
    assert!(host.is_leaving());
    host.reconcile(&snapshot(vec![])).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), leaving)
        .await
        .unwrap();
}

#[tokio::test]
async fn activation_retains_the_prepared_route_and_rejects_changed_coordinates() {
    let root = tempfile::tempdir().unwrap();
    let host = host(root.path());
    let prepared = prepared("rt-prepared-0123456789");
    host.reconcile(&snapshot(vec![prepared.to_assignment().unwrap()]))
        .await
        .unwrap();
    let registration = activation(&prepared);
    prepared.validate_activation(&registration).unwrap();
    for field in [
        "generation",
        "session",
        "tls",
        "claims",
        "identity",
        "transport",
        "evidence",
    ] {
        let mut changed = registration.clone();
        match field {
            "generation" => changed.runtime_descriptor.generation = "another-generation".into(),
            "session" => {
                changed.runtime_descriptor.session_id = openshell_core::SandboxSessionId::new();
            }
            "tls" => changed.runtime_descriptor.tls.server_name = "other.openshell.internal".into(),
            "claims" => {
                changed
                    .runtime_descriptor
                    .resource_claims
                    .insert("kubernetes.workload_pod_uid".into(), "other-pod".into());
            }
            "identity" => changed.runtime_descriptor.workload_identity.uid += 1,
            "transport" => {
                if let SandboxTransport::RuntimeInitiatedRouted { authority, .. } =
                    &mut changed.runtime_descriptor.transport
                {
                    *authority = "other:5500".into();
                }
            }
            "evidence" => {
                changed.runtime_descriptor.provisioning_evidence =
                    ProvisioningEvidence::from_enforcement_evidence("generation-1", b"other-fence")
                        .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(prepared.validate_activation(&changed).is_err(), "{field}");
        assert!(
            host.admit_pool_assignment(&changed.to_assignment().unwrap())
                .await
                .is_err(),
            "{field}"
        );
        assert!(host.host.list().is_empty());
        assert!(host.prepared.lock().unwrap().contains_key(&prepared.route));
    }

    // The production instance launch captures the route in its backend setup
    // before the reservation is removed. No runtime thread or gateway session
    // is needed to prove that ownership transfers without unregistering it.
    let route = host.prepared.lock().unwrap()[&prepared.route].route.clone();
    let instance_dir = root.path().join("instance");
    std::fs::create_dir(&instance_dir).unwrap();
    let (_, body) = host
        .instance_launch(registration.clone(), None, &instance_dir)
        .unwrap();
    host.prepared.lock().unwrap().remove(&prepared.route);
    assert_eq!(
        Arc::strong_count(&route),
        2,
        "the launch body owns the prepared registration"
    );
    assert!(
        host.router
            .register(&prepared.route, &prepared.runtime_descriptor.tls)
            .is_err()
    );
    drop(body);
    drop(route);
    assert!(
        host.router
            .register(&prepared.route, &prepared.runtime_descriptor.tls)
            .is_ok()
    );
}

#[tokio::test]
async fn prepared_routes_are_idempotent_kept_and_withdrawn_without_a_workload() {
    let root = tempfile::tempdir().unwrap();
    let host = host(root.path());
    let prepared = prepared("rt-prepared-0123456789");
    let assignment = prepared.to_assignment().unwrap();
    host.reconcile(&snapshot(vec![assignment.clone()]))
        .await
        .unwrap();
    assert!(
        host.host.list().is_empty(),
        "preparation starts no instance"
    );
    assert_eq!(
        host.status(&prepared.route).unwrap().phase,
        SandboxInstancePhaseReport::Prepared
    );
    assert!(!host.status(&prepared.route).unwrap().ready);
    let route = host.prepared.lock().unwrap()[&prepared.route].route.clone();
    host.reconcile(&snapshot(vec![assignment])).await.unwrap();
    assert!(Arc::ptr_eq(
        &route,
        &host.prepared.lock().unwrap()[&prepared.route].route
    ));

    // A replica still loading the preparation retains its existing connection.
    host.reconcile(&AssignmentSnapshot {
        keep_routes: vec![prepared.route.clone()],
        ..snapshot(vec![])
    })
    .await
    .unwrap();
    assert!(host.status(&prepared.route).is_some());
    drop(route);
    host.reconcile(&snapshot(vec![])).await.unwrap();
    assert!(host.status(&prepared.route).is_none());
    assert!(
        host.router
            .register(&prepared.route, &prepared.runtime_descriptor.tls)
            .is_ok()
    );
}

#[tokio::test]
async fn preparation_cannot_replace_physical_identity_or_downgrade_an_active_instance() {
    let root = tempfile::tempdir().unwrap();
    let host = host(root.path());
    let original = prepared("rt-prepared-0123456789");
    host.reconcile(&snapshot(vec![original.to_assignment().unwrap()]))
        .await
        .unwrap();
    let mut changed = original.clone();
    changed
        .runtime_descriptor
        .resource_claims
        .insert("kubernetes.workload_pod_uid".into(), "pod-2".into());
    host.reconcile(&snapshot(vec![changed.to_assignment().unwrap()]))
        .await
        .unwrap();
    assert!(host.list()[0].phase.is_terminal());
    assert_eq!(
        host.prepared.lock().unwrap()[&original.route].registration,
        original
    );

    let active_route = "rt-active-01234567890";
    let (stopped, _) = tokio::sync::mpsc::channel(1);
    tests::admit_supervising(&host, active_route, stopped);
    assert!(matches!(
        host.prepare(&prepared(active_route).to_assignment().unwrap()),
        Err(ControlError::Conflict)
    ));
    host.shut_down().await;
}

#[tokio::test]
async fn prepared_routes_share_capacity_with_active_instances_and_activation_uses_the_reserved_slot()
 {
    let root = tempfile::tempdir().unwrap();
    let host = host(root.path());
    let template = prepared("rt-template-012345678");
    let active_route = "rt-active-01234567890";
    let (stopped, _) = tokio::sync::mpsc::channel(1);
    tests::admit_supervising(&host, active_route, stopped);
    let with_active = |instances| AssignmentSnapshot {
        keep_routes: vec![active_route.into()],
        ..snapshot(instances)
    };
    let mut assignments = Vec::new();
    for index in 0..MAX_ASSIGNED_INSTANCES - 1 {
        let mut registration = template.clone();
        registration.route = format!("rt-prepared-{index:04}-0123456789");
        if let SandboxTransport::RuntimeInitiatedRouted { route, .. } =
            &mut registration.runtime_descriptor.transport
        {
            route.clone_from(&registration.route);
        }
        assignments.push(registration.to_assignment().unwrap());
    }
    host.reconcile(&with_active(assignments.clone()))
        .await
        .unwrap();
    assert_eq!(
        host.prepared.lock().unwrap().len(),
        MAX_ASSIGNED_INSTANCES - 1
    );
    let overflow = prepared("rt-zz-overflow-012345678")
        .to_assignment()
        .unwrap();
    assignments.push(overflow.clone());
    host.reconcile(&with_active(assignments.clone()))
        .await
        .unwrap();
    assert!(host.status(&overflow.route).is_none());
    assert_eq!(
        host.prepared.lock().unwrap().len(),
        MAX_ASSIGNED_INSTANCES - 1
    );

    // Replacing one preparation with an active assignment does not need a
    // second slot, even while every slot is reserved.
    assignments[0].prepared = false;
    assignments[0].sandbox_id = "claimed-sandbox".into();
    let mut hosted: std::collections::BTreeSet<_> =
        host.prepared.lock().unwrap().keys().cloned().collect();
    hosted.insert(active_route.into());
    let activation = with_active(assignments);
    let (admitted, unstarted) = within_capacity(&activation, &hosted);
    assert!(
        admitted
            .iter()
            .any(|assignment| assignment.sandbox_id == "claimed-sandbox")
    );
    assert_eq!(unstarted, vec![overflow.route.as_str()]);
    host.shut_down().await;
}
