// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::grpc::service_advertisement::{accept, test_support::installed_fixture};
use crate::supervisor_owner::{OWNER_TTL, OwnerGuard, SupervisorOwnerIndex};
use openshell_core::proto::{ServiceEndpoint, SupervisorServiceAdvertisement};

struct Prepared {
    state: Arc<ServerState>,
    owner: OwnerGuard,
    report: SupervisorServiceAdvertisement,
    inputs: DiscoveryConfigInputs,
    validated: Vec<ValidatedInstallation>,
}

impl Prepared {
    async fn new() -> Self {
        let (state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let inputs = DiscoveryConfigInputs::load(&state, "default")
            .await
            .unwrap();
        let validated = validate_installations(
            &state,
            "default",
            &inputs,
            records(&state, "default").await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(validated.len(), 1);
        Self {
            state,
            owner,
            report,
            inputs,
            validated,
        }
    }

    async fn publish(self) -> Result<ServiceRouteSnapshot, Status> {
        publish_installations(&self.state, "default", &self.inputs, self.validated).await
    }
}

#[tokio::test]
async fn renewal_after_validation_uses_the_accepted_deadline_and_preserves_identity() {
    let mut p = Prepared::new().await;
    let before = &p.validated[0].installation;
    let version = installation_version(before, &before.routes[0]).unwrap();
    let expiry = current_time_ms() + 14_000;
    p.report.lease_sequence += 1;
    accept(&p.state, &p.owner, &p.report, expiry).await.unwrap();
    let snapshot = p.publish().await.unwrap();
    assert_eq!(snapshot.routes.len(), 1);
    assert_eq!(
        snapshot.routes[0].expires_at,
        Some(openshell_core::time::timestamp_from_millis(expiry).unwrap())
    );
    assert_eq!(snapshot.routes[0].installation_version, version);
}

#[tokio::test]
async fn withdrawal_between_validation_and_publication_removes_the_route() {
    let mut p = Prepared::new().await;
    p.report.lease_sequence += 1;
    p.report.routes.clear();
    accept(&p.state, &p.owner, &p.report, current_time_ms() + 14_000)
        .await
        .unwrap();
    assert!(p.publish().await.unwrap().routes.is_empty());
}

#[tokio::test]
async fn replaced_owner_cannot_reuse_a_validated_route_or_renewal() {
    for renew in [false, true] {
        let mut p = Prepared::new().await;
        if renew {
            p.report.lease_sequence += 1;
            accept(&p.state, &p.owner, &p.report, current_time_ms() + 14_000)
                .await
                .unwrap();
        }
        SupervisorOwnerIndex::new(p.state.store.clone(), OWNER_TTL)
            .publish(
                "sandbox",
                "replacement",
                "instance",
                2,
                "replica",
                "local://replica",
            )
            .await
            .unwrap();
        assert!(p.publish().await.unwrap().routes.is_empty());
    }
}

#[tokio::test]
async fn renewed_receipt_revalidates_configuration_admission() {
    let mut p = Prepared::new().await;
    p.report.lease_sequence += 1;
    accept(&p.state, &p.owner, &p.report, current_time_ms() + 14_000)
        .await
        .unwrap();
    let mut sandbox = p
        .state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    sandbox
        .status
        .get_or_insert_with(Default::default)
        .configuration_admission = Some(openshell_core::proto::SandboxConfigurationAdmission {
        instance_id: "replacement-admission".into(),
        ..Default::default()
    });
    p.state.store.put_message(&sandbox).await.unwrap();
    assert!(p.publish().await.unwrap().routes.is_empty());
}

#[tokio::test]
async fn shared_declaration_edits_invalidate_the_captured_view() {
    let p = Prepared::new().await;
    let mut endpoint = p
        .state
        .store
        .get_message::<ServiceEndpoint>("endpoint")
        .await
        .unwrap()
        .unwrap();
    endpoint.target_port += 1;
    p.state.store.put_message(&endpoint).await.unwrap();
    let error = p.publish().await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(error.message().contains("configuration changed"));
}

#[tokio::test]
async fn global_settings_and_catalog_changes_invalidate_shared_inputs() {
    for catalog in [false, true] {
        let p = Prepared::new().await;
        if catalog {
            let record = p
                .state
                .store
                .list_by_type_after("provider_profile", None, 1)
                .await
                .unwrap()
                .pop()
                .unwrap();
            let mut stored =
                crate::storage_proto::StoredProviderProfile::decode(record.payload.as_slice())
                    .unwrap();
            stored
                .profile
                .as_mut()
                .unwrap()
                .display_name
                .push_str(" changed");
            p.state
                .store
                .put(
                    &record.object_type,
                    &record.id,
                    &record.name,
                    &record.workspace,
                    &stored.encode_to_vec(),
                    record.labels.as_deref(),
                )
                .await
                .unwrap();
        } else {
            let mut settings = super::super::policy::load_global_settings(&p.state.store)
                .await
                .unwrap();
            settings.revision += 1;
            super::super::policy::save_global_settings(&p.state.store, &settings)
                .await
                .unwrap();
        }
        let error = p.publish().await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(error.message().contains("configuration changed"));
    }
}

#[tokio::test]
async fn unsuitable_bulk_declarations_fall_back_without_blocking_other_sandboxes() {
    for payload in [b"invalid protobuf".to_vec(), vec![0; 4 * 1024 * 1024 + 1]] {
        let p = Prepared::new().await;
        p.state
            .store
            .put(
                "service_endpoint",
                "unrelated",
                "unrelated",
                "default",
                &payload,
                Some(r#"{"sandbox":"another"}"#),
            )
            .await
            .unwrap();
        let snapshot = snapshot(&p.state, "default").await.unwrap();
        assert_eq!(snapshot.routes.len(), 1);
    }
}

#[tokio::test]
async fn receipt_identity_changes_and_deletion_cannot_extend_a_validated_route() {
    for mutation in 0..3 {
        let p = Prepared::new().await;
        let id = &p.validated[0].id;
        if mutation == 0 {
            p.state.store.delete(OBJECT_TYPE, id).await.unwrap();
        } else {
            let mut value = p.validated[0].installation.clone();
            let record = p.state.store.get(OBJECT_TYPE, id).await.unwrap().unwrap();
            value.sequence += 1;
            value.expires_at_ms = current_time_ms() + 14_000;
            if mutation == 1 {
                value.host = "10.0.0.99".into();
            } else {
                value.runtime_identity = "replacement-runtime".into();
            }
            p.state
                .store
                .put(
                    OBJECT_TYPE,
                    id,
                    &record.name,
                    "default",
                    &serde_json::to_vec(&value).unwrap(),
                    None,
                )
                .await
                .unwrap();
        }
        assert!(p.publish().await.unwrap().routes.is_empty());
    }
}

#[tokio::test]
async fn renewed_receipts_recheck_policy_and_settings_without_a_sandbox_record_edit() {
    use crate::policy_store::PolicyStoreExt as _;
    for policy in [false, true] {
        let mut p = Prepared::new().await;
        p.report.lease_sequence += 1;
        accept(&p.state, &p.owner, &p.report, current_time_ms() + 14_000)
            .await
            .unwrap();
        if policy {
            let policy = openshell_policy::restrictive_default_policy();
            let hash = openshell_core::policy_identity::deterministic_policy_hash(&policy);
            p.state
                .store
                .put_policy_revision(
                    "changed-policy",
                    "sandbox",
                    "default",
                    2,
                    &policy.encode_to_vec(),
                    &hash,
                )
                .await
                .unwrap();
        } else {
            let mut settings =
                super::super::policy::load_sandbox_settings(&p.state.store, "default", "demo")
                    .await
                    .unwrap();
            settings.revision += 1;
            settings.settings.insert(
                "ocsf_json_enabled".into(),
                super::super::StoredSettingValue::Bool(true),
            );
            super::super::policy::save_sandbox_settings(
                &p.state.store,
                "default",
                "demo",
                &settings,
            )
            .await
            .unwrap();
        }
        let sandbox = p
            .state
            .store
            .get_message::<Sandbox>("sandbox")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sandbox.metadata, p.validated[0].sandbox.metadata);
        let changed = super::super::policy::build_sandbox_config_snapshot(&p.state, &sandbox)
            .await
            .unwrap();
        assert_ne!(
            changed.config_revision,
            p.validated[0].installation.config_revision
        );
        assert!(p.publish().await.unwrap().routes.is_empty());
    }
}
