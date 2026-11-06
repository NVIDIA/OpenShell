// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in cross-process qualification with the server's actual idle-reconcile
//! fixture. Existing protobuf messages cross a test-only atomic file rendezvous;
//! there is no new production protocol or cross-crate test dependency.

use super::*;
use openshell_core::proto::ConfigUpdate;
use prost::Message as _;

async fn receive_update(directory: &std::path::Path, step: usize) -> ConfigUpdate {
    let path = directory.join(format!("update-{step}.pb"));
    timeout(Duration::from_secs(90), async {
        loop {
            match std::fs::read(&path) {
                Ok(bytes) => return ConfigUpdate::decode(bytes.as_slice()).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("read gateway update: {error}"),
            }
        }
    })
    .await
    .expect("gateway qualification must deliver its next update")
}

fn assert_resolves(
    credentials: &ProviderCredentialState,
    placeholder: &str,
    expected: Option<&str>,
) {
    assert_eq!(
        credentials
            .resolver_for_endpoint("github.com", 443, "/")
            .and_then(|resolver| resolver.resolve_placeholder(placeholder).map(str::to_owned)),
        expected.map(str::to_owned)
    );
    assert!(
        credentials
            .resolver_for_endpoint("unrelated.example", 443, "/")
            .and_then(|resolver| resolver.resolve_placeholder(placeholder).map(str::to_owned))
            .is_none()
    );
}

#[tokio::test]
#[ignore = "run with the server idle qualification test and a fresh OPENSHELL_DELIVERY_QUALIFICATION_DIR"]
async fn actual_config_runtime_applies_idle_rotation_reconfiguration_and_revocation() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("OPENSHELL_DELIVERY_QUALIFICATION_DIR")
            .expect("set the shared fresh qualification rendezvous directory"),
    );
    let engine = Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).unwrap());
    let mut ctx = policy_poll_test_context(
        engine,
        LoadedPolicyOrigin::Gateway {
            revision: None,
            has_last_valid_policy: false,
        },
        default_middleware_connector(),
    );
    ctx.sandbox_id = "sandbox".into();
    ctx.sandbox = "sandbox".into();
    let (client, _polls, _reports) = scripted_policy_gateway();
    let mut runtime = ConfigRuntime::new(&ctx);
    let mut original_placeholder = String::new();
    let mut replacement_placeholder = String::new();
    let mut initial_identity = None;

    for step in 0..4 {
        let update = receive_update(&directory, step).await;
        let snapshot = update.sandbox_config.as_ref().unwrap().clone();
        let (response, receiver) = tokio::sync::oneshot::channel();
        runtime
            .apply_delivered(&ctx, &client, ConfigApplyRequest { update, response })
            .await;
        let result = receiver.await.unwrap();
        assert_eq!(result.outcome, i32::from(ConfigApplyOutcome::Applied));
        assert_eq!(
            runtime.provider_env_revision,
            snapshot.provider_env_revision
        );
        assert_eq!(runtime.policy_hash, snapshot.policy_hash);
        assert_eq!(
            ctx.provider_credentials.snapshot().revision,
            snapshot.provider_env_revision
        );
        let readiness = ctx
            .provider_readiness
            .observation(&ctx.provider_credentials);
        assert!(readiness.credentials_installed);
        assert!(readiness.policy_active);
        assert_eq!(
            readiness.provider_env_revision,
            snapshot.provider_env_revision
        );
        assert_eq!(
            readiness.attachment_epoch,
            snapshot.provider_attachment_epoch
        );
        assert_eq!(readiness.policy_hash, snapshot.policy_hash);
        assert_eq!(
            client.poll_calls.load(Ordering::SeqCst),
            0,
            "stream installation must not fetch a separate provider environment"
        );

        match step {
            0 => {
                original_placeholder =
                    ctx.provider_credentials.snapshot().child_env["GITHUB_TOKEN"].clone();
                assert_resolves(
                    &ctx.provider_credentials,
                    &original_placeholder,
                    Some("provider-secret"),
                );
                initial_identity = Some((
                    snapshot.provider_env_revision,
                    snapshot.policy_hash,
                    snapshot.config_revision,
                    snapshot.provider_attachment_epoch,
                ));
            }
            1 => {
                let (revision, hash, config_revision, attachment) =
                    initial_identity.as_ref().unwrap();
                assert_ne!(snapshot.provider_env_revision, *revision);
                assert_eq!(&snapshot.policy_hash, hash);
                assert_eq!(snapshot.config_revision, *config_revision);
                assert_eq!(&snapshot.provider_attachment_epoch, attachment);
                assert_eq!(
                    ctx.provider_credentials.snapshot().child_env["GITHUB_TOKEN"],
                    original_placeholder
                );
                assert_resolves(
                    &ctx.provider_credentials,
                    &original_placeholder,
                    Some("qualification-rotated-v2"),
                );
            }
            2 => {
                replacement_placeholder =
                    ctx.provider_credentials.snapshot().child_env["GITHUB_TOKEN"].clone();
                assert_ne!(replacement_placeholder, original_placeholder);
                assert_resolves(&ctx.provider_credentials, &original_placeholder, None);
                assert_resolves(
                    &ctx.provider_credentials,
                    &replacement_placeholder,
                    Some("qualification-rotated-v2"),
                );
            }
            3 => {
                assert!(ctx.provider_credentials.snapshot().child_env.is_empty());
                assert_resolves(&ctx.provider_credentials, &original_placeholder, None);
                assert_resolves(&ctx.provider_credentials, &replacement_placeholder, None);
            }
            _ => unreachable!(),
        }
        // The gateway's real durable result handler consumes exactly this
        // ConfigRuntime result before proceeding to the next mutation.
        let temporary = directory.join(format!("result-{step}.tmp"));
        std::fs::write(&temporary, result.encode_to_vec()).unwrap();
        std::fs::rename(temporary, directory.join(format!("result-{step}.pb"))).unwrap();
    }
}
