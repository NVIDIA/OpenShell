// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    GetInferenceBundleResponse, GetSandboxConfigResponse, GetSandboxProviderEnvironmentResponse,
    InferenceBundleSnapshot, ProviderEnvironmentSnapshot, SandboxConfigSnapshot,
};

macro_rules! snapshot_response {
    ($snapshot:ident, $response:ident, $($field:ident),+ $(,)?) => {
        impl From<$snapshot> for $response {
            fn from(value: $snapshot) -> Self {
                let $snapshot { $($field),+ } = value;
                Self { $($field),+ }
            }
        }
        impl From<$response> for $snapshot {
            fn from(value: $response) -> Self {
                let $response { $($field),+ } = value;
                Self { $($field),+ }
            }
        }
    };
}

snapshot_response!(
    SandboxConfigSnapshot,
    GetSandboxConfigResponse,
    policy,
    version,
    policy_hash,
    settings,
    config_revision,
    policy_source,
    global_policy_version,
    provider_env_revision,
    supervisor_middleware_services,
    workspace,
    policy_validation_failure_mode,
    extension_authentication_enabled,
);
snapshot_response!(
    ProviderEnvironmentSnapshot,
    GetSandboxProviderEnvironmentResponse,
    environment,
    provider_env_revision,
    credential_expires_at_ms,
    dynamic_credentials,
    static_credential_bindings,
    non_secret_environment_keys,
);
snapshot_response!(
    InferenceBundleSnapshot,
    GetInferenceBundleResponse,
    routes,
    revision,
    generated_at_ms,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        ConfigBootstrap, ConfigUpdate, GatewayHeartbeat, GatewayMessage, SessionAccepted,
        config_update, gateway_message,
    };
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct LegacyAccepted {
        #[prost(string, tag = "1")]
        session_id: String,
        #[prost(uint32, tag = "2")]
        heartbeat_interval_secs: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyGateway {
        #[prost(oneof = "LegacyPayload", tags = "1, 3")]
        payload: Option<LegacyPayload>,
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    enum LegacyPayload {
        #[prost(message, tag = "1")]
        Accepted(LegacyAccepted),
        #[prost(message, tag = "3")]
        Heartbeat(GatewayHeartbeat),
    }

    #[test]
    fn bootstrap_and_component_payloads_round_trip_with_old_peer_compatibility() {
        let bootstrap = ConfigBootstrap {
            sandbox_config: Some(SandboxConfigSnapshot {
                config_revision: 17,
                version: 3,
                ..Default::default()
            }),
            provider_environment: Some(ProviderEnvironmentSnapshot {
                environment: [("KEY".into(), "sensitive-test-value".into())].into(),
                provider_env_revision: 19,
                ..Default::default()
            }),
            inference_bundle: Some(InferenceBundleSnapshot {
                revision: "bundle-revision".into(),
                ..Default::default()
            }),
        };
        let accepted = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                session_id: "session".into(),
                heartbeat_interval_secs: 15,
                bootstrap: Some(bootstrap.clone()),
            })),
        };
        assert_eq!(
            GatewayMessage::decode(accepted.encode_to_vec().as_slice()).unwrap(),
            accepted
        );
        let legacy = LegacyGateway::decode(accepted.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            legacy.payload,
            Some(LegacyPayload::Accepted(LegacyAccepted {
                heartbeat_interval_secs: 15,
                ..
            }))
        ));
        let components = [
            config_update::Component::SandboxConfig(bootstrap.sandbox_config.unwrap()),
            config_update::Component::ProviderEnvironment(bootstrap.provider_environment.unwrap()),
            config_update::Component::InferenceBundle(bootstrap.inference_bundle.unwrap()),
        ];
        for component in components {
            let message = GatewayMessage {
                payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                    update_id: "update".into(),
                    component_sequence: 1,
                    component: Some(component),
                })),
            };
            let bytes = message.encode_to_vec();
            assert_eq!(GatewayMessage::decode(bytes.as_slice()).unwrap(), message);
            assert!(
                LegacyGateway::decode(bytes.as_slice())
                    .unwrap()
                    .payload
                    .is_none()
            );
        }
        let heartbeat = GatewayMessage {
            payload: Some(gateway_message::Payload::Heartbeat(
                GatewayHeartbeat::default(),
            )),
        };
        assert!(matches!(
            LegacyGateway::decode(heartbeat.encode_to_vec().as_slice())
                .unwrap()
                .payload,
            Some(LegacyPayload::Heartbeat(_))
        ));
    }

    #[test]
    fn unknown_component_is_absent_and_old_acceptance_has_no_bootstrap() {
        // Field 99 is an unknown length-delimited component, containing an empty message.
        let update = ConfigUpdate::decode([0x9a, 0x06, 0x00].as_slice()).unwrap();
        assert!(update.component.is_none());
        let old = LegacyAccepted {
            session_id: "old".into(),
            heartbeat_interval_secs: 15,
        };
        assert!(
            SessionAccepted::decode(old.encode_to_vec().as_slice())
                .unwrap()
                .bootstrap
                .is_none()
        );
    }
}
