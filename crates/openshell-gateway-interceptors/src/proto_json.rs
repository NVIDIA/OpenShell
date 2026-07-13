// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Descriptor-backed protobuf and `ProtoJSON` conversion.

use std::collections::HashSet;
use std::sync::Arc;

use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DeserializeOptions, DynamicMessage, ExtensionDescriptor, FieldDescriptor, Kind,
    MessageDescriptor, ReflectMessage as _, Value as ReflectValue,
};
use serde_json::Value;

use crate::{InterceptorError, Result};

/// Descriptor-backed protobuf/JSON codec used at the interceptor seam.
///
/// Binary input follows protobuf's standard semantics, including
/// last-member-wins handling when multiple alternatives from one `oneof`
/// appear on the wire. JSON input follows the canonical `ProtoJSON` mapping.
#[derive(Debug, Clone)]
pub struct ProtoJsonCodec {
    pool: Arc<DescriptorPool>,
    secret_option: Option<ExtensionDescriptor>,
}

const SECRET_OPTION: &str = "openshell.options.v1.secret";

impl ProtoJsonCodec {
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self> {
        let pool = DescriptorPool::decode(bytes).map_err(|err| {
            InterceptorError::Config(format!("decode protobuf descriptor set: {err}"))
        })?;
        let secret_option = pool.get_extension_by_name(SECRET_OPTION);
        Ok(Self {
            pool: Arc::new(pool),
            secret_option,
        })
    }

    pub fn openshell() -> Result<Self> {
        Self::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)
    }

    pub fn decode_message_to_json<M>(&self, type_name: &str, message: &M) -> Result<Value>
    where
        M: prost::Message,
    {
        self.decode_bytes_to_json(type_name, &message.encode_to_vec())
    }

    pub fn encode_json_to_message(&self, type_name: &str, value: &Value) -> Result<Vec<u8>> {
        let descriptor = self.message_descriptor(type_name)?;
        let encoded_json = serde_json::to_vec(value).map_err(|err| {
            InterceptorError::Transcode(format!(
                "serialize {type_name} JSON before protobuf encoding: {err}"
            ))
        })?;
        let mut deserializer = serde_json::Deserializer::from_slice(&encoded_json);
        let message = DynamicMessage::deserialize_with_options(
            descriptor,
            &mut deserializer,
            &DeserializeOptions::new(),
        )
        .map_err(|err| {
            InterceptorError::Transcode(format!("encode {type_name} from ProtoJSON: {err}"))
        })?;
        deserializer.end().map_err(|err| {
            InterceptorError::Transcode(format!("encode {type_name} from ProtoJSON: {err}"))
        })?;
        Ok(message.encode_to_vec())
    }

    pub(crate) fn descriptor_pool(&self) -> &DescriptorPool {
        &self.pool
    }

    /// Decodes a protobuf message into the view exposed to gateway
    /// interceptors, recursively omitting fields marked with the `OpenShell`
    /// secret field option.
    pub(crate) fn decode_bytes_to_interceptor_json(
        &self,
        type_name: &str,
        bytes: &[u8],
    ) -> Result<Value> {
        let descriptor = self.message_descriptor(type_name)?;
        let mut message = DynamicMessage::decode(descriptor, bytes).map_err(|err| {
            InterceptorError::Transcode(format!("decode {type_name} protobuf message: {err}"))
        })?;
        self.omit_secrets(&mut message);
        serde_json::to_value(message).map_err(|err| {
            InterceptorError::Transcode(format!("serialize {type_name} as ProtoJSON: {err}"))
        })
    }

    /// Rejects a JSON Pointer that could read, test, remove, or replace a
    /// secret field. Selecting a containing message is also rejected because
    /// replacing the parent could mutate an omitted descendant.
    pub(crate) fn ensure_interceptor_patch_path_visible(
        &self,
        type_name: &str,
        pointer: &str,
    ) -> Result<()> {
        let descriptor = self.message_descriptor(type_name)?;
        let segments = parse_json_pointer(pointer)?;
        if self.pointer_intersects_secret(&descriptor, &segments) {
            return Err(InterceptorError::InvalidResult(format!(
                "JSON patch path '{pointer}' targets an omitted secret field"
            )));
        }
        Ok(())
    }

    pub(crate) fn decode_bytes_to_json(&self, type_name: &str, bytes: &[u8]) -> Result<Value> {
        let descriptor = self.message_descriptor(type_name)?;
        let message = DynamicMessage::decode(descriptor, bytes).map_err(|err| {
            InterceptorError::Transcode(format!("decode {type_name} protobuf message: {err}"))
        })?;
        serde_json::to_value(message).map_err(|err| {
            InterceptorError::Transcode(format!("serialize {type_name} as ProtoJSON: {err}"))
        })
    }

    fn message_descriptor(&self, type_name: &str) -> Result<MessageDescriptor> {
        let normalized = type_name.strip_prefix('.').unwrap_or(type_name);
        self.pool.get_message_by_name(normalized).ok_or_else(|| {
            InterceptorError::Transcode(format!(
                "protobuf message type '{normalized}' was not found in the descriptor set"
            ))
        })
    }

    fn omit_secrets(&self, message: &mut DynamicMessage) {
        let fields = message.descriptor().fields().collect::<Vec<_>>();
        for field in fields {
            if self.is_secret(&field) {
                message.clear_field(&field);
                continue;
            }
            if !message.has_field(&field) {
                continue;
            }
            omit_nested_secrets(self, message.get_field_mut(&field));
        }
    }

    fn is_secret(&self, field: &FieldDescriptor) -> bool {
        let Some(secret_option) = &self.secret_option else {
            return false;
        };
        matches!(
            field.options().get_extension(secret_option).as_ref(),
            ReflectValue::Bool(true)
        )
    }

    fn pointer_intersects_secret(
        &self,
        descriptor: &MessageDescriptor,
        segments: &[String],
    ) -> bool {
        if segments.is_empty() {
            return self.message_contains_secret(descriptor, &mut HashSet::new());
        }

        let Some(field) = descriptor.get_field_by_json_name(&segments[0]) else {
            return false;
        };
        if self.is_secret(&field) {
            return true;
        }

        let remaining = &segments[1..];
        let Kind::Message(mut nested) = field.kind() else {
            return false;
        };

        if field.is_map() {
            let Some(value_field) = nested.get_field_by_name("value") else {
                return false;
            };
            let Kind::Message(value_message) = value_field.kind() else {
                return false;
            };
            nested = value_message;
            if remaining.is_empty() {
                return self.message_contains_secret(&nested, &mut HashSet::new());
            }
            return self.pointer_intersects_secret(&nested, &remaining[1..]);
        }

        if field.is_list() {
            if remaining.is_empty() {
                return self.message_contains_secret(&nested, &mut HashSet::new());
            }
            return self.pointer_intersects_secret(&nested, &remaining[1..]);
        }

        if remaining.is_empty() {
            self.message_contains_secret(&nested, &mut HashSet::new())
        } else {
            self.pointer_intersects_secret(&nested, remaining)
        }
    }

    fn message_contains_secret(
        &self,
        descriptor: &MessageDescriptor,
        visiting: &mut HashSet<String>,
    ) -> bool {
        if !visiting.insert(descriptor.full_name().to_string()) {
            return false;
        }
        let contains = descriptor.fields().any(|field| {
            if self.is_secret(&field) {
                return true;
            }
            match field.kind() {
                Kind::Message(message) if field.is_map() => message
                    .get_field_by_name("value")
                    .and_then(|value| match value.kind() {
                        Kind::Message(message) => Some(message),
                        _ => None,
                    })
                    .is_some_and(|message| self.message_contains_secret(&message, visiting)),
                Kind::Message(message) => self.message_contains_secret(&message, visiting),
                _ => false,
            }
        });
        visiting.remove(descriptor.full_name());
        contains
    }
}

fn omit_nested_secrets(codec: &ProtoJsonCodec, value: &mut ReflectValue) {
    match value {
        ReflectValue::Message(message) => codec.omit_secrets(message),
        ReflectValue::List(values) => {
            for value in values {
                omit_nested_secrets(codec, value);
            }
        }
        ReflectValue::Map(values) => {
            for value in values.values_mut() {
                omit_nested_secrets(codec, value);
            }
        }
        _ => {}
    }
}

fn parse_json_pointer(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(pointer) = pointer.strip_prefix('/') else {
        return Err(InterceptorError::InvalidResult(format!(
            "invalid JSON patch path '{pointer}': JSON Pointer must start with '/'"
        )));
    };
    pointer
        .split('/')
        .map(|segment| {
            let mut decoded = String::with_capacity(segment.len());
            let mut chars = segment.chars();
            while let Some(ch) = chars.next() {
                if ch != '~' {
                    decoded.push(ch);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => {
                        return Err(InterceptorError::InvalidResult(format!(
                            "invalid JSON patch path '/{pointer}': invalid JSON Pointer escape"
                        )));
                    }
                }
            }
            Ok(decoded)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openshell_core::proto::{
        CreateProviderRequest, CreateSandboxRequest, GpuResourceRequirements, Provider,
        SandboxSpec, UpdateConfigRequest,
    };
    use prost::Message as _;
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        field_descriptor_proto::{Label, Type},
    };
    use serde_json::json;

    use super::*;
    use crate::InterceptorError;

    #[test]
    fn dynamic_create_sandbox_round_trip_uses_json_names() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                ..SandboxSpec::default()
            }),
            name: "demo".to_string(),
            labels: HashMap::from([("team".to_string(), "agent".to_string())]),
            annotations: HashMap::new(),
        };
        let bytes = request.encode_to_vec();
        let json = codec
            .decode_bytes_to_json("openshell.v1.CreateSandboxRequest", &bytes)
            .unwrap();
        assert_eq!(json["spec"]["providers"][0], "github");
        assert_eq!(json["labels"]["team"], "agent");
        let encoded = codec
            .encode_json_to_message("openshell.v1.CreateSandboxRequest", &json)
            .unwrap();
        let decoded = CreateSandboxRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn interceptor_view_omits_nested_secrets_but_keeps_non_secret_fields() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let request = CreateProviderRequest {
            provider: Some(Provider {
                r#type: "github".to_string(),
                credentials: HashMap::from([(
                    "GITHUB_TOKEN".to_string(),
                    "secret-value".to_string(),
                )]),
                config: HashMap::from([("region".to_string(), "us-west".to_string())]),
                ..Provider::default()
            }),
        };
        let encoded = request.encode_to_vec();

        let authoritative = codec
            .decode_bytes_to_json("openshell.v1.CreateProviderRequest", &encoded)
            .unwrap();
        let interceptor = codec
            .decode_bytes_to_interceptor_json("openshell.v1.CreateProviderRequest", &encoded)
            .unwrap();

        assert_eq!(
            authoritative["provider"]["credentials"]["GITHUB_TOKEN"],
            "secret-value"
        );
        assert!(interceptor["provider"].get("credentials").is_none());
        assert_eq!(interceptor["provider"]["config"]["region"], "us-west");
    }

    #[test]
    fn dedicated_secret_fields_are_annotated_in_the_descriptor_set() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        for (message_name, field_name) in [
            ("openshell.datamodel.v1.Provider", "credentials"),
            ("openshell.inference.v1.ResolvedRoute", "api_key"),
            ("openshell.compute.v1.DriverSandboxSpec", "sandbox_token"),
            ("openshell.v1.IssueSandboxTokenResponse", "token"),
            ("openshell.v1.RefreshSandboxTokenResponse", "token"),
            ("openshell.v1.CreateSshSessionResponse", "token"),
            ("openshell.v1.RevokeSshSessionRequest", "token"),
            ("openshell.v1.TcpForwardInit", "authorization_token"),
            ("openshell.v1.SshSession", "token"),
            (
                "openshell.v1.StoredProviderCredentialRefreshState",
                "material",
            ),
            ("openshell.v1.ConfigureProviderRefreshRequest", "material"),
            (
                "openshell.v1.GetSandboxProviderEnvironmentResponse",
                "environment",
            ),
        ] {
            let message = codec.message_descriptor(message_name).unwrap();
            let field = message.get_field_by_name(field_name).unwrap();
            assert!(
                codec.is_secret(&field),
                "{message_name}.{field_name} must be marked secret"
            );
        }
    }

    #[test]
    fn generic_sandbox_environment_remains_visible() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                environment: HashMap::from([("FEATURE_FLAG".to_string(), "on".to_string())]),
                ..SandboxSpec::default()
            }),
            ..CreateSandboxRequest::default()
        };

        let interceptor = codec
            .decode_bytes_to_interceptor_json(
                "openshell.v1.CreateSandboxRequest",
                &request.encode_to_vec(),
            )
            .unwrap();

        assert_eq!(interceptor["spec"]["environment"]["FEATURE_FLAG"], "on");
    }

    #[test]
    fn secret_patch_paths_and_containing_objects_are_hidden() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        for pointer in [
            "",
            "/provider",
            "/provider/credentials",
            "/provider/credentials/key",
        ] {
            let err = codec
                .ensure_interceptor_patch_path_visible(
                    "openshell.v1.CreateProviderRequest",
                    pointer,
                )
                .expect_err("secret path or ancestor must be rejected");
            assert!(err.to_string().contains("omitted secret field"));
        }
        codec
            .ensure_interceptor_patch_path_visible(
                "openshell.v1.CreateProviderRequest",
                "/provider/config/region",
            )
            .unwrap();
        codec
            .ensure_interceptor_patch_path_visible(
                "openshell.v1.CreateProviderRequest",
                "/provider/metadata/name",
            )
            .unwrap();
    }

    #[test]
    fn dynamic_update_config_round_trip_preserves_annotations() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let request = UpdateConfigRequest {
            name: "demo".to_string(),
            annotations: HashMap::from([(
                "openshell.nvidia.com/policy-signature".to_string(),
                "signed".to_string(),
            )]),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let json = codec
            .decode_bytes_to_json("openshell.v1.UpdateConfigRequest", &bytes)
            .unwrap();
        assert_eq!(
            json["annotations"]["openshell.nvidia.com/policy-signature"],
            "signed"
        );
        let encoded = codec
            .encode_json_to_message("openshell.v1.UpdateConfigRequest", &json)
            .unwrap();
        let decoded = UpdateConfigRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn descriptor_loading_rejects_invalid_oneof_indexes() {
        let descriptor_set = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                package: Some("test".to_string()),
                message_type: vec![DescriptorProto {
                    name: Some("Broken".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("value".to_string()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        oneof_index: Some(0),
                        ..FieldDescriptorProto::default()
                    }],
                    ..DescriptorProto::default()
                }],
                ..FileDescriptorProto::default()
            }],
        };

        let err = ProtoJsonCodec::from_descriptor_set(&descriptor_set.encode_to_vec())
            .expect_err("out-of-range oneof index must be rejected");

        assert!(matches!(err, InterceptorError::Config(_)));
        assert!(err.to_string().contains("oneof"));
    }

    #[test]
    fn dynamic_codec_uses_last_policy_merge_oneof_member_on_wire() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let add_then_remove = vec![0x0a, 0x00, 0x1a, 0x00];
        let remove_then_add = vec![0x1a, 0x00, 0x0a, 0x00];

        for (bytes, selected, discarded) in [
            (add_then_remove, "removeRule", "addRule"),
            (remove_then_add, "addRule", "removeRule"),
        ] {
            let json = codec
                .decode_bytes_to_json("openshell.v1.PolicyMergeOperation", &bytes)
                .unwrap();
            assert_eq!(json[selected], json!({}));
            assert!(json.get(discarded).is_none());
        }
    }

    #[test]
    fn dynamic_codec_uses_last_interceptor_phase_on_wire() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let modify_then_validate = vec![0x32, 0x00, 0x3a, 0x00];

        let json = codec
            .decode_bytes_to_json(
                "openshell.gateway_interceptor.v1.InterceptorEvaluation",
                &modify_then_validate,
            )
            .unwrap();

        assert_eq!(json["validate"], json!({}));
        assert!(json.get("modifyOperation").is_none());
    }

    #[test]
    fn dynamic_codec_uses_last_well_known_value_member_on_wire() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let string_then_bool = [0x1a, 0x04, b't', b'e', b'x', b't', 0x20, 0x01];
        let bool_then_string = [0x20, 0x01, 0x1a, 0x04, b't', b'e', b'x', b't'];

        let bool_json = codec
            .decode_bytes_to_json("google.protobuf.Value", &string_then_bool)
            .unwrap();
        let string_json = codec
            .decode_bytes_to_json("google.protobuf.Value", &bool_then_string)
            .unwrap();

        assert_eq!(bool_json, json!(true));
        assert_eq!(string_json, json!("text"));
    }

    #[test]
    fn dynamic_codec_uses_last_value_member_nested_in_well_known_struct() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let struct_bytes = [
            0x0a, 0x0f, 0x0a, 0x03, b'k', b'e', b'y', 0x12, 0x08, 0x1a, 0x04, b't', b'e', b'x',
            b't', 0x20, 0x01,
        ];

        let json = codec
            .decode_bytes_to_json("google.protobuf.Struct", &struct_bytes)
            .unwrap();

        assert_eq!(json, json!({"key": true}));
    }

    #[test]
    fn dynamic_codec_rejects_ambiguous_oneof_json_before_encoding() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();

        let err = codec
            .encode_json_to_message(
                "openshell.v1.PolicyMergeOperation",
                &json!({
                    "addRule": {},
                    "removeRule": {}
                }),
            )
            .expect_err("multiple JSON alternatives must be rejected");

        assert!(err.to_string().contains("oneof 'operation'"));
    }

    #[test]
    fn dynamic_codec_round_trips_each_policy_merge_oneof_alternative() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();

        for field in [
            "addRule",
            "removeEndpoint",
            "removeRule",
            "addDenyRules",
            "addAllowRules",
            "removeBinary",
        ] {
            let json = json!({ (field): {} });
            let encoded = codec
                .encode_json_to_message("openshell.v1.PolicyMergeOperation", &json)
                .unwrap();
            let decoded = codec
                .decode_bytes_to_json("openshell.v1.PolicyMergeOperation", &encoded)
                .unwrap();
            let decoded = decoded
                .as_object()
                .expect("decoded oneof must be an object");
            assert_eq!(decoded.len(), 1);
            assert!(decoded.contains_key(field));
        }
    }

    #[test]
    fn dynamic_codec_preserves_proto3_optional_presence() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();

        for request in [
            GpuResourceRequirements { count: None },
            GpuResourceRequirements { count: Some(0) },
            GpuResourceRequirements { count: Some(2) },
        ] {
            let json = codec
                .decode_bytes_to_json(
                    "openshell.v1.GpuResourceRequirements",
                    &request.encode_to_vec(),
                )
                .unwrap();
            let encoded = codec
                .encode_json_to_message("openshell.v1.GpuResourceRequirements", &json)
                .unwrap();
            let decoded = GpuResourceRequirements::decode(encoded.as_slice()).unwrap();
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn dynamic_codec_uses_last_nested_oneof_member_on_wire() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let update_config = [0x3a, 0x04, 0x0a, 0x00, 0x1a, 0x00];

        let json = codec
            .decode_bytes_to_json("openshell.v1.UpdateConfigRequest", &update_config)
            .unwrap();

        assert_eq!(json["mergeOperations"][0], json!({"removeRule": {}}));
    }
}
