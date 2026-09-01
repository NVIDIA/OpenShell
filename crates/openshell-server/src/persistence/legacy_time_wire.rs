// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compatibility rewriting for protobuf records written before time fields used WKTs.

use prost::Message;
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
use std::sync::LazyLock;

use super::{PersistenceError, PersistenceResult};

static DESCRIPTORS: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
        .expect("the embedded protobuf descriptor set must be valid")
});

#[derive(Clone, Copy)]
enum Conversion {
    Timestamp { new_tag: u32 },
    TimestampString { new_tag: u32 },
    DurationSeconds { new_tag: u32 },
    DurationString { new_tag: u32 },
    TimestampMap { new_tag: u32 },
}

pub(super) fn migrate(object_type: &str, payload: &[u8]) -> PersistenceResult<Vec<u8>> {
    let Some(message_name) = root_message_name(object_type) else {
        return Ok(payload.to_vec());
    };
    let descriptor = DESCRIPTORS
        .get_message_by_name(message_name)
        .ok_or_else(|| {
            PersistenceError::Decode(format!("missing descriptor for {message_name}"))
        })?;
    rewrite_message(&descriptor, payload)
}

fn root_message_name(object_type: &str) -> Option<&'static str> {
    match object_type {
        "sandbox" => Some("openshell.v1.Sandbox"),
        "provider" => Some("openshell.datamodel.v1.Provider"),
        "workspace" => Some("openshell.datamodel.v1.Workspace"),
        "workspace_member" => Some("openshell.v1.WorkspaceMember"),
        "inference_route" => Some("openshell.inference.v1.InferenceRoute"),
        "provider_profile" => Some("openshell.v1.StoredProviderProfile"),
        "provider_credential_refresh_state" => {
            Some("openshell.v1.StoredProviderCredentialRefreshState")
        }
        "service_endpoint" => Some("openshell.v1.ServiceEndpoint"),
        "ssh_session" => Some("openshell.v1.SshSession"),
        "sandbox_policy" => Some("openshell.v1.PolicyRevisionPayload"),
        "draft_policy_chunk" => Some("openshell.v1.DraftChunkPayload"),
        _ => None,
    }
}

fn rewrite_message(descriptor: &MessageDescriptor, input: &[u8]) -> PersistenceResult<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while offset < input.len() {
        let field_start = offset;
        let (key, key_len) = read_varint(&input[offset..])?;
        offset += key_len;
        let field_number = u32::try_from(key >> 3)
            .map_err(|_| PersistenceError::Decode("protobuf field number overflow".into()))?;
        let wire_type = (key & 7) as u8;
        let (payload_start, payload_end, field_end) = field_bounds(input, offset, wire_type)?;

        if let Some(conversion) = conversion(descriptor.full_name(), field_number) {
            rewrite_legacy_field(
                &mut output,
                conversion,
                wire_type,
                &input[payload_start..payload_end],
            )?;
        } else if wire_type == 2
            && let Some(field) = descriptor.get_field(field_number)
            && !field.is_map()
            && let Kind::Message(child) = field.kind()
        {
            let rewritten = rewrite_message(&child, &input[payload_start..payload_end])?;
            write_key(&mut output, field_number, 2);
            write_varint(&mut output, rewritten.len() as u64);
            output.extend_from_slice(&rewritten);
        } else {
            output.extend_from_slice(&input[field_start..field_end]);
        }
        offset = field_end;
    }
    Ok(output)
}

fn rewrite_legacy_field(
    output: &mut Vec<u8>,
    conversion: Conversion,
    wire_type: u8,
    payload: &[u8],
) -> PersistenceResult<()> {
    match conversion {
        Conversion::Timestamp { new_tag } => {
            require_wire_type(wire_type, 0)?;
            let (raw, consumed) = read_varint(payload)?;
            if consumed != payload.len() {
                return Err(PersistenceError::Decode("invalid legacy timestamp".into()));
            }
            let millis = raw.cast_signed();
            if millis != 0 {
                let timestamp = openshell_core::time::timestamp_from_millis(millis)
                    .map_err(|error| PersistenceError::Decode(error.to_string()))?;
                write_embedded(output, new_tag, &timestamp.encode_to_vec());
            }
        }
        Conversion::TimestampString { new_tag } => {
            require_wire_type(wire_type, 2)?;
            if !payload.is_empty() {
                let value = std::str::from_utf8(payload).map_err(|error| {
                    PersistenceError::Decode(format!("legacy timestamp is not UTF-8: {error}"))
                })?;
                let timestamp: prost_types::Timestamp = value.parse().map_err(|error| {
                    PersistenceError::Decode(format!("invalid legacy timestamp: {error}"))
                })?;
                openshell_core::time::validate_timestamp(&timestamp)
                    .map_err(|error| PersistenceError::Decode(error.to_string()))?;
                write_embedded(output, new_tag, &timestamp.encode_to_vec());
            }
        }
        Conversion::DurationSeconds { new_tag } => {
            require_wire_type(wire_type, 0)?;
            let (seconds, consumed) = read_varint(payload)?;
            if consumed != payload.len() {
                return Err(PersistenceError::Decode("invalid legacy duration".into()));
            }
            if seconds != 0 {
                let seconds = i64::try_from(seconds).map_err(|_| {
                    PersistenceError::Decode("legacy duration exceeds protobuf range".into())
                })?;
                let duration = prost_types::Duration { seconds, nanos: 0 };
                openshell_core::time::validate_duration(&duration)
                    .map_err(|error| PersistenceError::Decode(error.to_string()))?;
                write_embedded(output, new_tag, &duration.encode_to_vec());
            }
        }
        Conversion::DurationString { new_tag } => {
            require_wire_type(wire_type, 2)?;
            if !payload.is_empty() {
                let value = std::str::from_utf8(payload).map_err(|error| {
                    PersistenceError::Decode(format!("legacy duration is not UTF-8: {error}"))
                })?;
                let duration = parse_legacy_duration(value)?;
                let duration = openshell_core::time::duration_from_std(duration)
                    .map_err(|error| PersistenceError::Decode(error.to_string()))?;
                write_embedded(output, new_tag, &duration.encode_to_vec());
            }
        }
        Conversion::TimestampMap { new_tag } => {
            require_wire_type(wire_type, 2)?;
            if let Some(rewritten) = rewrite_timestamp_map_entry(payload)? {
                write_embedded(output, new_tag, &rewritten);
            }
        }
    }
    Ok(())
}

fn parse_legacy_duration(value: &str) -> PersistenceResult<std::time::Duration> {
    let (number, millis_multiplier) = value
        .strip_suffix("ms")
        .map(|number| (number, 1u64))
        .or_else(|| value.strip_suffix('s').map(|number| (number, 1_000u64)))
        .ok_or_else(|| PersistenceError::Decode("legacy duration must end in ms or s".into()))?;
    let amount = number
        .parse::<u64>()
        .map_err(|error| PersistenceError::Decode(format!("invalid legacy duration: {error}")))?;
    let millis = amount
        .checked_mul(millis_multiplier)
        .ok_or_else(|| PersistenceError::Decode("legacy duration overflow".into()))?;
    Ok(std::time::Duration::from_millis(millis))
}

fn rewrite_timestamp_map_entry(input: &[u8]) -> PersistenceResult<Option<Vec<u8>>> {
    let mut output = Vec::with_capacity(input.len() + 8);
    let mut has_expiration = false;
    let mut offset = 0;
    while offset < input.len() {
        let start = offset;
        let (key, key_len) = read_varint(&input[offset..])?;
        offset += key_len;
        let number = u32::try_from(key >> 3)
            .map_err(|_| PersistenceError::Decode("protobuf field number overflow".into()))?;
        let wire_type = (key & 7) as u8;
        let (payload_start, payload_end, field_end) = field_bounds(input, offset, wire_type)?;
        if number == 2 {
            require_wire_type(wire_type, 0)?;
            let (raw, consumed) = read_varint(&input[payload_start..payload_end])?;
            if consumed != payload_end - payload_start {
                return Err(PersistenceError::Decode(
                    "invalid legacy expiration map".into(),
                ));
            }
            let millis = raw.cast_signed();
            if millis != 0 {
                let timestamp = openshell_core::time::timestamp_from_millis(millis)
                    .map_err(|error| PersistenceError::Decode(error.to_string()))?;
                write_embedded(&mut output, 2, &timestamp.encode_to_vec());
                has_expiration = true;
            }
        } else {
            output.extend_from_slice(&input[start..field_end]);
        }
        offset = field_end;
    }
    Ok(has_expiration.then_some(output))
}

fn conversion(message: &str, field: u32) -> Option<Conversion> {
    use Conversion::{
        DurationSeconds as D, DurationString as DS, Timestamp as T, TimestampMap as M,
        TimestampString as TS,
    };
    match (message, field) {
        ("openshell.datamodel.v1.ObjectMeta", 3) => Some(T { new_tag: 103 }),
        ("openshell.datamodel.v1.ObjectMeta" | "openshell.v1.SshSession", 8) => {
            Some(T { new_tag: 108 })
        }
        ("openshell.datamodel.v1.Provider", 5) => Some(M { new_tag: 105 }),
        ("openshell.inference.v1.InferenceRouteConfig", 3) => Some(D { new_tag: 103 }),
        ("openshell.v1.SandboxCondition", 5) => Some(TS { new_tag: 105 }),
        ("openshell.v1.PlatformEvent", 1) => Some(T { new_tag: 101 }),
        (
            "openshell.v1.ProviderCredentialTokenGrant" | "openshell.v1.ProviderCredentialRefresh",
            4,
        ) => Some(D { new_tag: 104 }),
        ("openshell.v1.ProviderCredentialRefresh", 5) => Some(D { new_tag: 105 }),
        ("openshell.sandbox.v1.MiddlewareBinding", 4) => Some(DS { new_tag: 104 }),
        _ => None,
    }
}

fn field_bounds(
    input: &[u8],
    value_offset: usize,
    wire_type: u8,
) -> PersistenceResult<(usize, usize, usize)> {
    match wire_type {
        0 => {
            let (_, len) = read_varint(&input[value_offset..])?;
            Ok((value_offset, value_offset + len, value_offset + len))
        }
        1 => checked_fixed_bounds(input, value_offset, 8),
        2 => {
            let (len, prefix_len) = read_varint(&input[value_offset..])?;
            let start = value_offset + prefix_len;
            let len = usize::try_from(len)
                .map_err(|_| PersistenceError::Decode("protobuf length overflow".into()))?;
            let end = start
                .checked_add(len)
                .filter(|end| *end <= input.len())
                .ok_or_else(|| PersistenceError::Decode("truncated protobuf field".into()))?;
            Ok((start, end, end))
        }
        5 => checked_fixed_bounds(input, value_offset, 4),
        _ => Err(PersistenceError::Decode(format!(
            "unsupported protobuf wire type {wire_type}"
        ))),
    }
}

fn checked_fixed_bounds(
    input: &[u8],
    value_offset: usize,
    len: usize,
) -> PersistenceResult<(usize, usize, usize)> {
    let end = value_offset
        .checked_add(len)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| PersistenceError::Decode("truncated protobuf field".into()))?;
    Ok((value_offset, end, end))
}

fn read_varint(input: &[u8]) -> PersistenceResult<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in input.iter().copied().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(PersistenceError::Decode("invalid protobuf varint".into()))
}

fn write_key(output: &mut Vec<u8>, field_number: u32, wire_type: u8) {
    write_varint(
        output,
        (u64::from(field_number) << 3) | u64::from(wire_type),
    );
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(value.to_le_bytes()[0] | 0x80);
        value >>= 7;
    }
    output.push(value.to_le_bytes()[0]);
}

fn write_embedded(output: &mut Vec<u8>, field_number: u32, payload: &[u8]) {
    write_key(output, field_number, 2);
    write_varint(output, payload.len() as u64);
    output.extend_from_slice(payload);
}

fn require_wire_type(actual: u8, expected: u8) -> PersistenceResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(PersistenceError::Decode(format!(
            "legacy time field has wire type {actual}, expected {expected}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{InferenceRoute, Provider};
    use std::collections::HashMap;

    #[derive(Clone, PartialEq, Message)]
    struct LegacyObjectMeta {
        #[prost(string, tag = "1")]
        id: String,
        #[prost(string, tag = "2")]
        name: String,
        #[prost(int64, tag = "3")]
        created_at_ms: i64,
        #[prost(int64, tag = "8")]
        deletion_timestamp_ms: i64,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyProvider {
        #[prost(message, optional, tag = "1")]
        metadata: Option<LegacyObjectMeta>,
        #[prost(string, tag = "2")]
        r#type: String,
        #[prost(map = "string, int64", tag = "5")]
        credential_expires_at_ms: HashMap<String, i64>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyInferenceRouteConfig {
        #[prost(string, tag = "1")]
        provider_name: String,
        #[prost(string, tag = "2")]
        model_id: String,
        #[prost(uint64, tag = "3")]
        timeout_secs: u64,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyInferenceRoute {
        #[prost(message, optional, tag = "1")]
        metadata: Option<LegacyObjectMeta>,
        #[prost(message, optional, tag = "2")]
        config: Option<LegacyInferenceRouteConfig>,
    }

    #[test]
    fn migrates_nested_metadata_and_timestamp_maps() {
        let legacy = LegacyProvider {
            metadata: Some(LegacyObjectMeta {
                id: "provider-id".into(),
                name: "provider-name".into(),
                created_at_ms: 1_700_000_000_123,
                deletion_timestamp_ms: 1_700_000_001_456,
            }),
            r#type: "test".into(),
            credential_expires_at_ms: HashMap::from([
                ("TOKEN".into(), 1_700_000_002_789),
                ("NO_EXPIRY".into(), 0),
            ]),
        };

        let migrated = migrate("provider", &legacy.encode_to_vec()).unwrap();
        let provider = Provider::decode(migrated.as_slice()).unwrap();
        let metadata = provider.metadata.unwrap();
        assert_eq!(
            openshell_core::time::timestamp_to_millis(&metadata.created_time.unwrap()).unwrap(),
            1_700_000_000_123
        );
        assert_eq!(
            openshell_core::time::timestamp_to_millis(&metadata.deletion_time.unwrap()).unwrap(),
            1_700_000_001_456
        );
        assert_eq!(
            openshell_core::time::timestamp_to_millis(
                provider.credential_expiration_times.get("TOKEN").unwrap()
            )
            .unwrap(),
            1_700_000_002_789
        );
        assert!(
            !provider
                .credential_expiration_times
                .contains_key("NO_EXPIRY")
        );
    }

    #[test]
    fn migrates_nested_duration() {
        let legacy = LegacyInferenceRoute {
            metadata: Some(LegacyObjectMeta {
                id: "route-id".into(),
                name: "route-name".into(),
                created_at_ms: 1_700_000_000_000,
                deletion_timestamp_ms: 0,
            }),
            config: Some(LegacyInferenceRouteConfig {
                provider_name: "provider".into(),
                model_id: "model".into(),
                timeout_secs: 90,
            }),
        };

        let migrated = migrate("inference_route", &legacy.encode_to_vec()).unwrap();
        let route = InferenceRoute::decode(migrated.as_slice()).unwrap();
        assert_eq!(route.config.unwrap().request_timeout.unwrap().seconds, 90);
    }

    #[test]
    fn rejects_malformed_legacy_time_wire_type() {
        let descriptor = DESCRIPTORS
            .get_message_by_name("openshell.datamodel.v1.ObjectMeta")
            .unwrap();
        // Legacy field 3 encoded as length-delimited instead of int64 varint.
        let error = rewrite_message(&descriptor, &[0x1a, 0x01, 0x00]).unwrap_err();
        assert!(error.to_string().contains("wire type"));
    }

    #[test]
    fn rejects_out_of_range_legacy_timestamps() {
        let legacy = LegacyObjectMeta {
            id: "invalid".into(),
            name: "invalid".into(),
            created_at_ms: i64::MAX,
            deletion_timestamp_ms: 0,
        };
        let descriptor = DESCRIPTORS
            .get_message_by_name("openshell.datamodel.v1.ObjectMeta")
            .unwrap();
        let error = rewrite_message(&descriptor, &legacy.encode_to_vec()).unwrap_err();
        assert!(error.to_string().contains("timestamp"));
    }

    #[test]
    fn public_time_fields_use_well_known_types() {
        let private_storage_messages = [
            "openshell.v1.StoredProviderCredentialRefreshState",
            "openshell.v1.PolicyRevisionPayload",
            "openshell.v1.DraftChunkPayload",
            "openshell.v1.StoredPolicyRevision",
            "openshell.v1.StoredDraftChunk",
        ];
        let mut violations = Vec::new();
        for message in DESCRIPTORS.all_messages() {
            if private_storage_messages.contains(&message.full_name()) {
                continue;
            }
            for field in message.fields() {
                let name = field.name();
                let looks_temporal = name.ends_with("_ms")
                    || name.ends_with("_secs")
                    || name.ends_with("_seconds")
                    || name == "timeout"
                    || name == "expires_in"
                    || name == "last_transition_time";
                if looks_temporal
                    && !matches!(
                        field.kind(),
                        Kind::Message(ref descriptor)
                            if descriptor.full_name() == "google.protobuf.Timestamp"
                                || descriptor.full_name() == "google.protobuf.Duration"
                    )
                {
                    violations.push(format!("{}.{}", message.full_name(), name));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "public scalar time fields remain: {}",
            violations.join(", ")
        );
    }
}
