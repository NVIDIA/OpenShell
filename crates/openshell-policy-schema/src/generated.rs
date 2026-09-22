// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use miette::{IntoDiagnostic, Result, WrapErr};
use prost::Message;
use prost_protovalidate::Validator;
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, MessageDescriptor, SerializeOptions};
use prost_types::{ListValue, Struct, Value, value};
use serde::Serialize;

use crate::proto;
use crate::{
    AnyMatcher, FilesystemPolicy, GraphqlOperation, JsonRpcConfig, L7Allow, L7DenyRule, L7Rule,
    LandlockCompatibility, LandlockPolicy, McpConfig, MiddlewareEndpointSelector, NetworkBinary,
    NetworkCredentialBinding, NetworkEndpoint, NetworkMiddleware, NetworkPolicyRule,
    ParameterMatcher, ParseLimits, PolicyDocument, ProcessPolicy, QueryMatcher,
};

const POLICY_MESSAGE_NAME: &str = "openshell.policy.v1.PolicyDocument";
const L7_RULE_MESSAGE_NAME: &str = "openshell.policy.v1.L7Rule";
const L7_DENY_RULE_MESSAGE_NAME: &str = "openshell.policy.v1.L7DenyRule";
const NETWORK_BINARY_MESSAGE_NAME: &str = "openshell.policy.v1.NetworkBinary";

fn policy_descriptor_pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(
            include_bytes!(concat!(env!("OUT_DIR"), "/policy_descriptor.bin")).as_slice(),
        )
        .expect("compiled policy descriptor set must decode")
    })
}

fn message_descriptor(full_name: &str) -> MessageDescriptor {
    policy_descriptor_pool()
        .get_message_by_name(full_name)
        .unwrap_or_else(|| panic!("compiled descriptor set must contain {full_name}"))
}

fn policy_descriptor() -> MessageDescriptor {
    message_descriptor(POLICY_MESSAGE_NAME)
}

fn policy_validator() -> &'static Validator {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR.get_or_init(Validator::new)
}

fn dynamic_message<T: Message>(message: &T, full_name: &str) -> Result<DynamicMessage> {
    let mut dynamic = DynamicMessage::new(message_descriptor(full_name));
    dynamic
        .transcode_from(message)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to encode generated {full_name}"))?;
    Ok(dynamic)
}

fn validate_proto_contract<T: Message>(message: &T, full_name: &str, context: &str) -> Result<()> {
    let dynamic = dynamic_message(message, full_name)?;
    if let Err(error) = policy_validator().validate(&dynamic) {
        let summary = error.to_string();
        return Err(error).into_diagnostic().wrap_err_with(|| {
            format!("{context} violates its protobuf validation contract: {summary}")
        });
    }
    Ok(())
}

fn validate_proto_json_yaml(value: &serde_yml::Value) -> Result<()> {
    match value {
        serde_yml::Value::Sequence(values) => {
            for value in values {
                validate_proto_json_yaml(value)?;
            }
        }
        serde_yml::Value::Mapping(entries) => {
            for value in entries.values() {
                validate_proto_json_yaml(value)?;
            }
        }
        serde_yml::Value::Number(number) => {
            let exact = number.as_i64().map_or_else(
                || {
                    number
                        .as_u64()
                        .map_or_else(|| number.as_f64().is_finite(), integer_is_exact_in_f64)
                },
                |value| integer_is_exact_in_f64(value.unsigned_abs()),
            );
            if !exact {
                miette::bail!(
                    "policy YAML number {number} cannot be represented exactly by protobuf JSON"
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_typed_null() -> Result<()> {
    miette::bail!(
        "policy YAML null is not allowed for typed protobuf fields; omit the field instead"
    )
}

fn validate_untyped_nulls(value: &serde_yml::Value) -> Result<()> {
    match value {
        serde_yml::Value::Null => reject_typed_null(),
        serde_yml::Value::Sequence(values) => {
            for value in values {
                validate_untyped_nulls(value)?;
            }
            Ok(())
        }
        serde_yml::Value::Mapping(entries) => {
            for value in entries.values() {
                validate_untyped_nulls(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_kind_nulls(value: &serde_yml::Value, kind: Kind) -> Result<()> {
    if matches!(value, serde_yml::Value::Null) {
        return reject_typed_null();
    }
    match kind {
        // Null is valid JSON data only below a google.protobuf.Struct value.
        Kind::Message(message) if message.full_name() == "google.protobuf.Struct" => Ok(()),
        Kind::Message(message) => validate_typed_nulls(value, &message),
        _ => validate_untyped_nulls(value),
    }
}

fn validate_typed_nulls(value: &serde_yml::Value, message: &MessageDescriptor) -> Result<()> {
    let serde_yml::Value::Mapping(entries) = value else {
        return validate_untyped_nulls(value);
    };
    for (key, value) in entries {
        // Mapping keys were already checked against the protobuf JSON model.
        let name = key.as_str();
        let Some(field) = message
            .get_field_by_name(name)
            .or_else(|| message.get_field_by_json_name(name))
        else {
            validate_untyped_nulls(value)?;
            continue;
        };
        if matches!(value, serde_yml::Value::Null) {
            return reject_typed_null();
        }
        if field.is_map() {
            let serde_yml::Value::Mapping(map) = value else {
                validate_untyped_nulls(value)?;
                continue;
            };
            let Kind::Message(entry) = field.kind() else {
                unreachable!("protobuf map fields use an entry message")
            };
            let value_kind = entry
                .get_field_by_name("value")
                .expect("protobuf map entry has a value field")
                .kind();
            for map_value in map.values() {
                validate_kind_nulls(map_value, value_kind.clone())?;
            }
        } else if field.is_list() {
            let serde_yml::Value::Sequence(items) = value else {
                validate_untyped_nulls(value)?;
                continue;
            };
            for item in items {
                validate_kind_nulls(item, field.kind())?;
            }
        } else {
            validate_kind_nulls(value, field.kind())?;
        }
    }
    Ok(())
}

fn validate_plain_mapping_key(source: &str) -> Result<()> {
    let value: serde_yml::Value = serde_yml::from_str(source)
        .into_diagnostic()
        .wrap_err("failed to inspect policy YAML mapping key")?;
    if !matches!(value, serde_yml::Value::String(_)) {
        miette::bail!(
            "policy YAML mapping key {source:?} is not a string in the protobuf JSON data model"
        );
    }
    Ok(())
}

fn is_yaml_trivia(kind: serde_yml::cst::SyntaxKind) -> bool {
    use serde_yml::cst::SyntaxKind;
    matches!(
        kind,
        SyntaxKind::Whitespace
            | SyntaxKind::Newline
            | SyntaxKind::Comment
            | SyntaxKind::Bom
            | SyntaxKind::Directive
    )
}

fn validate_mapping_entry_keys(
    node: &serde_yml::cst::GreenNode,
    source: &str,
    base: usize,
) -> Result<()> {
    use serde_yml::cst::{GreenChild, SyntaxKind};

    let mut offset = base;
    let mut found_key = false;
    for child in node.children() {
        match child {
            GreenChild::Token { kind, len } if *kind == SyntaxKind::ColonIndicator => break,
            GreenChild::Token { kind, .. }
                if is_yaml_trivia(*kind) || *kind == SyntaxKind::QuestionIndicator => {}
            GreenChild::Token { kind, len } if !found_key => {
                let raw = &source[offset..offset + *len as usize];
                match kind {
                    SyntaxKind::PlainScalar => validate_plain_mapping_key(raw)?,
                    SyntaxKind::SingleQuotedScalar
                    | SyntaxKind::DoubleQuotedScalar
                    | SyntaxKind::LiteralScalar
                    | SyntaxKind::FoldedScalar => {}
                    _ => miette::bail!(
                        "policy YAML mapping keys must be string scalars for the protobuf JSON data model"
                    ),
                }
                found_key = true;
            }
            GreenChild::Node(_) if !found_key => miette::bail!(
                "policy YAML mapping keys must be string scalars for the protobuf JSON data model"
            ),
            _ => {}
        }
        offset += child.text_len();
    }
    if !found_key {
        miette::bail!(
            "policy YAML mapping keys must be string scalars for the protobuf JSON data model"
        );
    }
    Ok(())
}

fn validate_flow_mapping_keys(
    node: &serde_yml::cst::GreenNode,
    source: &str,
    base: usize,
) -> Result<()> {
    use serde_yml::cst::{GreenChild, SyntaxKind};

    let mut offset = base;
    let mut expecting_key = true;
    let mut found_key = false;
    for child in node.children() {
        match child {
            GreenChild::Token { kind, .. }
                if is_yaml_trivia(*kind)
                    || *kind == SyntaxKind::OpenBrace
                    || *kind == SyntaxKind::QuestionIndicator => {}
            GreenChild::Token { kind, .. } if *kind == SyntaxKind::Comma => {
                expecting_key = true;
                found_key = false;
            }
            GreenChild::Token { kind, .. } if *kind == SyntaxKind::CloseBrace => {}
            GreenChild::Token { kind, .. } if *kind == SyntaxKind::ColonIndicator => {
                if expecting_key && !found_key {
                    miette::bail!(
                        "policy YAML mapping keys must be string scalars for the protobuf JSON data model"
                    );
                }
                expecting_key = false;
            }
            GreenChild::Token { kind, len } if expecting_key && !found_key => {
                let raw = &source[offset..offset + *len as usize];
                match kind {
                    SyntaxKind::PlainScalar => validate_plain_mapping_key(raw)?,
                    SyntaxKind::SingleQuotedScalar | SyntaxKind::DoubleQuotedScalar => {}
                    _ => miette::bail!(
                        "policy YAML mapping keys must be string scalars for the protobuf JSON data model"
                    ),
                }
                found_key = true;
            }
            GreenChild::Node(_) if expecting_key => miette::bail!(
                "policy YAML mapping keys must be string scalars for the protobuf JSON data model"
            ),
            _ => {}
        }
        offset += child.text_len();
    }
    Ok(())
}

fn validate_proto_json_mapping_keys(source: &str) -> Result<()> {
    fn walk(node: &serde_yml::cst::GreenNode, source: &str, base: usize) -> Result<()> {
        use serde_yml::cst::{GreenChild, SyntaxKind};

        match node.kind() {
            SyntaxKind::MappingEntry => validate_mapping_entry_keys(node, source, base)?,
            SyntaxKind::FlowMapping => validate_flow_mapping_keys(node, source, base)?,
            _ => {}
        }
        let mut offset = base;
        for child in node.children() {
            if let GreenChild::Node(child_node) = child {
                walk(child_node, source, offset)?;
            }
            offset += child.text_len();
        }
        Ok(())
    }

    let document = serde_yml::cst::parse_document(source)
        .into_diagnostic()
        .wrap_err("failed to inspect policy YAML mapping keys")?;
    walk(document.syntax(), source, 0)
}

/// Parse strict proto-shaped policy YAML into the generated public message.
pub fn parse_policy_proto(source: &str) -> Result<proto::PolicyDocument> {
    let config = crate::parser_config(ParseLimits::default());
    let value: serde_yml::Value = serde_yml::from_str_with_config(source, &config)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    validate_proto_json_mapping_keys(source)?;
    validate_typed_nulls(&value, &policy_descriptor())?;
    validate_proto_json_yaml(&value)?;
    let json_value = serde_json::to_value(value)
        .into_diagnostic()
        .wrap_err("policy YAML must use the JSON-compatible protobuf data model")?;
    let dynamic = DynamicMessage::deserialize(policy_descriptor(), json_value)
        .into_diagnostic()
        .wrap_err("failed to decode proto-shaped sandbox policy YAML")?;
    let policy = dynamic
        .transcode_to::<proto::PolicyDocument>()
        .into_diagnostic()
        .wrap_err("failed to decode generated sandbox policy")?;
    validate_authored_policy(&policy)?;
    Ok(policy)
}

/// Parse a strict proto-shaped policy YAML file into the generated message.
pub fn parse_policy_proto_file(path: &Path, limits: ParseLimits) -> Result<proto::PolicyDocument> {
    let metadata = path
        .metadata()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to inspect sandbox policy {}", path.display()))?;
    if !metadata.is_file() {
        miette::bail!(
            "sandbox policy source is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > u64::try_from(limits.max_bytes).unwrap_or(u64::MAX) {
        miette::bail!("policy exceeds the {}-byte input limit", limits.max_bytes);
    }
    let mut bytes = Vec::new();
    File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
        .take(
            u64::try_from(limits.max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?;
    if bytes.len() > limits.max_bytes {
        miette::bail!("policy exceeds the {}-byte input limit", limits.max_bytes);
    }
    let source = std::str::from_utf8(&bytes)
        .into_diagnostic()
        .wrap_err("sandbox policy is not valid UTF-8")?;
    let config = crate::parser_config(limits);
    let value: serde_yml::Value = serde_yml::from_str_with_config(source, &config)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    validate_proto_json_mapping_keys(source)?;
    validate_typed_nulls(&value, &policy_descriptor())?;
    validate_proto_json_yaml(&value)?;
    let json_value = serde_json::to_value(value)
        .into_diagnostic()
        .wrap_err("policy YAML must use the JSON-compatible protobuf data model")?;
    let dynamic = DynamicMessage::deserialize(policy_descriptor(), json_value)
        .into_diagnostic()
        .wrap_err("failed to decode proto-shaped sandbox policy YAML")?;
    let policy = dynamic
        .transcode_to::<proto::PolicyDocument>()
        .into_diagnostic()
        .wrap_err("failed to decode generated sandbox policy")?;
    validate_authored_policy(&policy)?;
    Ok(policy)
}

/// Validate a generated public policy with the schema-owned intrinsic checks.
pub fn validate_authored_policy(policy: &proto::PolicyDocument) -> Result<()> {
    validate_proto_contract(policy, POLICY_MESSAGE_NAME, "public policy")?;
    let document = PolicyDocument::try_from(policy.clone())?;
    crate::validate_policy(&document)
}

/// Validate a standalone public allow rule used by incremental policy APIs.
pub fn validate_authored_l7_rule(rule: &proto::L7Rule) -> Result<()> {
    validate_proto_contract(rule, L7_RULE_MESSAGE_NAME, "public L7 allow rule")
}

/// Validate a standalone public deny rule used by incremental policy APIs.
pub fn validate_authored_l7_deny_rule(rule: &proto::L7DenyRule) -> Result<()> {
    validate_proto_contract(rule, L7_DENY_RULE_MESSAGE_NAME, "public L7 deny rule")
}

/// Validate a standalone public binary selector used by incremental policy APIs.
pub fn validate_authored_network_binary(binary: &proto::NetworkBinary) -> Result<()> {
    validate_proto_contract(binary, NETWORK_BINARY_MESSAGE_NAME, "public network binary")
}

struct ProtoYaml<'a> {
    message: &'a DynamicMessage,
}

impl Serialize for ProtoYaml<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.message.serialize_with_options(
            serializer,
            &SerializeOptions::new().use_proto_field_name(true),
        )
    }
}

fn dynamic_policy(policy: &proto::PolicyDocument) -> Result<DynamicMessage> {
    dynamic_message(policy, POLICY_MESSAGE_NAME)
}

/// Serialize a generated public policy using canonical proto-shaped YAML.
pub fn serialize_policy_proto(policy: &proto::PolicyDocument) -> Result<String> {
    validate_authored_policy(policy)?;
    let dynamic = dynamic_policy(policy)?;
    serde_yml::to_string(&ProtoYaml { message: &dynamic })
        .into_diagnostic()
        .wrap_err("failed to serialize proto-shaped sandbox policy YAML")
}

/// Convert a generated public policy to canonical proto-shaped JSON.
pub fn policy_proto_to_json_value(policy: &proto::PolicyDocument) -> Result<serde_json::Value> {
    validate_authored_policy(policy)?;
    let dynamic = dynamic_policy(policy)?;
    serde_json::to_value(ProtoYaml { message: &dynamic })
        .into_diagnostic()
        .wrap_err("failed to serialize proto-shaped sandbox policy JSON")
}

impl TryFrom<PolicyDocument> for proto::PolicyDocument {
    type Error = miette::Report;

    fn try_from(document: PolicyDocument) -> Result<Self> {
        crate::validate_policy(&document)?;
        Ok(Self {
            version: document.version,
            filesystem_policy: document.filesystem_policy.map(Into::into),
            landlock: document.landlock.map(Into::into),
            process: document.process.map(Into::into),
            network_policies: document
                .network_policies
                .into_iter()
                .map(|(name, rule)| Ok((name, rule.try_into()?)))
                .collect::<Result<HashMap<_, _>>>()?,
            network_middlewares: document
                .network_middlewares
                .into_iter()
                .map(|(name, middleware)| Ok((name, middleware.try_into()?)))
                .collect::<Result<HashMap<_, _>>>()?,
        })
    }
}

impl TryFrom<proto::PolicyDocument> for PolicyDocument {
    type Error = miette::Report;

    fn try_from(policy: proto::PolicyDocument) -> Result<Self> {
        let document = Self {
            version: policy.version,
            filesystem_policy: policy.filesystem_policy.map(Into::into),
            landlock: policy.landlock.map(TryInto::try_into).transpose()?,
            process: policy.process.map(Into::into),
            network_policies: policy
                .network_policies
                .into_iter()
                .map(|(name, rule)| Ok((name, rule.try_into()?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
            network_middlewares: policy
                .network_middlewares
                .into_iter()
                .map(|(name, middleware)| Ok((name, middleware.try_into()?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
        };
        crate::validate_policy(&document)?;
        Ok(document)
    }
}

impl From<FilesystemPolicy> for proto::FilesystemPolicy {
    fn from(policy: FilesystemPolicy) -> Self {
        Self {
            include_workdir: policy.include_workdir,
            read_only: policy.read_only,
            read_write: policy.read_write,
        }
    }
}

impl From<proto::FilesystemPolicy> for FilesystemPolicy {
    fn from(policy: proto::FilesystemPolicy) -> Self {
        Self {
            include_workdir: policy.include_workdir,
            read_only: policy.read_only,
            read_write: policy.read_write,
        }
    }
}

impl From<LandlockPolicy> for proto::LandlockPolicy {
    fn from(policy: LandlockPolicy) -> Self {
        let compatibility = match policy.compatibility {
            LandlockCompatibility::BestEffort => "best_effort",
            LandlockCompatibility::HardRequirement => "hard_requirement",
        };
        Self {
            compatibility: compatibility.to_string(),
        }
    }
}

impl TryFrom<proto::LandlockPolicy> for LandlockPolicy {
    type Error = miette::Report;

    fn try_from(policy: proto::LandlockPolicy) -> Result<Self> {
        let compatibility = match policy.compatibility.as_str() {
            "" | "best_effort" => LandlockCompatibility::BestEffort,
            "hard_requirement" => LandlockCompatibility::HardRequirement,
            value => miette::bail!(
                "invalid landlock.compatibility '{value}'; expected best_effort or hard_requirement"
            ),
        };
        Ok(Self { compatibility })
    }
}

impl From<ProcessPolicy> for proto::ProcessPolicy {
    fn from(policy: ProcessPolicy) -> Self {
        Self {
            run_as_user: policy.run_as_user,
            run_as_group: policy.run_as_group,
        }
    }
}

impl From<proto::ProcessPolicy> for ProcessPolicy {
    fn from(policy: proto::ProcessPolicy) -> Self {
        Self {
            run_as_user: policy.run_as_user,
            run_as_group: policy.run_as_group,
        }
    }
}

impl TryFrom<NetworkPolicyRule> for proto::NetworkPolicyRule {
    type Error = miette::Report;

    fn try_from(rule: NetworkPolicyRule) -> Result<Self> {
        Ok(Self {
            name: rule.name,
            endpoints: rule
                .endpoints
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            binaries: rule.binaries.into_iter().map(Into::into).collect(),
        })
    }
}

impl TryFrom<proto::NetworkPolicyRule> for NetworkPolicyRule {
    type Error = miette::Report;

    fn try_from(rule: proto::NetworkPolicyRule) -> Result<Self> {
        Ok(Self {
            name: rule.name,
            endpoints: rule
                .endpoints
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            binaries: rule.binaries.into_iter().map(Into::into).collect(),
        })
    }
}

impl TryFrom<NetworkEndpoint> for proto::NetworkEndpoint {
    type Error = miette::Report;

    fn try_from(endpoint: NetworkEndpoint) -> Result<Self> {
        Ok(Self {
            host: endpoint.host,
            path: endpoint.path,
            ports: endpoint.ports.into_iter().map(u32::from).collect(),
            protocol: endpoint.protocol,
            tls: endpoint.tls,
            enforcement: endpoint.enforcement,
            access: endpoint.access,
            rules: endpoint
                .rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allowed_ips: endpoint.allowed_ips,
            deny_rules: endpoint
                .deny_rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allow_encoded_slash: endpoint.allow_encoded_slash,
            websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
            request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
            allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
            persisted_queries: endpoint.persisted_queries,
            graphql_persisted_queries: endpoint
                .graphql_persisted_queries
                .into_iter()
                .map(|(name, operation)| (name, operation.into()))
                .collect(),
            graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
            credential_signing: endpoint.credential_signing,
            signing_service: endpoint.signing_service,
            signing_region: endpoint.signing_region,
            credential_binding: endpoint.credential_binding.map(Into::into),
            json_rpc: endpoint.json_rpc.map(Into::into),
            mcp: endpoint.mcp.map(Into::into),
        })
    }
}

impl TryFrom<proto::NetworkEndpoint> for NetworkEndpoint {
    type Error = miette::Report;

    fn try_from(endpoint: proto::NetworkEndpoint) -> Result<Self> {
        Ok(Self {
            host: endpoint.host,
            path: endpoint.path,
            ports: endpoint
                .ports
                .into_iter()
                .map(|port| {
                    u16::try_from(port)
                        .into_diagnostic()
                        .wrap_err("endpoint.ports values must be in 0..=65535")
                })
                .collect::<Result<_>>()?,
            protocol: endpoint.protocol,
            tls: endpoint.tls,
            enforcement: endpoint.enforcement,
            access: endpoint.access,
            rules: endpoint
                .rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allowed_ips: endpoint.allowed_ips,
            deny_rules: endpoint
                .deny_rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allow_encoded_slash: endpoint.allow_encoded_slash,
            websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
            request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
            allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
            persisted_queries: endpoint.persisted_queries,
            graphql_persisted_queries: endpoint
                .graphql_persisted_queries
                .into_iter()
                .map(|(name, operation)| (name, operation.into()))
                .collect(),
            graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
            credential_signing: endpoint.credential_signing,
            signing_service: endpoint.signing_service,
            signing_region: endpoint.signing_region,
            credential_binding: endpoint.credential_binding.map(Into::into),
            json_rpc: endpoint.json_rpc.map(Into::into),
            mcp: endpoint.mcp.map(Into::into),
        })
    }
}

impl From<NetworkCredentialBinding> for proto::NetworkCredentialBinding {
    fn from(binding: NetworkCredentialBinding) -> Self {
        Self {
            provider: binding.provider,
        }
    }
}

impl From<proto::NetworkCredentialBinding> for NetworkCredentialBinding {
    fn from(binding: proto::NetworkCredentialBinding) -> Self {
        Self {
            provider: binding.provider,
        }
    }
}

impl From<JsonRpcConfig> for proto::JsonRpcConfig {
    fn from(config: JsonRpcConfig) -> Self {
        Self {
            max_body_bytes: config.max_body_bytes,
        }
    }
}

impl From<proto::JsonRpcConfig> for JsonRpcConfig {
    fn from(config: proto::JsonRpcConfig) -> Self {
        Self {
            max_body_bytes: config.max_body_bytes,
        }
    }
}

impl From<McpConfig> for proto::McpConfig {
    fn from(config: McpConfig) -> Self {
        Self {
            versions: config.versions.unwrap_or_default(),
            max_body_bytes: config.max_body_bytes,
            strict_tool_names: config.strict_tool_names,
            allow_all_known_mcp_methods: config.allow_all_known_mcp_methods,
        }
    }
}

impl From<proto::McpConfig> for McpConfig {
    fn from(config: proto::McpConfig) -> Self {
        Self {
            versions: (!config.versions.is_empty()).then_some(config.versions),
            max_body_bytes: config.max_body_bytes,
            strict_tool_names: config.strict_tool_names,
            allow_all_known_mcp_methods: config.allow_all_known_mcp_methods,
        }
    }
}

impl From<GraphqlOperation> for proto::GraphqlOperation {
    fn from(operation: GraphqlOperation) -> Self {
        Self {
            operation_type: operation.operation_type,
            operation_name: operation.operation_name,
            fields: operation.fields,
        }
    }
}

impl From<proto::GraphqlOperation> for GraphqlOperation {
    fn from(operation: proto::GraphqlOperation) -> Self {
        Self {
            operation_type: operation.operation_type,
            operation_name: operation.operation_name,
            fields: operation.fields,
        }
    }
}

impl TryFrom<L7Rule> for proto::L7Rule {
    type Error = miette::Report;

    fn try_from(rule: L7Rule) -> Result<Self> {
        Ok(Self {
            allow: Some(rule.allow.try_into()?),
        })
    }
}

impl TryFrom<proto::L7Rule> for L7Rule {
    type Error = miette::Report;

    fn try_from(rule: proto::L7Rule) -> Result<Self> {
        Ok(Self {
            allow: rule
                .allow
                .ok_or_else(|| miette::miette!("L7Rule.allow is required"))?
                .try_into()?,
        })
    }
}

impl TryFrom<L7Allow> for proto::L7Allow {
    type Error = miette::Report;

    fn try_from(allow: L7Allow) -> Result<Self> {
        Ok(Self {
            method: allow.method,
            path: allow.path,
            command: allow.command,
            query: allow
                .query
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
            operation_type: allow.operation_type,
            operation_name: allow.operation_name,
            fields: allow.fields,
            tool: allow.tool.map(Into::into),
            params: allow
                .params
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
        })
    }
}

impl TryFrom<proto::L7Allow> for L7Allow {
    type Error = miette::Report;

    fn try_from(allow: proto::L7Allow) -> Result<Self> {
        Ok(Self {
            method: allow.method,
            path: allow.path,
            command: allow.command,
            query: allow
                .query
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
            operation_type: allow.operation_type,
            operation_name: allow.operation_name,
            fields: allow.fields,
            tool: allow.tool.map(TryInto::try_into).transpose()?,
            params: allow
                .params
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<L7DenyRule> for proto::L7DenyRule {
    type Error = miette::Report;

    fn try_from(rule: L7DenyRule) -> Result<Self> {
        Ok(Self {
            method: rule.method,
            path: rule.path,
            command: rule.command,
            query: rule
                .query
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
            operation_type: rule.operation_type,
            operation_name: rule.operation_name,
            fields: rule.fields,
            tool: rule.tool.map(Into::into),
            params: rule
                .params
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
        })
    }
}

impl TryFrom<proto::L7DenyRule> for L7DenyRule {
    type Error = miette::Report;

    fn try_from(rule: proto::L7DenyRule) -> Result<Self> {
        Ok(Self {
            method: rule.method,
            path: rule.path,
            command: rule.command,
            query: rule
                .query
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
            operation_type: rule.operation_type,
            operation_name: rule.operation_name,
            fields: rule.fields,
            tool: rule.tool.map(TryInto::try_into).transpose()?,
            params: rule
                .params
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
        })
    }
}

impl From<QueryMatcher> for proto::Matcher {
    fn from(matcher: QueryMatcher) -> Self {
        let kind = match matcher {
            QueryMatcher::Glob(glob) => proto::matcher::Kind::Glob(glob),
            QueryMatcher::Any(any) => {
                proto::matcher::Kind::Any(proto::AnyMatcher { values: any.any })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<proto::Matcher> for QueryMatcher {
    type Error = miette::Report;

    fn try_from(matcher: proto::Matcher) -> Result<Self> {
        match matcher.kind {
            Some(proto::matcher::Kind::Glob(glob)) => Ok(Self::Glob(glob)),
            Some(proto::matcher::Kind::Any(any)) => Ok(Self::Any(AnyMatcher { any: any.values })),
            None => miette::bail!("matcher kind is required"),
        }
    }
}

impl From<ParameterMatcher> for proto::ParameterMatcher {
    fn from(matcher: ParameterMatcher) -> Self {
        let kind = match matcher {
            ParameterMatcher::Matcher(matcher) => {
                proto::parameter_matcher::Kind::Matcher(matcher.into())
            }
            ParameterMatcher::Object(fields) => {
                proto::parameter_matcher::Kind::Object(proto::ParameterObject {
                    fields: fields
                        .into_iter()
                        .map(|(name, matcher)| (name, matcher.into()))
                        .collect(),
                })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<proto::ParameterMatcher> for ParameterMatcher {
    type Error = miette::Report;

    fn try_from(matcher: proto::ParameterMatcher) -> Result<Self> {
        match matcher.kind {
            Some(proto::parameter_matcher::Kind::Matcher(matcher)) => {
                Ok(Self::Matcher(matcher.try_into()?))
            }
            Some(proto::parameter_matcher::Kind::Object(object)) => Ok(Self::Object(
                object
                    .fields
                    .into_iter()
                    .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                    .collect::<Result<_>>()?,
            )),
            None => miette::bail!("parameter matcher kind is required"),
        }
    }
}

impl From<NetworkBinary> for proto::NetworkBinary {
    fn from(binary: NetworkBinary) -> Self {
        Self { path: binary.path }
    }
}

impl From<proto::NetworkBinary> for NetworkBinary {
    fn from(binary: proto::NetworkBinary) -> Self {
        Self { path: binary.path }
    }
}

impl TryFrom<NetworkMiddleware> for proto::NetworkMiddleware {
    type Error = miette::Report;

    fn try_from(middleware: NetworkMiddleware) -> Result<Self> {
        Ok(Self {
            name: middleware.name,
            middleware: middleware.middleware,
            order: middleware.order,
            config: (!middleware.config.is_empty())
                .then(|| json_object_to_struct(middleware.config))
                .transpose()?,
            on_error: middleware.on_error,
            endpoints: middleware.endpoints.map(Into::into),
        })
    }
}

impl TryFrom<proto::NetworkMiddleware> for NetworkMiddleware {
    type Error = miette::Report;

    fn try_from(middleware: proto::NetworkMiddleware) -> Result<Self> {
        Ok(Self {
            name: middleware.name,
            middleware: middleware.middleware,
            order: middleware.order,
            config: middleware
                .config
                .map(struct_to_json_object)
                .transpose()?
                .unwrap_or_default(),
            on_error: middleware.on_error,
            endpoints: middleware.endpoints.map(Into::into),
        })
    }
}

impl From<MiddlewareEndpointSelector> for proto::MiddlewareEndpointSelector {
    fn from(selector: MiddlewareEndpointSelector) -> Self {
        Self {
            include: selector.include,
            exclude: selector.exclude,
        }
    }
}

impl From<proto::MiddlewareEndpointSelector> for MiddlewareEndpointSelector {
    fn from(selector: proto::MiddlewareEndpointSelector) -> Self {
        Self {
            include: selector.include,
            exclude: selector.exclude,
        }
    }
}

fn json_object_to_struct(config: BTreeMap<String, serde_json::Value>) -> Result<Struct> {
    Ok(Struct {
        fields: config
            .into_iter()
            .map(|(name, value)| Ok((name, json_to_proto_value(value)?)))
            .collect::<Result<_>>()?,
    })
}

fn json_to_proto_value(value: serde_json::Value) -> Result<Value> {
    let kind = match value {
        serde_json::Value::Null => value::Kind::NullValue(0),
        serde_json::Value::Bool(value) => value::Kind::BoolValue(value),
        serde_json::Value::Number(value) => value::Kind::NumberValue(number_to_f64_exact(&value)?),
        serde_json::Value::String(value) => value::Kind::StringValue(value),
        serde_json::Value::Array(values) => value::Kind::ListValue(ListValue {
            values: values
                .into_iter()
                .map(json_to_proto_value)
                .collect::<Result<_>>()?,
        }),
        serde_json::Value::Object(fields) => value::Kind::StructValue(Struct {
            fields: fields
                .into_iter()
                .map(|(name, value)| Ok((name, json_to_proto_value(value)?)))
                .collect::<Result<_>>()?,
        }),
    };
    Ok(Value { kind: Some(kind) })
}

fn number_to_f64_exact(value: &serde_json::Number) -> Result<f64> {
    let number = value.as_f64().ok_or_else(|| {
        miette::miette!(
            "middleware config number {value} is not representable as a protobuf double"
        )
    })?;
    let exact = value.as_i64().map_or_else(
        || value.as_u64().is_none_or(integer_is_exact_in_f64),
        |integer| integer_is_exact_in_f64(integer.unsigned_abs()),
    );
    exact.then_some(number).ok_or_else(|| {
        miette::miette!(
            "middleware config number {value} is not representable exactly as a protobuf double"
        )
    })
}

fn integer_is_exact_in_f64(integer: u64) -> bool {
    integer == 0
        || (u64::BITS - integer.leading_zeros()).saturating_sub(integer.trailing_zeros())
            <= f64::MANTISSA_DIGITS
}

fn struct_to_json_object(config: Struct) -> Result<BTreeMap<String, serde_json::Value>> {
    config
        .fields
        .into_iter()
        .map(|(name, value)| Ok((name, proto_to_json_value(value)?)))
        .collect()
}

fn proto_to_json_value(value: Value) -> Result<serde_json::Value> {
    match value.kind {
        Some(value::Kind::NullValue(_)) => Ok(serde_json::Value::Null),
        Some(value::Kind::BoolValue(value)) => Ok(serde_json::Value::Bool(value)),
        Some(value::Kind::NumberValue(value)) => serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| miette::miette!("middleware config contains a non-finite number")),
        Some(value::Kind::StringValue(value)) => Ok(serde_json::Value::String(value)),
        Some(value::Kind::ListValue(list)) => Ok(serde_json::Value::Array(
            list.values
                .into_iter()
                .map(proto_to_json_value)
                .collect::<Result<_>>()?,
        )),
        Some(value::Kind::StructValue(object)) => Ok(serde_json::Value::Object(
            object
                .fields
                .into_iter()
                .map(|(name, value)| Ok((name, proto_to_json_value(value)?)))
                .collect::<Result<_>>()?,
        )),
        None => miette::bail!("middleware config value is missing its kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_policy_round_trips_canonical_yaml() {
        let source = r#"
version: 1
filesystem_policy: {}
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        mcp:
          versions: ["2025-11-25"]
          strict_tool_names: false
        rules:
          - allow:
              method: tools/call
              tool:
                glob: search_*
              params:
                arguments:
                  object:
                    fields:
                      query:
                        matcher:
                          glob: "public-*"
    binaries:
      - path: /usr/bin/agent
network_middlewares:
  audit:
    middleware: example/audit
    config:
      enabled: true
      nullable: null
"#;

        let policy = parse_policy_proto(source).expect("generated policy must parse");
        assert!(policy.filesystem_policy.is_some());
        assert_eq!(
            policy.network_policies["mcp"].endpoints[0]
                .mcp
                .as_ref()
                .and_then(|mcp| mcp.strict_tool_names),
            Some(false)
        );
        let yaml = serialize_policy_proto(&policy).expect("generated policy must serialize");
        let reparsed = parse_policy_proto(&yaml).expect("canonical YAML must parse");
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn generated_policy_uses_protobuf_empty_list_semantics_for_mcp_versions() {
        let absent = parse_policy_proto(
            "version: 1\nnetwork_policies:\n  mcp:\n    endpoints:\n      - { host: x, ports: [443], protocol: mcp, mcp: {} }\n",
        )
        .unwrap();
        assert!(
            absent.network_policies["mcp"].endpoints[0]
                .mcp
                .as_ref()
                .unwrap()
                .versions
                .is_empty()
        );
        assert!(validate_authored_policy(&absent).is_ok());
    }

    #[test]
    fn generated_policy_rejects_runtime_authority_by_construction() {
        let fields = proto::NetworkEndpoint::default();
        let debug = format!("{fields:?}");
        assert!(!debug.contains("advisor_proposed"));
        assert!(!debug.contains("provider_credentialed"));
    }

    #[test]
    fn generated_policy_rejects_middleware_integers_that_protobuf_would_round() {
        let source = r"
version: 1
network_middlewares:
  audit:
    middleware: example/audit
    config:
      request_id: 9007199254740993
";
        let error = parse_policy_proto(source).expect_err("integer must not be rounded");
        assert!(error.to_string().contains("cannot be represented exactly"));
    }

    #[test]
    fn generated_policy_rejects_legacy_scalar_matchers() {
        let source = r"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        rules:
          - allow:
              tool: search_*
";
        let error = parse_policy_proto(source).expect_err("scalar matcher must be rejected");
        assert!(error.to_string().contains("proto-shaped"));
    }

    #[test]
    fn generated_policy_rejects_legacy_non_proto_shapes() {
        let cases = [
            (
                "scalar query matcher",
                r"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        ports: [443]
        rules:
          - allow:
              query:
                owner: NVIDIA/*
",
            ),
            (
                "legacy any matcher",
                r"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        ports: [443]
        rules:
          - allow:
              query:
                owner:
                  any: [NVIDIA/*, openai/*]
",
            ),
            (
                "scalar parameter matcher",
                r"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              params:
                name: search_*
",
            ),
            (
                "unwrapped parameter object",
                r"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              params:
                arguments:
                  query: public-*
",
            ),
            (
                "scalar binary",
                r"
version: 1
network_policies:
  api:
    binaries: [/usr/bin/curl]
",
            ),
        ];

        for (name, source) in cases {
            let Err(error) = parse_policy_proto(source) else {
                panic!("{name} unexpectedly parsed");
            };
            assert!(
                error.to_string().contains("proto-shaped"),
                "{name}: {error:?}"
            );
        }
    }

    #[test]
    fn generated_policy_rejects_incomplete_and_ambiguous_oneofs() {
        let cases = [
            (
                "missing matcher kind",
                r"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        ports: [443]
        rules:
          - allow:
              query:
                owner: {}
",
            ),
            (
                "multiple matcher kinds",
                r"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        ports: [443]
        rules:
          - allow:
              tool:
                glob: search_*
                any:
                  values: [fetch_*]
",
            ),
            (
                "missing parameter matcher kind",
                r"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              params:
                arguments: {}
",
            ),
        ];

        for (name, source) in cases {
            assert!(
                parse_policy_proto(source).is_err(),
                "{name} unexpectedly parsed"
            );
        }
    }

    #[test]
    fn generated_policy_reports_stable_protovalidate_rule_ids() {
        let cases = [
            ("version", "version: 0\n", "uint32.const"),
            (
                "missing ports",
                "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - { host: api.example.com }\n",
                "repeated.min_items",
            ),
            (
                "duplicate ports",
                "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - { host: api.example.com, ports: [443, 443] }\n",
                "repeated.unique",
            ),
            (
                "port range",
                "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - { host: api.example.com, ports: [65536] }\n",
                "uint32.gte_lte",
            ),
            (
                "binary path",
                "version: 1\nnetwork_policies:\n  api:\n    binaries:\n      - { path: \"\" }\n",
                "string.min_len",
            ),
            (
                "matcher choice",
                "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: api.example.com\n        ports: [443]\n        rules:\n          - allow:\n              query:\n                owner: {}\n",
                "required",
            ),
        ];

        for (name, source, rule_id) in cases {
            let value: serde_yml::Value = serde_yml::from_str(source).expect(name);
            let dynamic = DynamicMessage::deserialize(
                policy_descriptor(),
                serde_json::to_value(value).expect(name),
            )
            .expect(name);
            let error = policy_validator().validate(&dynamic).expect_err(name);
            let prost_protovalidate::Error::Validation(error) = error else {
                panic!("{name} returned a validator runtime error: {error}");
            };
            assert!(
                error
                    .violations()
                    .iter()
                    .any(|violation| violation.rule_id() == rule_id),
                "{name} did not report {rule_id}: {error}"
            );
        }
    }

    #[test]
    fn standalone_incremental_fragments_run_the_same_portable_rules() {
        let missing_allow = proto::L7Rule::default();
        let error = validate_authored_l7_rule(&missing_allow).expect_err("allow is required");
        assert!(
            error.to_string().contains("required"),
            "unexpected validation error: {error:?}"
        );

        let missing_matcher = proto::L7DenyRule {
            query: HashMap::from([("owner".to_string(), proto::Matcher::default())]),
            ..Default::default()
        };
        let error = validate_authored_l7_deny_rule(&missing_matcher)
            .expect_err("matcher choice is required");
        assert!(
            error.to_string().contains("required"),
            "unexpected validation error: {error:?}"
        );

        let empty_binary = proto::NetworkBinary::default();
        let error =
            validate_authored_network_binary(&empty_binary).expect_err("binary path is required");
        assert!(
            error.to_string().contains("at least 1 characters"),
            "unexpected validation error: {error:?}"
        );
    }

    #[test]
    fn generated_policy_rejects_typed_nulls_but_preserves_struct_null_data() {
        let typed_null = parse_policy_proto(
            r"
version: 1
filesystem_policy: null
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        mcp:
          versions: null
        rules:
          - allow:
              method: tools/call
              tool: null
",
        )
        .expect_err("typed nulls must not silently become absent fields");
        assert!(typed_null.to_string().contains("null is not allowed"));

        let missing_version =
            parse_policy_proto("version:\n").expect_err("a null scalar field must be rejected");
        assert!(missing_version.to_string().contains("null is not allowed"));

        let deceptive_map_key = parse_policy_proto(
            "version: 1\nnetwork_middlewares:\n  config:\n    endpoints: null\n",
        )
        .expect_err("a map key named config must not turn its typed value into Struct data");
        assert!(
            deceptive_map_key
                .to_string()
                .contains("null is not allowed")
        );

        let struct_null = parse_policy_proto(
            "version: 1\nnetwork_middlewares:\n  audit:\n    config:\n      optional: null\n",
        )
        .expect("null remains valid data inside google.protobuf.Struct");
        assert!(
            struct_null.network_middlewares["audit"]
                .config
                .as_ref()
                .unwrap()
                .fields["optional"]
                .kind
                .is_some()
        );
    }

    #[test]
    fn generated_policy_follows_protobuf_json_scalar_rules() {
        let policy = parse_policy_proto(
            r#"
version: "1"
network_policies:
  api:
    endpoints:
      - host: api.example.com
        ports: ["443"]
"#,
        )
        .expect("protobuf JSON permits quoted integer scalars");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.network_policies["api"].endpoints[0].ports, [443]);
        assert_eq!(
            parse_policy_proto("version: 1.0\n")
                .expect("an exact integral JSON number must parse")
                .version,
            1
        );

        for (name, source) in [
            (
                "number for string",
                "version: 1\nprocess: { run_as_user: 1000 }\n",
            ),
            (
                "string for bool",
                "version: 1\nfilesystem_policy: { include_workdir: \"true\" }\n",
            ),
            ("non-integral number", "version: 1.5\n"),
            ("negative unsigned integer", "version: -1\n"),
            ("out-of-range uint32", "version: 4294967296\n"),
        ] {
            assert!(
                parse_policy_proto(source).is_err(),
                "{name} unexpectedly parsed"
            );
        }
    }

    #[test]
    fn generated_policy_accepts_proto_json_names_but_serializes_proto_names() {
        let policy = parse_policy_proto(
            r"
version: 1
filesystemPolicy:
  includeWorkdir: true
  readOnly: [/usr]
",
        )
        .expect("protobuf JSON lowerCamelCase names must parse");
        assert!(policy.filesystem_policy.as_ref().unwrap().include_workdir);

        let yaml = serialize_policy_proto(&policy).expect("policy must serialize");
        assert!(yaml.contains("filesystem_policy:"));
        assert!(yaml.contains("include_workdir: true"));
        assert!(!yaml.contains("filesystemPolicy"));
    }

    #[test]
    fn generated_policy_rejects_public_attempts_to_set_internal_authority() {
        let error = parse_policy_proto(
            r"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        ports: [443]
        advisor_proposed: true
",
        )
        .expect_err("runtime-only authority must not be accepted from YAML");
        assert!(error.to_string().contains("proto-shaped"));
    }

    #[test]
    fn generated_policy_rejects_yaml_features_outside_the_safe_profile() {
        let cases = [
            ("duplicate key", "version: 1\nversion: 1\n"),
            (
                "merge key",
                "version: 1\nbase: &base { include_workdir: true }\nfilesystem_policy:\n  <<: *base\n",
            ),
            ("multiple documents", "version: 1\n---\nversion: 1\n"),
            ("custom YAML tag", "version: !custom 1\n"),
            (
                "non-finite number",
                "version: 1\nnetwork_middlewares:\n  audit:\n    middleware: example/audit\n    config: { threshold: .nan }\n",
            ),
            (
                "non-string protobuf map key",
                "version: 1\nnetwork_policies:\n  1: {}\n",
            ),
            (
                "non-string protobuf flow-map key",
                "version: 1\nnetwork_policies: {1: {}}\n",
            ),
        ];

        for (name, source) in cases {
            assert!(
                parse_policy_proto(source).is_err(),
                "{name} unexpectedly parsed"
            );
        }
    }

    #[test]
    fn generated_policy_accepts_quoted_and_plain_string_mapping_keys() {
        let policy = parse_policy_proto(
            "version: 1\nnetwork_policies:\n  \"1\":\n    endpoints: []\n  ordinary-name:\n    endpoints: []\n",
        )
        .expect("quoted and ordinary string mapping keys should parse");

        assert!(policy.network_policies.contains_key("1"));
        assert!(policy.network_policies.contains_key("ordinary-name"));
    }

    #[test]
    fn generated_policy_enforces_default_input_and_collection_limits() {
        let limits = ParseLimits::default();
        let prefix = "version: 1\n#";
        let at_limit = format!("{prefix}{}", "x".repeat(limits.max_bytes - prefix.len()));
        assert_eq!(at_limit.len(), limits.max_bytes);
        parse_policy_proto(&at_limit).expect("document at byte limit must parse");
        let over_limit = format!("{at_limit}x");
        assert!(parse_policy_proto(&over_limit).is_err());

        let mut oversized_sequence = String::from("version: 1\nfilesystem_policy:\n  read_only:\n");
        for _ in 0..=limits.max_sequence_elements {
            oversized_sequence.push_str("    - /usr\n");
        }
        assert!(parse_policy_proto(&oversized_sequence).is_err());

        let mut oversized_map = String::from("version: 1\nnetwork_policies:\n");
        for index in 0..=limits.max_mapping_keys {
            use std::fmt::Write as _;
            writeln!(oversized_map, "  rule_{index}: {{}}").unwrap();
        }
        assert!(parse_policy_proto(&oversized_map).is_err());

        let mut deeply_nested = String::from(
            "version: 1\nnetwork_middlewares:\n  audit:\n    middleware: example/audit\n    config: ",
        );
        for _ in 0..limits.max_depth {
            deeply_nested.push_str("{child: ");
        }
        deeply_nested.push_str("null");
        for _ in 0..limits.max_depth {
            deeply_nested.push('}');
        }
        deeply_nested.push('\n');
        assert!(parse_policy_proto(&deeply_nested).is_err());

        let alias_amplification = format!(
            "version: 1\nnetwork_middlewares:\n  audit:\n    middleware: example/audit\n    config:\n      base: &base {{ value: x }}\n      copies: [{}]\n",
            std::iter::repeat_n("*base", 6)
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(parse_policy_proto(&alias_amplification).is_err());
    }
}
