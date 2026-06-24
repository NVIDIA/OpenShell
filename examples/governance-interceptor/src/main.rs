// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, InterceptorSelector, JsonPatch,
    gateway_interceptor_server::{GatewayInterceptor, GatewayInterceptorServer},
};
use openshell_core::proto::{
    GraphqlOperation, L7Allow, L7DenyRule, L7Rule, NetworkEndpoint, NetworkPolicyRule,
    SandboxPolicy,
};
use openshell_policy::parse_sandbox_policy;
use prost_types::{ListValue, Struct, Value as ProtoValue, value::Kind};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const LABEL_KEY: &str = "openshell.nvidia.com/policy-signature";
const SERVICE: &str = "openshell.v1.OpenShell";
const GOVERNED_PROVIDERS: [&str; 2] = ["github", "gitlab"];

#[derive(Clone, Debug)]
struct GovernanceInterceptorService {
    policy: Value,
    policy_signature: String,
}

impl GovernanceInterceptorService {
    fn from_yaml(policy_yaml: &str) -> Result<Self, String> {
        let policy = parse_sandbox_policy(policy_yaml)
            .map_err(|err| format!("failed to parse policy YAML: {err}"))?;
        let policy = sandbox_policy_to_proto_json(&policy);
        let policy = normalize_for_struct(policy)?;
        let policy_digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&policy)
                .map_err(|err| format!("failed to encode policy JSON: {err}"))?,
        )
        .into();
        let policy_signature = format!("sha256-{}", URL_SAFE_NO_PAD.encode(policy_digest));
        Ok(Self {
            policy,
            policy_signature,
        })
    }

    fn manifest() -> InterceptorManifest {
        InterceptorManifest {
            name: "source-control-governance".to_string(),
            failure_policy: "fail_closed".to_string(),
            bindings: vec![
                binding(
                    "govern-create-sandbox",
                    "CreateSandbox",
                    &[
                        GatewayInterceptorPhase::ModifyOperation,
                        GatewayInterceptorPhase::Validate,
                    ],
                ),
                binding(
                    "govern-attach-provider",
                    "AttachSandboxProvider",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-detach-provider",
                    "DetachSandboxProvider",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-update-config",
                    "UpdateConfig",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-create-provider",
                    "CreateProvider",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-update-provider",
                    "UpdateProvider",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-delete-provider",
                    "DeleteProvider",
                    &[GatewayInterceptorPhase::Validate],
                ),
            ],
        }
    }

    fn evaluate_inner(
        &self,
        evaluation: &InterceptorEvaluation,
    ) -> Result<InterceptorResult, Status> {
        let phase = GatewayInterceptorPhase::try_from(evaluation.phase)
            .map_err(|_| Status::invalid_argument("unknown interceptor phase"))?;
        let operation = evaluation
            .operation
            .as_ref()
            .map(struct_to_json)
            .unwrap_or_else(|| Value::Object(Map::new()));

        match (evaluation.method.as_str(), phase) {
            ("CreateSandbox", GatewayInterceptorPhase::ModifyOperation) => {
                self.patch_create_sandbox(&operation)
            }
            ("CreateSandbox", GatewayInterceptorPhase::Validate) => {
                Ok(self.validate_create_sandbox(&operation))
            }
            (
                "AttachSandboxProvider" | "DetachSandboxProvider",
                GatewayInterceptorPhase::Validate,
            ) => Ok(deny(
                "source-control providers are fixed at sandbox creation",
            )),
            ("UpdateConfig", GatewayInterceptorPhase::Validate) => {
                Ok(validate_update_config(&operation))
            }
            ("CreateProvider", GatewayInterceptorPhase::Validate) => {
                Ok(validate_create_provider(&operation))
            }
            ("UpdateProvider", GatewayInterceptorPhase::Validate) => {
                Ok(validate_update_provider(&operation))
            }
            ("DeleteProvider", GatewayInterceptorPhase::Validate) => {
                Ok(validate_delete_provider(&operation))
            }
            _ => Ok(allow()),
        }
    }

    fn patch_create_sandbox(&self, operation: &Value) -> Result<InterceptorResult, Status> {
        let mut patches = Vec::new();
        if operation.get("spec").is_some_and(Value::is_object) {
            patches.push(json_patch("add", "/spec/policy", self.policy.clone())?);
            patches.push(json_patch(
                "add",
                "/spec/providers",
                json!(GOVERNED_PROVIDERS),
            )?);
        } else {
            patches.push(json_patch(
                "add",
                "/spec",
                json!({
                    "policy": self.policy,
                    "providers": GOVERNED_PROVIDERS,
                }),
            )?);
        }

        if operation.get("labels").is_some_and(Value::is_object) {
            patches.push(json_patch(
                "add",
                &format!("/labels/{}", json_pointer_escape(LABEL_KEY)),
                Value::String(self.policy_signature.clone()),
            )?);
        } else {
            patches.push(json_patch(
                "add",
                "/labels",
                json!({ LABEL_KEY: self.policy_signature }),
            )?);
        }

        let mut result = allow();
        result.patches = patches;
        result.audit_annotations.insert(
            "policy_signature".to_string(),
            self.policy_signature.clone(),
        );
        Ok(result)
    }

    fn validate_create_sandbox(&self, operation: &Value) -> InterceptorResult {
        if operation.pointer("/spec/policy") != Some(&self.policy) {
            return deny("sandbox policy must match the source-control governance baseline");
        }
        if !providers_are_governed(operation.pointer("/spec/providers")) {
            return deny("sandbox providers must be exactly github and gitlab");
        }
        if operation
            .pointer(&format!("/labels/{}", json_pointer_escape(LABEL_KEY)))
            .and_then(Value::as_str)
            != Some(self.policy_signature.as_str())
        {
            return deny("sandbox is missing the governance policy signature label");
        }
        allow()
    }
}

#[tonic::async_trait]
impl GatewayInterceptor for GovernanceInterceptorService {
    async fn describe(
        &self,
        _request: Request<DescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        Ok(Response::new(Self::manifest()))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        self.evaluate_inner(request.get_ref()).map(Response::new)
    }
}

fn binding(id: &str, method: &str, phases: &[GatewayInterceptorPhase]) -> InterceptorBinding {
    InterceptorBinding {
        id: id.to_string(),
        selector: Some(InterceptorSelector {
            rpc: format!("{SERVICE}/{method}"),
            service: String::new(),
            method: String::new(),
        }),
        phases: phases.iter().map(|phase| *phase as i32).collect(),
        failure_policy: "fail_closed".to_string(),
    }
}

fn allow() -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        audit_annotations: HashMap::new(),
    }
}

fn deny(reason: &str) -> InterceptorResult {
    InterceptorResult {
        allowed: false,
        reason: reason.to_string(),
        status_code: "PERMISSION_DENIED".to_string(),
        patches: Vec::new(),
        audit_annotations: HashMap::new(),
    }
}

fn validate_update_config(operation: &Value) -> InterceptorResult {
    let has_policy = operation
        .get("policy")
        .is_some_and(|value| !value.is_null());
    let has_merge_operations = operation
        .get("mergeOperations")
        .or_else(|| operation.get("merge_operations"))
        .and_then(Value::as_array)
        .is_some_and(|operations| !operations.is_empty());
    if has_policy || has_merge_operations {
        deny("sandbox policy updates are blocked by the governance baseline")
    } else {
        allow()
    }
}

fn validate_create_provider(operation: &Value) -> InterceptorResult {
    let name = provider_name(operation);
    if is_governed_provider(name) {
        allow()
    } else {
        deny("only github and gitlab provider records may be created")
    }
}

fn validate_update_provider(operation: &Value) -> InterceptorResult {
    let name = provider_name(operation);
    if is_governed_provider(name) {
        deny("governed provider records cannot be updated")
    } else {
        allow()
    }
}

fn validate_delete_provider(operation: &Value) -> InterceptorResult {
    let name = operation
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if is_governed_provider(name) {
        deny("governed provider records cannot be deleted")
    } else {
        allow()
    }
}

fn provider_name(operation: &Value) -> &str {
    operation
        .pointer("/provider/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn is_governed_provider(name: &str) -> bool {
    GOVERNED_PROVIDERS.contains(&name)
}

fn providers_are_governed(value: Option<&Value>) -> bool {
    let Some(Value::Array(providers)) = value else {
        return false;
    };
    if providers.len() != GOVERNED_PROVIDERS.len() {
        return false;
    }
    GOVERNED_PROVIDERS.iter().all(|provider| {
        providers
            .iter()
            .any(|value| value.as_str() == Some(provider))
    })
}

fn json_patch(op: &str, path: &str, value: Value) -> Result<JsonPatch, Status> {
    Ok(JsonPatch {
        op: op.to_string(),
        path: path.to_string(),
        value: Some(json_to_proto_value(&value).map_err(Status::internal)?),
        from: String::new(),
    })
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn normalize_for_struct(value: Value) -> Result<Value, String> {
    json_to_proto_value(&value).map(|value| proto_value_to_json(&value))
}

fn sandbox_policy_to_proto_json(policy: &SandboxPolicy) -> Value {
    let mut out = Map::new();
    out.insert("version".to_string(), json!(policy.version));

    if let Some(filesystem) = &policy.filesystem {
        out.insert(
            "filesystem".to_string(),
            json!({
                "includeWorkdir": filesystem.include_workdir,
                "readOnly": filesystem.read_only,
                "readWrite": filesystem.read_write,
            }),
        );
    }

    if let Some(landlock) = &policy.landlock {
        out.insert(
            "landlock".to_string(),
            json!({ "compatibility": landlock.compatibility }),
        );
    }

    if let Some(process) = &policy.process {
        out.insert(
            "process".to_string(),
            json!({
                "runAsUser": process.run_as_user,
                "runAsGroup": process.run_as_group,
            }),
        );
    }

    out.insert(
        "networkPolicies".to_string(),
        Value::Object(
            policy
                .network_policies
                .iter()
                .map(|(key, rule)| (key.clone(), network_rule_to_proto_json(rule)))
                .collect(),
        ),
    );

    Value::Object(out)
}

fn network_rule_to_proto_json(rule: &NetworkPolicyRule) -> Value {
    json!({
        "name": rule.name,
        "endpoints": rule.endpoints.iter().map(endpoint_to_proto_json).collect::<Vec<_>>(),
        "binaries": rule.binaries.iter().map(|binary| {
            json!({ "path": binary.path })
        }).collect::<Vec<_>>(),
    })
}

fn endpoint_to_proto_json(endpoint: &NetworkEndpoint) -> Value {
    let mut out = Map::new();
    insert_string(&mut out, "host", &endpoint.host);
    insert_u32(&mut out, "port", endpoint.port);
    insert_string(&mut out, "protocol", &endpoint.protocol);
    insert_string(&mut out, "tls", &endpoint.tls);
    insert_string(&mut out, "enforcement", &endpoint.enforcement);
    insert_string(&mut out, "access", &endpoint.access);
    insert_values(
        &mut out,
        "rules",
        endpoint.rules.iter().map(l7_rule_to_proto_json).collect(),
    );
    insert_strings(&mut out, "allowedIps", &endpoint.allowed_ips);
    insert_values(
        &mut out,
        "denyRules",
        endpoint
            .deny_rules
            .iter()
            .map(l7_deny_rule_to_proto_json)
            .collect(),
    );
    insert_u32s(&mut out, "ports", &endpoint.ports);
    insert_bool(&mut out, "allowEncodedSlash", endpoint.allow_encoded_slash);
    insert_string(&mut out, "persistedQueries", &endpoint.persisted_queries);
    if !endpoint.graphql_persisted_queries.is_empty() {
        out.insert(
            "graphqlPersistedQueries".to_string(),
            Value::Object(
                endpoint
                    .graphql_persisted_queries
                    .iter()
                    .map(|(key, operation)| {
                        (key.clone(), graphql_operation_to_proto_json(operation))
                    })
                    .collect(),
            ),
        );
    }
    insert_u32(
        &mut out,
        "graphqlMaxBodyBytes",
        endpoint.graphql_max_body_bytes,
    );
    insert_string(&mut out, "path", &endpoint.path);
    insert_bool(
        &mut out,
        "websocketCredentialRewrite",
        endpoint.websocket_credential_rewrite,
    );
    insert_bool(
        &mut out,
        "requestBodyCredentialRewrite",
        endpoint.request_body_credential_rewrite,
    );
    insert_bool(&mut out, "advisorProposed", endpoint.advisor_proposed);
    Value::Object(out)
}

fn l7_rule_to_proto_json(rule: &L7Rule) -> Value {
    let mut out = Map::new();
    if let Some(allow) = &rule.allow {
        out.insert("allow".to_string(), l7_allow_to_proto_json(allow));
    }
    Value::Object(out)
}

fn l7_allow_to_proto_json(allow: &L7Allow) -> Value {
    let mut out = Map::new();
    insert_string(&mut out, "method", &allow.method);
    insert_string(&mut out, "path", &allow.path);
    insert_string(&mut out, "command", &allow.command);
    insert_query(&mut out, &allow.query);
    insert_string(&mut out, "operationType", &allow.operation_type);
    insert_string(&mut out, "operationName", &allow.operation_name);
    insert_strings(&mut out, "fields", &allow.fields);
    Value::Object(out)
}

fn l7_deny_rule_to_proto_json(rule: &L7DenyRule) -> Value {
    let mut out = Map::new();
    insert_string(&mut out, "method", &rule.method);
    insert_string(&mut out, "path", &rule.path);
    insert_string(&mut out, "command", &rule.command);
    insert_query(&mut out, &rule.query);
    insert_string(&mut out, "operationType", &rule.operation_type);
    insert_string(&mut out, "operationName", &rule.operation_name);
    insert_strings(&mut out, "fields", &rule.fields);
    Value::Object(out)
}

fn graphql_operation_to_proto_json(operation: &GraphqlOperation) -> Value {
    let mut out = Map::new();
    insert_string(&mut out, "operationType", &operation.operation_type);
    insert_string(&mut out, "operationName", &operation.operation_name);
    insert_strings(&mut out, "fields", &operation.fields);
    Value::Object(out)
}

fn insert_query(
    out: &mut Map<String, Value>,
    query: &HashMap<String, openshell_core::proto::L7QueryMatcher>,
) {
    if query.is_empty() {
        return;
    }
    out.insert(
        "query".to_string(),
        Value::Object(
            query
                .iter()
                .map(|(key, matcher)| {
                    let mut value = Map::new();
                    insert_string(&mut value, "glob", &matcher.glob);
                    insert_strings(&mut value, "any", &matcher.any);
                    (key.clone(), Value::Object(value))
                })
                .collect(),
        ),
    );
}

fn insert_string(out: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        out.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn insert_bool(out: &mut Map<String, Value>, key: &str, value: bool) {
    if value {
        out.insert(key.to_string(), Value::Bool(value));
    }
}

fn insert_u32(out: &mut Map<String, Value>, key: &str, value: u32) {
    if value != 0 {
        out.insert(key.to_string(), json!(value));
    }
}

fn insert_strings(out: &mut Map<String, Value>, key: &str, values: &[String]) {
    if !values.is_empty() {
        out.insert(key.to_string(), json!(values));
    }
}

fn insert_u32s(out: &mut Map<String, Value>, key: &str, values: &[u32]) {
    if !values.is_empty() {
        out.insert(key.to_string(), json!(values));
    }
}

fn insert_values(out: &mut Map<String, Value>, key: &str, values: Vec<Value>) {
    if !values.is_empty() {
        out.insert(key.to_string(), Value::Array(values));
    }
}

fn struct_to_json(value: &Struct) -> Value {
    Value::Object(
        value
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
            .collect(),
    )
}

#[cfg(test)]
fn json_to_struct(value: &Value) -> Result<Struct, String> {
    let Value::Object(fields) = value else {
        return Err("JSON value must be an object".to_string());
    };
    Ok(Struct {
        fields: fields
            .iter()
            .map(|(key, value)| json_to_proto_value(value).map(|value| (key.clone(), value)))
            .collect::<Result<_, _>>()?,
    })
}

fn json_to_proto_value(value: &Value) -> Result<ProtoValue, String> {
    let kind = match value {
        Value::Null => Kind::NullValue(0),
        Value::Bool(value) => Kind::BoolValue(*value),
        Value::Number(value) => Kind::NumberValue(
            value
                .as_f64()
                .ok_or_else(|| "invalid JSON number".to_string())?,
        ),
        Value::String(value) => Kind::StringValue(value.clone()),
        Value::Array(values) => Kind::ListValue(ListValue {
            values: values
                .iter()
                .map(json_to_proto_value)
                .collect::<Result<_, _>>()?,
        }),
        Value::Object(fields) => Kind::StructValue(Struct {
            fields: fields
                .iter()
                .map(|(key, value)| json_to_proto_value(value).map(|value| (key.clone(), value)))
                .collect::<Result<_, _>>()?,
        }),
    };
    Ok(ProtoValue { kind: Some(kind) })
}

fn proto_value_to_json(value: &ProtoValue) -> Value {
    match value.kind.as_ref() {
        Some(Kind::NullValue(_)) | None => Value::Null,
        Some(Kind::NumberValue(value)) => {
            Number::from_f64(*value).map_or(Value::Null, Value::Number)
        }
        Some(Kind::StringValue(value)) => Value::String(value.clone()),
        Some(Kind::BoolValue(value)) => Value::Bool(*value),
        Some(Kind::StructValue(value)) => struct_to_json(value),
        Some(Kind::ListValue(value)) => {
            Value::Array(value.values.iter().map(proto_value_to_json).collect())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen: SocketAddr = "127.0.0.1:18081".parse()?;
    let mut policy_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                let value = args.next().ok_or("--listen requires an address")?;
                listen = value.parse()?;
            }
            "--policy" => {
                let value = args.next().ok_or("--policy requires a path")?;
                policy_path = Some(PathBuf::from(value));
            }
            "-h" | "--help" => {
                println!("usage: governance-interceptor [--listen ADDR] [--policy FILE]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    let policy_yaml = if let Some(path) = policy_path {
        tokio::fs::read_to_string(path).await?
    } else {
        include_str!("../policy.yaml").to_string()
    };
    let service = GovernanceInterceptorService::from_yaml(&policy_yaml)?;

    println!("governance interceptor listening on {listen}");
    Server::builder()
        .add_service(GatewayInterceptorServer::new(service))
        .serve(listen)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> GovernanceInterceptorService {
        GovernanceInterceptorService::from_yaml(include_str!("../policy.yaml")).unwrap()
    }

    fn evaluation(
        method: &str,
        phase: GatewayInterceptorPhase,
        operation: Value,
    ) -> InterceptorEvaluation {
        InterceptorEvaluation {
            interceptor_name: "test".to_string(),
            binding_id: "binding".to_string(),
            service: SERVICE.to_string(),
            method: method.to_string(),
            phase: phase as i32,
            operation: Some(json_to_struct(&operation).unwrap()),
            current_state: Some(Struct::default()),
            principal: HashMap::new(),
        }
    }

    #[test]
    fn manifest_declares_governance_bindings() {
        let manifest = GovernanceInterceptorService::manifest();
        let ids: Vec<_> = manifest
            .bindings
            .iter()
            .map(|binding| binding.id.as_str())
            .collect();
        assert!(ids.contains(&"govern-create-sandbox"));
        assert!(ids.contains(&"govern-attach-provider"));
        assert!(ids.contains(&"govern-update-config"));
        assert_eq!(manifest.failure_policy, "fail_closed");
    }

    #[test]
    fn create_sandbox_modify_adds_policy_providers_and_signature() {
        let service = service();
        let result = service
            .evaluate_inner(&evaluation(
                "CreateSandbox",
                GatewayInterceptorPhase::ModifyOperation,
                json!({"spec": {}, "labels": {"team": "platform"}}),
            ))
            .unwrap();
        assert!(result.allowed);
        let paths: Vec<_> = result
            .patches
            .iter()
            .map(|patch| patch.path.as_str())
            .collect();
        assert!(paths.contains(&"/spec/policy"));
        assert!(paths.contains(&"/spec/providers"));
        assert!(paths.contains(&"/labels/openshell.nvidia.com~1policy-signature"));
    }

    #[test]
    fn policy_patch_uses_protobuf_json_names() {
        let service = service();
        assert!(service.policy.get("filesystem").is_some());
        assert!(service.policy.get("networkPolicies").is_some());
        assert!(service.policy.get("filesystem_policy").is_none());
        assert!(service.policy.get("network_policies").is_none());
    }

    #[test]
    fn provider_creation_is_limited_to_governed_names() {
        let service = service();
        let github = service
            .evaluate_inner(&evaluation(
                "CreateProvider",
                GatewayInterceptorPhase::Validate,
                json!({"provider": {"metadata": {"name": "github"}}}),
            ))
            .unwrap();
        assert!(github.allowed);

        let slack = service
            .evaluate_inner(&evaluation(
                "CreateProvider",
                GatewayInterceptorPhase::Validate,
                json!({"provider": {"metadata": {"name": "slack"}}}),
            ))
            .unwrap();
        assert!(!slack.allowed);
    }

    #[test]
    fn provider_attach_and_detach_are_denied() {
        let service = service();
        for method in ["AttachSandboxProvider", "DetachSandboxProvider"] {
            let result = service
                .evaluate_inner(&evaluation(
                    method,
                    GatewayInterceptorPhase::Validate,
                    json!({"sandboxName": "demo", "providerName": "github"}),
                ))
                .unwrap();
            assert!(!result.allowed);
        }
    }

    #[test]
    fn policy_update_and_merge_are_denied() {
        let service = service();
        for operation in [
            json!({"name": "demo", "policy": {"version": 1}}),
            json!({"name": "demo", "mergeOperations": [{"op": "add"}]}),
        ] {
            let result = service
                .evaluate_inner(&evaluation(
                    "UpdateConfig",
                    GatewayInterceptorPhase::Validate,
                    operation,
                ))
                .unwrap();
            assert!(!result.allowed);
        }
    }

    #[test]
    fn governed_provider_update_and_delete_are_denied() {
        let service = service();
        let update = service
            .evaluate_inner(&evaluation(
                "UpdateProvider",
                GatewayInterceptorPhase::Validate,
                json!({"provider": {"metadata": {"name": "gitlab"}}}),
            ))
            .unwrap();
        assert!(!update.allowed);

        let delete = service
            .evaluate_inner(&evaluation(
                "DeleteProvider",
                GatewayInterceptorPhase::Validate,
                json!({"name": "github"}),
            ))
            .unwrap();
        assert!(!delete.allowed);
    }
}
