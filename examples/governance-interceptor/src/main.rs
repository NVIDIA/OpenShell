// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
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
use rcgen::{KeyPair, PKCS_ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const POLICY_SIGNATURE_ANNOTATION: &str = "openshell.nvidia.com/policy-signature";
const POLICY_JWT_ISSUER: &str = "openshell-governance-interceptor";
const POLICY_JWT_AUDIENCE: &str = "openshell-governance-policy";
const POLICY_JWT_SUBJECT: &str = "policy.yaml";
const CREATE_SANDBOX_CORRELATION_PREFIX: &str = "governance:create-sandbox";
const SERVICE: &str = "openshell.v1.OpenShell";
const GOVERNED_PROVIDERS: [&str; 2] = ["github", "gitlab"];

#[derive(Clone)]
struct PolicySigner {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    kid: String,
}

impl std::fmt::Debug for PolicySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicySigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicySignatureClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    policy_sha256: String,
}

impl PolicySigner {
    fn generate() -> Result<Self, String> {
        let keypair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|err| format!("failed to generate policy signing key: {err}"))?;
        let signing_key_pem = keypair.serialize_pem();
        let public_key_pem = keypair.public_key_pem();
        let encoding_key = EncodingKey::from_ed_pem(signing_key_pem.as_bytes())
            .map_err(|err| format!("failed to parse policy signing key: {err}"))?;
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem.as_bytes())
            .map_err(|err| format!("failed to parse policy verification key: {err}"))?;
        let kid = kid_from_public_key_der(&keypair.public_key_der());
        Ok(Self {
            encoding_key,
            decoding_key,
            kid,
        })
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign_policy(&self, policy_hash: &str) -> Result<String, String> {
        let claims = PolicySignatureClaims {
            sub: POLICY_JWT_SUBJECT.to_string(),
            iss: POLICY_JWT_ISSUER.to_string(),
            aud: POLICY_JWT_AUDIENCE.to_string(),
            iat: now_secs(),
            exp: 0,
            policy_sha256: policy_hash.to_string(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|err| format!("failed to sign policy JWT: {err}"))
    }

    fn verify_policy_signature(&self, token: &str, policy_hash: &str) -> Result<(), String> {
        let header = decode_header(token)
            .map_err(|err| format!("failed to decode policy JWT header: {err}"))?;
        if header.kid.as_deref() != Some(self.kid.as_str()) {
            return Err("unexpected policy signing key id".to_string());
        }
        if header.alg != Algorithm::EdDSA {
            return Err("unexpected policy signing algorithm".to_string());
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.set_issuer(&[POLICY_JWT_ISSUER]);
        validation.set_audience(&[POLICY_JWT_AUDIENCE]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.validate_exp = false;

        let data = decode::<PolicySignatureClaims>(token, &self.decoding_key, &validation)
            .map_err(|err| format!("failed to verify policy JWT: {err}"))?;
        if data.claims.sub != POLICY_JWT_SUBJECT {
            return Err("unexpected policy JWT subject".to_string());
        }
        if data.claims.policy_sha256 != policy_hash {
            return Err("signed policy hash does not match sandbox policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct GovernanceInterceptorService {
    policy: Value,
    policy_hash: String,
    policy_signature: String,
    policy_signer: PolicySigner,
}

impl GovernanceInterceptorService {
    fn from_yaml(policy_yaml: &str) -> Result<Self, String> {
        let policy = parse_sandbox_policy(policy_yaml)
            .map_err(|err| format!("failed to parse policy YAML: {err}"))?;
        let policy = sandbox_policy_to_proto_json(&policy);
        let policy = normalize_for_struct(policy)?;
        let policy_hash = policy_hash(&policy)?;
        let policy_signer = PolicySigner::generate()?;
        let policy_signature = policy_signer.sign_policy(&policy_hash)?;
        Ok(Self {
            policy,
            policy_hash,
            policy_signature,
            policy_signer,
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

        add_policy_signature_patches(operation, &mut patches, &self.policy_signature)?;

        let mut result = allow();
        result.patches = patches;
        result.log_annotations.insert(
            "correlation_id".to_string(),
            create_sandbox_correlation_id(operation),
        );
        result
            .log_annotations
            .insert("policy_hash".to_string(), self.policy_hash.clone());
        result.log_annotations.insert(
            "policy_signature_kid".to_string(),
            self.policy_signer.kid().to_string(),
        );
        Ok(result)
    }

    fn validate_create_sandbox(&self, operation: &Value) -> InterceptorResult {
        let Some(policy) = operation.pointer("/spec/policy") else {
            return deny("sandbox policy must match the source-control governance baseline");
        };
        let sandbox_policy_hash = match policy_hash(policy) {
            Ok(hash) => hash,
            Err(err) => return deny(&format!("sandbox policy cannot be hashed: {err}")),
        };
        let Some(signature) = operation
            .pointer(&format!(
                "/annotations/{}",
                json_pointer_escape(POLICY_SIGNATURE_ANNOTATION)
            ))
            .and_then(Value::as_str)
        else {
            return deny("sandbox is missing the governance policy signature");
        };
        if let Err(err) = self
            .policy_signer
            .verify_policy_signature(signature, &sandbox_policy_hash)
        {
            return deny(&format!("sandbox policy signature is invalid: {err}"));
        }
        if sandbox_policy_hash != self.policy_hash || policy != &self.policy {
            return deny("sandbox policy must match the source-control governance baseline");
        }
        if !providers_are_governed(operation.pointer("/spec/providers")) {
            return deny("sandbox providers must be exactly github and gitlab");
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

fn create_sandbox_correlation_id(operation: &Value) -> String {
    let sandbox_name = operation
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unnamed");
    format!("{CREATE_SANDBOX_CORRELATION_PREFIX}:{sandbox_name}")
}

fn allow() -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
    }
}

fn deny(reason: &str) -> InterceptorResult {
    InterceptorResult {
        allowed: false,
        reason: reason.to_string(),
        status_code: "PERMISSION_DENIED".to_string(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
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

fn add_policy_signature_patches(
    operation: &Value,
    patches: &mut Vec<JsonPatch>,
    policy_signature: &str,
) -> Result<(), Status> {
    let signature = Value::String(policy_signature.to_string());
    if operation
        .get("annotations")
        .is_none_or(|value| !value.is_object())
    {
        patches.push(json_patch(
            "add",
            "/annotations",
            json!({
                POLICY_SIGNATURE_ANNOTATION: policy_signature,
            }),
        )?);
    } else {
        patches.push(json_patch(
            "add",
            &format!(
                "/annotations/{}",
                json_pointer_escape(POLICY_SIGNATURE_ANNOTATION)
            ),
            signature,
        )?);
    }
    Ok(())
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn normalize_for_struct(value: Value) -> Result<Value, String> {
    json_to_proto_value(&value).map(|value| proto_value_to_json(&value))
}

fn policy_hash(policy: &Value) -> Result<String, String> {
    let policy = normalize_for_struct(policy.clone())?;
    let encoded = serde_json::to_vec(&policy)
        .map_err(|err| format!("failed to encode policy JSON: {err}"))?;
    let digest: [u8; 32] = Sha256::digest(encoded).into();
    Ok(format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest)))
}

fn kid_from_public_key_der(public_key_der: &[u8]) -> String {
    let digest = Sha256::digest(public_key_der);
    hex_encode_prefix(&digest, 16)
}

fn hex_encode_prefix(bytes: &[u8], n: usize) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(n * 2);
    for byte in bytes.iter().take(n) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
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

    fn governed_create_operation(policy: Value, signature: String) -> Value {
        let mut operation = json!({
            "spec": {
                "policy": policy,
                "providers": GOVERNED_PROVIDERS,
            },
            "annotations": {},
        });
        operation
            .pointer_mut("/annotations")
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(
                POLICY_SIGNATURE_ANNOTATION.to_string(),
                Value::String(signature),
            );
        operation
    }

    fn valid_create_operation(service: &GovernanceInterceptorService) -> Value {
        governed_create_operation(service.policy.clone(), service.policy_signature.clone())
    }

    fn signature_patch_token(result: &InterceptorResult) -> String {
        result
            .patches
            .iter()
            .find(|patch| {
                patch.path == "/annotations/openshell.nvidia.com~1policy-signature"
                    || patch.path == "/annotations"
            })
            .and_then(|patch| patch.value.as_ref())
            .map(proto_value_to_json)
            .and_then(|value| {
                value.as_str().map(ToString::to_string).or_else(|| {
                    value
                        .pointer(&format!(
                            "/{}",
                            json_pointer_escape(POLICY_SIGNATURE_ANNOTATION)
                        ))
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                })
            })
            .expect("signature patch value")
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
                json!({"name": "demo", "spec": {}, "labels": {"team": "platform"}}),
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
        assert!(
            paths.contains(&"/annotations")
                || paths.contains(&"/annotations/openshell.nvidia.com~1policy-signature")
        );
        let token = signature_patch_token(&result);
        assert_eq!(token.split('.').count(), 3);
        assert_eq!(
            result
                .log_annotations
                .get("correlation_id")
                .map(String::as_str),
            Some("governance:create-sandbox:demo")
        );
        assert!(result.log_annotations.contains_key("policy_hash"));
        assert!(result.log_annotations.contains_key("policy_signature_kid"));
        assert!(!result.log_annotations.contains_key("policy_signature"));
    }

    #[test]
    fn create_sandbox_validate_accepts_signed_policy() {
        let service = service();
        let result = service
            .evaluate_inner(&evaluation(
                "CreateSandbox",
                GatewayInterceptorPhase::Validate,
                valid_create_operation(&service),
            ))
            .unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn create_sandbox_validate_denies_missing_signature() {
        let service = service();
        let result = service
            .evaluate_inner(&evaluation(
                "CreateSandbox",
                GatewayInterceptorPhase::Validate,
                json!({
                    "spec": {
                        "policy": service.policy,
                        "providers": GOVERNED_PROVIDERS,
                    },
                }),
            ))
            .unwrap();
        assert!(!result.allowed);
        assert!(result.reason.contains("missing"));
    }

    #[test]
    fn create_sandbox_validate_denies_malformed_signature() {
        let service = service();
        let result = service
            .evaluate_inner(&evaluation(
                "CreateSandbox",
                GatewayInterceptorPhase::Validate,
                governed_create_operation(service.policy.clone(), "not-a-jwt".to_string()),
            ))
            .unwrap();
        assert!(!result.allowed);
        assert!(result.reason.contains("signature"));
    }

    #[test]
    fn create_sandbox_validate_denies_signature_from_other_key() {
        let governance = service();
        let other = service();
        let result = governance
            .evaluate_inner(&evaluation(
                "CreateSandbox",
                GatewayInterceptorPhase::Validate,
                governed_create_operation(governance.policy.clone(), other.policy_signature),
            ))
            .unwrap();
        assert!(!result.allowed);
        assert!(result.reason.contains("signature"));
    }

    #[test]
    fn create_sandbox_validate_denies_signed_policy_mismatch() {
        let service = service();
        let mut tampered_policy = service.policy.clone();
        tampered_policy
            .as_object_mut()
            .unwrap()
            .insert("version".to_string(), json!(999));
        let result = service
            .evaluate_inner(&evaluation(
                "CreateSandbox",
                GatewayInterceptorPhase::Validate,
                governed_create_operation(tampered_policy, service.policy_signature.clone()),
            ))
            .unwrap();
        assert!(!result.allowed);
        assert!(result.reason.contains("signature"));
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
