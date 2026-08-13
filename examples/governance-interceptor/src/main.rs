// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod policy_hash;
mod proto_json;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, InterceptorSelector, JsonPatch,
    ProviderProfileSnapshot, ProviderProfileSnapshotRequest,
    gateway_interceptor_server::{GatewayInterceptor, GatewayInterceptorServer},
    interceptor_evaluation,
};
use openshell_core::proto::{
    ListSandboxesRequest, ProviderProfile, Sandbox, SandboxPhase, SandboxPolicy,
    UpdateConfigRequest, open_shell_client::OpenShellClient,
};
use openshell_policy::parse_sandbox_policy;
use openshell_providers::{ProviderTypeProfile, normalize_profile_id};
use policy_hash::{
    HASH_ALGORITHM, canonical_policy_hash, canonical_profile_hash,
    canonical_profile_snapshot_revision, is_v2_digest,
};
use prost::Message as _;
use prost_types::ListValue;
use prost_types::{Struct, Value as ProtoValue, value::Kind};
use proto_json::{decode_message_to_json, encode_json_to_message};
use rcgen::{KeyPair, PKCS_ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value, json};
use sha2::{Digest, Sha256};
use tonic::Code;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

const POLICY_SIGNATURE_ANNOTATION: &str = "openshell.nvidia.com/policy-signature";
const POLICY_HASH_ANNOTATION: &str = "openshell.nvidia.com/policy-hash";
const POLICY_SIGNATURE_KID_ANNOTATION: &str = "openshell.nvidia.com/policy-signature-kid";
const POLICY_RELOAD_CORRELATION_ANNOTATION: &str =
    "openshell.nvidia.com/policy-reload-correlation-id";
const PROFILE_SIGNATURE_ANNOTATION: &str = "openshell.nvidia.com/profile-signature";
const PROFILE_HASH_ANNOTATION: &str = "openshell.nvidia.com/profile-hash";
const PROFILE_SIGNATURE_KID_ANNOTATION: &str = "openshell.nvidia.com/profile-signature-kid";
const POLICY_JWT_ISSUER: &str = "openshell-governance-interceptor";
const POLICY_JWT_AUDIENCE: &str = "openshell-governance-policy";
const POLICY_JWT_SUBJECT: &str = "policy.yaml";
const PROFILE_JWT_AUDIENCE: &str = "openshell-governance-profile";
const PROFILE_JWT_SUBJECT_PREFIX: &str = "provider-profile:";
const CREATE_SANDBOX_CORRELATION_PREFIX: &str = "governance:create-sandbox";
const RELOAD_CORRELATION_PREFIX: &str = "governance:reload-policy";
const SERVICE: &str = "openshell.v1.OpenShell";
const SANDBOX_POLICY_TYPE: &str = "openshell.sandbox.v1.SandboxPolicy";
const DEFAULT_POLICY_WATCH_INTERVAL_MS: u64 = 1_000;

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
    hash_algorithm: String,
    policy_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProfileSignatureClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    hash_algorithm: String,
    profile_id: String,
    profile_sha256: String,
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
            hash_algorithm: HASH_ALGORITHM.to_string(),
            policy_sha256: policy_hash.to_string(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|err| format!("failed to sign policy JWT: {err}"))
    }

    fn sign_profile(&self, profile_id: &str, profile_hash: &str) -> Result<String, String> {
        let claims = ProfileSignatureClaims {
            sub: format!("{PROFILE_JWT_SUBJECT_PREFIX}{profile_id}"),
            iss: POLICY_JWT_ISSUER.to_string(),
            aud: PROFILE_JWT_AUDIENCE.to_string(),
            iat: 0,
            exp: 0,
            hash_algorithm: HASH_ALGORITHM.to_string(),
            profile_id: profile_id.to_string(),
            profile_sha256: profile_hash.to_string(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|err| format!("failed to sign provider profile JWT: {err}"))
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
        if data.claims.hash_algorithm != HASH_ALGORITHM {
            return Err("unexpected policy hash algorithm".to_string());
        }
        if !is_v2_digest(&data.claims.policy_sha256) {
            return Err("unexpected policy hash format".to_string());
        }
        if data.claims.policy_sha256 != policy_hash {
            return Err("signed policy hash does not match sandbox policy".to_string());
        }
        Ok(())
    }

    #[cfg(test)]
    fn verify_profile_signature(
        &self,
        token: &str,
        profile_id: &str,
        profile_hash: &str,
    ) -> Result<(), String> {
        let header = decode_header(token)
            .map_err(|err| format!("failed to decode provider profile JWT header: {err}"))?;
        if header.kid.as_deref() != Some(self.kid.as_str()) {
            return Err("unexpected provider profile signing key id".to_string());
        }
        if header.alg != Algorithm::EdDSA {
            return Err("unexpected provider profile signing algorithm".to_string());
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.set_issuer(&[POLICY_JWT_ISSUER]);
        validation.set_audience(&[PROFILE_JWT_AUDIENCE]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.validate_exp = false;

        let data = decode::<ProfileSignatureClaims>(token, &self.decoding_key, &validation)
            .map_err(|err| format!("failed to verify provider profile JWT: {err}"))?;
        if data.claims.sub != format!("{PROFILE_JWT_SUBJECT_PREFIX}{profile_id}") {
            return Err("unexpected provider profile JWT subject".to_string());
        }
        if data.claims.profile_id != profile_id {
            return Err("unexpected provider profile id".to_string());
        }
        if data.claims.hash_algorithm != HASH_ALGORITHM {
            return Err("unexpected provider profile hash algorithm".to_string());
        }
        if !is_v2_digest(&data.claims.profile_sha256) {
            return Err("unexpected provider profile hash format".to_string());
        }
        if data.claims.profile_sha256 != profile_hash {
            return Err("signed provider profile hash does not match profile".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct GovernanceInterceptorService {
    policy_signer: PolicySigner,
    policy_state: Arc<RwLock<PolicyState>>,
    profiles_path: Option<PathBuf>,
    profile_state: Arc<RwLock<ProviderProfileState>>,
}

#[derive(Clone, Debug)]
struct PolicyState {
    policy: Value,
    policy_proto: SandboxPolicy,
    policy_hash: String,
    policy_signature: String,
    policy_signature_kid: String,
}

#[derive(Clone, Debug)]
struct ProviderProfileState {
    ids: Vec<String>,
    profiles: Vec<ProviderProfile>,
    revision: String,
}

#[derive(Clone, Debug)]
struct LoadedProviderProfile {
    profile: ProviderProfile,
}

impl GovernanceInterceptorService {
    #[cfg(test)]
    fn from_profiles(profiles: Vec<LoadedProviderProfile>) -> Result<Self, String> {
        Self::from_yaml(include_str!("../policy.yaml"), profiles, None)
    }

    fn from_policy_and_profiles_path(policy_yaml: &str, path: PathBuf) -> Result<Self, String> {
        let profiles = load_provider_profiles(&path)?;
        Self::from_yaml(policy_yaml, profiles, Some(path))
    }

    fn from_yaml(
        policy_yaml: &str,
        profiles: Vec<LoadedProviderProfile>,
        profiles_path: Option<PathBuf>,
    ) -> Result<Self, String> {
        if profiles.is_empty() {
            return Err("at least one provider profile must be loaded".to_string());
        }
        let policy_signer = PolicySigner::generate()?;
        let profile_state = profile_state_from_loaded(profiles, &policy_signer)?;
        let policy_state = load_policy_state(policy_yaml, &policy_signer)?;
        Ok(Self {
            policy_signer,
            policy_state: Arc::new(RwLock::new(policy_state)),
            profiles_path,
            profile_state: Arc::new(RwLock::new(profile_state)),
        })
    }

    fn manifest(&self) -> InterceptorManifest {
        InterceptorManifest {
            name: "provider-governance".to_string(),
            failure_policy: "fail_closed".to_string(),
            provider_profiles: true,
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
                    "govern-create-provider",
                    "CreateProvider",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-update-config",
                    "UpdateConfig",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-submit-policy-analysis",
                    "SubmitPolicyAnalysis",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-import-provider-profiles",
                    "ImportProviderProfiles",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-update-provider-profiles",
                    "UpdateProviderProfiles",
                    &[GatewayInterceptorPhase::Validate],
                ),
                binding(
                    "govern-delete-provider-profile",
                    "DeleteProviderProfile",
                    &[GatewayInterceptorPhase::Validate],
                ),
            ],
        }
    }

    fn evaluate_inner(
        &self,
        evaluation: &InterceptorEvaluation,
    ) -> Result<InterceptorResult, Status> {
        let profile_state = self.current_profile_state();
        let policy_state = self.current_policy_state();
        let phase = evaluation
            .phase
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("interceptor phase is required"))?;
        let proposed_operation = match phase {
            interceptor_evaluation::Phase::ModifyOperation(payload) => {
                payload.proposed_operation.as_ref()
            }
            interceptor_evaluation::Phase::Validate(payload) => payload.proposed_operation.as_ref(),
            interceptor_evaluation::Phase::PostCommit(payload) => {
                payload.committed_response.as_ref()
            }
        }
        .ok_or_else(|| Status::invalid_argument("phase payload is required"))?;
        let operation = struct_to_json(proposed_operation);

        match (evaluation.method.as_str(), phase) {
            ("CreateSandbox", interceptor_evaluation::Phase::ModifyOperation(_)) => {
                Self::patch_create_sandbox(&operation, &policy_state)
            }
            ("CreateSandbox", interceptor_evaluation::Phase::Validate(_)) => {
                Ok(validate_create_sandbox(
                    &operation,
                    &profile_state.ids,
                    &policy_state,
                    &self.policy_signer,
                ))
            }
            ("CreateProvider", interceptor_evaluation::Phase::Validate(_)) => {
                Ok(self.validate_create_provider(&operation, &profile_state.ids))
            }
            ("UpdateConfig", interceptor_evaluation::Phase::Validate(_)) => Ok(
                validate_update_config(&operation, &policy_state, &self.policy_signer),
            ),
            ("SubmitPolicyAnalysis", interceptor_evaluation::Phase::Validate(_)) => Ok(
                validate_submit_policy_analysis(&operation, &evaluation.principal),
            ),
            ("ImportProviderProfiles", interceptor_evaluation::Phase::Validate(_)) => {
                Ok(self.validate_import_provider_profiles(&operation, &profile_state.ids))
            }
            ("UpdateProviderProfiles", interceptor_evaluation::Phase::Validate(_)) => {
                Ok(self.validate_update_provider_profiles(&operation, &profile_state.ids))
            }
            ("DeleteProviderProfile", interceptor_evaluation::Phase::Validate(_)) => {
                Ok(validate_delete_provider_profile())
            }
            _ => Ok(allow()),
        }
    }

    fn patch_create_sandbox(
        operation: &Value,
        policy_state: &PolicyState,
    ) -> Result<InterceptorResult, Status> {
        let mut patches = Vec::new();
        if operation.get("spec").is_some_and(Value::is_object) {
            patches.push(json_patch(
                "add",
                "/spec/policy",
                policy_state.policy.clone(),
            )?);
        } else {
            patches.push(json_patch(
                "add",
                "/spec",
                json!({
                    "policy": policy_state.policy.clone(),
                }),
            )?);
        }

        add_policy_signature_patches(operation, &mut patches, &policy_state.policy_signature)?;

        let mut result = allow();
        result.patches = patches;
        result.log_annotations.insert(
            "correlation_id".to_string(),
            create_sandbox_correlation_id(operation),
        );
        result
            .log_annotations
            .insert("policy_hash".to_string(), policy_state.policy_hash.clone());
        result.log_annotations.insert(
            "policy_signature_kid".to_string(),
            policy_state.policy_signature_kid.clone(),
        );
        Ok(result)
    }

    fn current_profile_state(&self) -> ProviderProfileState {
        if let Some(path) = &self.profiles_path {
            match load_provider_profiles(path)
                .and_then(|profiles| profile_state_from_loaded(profiles, &self.policy_signer))
            {
                Ok(state) => {
                    if let Ok(mut guard) = self.profile_state.write() {
                        *guard = state.clone();
                    }
                    return state;
                }
                Err(err) => {
                    eprintln!(
                        "failed to reload provider profiles; keeping last valid snapshot: {err}"
                    );
                }
            }
        }
        self.profile_state
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    fn current_policy_state(&self) -> PolicyState {
        self.policy_state
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    fn reload_policy_from_yaml(&self, policy_yaml: &str) -> Result<Option<PolicyState>, String> {
        let next = load_policy_state(policy_yaml, &self.policy_signer)?;
        let mut guard = self
            .policy_state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.policy_hash == next.policy_hash {
            return Ok(None);
        }
        *guard = next.clone();
        Ok(Some(next))
    }

    fn validate_create_provider(
        &self,
        operation: &Value,
        managed_profile_ids: &[String],
    ) -> InterceptorResult {
        let provider_type = provider_type(operation);
        if !is_managed_profile_id(managed_profile_ids, provider_type) {
            return deny(&format!(
                "providers may only use vended provider profiles: {}",
                format_id_list(managed_profile_ids)
            ));
        }
        allow()
    }

    fn validate_import_provider_profiles(
        &self,
        operation: &Value,
        managed_profile_ids: &[String],
    ) -> InterceptorResult {
        let Some(profiles) = operation.get("profiles").and_then(Value::as_array) else {
            return deny("provider profile imports must include governed profile payloads");
        };
        if profiles.is_empty() {
            return deny("provider profile imports must include governed profile payloads");
        }
        for item in profiles {
            let id = profile_id_from_import_item(item);
            if !is_managed_profile_id(managed_profile_ids, id) {
                return deny(&format!(
                    "only managed provider profiles may be imported: {}",
                    format_id_list(managed_profile_ids)
                ));
            }
        }
        allow()
    }

    fn validate_update_provider_profiles(
        &self,
        operation: &Value,
        managed_profile_ids: &[String],
    ) -> InterceptorResult {
        let target_id = operation
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_managed_profile_id(managed_profile_ids, target_id) {
            return deny(&format!(
                "only managed provider profiles may be updated: {}",
                format_id_list(managed_profile_ids)
            ));
        }
        let payload_id = operation
            .get("profile")
            .map(profile_id_from_import_item)
            .unwrap_or_default();
        if payload_id != target_id {
            return deny(
                "provider profile update target must match the governed profile payload id",
            );
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
        Ok(Response::new(self.manifest()))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        self.evaluate_inner(request.get_ref()).map(Response::new)
    }

    async fn snapshot_provider_profiles(
        &self,
        _request: Request<ProviderProfileSnapshotRequest>,
    ) -> Result<Response<ProviderProfileSnapshot>, Status> {
        let state = self.current_profile_state();
        Ok(Response::new(ProviderProfileSnapshot {
            revision: state.revision,
            profiles: state.profiles,
        }))
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

fn validate_create_sandbox(
    operation: &Value,
    managed_profile_ids: &[String],
    policy_state: &PolicyState,
    policy_signer: &PolicySigner,
) -> InterceptorResult {
    let Some(policy) = operation.pointer("/spec/policy") else {
        return deny("sandbox policy must match the provider governance baseline");
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
    let signature_validation =
        validate_signed_policy_payload(policy, signature, policy_state, policy_signer);
    if let Err(reason) = signature_validation {
        return deny(&reason);
    }
    if !providers_are_managed(operation.pointer("/spec/providers"), managed_profile_ids) {
        return deny(&format!(
            "sandbox providers may only use vended provider profiles: {}",
            format_id_list(managed_profile_ids)
        ));
    }
    allow()
}

fn validate_signed_policy_payload(
    policy: &Value,
    signature: &str,
    policy_state: &PolicyState,
    policy_signer: &PolicySigner,
) -> Result<(), String> {
    let sandbox_policy = sandbox_policy_from_interceptor_json(policy)?;
    let sandbox_policy_hash = canonical_policy_hash(&sandbox_policy)?;
    policy_signer
        .verify_policy_signature(signature, &sandbox_policy_hash)
        .map_err(|err| format!("sandbox policy signature is invalid: {err}"))?;
    if sandbox_policy_hash != policy_state.policy_hash
        || sandbox_policy != policy_state.policy_proto
    {
        return Err("sandbox policy must match the provider governance baseline".to_string());
    }
    Ok(())
}

fn validate_update_config(
    operation: &Value,
    policy_state: &PolicyState,
    policy_signer: &PolicySigner,
) -> InterceptorResult {
    if requests_auto_proposal_approval(operation) {
        return deny(
            "automatic policy proposal approval is blocked by provider profile governance",
        );
    }
    let is_global = operation
        .get("global")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_policy = operation
        .get("policy")
        .is_some_and(|value| !value.is_null());
    let has_merge_operations = operation
        .get("mergeOperations")
        .or_else(|| operation.get("merge_operations"))
        .and_then(Value::as_array)
        .is_some_and(|operations| !operations.is_empty());
    if !is_global && has_policy {
        return validate_update_config_policy(operation, policy_state, policy_signer);
    }
    if !is_global && has_merge_operations {
        deny("sandbox policy updates are blocked by provider profile governance")
    } else {
        allow()
    }
}

fn requests_auto_proposal_approval(operation: &Value) -> bool {
    let setting_key = operation
        .get("settingKey")
        .or_else(|| operation.get("setting_key"))
        .and_then(Value::as_str);
    if setting_key != Some("proposal_approval_mode") {
        return false;
    }

    operation
        .get("settingValue")
        .or_else(|| operation.get("setting_value"))
        .and_then(|value| {
            value
                .get("stringValue")
                .or_else(|| value.get("string_value"))
        })
        .and_then(Value::as_str)
        == Some("auto")
}

fn validate_submit_policy_analysis(
    operation: &Value,
    principal: &HashMap<String, String>,
) -> InterceptorResult {
    if principal.get("kind").map(String::as_str) != Some("sandbox") {
        return deny("policy analysis requires an authenticated sandbox principal");
    }

    match operation
        .get("proposedChunks")
        .or_else(|| operation.get("proposed_chunks"))
    {
        Some(Value::Array(chunks)) if !chunks.is_empty() => {
            deny("sandbox-authored policy proposals are blocked by provider profile governance")
        }
        Some(Value::Array(_)) | None => allow(),
        Some(_) => deny("policy analysis proposed chunks must be an array"),
    }
}

fn validate_update_config_policy(
    operation: &Value,
    policy_state: &PolicyState,
    policy_signer: &PolicySigner,
) -> InterceptorResult {
    let Some(policy) = operation.get("policy") else {
        return deny("sandbox policy updates must include a policy payload");
    };
    let Some(annotations) = operation.get("annotations").and_then(Value::as_object) else {
        return deny("sandbox policy updates must include governance annotations");
    };
    let Some(signature) = annotations
        .get(POLICY_SIGNATURE_ANNOTATION)
        .and_then(Value::as_str)
    else {
        return deny("sandbox policy update is missing the governance policy signature");
    };
    let Some(policy_hash) = annotations
        .get(POLICY_HASH_ANNOTATION)
        .and_then(Value::as_str)
    else {
        return deny("sandbox policy update is missing the governance policy hash");
    };
    let Some(policy_signature_kid) = annotations
        .get(POLICY_SIGNATURE_KID_ANNOTATION)
        .and_then(Value::as_str)
    else {
        return deny("sandbox policy update is missing the governance policy signing key id");
    };
    if policy_hash != policy_state.policy_hash
        || policy_signature_kid != policy_state.policy_signature_kid
    {
        return deny("sandbox policy update governance annotations are stale");
    }
    match validate_signed_policy_payload(policy, signature, policy_state, policy_signer) {
        Ok(()) => allow(),
        Err(reason) => deny(&reason),
    }
}

fn validate_delete_provider_profile() -> InterceptorResult {
    deny("provider profile deletes are blocked by provider governance")
}

fn load_policy_state(
    policy_yaml: &str,
    policy_signer: &PolicySigner,
) -> Result<PolicyState, String> {
    let policy_proto = parse_sandbox_policy(policy_yaml)
        .map_err(|err| format!("failed to parse policy YAML: {err}"))?;
    let policy = sandbox_policy_to_proto_json(&policy_proto)?;
    let policy = normalize_for_struct(policy)?;
    let policy_hash = canonical_policy_hash(&policy_proto)?;
    let policy_signature = policy_signer.sign_policy(&policy_hash)?;
    Ok(PolicyState {
        policy,
        policy_proto,
        policy_hash,
        policy_signature,
        policy_signature_kid: policy_signer.kid().to_string(),
    })
}

fn provider_type(operation: &Value) -> &str {
    operation
        .pointer("/provider/type")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn profile_id_from_import_item(item: &Value) -> &str {
    item.pointer("/profile/id")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn load_provider_profiles(path: &Path) -> Result<Vec<LoadedProviderProfile>, String> {
    if path.is_dir() {
        let mut entries = std::fs::read_dir(path)
            .map_err(|err| format!("failed to read provider profiles dir: {err}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to read provider profiles dir entry: {err}"))?;
        entries.sort_by_key(|entry| entry.path());
        let mut profiles = Vec::new();
        for entry in entries {
            let path = entry.path();
            if !profile_path_supported(&path) {
                continue;
            }
            profiles.push(load_provider_profile_file(&path)?);
        }
        validate_loaded_profiles(&profiles)?;
        return Ok(profiles);
    }
    if path.is_file() {
        let profiles = vec![load_provider_profile_file(path)?];
        validate_loaded_profiles(&profiles)?;
        return Ok(profiles);
    }
    Err(format!(
        "provider profiles path not found: {}",
        path.display()
    ))
}

fn load_provider_profile_file(path: &Path) -> Result<LoadedProviderProfile, String> {
    let profile_id = profile_id_from_file_name(path)?;
    let input = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read provider profile {}: {err}", path.display()))?;
    let source = path.display().to_string();
    load_provider_profile_source(&source, &input, &profile_id)
}

fn load_provider_profile_source(
    source: &str,
    input: &str,
    profile_id: &str,
) -> Result<LoadedProviderProfile, String> {
    let mut value = serde_yml::from_str::<serde_yml::Value>(input)
        .map_err(|err| format!("failed to parse provider profile {source}: {err}"))?;
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| format!("provider profile {source} must be a YAML mapping"))?;
    mapping.insert(
        serde_yml::Value::String("id".to_string()),
        serde_yml::Value::String(profile_id.to_string()),
    );
    let profile = serde_yml::from_value::<ProviderTypeProfile>(value)
        .map_err(|err| format!("failed to decode provider profile {source}: {err}"))?
        .to_proto();
    Ok(LoadedProviderProfile { profile })
}

fn profile_id_from_file_name(path: &Path) -> Result<String, String> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            format!(
                "provider profile path has no UTF-8 file stem: {}",
                path.display()
            )
        })?;
    let Some(normalized) = normalize_profile_id(stem) else {
        return Err(format!(
            "provider profile filename stem must be lowercase kebab-case: {}",
            path.display()
        ));
    };
    if normalized != stem {
        return Err(format!(
            "provider profile filename stem must already be normalized: {}",
            path.display()
        ));
    }
    Ok(normalized)
}

fn profile_path_supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yaml" | "yml")
    )
}

fn validate_loaded_profiles(profiles: &[LoadedProviderProfile]) -> Result<(), String> {
    if profiles.is_empty() {
        return Err("provider profiles path did not contain any YAML files".to_string());
    }
    let mut ids = profiles
        .iter()
        .map(|profile| profile.profile.id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    for pair in ids.windows(2) {
        if pair[0] == pair[1] {
            return Err(format!(
                "duplicate provider profile filename stem: {}",
                pair[0]
            ));
        }
    }
    Ok(())
}

fn loaded_profile_ids(profiles: &[LoadedProviderProfile]) -> Vec<String> {
    profiles
        .iter()
        .map(|profile| profile.profile.id.clone())
        .collect()
}

fn profile_state_from_loaded(
    profiles: Vec<LoadedProviderProfile>,
    policy_signer: &PolicySigner,
) -> Result<ProviderProfileState, String> {
    let ids = loaded_profile_ids(&profiles);
    let profiles = profiles
        .into_iter()
        .map(|loaded| sign_provider_profile(loaded.profile, policy_signer))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProviderProfileState {
        revision: canonical_profile_snapshot_revision(&profiles)?,
        ids,
        profiles,
    })
}

fn sign_provider_profile(
    mut profile: ProviderProfile,
    policy_signer: &PolicySigner,
) -> Result<ProviderProfile, String> {
    profile.annotations.remove(PROFILE_SIGNATURE_ANNOTATION);
    profile.annotations.remove(PROFILE_HASH_ANNOTATION);
    profile.annotations.remove(PROFILE_SIGNATURE_KID_ANNOTATION);

    let profile_hash = deterministic_profile_hash(&profile)?;
    let profile_signature = policy_signer.sign_profile(&profile.id, &profile_hash)?;
    profile
        .annotations
        .insert(PROFILE_HASH_ANNOTATION.to_string(), profile_hash);
    profile.annotations.insert(
        PROFILE_SIGNATURE_KID_ANNOTATION.to_string(),
        policy_signer.kid().to_string(),
    );
    profile
        .annotations
        .insert(PROFILE_SIGNATURE_ANNOTATION.to_string(), profile_signature);
    Ok(profile)
}

fn deterministic_profile_hash(profile: &ProviderProfile) -> Result<String, String> {
    let mut profile = profile.clone();
    profile.annotations.remove(PROFILE_SIGNATURE_ANNOTATION);
    profile.annotations.remove(PROFILE_HASH_ANNOTATION);
    profile.annotations.remove(PROFILE_SIGNATURE_KID_ANNOTATION);
    canonical_profile_hash(&profile)
}

fn is_managed_profile_id(managed_profile_ids: &[String], id: &str) -> bool {
    managed_profile_ids.iter().any(|managed| managed == id)
}

fn format_id_list(ids: &[String]) -> String {
    ids.join(", ")
}

fn providers_are_managed(value: Option<&Value>, managed_profile_ids: &[String]) -> bool {
    let Some(value) = value else {
        return true;
    };
    let Value::Array(providers) = value else {
        return false;
    };
    providers.iter().all(|provider| {
        provider
            .as_str()
            .is_some_and(|provider| is_managed_profile_id(managed_profile_ids, provider))
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

fn sandbox_policy_to_proto_json(policy: &SandboxPolicy) -> Result<Value, String> {
    decode_message_to_json(SANDBOX_POLICY_TYPE, policy)
        .map_err(|err| format!("failed to render policy protobuf JSON: {err}"))
}

fn sandbox_policy_from_interceptor_json(policy: &Value) -> Result<SandboxPolicy, String> {
    let bytes = encode_json_to_message(SANDBOX_POLICY_TYPE, policy)
        .map_err(|err| format!("sandbox policy cannot be decoded as protobuf JSON: {err}"))?;
    SandboxPolicy::decode(bytes.as_slice())
        .map_err(|err| format!("sandbox policy protobuf payload is invalid: {err}"))
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

fn spawn_policy_watch_worker(
    service: GovernanceInterceptorService,
    policy_path: PathBuf,
    gateway_endpoint: Option<String>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut last_seen = policy_file_fingerprint(&policy_path).await.ok();
        loop {
            tokio::time::sleep(interval).await;
            let fingerprint = match policy_file_fingerprint(&policy_path).await {
                Ok(fingerprint) => fingerprint,
                Err(err) => {
                    eprintln!("failed to stat governance policy file: {err}");
                    continue;
                }
            };
            if last_seen.as_ref() == Some(&fingerprint) {
                continue;
            }
            last_seen = Some(fingerprint);

            let policy_yaml = match tokio::fs::read_to_string(&policy_path).await {
                Ok(policy_yaml) => policy_yaml,
                Err(err) => {
                    eprintln!(
                        "failed to read governance policy file {}: {err}",
                        policy_path.display()
                    );
                    continue;
                }
            };

            let policy_state = match service.reload_policy_from_yaml(&policy_yaml) {
                Ok(Some(policy_state)) => policy_state,
                Ok(None) => continue,
                Err(err) => {
                    eprintln!(
                        "failed to reload governance policy file {}; keeping previous policy: {err}",
                        policy_path.display()
                    );
                    continue;
                }
            };

            println!("reloaded governance policy {}", policy_state.policy_hash);
            if let Some(endpoint) = gateway_endpoint.as_deref() {
                if let Err(err) =
                    propagate_policy_to_running_sandboxes(endpoint, &policy_state).await
                {
                    eprintln!("failed to propagate governance policy reload: {err}");
                }
            } else {
                println!(
                    "gateway endpoint not configured; policy reload applies to future sandbox creation only"
                );
            }
        }
    });
}

async fn policy_file_fingerprint(path: &Path) -> Result<(SystemTime, u64), String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    Ok((modified, metadata.len()))
}

async fn propagate_policy_to_running_sandboxes(
    gateway_endpoint: &str,
    policy_state: &PolicyState,
) -> Result<(), String> {
    let channel = Channel::from_shared(gateway_endpoint.to_string())
        .map_err(|err| format!("invalid gateway endpoint {gateway_endpoint}: {err}"))?
        .connect()
        .await
        .map_err(|err| format!("connect to gateway {gateway_endpoint} failed: {err}"))?;
    let mut client = OpenShellClient::new(channel);
    let mut offset = 0_u32;
    let limit = 100_u32;
    let correlation_id = format!("{}:{}", RELOAD_CORRELATION_PREFIX, now_secs());
    loop {
        let response = client
            .list_sandboxes(ListSandboxesRequest {
                limit,
                offset,
                label_selector: String::new(),
                workspace: String::new(),
                all_workspaces: true,
            })
            .await
            .map_err(|status| format!("list sandboxes failed: {status}"))?
            .into_inner();
        let count = response.sandboxes.len();
        for sandbox in response.sandboxes {
            if !sandbox_accepts_policy_reload(&sandbox) {
                continue;
            }
            let Some(name) = sandbox_name(&sandbox).filter(|name| !name.is_empty()) else {
                continue;
            };
            let resource_version = sandbox
                .metadata
                .as_ref()
                .map_or(0, |metadata| metadata.resource_version);
            let result = client
                .update_config(UpdateConfigRequest {
                    name: name.clone(),
                    policy: Some(policy_state.policy_proto.clone()),
                    annotations: policy_update_annotations(policy_state, &correlation_id),
                    expected_resource_version: resource_version,
                    ..Default::default()
                })
                .await;
            match result {
                Ok(response) => {
                    println!(
                        "propagated governance policy reload to sandbox {} version {}",
                        name,
                        response.into_inner().version
                    );
                }
                Err(status) if status.code() == Code::InvalidArgument => {
                    eprintln!(
                        "governance policy reload rejected for sandbox {name}: {}",
                        status.message()
                    );
                }
                Err(status) => {
                    eprintln!("failed to update sandbox {name}: {status}");
                }
            }
        }
        if count < usize::try_from(limit).unwrap_or(usize::MAX) {
            break;
        }
        offset = offset.saturating_add(limit);
    }
    Ok(())
}

fn sandbox_accepts_policy_reload(sandbox: &Sandbox) -> bool {
    let phase = sandbox
        .status
        .as_ref()
        .and_then(|status| SandboxPhase::try_from(status.phase).ok());
    matches!(
        phase,
        Some(SandboxPhase::Ready | SandboxPhase::Provisioning)
    )
}

fn sandbox_name(sandbox: &Sandbox) -> Option<String> {
    sandbox
        .metadata
        .as_ref()
        .map(|metadata| metadata.name.clone())
}

fn policy_update_annotations(
    policy_state: &PolicyState,
    correlation_id: &str,
) -> HashMap<String, String> {
    HashMap::from([
        (
            POLICY_SIGNATURE_ANNOTATION.to_string(),
            policy_state.policy_signature.clone(),
        ),
        (
            POLICY_HASH_ANNOTATION.to_string(),
            policy_state.policy_hash.clone(),
        ),
        (
            POLICY_SIGNATURE_KID_ANNOTATION.to_string(),
            policy_state.policy_signature_kid.clone(),
        ),
        (
            POLICY_RELOAD_CORRELATION_ANNOTATION.to_string(),
            correlation_id.to_string(),
        ),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen: SocketAddr = "127.0.0.1:18081".parse()?;
    let mut policy_path: Option<PathBuf> = None;
    let mut profiles_path: Option<PathBuf> = None;
    let mut gateway_endpoint: Option<String> = None;
    let mut policy_watch_interval = Duration::from_millis(DEFAULT_POLICY_WATCH_INTERVAL_MS);
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
            "--profiles" => {
                let value = args.next().ok_or("--profiles requires a path")?;
                profiles_path = Some(PathBuf::from(value));
            }
            "--gateway-endpoint" => {
                let value = args.next().ok_or("--gateway-endpoint requires a URL")?;
                gateway_endpoint = Some(value);
            }
            "--policy-watch-interval-ms" => {
                let value = args
                    .next()
                    .ok_or("--policy-watch-interval-ms requires a duration")?;
                let millis = value.parse::<u64>()?;
                if millis == 0 {
                    return Err("--policy-watch-interval-ms must be greater than zero".into());
                }
                policy_watch_interval = Duration::from_millis(millis);
            }
            "-h" | "--help" => {
                println!(
                    "usage: governance-interceptor [--listen ADDR] [--policy FILE] [--profiles FILE_OR_DIR] [--gateway-endpoint URL] [--policy-watch-interval-ms MS]"
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    let policy_path = policy_path.unwrap_or_else(default_policy_path);
    let policy_yaml = tokio::fs::read_to_string(&policy_path).await?;
    let profiles_path = profiles_path.unwrap_or_else(default_profiles_path);
    let service =
        GovernanceInterceptorService::from_policy_and_profiles_path(&policy_yaml, profiles_path)?;

    if let Some(endpoint) = &gateway_endpoint {
        println!("policy reload propagation enabled through gateway endpoint {endpoint}");
    } else {
        println!("policy reload propagation disabled; --gateway-endpoint was not provided");
    }
    let profile_state = service.current_profile_state();
    println!("loaded provider profiles: {}", profile_state.ids.join(", "));
    println!(
        "loaded governance policy {} from {}",
        service.current_policy_state().policy_hash,
        policy_path.display()
    );
    spawn_policy_watch_worker(
        service.clone(),
        policy_path,
        gateway_endpoint,
        policy_watch_interval,
    );

    println!("governance interceptor listening on {listen}");
    Server::builder()
        .add_service(GatewayInterceptorServer::new(service))
        .serve(listen)
        .await?;
    Ok(())
}

fn default_profiles_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("profiles")
}

fn default_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.yaml")
}

#[cfg(test)]
mod tests;
