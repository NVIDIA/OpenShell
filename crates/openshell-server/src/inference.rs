// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

use openshell_core::ObjectId;
use openshell_core::inference::{
    VERTEX_AI_PROJECT_ID_KEY, VERTEX_AI_PUBLISHER_KEY, VERTEX_AI_REGION_KEY,
};
use openshell_core::proto::{
    ClusterInferenceConfig, GetClusterInferenceRequest, GetClusterInferenceResponse,
    GetInferenceBundleRequest, GetInferenceBundleResponse, InferenceRoute, Provider, ResolvedRoute,
    SetClusterInferenceRequest, SetClusterInferenceResponse, ValidatedEndpoint,
    inference_server::Inference,
};
use openshell_providers::normalize_provider_type;
use openshell_router::config::ResolvedRoute as RouterResolvedRoute;
use openshell_router::{ValidationFailureKind, verify_backend_endpoint};
use openshell_server_macros::rpc_authz;
use prost::Message as _;
use std::sync::Arc;
use std::time::Duration;
use tonic::{Request, Response, Status};

use crate::{
    ServerState,
    persistence::{ObjectName, ObjectType, Store, WriteCondition, current_time_ms},
};

#[derive(Debug)]
pub struct InferenceService {
    state: Arc<ServerState>,
}

impl InferenceService {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

const CLUSTER_INFERENCE_ROUTE_NAME: &str = "inference.local";
const SANDBOX_SYSTEM_ROUTE_NAME: &str = "sandbox-system";

/// Map a request `route_name` to the canonical store key.
///
/// Empty string defaults to `CLUSTER_INFERENCE_ROUTE_NAME` for backward compat.
fn effective_route_name(name: &str) -> Result<&str, Status> {
    match name.trim() {
        "" | "inference.local" => Ok(CLUSTER_INFERENCE_ROUTE_NAME),
        "sandbox-system" => Ok(SANDBOX_SYSTEM_ROUTE_NAME),
        other => Err(Status::invalid_argument(format!(
            "unknown route_name '{other}'; expected 'inference.local' or 'sandbox-system'"
        ))),
    }
}

impl ObjectType for InferenceRoute {
    fn object_type() -> &'static str {
        "inference_route"
    }
}

#[rpc_authz(service = "openshell.inference.v1.Inference")]
#[tonic::async_trait]
impl Inference for InferenceService {
    #[rpc_auth(auth = "sandbox")]
    async fn get_inference_bundle(
        &self,
        request: Request<GetInferenceBundleRequest>,
    ) -> Result<Response<GetInferenceBundleResponse>, Status> {
        authorize_inference_bundle(
            request
                .extensions()
                .get::<crate::auth::principal::Principal>(),
        )?;
        resolve_inference_bundle(self.state.store.as_ref())
            .await
            .map(Response::new)
    }

    #[rpc_auth(auth = "bearer", scope = "inference:write", role = "admin")]
    async fn set_cluster_inference(
        &self,
        request: Request<SetClusterInferenceRequest>,
    ) -> Result<Response<SetClusterInferenceResponse>, Status> {
        let req = request.into_inner();
        let route_name = effective_route_name(&req.route_name)?;
        let verify = !req.no_verify;
        let route = upsert_cluster_inference_route(
            self.state.store.as_ref(),
            route_name,
            &req.provider_name,
            &req.model_id,
            req.timeout_secs,
            verify,
        )
        .await?;

        let config = route
            .route
            .config
            .as_ref()
            .ok_or_else(|| Status::internal("managed route missing config"))?;

        Ok(Response::new(SetClusterInferenceResponse {
            provider_name: config.provider_name.clone(),
            model_id: config.model_id.clone(),
            version: route.route.version,
            route_name: route_name.to_string(),
            validation_performed: !route.validation.is_empty(),
            validated_endpoints: route.validation,
            timeout_secs: config.timeout_secs,
        }))
    }

    #[rpc_auth(auth = "bearer", scope = "inference:read", role = "user")]
    async fn get_cluster_inference(
        &self,
        request: Request<GetClusterInferenceRequest>,
    ) -> Result<Response<GetClusterInferenceResponse>, Status> {
        let req = request.into_inner();
        let route_name = effective_route_name(&req.route_name)?;
        let route = self
            .state
            .store
            .get_message_by_name::<InferenceRoute>(route_name)
            .await
            .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "inference route '{route_name}' is not configured; run 'openshell inference set --provider <name> --model <id>'"
                ))
            })?;

        let config = route
            .config
            .as_ref()
            .ok_or_else(|| Status::internal("managed route missing config"))?;

        if config.provider_name.trim().is_empty() || config.model_id.trim().is_empty() {
            return Err(Status::failed_precondition(
                "managed route is missing provider/model metadata",
            ));
        }

        Ok(Response::new(GetClusterInferenceResponse {
            provider_name: config.provider_name.clone(),
            model_id: config.model_id.clone(),
            version: route.version,
            route_name: route_name.to_string(),
            timeout_secs: config.timeout_secs,
        }))
    }
}

async fn upsert_cluster_inference_route(
    store: &Store,
    route_name: &str,
    provider_name: &str,
    model_id: &str,
    timeout_secs: u64,
    verify: bool,
) -> Result<UpsertedInferenceRoute, Status> {
    if provider_name.trim().is_empty() {
        return Err(Status::invalid_argument("provider_name is required"));
    }
    if model_id.trim().is_empty() {
        return Err(Status::invalid_argument("model_id is required"));
    }

    let provider = store
        .get_message_by_name::<Provider>(provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| {
            Status::failed_precondition(format!("provider '{provider_name}' not found"))
        })?;

    let resolved = resolve_provider_route(&provider, model_id)?;
    let validation = if verify {
        vec![verify_provider_endpoint(provider.object_name(), model_id, &resolved).await?]
    } else {
        Vec::new()
    };

    let config = build_cluster_inference_config(&provider, model_id, timeout_secs);

    // Fetch existing route to determine create vs. update path
    let existing = store
        .get_message_by_name::<InferenceRoute>(route_name)
        .await
        .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

    let now_ms = current_time_ms();

    let (id, metadata, new_version, condition) = if let Some(existing) = existing {
        // Update path: preserve metadata, increment version, use CAS
        let resource_version = existing.metadata.as_ref().map_or(0, |m| m.resource_version);
        (
            existing.object_id().to_string(),
            existing.metadata.clone(),
            existing.version.saturating_add(1),
            WriteCondition::MatchResourceVersion(resource_version),
        )
    } else {
        // Create path: new metadata, version 1, use MustCreate
        let new_id = uuid::Uuid::new_v4().to_string();
        let new_metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: new_id.clone(),
            name: route_name.to_string(),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
            resource_version: 0,
        });
        (new_id, new_metadata, 1, WriteCondition::MustCreate)
    };

    let route = InferenceRoute {
        metadata,
        config: Some(config),
        version: new_version,
    };

    // Ensure metadata is valid (defense in depth - should always be true for server-constructed metadata)
    crate::grpc::validate_object_metadata(route.metadata.as_ref(), "inference_route")?;

    // Single-attempt CAS write: fails with ABORTED on concurrent modification
    store
        .put_if(
            InferenceRoute::object_type(),
            &id,
            route_name,
            &route.encode_to_vec(),
            None,
            condition,
        )
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "upsert inference route"))?;

    Ok(UpsertedInferenceRoute { route, validation })
}

fn build_cluster_inference_config(
    provider: &Provider,
    model_id: &str,
    timeout_secs: u64,
) -> ClusterInferenceConfig {
    ClusterInferenceConfig {
        provider_name: provider.object_name().to_string(),
        model_id: model_id.to_string(),
        timeout_secs,
    }
}

#[derive(Debug)]
struct ResolvedProviderRoute {
    provider_type: String,
    route: RouterResolvedRoute,
}

#[derive(Debug)]
struct UpsertedInferenceRoute {
    route: InferenceRoute,
    validation: Vec<ValidatedEndpoint>,
}

/// Infer the Vertex AI publisher segment from a model identifier.
///
/// Currently only the `"anthropic"` result is consumed by
/// `resolve_vertex_ai_route` to select between the native Anthropic
/// Messages API (`rawPredict`) and the OpenAI-compatible endpoint.
/// Non-Anthropic publisher mappings (`meta`, `mistralai`, `ai21`,
/// `deepseek`, `google`) are maintained for forward compatibility
/// and documentation value — all non-Anthropic models route to the
/// same OpenAI-compatible endpoint regardless of publisher.
///
/// Returns `None` for unrecognized models, which causes resolution to
/// fall back to the OpenAI-compatible endpoint
/// (`v1beta1/.../endpoints/openapi`).
fn infer_vertex_publisher(model_id: &str) -> Option<&'static str> {
    if model_id.starts_with("claude-") {
        Some("anthropic")
    } else if model_id.starts_with("gemini-")
        || model_id.starts_with("text-bison-")
        || model_id.starts_with("chat-bison-")
    {
        Some("google")
    } else if model_id.starts_with("llama-") {
        Some("meta")
    } else if model_id.starts_with("mistral-") || model_id.starts_with("codestral-") {
        Some("mistralai")
    } else if model_id.starts_with("jamba-") {
        Some("ai21")
    } else if model_id.starts_with("deepseek-") {
        Some("deepseek")
    } else {
        None
    }
}

/// Return a required Vertex AI config value, or a `FailedPrecondition` status.
fn required_vertex_config<'a>(
    config: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str, Status> {
    config
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            Status::failed_precondition(format!("Vertex AI provider requires {key} config"))
        })
}

/// Validate a GCP project ID against the documented format.
///
/// GCP project IDs must be 6–30 characters, start with a lowercase letter,
/// contain only lowercase letters, digits, and hyphens, and not end with a hyphen.
fn validate_gcp_project_id(value: &str) -> Result<(), Status> {
    let valid = value.len() >= 6
        && value.len() <= 30
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && !value.ends_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(Status::invalid_argument(format!(
            "VERTEX_AI_PROJECT_ID has invalid format: {value:?}. \
             GCP project IDs must be 6-30 characters, start with a lowercase letter, \
             contain only lowercase letters, digits, and hyphens, and not end with a hyphen."
        )))
    }
}

/// Validate a GCP region/location value.
///
/// Accepts the special keywords `global`, `us`, and `eu`, plus standard
/// regional patterns like `us-central1`, `europe-west4`, `us-east4-a`.
fn validate_gcp_region(value: &str) -> Result<(), Status> {
    let lower = value.trim().to_ascii_lowercase();
    let valid = matches!(lower.as_str(), "global" | "us" | "eu")
        || (lower
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && lower.contains('-')
            && !lower.starts_with('-')
            && !lower.ends_with('-'));
    if valid {
        Ok(())
    } else {
        Err(Status::invalid_argument(format!(
            "VERTEX_AI_REGION has invalid format: {value:?}. \
             Expected a GCP region (e.g. us-central1, europe-west4) \
             or one of: global, us, eu."
        )))
    }
}

/// Resolve the Vertex AI API host and normalized location from a configured region.
fn vertex_location_and_host(region: &str) -> (String, String) {
    let location = region.trim().to_ascii_lowercase();
    let host = match location.as_str() {
        "global" => "aiplatform.googleapis.com".to_string(),
        "us" | "eu" => format!("aiplatform.{location}.rep.googleapis.com"),
        _ => format!("{location}-aiplatform.googleapis.com"),
    };
    (location, host)
}

fn validate_vertex_model_id(value: &str) -> Result<(), Status> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument("model_id is required"));
    }
    if value != trimmed {
        return Err(Status::invalid_argument(format!(
            "Vertex AI model_id must not include leading or trailing whitespace: {value:?}"
        )));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(Status::invalid_argument(format!(
            "Vertex AI model_id must not contain path separators: {value:?}"
        )));
    }
    if value.chars().any(|c| matches!(c, '?' | '#' | '%')) {
        return Err(Status::invalid_argument(format!(
            "Vertex AI model_id must not contain URL delimiters or percent escapes: {value:?}"
        )));
    }
    if value.contains("..") {
        return Err(Status::invalid_argument(format!(
            "Vertex AI model_id must not contain traversal segments: {value:?}"
        )));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Status::invalid_argument(format!(
            "Vertex AI model_id must not contain whitespace or control characters: {value:?}"
        )));
    }
    Ok(())
}

fn is_allowed_vertex_override_host(host: &str) -> bool {
    matches!(
        host,
        "aiplatform.googleapis.com"
            | "aiplatform.us.rep.googleapis.com"
            | "aiplatform.eu.rep.googleapis.com"
    ) || host.ends_with("-aiplatform.googleapis.com")
}

fn validate_vertex_base_url(value: &str) -> Result<String, Status> {
    let trimmed = value.trim();
    let url = url::Url::parse(trimmed).map_err(|err| {
        Status::invalid_argument(format!("Vertex AI base URL override is invalid: {err}"))
    })?;

    if url.scheme() != "https" {
        return Err(Status::invalid_argument(
            "Vertex AI base URL override must use https".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Status::invalid_argument(
            "Vertex AI base URL override must not include userinfo".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Status::invalid_argument(
            "Vertex AI base URL override must not include query or fragment components".to_string(),
        ));
    }
    if let Some(port) = url.port()
        && port != 443
    {
        return Err(Status::invalid_argument(format!(
            "Vertex AI base URL override must use port 443 when an explicit port is set, got {port}"
        )));
    }

    match url.host() {
        Some(url::Host::Domain(host)) if is_allowed_vertex_override_host(host) => {}
        Some(url::Host::Domain(host)) => {
            return Err(Status::invalid_argument(format!(
                "Vertex AI base URL override must target an official Vertex AI hostname, got {host:?}"
            )));
        }
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => {
            return Err(Status::invalid_argument(format!(
                "Vertex AI base URL override must not use IP literal hosts: {}",
                url.host_str().unwrap_or("<unknown>")
            )));
        }
        None => {
            return Err(Status::invalid_argument(
                "Vertex AI base URL override must include a host".to_string(),
            ));
        }
    }

    Ok(trimmed.to_string())
}

/// Build a [`RouterResolvedRoute`] for Vertex AI without duplicating the 15-field struct.
#[allow(clippy::too_many_arguments)]
fn build_vertex_route(
    route_name: &str,
    endpoint: String,
    model_id: &str,
    api_key: &str,
    protocols: Vec<String>,
    profile: &openshell_core::inference::InferenceProviderProfile,
    model_in_path: bool,
    request_path_override: Option<String>,
) -> RouterResolvedRoute {
    RouterResolvedRoute {
        name: route_name.to_string(),
        endpoint,
        model: model_id.to_string(),
        api_key: api_key.to_string(),
        protocols,
        auth: profile.auth.clone(),
        default_headers: profile
            .default_headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        passthrough_headers: profile
            .passthrough_headers
            .iter()
            .map(|p| (*p).to_string())
            .collect(),
        timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
        model_in_path,
        request_path_override,
    }
}

/// Resolve a Vertex AI route given provider config, model, and bearer token.
fn resolve_vertex_ai_route(
    config: &std::collections::HashMap<String, String>,
    model_id: &str,
    route_name: &str,
    api_key: &str,
    profile: &openshell_core::inference::InferenceProviderProfile,
) -> Result<RouterResolvedRoute, Status> {
    // Validate model_id early — it appears in URL paths for Anthropic routes
    // and in JSON request bodies for all routes. Rejecting path separators,
    // traversal segments, and control characters up front is defense-in-depth.
    validate_vertex_model_id(model_id)?;

    // Determine if this is an Anthropic model.
    // Explicit VERTEX_AI_PUBLISHER=anthropic overrides inference.
    // All non-Anthropic models route to the OpenAI-compatible endpoint.
    let explicit_publisher = config
        .get(VERTEX_AI_PUBLISHER_KEY)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty());

    let is_anthropic = explicit_publisher.map_or_else(
        || infer_vertex_publisher(model_id) == Some("anthropic"),
        |p| p.eq_ignore_ascii_case("anthropic"),
    );

    // Escape hatch: caller-supplied full base URL still uses the model-derived
    // protocol and path contract, but only for the OpenAI-compatible Vertex surface.
    // Anthropic-on-Vertex needs model-path shaping and body adaptation that a fully
    // caller-controlled URL cannot safely preserve.
    if let Some(base_url) = config
        .get(profile.base_url_config_keys[0])
        .or_else(|| config.get(profile.base_url_config_keys[1]))
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
    {
        if is_anthropic {
            return Err(Status::invalid_argument(
                "Vertex AI base URL overrides are not supported for Anthropic models. \
                 Remove GOOGLE_VERTEX_AI_BASE_URL / VERTEX_AI_BASE_URL and configure \
                 VERTEX_AI_PROJECT_ID + VERTEX_AI_REGION instead."
                    .to_string(),
            ));
        }
        let base_url = validate_vertex_base_url(base_url)?;

        return Ok(build_vertex_route(
            route_name,
            base_url,
            model_id,
            api_key,
            vec!["openai_chat_completions".to_string()],
            profile,
            false,
            Some("/chat/completions".to_string()),
        ));
    }

    let project = required_vertex_config(config, VERTEX_AI_PROJECT_ID_KEY)?;
    validate_gcp_project_id(project)?;
    let region = config
        .get(VERTEX_AI_REGION_KEY)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("us-central1");
    validate_gcp_region(region)?;
    let (location, host) = vertex_location_and_host(region);

    if is_anthropic {
        // Native Anthropic Messages API via rawPredict.
        // model_id is NOT embedded in the endpoint — it is carried in route.model
        // and appended with the suffix by build_provider_url(). The router upgrades
        // `:rawPredict` to `:streamRawPredict` only for streaming proxy calls.
        let endpoint = format!(
            "https://{host}/v1/projects/{project}/locations/{location}/publishers/anthropic/models"
        );
        let protocols = vec!["anthropic_messages".to_string()];
        Ok(build_vertex_route(
            route_name,
            endpoint,
            model_id,
            api_key,
            protocols,
            profile,
            true,
            Some(":rawPredict".to_string()),
        ))
    } else {
        // OpenAI-compatible endpoint for all non-Anthropic models
        // (Gemini, Llama, Mistral, unknown, etc.). Vertex's OpenAI-compatible
        // surface uses `/chat/completions` under the `.../endpoints/openapi`
        // base, so we pin the route to that path instead of appending the
        // router's default `/v1/...` protocol path.
        let endpoint = format!(
            "https://{host}/v1beta1/projects/{project}/locations/{location}/endpoints/openapi"
        );
        let protocols = vec!["openai_chat_completions".to_string()];
        Ok(build_vertex_route(
            route_name,
            endpoint,
            model_id,
            api_key,
            protocols,
            profile,
            false,
            Some("/chat/completions".to_string()),
        ))
    }
}

fn resolve_provider_route(
    provider: &Provider,
    model_id: &str,
) -> Result<ResolvedProviderRoute, Status> {
    let raw_provider_type = provider.r#type.trim();
    let provider_type = normalize_provider_type(raw_provider_type)
        .map_or_else(|| raw_provider_type.to_ascii_lowercase(), str::to_string);

    let profile = openshell_core::inference::profile_for(&provider_type).ok_or_else(|| {
        Status::invalid_argument(format!(
            "provider '{name}' has unsupported type '{raw_provider_type}' for cluster inference \
                 (supported: openai, anthropic, nvidia, google-vertex-ai)",
            name = provider.object_name()
        ))
    })?;

    let api_key = find_provider_api_key(
        provider,
        profile.credential_key_names,
        if provider_type == "google-vertex-ai" {
            CredentialLookup::PreferredOnly
        } else {
            CredentialLookup::PreferredThenAny
        },
    )
    .ok_or_else(|| {
        Status::invalid_argument(format!(
            "provider '{name}' has no usable API key credential",
            name = provider.object_name()
        ))
    })?;

    // Vertex AI requires a model-aware URL; delegate to specialised resolver.
    if provider_type == "google-vertex-ai" {
        let route = resolve_vertex_ai_route(
            &provider.config,
            model_id,
            provider.object_name(),
            &api_key,
            profile,
        )?;
        return Ok(ResolvedProviderRoute {
            provider_type,
            route,
        });
    }

    let base_url = find_provider_config_value(provider, profile.base_url_config_keys)
        .unwrap_or_else(|| profile.default_base_url.to_string())
        .trim()
        .to_string();

    if base_url.is_empty() {
        return Err(Status::invalid_argument(format!(
            "provider '{name}' resolved to empty base_url",
            name = provider.object_name()
        )));
    }

    Ok(ResolvedProviderRoute {
        provider_type,
        route: RouterResolvedRoute {
            name: provider.object_name().to_string(),
            endpoint: base_url,
            model: model_id.to_string(),
            api_key,
            protocols: profile.protocols.iter().map(|p| (*p).to_string()).collect(),
            auth: profile.auth.clone(),
            default_headers: profile
                .default_headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            passthrough_headers: profile
                .passthrough_headers
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
        },
    })
}

fn validation_failure(
    provider_name: &str,
    model_id: &str,
    base_url: &str,
    details: &str,
    next_steps: &str,
) -> Status {
    Status::failed_precondition(format!(
        "failed to verify inference endpoint for provider '{provider_name}' and model '{model_id}' at '{base_url}': {details}. Next steps: {next_steps}, or retry with '--no-verify' if you want to skip verification"
    ))
}

fn validation_next_steps(kind: ValidationFailureKind) -> &'static str {
    match kind {
        ValidationFailureKind::Credentials => {
            "verify the provider API key and any required auth headers"
        }
        ValidationFailureKind::RateLimited => {
            "retry later or verify quota/limits on the upstream provider"
        }
        ValidationFailureKind::RequestShape => {
            "confirm the provider type, base URL, and model identifier"
        }
        ValidationFailureKind::Connectivity => {
            "check that the service is running, confirm the base URL and protocol, and verify credentials"
        }
        ValidationFailureKind::UpstreamHealth => {
            "check whether the endpoint is healthy and serving requests"
        }
        ValidationFailureKind::Unexpected => {
            "confirm the endpoint URL, protocol, credentials, and model identifier"
        }
    }
}

async fn verify_provider_endpoint(
    provider_name: &str,
    model_id: &str,
    route: &ResolvedProviderRoute,
) -> Result<ValidatedEndpoint, Status> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| Status::internal(format!("build validation client failed: {err}")))?;
    verify_backend_endpoint(&client, &route.route)
        .await
        .map(|validated| ValidatedEndpoint {
            url: validated.url,
            protocol: validated.protocol,
        })
        .map_err(|err| {
            validation_failure(
                provider_name,
                model_id,
                &route.route.endpoint,
                &err.details,
                validation_next_steps(err.kind),
            )
        })
}

/// Controls whether `find_provider_api_key` is allowed to fall back to any
/// non-empty credential when the preferred key names produce no match.
///
/// `PreferredOnly` is used for providers like Vertex AI where the fallback
/// would pick up JSON bootstrap material (e.g. service account keys) that
/// are not valid bearer tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialLookup {
    /// Only search `preferred_key_names`. Return `None` if none match.
    PreferredOnly,
    /// Search `preferred_key_names` first, then fall back to any non-empty credential.
    PreferredThenAny,
}

fn find_provider_api_key(
    provider: &Provider,
    preferred_key_names: &[&str],
    lookup: CredentialLookup,
) -> Option<String> {
    for key in preferred_key_names {
        if let Some(value) = provider.credentials.get(*key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }

    if lookup == CredentialLookup::PreferredOnly {
        return None;
    }

    let mut keys = provider.credentials.keys().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        if let Some(value) = provider.credentials.get(key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }

    None
}

fn find_provider_config_value(provider: &Provider, preferred_keys: &[&str]) -> Option<String> {
    for key in preferred_keys {
        if let Some(value) = provider.config.get(*key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }
    None
}

fn authorize_inference_bundle(
    principal: Option<&crate::auth::principal::Principal>,
) -> Result<(), Status> {
    match principal {
        Some(crate::auth::principal::Principal::Sandbox(_)) => Ok(()),
        Some(crate::auth::principal::Principal::User(_)) => Err(Status::permission_denied(
            "GetInferenceBundle requires a sandbox principal",
        )),
        Some(crate::auth::principal::Principal::Anonymous) | None => Err(Status::unauthenticated(
            "GetInferenceBundle requires an authenticated sandbox principal",
        )),
    }
}

/// Resolve the inference bundle (all managed routes + revision hash).
async fn resolve_inference_bundle(store: &Store) -> Result<GetInferenceBundleResponse, Status> {
    let mut routes = Vec::new();
    if let Some(r) = resolve_route_by_name(store, CLUSTER_INFERENCE_ROUTE_NAME).await? {
        routes.push(r);
    }
    if let Some(r) = resolve_route_by_name(store, SANDBOX_SYSTEM_ROUTE_NAME).await? {
        routes.push(r);
    }

    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX);

    // Compute a simple revision from route contents for cache freshness checks.
    let revision = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for r in &routes {
            r.name.hash(&mut hasher);
            r.base_url.hash(&mut hasher);
            r.model_id.hash(&mut hasher);
            r.api_key.hash(&mut hasher);
            r.protocols.hash(&mut hasher);
            r.provider_type.hash(&mut hasher);
            r.timeout_secs.hash(&mut hasher);
            r.model_in_path.hash(&mut hasher);
            r.request_path_override.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    };

    Ok(GetInferenceBundleResponse {
        routes,
        revision,
        generated_at_ms: now_ms,
    })
}

async fn resolve_route_by_name(
    store: &Store,
    route_name: &str,
) -> Result<Option<ResolvedRoute>, Status> {
    let route = store
        .get_message_by_name::<InferenceRoute>(route_name)
        .await
        .map_err(|e| Status::internal(format!("fetch route failed: {e}")))?;

    let Some(route) = route else {
        return Ok(None);
    };

    let Some(config) = route.config.as_ref() else {
        return Ok(None);
    };

    if config.provider_name.trim().is_empty() {
        return Err(Status::failed_precondition(format!(
            "route '{route_name}' is missing provider_name"
        )));
    }

    if config.model_id.trim().is_empty() {
        return Err(Status::failed_precondition(format!(
            "route '{route_name}' is missing model_id"
        )));
    }

    let provider = store
        .get_message_by_name::<Provider>(&config.provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "configured provider '{}' was not found",
                config.provider_name
            ))
        })?;

    let resolved = resolve_provider_route(&provider, &config.model_id)?;

    Ok(Some(ResolvedRoute {
        name: route_name.to_string(),
        base_url: resolved.route.endpoint,
        model_id: config.model_id.clone(),
        api_key: resolved.route.api_key,
        protocols: resolved.route.protocols,
        provider_type: resolved.provider_type,
        timeout_secs: config.timeout_secs,
        model_in_path: resolved.route.model_in_path,
        request_path_override: resolved.route.request_path_override,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{
        Principal, SandboxIdentitySource, SandboxPrincipal, UserPrincipal,
    };
    use openshell_core::ObjectId;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn test_store() -> Store {
        crate::persistence::test_store().await
    }

    fn test_user_principal() -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: "user-a".to_string(),
                display_name: None,
                roles: vec!["openshell-user".to_string()],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    fn test_sandbox_principal() -> Principal {
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: "sandbox-a".to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    fn make_route(name: &str, provider_name: &str, model_id: &str) -> InferenceRoute {
        InferenceRoute {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("id-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            config: Some(ClusterInferenceConfig {
                provider_name: provider_name.to_string(),
                model_id: model_id.to_string(),
                timeout_secs: 0,
            }),
            version: 0,
        }
    }

    fn make_provider(name: &str, provider_type: &str, key_name: &str, key_value: &str) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("provider-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            r#type: provider_type.to_string(),
            credentials: std::iter::once((key_name.to_string(), key_value.to_string())).collect(),
            config: std::collections::HashMap::new(),
            credential_expires_at_ms: std::collections::HashMap::new(),
        }
    }

    fn make_provider_with_base_url(
        name: &str,
        provider_type: &str,
        key_name: &str,
        key_value: &str,
        base_url_key: &str,
        base_url: &str,
    ) -> Provider {
        Provider {
            config: std::iter::once((base_url_key.to_string(), base_url.to_string())).collect(),
            ..make_provider(name, provider_type, key_name, key_value)
        }
    }

    #[test]
    fn inference_bundle_requires_sandbox_principal() {
        let sandbox = test_sandbox_principal();
        assert!(authorize_inference_bundle(Some(&sandbox)).is_ok());

        let user = test_user_principal();
        let err = authorize_inference_bundle(Some(&user)).expect_err("users cannot fetch bundle");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = authorize_inference_bundle(None).expect_err("missing principal rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn upsert_cluster_route_creates_and_increments_version() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store
            .put_message(&provider)
            .await
            .expect("provider should persist");

        let first = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o",
            0,
            false,
        )
        .await
        .expect("first set should succeed");
        assert_eq!(first.route.object_name(), CLUSTER_INFERENCE_ROUTE_NAME);

        let second = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4.1",
            0,
            false,
        )
        .await
        .expect("second set should succeed");
        assert_eq!(second.route.object_id(), first.route.object_id());

        let config = second.route.config.as_ref().expect("config");
        assert_eq!(config.provider_name, "openai-dev");
        assert_eq!(config.model_id, "gpt-4.1");
    }

    #[tokio::test]
    async fn resolve_managed_route_returns_none_when_missing() {
        let store = test_store().await;

        let route = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("resolution should not fail");
        assert!(route.is_none());
    }

    #[tokio::test]
    async fn bundle_happy_path_returns_managed_route() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = make_route(CLUSTER_INFERENCE_ROUTE_NAME, "openai-dev", "mock/model-a");
        store.put_message(&route).await.expect("persist route");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].name, CLUSTER_INFERENCE_ROUTE_NAME);
        assert_eq!(resp.routes[0].model_id, "mock/model-a");
        assert_eq!(resp.routes[0].provider_type, "openai");
        assert_eq!(resp.routes[0].api_key, "sk-test");
        assert_eq!(resp.routes[0].base_url, "https://api.openai.com/v1");
        assert!(!resp.revision.is_empty());
        assert!(resp.generated_at_ms > 0);
    }

    #[tokio::test]
    async fn bundle_vertex_ai_anthropic_route_preserves_model_path_and_rawpredict() {
        let store = test_store().await;
        let config = [
            (
                "VERTEX_AI_PROJECT_ID".to_string(),
                "my-gcp-project".to_string(),
            ),
            ("VERTEX_AI_REGION".to_string(), "us-central1".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-dev", config);
        store
            .put_message(&provider)
            .await
            .expect("persist provider");
        let route = make_route(
            CLUSTER_INFERENCE_ROUTE_NAME,
            "vertex-dev",
            "claude-3-5-sonnet@20241022",
        );
        store.put_message(&route).await.expect("persist route");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        let route = &resp.routes[0];
        assert_eq!(route.provider_type, "google-vertex-ai");
        assert_eq!(route.api_key, "ya29.test-token");
        assert_eq!(route.protocols, vec!["anthropic_messages"]);
        assert!(route.model_in_path);
        assert_eq!(route.request_path_override, Some(":rawPredict".to_string()));
        assert_eq!(route.model_id, "claude-3-5-sonnet@20241022");
        assert_eq!(
            route.base_url,
            "https://us-central1-aiplatform.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/publishers/anthropic/models"
        );
    }

    #[tokio::test]
    async fn bundle_vertex_ai_gemini_route_preserves_chat_completions_override() {
        let store = test_store().await;
        let config = [
            (
                "VERTEX_AI_PROJECT_ID".to_string(),
                "my-gcp-project".to_string(),
            ),
            ("VERTEX_AI_REGION".to_string(), "us-central1".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-dev", config);
        store
            .put_message(&provider)
            .await
            .expect("persist provider");
        let route = make_route(
            CLUSTER_INFERENCE_ROUTE_NAME,
            "vertex-dev",
            "gemini-2.0-flash-001",
        );
        store.put_message(&route).await.expect("persist route");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        let route = &resp.routes[0];
        assert_eq!(route.provider_type, "google-vertex-ai");
        assert_eq!(route.api_key, "ya29.test-token");
        assert_eq!(route.protocols, vec!["openai_chat_completions"]);
        assert!(!route.model_in_path);
        assert_eq!(
            route.request_path_override,
            Some("/chat/completions".to_string())
        );
        assert_eq!(route.model_id, "gemini-2.0-flash-001");
        assert_eq!(
            route.base_url,
            "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-gcp-project/locations/us-central1/endpoints/openapi"
        );
    }

    #[tokio::test]
    async fn bundle_without_cluster_route_returns_empty_routes() {
        let store = test_store().await;

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");
        assert!(resp.routes.is_empty());
    }

    #[tokio::test]
    async fn bundle_revision_is_stable_for_same_route() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = make_route(
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "mock/model-stable",
        );
        store.put_message(&route).await.expect("persist route");

        let resp1 = resolve_inference_bundle(&store)
            .await
            .expect("first resolve");
        let resp2 = resolve_inference_bundle(&store)
            .await
            .expect("second resolve");

        assert_eq!(
            resp1.revision, resp2.revision,
            "same route should produce same revision"
        );
    }

    #[tokio::test]
    async fn resolve_managed_route_derives_from_provider() {
        let store = test_store().await;

        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "provider-1".to_string(),
                name: "openai-dev".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            r#type: "openai".to_string(),
            credentials: std::iter::once(("OPENAI_API_KEY".to_string(), "sk-test".to_string()))
                .collect(),
            config: std::iter::once((
                "OPENAI_BASE_URL".to_string(),
                "https://station.example.com/v1".to_string(),
            ))
            .collect(),
            credential_expires_at_ms: std::collections::HashMap::new(),
        };
        store
            .put_message(&provider)
            .await
            .expect("provider should persist");

        let route = InferenceRoute {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "r-1".to_string(),
                name: CLUSTER_INFERENCE_ROUTE_NAME.to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            config: Some(ClusterInferenceConfig {
                provider_name: "openai-dev".to_string(),
                model_id: "test/model".to_string(),
                timeout_secs: 0,
            }),
            version: 1,
        };
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let managed = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");

        assert_eq!(managed.base_url, "https://station.example.com/v1");
        assert_eq!(managed.api_key, "sk-test");
        assert_eq!(managed.provider_type, "openai");
        assert_eq!(
            managed.protocols,
            vec![
                "openai_chat_completions".to_string(),
                "openai_completions".to_string(),
                "openai_responses".to_string(),
                "model_discovery".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn resolve_managed_route_reflects_provider_key_rotation() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-initial");
        store
            .put_message(&provider)
            .await
            .expect("provider should persist");

        let route = make_route(CLUSTER_INFERENCE_ROUTE_NAME, "openai-dev", "test/model");
        store
            .put_message(&route)
            .await
            .expect("route should persist");

        let first = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");
        assert_eq!(first.api_key, "sk-initial");

        let rotated_provider = Provider {
            metadata: provider.metadata.clone(),
            r#type: provider.r#type.clone(),
            credentials: std::iter::once(("OPENAI_API_KEY".to_string(), "sk-rotated".to_string()))
                .collect(),
            config: provider.config.clone(),
            credential_expires_at_ms: provider.credential_expires_at_ms.clone(),
        };
        store
            .put_message(&rotated_provider)
            .await
            .expect("provider rotation should persist");

        let second = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("route should resolve")
            .expect("managed route should exist");
        assert_eq!(second.api_key, "sk-rotated");
    }

    #[tokio::test]
    async fn upsert_system_route_creates_with_correct_name() {
        let store = test_store().await;

        let provider = make_provider("anthropic-dev", "anthropic", "ANTHROPIC_API_KEY", "sk-ant");
        store.put_message(&provider).await.expect("persist");

        let route = upsert_cluster_inference_route(
            &store,
            SANDBOX_SYSTEM_ROUTE_NAME,
            "anthropic-dev",
            "claude-sonnet-4-20250514",
            0,
            false,
        )
        .await
        .expect("should succeed");

        assert_eq!(route.route.object_name(), SANDBOX_SYSTEM_ROUTE_NAME);
        let config = route.route.config.as_ref().expect("config");
        assert_eq!(config.provider_name, "anthropic-dev");
        assert_eq!(config.model_id, "claude-sonnet-4-20250514");
    }

    #[tokio::test]
    async fn upsert_cluster_inference_route_vertex_ai_anthropic_sets_model_in_path() {
        let store = test_store().await;

        // Build a Vertex AI provider with the required config and a minted access token.
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "provider-vertex-test".to_string(),
                name: "vertex-test".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            r#type: "google-vertex-ai".to_string(),
            credentials: std::iter::once((
                "GOOGLE_VERTEX_AI_TOKEN".to_string(),
                "ya29.test-access-token".to_string(),
            ))
            .collect(),
            config: [
                (
                    "VERTEX_AI_PROJECT_ID".to_string(),
                    "my-gcp-project".to_string(),
                ),
                ("VERTEX_AI_REGION".to_string(), "us-central1".to_string()),
            ]
            .into_iter()
            .collect(),
            credential_expires_at_ms: std::collections::HashMap::new(),
        };
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let result = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "vertex-test",
            "claude-3-5-sonnet@20241022",
            0,
            false, // skip verification — no live endpoint
        )
        .await
        .expect("upsert should succeed for Vertex AI Anthropic model");

        // Confirm the route was persisted with correct metadata
        assert_eq!(result.route.object_name(), CLUSTER_INFERENCE_ROUTE_NAME);
        let config = result.route.config.as_ref().expect("config");
        assert_eq!(config.provider_name, "vertex-test");
        assert_eq!(config.model_id, "claude-3-5-sonnet@20241022");

        // Resolve the persisted route and assert Vertex AI Anthropic path contract
        let resolved = resolve_route_by_name(&store, CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("resolve should not fail")
            .expect("route should exist after upsert");

        assert!(
            resolved.model_in_path,
            "Anthropic-on-Vertex routes must set model_in_path=true"
        );
        assert_eq!(
            resolved.request_path_override,
            Some(":rawPredict".to_string()),
            "Anthropic-on-Vertex routes must persist the rawPredict suffix"
        );
        assert_eq!(resolved.provider_type, "google-vertex-ai");
        assert!(
            resolved.base_url.contains("publishers/anthropic/models"),
            "endpoint must end with /publishers/anthropic/models, got: {}",
            resolved.base_url
        );
        assert!(
            !resolved.base_url.contains("claude-3-5-sonnet"),
            "model_id must not be embedded in the endpoint, got: {}",
            resolved.base_url
        );
    }

    #[tokio::test]
    async fn bundle_includes_both_user_and_system_routes() {
        let store = test_store().await;

        let openai = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-oai");
        store.put_message(&openai).await.expect("persist openai");
        let anthropic = make_provider("anthropic-dev", "anthropic", "ANTHROPIC_API_KEY", "sk-ant");
        store
            .put_message(&anthropic)
            .await
            .expect("persist anthropic");

        let user_route = make_route(CLUSTER_INFERENCE_ROUTE_NAME, "openai-dev", "gpt-4o");
        store
            .put_message(&user_route)
            .await
            .expect("persist user route");
        let system_route = make_route(
            SANDBOX_SYSTEM_ROUTE_NAME,
            "anthropic-dev",
            "claude-sonnet-4-20250514",
        );
        store
            .put_message(&system_route)
            .await
            .expect("persist system route");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 2);
        assert_eq!(resp.routes[0].name, CLUSTER_INFERENCE_ROUTE_NAME);
        assert_eq!(resp.routes[0].model_id, "gpt-4o");
        assert_eq!(resp.routes[1].name, SANDBOX_SYSTEM_ROUTE_NAME);
        assert_eq!(resp.routes[1].model_id, "claude-sonnet-4-20250514");
    }

    #[tokio::test]
    async fn bundle_with_only_system_route() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store.put_message(&provider).await.expect("persist");
        let system_route = make_route(SANDBOX_SYSTEM_ROUTE_NAME, "openai-dev", "gpt-4o-mini");
        store.put_message(&system_route).await.expect("persist");

        let resp = resolve_inference_bundle(&store)
            .await
            .expect("bundle should resolve");

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].name, SANDBOX_SYSTEM_ROUTE_NAME);
        assert_eq!(resp.routes[0].model_id, "gpt-4o-mini");
    }

    #[tokio::test]
    async fn get_returns_system_route_when_requested() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store.put_message(&provider).await.expect("persist");

        upsert_cluster_inference_route(
            &store,
            SANDBOX_SYSTEM_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            false,
        )
        .await
        .expect("upsert should succeed");

        let route = store
            .get_message_by_name::<InferenceRoute>(SANDBOX_SYSTEM_ROUTE_NAME)
            .await
            .expect("fetch should succeed")
            .expect("route should exist");

        assert_eq!(route.object_name(), SANDBOX_SYSTEM_ROUTE_NAME);
        let config = route.config.as_ref().expect("config");
        assert_eq!(config.model_id, "gpt-4o-mini");
    }

    #[tokio::test]
    async fn upsert_cluster_route_verifies_endpoint_when_requested() {
        let store = test_store().await;
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-test"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(serde_json::json!({
                "model": "gpt-4o-mini",
                "max_completion_tokens": 32,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "model": "gpt-4o-mini"
            })))
            .mount(&mock_server)
            .await;

        let provider = make_provider_with_base_url(
            "openai-dev",
            "openai",
            "OPENAI_API_KEY",
            "sk-test",
            "OPENAI_BASE_URL",
            &mock_server.uri(),
        );
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            true,
        )
        .await
        .expect("validation should succeed");

        assert_eq!(route.route.version, 1);
        assert_eq!(route.validation.len(), 1);
        assert_eq!(route.validation[0].protocol, "openai_chat_completions");
    }

    #[tokio::test]
    async fn upsert_cluster_route_rejects_failed_validation() {
        let store = test_store().await;
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad key"))
            .mount(&mock_server)
            .await;

        let provider = make_provider_with_base_url(
            "openai-dev",
            "openai",
            "OPENAI_API_KEY",
            "sk-test",
            "OPENAI_BASE_URL",
            &mock_server.uri(),
        );
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let err = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            true,
        )
        .await
        .expect_err("validation should fail");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("failed to verify inference endpoint")
        );
        assert!(err.message().contains("verify the provider API key"));
        assert!(err.message().contains("--no-verify"));

        let persisted = store
            .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("fetch route")
            .is_none();
        assert!(persisted, "route should not persist on failed validation");
    }

    #[tokio::test]
    async fn upsert_cluster_route_skips_validation_by_default() {
        let store = test_store().await;
        let provider = make_provider_with_base_url(
            "openai-dev",
            "openai",
            "OPENAI_API_KEY",
            "sk-test",
            "OPENAI_BASE_URL",
            "http://127.0.0.1:9",
        );
        store
            .put_message(&provider)
            .await
            .expect("persist provider");

        let route = upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-4o-mini",
            0,
            false,
        )
        .await
        .expect("non-verified route should persist");

        assert_eq!(route.route.version, 1);
        assert!(route.validation.is_empty());
    }

    // -------------------------------------------------------------------------
    // infer_vertex_publisher tests
    // -------------------------------------------------------------------------

    #[test]
    fn infer_vertex_publisher_anthropic() {
        assert_eq!(
            infer_vertex_publisher("claude-3-5-sonnet@20241022"),
            Some("anthropic")
        );
        assert_eq!(infer_vertex_publisher("claude-opus-4"), Some("anthropic"));
    }

    #[test]
    fn infer_vertex_publisher_gemini() {
        assert_eq!(infer_vertex_publisher("gemini-pro"), Some("google"));
        assert_eq!(infer_vertex_publisher("gemini-1.5-flash"), Some("google"));
        assert_eq!(infer_vertex_publisher("text-bison-001"), Some("google"));
        assert_eq!(infer_vertex_publisher("chat-bison-001"), Some("google"));
    }

    #[test]
    fn infer_vertex_publisher_unknown() {
        assert_eq!(infer_vertex_publisher("some-unknown-model"), None);
        assert_eq!(infer_vertex_publisher("gpt-4o"), None);
    }

    #[test]
    fn infer_vertex_publisher_other_publishers() {
        assert_eq!(infer_vertex_publisher("llama-3-70b"), Some("meta"));
        assert_eq!(infer_vertex_publisher("mistral-large"), Some("mistralai"));
        assert_eq!(infer_vertex_publisher("codestral-22b"), Some("mistralai"));
        assert_eq!(infer_vertex_publisher("jamba-1.5-large"), Some("ai21"));
        assert_eq!(infer_vertex_publisher("deepseek-r1"), Some("deepseek"));
    }

    // -------------------------------------------------------------------------
    // resolve_vertex_ai_route tests
    // -------------------------------------------------------------------------

    fn make_vertex_provider_with_config(
        name: &str,
        config: std::collections::HashMap<String, String>,
    ) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("provider-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 1,
            }),
            r#type: "google-vertex-ai".to_string(),
            credentials: std::iter::once((
                "GOOGLE_VERTEX_AI_TOKEN".to_string(),
                "ya29.test-token".to_string(),
            ))
            .collect(),
            config,
            credential_expires_at_ms: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn resolve_vertex_ai_route_anthropic_model() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "my-project".to_string()),
            ("VERTEX_AI_REGION".to_string(), "us-east1".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-dev", config);

        let resolved = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022")
            .expect("should resolve");

        assert_eq!(resolved.provider_type, "google-vertex-ai");
        assert!(resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some(":rawPredict".to_string())
        );
        // model_id must NOT be embedded in the endpoint — it travels via route.model
        assert!(
            !resolved.route.endpoint.contains("claude-3-5-sonnet"),
            "model_id must not be in endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved
                .route
                .endpoint
                .ends_with("/publishers/anthropic/models"),
            "endpoint should end with /publishers/anthropic/models, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved
                .route
                .endpoint
                .starts_with("https://us-east1-aiplatform.googleapis.com/"),
            "expected regional Vertex host, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved.route.endpoint.contains("my-project"),
            "expected project in URL"
        );
        assert!(
            resolved
                .route
                .protocols
                .contains(&"anthropic_messages".to_string()),
            "expected anthropic_messages protocol"
        );
        assert_eq!(resolved.route.model, "claude-3-5-sonnet@20241022");
    }

    #[test]
    fn resolve_vertex_ai_route_base_url_override() {
        let config = std::iter::once((
            "VERTEX_AI_BASE_URL".to_string(),
            "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-project/locations/us-central1/endpoints/openapi".to_string(),
        ))
        .collect();
        let provider = make_vertex_provider_with_config("vertex-custom", config);

        let resolved = resolve_provider_route(&provider, "any-model").expect("should resolve");

        assert_eq!(
            resolved.route.endpoint,
            "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-project/locations/us-central1/endpoints/openapi"
        );
        assert!(!resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
        assert_eq!(
            resolved.route.protocols,
            vec!["openai_chat_completions".to_string()]
        );
        assert_eq!(resolved.route.model, "any-model");
    }

    #[test]
    fn resolve_vertex_ai_route_google_prefixed_base_url_override() {
        // GOOGLE_VERTEX_AI_BASE_URL (the preferred key) must work on its own.
        let config = std::iter::once((
            "GOOGLE_VERTEX_AI_BASE_URL".to_string(),
            "https://aiplatform.googleapis.com/v1beta1/projects/my-project/locations/global/endpoints/openapi".to_string(),
        ))
        .collect();
        let provider = make_vertex_provider_with_config("vertex-custom-google", config);

        let resolved = resolve_provider_route(&provider, "any-model").expect("should resolve");

        assert_eq!(
            resolved.route.endpoint,
            "https://aiplatform.googleapis.com/v1beta1/projects/my-project/locations/global/endpoints/openapi"
        );
        assert!(!resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
    }

    #[test]
    fn resolve_vertex_ai_route_base_url_priority_google_wins() {
        // When both override keys are set, GOOGLE_VERTEX_AI_BASE_URL takes priority.
        let config = [
            (
                "GOOGLE_VERTEX_AI_BASE_URL".to_string(),
                "https://aiplatform.googleapis.com/v1beta1/projects/my-project/locations/global/endpoints/openapi".to_string(),
            ),
            (
                "VERTEX_AI_BASE_URL".to_string(),
                "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-project/locations/us-central1/endpoints/openapi".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-priority", config);

        let resolved = resolve_provider_route(&provider, "any-model").expect("should resolve");

        assert_eq!(
            resolved.route.endpoint,
            "https://aiplatform.googleapis.com/v1beta1/projects/my-project/locations/global/endpoints/openapi",
            "GOOGLE_VERTEX_AI_BASE_URL must win over VERTEX_AI_BASE_URL"
        );
    }

    #[test]
    fn resolve_vertex_ai_route_base_url_override_rejects_anthropic_models() {
        let config = std::iter::once((
            "GOOGLE_VERTEX_AI_BASE_URL".to_string(),
            "https://aiplatform.googleapis.com/v1beta1/projects/my-project/locations/global/endpoints/openapi".to_string(),
        ))
        .collect();
        let provider = make_vertex_provider_with_config("vertex-custom-anthropic", config);

        let err = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022")
            .expect_err("anthropic overrides should fail closed");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("base URL overrides are not supported")
        );
    }

    #[test]
    fn resolve_vertex_ai_route_base_url_override_rejects_non_vertex_host() {
        let config = std::iter::once((
            "VERTEX_AI_BASE_URL".to_string(),
            "https://custom.example.com/v1".to_string(),
        ))
        .collect();
        let provider = make_vertex_provider_with_config("vertex-custom-invalid-host", config);

        let err = resolve_provider_route(&provider, "gemini-pro")
            .expect_err("non-Vertex hosts must be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("must target an official Vertex AI hostname")
        );
    }

    #[test]
    fn resolve_vertex_ai_route_base_url_override_rejects_non_https() {
        let config = std::iter::once((
            "VERTEX_AI_BASE_URL".to_string(),
            "http://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-project/locations/us-central1/endpoints/openapi".to_string(),
        ))
        .collect();
        let provider = make_vertex_provider_with_config("vertex-custom-http", config);

        let err = resolve_provider_route(&provider, "gemini-pro")
            .expect_err("non-https overrides must be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("must use https"));
    }

    #[test]
    fn resolve_vertex_ai_route_base_url_override_rejects_ip_literal() {
        let config = std::iter::once((
            "VERTEX_AI_BASE_URL".to_string(),
            "https://127.0.0.1/v1beta1/projects/my-project/locations/us-central1/endpoints/openapi"
                .to_string(),
        ))
        .collect();
        let provider = make_vertex_provider_with_config("vertex-custom-ip", config);

        let err = resolve_provider_route(&provider, "gemini-pro")
            .expect_err("IP literal overrides must be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("must not use IP literal hosts"));
    }

    #[test]
    fn resolve_vertex_ai_route_gemini_model() {
        let config =
            std::iter::once(("VERTEX_AI_PROJECT_ID".to_string(), "proj-123".to_string())).collect();
        let provider = make_vertex_provider_with_config("vertex-gemini", config);

        let resolved = resolve_provider_route(&provider, "gemini-pro").expect("should resolve");

        // Gemini routes to OpenAI-compatible endpoint, not publisher endpoint
        assert!(!resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
        assert!(
            resolved.route.endpoint.contains("v1beta1"),
            "gemini should use v1beta1 endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved.route.endpoint.contains("endpoints/openapi"),
            "gemini should use openapi endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            !resolved.route.endpoint.contains("publishers/google"),
            "gemini must not embed publisher in endpoint, got: {}",
            resolved.route.endpoint
        );
        // Default region
        assert!(resolved.route.endpoint.contains("us-central1"));
        assert!(
            resolved
                .route
                .protocols
                .contains(&"openai_chat_completions".to_string()),
            "expected openai_chat_completions protocol"
        );
        assert!(
            !resolved
                .route
                .protocols
                .contains(&"anthropic_messages".to_string()),
            "must not have anthropic_messages protocol for gemini"
        );
    }

    #[test]
    fn resolve_vertex_ai_route_unknown_model_uses_openai_compat() {
        let config =
            std::iter::once(("VERTEX_AI_PROJECT_ID".to_string(), "proj-abc".to_string())).collect();
        let provider = make_vertex_provider_with_config("vertex-compat", config);

        let resolved =
            resolve_provider_route(&provider, "some-unknown-model").expect("should resolve");

        assert!(!resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
        assert!(
            resolved.route.endpoint.contains("v1beta1"),
            "unknown model should use v1beta1 endpoint"
        );
        assert!(
            resolved.route.endpoint.contains("endpoints/openapi"),
            "unknown model should use openapi endpoint"
        );
        assert!(
            resolved
                .route
                .protocols
                .contains(&"openai_chat_completions".to_string()),
            "expected openai_chat_completions protocol for unknown model"
        );
        assert!(
            !resolved
                .route
                .protocols
                .contains(&"anthropic_messages".to_string()),
            "must not have anthropic_messages for unknown model"
        );
    }

    #[test]
    fn resolve_vertex_ai_route_global_region_uses_global_host() {
        let config = [
            (
                "VERTEX_AI_PROJECT_ID".to_string(),
                "proj-global".to_string(),
            ),
            ("VERTEX_AI_REGION".to_string(), "GLOBAL".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-global", config);

        let resolved =
            resolve_provider_route(&provider, "claude-opus-4-7").expect("should resolve");

        assert_eq!(
            resolved.route.endpoint,
            "https://aiplatform.googleapis.com/v1/projects/proj-global/locations/global/publishers/anthropic/models"
        );
        assert!(resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some(":rawPredict".to_string())
        );
    }

    #[test]
    fn resolve_vertex_ai_route_us_multiregion_uses_rep_host() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-us".to_string()),
            ("VERTEX_AI_REGION".to_string(), "us".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-us", config);

        let resolved = resolve_provider_route(&provider, "gemini-pro").expect("should resolve");

        assert_eq!(
            resolved.route.endpoint,
            "https://aiplatform.us.rep.googleapis.com/v1beta1/projects/proj-us/locations/us/endpoints/openapi"
        );
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
    }

    #[test]
    fn resolve_vertex_ai_route_eu_multiregion_uses_rep_host() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-eu".to_string()),
            ("VERTEX_AI_REGION".to_string(), "eu".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-eu", config);

        let resolved = resolve_provider_route(&provider, "gemini-pro").expect("should resolve");

        assert_eq!(
            resolved.route.endpoint,
            "https://aiplatform.eu.rep.googleapis.com/v1beta1/projects/proj-eu/locations/eu/endpoints/openapi"
        );
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
    }

    #[test]
    fn resolve_vertex_ai_route_explicit_publisher_anthropic_override() {
        // Explicit VERTEX_AI_PUBLISHER=anthropic → Anthropic Messages API path
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "my-proj".to_string()),
            ("VERTEX_AI_PUBLISHER".to_string(), "anthropic".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-pub-anthropic", config);

        let resolved = resolve_provider_route(&provider, "some-model").expect("should resolve");

        assert!(resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some(":rawPredict".to_string())
        );
        assert!(
            resolved
                .route
                .endpoint
                .ends_with("/publishers/anthropic/models"),
            "expected anthropic publisher endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            !resolved.route.endpoint.contains("some-model"),
            "model must not be in endpoint"
        );
        assert!(
            resolved
                .route
                .protocols
                .contains(&"anthropic_messages".to_string()),
            "expected anthropic_messages protocol"
        );
    }

    #[test]
    fn resolve_vertex_ai_route_explicit_publisher_non_anthropic_uses_openai_compat() {
        // Explicit VERTEX_AI_PUBLISHER=google (any non-anthropic) → OpenAI-compat endpoint
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "my-proj".to_string()),
            ("VERTEX_AI_PUBLISHER".to_string(), "google".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-pub-google", config);

        let resolved = resolve_provider_route(&provider, "some-model").expect("should resolve");

        assert!(!resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some("/chat/completions".to_string())
        );
        assert!(
            resolved.route.endpoint.contains("v1beta1"),
            "non-anthropic publisher should use v1beta1 endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved.route.endpoint.contains("endpoints/openapi"),
            "non-anthropic publisher should use openapi endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            !resolved.route.endpoint.contains("publishers/google"),
            "must not embed publisher in endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved
                .route
                .protocols
                .contains(&"openai_chat_completions".to_string()),
            "expected openai_chat_completions for non-anthropic publisher"
        );
    }

    #[test]
    fn resolve_vertex_ai_route_missing_project_fails() {
        let config = std::collections::HashMap::new();
        let provider = make_vertex_provider_with_config("vertex-no-proj", config);

        let err = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022")
            .expect_err("should fail without project");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("VERTEX_AI_PROJECT_ID"));
    }

    #[test]
    fn resolve_vertex_ai_route_whitespace_only_project_fails() {
        // required_vertex_config rejects whitespace-only values via .filter(|v| !v.trim().is_empty())
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "   ".to_string()),
            ("VERTEX_AI_REGION".to_string(), "us-central1".to_string()),
        ]
        .into_iter()
        .collect();
        let result = resolve_vertex_ai_route(
            &config,
            "claude-3-5-sonnet@20241022",
            "test-route",
            "dummy-token",
            openshell_core::inference::profile_for("google-vertex-ai").unwrap(),
        );
        assert!(
            result.is_err(),
            "whitespace-only project should fail, got: {result:?}"
        );
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn resolve_vertex_ai_route_requires_minted_access_token() {
        let config =
            std::iter::once(("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string())).collect();
        let provider = Provider {
            credentials: std::iter::once((
                "GOOGLE_SERVICE_ACCOUNT_KEY".to_string(),
                "{\"type\":\"service_account\"}".to_string(),
            ))
            .collect(),
            config,
            ..make_vertex_provider_with_config(
                "vertex-bootstrap-only",
                std::collections::HashMap::new(),
            )
        };

        let err = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022")
            .expect_err("bootstrap JSON must not be treated as a bearer token");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("no usable API key credential"));
    }

    #[test]
    fn resolve_vertex_ai_route_alias_canonicalizes_provider_type() {
        let config =
            std::iter::once(("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string())).collect();
        let mut provider = make_vertex_provider_with_config("vertex-alias", config);
        provider.r#type = "vertex-ai".to_string();

        let resolved = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022")
            .expect("alias should resolve through Vertex routing");

        assert_eq!(resolved.provider_type, "google-vertex-ai");
        assert!(resolved.route.model_in_path);
        assert_eq!(
            resolved.route.request_path_override,
            Some(":rawPredict".to_string())
        );
    }

    #[test]
    fn resolve_vertex_ai_route_anthropic_protocols() {
        let config =
            std::iter::once(("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string())).collect();
        let provider = make_vertex_provider_with_config("v", config);
        let resolved = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022").unwrap();
        assert!(
            resolved
                .route
                .protocols
                .contains(&"anthropic_messages".to_string())
        );
        assert!(
            !resolved
                .route
                .protocols
                .contains(&"openai_chat_completions".to_string())
        );
        assert_eq!(
            resolved.route.protocols,
            vec!["anthropic_messages".to_string()]
        );
    }

    #[test]
    fn resolve_vertex_ai_route_openai_compat_protocols() {
        let config =
            std::iter::once(("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string())).collect();
        let provider = make_vertex_provider_with_config("v", config);
        let resolved = resolve_provider_route(&provider, "gemini-pro").unwrap();
        assert!(
            resolved
                .route
                .protocols
                .contains(&"openai_chat_completions".to_string())
        );
        assert!(
            resolved
                .route
                .protocols
                .iter()
                .all(|protocol| protocol == "openai_chat_completions")
        );
    }

    #[test]
    fn resolve_vertex_ai_route_model_not_in_endpoint() {
        // model_id must NOT appear in the endpoint URL — it travels via route.model
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string()),
            ("VERTEX_AI_REGION".to_string(), "us-east1".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("v", config);
        let resolved = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022").unwrap();
        assert!(
            !resolved.route.endpoint.contains("claude-3-5-sonnet"),
            "model_id must not be in endpoint, got: {}",
            resolved.route.endpoint
        );
        assert!(
            resolved
                .route
                .endpoint
                .ends_with("/publishers/anthropic/models")
        );
    }

    #[test]
    fn resolve_vertex_ai_route_rejects_model_ids_with_path_separators() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string()),
            ("VERTEX_AI_PUBLISHER".to_string(), "anthropic".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-bad-model", config);

        let err = resolve_provider_route(&provider, "claude/3-sonnet")
            .expect_err("path-like model IDs must be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("must not contain path separators"));
    }

    #[test]
    fn resolve_vertex_ai_route_rejects_model_ids_with_url_delimiters() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string()),
            ("VERTEX_AI_PUBLISHER".to_string(), "anthropic".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-bad-model-url", config);

        for model_id in ["claude?alt=1", "claude#fragment", "claude%2Fbad"] {
            let err = resolve_provider_route(&provider, model_id)
                .expect_err("URL delimiter-bearing model IDs must be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("must not contain URL delimiters or percent escapes"),
                "unexpected error for {model_id:?}: {}",
                err.message()
            );
        }
    }

    #[test]
    fn resolve_vertex_ai_route_accepts_versioned_claude_model_id() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string()),
            ("VERTEX_AI_PUBLISHER".to_string(), "anthropic".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-good-model", config);

        let resolved = resolve_provider_route(&provider, "claude-3-5-sonnet@20241022")
            .expect("versioned Claude model IDs must remain valid");

        assert!(resolved.route.model_in_path);
        assert_eq!(resolved.route.model, "claude-3-5-sonnet@20241022");
    }

    #[test]
    fn resolve_vertex_ai_route_rejects_model_ids_with_whitespace() {
        let config = [
            ("VERTEX_AI_PROJECT_ID".to_string(), "proj-id".to_string()),
            ("VERTEX_AI_PUBLISHER".to_string(), "anthropic".to_string()),
        ]
        .into_iter()
        .collect();
        let provider = make_vertex_provider_with_config("vertex-bad-model-whitespace", config);

        let err = resolve_provider_route(&provider, "some model")
            .expect_err("whitespace in Anthropic Vertex model IDs must be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("must not contain whitespace or control characters")
        );
    }

    #[test]
    fn validate_gcp_project_id_accepts_valid() {
        assert!(validate_gcp_project_id("my-project").is_ok());
        assert!(validate_gcp_project_id("my-project-123").is_ok());
        assert!(validate_gcp_project_id("abcdef").is_ok()); // min length 6
    }

    #[test]
    fn validate_gcp_project_id_rejects_invalid() {
        assert!(validate_gcp_project_id("").is_err()); // empty
        assert!(validate_gcp_project_id("ab").is_err()); // too short
        assert!(validate_gcp_project_id("../admin").is_err()); // path traversal
        assert!(validate_gcp_project_id("MY-PROJECT").is_err()); // uppercase
        assert!(validate_gcp_project_id("my-project-").is_err()); // trailing hyphen
        assert!(validate_gcp_project_id("1my-project").is_err()); // starts with digit
    }

    #[test]
    fn validate_gcp_region_accepts_valid() {
        assert!(validate_gcp_region("us-central1").is_ok());
        assert!(validate_gcp_region("europe-west4").is_ok());
        assert!(validate_gcp_region("global").is_ok());
        assert!(validate_gcp_region("us").is_ok());
        assert!(validate_gcp_region("eu").is_ok());
        assert!(validate_gcp_region("us-east4-a").is_ok()); // zone-like
    }

    #[test]
    fn validate_gcp_region_rejects_invalid() {
        assert!(validate_gcp_region("").is_err());
        assert!(validate_gcp_region("../../etc").is_err()); // path traversal
        assert!(validate_gcp_region("us central1").is_err()); // space
        assert!(validate_gcp_region("-us-central1").is_err()); // leading hyphen
        assert!(validate_gcp_region("us-central1-").is_err()); // trailing hyphen
    }

    // -------------------------------------------------------------------------
    // validate_vertex_base_url edge-case tests
    // -------------------------------------------------------------------------

    #[test]
    fn validate_vertex_base_url_rejects_ipv6_literal() {
        let err = validate_vertex_base_url(
            "https://[::1]/v1beta1/projects/p/locations/l/endpoints/openapi",
        )
        .expect_err("IPv6 literals must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("IP literal"),
            "expected IP literal error, got: {}",
            err.message()
        );
    }

    #[test]
    fn validate_vertex_base_url_rejects_userinfo() {
        let err =
            validate_vertex_base_url("https://user:pass@us-central1-aiplatform.googleapis.com/v1")
                .expect_err("userinfo must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("userinfo"),
            "expected userinfo error, got: {}",
            err.message()
        );
    }

    #[test]
    fn validate_vertex_base_url_rejects_query_string() {
        let err =
            validate_vertex_base_url("https://us-central1-aiplatform.googleapis.com/v1?key=val")
                .expect_err("query string must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("query or fragment"),
            "expected query/fragment error, got: {}",
            err.message()
        );
    }

    #[test]
    fn validate_vertex_base_url_rejects_fragment() {
        let err =
            validate_vertex_base_url("https://us-central1-aiplatform.googleapis.com/v1#section")
                .expect_err("fragment must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("query or fragment"),
            "expected query/fragment error, got: {}",
            err.message()
        );
    }

    #[test]
    fn validate_vertex_base_url_rejects_non_443_port() {
        let err = validate_vertex_base_url("https://us-central1-aiplatform.googleapis.com:8443/v1")
            .expect_err("non-443 port must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("443"),
            "expected port 443 error, got: {}",
            err.message()
        );
    }

    #[test]
    fn validate_vertex_model_id_rejects_double_dot_traversal() {
        // ".." without a slash should still be rejected as a path traversal segment.
        let err = validate_vertex_model_id("model..v2")
            .expect_err("double-dot traversal must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("traversal"),
            "expected path traversal error, got: {}",
            err.message()
        );
    }

    #[test]
    fn effective_route_name_defaults_empty_to_inference_local() {
        assert_eq!(
            effective_route_name("").unwrap(),
            CLUSTER_INFERENCE_ROUTE_NAME
        );
        assert_eq!(
            effective_route_name("  ").unwrap(),
            CLUSTER_INFERENCE_ROUTE_NAME
        );
        assert_eq!(
            effective_route_name("inference.local").unwrap(),
            CLUSTER_INFERENCE_ROUTE_NAME
        );
    }

    #[test]
    fn effective_route_name_accepts_sandbox_system() {
        assert_eq!(
            effective_route_name("sandbox-system").unwrap(),
            SANDBOX_SYSTEM_ROUTE_NAME
        );
    }

    #[test]
    fn effective_route_name_rejects_unknown_name() {
        let err = effective_route_name("unknown-route").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn concurrent_upsert_route_create_uses_must_create() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store.put_message(&provider).await.expect("persist");

        // Spawn two concurrent upsert calls for the same route (create path)
        let store1 = store.clone();
        let handle1 = tokio::spawn(async move {
            upsert_cluster_inference_route(
                &store1,
                CLUSTER_INFERENCE_ROUTE_NAME,
                "openai-dev",
                "gpt-4o",
                0,
                false,
            )
            .await
        });

        let store2 = store.clone();
        let handle2 = tokio::spawn(async move {
            upsert_cluster_inference_route(
                &store2,
                CLUSTER_INFERENCE_ROUTE_NAME,
                "openai-dev",
                "gpt-4.1",
                0,
                false,
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // If both tasks observe a missing route before either insert commits, MustCreate
        // should let exactly one win. If the scheduler serializes them, the second call
        // may legitimately observe the new route and take the update path.
        let successes = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
        let failures = [&result1, &result2]
            .iter()
            .filter(|r| {
                r.as_ref().is_err_and(|e| {
                    // Accept either ABORTED (from CAS) or Internal (from DB unique constraint)
                    e.code() == tonic::Code::Aborted
                        || (e.code() == tonic::Code::Internal
                            && e.message().contains("unique violation"))
                })
            })
            .count();

        assert!(
            successes == 1 || successes == 2,
            "one racing create should succeed, or both serialized upserts should succeed, got: {result1:?}, {result2:?}"
        );
        if successes == 1 {
            assert_eq!(
                failures, 1,
                "the losing racing create should fail, got: {result1:?}, {result2:?}"
            );
        } else {
            assert_eq!(
                failures, 0,
                "serialized upserts should not fail, got: {result1:?}, {result2:?}"
            );
            let mut versions = [&result1, &result2]
                .into_iter()
                .map(|result| result.as_ref().expect("success").route.version)
                .collect::<Vec<_>>();
            versions.sort_unstable();
            assert_eq!(
                versions,
                vec![1, 2],
                "serialized create-then-update should return versions 1 and 2"
            );
        }

        // Only one route should exist.
        let route = store
            .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("fetch")
            .expect("route should exist");
        let expected_version = if successes == 1 { 1 } else { 2 };
        assert_eq!(route.version, expected_version);
    }

    #[tokio::test]
    async fn concurrent_upsert_route_update_uses_cas() {
        let store = test_store().await;

        let provider = make_provider("openai-dev", "openai", "OPENAI_API_KEY", "sk-test");
        store.put_message(&provider).await.expect("persist");

        // Create initial route
        upsert_cluster_inference_route(
            &store,
            CLUSTER_INFERENCE_ROUTE_NAME,
            "openai-dev",
            "gpt-3.5",
            0,
            false,
        )
        .await
        .expect("initial create should succeed");

        // Spawn two concurrent updates
        let store1 = store.clone();
        let handle1 = tokio::spawn(async move {
            upsert_cluster_inference_route(
                &store1,
                CLUSTER_INFERENCE_ROUTE_NAME,
                "openai-dev",
                "gpt-4o",
                0,
                false,
            )
            .await
        });

        let store2 = store.clone();
        let handle2 = tokio::spawn(async move {
            upsert_cluster_inference_route(
                &store2,
                CLUSTER_INFERENCE_ROUTE_NAME,
                "openai-dev",
                "gpt-4.1",
                0,
                false,
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // One should succeed, one may fail with ABORTED due to CAS conflict
        let successes = [&result1, &result2].iter().filter(|r| r.is_ok()).count();

        assert!(
            successes >= 1,
            "at least one update should succeed, got: {result1:?}, {result2:?}"
        );

        // The route should have one of the new model values and version 2
        let route = store
            .get_message_by_name::<InferenceRoute>(CLUSTER_INFERENCE_ROUTE_NAME)
            .await
            .expect("fetch")
            .expect("route should exist");
        let config = route.config.expect("config");
        assert!(
            config.model_id == "gpt-4o" || config.model_id == "gpt-4.1",
            "model should be one of the updated values, got {}",
            config.model_id
        );
        assert_ne!(
            config.model_id, "gpt-3.5",
            "model should not be the original value"
        );
        assert!(
            route.version >= 2 && route.version <= 3,
            "version should be 2 (one update won, one conflicted) or 3 (both succeeded sequentially), got {}",
            route.version
        );
    }
}
