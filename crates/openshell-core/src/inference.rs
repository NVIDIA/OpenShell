// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Auth header abstraction
// ---------------------------------------------------------------------------

/// How to inject an API key on outgoing inference requests.
///
/// Defined in `openshell-core` so both `openshell-router` (which applies it)
/// and `openshell-server` / `openshell-sandbox` (which resolve it from
/// provider metadata) can share the same type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthHeader {
    /// `Authorization: Bearer <key>`
    Bearer,
    /// Custom header name (e.g. `x-api-key` for Anthropic).
    Custom(&'static str),
}

// ---------------------------------------------------------------------------
// Inference provider profiles
// ---------------------------------------------------------------------------

/// Static metadata describing how to talk to a specific inference provider's API.
///
/// This is the single source of truth for provider-specific inference knowledge:
/// default endpoint, supported protocols, credential key lookup order, auth
/// header style, default headers, and allowed client-supplied passthrough
/// headers.
///
/// This is separate from [`openshell_providers::ProviderPlugin`] which handles
/// credential *discovery* (scanning env vars). `InferenceProviderProfile` handles
/// how to *use* discovered credentials to make inference API calls.
pub struct InferenceProviderProfile {
    pub provider_type: &'static str,
    pub default_base_url: &'static str,
    pub protocols: &'static [&'static str],
    /// Credential map key names to search for the API key, in priority order.
    pub credential_key_names: &'static [&'static str],
    /// Config map key names to search for a base URL override, in priority order.
    pub base_url_config_keys: &'static [&'static str],
    /// Auth header style for outgoing requests.
    pub auth: AuthHeader,
    /// Default headers injected on every outgoing request.
    pub default_headers: &'static [(&'static str, &'static str)],
    /// Client-supplied headers that may be forwarded to the upstream backend.
    ///
    /// Header names must be lowercase and must not include auth headers.
    pub passthrough_headers: &'static [&'static str],
}

const OPENAI_PROTOCOLS: &[&str] = &[
    "openai_chat_completions",
    "openai_completions",
    "openai_responses",
    "model_discovery",
];

const ANTHROPIC_PROTOCOLS: &[&str] = &["anthropic_messages", "model_discovery"];

/// Default protocol set for the Vertex AI profile. These are overridden at route
/// resolution time in `resolve_vertex_ai_route`: Anthropic models use
/// `anthropic_messages`, while Gemini and other models use the OpenAI-compatible
/// endpoint with `openai_chat_completions`. This default applies only to the
/// base-URL-override escape hatch path.
const VERTEX_AI_PROTOCOLS: &[&str] = &["anthropic_messages", "model_discovery"];

static OPENAI_PROFILE: InferenceProviderProfile = InferenceProviderProfile {
    provider_type: "openai",
    default_base_url: "https://api.openai.com/v1",
    protocols: OPENAI_PROTOCOLS,
    credential_key_names: &["OPENAI_API_KEY"],
    base_url_config_keys: &["OPENAI_BASE_URL"],
    auth: AuthHeader::Bearer,
    default_headers: &[],
    passthrough_headers: &["openai-organization", "x-model-id"],
};

static ANTHROPIC_PROFILE: InferenceProviderProfile = InferenceProviderProfile {
    provider_type: "anthropic",
    default_base_url: "https://api.anthropic.com/v1",
    protocols: ANTHROPIC_PROTOCOLS,
    credential_key_names: &["ANTHROPIC_API_KEY"],
    base_url_config_keys: &["ANTHROPIC_BASE_URL"],
    auth: AuthHeader::Custom("x-api-key"),
    default_headers: &[("anthropic-version", "2023-06-01")],
    passthrough_headers: &["anthropic-version", "anthropic-beta"],
};

/// Credential environment variable names for the Vertex AI provider, in priority order.
///
/// These are referenced by both the provider discovery logic in `openshell-providers`
/// and the inference profile here so both crates agree on which env vars hold credentials.
pub const VERTEX_AI_CREDENTIAL_KEY_NAMES: &[&str] = &[
    "GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN",
    "VERTEX_AI_SERVICE_ACCOUNT_TOKEN",
    "GOOGLE_VERTEX_AI_TOKEN",
    "VERTEX_AI_TOKEN",
];

/// The credential key used for tokens minted from gcloud Application Default Credentials.
///
/// This is the key written by the gateway's `OAuth2` refresh worker when using the
/// `--from-gcloud-adc` CLI flow. It must match `VERTEX_AI_CREDENTIAL_KEY_NAMES[2]`.
pub const VERTEX_AI_ADC_TOKEN_KEY: &str = "GOOGLE_VERTEX_AI_TOKEN";

/// GCP project ID config key for Vertex AI providers.
pub const VERTEX_AI_PROJECT_ID_KEY: &str = "VERTEX_AI_PROJECT_ID";

/// GCP region/location config key for Vertex AI providers.
pub const VERTEX_AI_REGION_KEY: &str = "VERTEX_AI_REGION";

/// Publisher override config key for Vertex AI providers.
///
/// Set to `"anthropic"` to force Anthropic Messages API routing regardless of model name,
/// or any other value to force OpenAI-compatible routing.
pub const VERTEX_AI_PUBLISHER_KEY: &str = "VERTEX_AI_PUBLISHER";

/// Config key names scanned during provider discovery, in addition to credential keys.
///
/// These are referenced by the provider discovery plugin in `openshell-providers` to
/// collect Vertex AI config from the environment during `--from-existing` flows.
pub const VERTEX_AI_CONFIG_KEY_NAMES: &[&str] = &[
    VERTEX_AI_PROJECT_ID_KEY,
    VERTEX_AI_REGION_KEY,
    "GOOGLE_VERTEX_AI_BASE_URL",
    "VERTEX_AI_BASE_URL",
    VERTEX_AI_PUBLISHER_KEY,
];

static VERTEX_AI_PROFILE: InferenceProviderProfile = InferenceProviderProfile {
    provider_type: "google-vertex-ai",
    // Base URL is project/region specific and built at route resolution time.
    default_base_url: "",
    protocols: VERTEX_AI_PROTOCOLS,
    credential_key_names: VERTEX_AI_CREDENTIAL_KEY_NAMES,
    base_url_config_keys: &["GOOGLE_VERTEX_AI_BASE_URL", "VERTEX_AI_BASE_URL"],
    auth: AuthHeader::Bearer,
    default_headers: &[],
    passthrough_headers: &[],
};

static NVIDIA_PROFILE: InferenceProviderProfile = InferenceProviderProfile {
    provider_type: "nvidia",
    default_base_url: "https://integrate.api.nvidia.com/v1",
    protocols: OPENAI_PROTOCOLS,
    credential_key_names: &["NVIDIA_API_KEY"],
    base_url_config_keys: &["NVIDIA_BASE_URL"],
    auth: AuthHeader::Bearer,
    default_headers: &[],
    passthrough_headers: &["x-model-id"],
};

/// Canonicalize an inference provider type string to a well-known identifier.
///
/// Returns `Some(canonical_name)` for recognized inference providers,
/// `None` for unrecognized inputs. This is the single source of truth for
/// Vertex AI (and other inference provider) alias resolution so that both
/// [`profile_for`] and `openshell-providers` normalization agree.
#[must_use]
pub fn normalize_inference_provider_type(input: &str) -> Option<&'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "openai" => Some("openai"),
        "anthropic" => Some("anthropic"),
        "nvidia" => Some("nvidia"),
        "google-vertex-ai" | "vertex" | "vertex-ai" | "google-vertex" | "gcp-vertex" => {
            Some("google-vertex-ai")
        }
        _ => None,
    }
}

/// Look up the inference provider profile for a given provider type.
///
/// Returns `None` for provider types that don't support inference routing
/// (e.g. `github`, `gitlab`, `outlook`).
pub fn profile_for(provider_type: &str) -> Option<&'static InferenceProviderProfile> {
    match normalize_inference_provider_type(provider_type)? {
        "openai" => Some(&OPENAI_PROFILE),
        "anthropic" => Some(&ANTHROPIC_PROFILE),
        "nvidia" => Some(&NVIDIA_PROFILE),
        "google-vertex-ai" => Some(&VERTEX_AI_PROFILE),
        _ => None,
    }
}

/// Derive the [`AuthHeader`] and default headers for a provider type string.
///
/// This is a convenience wrapper around [`profile_for`] for callers that only
/// need the auth/header information (e.g. the sandbox bundle-to-route
/// conversion).
pub fn auth_for_provider_type(provider_type: &str) -> (AuthHeader, Vec<(String, String)>) {
    let (auth, headers, _) = route_headers_for_provider_type(provider_type);
    (auth, headers)
}

/// Derive routing header policy for a provider type string.
///
/// Returns the auth injection mode, route-level default headers, and the
/// allowed client-supplied passthrough headers for `inference.local`.
pub fn route_headers_for_provider_type(
    provider_type: &str,
) -> (AuthHeader, Vec<(String, String)>, Vec<String>) {
    profile_for(provider_type).map_or_else(
        || (AuthHeader::Bearer, Vec::new(), Vec::new()),
        |profile| {
            let headers = profile
                .default_headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            let passthrough_headers = profile
                .passthrough_headers
                .iter()
                .map(|name| (*name).to_string())
                .collect();
            (profile.auth.clone(), headers, passthrough_headers)
        },
    )
}

/// Derive routing header policy for a specific resolved route.
///
/// Most providers only need their provider type. Vertex AI is special because
/// Claude routes should forward `anthropic-beta`, while Gemini/OpenAI-compatible
/// routes should not inherit Anthropic passthrough headers.
pub fn route_headers_for_route(
    provider_type: &str,
    protocols: &[String],
) -> (AuthHeader, Vec<(String, String)>, Vec<String>) {
    let (auth, headers, mut passthrough_headers) = route_headers_for_provider_type(provider_type);
    if profile_for(provider_type).is_some_and(|profile| profile.provider_type == "google-vertex-ai")
    {
        let is_vertex_anthropic = protocols
            .iter()
            .any(|protocol| protocol == "anthropic_messages");
        if is_vertex_anthropic && !passthrough_headers.iter().any(|h| h == "anthropic-beta") {
            passthrough_headers.push("anthropic-beta".to_string());
        }
    }
    (auth, headers, passthrough_headers)
}

// ---------------------------------------------------------------------------
// Protocol normalization
// ---------------------------------------------------------------------------

/// Normalize a list of protocol strings: trim, lowercase, deduplicate, skip empty.
pub fn normalize_protocols(protocols: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for protocol in protocols {
        let candidate = protocol.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            continue;
        }
        if seen.insert(candidate.clone()) {
            normalized.push(candidate);
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_deduplicates() {
        let input = vec![
            "OpenAI_Chat_Completions".to_string(),
            " openai_chat_completions ".to_string(),
            "anthropic_messages".to_string(),
        ];
        let result = normalize_protocols(&input);
        assert_eq!(
            result,
            vec!["openai_chat_completions", "anthropic_messages"]
        );
    }

    #[test]
    fn skips_empty_and_whitespace() {
        let input = vec![String::new(), "  ".to_string(), "valid".to_string()];
        let result = normalize_protocols(&input);
        assert_eq!(result, vec!["valid"]);
    }

    #[test]
    fn empty_input() {
        let result = normalize_protocols(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn profile_for_known_types() {
        assert!(profile_for("openai").is_some());
        assert!(profile_for("anthropic").is_some());
        assert!(profile_for("nvidia").is_some());
        assert!(profile_for("OpenAI").is_some()); // case insensitive
    }

    #[test]
    fn profile_for_unknown_types() {
        assert!(profile_for("github").is_none());
        assert!(profile_for("gitlab").is_none());
        assert!(profile_for("unknown").is_none());
    }

    #[test]
    fn auth_for_anthropic_uses_custom_header() {
        let (auth, headers) = auth_for_provider_type("anthropic");
        assert_eq!(auth, AuthHeader::Custom("x-api-key"));
        assert!(headers.iter().any(|(k, _)| k == "anthropic-version"));
    }

    #[test]
    fn route_headers_for_openai_include_passthrough_headers() {
        let (_, _, passthrough_headers) = route_headers_for_provider_type("openai");
        assert!(
            passthrough_headers
                .iter()
                .any(|name| name == "openai-organization")
        );
        assert!(passthrough_headers.iter().any(|name| name == "x-model-id"));
    }

    #[test]
    fn route_headers_for_anthropic_include_passthrough_headers() {
        let (_, _, passthrough_headers) = route_headers_for_provider_type("anthropic");
        assert!(
            passthrough_headers
                .iter()
                .any(|name| name == "anthropic-version")
        );
        assert!(
            passthrough_headers
                .iter()
                .any(|name| name == "anthropic-beta")
        );
    }

    #[test]
    fn auth_for_openai_uses_bearer() {
        let (auth, headers) = auth_for_provider_type("openai");
        assert_eq!(auth, AuthHeader::Bearer);
        assert!(headers.is_empty());
    }

    #[test]
    fn profile_for_vertex_types() {
        for key in &["google-vertex-ai", "vertex", "vertex-ai"] {
            let profile = profile_for(key).expect("vertex profile should be Some");
            assert_eq!(profile.provider_type, "google-vertex-ai");
        }
    }

    #[test]
    fn auth_for_vertex_uses_bearer() {
        let (auth, headers) = auth_for_provider_type("google-vertex-ai");
        assert_eq!(auth, AuthHeader::Bearer);
        assert!(headers.is_empty());
    }

    #[test]
    fn route_headers_for_vertex_anthropic_route_forward_beta_only() {
        let (_, headers, passthrough_headers) =
            route_headers_for_route("google-vertex-ai", &["anthropic_messages".to_string()]);
        assert!(headers.is_empty());
        assert_eq!(passthrough_headers, vec!["anthropic-beta".to_string()]);
    }

    #[test]
    fn route_headers_for_vertex_openai_route_do_not_forward_anthropic_headers() {
        let (_, headers, passthrough_headers) =
            route_headers_for_route("google-vertex-ai", &["openai_chat_completions".to_string()]);
        assert!(headers.is_empty());
        assert!(passthrough_headers.is_empty());
    }

    #[test]
    fn auth_for_unknown_defaults_to_bearer() {
        let (auth, headers) = auth_for_provider_type("unknown");
        assert_eq!(auth, AuthHeader::Bearer);
        assert!(headers.is_empty());
    }

    #[test]
    fn route_headers_for_unknown_are_empty() {
        let (auth, headers, passthrough_headers) = route_headers_for_provider_type("unknown");
        assert_eq!(auth, AuthHeader::Bearer);
        assert!(headers.is_empty());
        assert!(passthrough_headers.is_empty());
    }
}
