// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inference route bundle resolution and refresh.
//!
//! Resolves inference routes from one of two sources at sandbox startup:
//! a local YAML file (`--inference-routes`) or a cluster bundle fetched via
//! gRPC. Builds the [`InferenceContext`] consumed by the proxy's L7 layer
//! and spawns a background refresh loop in cluster mode so route changes
//! propagate without restarting the sandbox.
//!
//! Distinct from [`crate::l7::inference`], which parses HTTP requests and
//! matches them against API patterns at request time.
//!
//! [`InferenceContext`]: crate::proxy::InferenceContext

use std::sync::Arc;
use std::time::Duration;

use miette::Result;
use tracing::{info, trace, warn};

use openshell_ocsf::{
    ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};

/// Default interval (seconds) for re-fetching the inference route bundle from
/// the gateway in cluster mode.
///
/// Override at runtime with the `OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS`
/// environment variable. File-based routes (`--inference-routes`) are loaded
/// once at startup and never refreshed.
pub const DEFAULT_ROUTE_REFRESH_INTERVAL_SECS: u64 = 5;

/// Route name for the sandbox system inference route.
const SANDBOX_SYSTEM_ROUTE_NAME: &str = "sandbox-system";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceRouteSource {
    File,
    Cluster,
    None,
}

pub fn infer_route_source(
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> InferenceRouteSource {
    if inference_routes.is_some() {
        InferenceRouteSource::File
    } else if sandbox_id.is_some() && openshell_endpoint.is_some() {
        InferenceRouteSource::Cluster
    } else {
        InferenceRouteSource::None
    }
}

pub fn disable_inference_on_empty_routes(source: InferenceRouteSource) -> bool {
    !matches!(source, InferenceRouteSource::Cluster)
}

pub fn route_refresh_interval_secs() -> u64 {
    let Ok(value) = std::env::var("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS") else {
        return DEFAULT_ROUTE_REFRESH_INTERVAL_SECS;
    };
    match value.parse::<u64>() {
        Ok(interval) if interval > 0 => interval,
        Ok(_) => {
            warn!(
                default_interval_secs = DEFAULT_ROUTE_REFRESH_INTERVAL_SECS,
                "Ignoring zero route refresh interval"
            );
            DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
        }
        Err(error) => {
            warn!(
                interval = %value,
                error = %error,
                default_interval_secs = DEFAULT_ROUTE_REFRESH_INTERVAL_SECS,
                "Ignoring invalid route refresh interval"
            );
            DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
        }
    }
}

/// Build an [`InferenceContext`](crate::proxy::InferenceContext) by resolving
/// inference routes from either a local YAML file or the gateway bundle.
///
/// If both a routes file and cluster credentials are provided, the routes file
/// wins and the cluster bundle is not fetched.
///
/// Returns `None` if neither source is configured (inference routing disabled).
///
/// # Errors
///
/// Returns an error if loading the routes file fails or the file's routes
/// cannot be resolved. gRPC errors are swallowed (logged) and produce
/// `Ok(None)` so a missing cluster bundle disables inference routing rather
/// than aborting sandbox startup.
// `routes`/`router` are intentionally distinct nouns (the route list vs the
// router that consumes them); both names are clearer than alternatives.
#[allow(clippy::similar_names)]
pub async fn build_inference_context(
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> Result<Option<Arc<crate::proxy::InferenceContext>>> {
    use openshell_router::Router;
    use openshell_router::config::RouterConfig;

    let source = infer_route_source(sandbox_id, openshell_endpoint, inference_routes);

    // Captured during the initial cluster bundle fetch so the background refresh
    // loop can skip no-op updates from the very first tick.
    let mut initial_revision: Option<String> = None;

    let routes = match source {
        InferenceRouteSource::File => {
            let Some(path) = inference_routes else {
                return Ok(None);
            };

            // Standalone mode: load routes from file (fail-fast on errors)
            if sandbox_id.is_some() {
                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped("inference_routes", serde_json::json!(path))
                    .message(format!(
                        "Inference routes file takes precedence over cluster bundle [path:{path}]"
                    ))
                    .build());
            }
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Other, "loading")
                    .unmapped("inference_routes", serde_json::json!(path))
                    .message(format!("Loading inference routes from file [path:{path}]"))
                    .build()
            );
            let config = RouterConfig::load_from_file(std::path::Path::new(path))
                .map_err(|e| miette::miette!("failed to load inference routes {path}: {e}"))?;
            config
                .resolve_routes()
                .map_err(|e| miette::miette!("failed to resolve routes from {path}: {e}"))?
        }
        InferenceRouteSource::Cluster => {
            let (Some(_id), Some(endpoint)) = (sandbox_id, openshell_endpoint) else {
                return Ok(None);
            };

            // Cluster mode: fetch bundle from gateway
            info!(endpoint = %endpoint, "Fetching inference route bundle from gateway");
            match openshell_core::grpc_client::fetch_inference_bundle(endpoint).await {
                Ok(bundle) => {
                    initial_revision = Some(bundle.revision.clone());
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped("route_count", serde_json::json!(bundle.routes.len()))
                            .unmapped("revision", serde_json::json!(&bundle.revision))
                            .message(format!(
                                "Loaded inference route bundle [route_count:{} revision:{}]",
                                bundle.routes.len(),
                                bundle.revision
                            ))
                            .build()
                    );
                    bundle_to_resolved_routes(&bundle)
                }
                Err(e) => {
                    // Distinguish expected "not configured" states from server errors.
                    // gRPC PermissionDenied/NotFound means inference bundle is unavailable
                    // for this sandbox — skip gracefully. Other errors are unexpected.
                    let msg = e.to_string();
                    if msg.contains("permission denied") || msg.contains("not found") {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Disabled, "disabled")
                                .unmapped("error", serde_json::json!(e.to_string()))
                                .message(format!(
                                    "Inference bundle unavailable, routing disabled [error:{e}]"
                                ))
                                .build()
                        );
                        return Ok(None);
                    }
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Disabled, "disabled")
                        .unmapped("error", serde_json::json!(e.to_string()))
                        .message(format!(
                            "Failed to fetch inference bundle, inference routing disabled [error:{e}]"
                        ))
                        .build());
                    return Ok(None);
                }
            }
        }
        InferenceRouteSource::None => {
            // No route source — inference routing is not configured
            return Ok(None);
        }
    };

    if routes.is_empty() && disable_inference_on_empty_routes(source) {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Disabled, "disabled")
                .message("No usable inference routes, inference routing disabled")
                .build()
        );
        return Ok(None);
    }

    if routes.is_empty() {
        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "waiting")
            .message("Inference route bundle is empty; keeping routing enabled and waiting for refresh")
            .build());
    }

    ocsf_emit!(
        ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "enabled")
            .unmapped("route_count", serde_json::json!(routes.len()))
            .message(format!(
                "Inference routing enabled with local execution [route_count:{}]",
                routes.len()
            ))
            .build()
    );

    // Partition routes by name into user-facing and system caches.
    let (user_routes, system_routes) = partition_routes(routes);

    let router =
        Router::new().map_err(|e| miette::miette!("failed to initialize inference router: {e}"))?;
    let patterns = crate::l7::inference::default_patterns();

    let ctx = Arc::new(crate::proxy::InferenceContext::new(
        patterns,
        router,
        user_routes,
        system_routes,
    ));

    // Spawn background route cache refresh for cluster mode at startup so
    // request handling never depends on control-plane latency.
    if matches!(source, InferenceRouteSource::Cluster)
        && let (Some(_id), Some(endpoint)) = (sandbox_id, openshell_endpoint)
    {
        spawn_route_refresh(
            ctx.route_cache(),
            ctx.system_route_cache(),
            endpoint.to_string(),
            route_refresh_interval_secs(),
            initial_revision,
        );
    }

    Ok(Some(ctx))
}

/// Split resolved routes into user-facing and system caches by route name.
///
/// Routes named `"sandbox-system"` go to the system cache; everything else
/// (including `"inference.local"` and empty names) goes to the user cache.
pub fn partition_routes(
    routes: Vec<openshell_router::config::ResolvedRoute>,
) -> (
    Vec<openshell_router::config::ResolvedRoute>,
    Vec<openshell_router::config::ResolvedRoute>,
) {
    let mut user = Vec::new();
    let mut system = Vec::new();
    for r in routes {
        if r.name == SANDBOX_SYSTEM_ROUTE_NAME {
            system.push(r);
        } else {
            user.push(r);
        }
    }
    (user, system)
}

/// Convert a proto bundle response into resolved routes for the router.
pub fn bundle_to_resolved_routes(
    bundle: &openshell_core::proto::GetInferenceBundleResponse,
) -> Vec<openshell_router::config::ResolvedRoute> {
    bundle
        .routes
        .iter()
        .map(|r| {
            let (auth, default_headers, passthrough_headers) =
                openshell_core::inference::route_headers_for_provider_type(&r.provider_type);
            let timeout = if r.timeout_secs == 0 {
                openshell_router::config::DEFAULT_ROUTE_TIMEOUT
            } else {
                Duration::from_secs(r.timeout_secs)
            };
            openshell_router::config::ResolvedRoute {
                name: r.name.clone(),
                endpoint: r.base_url.clone(),
                model: r.model_id.clone(),
                api_key: r.api_key.clone(),
                protocols: r.protocols.clone(),
                auth,
                default_headers,
                passthrough_headers,
                timeout,
                model_in_path: r.model_in_path,
                request_path_override: r.request_path_override.clone(),
            }
        })
        .collect()
}

/// Spawn a background task that periodically refreshes both route caches from the gateway.
///
/// The loop uses the bundle `revision` hash to avoid unnecessary cache writes
/// when routes haven't changed. `initial_revision` is the revision captured
/// during the startup fetch in [`build_inference_context`] so the first refresh
/// cycle can already skip a no-op update.
pub fn spawn_route_refresh(
    user_cache: Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>>,
    system_cache: Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>>,
    endpoint: String,
    interval_secs: u64,
    initial_revision: Option<String>,
) {
    tokio::spawn(async move {
        use tokio::time::{MissedTickBehavior, interval};

        let mut current_revision = initial_revision;

        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tick.tick().await;

            match openshell_core::grpc_client::fetch_inference_bundle(&endpoint).await {
                Ok(bundle) => {
                    if current_revision.as_deref() == Some(&bundle.revision) {
                        trace!(revision = %bundle.revision, "Inference bundle unchanged");
                        continue;
                    }

                    let routes = bundle_to_resolved_routes(&bundle);
                    let (user_routes, system_routes) = partition_routes(routes);
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "updated")
                        .unmapped("user_route_count", serde_json::json!(user_routes.len()))
                        .unmapped("system_route_count", serde_json::json!(system_routes.len()))
                        .unmapped("revision", serde_json::json!(&bundle.revision))
                        .message(format!(
                            "Inference routes updated [user_route_count:{} system_route_count:{} revision:{}]",
                            user_routes.len(),
                            system_routes.len(),
                            bundle.revision
                        ))
                        .build());
                    current_revision = Some(bundle.revision);
                    *user_cache.write().await = user_routes;
                    *system_cache.write().await = system_routes;
                }
                Err(e) => {
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "stale")
                        .unmapped("error", serde_json::json!(e.to_string()))
                        .message(format!(
                            "Failed to refresh inference route cache, keeping stale routes [error:{e}]"
                        ))
                        .build());
                }
            }
        }
    });
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::similar_names,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex};
    use temp_env::with_vars;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn bundle_to_resolved_routes_converts_all_fields() {
        let bundle = openshell_core::proto::GetInferenceBundleResponse {
            routes: vec![
                openshell_core::proto::ResolvedRoute {
                    name: "frontier".to_string(),
                    base_url: "https://api.example.com/v1".to_string(),
                    api_key: "sk-test-key".to_string(),
                    model_id: "gpt-4".to_string(),
                    protocols: vec![
                        "openai_chat_completions".to_string(),
                        "openai_responses".to_string(),
                    ],
                    provider_type: "openai".to_string(),
                    timeout_secs: 0,
                    model_in_path: false,
                    request_path_override: None,
                },
                openshell_core::proto::ResolvedRoute {
                    name: "local".to_string(),
                    base_url: "http://vllm:8000/v1".to_string(),
                    api_key: "local-key".to_string(),
                    model_id: "llama-3".to_string(),
                    protocols: vec!["openai_chat_completions".to_string()],
                    provider_type: String::new(),
                    timeout_secs: 120,
                    model_in_path: false,
                    request_path_override: None,
                },
            ],
            revision: "abc123".to_string(),
            generated_at_ms: 1000,
        };

        let routes = bundle_to_resolved_routes(&bundle);

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].endpoint, "https://api.example.com/v1");
        assert_eq!(routes[0].model, "gpt-4");
        assert_eq!(routes[0].api_key, "sk-test-key");
        assert_eq!(
            routes[0].auth,
            openshell_core::inference::AuthHeader::Bearer
        );
        assert_eq!(
            routes[0].protocols,
            vec!["openai_chat_completions", "openai_responses"]
        );
        assert_eq!(
            routes[0].timeout,
            openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
            "timeout_secs=0 should map to default"
        );
        assert_eq!(routes[1].endpoint, "http://vllm:8000/v1");
        assert_eq!(
            routes[1].auth,
            openshell_core::inference::AuthHeader::Bearer
        );
        assert_eq!(
            routes[1].timeout,
            Duration::from_secs(120),
            "timeout_secs=120 should map to 120s"
        );
    }

    #[test]
    fn bundle_to_resolved_routes_handles_empty_bundle() {
        let bundle = openshell_core::proto::GetInferenceBundleResponse {
            routes: vec![],
            revision: "empty".to_string(),
            generated_at_ms: 0,
        };

        let routes = bundle_to_resolved_routes(&bundle);
        assert!(routes.is_empty());
    }

    #[test]
    fn bundle_to_resolved_routes_preserves_name_field() {
        let bundle = openshell_core::proto::GetInferenceBundleResponse {
            routes: vec![openshell_core::proto::ResolvedRoute {
                name: "sandbox-system".to_string(),
                base_url: "https://api.example.com/v1".to_string(),
                api_key: "key".to_string(),
                model_id: "model".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                provider_type: "openai".to_string(),
                timeout_secs: 0,
                model_in_path: false,
                request_path_override: None,
            }],
            revision: "rev".to_string(),
            generated_at_ms: 0,
        };

        let routes = bundle_to_resolved_routes(&bundle);
        assert_eq!(routes[0].name, "sandbox-system");
    }

    #[test]
    fn routes_segregated_by_name() {
        let routes = vec![
            openshell_router::config::ResolvedRoute {
                name: "inference.local".to_string(),
                endpoint: "https://api.openai.com/v1".to_string(),
                model: "gpt-4o".to_string(),
                api_key: "key1".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                auth: openshell_core::inference::AuthHeader::Bearer,
                default_headers: vec![],
                passthrough_headers: vec![],
                timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
                model_in_path: false,
                request_path_override: None,
            },
            openshell_router::config::ResolvedRoute {
                name: "sandbox-system".to_string(),
                endpoint: "https://api.anthropic.com/v1".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                api_key: "key2".to_string(),
                protocols: vec!["anthropic_messages".to_string()],
                auth: openshell_core::inference::AuthHeader::Custom("x-api-key"),
                default_headers: vec![],
                passthrough_headers: vec![],
                timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
                model_in_path: false,
                request_path_override: None,
            },
        ];

        let (user, system) = partition_routes(routes);
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].name, "inference.local");
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].name, "sandbox-system");
    }

    // -- build_inference_context tests --

    #[tokio::test]
    async fn build_inference_context_route_file_loads_routes() {
        use std::io::Write;

        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:8000/v1
    model: llama-3
    protocols: [openai_chat_completions]
    api_key: test-key
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap();

        let ctx = build_inference_context(None, None, Some(path))
            .await
            .expect("should load routes from file");

        let ctx = ctx.expect("context should be Some");
        let cache = ctx.route_cache();
        let routes = cache.read().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].endpoint, "http://localhost:8000/v1");
    }

    #[tokio::test]
    async fn build_inference_context_empty_route_file_returns_none() {
        use std::io::Write;

        // Route file with empty routes list → inference routing disabled (not an error)
        let yaml = "routes: []\n";
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap();

        let ctx = build_inference_context(None, None, Some(path))
            .await
            .expect("empty routes file should not error");
        assert!(
            ctx.is_none(),
            "empty routes should disable inference routing"
        );
    }

    #[tokio::test]
    async fn build_inference_context_no_sources_returns_none() {
        let ctx = build_inference_context(None, None, None)
            .await
            .expect("should succeed with None");

        assert!(ctx.is_none(), "no sources should return None");
    }

    #[tokio::test]
    async fn build_inference_context_route_file_overrides_cluster() {
        use std::io::Write;

        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:9999/v1
    model: file-model
    protocols: [openai_chat_completions]
    api_key: file-key
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap();

        // Even with sandbox_id and endpoint, route_file takes precedence
        let ctx = build_inference_context(Some("sb-1"), Some("http://localhost:50051"), Some(path))
            .await
            .expect("should load from file");

        let ctx = ctx.expect("context should be Some");
        let cache = ctx.route_cache();
        let routes = cache.read().await;
        assert_eq!(routes[0].endpoint, "http://localhost:9999/v1");
    }

    #[test]
    fn infer_route_source_prefers_file_mode() {
        assert_eq!(
            infer_route_source(
                Some("sb-1"),
                Some("http://localhost:50051"),
                Some("routes.yaml")
            ),
            InferenceRouteSource::File
        );
    }

    #[test]
    fn infer_route_source_cluster_requires_id_and_endpoint() {
        assert_eq!(
            infer_route_source(Some("sb-1"), Some("http://localhost:50051"), None),
            InferenceRouteSource::Cluster
        );
        assert_eq!(
            infer_route_source(Some("sb-1"), None, None),
            InferenceRouteSource::None
        );
        assert_eq!(
            infer_route_source(None, Some("http://localhost:50051"), None),
            InferenceRouteSource::None
        );
    }

    #[test]
    fn disable_inference_on_empty_routes_depends_on_source() {
        assert!(disable_inference_on_empty_routes(
            InferenceRouteSource::File
        ));
        assert!(!disable_inference_on_empty_routes(
            InferenceRouteSource::Cluster
        ));
        assert!(disable_inference_on_empty_routes(
            InferenceRouteSource::None
        ));
    }

    // ---- Route refresh interval + revision tests ----

    #[test]
    fn default_route_refresh_interval_is_five_seconds() {
        assert_eq!(DEFAULT_ROUTE_REFRESH_INTERVAL_SECS, 5);
    }

    #[test]
    fn route_refresh_interval_uses_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_vars(
            [("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS", Some("9"))],
            || {
                assert_eq!(route_refresh_interval_secs(), 9);
            },
        );
    }

    #[test]
    fn route_refresh_interval_rejects_zero() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_vars(
            [("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS", Some("0"))],
            || {
                assert_eq!(
                    route_refresh_interval_secs(),
                    DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
                );
            },
        );
    }

    #[test]
    fn route_refresh_interval_rejects_invalid_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_vars(
            [("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS", Some("abc"))],
            || {
                assert_eq!(
                    route_refresh_interval_secs(),
                    DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
                );
            },
        );
    }

    #[tokio::test]
    async fn route_cache_preserves_content_when_not_written() {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let routes = vec![openshell_router::config::ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "http://original:8000/v1".to_string(),
            model: "original-model".to_string(),
            api_key: "key".to_string(),
            auth: openshell_core::inference::AuthHeader::Bearer,
            protocols: vec!["openai_chat_completions".to_string()],
            default_headers: vec![],
            passthrough_headers: vec![],
            timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
        }];

        let cache = Arc::new(RwLock::new(routes));

        // Verify the cache preserves its content — the revision-based skip
        // logic in spawn_route_refresh ensures the cache is only written
        // when the revision actually changes.
        let read = cache.read().await;
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].model, "original-model");
    }
}
