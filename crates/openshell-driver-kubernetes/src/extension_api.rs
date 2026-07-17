// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Discovery and availability caching for Agent Sandbox extension APIs.

use kube::core::gvk::GroupVersion;
use kube::discovery;
use kube::{Client, Error as KubeError};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::debug;

pub const EXTENSIONS_GROUP: &str = "extensions.agents.x-k8s.io";
pub const EXTENSIONS_VERSION_V1BETA1: &str = "v1beta1";
pub const SANDBOX_CLAIM_KIND: &str = "SandboxClaim";
pub const SANDBOX_TEMPLATE_KIND: &str = "SandboxTemplate";
pub const SANDBOX_WARM_POOL_KIND: &str = "SandboxWarmPool";

const EXTENSION_API_DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(30);
const EXTENSION_API_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct ExtensionApiAvailability {
    pub sandbox_claim: bool,
    pub sandbox_template: bool,
    pub sandbox_warm_pool: bool,
}

impl ExtensionApiAvailability {
    #[cfg(test)]
    pub fn all() -> Self {
        Self {
            sandbox_claim: true,
            sandbox_template: true,
            sandbox_warm_pool: true,
        }
    }

    pub fn supports_warm_allocation(self) -> bool {
        self.sandbox_claim && self.sandbox_template && self.sandbox_warm_pool
    }
}

#[derive(Debug, Clone, Copy)]
struct CachedExtensionApiAvailability {
    availability: ExtensionApiAvailability,
    discovered_at: tokio::time::Instant,
}

#[derive(Clone)]
pub struct ExtensionApiDiscoveryCache {
    state: Arc<Mutex<Option<CachedExtensionApiAvailability>>>,
    ttl: Duration,
}

impl Default for ExtensionApiDiscoveryCache {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            ttl: EXTENSION_API_DISCOVERY_CACHE_TTL,
        }
    }
}

impl ExtensionApiDiscoveryCache {
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            ttl,
        }
    }

    #[cfg(test)]
    pub fn seeded(availability: ExtensionApiAvailability) -> Self {
        Self {
            state: Arc::new(Mutex::new(Some(CachedExtensionApiAvailability {
                availability,
                discovered_at: tokio::time::Instant::now(),
            }))),
            ttl: EXTENSION_API_DISCOVERY_CACHE_TTL,
        }
    }

    pub async fn get(&self, client: &Client) -> Result<ExtensionApiAvailability, String> {
        // Hold the mutex during discovery so concurrent reconciliation, lifecycle,
        // and watch paths share one in-flight request instead of stampeding the API.
        let mut state = self.state.lock().await;
        if let Some(cached) = *state
            && cached.discovered_at.elapsed() < self.ttl
        {
            return Ok(cached.availability);
        }

        let group_version = GroupVersion::gv(EXTENSIONS_GROUP, EXTENSIONS_VERSION_V1BETA1);
        let availability = match tokio::time::timeout(
            EXTENSION_API_DISCOVERY_TIMEOUT,
            discovery::pinned_group(client, &group_version),
        )
        .await
        {
            Ok(Ok(group)) => {
                let mut availability = ExtensionApiAvailability::default();
                for (resource, _) in group.versioned_resources(EXTENSIONS_VERSION_V1BETA1) {
                    match resource.kind.as_str() {
                        SANDBOX_CLAIM_KIND => availability.sandbox_claim = true,
                        SANDBOX_TEMPLATE_KIND => availability.sandbox_template = true,
                        SANDBOX_WARM_POOL_KIND => availability.sandbox_warm_pool = true,
                        _ => {}
                    }
                }
                availability
            }
            Ok(Err(err)) if extension_api_unavailable(&err) => ExtensionApiAvailability::default(),
            Ok(Err(err)) => {
                return Err(format!(
                    "failed to discover Agent Sandbox extension APIs: {err}"
                ));
            }
            Err(_) => {
                return Err(format!(
                    "timed out after {}s discovering Agent Sandbox extension APIs",
                    EXTENSION_API_DISCOVERY_TIMEOUT.as_secs()
                ));
            }
        };

        *state = Some(CachedExtensionApiAvailability {
            availability,
            discovered_at: tokio::time::Instant::now(),
        });
        debug!(
            sandbox_claim = availability.sandbox_claim,
            sandbox_template = availability.sandbox_template,
            sandbox_warm_pool = availability.sandbox_warm_pool,
            cache_ttl_secs = self.ttl.as_secs(),
            "Discovered Agent Sandbox extension APIs"
        );
        Ok(availability)
    }

    pub async fn invalidate(&self) {
        *self.state.lock().await = None;
    }
}

pub fn extension_api_unavailable(err: &KubeError) -> bool {
    matches!(err, KubeError::Api(api) if api.code == 404)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn extension_api_resource_list() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "APIResourceList",
            "groupVersion": "extensions.agents.x-k8s.io/v1beta1",
            "resources": [
                {
                    "name": "sandboxclaims",
                    "singularName": "sandboxclaim",
                    "namespaced": true,
                    "kind": SANDBOX_CLAIM_KIND,
                    "verbs": ["create", "delete", "get", "list", "watch"]
                },
                {
                    "name": "sandboxtemplates",
                    "singularName": "sandboxtemplate",
                    "namespaced": true,
                    "kind": SANDBOX_TEMPLATE_KIND,
                    "verbs": ["create", "delete", "get", "list", "patch", "watch"]
                },
                {
                    "name": "sandboxwarmpools",
                    "singularName": "sandboxwarmpool",
                    "namespaced": true,
                    "kind": SANDBOX_WARM_POOL_KIND,
                    "verbs": ["create", "delete", "get", "list", "patch", "watch"]
                }
            ]
        })
    }

    #[tokio::test]
    async fn caches_successful_results() {
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = requests.clone();
        let service = tower::service_fn(move |_request: http::Request<kube::client::Body>| {
            let captured = captured.clone();
            async move {
                captured.fetch_add(1, Ordering::SeqCst);
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(
                            extension_api_resource_list().to_string(),
                        )))
                        .unwrap(),
                )
            }
        });
        let client = Client::new(service, "default");
        let cache = ExtensionApiDiscoveryCache::default();

        assert!(cache.get(&client).await.unwrap().supports_warm_allocation());
        assert!(cache.get(&client).await.unwrap().supports_warm_allocation());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn does_not_cache_errors() {
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = requests.clone();
        let service = tower::service_fn(move |_request: http::Request<kube::client::Body>| {
            let captured = captured.clone();
            async move {
                let request = captured.fetch_add(1, Ordering::SeqCst);
                if request == 0 {
                    let status = serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "temporary discovery failure",
                        "reason": "InternalError",
                        "code": 500
                    });
                    return Ok::<_, Infallible>(
                        http::Response::builder()
                            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from(status.to_string())))
                            .unwrap(),
                    );
                }
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(
                            extension_api_resource_list().to_string(),
                        )))
                        .unwrap(),
                )
            }
        });
        let client = Client::new(service, "default");
        let cache = ExtensionApiDiscoveryCache::default();

        assert!(cache.get(&client).await.is_err());
        assert!(cache.get(&client).await.unwrap().supports_warm_allocation());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn observes_installation_after_cached_absence_expires() {
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = requests.clone();
        let service = tower::service_fn(move |_request: http::Request<kube::client::Body>| {
            let captured = captured.clone();
            async move {
                let request = captured.fetch_add(1, Ordering::SeqCst);
                if request == 0 {
                    let status = serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "the server could not find the requested resource",
                        "reason": "NotFound",
                        "code": 404
                    });
                    return Ok::<_, Infallible>(
                        http::Response::builder()
                            .status(http::StatusCode::NOT_FOUND)
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from(status.to_string())))
                            .unwrap(),
                    );
                }
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(
                            extension_api_resource_list().to_string(),
                        )))
                        .unwrap(),
                )
            }
        });
        let client = Client::new(service, "default");
        let cache = ExtensionApiDiscoveryCache::with_ttl(Duration::ZERO);

        assert_eq!(
            cache.get(&client).await.unwrap(),
            ExtensionApiAvailability::default()
        );
        assert!(cache.get(&client).await.unwrap().supports_warm_allocation());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }
}
