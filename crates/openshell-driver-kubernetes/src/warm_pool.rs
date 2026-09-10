// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes warm-pool allocation and template reconciliation.

// The module is private, while selected items form its crate-internal interface
// with the driver and its existing tests.
#![allow(clippy::redundant_pub_crate)]

use crate::config::{KubernetesComputeConfig, OperatorNamespaceAllowlist, WorkspaceMode};
use crate::driver::{
    KUBE_API_TIMEOUT, KubernetesDriverError, MAX_KUBE_NAME_LEN, SandboxPodParams,
    annotation_or_label, condition_from_value, is_openshell_managed, kube_error_code,
    log_extension_api_permission_error, resolve_sandbox_identity_for_config, sandbox_annotations,
    sandbox_id_from_object, sandbox_labels, sandbox_to_k8s_spec, validate_kubernetes_dns1123_label,
    validate_sidecar_proxy_identity, watcher_error_code,
};
use crate::extension_api::{
    EXTENSIONS_GROUP, EXTENSIONS_VERSION_V1BETA1, ExtensionApiDiscoveryCache, SANDBOX_CLAIM_KIND,
    SANDBOX_TEMPLATE_KIND, SANDBOX_WARM_POOL_KIND, extension_api_unavailable,
};
use futures::{Stream, StreamExt, TryStreamExt};
use kube::api::{Api, ApiResource, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_utils::{
    LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_WORKSPACE,
};
use openshell_core::proto::compute::v1::{
    DriverSandbox as Sandbox, DriverSandboxSpec as SandboxSpec,
    DriverSandboxStatus as SandboxStatus, DriverSandboxTemplateRef, DriverSandboxTemplateResource,
    DriverSandboxTemplateStartup,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

struct ExtensionApi {
    api: Api<DynamicObject>,
    resource: ApiResource,
}

pub(super) fn extension_resource(kind: &str) -> ApiResource {
    let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, EXTENSIONS_VERSION_V1BETA1, kind);
    ApiResource::from_gvk(&gvk)
}

fn namespaced_extension_api(client: Client, namespace: &str, kind: &str) -> ExtensionApi {
    let resource = extension_resource(kind);
    let api = Api::namespaced_with(client, namespace, &resource);
    ExtensionApi { api, resource }
}

fn all_extension_api(client: Client, kind: &str) -> ExtensionApi {
    let resource = extension_resource(kind);
    let api = Api::all_with(client, &resource);
    ExtensionApi { api, resource }
}

fn sandbox_claim_api(client: Client, namespace: &str) -> ExtensionApi {
    namespaced_extension_api(client, namespace, SANDBOX_CLAIM_KIND)
}

fn sandbox_claim_api_all(client: Client) -> ExtensionApi {
    all_extension_api(client, SANDBOX_CLAIM_KIND)
}

fn sandbox_warm_pool_api(client: Client, namespace: &str) -> ExtensionApi {
    namespaced_extension_api(client, namespace, SANDBOX_WARM_POOL_KIND)
}

fn sandbox_warm_pool_api_all(client: Client) -> ExtensionApi {
    all_extension_api(client, SANDBOX_WARM_POOL_KIND)
}

fn sandbox_template_api(client: Client, namespace: &str) -> ExtensionApi {
    namespaced_extension_api(client, namespace, SANDBOX_TEMPLATE_KIND)
}

fn sandbox_template_api_all(client: Client) -> ExtensionApi {
    all_extension_api(client, SANDBOX_TEMPLATE_KIND)
}

/// Whether this driver instance has a gateway-side controller capable of
/// completing a pending warm supervisor registration.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WarmActivationSupport {
    Available,
    Unavailable,
}

/// Driver-local façade for warm-pool state and controller lifecycle.
///
/// Claim inventory deliberately remains available when allocation is disabled,
/// so this component is always present on a Kubernetes driver instance.
#[derive(Clone)]
pub(super) struct WarmPoolManager {
    pub(super) cache: WarmPoolCache,
    pub(super) discovery: ExtensionApiDiscoveryCache,
    pub(super) activation_support: WarmActivationSupport,
}

impl WarmPoolManager {
    async fn list_claim_objects(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        params: &ListParams,
        operation: &'static str,
    ) -> Result<Vec<DynamicObject>, String> {
        let availability = self.extension_api_availability(client).await?;
        if !availability.sandbox_claim {
            return Ok(Vec::new());
        }

        let claim_api = if config.is_multi_namespace() {
            sandbox_claim_api_all(client.clone())
        } else {
            sandbox_claim_api(client.clone(), &config.namespace)
        };
        match tokio::time::timeout(KUBE_API_TIMEOUT, claim_api.api.list(params)).await {
            Ok(Ok(list)) => Ok(list.items),
            Ok(Err(err)) if extension_api_unavailable(&err) => {
                self.discovery.invalidate().await;
                Ok(Vec::new())
            }
            Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
                let scope = if config.is_multi_namespace() {
                    "cluster-wide"
                } else {
                    config.namespace.as_str()
                };
                Err(log_extension_api_permission_error(
                    SANDBOX_CLAIM_KIND,
                    operation,
                    scope,
                    &err,
                ))
            }
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    pub(super) async fn list_claims(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        selector: &str,
    ) -> Result<Vec<Sandbox>, String> {
        let objects = self
            .list_claim_objects(
                client,
                config,
                &ListParams::default().labels(selector),
                "list",
            )
            .await?;
        Ok(objects
            .into_iter()
            .filter_map(|obj| sandbox_from_claim_object(&config.namespace, obj).ok())
            .collect())
    }

    pub(super) async fn get_claim(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        selector: &str,
    ) -> Result<Option<Sandbox>, String> {
        let objects = self
            .list_claim_objects(
                client,
                config,
                &ListParams::default().labels(selector),
                "get",
            )
            .await?;
        Ok(objects
            .into_iter()
            .find_map(|obj| sandbox_from_claim_object(&config.namespace, obj).ok()))
    }

    pub(super) async fn delete_claim(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        sandbox_id: &str,
        selector: &str,
    ) -> Result<bool, String> {
        let objects = self
            .list_claim_objects(
                client,
                config,
                &ListParams::default().labels(selector),
                "list for delete",
            )
            .await?;
        let Some(obj) = objects.into_iter().next() else {
            return Ok(false);
        };
        let Some(claim_name) = obj.metadata.name.clone() else {
            return Ok(false);
        };
        let claim_namespace = obj
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| config.namespace.clone());
        let preconditions = kube::api::Preconditions {
            uid: obj.metadata.uid,
            resource_version: obj.metadata.resource_version,
        };
        let claim_api = sandbox_claim_api(client.clone(), &claim_namespace);
        let params = DeleteParams::default().preconditions(preconditions);
        match tokio::time::timeout(KUBE_API_TIMEOUT, claim_api.api.delete(&claim_name, &params))
            .await
        {
            Ok(Ok(_)) => {
                info!(
                    sandbox_id,
                    namespace = %claim_namespace,
                    sandbox_claim = %claim_name,
                    "SandboxClaim deleted from Kubernetes"
                );
                Ok(true)
            }
            Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(false),
            Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
                Err(log_extension_api_permission_error(
                    SANDBOX_CLAIM_KIND,
                    "delete",
                    &claim_namespace,
                    &err,
                ))
            }
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    async fn reconcile_template(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        operator_allowlist: Option<&OperatorNamespaceAllowlist>,
        template: &DriverSandboxTemplateResource,
    ) -> Result<(), KubernetesDriverError> {
        let maybe_rendered =
            render_warm_pool_template(client.clone(), config, operator_allowlist, template)
                .await
                .map_err(KubernetesDriverError::InvalidArgument)?;
        let Some(rendered) = maybe_rendered else {
            garbage_collect_warm_pool_template(
                client.clone(),
                config,
                operator_allowlist,
                &template.id,
                &template.workspace,
            )
            .await
            .map_err(KubernetesDriverError::Message)?;
            return Ok(());
        };
        apply_rendered_warm_pool_template(client.clone(), &rendered)
            .await
            .map_err(KubernetesDriverError::Message)?;
        garbage_collect_superseded_warm_pool_template_resources(client.clone(), &rendered)
            .await
            .map_err(KubernetesDriverError::Message)?;
        info!(
            template_id = %rendered.source.id,
            template_name = %rendered.source.name,
            workspace = %rendered.source.workspace,
            namespace = %rendered.target_namespace,
            warm_pool = %rendered.generated_name,
            replicas = rendered.replicas,
            "Reconciled sandbox template warm pool"
        );
        Ok(())
    }

    pub(super) async fn reconcile_templates(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        operator_allowlist: Option<&OperatorNamespaceAllowlist>,
        templates: &[DriverSandboxTemplateResource],
    ) -> Result<(u32, u32), KubernetesDriverError> {
        let availability = self
            .extension_api_availability(client)
            .await
            .map_err(KubernetesDriverError::Unavailable)?;
        if !availability.sandbox_template || !availability.sandbox_warm_pool {
            debug!(
                sandbox_template = availability.sandbox_template,
                sandbox_warm_pool = availability.sandbox_warm_pool,
                "Skipping sandbox template reconciliation because the required Agent Sandbox extension APIs are absent"
            );
            return Ok((0, 0));
        }

        if matches!(config.workspace_mode, WorkspaceMode::Operator) {
            let allowlist = operator_allowlist.ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "operator mode requires a namespace allowlist".to_string(),
                )
            })?;
            tokio::time::timeout(
                KUBE_API_TIMEOUT,
                allowlist.wait_until_initially_synced(),
            )
            .await
            .map_err(|_| {
                KubernetesDriverError::Unavailable(format!(
                    "operator namespace allowlist did not complete its initial synchronization within {}s; deferring warm-pool reconciliation",
                    KUBE_API_TIMEOUT.as_secs()
                ))
            })?;
        }

        let mut desired_ids = HashSet::with_capacity(templates.len());
        let mut reconciled = 0usize;
        if self.allocation_enabled(config) && availability.supports_warm_allocation() {
            for template in templates {
                match self
                    .reconcile_template(client, config, operator_allowlist, template)
                    .await
                {
                    Ok(()) => {
                        desired_ids.insert(template.id.as_str());
                        reconciled += 1;
                    }
                    Err(KubernetesDriverError::InvalidArgument(err)) => {
                        warn!(
                            template_id = %template.id,
                            template_name = %template.name,
                            workspace = %template.workspace,
                            error = %err,
                            "Skipping invalid sandbox template during warm-pool reconciliation"
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        let desired_ids =
            if self.allocation_enabled(config) && availability.supports_warm_allocation() {
                desired_ids
            } else {
                HashSet::new()
            };
        let pruned = prune_stale_warm_pool_template_resources(client.clone(), config, &desired_ids)
            .await
            .map_err(KubernetesDriverError::Message)?;
        Ok((
            u32::try_from(reconciled).unwrap_or(u32::MAX),
            u32::try_from(pruned).unwrap_or(u32::MAX),
        ))
    }

    pub(super) fn new(
        discovery: ExtensionApiDiscoveryCache,
        activation_support: WarmActivationSupport,
    ) -> Self {
        Self {
            cache: WarmPoolCache::default(),
            discovery,
            activation_support,
        }
    }

    pub(super) fn allocation_enabled(&self, config: &KubernetesComputeConfig) -> bool {
        config.warm_pooling.enabled && self.activation_support == WarmActivationSupport::Available
    }

    pub(super) fn supports_activation(&self) -> bool {
        self.activation_support == WarmActivationSupport::Available
    }

    pub(super) async fn extension_api_availability(
        &self,
        client: &Client,
    ) -> Result<crate::extension_api::ExtensionApiAvailability, String> {
        self.discovery.get(client).await
    }

    pub(super) fn discovery_cache(&self) -> ExtensionApiDiscoveryCache {
        self.discovery.clone()
    }

    pub(super) fn spawn_cache_controller(
        &self,
        client: Client,
        watch_client: Client,
        config: &KubernetesComputeConfig,
    ) {
        let cache = self.cache.clone();
        let context = WarmPoolCacheControllerContext {
            client,
            fallback_namespace: config.namespace.clone(),
            gateway_id: config.gateway_id.clone(),
            extension_api_discovery: self.discovery.clone(),
            multi_namespace: config.is_multi_namespace(),
        };

        tokio::spawn(async move {
            run_warm_pool_cache_controller(cache, watch_client, context).await;
        });
    }
}

pub(super) const CLAIM_CREATE_RECONCILE_ATTEMPTS: usize = 3;
async fn list_generated_warm_pools_with_client(
    client: Client,
    fallback_namespace: &str,
    gateway_id: &str,
    multi_namespace: bool,
) -> Result<Vec<GeneratedWarmPool>, String> {
    let lp = ListParams::default().labels(&owned_generated_warm_pool_label_selector(gateway_id));
    let warm_pool_api = if multi_namespace {
        sandbox_warm_pool_api_all(client)
    } else {
        sandbox_warm_pool_api(client, fallback_namespace)
    };
    let list = match tokio::time::timeout(KUBE_API_TIMEOUT, warm_pool_api.api.list(&lp)).await {
        Ok(Ok(list)) => list,
        Ok(Err(err)) if extension_api_unavailable(&err) => return Ok(Vec::new()),
        Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
            let scope = if multi_namespace {
                "cluster-wide"
            } else {
                fallback_namespace
            };
            return Err(log_extension_api_permission_error(
                SANDBOX_WARM_POOL_KIND,
                "list",
                scope,
                &err,
            ));
        }
        Ok(Err(err)) => return Err(err.to_string()),
        Err(_) => {
            return Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            ));
        }
    };

    Ok(list
        .items
        .into_iter()
        .filter_map(generated_warm_pool_from_object)
        .collect())
}

async fn template_fingerprint_for_warm_pool_with_client(
    client: Client,
    pool: &GeneratedWarmPool,
) -> Result<Option<String>, String> {
    let template_api = sandbox_template_api(client, &pool.template_namespace);
    match tokio::time::timeout(KUBE_API_TIMEOUT, template_api.api.get(&pool.template_name)).await {
        Ok(Ok(template)) => sandbox_template_fingerprint(&template).map(Some),
        Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(None),
        Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
            Err(log_extension_api_permission_error(
                SANDBOX_TEMPLATE_KIND,
                "get",
                &pool.template_namespace,
                &err,
            ))
        }
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!(
            "timed out after {}s waiting for Kubernetes API",
            KUBE_API_TIMEOUT.as_secs()
        )),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum AllocationDecision {
    Claimed,
    UseDirectSandbox,
}

impl WarmPoolManager {
    pub(super) async fn try_allocate(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        sandbox: &Sandbox,
        target_namespace: &str,
        sandbox_template: &DriverSandboxTemplateRef,
        rendered_sandbox: &serde_json::Value,
    ) -> Result<AllocationDecision, KubernetesDriverError> {
        let request_fingerprint = match sandbox_spec_fingerprint(rendered_sandbox) {
            Ok(fingerprint) => fingerprint,
            Err(err) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    error = %err,
                    "Could not fingerprint sandbox request for warm-pool matching; falling back to direct Sandbox"
                );
                return Ok(AllocationDecision::UseDirectSandbox);
            }
        };
        let claimed = self
            .try_create_claim(
                client,
                config,
                sandbox,
                target_namespace,
                sandbox_template,
                &request_fingerprint,
            )
            .await?;
        if claimed {
            Ok(AllocationDecision::Claimed)
        } else {
            info!(
                sandbox_id = %sandbox.id,
                sandbox_name = %sandbox.name,
                namespace = %target_namespace,
                request_fingerprint,
                "Warm-pool request fingerprint input"
            );
            Ok(AllocationDecision::UseDirectSandbox)
        }
    }

    async fn matching_pool(
        &self,
        target_namespace: &str,
        sandbox_template: &DriverSandboxTemplateRef,
        request_fingerprint: &str,
    ) -> Option<WarmPoolCacheEntry> {
        match self
            .cache
            .matching_pool(target_namespace, sandbox_template, request_fingerprint)
            .await
        {
            WarmPoolCacheLookup::NotReady => {
                info!(
                    namespace = %target_namespace,
                    "Warm-pool cache is not ready; falling back to direct Sandbox"
                );
                None
            }
            WarmPoolCacheLookup::NoMatch => {
                let cached_warm_pool_templates = self
                    .cache
                    .entries_for_namespace(target_namespace)
                    .await
                    .into_iter()
                    .map(|entry| {
                        format!(
                            "{}/{}:{}",
                            entry.template_namespace,
                            entry.template_name,
                            entry.template_fingerprint
                        )
                    })
                    .collect::<Vec<_>>();
                info!(
                    namespace = %target_namespace,
                    template_id = %sandbox_template.id,
                    template_name = %sandbox_template.name,
                    template_workspace = %sandbox_template.workspace,
                    template_resource_version = sandbox_template.resource_version,
                    request_fingerprint,
                    cached_warm_pool_template_count = cached_warm_pool_templates.len(),
                    cached_warm_pool_templates = ?cached_warm_pool_templates,
                    "No OpenShell-generated warm pool matches sandbox request; falling back to direct Sandbox"
                );
                None
            }
            WarmPoolCacheLookup::Match(warm_pool) => {
                debug!(
                    namespace = %target_namespace,
                    template_id = %sandbox_template.id,
                    template_name = %sandbox_template.name,
                    template_workspace = %sandbox_template.workspace,
                    template_resource_version = sandbox_template.resource_version,
                    request_fingerprint,
                    warm_pool = %warm_pool.name,
                    template_namespace = %warm_pool.template_namespace,
                    template = %warm_pool.template_name,
                    "OpenShell-generated warm pool matches sandbox request"
                );
                Some(warm_pool)
            }
            WarmPoolCacheLookup::Ambiguous(count) => {
                warn!(
                    namespace = %target_namespace,
                    count,
                    "Multiple OpenShell-generated warm pools match sandbox request; falling back to direct Sandbox"
                );
                None
            }
        }
    }

    async fn try_create_claim(
        &self,
        client: &Client,
        config: &KubernetesComputeConfig,
        sandbox: &Sandbox,
        target_namespace: &str,
        sandbox_template: &DriverSandboxTemplateRef,
        request_fingerprint: &str,
    ) -> Result<bool, KubernetesDriverError> {
        if !self.allocation_enabled(config) {
            return Ok(false);
        }
        let availability = self
            .extension_api_availability(client)
            .await
            .map_err(KubernetesDriverError::Unavailable)?;
        if !availability.supports_warm_allocation() {
            return Ok(false);
        }

        let Some(warm_pool) = self
            .matching_pool(target_namespace, sandbox_template, request_fingerprint)
            .await
        else {
            return Ok(false);
        };

        let claim_api = sandbox_claim_api(client.clone(), target_namespace);
        let claim =
            sandbox_claim_to_k8s_object(config, sandbox, &warm_pool.name, &claim_api.resource);
        let create_result = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            claim_api.api.create(&PostParams::default(), &claim),
        )
        .await;
        match create_result {
            Ok(Ok(_result)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    namespace = %target_namespace,
                    warm_pool = %warm_pool.name,
                    "SandboxClaim created in Kubernetes successfully"
                );
                Ok(true)
            }
            Ok(Err(err)) if extension_api_unavailable(&err) => {
                self.discovery.invalidate().await;
                debug!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    namespace = %target_namespace,
                    error = %err,
                    "SandboxClaim API is unavailable; falling back to direct Sandbox"
                );
                Ok(false)
            }
            Ok(Err(err)) if kube_error_code(&err) == Some(403) => Err(
                KubernetesDriverError::Precondition(log_extension_api_permission_error(
                    SANDBOX_CLAIM_KIND,
                    "create",
                    target_namespace,
                    &err,
                )),
            ),
            Ok(Err(err)) if claim_create_result_is_ambiguous(&err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    namespace = %target_namespace,
                    warm_pool = %warm_pool.name,
                    error = %err,
                    "SandboxClaim create result is ambiguous; reconciling by name"
                );
                self.reconcile_claim_create(&claim_api.api, &claim).await
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    namespace = %target_namespace,
                    warm_pool = %warm_pool.name,
                    error = %err,
                    "SandboxClaim create was definitively rejected; falling back to direct Sandbox"
                );
                Ok(false)
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    namespace = %target_namespace,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out creating SandboxClaim; reconciling by name"
                );
                self.reconcile_claim_create(&claim_api.api, &claim).await
            }
        }
    }

    async fn reconcile_claim_create(
        &self,
        api: &Api<DynamicObject>,
        desired: &DynamicObject,
    ) -> Result<bool, KubernetesDriverError> {
        let name = desired.metadata.name.as_deref().ok_or_else(|| {
            KubernetesDriverError::InvalidArgument("SandboxClaim name is required".to_string())
        })?;

        for attempt in 1..=CLAIM_CREATE_RECONCILE_ATTEMPTS {
            match tokio::time::timeout(KUBE_API_TIMEOUT, api.get(name)).await {
                Ok(Ok(existing)) => {
                    validate_existing_sandbox_claim(desired, &existing)?;
                    info!(
                        sandbox_claim = %name,
                        attempt,
                        "Reconciled existing SandboxClaim after ambiguous create"
                    );
                    return Ok(true);
                }
                Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                    debug!(
                        sandbox_claim = %name,
                        attempt,
                        "SandboxClaim not visible after ambiguous create; retrying idempotent create"
                    );
                    match tokio::time::timeout(
                        KUBE_API_TIMEOUT,
                        api.create(&PostParams::default(), desired),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            info!(
                                sandbox_claim = %name,
                                attempt,
                                "Created SandboxClaim while reconciling ambiguous create"
                            );
                            return Ok(true);
                        }
                        Ok(Err(err)) if claim_create_result_is_ambiguous(&err) => {
                            debug!(
                                sandbox_claim = %name,
                                attempt,
                                error = %err,
                                "Idempotent SandboxClaim create remains ambiguous"
                            );
                        }
                        Ok(Err(err)) => {
                            warn!(
                                sandbox_claim = %name,
                                attempt,
                                error = %err,
                                "Idempotent SandboxClaim create was rejected after an ambiguous write"
                            );
                        }
                        Err(_) => {
                            warn!(
                                sandbox_claim = %name,
                                attempt,
                                timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                                "Idempotent SandboxClaim create timed out"
                            );
                        }
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        sandbox_claim = %name,
                        attempt,
                        error = %err,
                        "Failed to reconcile ambiguous SandboxClaim create"
                    );
                }
                Err(_) => {
                    warn!(
                        sandbox_claim = %name,
                        attempt,
                        timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                        "Timed out reconciling ambiguous SandboxClaim create"
                    );
                }
            }

            if attempt < CLAIM_CREATE_RECONCILE_ATTEMPTS {
                tokio::time::sleep(CLAIM_CREATE_RECONCILE_DELAY).await;
            }
        }

        Err(KubernetesDriverError::Unavailable(format!(
            "SandboxClaim '{name}' create result remains unknown; preserving provisioning state for reconciliation"
        )))
    }
}

pub(super) const CLAIM_CREATE_RECONCILE_DELAY: Duration = Duration::from_millis(250);
pub(super) const WARM_POOL_CACHE_RETRY_DELAY: Duration = Duration::from_secs(10);
pub(super) const LABEL_WARM_POOL_ENABLED: &str = "openshell.ai/enabled";
pub(super) const LABEL_ALLOCATION: &str = "openshell.ai/allocation";
pub(super) const LABEL_ALLOCATION_SANDBOX_CLAIM: &str = "sandbox-claim";
pub(super) const LABEL_WARM_POOL_TEMPLATE: &str = "openshell.ai/warm-pool-template";
pub(super) const LABEL_WARM_POOL_TEMPLATE_ID: &str = "openshell.ai/warm-pool-template-id";
pub(super) const LABEL_WARM_POOL_MANAGED_BY: &str = "openshell.ai/managed-by";
pub(super) const LABEL_WARM_POOL_MANAGED_BY_VALUE: &str = "openshell-kubernetes-driver";
pub(super) const ANNOTATION_WARM_POOL_TEMPLATE_NAME: &str = "openshell.ai/warm-pool-template-name";
pub(super) const ANNOTATION_WARM_POOL_TEMPLATE_ID: &str = "openshell.ai/warm-pool-template-id";
pub(super) const ANNOTATION_WARM_POOL_TEMPLATE_WORKSPACE: &str =
    "openshell.ai/warm-pool-template-workspace";
pub(super) const ANNOTATION_WARM_POOL_SOURCE_RESOURCE_VERSION: &str =
    "openshell.ai/source-resource-version";
pub(super) const ANNOTATION_WARM_POOL_TEMPLATE_FINGERPRINT: &str =
    "openshell.ai/template-fingerprint";
pub(super) const POD_ANNOTATION_SANDBOX_ID: &str = "openshell.ai/sandbox-id";
pub(super) const WARM_POOL_TEMPLATE_NAME_PREFIX: &str = "openshell-wp";
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct GeneratedWarmPool {
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) template_namespace: String,
    pub(super) template_name: String,
    pub(super) source_template_id: String,
    pub(super) source_template_name: String,
    pub(super) source_template_workspace: String,
    pub(super) source_template_resource_version: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct WarmPoolCacheEntry {
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) template_namespace: String,
    pub(super) template_name: String,
    pub(super) source_template_id: String,
    pub(super) source_template_name: String,
    pub(super) source_template_workspace: String,
    pub(super) source_template_resource_version: u64,
    pub(super) template_fingerprint: String,
}

#[derive(Debug, Clone)]
pub(super) struct WarmPoolTemplateSource {
    pub(super) name: String,
    pub(super) id: String,
    pub(super) workspace: String,
    pub(super) resource_version: u64,
}

#[derive(Debug, Clone)]
pub(super) struct RenderedWarmPoolTemplate {
    pub(super) source: WarmPoolTemplateSource,
    pub(super) gateway_id: String,
    pub(super) target_namespace: String,
    pub(super) generated_name: String,
    pub(super) replicas: u32,
    pub(super) template_spec: serde_json::Value,
    pub(super) fingerprint: String,
}

#[derive(Debug, Clone, Default)]
pub(super) struct WarmPoolCache {
    state: Arc<RwLock<WarmPoolCacheState>>,
}

#[derive(Debug, Default)]
pub(super) struct WarmPoolCacheState {
    ready: bool,
    entries: BTreeMap<(String, String), WarmPoolCacheEntry>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum WarmPoolCacheLookup {
    NotReady,
    NoMatch,
    Match(WarmPoolCacheEntry),
    Ambiguous(usize),
}

impl WarmPoolCache {
    pub(super) async fn replace_entries(&self, entries: Vec<WarmPoolCacheEntry>) {
        let mut state = self.state.write().await;
        state.ready = true;
        state.entries = entries
            .into_iter()
            .map(|entry| ((entry.namespace.clone(), entry.name.clone()), entry))
            .collect();
    }

    pub(super) async fn mark_not_ready(&self) {
        let mut state = self.state.write().await;
        state.ready = false;
        state.entries.clear();
    }

    pub(super) async fn matching_pool(
        &self,
        namespace: &str,
        sandbox_template: &DriverSandboxTemplateRef,
        template_fingerprint: &str,
    ) -> WarmPoolCacheLookup {
        let state = self.state.read().await;
        if !state.ready {
            return WarmPoolCacheLookup::NotReady;
        }

        let mut matches = state
            .entries
            .values()
            .filter(|entry| {
                entry.namespace == namespace
                    && entry.source_template_id == sandbox_template.id
                    && entry.source_template_name == sandbox_template.name
                    && entry.source_template_workspace == sandbox_template.workspace
                    && entry.source_template_resource_version == sandbox_template.resource_version
                    && entry.template_fingerprint == template_fingerprint
            })
            .cloned()
            .collect::<Vec<_>>();

        match matches.len() {
            0 => WarmPoolCacheLookup::NoMatch,
            1 => WarmPoolCacheLookup::Match(matches.pop().expect("one match exists")),
            count => WarmPoolCacheLookup::Ambiguous(count),
        }
    }

    pub(super) async fn entries_for_namespace(&self, namespace: &str) -> Vec<WarmPoolCacheEntry> {
        let state = self.state.read().await;
        state
            .entries
            .values()
            .filter(|entry| entry.namespace == namespace)
            .cloned()
            .collect()
    }
}
pub(super) fn dynamic_sandbox_claim_watcher(
    client: Client,
    discovery: ExtensionApiDiscoveryCache,
    namespace: String,
    cluster_wide: bool,
    selector: String,
) -> Pin<Box<dyn Stream<Item = Event<DynamicObject>> + Send>> {
    let (tx, rx) = mpsc::channel(256);

    tokio::spawn(async move {
        loop {
            let availability = match discovery.get(&client).await {
                Ok(availability) => availability,
                Err(err) => {
                    warn!(
                        error = %err,
                        "Could not discover SandboxClaim API; claim watch deferred until retry"
                    );
                    tokio::select! {
                        () = tx.closed() => return,
                        () = tokio::time::sleep(WARM_POOL_CACHE_RETRY_DELAY) => {}
                    }
                    continue;
                }
            };
            if !availability.sandbox_claim {
                tokio::select! {
                    () = tx.closed() => return,
                    () = tokio::time::sleep(WARM_POOL_CACHE_RETRY_DELAY) => {}
                }
                continue;
            }

            let claim_api = if cluster_wide {
                sandbox_claim_api_all(client.clone())
            } else {
                sandbox_claim_api(client.clone(), &namespace)
            };
            let config = watcher::Config::default().labels(&selector);
            let mut stream = watcher::watcher(claim_api.api, config).boxed();
            let mut retry = false;
            while let Some(event) = stream.next().await {
                match event {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    Err(err) => {
                        let scope = if cluster_wide {
                            "cluster-wide"
                        } else {
                            namespace.as_str()
                        };
                        match watcher_error_code(&err) {
                            Some(403) => error!(
                                api_group = EXTENSIONS_GROUP,
                                api_version = EXTENSIONS_VERSION_V1BETA1,
                                kind = SANDBOX_CLAIM_KIND,
                                operation = "list/watch",
                                scope,
                                error = %err,
                                "Kubernetes RBAC configuration error for Agent Sandbox extension API"
                            ),
                            Some(404) => discovery.invalidate().await,
                            _ => warn!(
                                scope,
                                error = %err,
                                "SandboxClaim watcher failed; retrying after discovery"
                            ),
                        }
                        retry = true;
                        break;
                    }
                }
            }

            if !retry {
                warn!("SandboxClaim watcher ended; retrying after discovery");
            }
            tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep(WARM_POOL_CACHE_RETRY_DELAY) => {}
            }
        }
    });

    Box::pin(ReceiverStream::new(rx))
}
pub(super) struct WarmPoolCacheControllerContext {
    pub(super) client: Client,
    pub(super) fallback_namespace: String,
    pub(super) gateway_id: String,
    pub(super) extension_api_discovery: ExtensionApiDiscoveryCache,
    pub(super) multi_namespace: bool,
}

pub(super) async fn run_warm_pool_cache_controller(
    cache: WarmPoolCache,
    watch_client: Client,
    context: WarmPoolCacheControllerContext,
) {
    loop {
        let availability = match context.extension_api_discovery.get(&context.client).await {
            Ok(availability) => availability,
            Err(err) => {
                cache.mark_not_ready().await;
                warn!(
                    namespace = %context.fallback_namespace,
                    error = %err,
                    "Could not discover Agent Sandbox extension APIs; warm-pool allocation disabled until retry"
                );
                tokio::time::sleep(WARM_POOL_CACHE_RETRY_DELAY).await;
                continue;
            }
        };
        if !availability.supports_warm_allocation() {
            cache.mark_not_ready().await;
            tokio::time::sleep(WARM_POOL_CACHE_RETRY_DELAY).await;
            continue;
        }

        refresh_warm_pool_cache(&cache, &context).await;

        let warm_pool_api = if context.multi_namespace {
            sandbox_warm_pool_api_all(watch_client.clone())
        } else {
            sandbox_warm_pool_api(watch_client.clone(), &context.fallback_namespace)
        };
        let template_api = if context.multi_namespace {
            sandbox_template_api_all(watch_client.clone())
        } else {
            sandbox_template_api(watch_client.clone(), &context.fallback_namespace)
        };

        let watcher_config = watcher::Config::default().labels(
            &owned_generated_warm_pool_label_selector(&context.gateway_id),
        );
        let mut warm_pool_stream =
            watcher::watcher(warm_pool_api.api, watcher_config.clone()).boxed();
        let mut template_stream = watcher::watcher(template_api.api, watcher_config).boxed();

        loop {
            tokio::select! {
                event = warm_pool_stream.try_next() => {
                    if !handle_warm_pool_cache_watch_event(
                        &cache,
                        &context,
                        event,
                        SANDBOX_WARM_POOL_KIND,
                    )
                    .await
                    {
                        break;
                    }
                }
                event = template_stream.try_next() => {
                    if !handle_warm_pool_cache_watch_event(
                        &cache,
                        &context,
                        event,
                        SANDBOX_TEMPLATE_KIND,
                    )
                    .await
                    {
                        break;
                    }
                }
            }
        }

        cache.mark_not_ready().await;
        tokio::time::sleep(WARM_POOL_CACHE_RETRY_DELAY).await;
    }
}

pub(super) async fn handle_warm_pool_cache_watch_event(
    cache: &WarmPoolCache,
    context: &WarmPoolCacheControllerContext,
    event: Result<Option<Event<DynamicObject>>, watcher::Error>,
    kind: &str,
) -> bool {
    match event {
        Ok(Some(Event::Apply(_) | Event::Delete(_) | Event::InitDone)) => {
            refresh_warm_pool_cache(cache, context).await;
            true
        }
        Ok(Some(Event::Init | Event::InitApply(_))) => true,
        Ok(None) => {
            warn!(
                kind,
                "Warm-pool cache watch stream ended; warm-pool allocation disabled until retry"
            );
            false
        }
        Err(err) => {
            let scope = if context.multi_namespace {
                "cluster-wide"
            } else {
                &context.fallback_namespace
            };
            match watcher_error_code(&err) {
                Some(403) => error!(
                    api_group = EXTENSIONS_GROUP,
                    api_version = EXTENSIONS_VERSION_V1BETA1,
                    kind,
                    operation = "list/watch",
                    scope,
                    error = %err,
                    "Kubernetes RBAC configuration error for Agent Sandbox extension API"
                ),
                Some(404) => context.extension_api_discovery.invalidate().await,
                _ => warn!(
                    kind,
                    error = %err,
                    "Warm-pool cache watch failed; warm-pool allocation disabled until retry"
                ),
            }
            false
        }
    }
}

pub(super) async fn refresh_warm_pool_cache(
    cache: &WarmPoolCache,
    context: &WarmPoolCacheControllerContext,
) {
    let pools = match list_generated_warm_pools_with_client(
        context.client.clone(),
        &context.fallback_namespace,
        &context.gateway_id,
        context.multi_namespace,
    )
    .await
    {
        Ok(pools) => pools,
        Err(err) => {
            cache.mark_not_ready().await;
            warn!(
                namespace = %context.fallback_namespace,
                error = %err,
                "Failed to refresh warm-pool cache; warm-pool allocation disabled until retry"
            );
            return;
        }
    };

    let mut entries = Vec::new();
    for pool in pools {
        let template_fingerprint =
            match template_fingerprint_for_warm_pool_with_client(context.client.clone(), &pool)
                .await
            {
                Ok(Some(fingerprint)) => fingerprint,
                Ok(None) => {
                    debug!(
                        namespace = %pool.namespace,
                        warm_pool = %pool.name,
                        template_namespace = %pool.template_namespace,
                        template = %pool.template_name,
                        "Skipping warm pool with missing or unreadable SandboxTemplate"
                    );
                    continue;
                }
                Err(err) => {
                    warn!(
                        namespace = %pool.namespace,
                        warm_pool = %pool.name,
                        template_namespace = %pool.template_namespace,
                        template = %pool.template_name,
                        error = %err,
                        "Skipping warm pool after SandboxTemplate fingerprint failed"
                    );
                    continue;
                }
            };

        debug!(
            namespace = %pool.namespace,
            warm_pool = %pool.name,
            template_namespace = %pool.template_namespace,
            template = %pool.template_name,
            template_fingerprint = %template_fingerprint,
            "Cached OpenShell-generated warm-pool template fingerprint"
        );

        entries.push(WarmPoolCacheEntry {
            namespace: pool.namespace,
            name: pool.name,
            template_namespace: pool.template_namespace,
            template_name: pool.template_name,
            source_template_id: pool.source_template_id,
            source_template_name: pool.source_template_name,
            source_template_workspace: pool.source_template_workspace,
            source_template_resource_version: pool.source_template_resource_version,
            template_fingerprint,
        });
    }

    let count = entries.len();
    cache.replace_entries(entries).await;
    debug!(
        namespace = %context.fallback_namespace,
        count,
        "Warm-pool cache refreshed"
    );
}

pub(super) async fn render_warm_pool_template(
    client: Client,
    config: &KubernetesComputeConfig,
    operator_allowlist: Option<&OperatorNamespaceAllowlist>,
    template: &DriverSandboxTemplateResource,
) -> Result<Option<RenderedWarmPoolTemplate>, String> {
    if !config.warm_pooling.enabled {
        return Ok(None);
    }
    validate_warm_pool_template(template)?;
    if !template_requires_warm_pool(
        template
            .desired_service_level
            .as_ref()
            .and_then(|slo| slo.startup.as_ref()),
        config
            .warm_pooling
            .templates
            .effective_ready_within_threshold(),
    )? {
        return Ok(None);
    }

    let target_namespace =
        config.namespace_for_workspace(&template.workspace, operator_allowlist)?;
    let spec = warm_pool_template_to_sandbox_spec(template)?;
    let replicas = requested_warm_pool_replicas(
        template
            .desired_service_level
            .as_ref()
            .and_then(|slo| slo.startup.as_ref()),
        config.warm_pooling.templates.effective_max_replicas(),
    );
    let (template_user_id, template_group_id, _) =
        resolve_sandbox_identity_for_config(client, config, &target_namespace).await;
    let params = SandboxPodParams {
        default_image: &config.default_image,
        image_pull_policy: &config.image_pull_policy,
        image_pull_secrets: &config.image_pull_secrets,
        supervisor_image: &config.supervisor_image,
        supervisor_image_pull_policy: &config.supervisor_image_pull_policy,
        supervisor_sideload_method: config.supervisor_sideload_method,
        topology: config.topology,
        proxy_uid: config.sidecar.proxy_uid,
        process_binary_aware_network_policy: config.sidecar.process_binary_aware_network_policy,
        https_proxy: config.https_proxy.as_deref(),
        no_proxy: config.no_proxy.as_deref(),
        proxy_auth_secret_name: config.proxy_auth_secret_name.as_deref(),
        proxy_auth_secret_key: config.proxy_auth_secret_key.as_deref(),
        proxy_auth_allow_insecure: config.proxy_auth_allow_insecure == Some(true),
        proxy_connect_by_hostname: config.proxy_connect_by_hostname == Some(true),
        service_account_name: &config.service_account_name,
        sandbox_id: "",
        sandbox_name: "",
        grpc_endpoint: &config.grpc_endpoint,
        ssh_socket_path: &config.ssh_socket_path,
        client_tls_secret_name: &config.client_tls_secret_name,
        host_gateway_ip: &config.host_gateway_ip,
        enable_user_namespaces: config.enable_user_namespaces,
        app_armor_profile: config.app_armor_profile.as_ref(),
        workspace_default_storage_size: &config.workspace_default_storage_size,
        workspace_storage_class: &config.workspace_storage_class,
        default_runtime_class_name: &config.default_runtime_class_name,
        sa_token_ttl_secs: config.effective_sa_token_ttl_secs(),
        provider_spiffe_enabled: config.provider_spiffe_enabled(),
        provider_spiffe_workload_api_socket_path: &config.provider_spiffe_workload_api_socket_path,
        sandbox_uid: template_user_id,
        sandbox_gid: template_group_id,
    };
    validate_sidecar_proxy_identity(&params).map_err(|err| err.to_string())?;

    let mut rendered = sandbox_to_k8s_spec(Some(&spec), &params)?;
    remove_warm_pool_template_identity_env(&mut rendered);
    ensure_pod_dns_policy(&mut rendered);
    ensure_network_policy_management_unmanaged(&mut rendered);
    let fingerprint = sandbox_spec_fingerprint(&rendered)?;
    let generated_name =
        generated_warm_pool_template_name(&template.name, &template.id, &fingerprint);
    validate_kubernetes_dns1123_label(&generated_name, "generated warm-pool resource name")?;
    let template_spec = rendered
        .get("spec")
        .cloned()
        .ok_or_else(|| "rendered sandbox spec is missing spec".to_string())?;
    let source = WarmPoolTemplateSource {
        name: template.name.clone(),
        id: template.id.clone(),
        workspace: template.workspace.clone(),
        resource_version: template.resource_version,
    };

    Ok(Some(RenderedWarmPoolTemplate {
        source,
        gateway_id: config.gateway_id.clone(),
        target_namespace,
        generated_name,
        replicas,
        template_spec,
        fingerprint,
    }))
}

pub(super) fn validate_warm_pool_template(
    template: &DriverSandboxTemplateResource,
) -> Result<(), String> {
    if template.id.trim().is_empty() {
        return Err("template id must not be empty".to_string());
    }
    if template.name.trim().is_empty() {
        return Err("template name must not be empty".to_string());
    }
    if template.workspace.trim().is_empty() {
        return Err("workspace must not be empty".to_string());
    }
    if template.workspace.chars().any(char::is_control) {
        return Err("workspace must not contain control characters".to_string());
    }
    validate_warm_pool_template_environment(
        &template
            .template
            .as_ref()
            .map_or_else(BTreeMap::new, |runtime_template| {
                runtime_template.environment.clone().into_iter().collect()
            }),
    )?;
    if let Some(count) = template
        .resource_requirements
        .as_ref()
        .and_then(|requirements| requirements.gpu.as_ref())
        .and_then(|gpu| gpu.count)
        && count == 0
    {
        return Err("resource_requirements.gpu.count must be greater than 0".to_string());
    }
    Ok(())
}

pub(super) fn validate_warm_pool_template_environment(
    env: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (key, value) in env {
        if !is_valid_env_key(key) {
            return Err(format!(
                "environment keys must match ^[A-Za-z_][A-Za-z0-9_]*$; got '{key}'"
            ));
        }
        if key.starts_with("OPENSHELL_") {
            return Err(format!(
                "environment keys starting with OPENSHELL_ are reserved; got '{key}'"
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(format!(
                "environment value for '{key}' must not contain control characters"
            ));
        }
    }
    Ok(())
}

pub(super) fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

pub(super) fn template_requires_warm_pool(
    startup: Option<&DriverSandboxTemplateStartup>,
    threshold: Duration,
) -> Result<bool, String> {
    let Some(ready_within) = startup.and_then(|startup| startup.ready_within.as_ref()) else {
        return Ok(false);
    };
    let ready_within = prost_duration_to_std(ready_within)?;
    Ok(ready_within < threshold)
}

pub(super) fn prost_duration_to_std(duration: &prost_types::Duration) -> Result<Duration, String> {
    if duration.seconds < 0 || duration.nanos < 0 {
        return Err("ready_within must not be negative".to_string());
    }
    let seconds = u64::try_from(duration.seconds)
        .map_err(|_| "ready_within seconds exceed supported range".to_string())?;
    let nanos = u32::try_from(duration.nanos)
        .map_err(|_| "ready_within nanos exceed supported range".to_string())?;
    Duration::from_secs(seconds)
        .checked_add(Duration::from_nanos(u64::from(nanos)))
        .ok_or_else(|| "ready_within exceeds supported range".to_string())
}

pub(super) fn requested_warm_pool_replicas(
    startup: Option<&DriverSandboxTemplateStartup>,
    max_replicas: u32,
) -> u32 {
    let requested = startup.map_or(1, |startup| startup.max_burst).max(1);
    requested.min(max_replicas)
}

pub(super) fn warm_pool_template_to_sandbox_spec(
    template: &DriverSandboxTemplateResource,
) -> Result<SandboxSpec, String> {
    let runtime_template = template
        .template
        .clone()
        .ok_or_else(|| "template runtime template is required".to_string())?;
    Ok(SandboxSpec {
        environment: runtime_template.environment.clone(),
        template: Some(runtime_template),
        resource_requirements: template.resource_requirements,
        ..Default::default()
    })
}

pub(super) fn ensure_pod_dns_policy(rendered: &mut serde_json::Value) {
    if let Some(spec) = rendered
        .pointer_mut("/spec/podTemplate/spec")
        .and_then(serde_json::Value::as_object_mut)
    {
        spec.entry("dnsPolicy".to_string())
            .or_insert_with(|| serde_json::json!("ClusterFirst"));
    }
}

pub(super) fn ensure_network_policy_management_unmanaged(rendered: &mut serde_json::Value) {
    if let Some(spec) = rendered
        .get_mut("spec")
        .and_then(serde_json::Value::as_object_mut)
    {
        spec.insert(
            "networkPolicyManagement".to_string(),
            serde_json::json!("Unmanaged"),
        );
    }
}

pub(super) fn remove_warm_pool_template_identity_env(rendered: &mut serde_json::Value) {
    if let Some(containers) = rendered
        .pointer_mut("/spec/podTemplate/spec/containers")
        .and_then(serde_json::Value::as_array_mut)
    {
        for container in containers {
            remove_sandbox_identity_env(container);
        }
    }
}

pub(super) fn generated_warm_pool_template_name(
    template_name: &str,
    template_id: &str,
    fingerprint: &str,
) -> String {
    let fingerprint_suffix = fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint)
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    let fingerprint_suffix = if fingerprint_suffix.is_empty() {
        "00000000".to_string()
    } else {
        fingerprint_suffix
    };
    // Template IDs are globally unique across workspaces. Keep an identity
    // segment separate from the workload fingerprint so same-named templates
    // with identical specs cannot address the same resource in shared mode.
    let identity_suffix = hex_encode(&Sha256::digest(template_id.as_bytes()))
        .chars()
        .take(16)
        .collect::<String>();
    let prefix = sanitize_dns_label_segment(template_name);
    let reserved =
        WARM_POOL_TEMPLATE_NAME_PREFIX.len() + 3 + identity_suffix.len() + fingerprint_suffix.len();
    let max_prefix_len = MAX_KUBE_NAME_LEN.saturating_sub(reserved);
    let mut trimmed = prefix.chars().take(max_prefix_len).collect::<String>();
    trimmed = trimmed.trim_matches('-').to_string();
    if trimmed.is_empty() {
        trimmed = "template".to_string();
    }
    format!("{WARM_POOL_TEMPLATE_NAME_PREFIX}-{trimmed}-{identity_suffix}-{fingerprint_suffix}")
}

pub(super) fn sanitize_dns_label_segment(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for byte in value.bytes() {
        let ch = if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            byte as char
        } else if byte.is_ascii_uppercase() {
            (byte as char).to_ascii_lowercase()
        } else {
            '-'
        };
        if ch == '-' {
            if !last_dash {
                out.push(ch);
            }
            last_dash = true;
        } else {
            out.push(ch);
            last_dash = false;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "template".to_string()
    } else {
        trimmed
    }
}

pub(super) async fn apply_rendered_warm_pool_template(
    client: Client,
    rendered: &RenderedWarmPoolTemplate,
) -> Result<(), String> {
    let template_api = sandbox_template_api(client.clone(), &rendered.target_namespace);
    let warm_pool_api = sandbox_warm_pool_api(client.clone(), &rendered.target_namespace);
    let template = rendered_warm_pool_template_object(rendered, &template_api.resource);
    let warm_pool = rendered_warm_pool_object(rendered, &warm_pool_api.resource);
    apply_dynamic_object(
        &template_api.api,
        &rendered.generated_name,
        &template,
        SANDBOX_TEMPLATE_KIND,
        &rendered.target_namespace,
    )
    .await?;
    apply_dynamic_object(
        &warm_pool_api.api,
        &rendered.generated_name,
        &warm_pool,
        SANDBOX_WARM_POOL_KIND,
        &rendered.target_namespace,
    )
    .await?;
    Ok(())
}

pub(super) async fn apply_dynamic_object(
    api: &Api<DynamicObject>,
    name: &str,
    obj: &DynamicObject,
    kind: &str,
    namespace: &str,
) -> Result<(), String> {
    match tokio::time::timeout(KUBE_API_TIMEOUT, api.create(&PostParams::default(), obj)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(KubeError::Api(err))) if err.code == 409 => {
            let patch = dynamic_object_merge_patch(obj);
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                api.patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
            )
            .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(err)) if kube_error_code(&err) == Some(403) => Err(
                    log_extension_api_permission_error(kind, "patch", namespace, &err),
                ),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                )),
            }
        }
        Ok(Err(err)) if kube_error_code(&err) == Some(403) => Err(
            log_extension_api_permission_error(kind, "create", namespace, &err),
        ),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!(
            "timed out after {}s waiting for Kubernetes API",
            KUBE_API_TIMEOUT.as_secs()
        )),
    }
}

pub(super) fn dynamic_object_merge_patch(obj: &DynamicObject) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "labels": obj.metadata.labels,
            "annotations": obj.metadata.annotations,
        },
        "spec": obj.data.get("spec").cloned().unwrap_or_else(|| serde_json::json!({})),
    })
}

pub(super) fn rendered_warm_pool_template_object(
    rendered: &RenderedWarmPoolTemplate,
    resource: &ApiResource,
) -> DynamicObject {
    let mut obj = DynamicObject::new(&rendered.generated_name, resource);
    obj.metadata = ObjectMeta {
        name: Some(rendered.generated_name.clone()),
        namespace: Some(rendered.target_namespace.clone()),
        labels: Some(warm_pool_template_generated_labels(rendered)),
        annotations: Some(warm_pool_template_generated_annotations(rendered)),
        ..Default::default()
    };
    obj.data = serde_json::json!({
        "spec": rendered.template_spec,
    });
    obj
}

pub(super) fn rendered_warm_pool_object(
    rendered: &RenderedWarmPoolTemplate,
    resource: &ApiResource,
) -> DynamicObject {
    let mut obj = DynamicObject::new(&rendered.generated_name, resource);
    obj.metadata = ObjectMeta {
        name: Some(rendered.generated_name.clone()),
        namespace: Some(rendered.target_namespace.clone()),
        labels: Some(warm_pool_template_generated_labels(rendered)),
        annotations: Some(warm_pool_template_generated_annotations(rendered)),
        ..Default::default()
    };
    obj.data = serde_json::json!({
        "spec": {
            "replicas": rendered.replicas,
            "sandboxTemplateRef": {
                "name": rendered.generated_name
            }
        }
    });
    obj
}

pub(super) fn warm_pool_template_generated_labels(
    rendered: &RenderedWarmPoolTemplate,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_WARM_POOL_ENABLED.to_string(), "true".to_string()),
        (
            LABEL_WARM_POOL_MANAGED_BY.to_string(),
            LABEL_WARM_POOL_MANAGED_BY_VALUE.to_string(),
        ),
        (LABEL_GATEWAY_ID.to_string(), rendered.gateway_id.clone()),
        (
            LABEL_WARM_POOL_TEMPLATE.to_string(),
            label_value_for_template_name(&rendered.source.name),
        ),
        (
            LABEL_WARM_POOL_TEMPLATE_ID.to_string(),
            label_value_for_template_id(&rendered.source.id),
        ),
    ])
}

pub(super) fn label_value_for_template_name(name: &str) -> String {
    let sanitized = sanitize_dns_label_segment(name);
    let mut value = sanitized.chars().take(63).collect::<String>();
    value = value.trim_matches('-').to_string();
    if value.is_empty() {
        "template".to_string()
    } else {
        value
    }
}

pub(super) fn label_value_for_template_id(id: &str) -> String {
    let sanitized = sanitize_dns_label_segment(id);
    let mut value = sanitized.chars().take(63).collect::<String>();
    value = value.trim_matches('-').to_string();
    if value.is_empty() {
        "template".to_string()
    } else {
        value
    }
}

pub(super) fn warm_pool_template_generated_annotations(
    rendered: &RenderedWarmPoolTemplate,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            ANNOTATION_WARM_POOL_TEMPLATE_NAME.to_string(),
            rendered.source.name.clone(),
        ),
        (
            ANNOTATION_WARM_POOL_TEMPLATE_ID.to_string(),
            rendered.source.id.clone(),
        ),
        (
            ANNOTATION_WARM_POOL_TEMPLATE_WORKSPACE.to_string(),
            rendered.source.workspace.clone(),
        ),
        (
            ANNOTATION_WARM_POOL_SOURCE_RESOURCE_VERSION.to_string(),
            rendered.source.resource_version.to_string(),
        ),
        (
            ANNOTATION_WARM_POOL_TEMPLATE_FINGERPRINT.to_string(),
            rendered.fingerprint.clone(),
        ),
        (
            LABEL_SANDBOX_WORKSPACE.to_string(),
            rendered.source.workspace.clone(),
        ),
    ])
}

pub(super) async fn garbage_collect_superseded_warm_pool_template_resources(
    client: Client,
    rendered: &RenderedWarmPoolTemplate,
) -> Result<(), String> {
    garbage_collect_warm_pool_template_resources(
        client,
        &rendered.target_namespace,
        &rendered.source.id,
        Some(&rendered.generated_name),
    )
    .await
}

pub(super) async fn garbage_collect_warm_pool_template(
    client: Client,
    config: &KubernetesComputeConfig,
    operator_allowlist: Option<&OperatorNamespaceAllowlist>,
    template_id: &str,
    workspace: &str,
) -> Result<(), String> {
    if template_id.is_empty() {
        return Ok(());
    }
    let namespace = config.namespace_for_workspace(workspace, operator_allowlist)?;
    garbage_collect_warm_pool_template_resources(client, &namespace, template_id, None).await
}

pub(super) async fn garbage_collect_warm_pool_template_resources(
    client: Client,
    target_namespace: &str,
    template_id: &str,
    keep_name: Option<&str>,
) -> Result<(), String> {
    let selector = format!(
        "{LABEL_WARM_POOL_MANAGED_BY}={LABEL_WARM_POOL_MANAGED_BY_VALUE},{LABEL_WARM_POOL_TEMPLATE_ID}={}",
        label_value_for_template_id(template_id)
    );
    let lp = ListParams::default().labels(&selector);
    let warm_pool_api = sandbox_warm_pool_api(client.clone(), target_namespace);
    delete_matching_dynamic_objects(
        &warm_pool_api.api,
        &lp,
        keep_name,
        SANDBOX_WARM_POOL_KIND,
        target_namespace,
    )
    .await?;
    let template_api = sandbox_template_api(client, target_namespace);
    delete_matching_dynamic_objects(
        &template_api.api,
        &lp,
        keep_name,
        SANDBOX_TEMPLATE_KIND,
        target_namespace,
    )
    .await?;
    Ok(())
}

pub(super) async fn prune_stale_warm_pool_template_resources(
    client: Client,
    config: &KubernetesComputeConfig,
    desired_ids: &HashSet<&str>,
) -> Result<usize, String> {
    let selector = owned_generated_warm_pool_label_selector(&config.gateway_id);
    let lp = ListParams::default().labels(&selector);
    let mut pruned = 0usize;
    for kind in [SANDBOX_WARM_POOL_KIND, SANDBOX_TEMPLATE_KIND] {
        let extension_api = if config.is_multi_namespace() {
            all_extension_api(client.clone(), kind)
        } else {
            namespaced_extension_api(client.clone(), &config.namespace, kind)
        };
        let objects =
            match tokio::time::timeout(KUBE_API_TIMEOUT, extension_api.api.list(&lp)).await {
                Ok(Ok(list)) => list.items,
                Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
                    let scope = if config.is_multi_namespace() {
                        "cluster-wide"
                    } else {
                        config.namespace.as_str()
                    };
                    return Err(log_extension_api_permission_error(
                        kind, "list", scope, &err,
                    ));
                }
                Ok(Err(KubeError::Api(err))) if err.code == 404 => Vec::new(),
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_) => return Err(kubernetes_api_timeout_message("listing", kind)),
            };

        for object in objects {
            let Some(template_id) = object
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(ANNOTATION_WARM_POOL_TEMPLATE_ID))
            else {
                continue;
            };
            if desired_ids.contains(template_id.as_str()) {
                continue;
            }
            let (Some(namespace), Some(name)) = (
                object.metadata.namespace.as_deref(),
                object.metadata.name.as_deref(),
            ) else {
                continue;
            };
            let namespaced_api = namespaced_extension_api(client.clone(), namespace, kind);
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                namespaced_api.api.delete(name, &DeleteParams::default()),
            )
            .await
            {
                Ok(Ok(_)) => {
                    pruned = pruned.saturating_add(1);
                }
                Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                    pruned = pruned.saturating_add(1);
                }
                Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
                    return Err(log_extension_api_permission_error(
                        kind, "delete", namespace, &err,
                    ));
                }
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_) => return Err(kubernetes_api_timeout_message("deleting", kind)),
            }
        }
    }
    Ok(pruned)
}

pub(super) fn kubernetes_api_timeout_message(action: &str, kind: &str) -> String {
    format!(
        "timed out after {}s {action} {kind} resources",
        KUBE_API_TIMEOUT.as_secs()
    )
}

pub(super) async fn delete_matching_dynamic_objects(
    api: &Api<DynamicObject>,
    lp: &ListParams,
    keep_name: Option<&str>,
    kind: &str,
    namespace: &str,
) -> Result<(), String> {
    let list = match tokio::time::timeout(KUBE_API_TIMEOUT, api.list(lp)).await {
        Ok(Ok(list)) => list,
        Ok(Err(KubeError::Api(err))) if err.code == 404 => return Ok(()),
        Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
            return Err(log_extension_api_permission_error(
                kind, "list", namespace, &err,
            ));
        }
        Ok(Err(err)) => return Err(err.to_string()),
        Err(_) => {
            return Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            ));
        }
    };
    for obj in list.items {
        let Some(name) = obj.metadata.name.as_deref() else {
            continue;
        };
        if keep_name == Some(name) {
            continue;
        }
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.delete(name, &DeleteParams::default()))
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {}
            Ok(Err(err)) if kube_error_code(&err) == Some(403) => {
                return Err(log_extension_api_permission_error(
                    kind, "delete", namespace, &err,
                ));
            }
            Ok(Err(err)) => return Err(err.to_string()),
            Err(_) => {
                return Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn sandbox_claim_to_k8s_object(
    config: &KubernetesComputeConfig,
    sandbox: &Sandbox,
    warm_pool_name: &str,
    resource: &ApiResource,
) -> DynamicObject {
    let kube_name = config.kube_resource_name(&sandbox.workspace, &sandbox.name);
    let mut obj = DynamicObject::new(&kube_name, resource);
    let mut labels = sandbox_labels(sandbox, Some(&config.gateway_id));
    labels.insert(
        LABEL_ALLOCATION.to_string(),
        LABEL_ALLOCATION_SANDBOX_CLAIM.to_string(),
    );
    obj.metadata = ObjectMeta {
        name: Some(kube_name),
        labels: Some(labels),
        annotations: Some(sandbox_annotations(sandbox)),
        ..Default::default()
    };
    obj.data = serde_json::json!({
        "spec": {
            "lifecycle": {
                "shutdownPolicy": "Delete"
            },
            "warmPoolRef": {
                "name": warm_pool_name
            }
        }
    });
    obj
}

pub(super) fn claim_create_result_is_ambiguous(err: &KubeError) -> bool {
    match err {
        KubeError::Api(response) => {
            response.code == 408 || response.code == 409 || response.code >= 500
        }
        _ => true,
    }
}

pub(super) fn validate_existing_sandbox_claim(
    desired: &DynamicObject,
    existing: &DynamicObject,
) -> Result<(), KubernetesDriverError> {
    let desired_name = desired.metadata.name.as_deref().unwrap_or_default();
    let existing_name = existing.metadata.name.as_deref().unwrap_or_default();
    if desired_name.is_empty() || existing_name != desired_name {
        return Err(KubernetesDriverError::Precondition(format!(
            "existing SandboxClaim name '{existing_name}' does not match requested claim '{desired_name}'"
        )));
    }

    for key in [
        LABEL_MANAGED_BY,
        LABEL_GATEWAY_ID,
        LABEL_SANDBOX_ID,
        LABEL_SANDBOX_NAME,
        LABEL_SANDBOX_WORKSPACE,
        LABEL_ALLOCATION,
    ] {
        let expected = desired
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(key))
            .map(String::as_str)
            .unwrap_or_default();
        let actual = existing
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(key))
            .map(String::as_str)
            .unwrap_or_default();
        if expected.is_empty() || actual != expected {
            return Err(KubernetesDriverError::Precondition(format!(
                "existing SandboxClaim '{desired_name}' has conflicting {key} metadata"
            )));
        }
    }

    let expected_pool = string_at(&desired.data, &["spec", "warmPoolRef", "name"]);
    let actual_pool = string_at(&existing.data, &["spec", "warmPoolRef", "name"]);
    if expected_pool.is_none() || actual_pool != expected_pool {
        return Err(KubernetesDriverError::Precondition(format!(
            "existing SandboxClaim '{desired_name}' targets a different warm pool"
        )));
    }

    Ok(())
}

pub(super) fn generated_warm_pool_label_selector() -> String {
    format!(
        "{LABEL_WARM_POOL_ENABLED}=true,{LABEL_WARM_POOL_MANAGED_BY}={LABEL_WARM_POOL_MANAGED_BY_VALUE}"
    )
}

pub(super) fn owned_generated_warm_pool_label_selector(gateway_id: &str) -> String {
    format!(
        "{},{LABEL_GATEWAY_ID}={gateway_id}",
        generated_warm_pool_label_selector()
    )
}

pub(super) fn generated_warm_pool_from_object(obj: DynamicObject) -> Option<GeneratedWarmPool> {
    let namespace = obj.metadata.namespace.clone()?;
    let name = obj.metadata.name.clone()?;
    let annotations = obj.metadata.annotations.as_ref()?;
    let template_name = string_at(&obj.data, &["spec", "sandboxTemplateRef", "name"])?;
    let template_namespace = string_at(&obj.data, &["spec", "sandboxTemplateRef", "namespace"])
        .unwrap_or_else(|| namespace.clone());
    let source_template_id = annotations
        .get(ANNOTATION_WARM_POOL_TEMPLATE_ID)
        .filter(|value| !value.is_empty())?
        .clone();
    let source_template_name = annotations
        .get(ANNOTATION_WARM_POOL_TEMPLATE_NAME)
        .filter(|value| !value.is_empty())?
        .clone();
    let source_template_workspace = annotations
        .get(ANNOTATION_WARM_POOL_TEMPLATE_WORKSPACE)
        .filter(|value| !value.is_empty())?
        .clone();
    let source_template_resource_version = annotations
        .get(ANNOTATION_WARM_POOL_SOURCE_RESOURCE_VERSION)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)?;
    Some(GeneratedWarmPool {
        namespace,
        name,
        template_namespace,
        template_name,
        source_template_id,
        source_template_name,
        source_template_workspace,
        source_template_resource_version,
    })
}

pub(super) fn sandbox_template_fingerprint(obj: &DynamicObject) -> Result<String, String> {
    sandbox_spec_fingerprint(&obj.data)
}

pub(super) fn sandbox_spec_fingerprint(data: &serde_json::Value) -> Result<String, String> {
    let spec = data
        .get("spec")
        .ok_or_else(|| "object is missing spec".to_string())?;
    let mut normalized = spec.clone();
    normalize_template_spec_for_fingerprint(&mut normalized);
    stable_json_fingerprint(&normalized)
}

pub(super) fn normalize_template_spec_for_fingerprint(value: &mut serde_json::Value) {
    remove_path_if_value(
        value,
        &["envVarsInjectionPolicy"],
        &serde_json::json!("Disallowed"),
    );
    remove_path_if_value(
        value,
        &["networkPolicyManagement"],
        &serde_json::json!("Unmanaged"),
    );
    remove_path_if_value(value, &["operatingMode"], &serde_json::json!("Running"));
    remove_path_if_value(value, &["replicas"], &serde_json::json!(1));
    remove_path_if_value(value, &["shutdownPolicy"], &serde_json::json!("Retain"));
    remove_path_if_value(
        value,
        &["podTemplate", "spec", "dnsPolicy"],
        &serde_json::json!("ClusterFirst"),
    );
    remove_path_if_value(
        value,
        &["volumeClaimTemplatesPolicy"],
        &serde_json::json!("Disallowed"),
    );
    remove_path(
        value,
        &[
            "podTemplate",
            "metadata",
            "annotations",
            POD_ANNOTATION_SANDBOX_ID,
        ],
    );
    remove_path(
        value,
        &["podTemplate", "metadata", "labels", LABEL_SANDBOX_ID],
    );
    remove_empty_object_path(value, &["podTemplate", "metadata", "annotations"]);
    remove_empty_object_path(value, &["podTemplate", "metadata", "labels"]);
    remove_empty_object_path(value, &["podTemplate", "metadata"]);
    if let Some(containers) = value
        .pointer_mut("/podTemplate/spec/containers")
        .and_then(serde_json::Value::as_array_mut)
    {
        for container in containers {
            remove_sandbox_identity_env(container);
            remove_empty_container_resources(container);
            remove_default_volume_mount_read_only(container);
        }
    }
    if let Some(init_containers) = value
        .pointer_mut("/podTemplate/spec/initContainers")
        .and_then(serde_json::Value::as_array_mut)
    {
        for container in init_containers {
            remove_empty_container_resources(container);
            remove_default_volume_mount_read_only(container);
        }
    }
}

pub(super) fn remove_sandbox_identity_env(container: &mut serde_json::Value) {
    let Some(env) = container
        .get_mut("env")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    env.retain(|entry| {
        !matches!(
            entry.get("name").and_then(serde_json::Value::as_str),
            Some(name)
                if name == openshell_core::sandbox_env::SANDBOX_ID
                    || name == openshell_core::sandbox_env::SANDBOX
                    || name == openshell_core::sandbox_env::MAIN_PROCESS_SPEC
        )
    });
}

pub(super) fn remove_path(value: &mut serde_json::Value, path: &[&str]) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut current = value;
    for key in parents {
        let Some(next) = current.get_mut(*key) else {
            return;
        };
        current = next;
    }
    if let Some(object) = current.as_object_mut() {
        object.remove(*last);
    }
}

pub(super) fn remove_path_if_value(
    value: &mut serde_json::Value,
    path: &[&str],
    expected: &serde_json::Value,
) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut current = value;
    for key in parents {
        let Some(next) = current.get_mut(*key) else {
            return;
        };
        current = next;
    }
    if current.get(*last) == Some(expected)
        && let Some(object) = current.as_object_mut()
    {
        object.remove(*last);
    }
}

pub(super) fn remove_empty_container_resources(container: &mut serde_json::Value) {
    if container
        .get("resources")
        .is_some_and(|resources| resources.as_object().is_some_and(serde_json::Map::is_empty))
        && let Some(object) = container.as_object_mut()
    {
        object.remove("resources");
    }
}

pub(super) fn remove_default_volume_mount_read_only(container: &mut serde_json::Value) {
    let Some(volume_mounts) = container
        .get_mut("volumeMounts")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for mount in volume_mounts {
        remove_path_if_value(mount, &["readOnly"], &serde_json::json!(false));
    }
}

pub(super) fn remove_empty_object_path(value: &mut serde_json::Value, path: &[&str]) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut current = value;
    for key in parents {
        let Some(next) = current.get_mut(*key) else {
            return;
        };
        current = next;
    }
    if current
        .get(*last)
        .is_some_and(|entry| entry.as_object().is_some_and(serde_json::Map::is_empty))
        && let Some(object) = current.as_object_mut()
    {
        object.remove(*last);
    }
}

pub(super) fn stable_json_fingerprint(value: &serde_json::Value) -> Result<String, String> {
    let canonical = canonical_json_value(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|err| format!("failed to serialize canonical template: {err}"))?;
    let digest = Sha256::digest(bytes);
    Ok(hex_encode(&digest))
}

pub(super) fn canonical_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical_json_value).collect())
        }
        serde_json::Value::Object(object) => {
            let mut sorted = serde_json::Map::new();
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                if let Some(value) = object.get(key) {
                    sorted.insert(key.clone(), canonical_json_value(value));
                }
            }
            serde_json::Value::Object(sorted)
        }
        other => other.clone(),
    }
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn string_at(data: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = data;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(super) fn sandbox_from_claim_object(
    default_namespace: &str,
    obj: DynamicObject,
) -> Result<Sandbox, String> {
    let kube_name = obj.metadata.name.clone().unwrap_or_default();
    if !is_openshell_managed(&obj) {
        debug!(object = %kube_name, "skipping SandboxClaim not managed by openshell");
        return Err(format!("SandboxClaim {kube_name} not managed by openshell"));
    }
    let id = sandbox_id_from_object(&obj)?;
    let Some(name) = annotation_or_label(&obj, LABEL_SANDBOX_NAME) else {
        return Err(format!("SandboxClaim {kube_name} missing sandbox name"));
    };
    let Some(workspace) = annotation_or_label(&obj, LABEL_SANDBOX_WORKSPACE) else {
        return Err(format!(
            "SandboxClaim {kube_name} missing sandbox workspace"
        ));
    };
    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| default_namespace.to_string());
    Ok(Sandbox {
        id,
        name,
        namespace,
        spec: None,
        status: Some(claim_status_from_object(&obj)),
        workspace,
    })
}

pub(super) fn claim_status_from_object(obj: &DynamicObject) -> SandboxStatus {
    let status_obj = obj
        .data
        .get("status")
        .and_then(serde_json::Value::as_object);
    let sandbox_name = status_obj
        .and_then(|status| status.get("sandbox"))
        .and_then(|value| value.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let instance_id = string_at(&obj.data, &["status", "sandbox", "podName"])
        .or_else(|| string_at(&obj.data, &["status", "sandbox", "agentPod"]))
        .or_else(|| string_at(&obj.data, &["status", "sandbox", "pod", "name"]))
        .unwrap_or_default();
    let conditions = status_obj
        .and_then(|status| status.get("conditions"))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(condition_from_value)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    SandboxStatus {
        sandbox_name,
        instance_id,
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions,
        deleting: obj.metadata.deletion_timestamp.is_some(),
    }
}

pub(super) fn update_claim_indexes(
    sandbox_name_to_id: &mut std::collections::HashMap<String, String>,
    agent_pod_to_id: &mut std::collections::HashMap<String, String>,
    claim_name: &str,
    sandbox: &Sandbox,
) {
    if !claim_name.is_empty() {
        sandbox_name_to_id.insert(claim_name.to_string(), sandbox.id.clone());
    }
    if let Some(status) = sandbox.status.as_ref() {
        if !status.sandbox_name.is_empty() {
            sandbox_name_to_id.insert(status.sandbox_name.clone(), sandbox.id.clone());
        }
        if !status.instance_id.is_empty() {
            agent_pod_to_id.insert(status.instance_id.clone(), sandbox.id.clone());
        }
    }
}
