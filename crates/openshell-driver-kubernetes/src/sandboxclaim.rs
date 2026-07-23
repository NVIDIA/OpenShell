// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes `SandboxClaim` activation support.

use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ApiResource, ListParams};
use kube::core::DynamicObject;
use kube::core::gvk::GroupVersionKind;
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_utils::LABEL_SANDBOX_ID;
use openshell_core::supervisor_bootstrap::{
    SupervisorBootstrapActivationRequest, SupervisorBootstrapActivator,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tonic::Code;
use tracing::{debug, info, warn};

const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);
const ACTIVATION_RETRY_ATTEMPTS: usize = 8;
const ACTIVATION_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);
const ACTIVATION_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const DRIVER_NAME: &str = "kubernetes";

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_VERSION_V1BETA1: &str = "v1beta1";
const SANDBOX_VERSION_V1ALPHA1: &str = "v1alpha1";
const SANDBOX_VERSIONS: &[&str] = &[SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1];
const SANDBOX_API_VERSION_FULL_V1BETA1: &str = "agents.x-k8s.io/v1beta1";
const SANDBOX_API_VERSION_FULL_V1ALPHA1: &str = "agents.x-k8s.io/v1alpha1";
const SANDBOX_POD_NAME_ANNOTATION: &str = "agents.x-k8s.io/pod-name";

const SANDBOX_CLAIM_GROUP: &str = "extensions.agents.x-k8s.io";
const SANDBOX_CLAIM_KIND: &str = "SandboxClaim";
const SANDBOX_CLAIM_VERSION_V1BETA1: &str = "v1beta1";

/// Watches Kubernetes `SandboxClaim` resources and activates pending
/// supervisor bootstrap streams after revalidating live driver state.
#[derive(Clone)]
pub struct SandboxClaimActivationController {
    client: Client,
    watch_client: Client,
    namespace: String,
}

impl SandboxClaimActivationController {
    #[must_use]
    pub fn new(client: Client, watch_client: Client, namespace: impl Into<String>) -> Self {
        Self {
            client,
            watch_client,
            namespace: namespace.into(),
        }
    }

    pub fn spawn(
        &self,
        activator: Arc<dyn SupervisorBootstrapActivator>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let controller = self.clone();
        tokio::spawn(async move {
            controller.run(activator, shutdown_rx).await;
        });
    }

    async fn run(
        self,
        activator: Arc<dyn SupervisorBootstrapActivator>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let claim_api = match self
            .supported_sandbox_claim_api(self.watch_client.clone())
            .await
        {
            Ok(api) => api,
            Err(err) => {
                debug!(
                    namespace = %self.namespace,
                    error = %err,
                    "SandboxClaim API is not available; warm-pool claim activation disabled"
                );
                return;
            }
        };

        let mut stream = watcher::watcher(claim_api.api, watcher::Config::default()).boxed();
        info!(
            namespace = %self.namespace,
            sandbox_claim_api_version = %claim_api.version,
            "Watching Kubernetes SandboxClaims for warm-pool activation"
        );

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                event = stream.try_next() => match event {
                    Ok(Some(Event::Applied(claim))) => {
                        self.handle_claim(claim, activator.as_ref()).await;
                    }
                    Ok(Some(Event::Restarted(claims))) => {
                        for claim in claims {
                            self.handle_claim(claim, activator.as_ref()).await;
                        }
                    }
                    Ok(Some(Event::Deleted(_))) => {}
                    Ok(None) => break,
                    Err(err) => {
                        warn!(
                            namespace = %self.namespace,
                            error = %err,
                            "SandboxClaim watch failed; warm-pool claim activation stopped"
                        );
                        break;
                    }
                }
            }
        }
    }

    async fn handle_claim(
        &self,
        claim: DynamicObject,
        activator: &(dyn SupervisorBootstrapActivator + '_),
    ) {
        let claim = match parse_sandbox_claim(&claim) {
            Ok(claim) => claim,
            Err(err) => {
                warn!(
                    namespace = %self.namespace,
                    error = %err,
                    "Ignoring invalid SandboxClaim"
                );
                return;
            }
        };
        debug!(
            namespace = %self.namespace,
            sandbox_claim = %claim.name,
            sandbox_claim_uid = %claim.uid,
            warm_pool = ?claim.warm_pool_name,
            sandbox_template = ?claim.sandbox_template_name,
            sandbox = ?claim.sandbox_name,
            pod_ips = ?claim.pod_ips,
            "Processing SandboxClaim for warm-pool activation"
        );
        let Some(sandbox_name) = claim.sandbox_name.as_deref() else {
            debug!(
                namespace = %self.namespace,
                sandbox_claim = %claim.name,
                "SandboxClaim has not selected a Sandbox yet"
            );
            return;
        };

        let sandbox_cr = match self.get_sandbox_cr(sandbox_name).await {
            Ok(Some(sandbox_cr)) => sandbox_cr,
            Ok(None) => {
                debug!(
                    namespace = %self.namespace,
                    sandbox_claim = %claim.name,
                    sandbox = %sandbox_name,
                    "SandboxClaim selected Sandbox is not available yet"
                );
                return;
            }
            Err(err) => {
                warn!(
                    namespace = %self.namespace,
                    sandbox_claim = %claim.name,
                    sandbox = %sandbox_name,
                    error = %err,
                    "Failed to read Sandbox selected by SandboxClaim"
                );
                return;
            }
        };

        let pod = match self.resolve_controlled_pod(&sandbox_cr).await {
            Ok(Some(pod)) => pod,
            Ok(None) => return,
            Err(err) => {
                warn!(
                    namespace = %self.namespace,
                    sandbox_claim = %claim.name,
                    sandbox = %sandbox_name,
                    error = %err,
                    "Failed to resolve Sandbox pod for SandboxClaim activation"
                );
                return;
            }
        };

        let request = match activation_request_from_claim_state(&claim, &sandbox_cr, &pod) {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(err) => {
                warn!(
                    namespace = %self.namespace,
                    sandbox_claim = %claim.name,
                    sandbox = %sandbox_name,
                    error = %err,
                    "SandboxClaim activation validation failed"
                );
                return;
            }
        };

        debug!(
            namespace = %self.namespace,
            sandbox_claim = %claim.name,
            sandbox = %sandbox_name,
            sandbox_id = %request.sandbox_id,
            instance_id = %request.instance_id,
            owner_uid = %request.owner_uid,
            pod = %pod.metadata.name.as_deref().unwrap_or_default(),
            "Resolved SandboxClaim activation target"
        );

        activate_registered_supervisor_with_retry(
            activator,
            request,
            ActivationLogContext {
                namespace: self.namespace.as_str(),
                sandbox_claim: claim.name.as_str(),
                sandbox: sandbox_name,
            },
            ACTIVATION_RETRY_ATTEMPTS,
            ACTIVATION_RETRY_INITIAL_DELAY,
            ACTIVATION_RETRY_MAX_DELAY,
        )
        .await;
    }

    fn sandbox_claim_api(&self, client: Client, version: &'static str) -> SandboxClaimApi {
        let gvk = GroupVersionKind::gvk(SANDBOX_CLAIM_GROUP, version, SANDBOX_CLAIM_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let api = Api::namespaced_with(client, &self.namespace, &resource);
        SandboxClaimApi { api, version }
    }

    async fn supported_sandbox_claim_api(&self, client: Client) -> Result<SandboxClaimApi, String> {
        let claim_api = self.sandbox_claim_api(client, SANDBOX_CLAIM_VERSION_V1BETA1);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            claim_api.api.list(&ListParams::default().limit(1)),
        )
        .await
        {
            Ok(Ok(_)) => Ok(claim_api),
            Ok(Err(err)) if should_try_next_api_version(&err) => Err(
                "SandboxClaim API extensions.agents.x-k8s.io/v1beta1 is not available".to_string(),
            ),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    fn sandbox_api(&self, client: Client, version: &'static str) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        Api::namespaced_with(client, &self.namespace, &resource)
    }

    async fn get_sandbox_cr(&self, name: &str) -> Result<Option<DynamicObject>, String> {
        for version in SANDBOX_VERSIONS {
            let sandbox_api = self.sandbox_api(self.client.clone(), version);
            match tokio::time::timeout(KUBE_API_TIMEOUT, sandbox_api.get(name)).await {
                Ok(Ok(sandbox_cr)) => return Ok(Some(sandbox_cr)),
                Ok(Err(KubeError::Api(err))) if err.code == 404 => {}
                Ok(Err(err)) if should_try_next_api_version(&err) => {}
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_) => {
                    return Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        Ok(None)
    }

    async fn resolve_controlled_pod(
        &self,
        sandbox_cr: &DynamicObject,
    ) -> Result<Option<Pod>, String> {
        let Some(owner_uid) = sandbox_cr.metadata.uid.as_deref() else {
            return Err("Sandbox CR is missing uid".to_string());
        };

        let pods_api: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        if let Some(pod_name) = sandbox_pod_name(sandbox_cr) {
            let pod = match tokio::time::timeout(KUBE_API_TIMEOUT, pods_api.get(&pod_name)).await {
                Ok(Ok(pod)) => pod,
                Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                    debug!(
                        namespace = %self.namespace,
                        sandbox = %sandbox_cr.metadata.name.as_deref().unwrap_or_default(),
                        sandbox_uid = %owner_uid,
                        pod = %pod_name,
                        "Annotated Sandbox pod was not found for SandboxClaim activation"
                    );
                    return Ok(None);
                }
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_) => {
                    return Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ));
                }
            };
            if !pod_has_sandbox_owner(&pod, owner_uid) {
                return Err(format!(
                    "annotated Sandbox pod {pod_name} is not controlled by the selected Sandbox"
                ));
            }
            return Ok(Some(pod));
        }

        let pods = match sandbox_selector(sandbox_cr) {
            Some(selector) => {
                let params = ListParams::default().labels(&selector);
                list_pods(&pods_api, &params).await?
            }
            None => list_pods(&pods_api, &ListParams::default()).await?,
        };

        let controlled = pods
            .into_iter()
            .filter(|pod| pod_has_sandbox_owner(pod, owner_uid))
            .collect::<Vec<_>>();

        match controlled.as_slice() {
            [pod] => Ok(Some(pod.clone())),
            [] => {
                debug!(
                    namespace = %self.namespace,
                    sandbox = %sandbox_cr.metadata.name.as_deref().unwrap_or_default(),
                    sandbox_uid = %owner_uid,
                    "No controlled pod found for SandboxClaim activation"
                );
                Ok(None)
            }
            _ => Err(format!(
                "expected one controlled Sandbox pod, found {}",
                controlled.len()
            )),
        }
    }
}

struct SandboxClaimApi {
    api: Api<DynamicObject>,
    version: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedSandboxClaim {
    name: String,
    uid: String,
    sandbox_id: Option<String>,
    warm_pool_name: Option<String>,
    sandbox_template_name: Option<String>,
    sandbox_name: Option<String>,
    pod_ips: Vec<String>,
}

struct ActivationLogContext<'a> {
    namespace: &'a str,
    sandbox_claim: &'a str,
    sandbox: &'a str,
}

async fn activate_registered_supervisor_with_retry(
    activator: &(dyn SupervisorBootstrapActivator + '_),
    request: SupervisorBootstrapActivationRequest,
    context: ActivationLogContext<'_>,
    attempts: usize,
    initial_delay: Duration,
    max_delay: Duration,
) {
    let attempts = attempts.max(1);
    let mut delay = initial_delay;

    for attempt in 1..=attempts {
        match activator
            .activate_registered_supervisor(request.clone())
            .await
        {
            Ok(()) => {
                info!(
                    namespace = %context.namespace,
                    sandbox_claim = %context.sandbox_claim,
                    sandbox = %context.sandbox,
                    sandbox_id = %request.sandbox_id,
                    instance_id = %request.instance_id,
                    attempt,
                    "Activated warm-pool supervisor from SandboxClaim"
                );
                return;
            }
            Err(status) if status.code() == Code::AlreadyExists => {
                debug!(
                    namespace = %context.namespace,
                    sandbox_claim = %context.sandbox_claim,
                    sandbox = %context.sandbox,
                    sandbox_id = %request.sandbox_id,
                    instance_id = %request.instance_id,
                    attempt,
                    "Warm-pool supervisor was already activated"
                );
                return;
            }
            Err(status) if status.code() == Code::NotFound && attempt < attempts => {
                debug!(
                    namespace = %context.namespace,
                    sandbox_claim = %context.sandbox_claim,
                    sandbox = %context.sandbox,
                    sandbox_id = %request.sandbox_id,
                    instance_id = %request.instance_id,
                    attempt,
                    retry_after_ms = delay.as_millis(),
                    "Warm-pool supervisor registration is not pending yet; retrying activation"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(max_delay);
            }
            Err(status) if status.code() == Code::NotFound => {
                debug!(
                    namespace = %context.namespace,
                    sandbox_claim = %context.sandbox_claim,
                    sandbox = %context.sandbox,
                    sandbox_id = %request.sandbox_id,
                    instance_id = %request.instance_id,
                    attempts,
                    "Warm-pool supervisor registration is not pending after retries"
                );
                return;
            }
            Err(status) => {
                warn!(
                    namespace = %context.namespace,
                    sandbox_claim = %context.sandbox_claim,
                    sandbox = %context.sandbox,
                    sandbox_id = %request.sandbox_id,
                    instance_id = %request.instance_id,
                    attempt,
                    code = ?status.code(),
                    message = %status.message(),
                    "Failed to activate warm-pool supervisor from SandboxClaim"
                );
                return;
            }
        }
    }
}

fn parse_sandbox_claim(obj: &DynamicObject) -> Result<ParsedSandboxClaim, String> {
    Ok(ParsedSandboxClaim {
        name: required_metadata_field(&obj.metadata.name, "name")?,
        uid: required_metadata_field(&obj.metadata.uid, "uid")?,
        sandbox_id: obj
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
            .filter(|id| !id.is_empty())
            .cloned(),
        warm_pool_name: string_at(&obj.data, &["spec", "warmPoolRef", "name"]),
        sandbox_template_name: string_at(&obj.data, &["spec", "sandboxTemplateRef", "name"]),
        sandbox_name: string_at(&obj.data, &["status", "sandbox", "name"]),
        pod_ips: strings_at(&obj.data, &["status", "sandbox", "podIPs"]),
    })
}

fn required_metadata_field(value: &Option<String>, field: &str) -> Result<String, String> {
    value
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| format!("SandboxClaim is missing metadata.{field}"))
}

fn activation_request_from_claim_state(
    claim: &ParsedSandboxClaim,
    sandbox_cr: &DynamicObject,
    pod: &Pod,
) -> Result<Option<SupervisorBootstrapActivationRequest>, String> {
    let Some(claim_sandbox_name) = claim.sandbox_name.as_deref() else {
        return Ok(None);
    };
    let sandbox_name = sandbox_cr.metadata.name.as_deref().unwrap_or_default();
    if sandbox_name != claim_sandbox_name {
        return Err(format!(
            "SandboxClaim selected Sandbox {claim_sandbox_name}, but live Sandbox is {sandbox_name}"
        ));
    }
    let owner_uid = sandbox_cr
        .metadata
        .uid
        .as_ref()
        .filter(|uid| !uid.is_empty())
        .cloned()
        .ok_or_else(|| "Sandbox CR is missing uid".to_string())?;
    let sandbox_id = sandbox_cr
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .filter(|id| !id.is_empty())
        .cloned()
        .or_else(|| claim.sandbox_id.clone())
        .ok_or_else(|| {
            "SandboxClaim and selected Sandbox are missing OpenShell sandbox id label".to_string()
        })?;
    let instance_id = pod
        .metadata
        .uid
        .as_ref()
        .filter(|uid| !uid.is_empty())
        .cloned()
        .ok_or_else(|| "Sandbox pod is missing uid".to_string())?;
    if !pod_has_sandbox_owner(pod, &owner_uid) {
        return Err("Sandbox pod is not controlled by the selected Sandbox".to_string());
    }

    Ok(Some(SupervisorBootstrapActivationRequest {
        driver: DRIVER_NAME.to_string(),
        instance_id,
        sandbox_id,
        owner_uid,
        reason: format!("SandboxClaim/{}", claim.name),
    }))
}

async fn list_pods(api: &Api<Pod>, params: &ListParams) -> Result<Vec<Pod>, String> {
    match tokio::time::timeout(KUBE_API_TIMEOUT, api.list(params)).await {
        Ok(Ok(list)) => Ok(list.items),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!(
            "timed out after {}s waiting for Kubernetes API",
            KUBE_API_TIMEOUT.as_secs()
        )),
    }
}

fn sandbox_selector(obj: &DynamicObject) -> Option<String> {
    string_at(&obj.data, &["status", "selector"])
}

fn sandbox_pod_name(obj: &DynamicObject) -> Option<String> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
        .filter(|pod_name| !pod_name.is_empty())
        .cloned()
}

fn pod_has_sandbox_owner(pod: &Pod, owner_uid: &str) -> bool {
    pod.metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|owner| is_supported_sandbox_owner_reference(owner) && owner.uid == owner_uid)
}

fn is_supported_sandbox_owner_reference(owner: &OwnerReference) -> bool {
    owner.kind == SANDBOX_KIND
        && owner.controller == Some(true)
        && matches!(
            owner.api_version.as_str(),
            SANDBOX_API_VERSION_FULL_V1BETA1 | SANDBOX_API_VERSION_FULL_V1ALPHA1
        )
}

fn should_try_next_api_version(err: &KubeError) -> bool {
    matches!(err, KubeError::Api(api) if api.code == 404)
}

fn string_at(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value, |current, segment| current.get(segment))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn strings_at(value: &serde_json::Value, path: &[&str]) -> Vec<String> {
    path.iter()
        .try_fold(value, |current, segment| current.get(segment))
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tonic::Status;
    use tonic::async_trait;

    struct FakeActivator {
        outcomes: Mutex<Vec<Result<(), Status>>>,
        requests: Mutex<Vec<SupervisorBootstrapActivationRequest>>,
    }

    impl FakeActivator {
        fn new(outcomes: Vec<Result<(), Status>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().expect("requests mutex poisoned").len()
        }
    }

    #[async_trait]
    impl SupervisorBootstrapActivator for FakeActivator {
        async fn activate_registered_supervisor(
            &self,
            request: SupervisorBootstrapActivationRequest,
        ) -> Result<(), Status> {
            self.requests
                .lock()
                .expect("requests mutex poisoned")
                .push(request);
            self.outcomes
                .lock()
                .expect("outcomes mutex poisoned")
                .remove(0)
        }
    }

    fn dynamic_object(
        group: &'static str,
        version: &'static str,
        kind: &'static str,
        name: &str,
        uid: &str,
        data: serde_json::Value,
    ) -> DynamicObject {
        let gvk = GroupVersionKind::gvk(group, version, kind);
        let resource = ApiResource::from_gvk(&gvk);
        let mut obj = DynamicObject::new(name, &resource);
        obj.metadata.uid = Some(uid.to_string());
        obj.data = data;
        obj
    }

    fn sandbox_cr(name: &str, uid: &str, sandbox_id: &str, version: &'static str) -> DynamicObject {
        let mut obj = dynamic_object(
            SANDBOX_GROUP,
            version,
            SANDBOX_KIND,
            name,
            uid,
            json!({"status": {"selector": "agents.x-k8s.io/sandbox=sandbox-a"}}),
        );
        obj.metadata
            .labels
            .get_or_insert_with(BTreeMap::new)
            .insert(LABEL_SANDBOX_ID.to_string(), sandbox_id.to_string());
        obj
    }

    fn sandbox_pod(name: &str, uid: &str, owner_uid: &str, api_version: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                uid: Some(uid.to_string()),
                owner_references: Some(vec![OwnerReference {
                    api_version: api_version.to_string(),
                    kind: SANDBOX_KIND.to_string(),
                    name: "sandbox-a".to_string(),
                    uid: owner_uid.to_string(),
                    controller: Some(true),
                    block_owner_deletion: None,
                }]),
                ..ObjectMeta::default()
            },
            ..Pod::default()
        }
    }

    #[test]
    fn parses_v1beta1_sandbox_claim_status() {
        let obj = dynamic_object(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION_V1BETA1,
            SANDBOX_CLAIM_KIND,
            "claim-a",
            "claim-uid",
            json!({
                "spec": {"warmPoolRef": {"name": "pool-a"}},
                "status": {
                    "sandbox": {
                        "name": "sandbox-a",
                        "podIPs": ["10.0.0.10", "fd00::10"]
                    }
                }
            }),
        );

        let claim = parse_sandbox_claim(&obj).unwrap();

        assert_eq!(claim.name, "claim-a");
        assert_eq!(claim.uid, "claim-uid");
        assert_eq!(claim.sandbox_id, None);
        assert_eq!(claim.warm_pool_name.as_deref(), Some("pool-a"));
        assert_eq!(claim.sandbox_name.as_deref(), Some("sandbox-a"));
        assert_eq!(claim.pod_ips, vec!["10.0.0.10", "fd00::10"]);
    }

    #[test]
    fn claim_without_selected_sandbox_does_not_activate() {
        let obj = dynamic_object(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION_V1BETA1,
            SANDBOX_CLAIM_KIND,
            "claim-a",
            "claim-uid",
            json!({"spec": {"warmPoolRef": {"name": "pool-a"}}}),
        );
        let claim = parse_sandbox_claim(&obj).unwrap();
        let sandbox = sandbox_cr(
            "sandbox-a",
            "sandbox-uid",
            "openshell-sandbox",
            SANDBOX_VERSION_V1BETA1,
        );
        let pod = sandbox_pod(
            "pod-a",
            "pod-uid",
            "sandbox-uid",
            SANDBOX_API_VERSION_FULL_V1BETA1,
        );

        assert_eq!(
            activation_request_from_claim_state(&claim, &sandbox, &pod).unwrap(),
            None
        );
    }

    #[test]
    fn activation_request_uses_live_sandbox_and_pod_identity() {
        let obj = dynamic_object(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION_V1BETA1,
            SANDBOX_CLAIM_KIND,
            "claim-a",
            "claim-uid",
            json!({
                "spec": {"warmPoolRef": {"name": "pool-a"}},
                "status": {"sandbox": {"name": "sandbox-a"}}
            }),
        );
        let claim = parse_sandbox_claim(&obj).unwrap();
        let sandbox = sandbox_cr(
            "sandbox-a",
            "sandbox-uid",
            "openshell-sandbox",
            SANDBOX_VERSION_V1ALPHA1,
        );
        let pod = sandbox_pod(
            "pod-a",
            "pod-uid",
            "sandbox-uid",
            SANDBOX_API_VERSION_FULL_V1ALPHA1,
        );

        let request = activation_request_from_claim_state(&claim, &sandbox, &pod)
            .unwrap()
            .unwrap();

        assert_eq!(request.driver, "kubernetes");
        assert_eq!(request.instance_id, "pod-uid");
        assert_eq!(request.sandbox_id, "openshell-sandbox");
        assert_eq!(request.owner_uid, "sandbox-uid");
        assert_eq!(request.reason, "SandboxClaim/claim-a");
    }

    #[test]
    fn activation_request_uses_claim_sandbox_id_when_sandbox_lacks_label() {
        let mut obj = dynamic_object(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION_V1BETA1,
            SANDBOX_CLAIM_KIND,
            "claim-a",
            "claim-uid",
            json!({"status": {"sandbox": {"name": "sandbox-a"}}}),
        );
        obj.metadata.labels = Some(BTreeMap::from([(
            LABEL_SANDBOX_ID.to_string(),
            "openshell-sandbox".to_string(),
        )]));
        let claim = parse_sandbox_claim(&obj).unwrap();
        let mut sandbox = sandbox_cr("sandbox-a", "sandbox-uid", "", SANDBOX_VERSION_V1BETA1);
        sandbox.metadata.labels = None;
        let pod = sandbox_pod(
            "pod-a",
            "pod-uid",
            "sandbox-uid",
            SANDBOX_API_VERSION_FULL_V1BETA1,
        );

        let request = activation_request_from_claim_state(&claim, &sandbox, &pod)
            .unwrap()
            .unwrap();

        assert_eq!(request.sandbox_id, "openshell-sandbox");
    }

    #[tokio::test]
    async fn activation_retry_handles_registration_after_claim_binding() {
        let activator = FakeActivator::new(vec![Err(Status::not_found("not pending")), Ok(())]);
        let request = SupervisorBootstrapActivationRequest {
            driver: DRIVER_NAME.to_string(),
            instance_id: "pod-uid".to_string(),
            sandbox_id: "sandbox-id".to_string(),
            owner_uid: "sandbox-uid".to_string(),
            reason: "SandboxClaim/claim-a".to_string(),
        };

        activate_registered_supervisor_with_retry(
            &activator,
            request,
            ActivationLogContext {
                namespace: "openshell",
                sandbox_claim: "claim-a",
                sandbox: "sandbox-a",
            },
            2,
            Duration::ZERO,
            Duration::ZERO,
        )
        .await;

        assert_eq!(activator.request_count(), 2);
    }

    #[test]
    fn activation_request_rejects_missing_sandbox_id_labels() {
        let obj = dynamic_object(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION_V1BETA1,
            SANDBOX_CLAIM_KIND,
            "claim-a",
            "claim-uid",
            json!({"status": {"sandbox": {"name": "sandbox-a"}}}),
        );
        let claim = parse_sandbox_claim(&obj).unwrap();
        let mut sandbox = sandbox_cr("sandbox-a", "sandbox-uid", "", SANDBOX_VERSION_V1BETA1);
        sandbox.metadata.labels = None;
        let pod = sandbox_pod(
            "pod-a",
            "pod-uid",
            "sandbox-uid",
            SANDBOX_API_VERSION_FULL_V1BETA1,
        );

        let err = activation_request_from_claim_state(&claim, &sandbox, &pod).unwrap_err();

        assert!(err.contains("missing OpenShell sandbox id label"));
    }

    #[test]
    fn activation_request_rejects_uncontrolled_pod() {
        let obj = dynamic_object(
            SANDBOX_CLAIM_GROUP,
            SANDBOX_CLAIM_VERSION_V1BETA1,
            SANDBOX_CLAIM_KIND,
            "claim-a",
            "claim-uid",
            json!({"status": {"sandbox": {"name": "sandbox-a"}}}),
        );
        let claim = parse_sandbox_claim(&obj).unwrap();
        let sandbox = sandbox_cr(
            "sandbox-a",
            "sandbox-uid",
            "openshell-sandbox",
            SANDBOX_VERSION_V1BETA1,
        );
        let pod = sandbox_pod(
            "pod-a",
            "pod-uid",
            "other-sandbox-uid",
            SANDBOX_API_VERSION_FULL_V1BETA1,
        );

        assert!(activation_request_from_claim_state(&claim, &sandbox, &pod).is_err());
    }

    #[test]
    fn sandbox_selector_reads_status_selector() {
        let sandbox = sandbox_cr(
            "sandbox-a",
            "sandbox-uid",
            "openshell-sandbox",
            SANDBOX_VERSION_V1BETA1,
        );

        assert_eq!(
            sandbox_selector(&sandbox).as_deref(),
            Some("agents.x-k8s.io/sandbox=sandbox-a")
        );
    }

    #[test]
    fn sandbox_pod_name_reads_pod_name_annotation() {
        let mut sandbox = sandbox_cr(
            "sandbox-a",
            "sandbox-uid",
            "openshell-sandbox",
            SANDBOX_VERSION_V1BETA1,
        );
        sandbox.metadata.annotations = Some(BTreeMap::from([(
            SANDBOX_POD_NAME_ANNOTATION.to_string(),
            "pod-a".to_string(),
        )]));

        assert_eq!(sandbox_pod_name(&sandbox).as_deref(), Some("pod-a"));
    }

    #[test]
    fn api_version_probe_retries_only_404_errors() {
        let unavailable = KubeError::Api(kube::core::ErrorResponse {
            status: "404 Not Found".to_string(),
            message: "could not find the requested resource".to_string(),
            reason: "NotFound".to_string(),
            code: 404,
        });
        let forbidden = KubeError::Api(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "forbidden".to_string(),
            reason: "Forbidden".to_string(),
            code: 403,
        });

        assert!(should_try_next_api_version(&unavailable));
        assert!(!should_try_next_api_version(&forbidden));
    }
}
