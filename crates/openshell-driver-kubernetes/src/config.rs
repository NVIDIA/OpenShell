// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

/// Default gateway identity used in managed-mode namespace naming.
pub const DEFAULT_GATEWAY_ID: &str = "openshell";

/// Default Kubernetes namespace for sandbox resources.
pub const DEFAULT_K8S_NAMESPACE: &str = "openshell";

/// Default Kubernetes `ServiceAccount` assigned to sandbox pods.
pub const DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME: &str = "default";

/// Default storage size for the workspace PVC.
pub const DEFAULT_WORKSPACE_STORAGE_SIZE: &str = "2Gi";

/// Default non-root UID for relaxed Kubernetes network supervisor sidecars.
pub const DEFAULT_PROXY_UID: u32 = 1337;

/// How the supervisor binary is delivered into sandbox pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorSideloadMethod {
    /// Mount the supervisor OCI image directly as a read-only volume
    /// (requires Kubernetes >= v1.33 with the `ImageVolume` feature gate,
    /// or >= v1.36 where it is GA).
    #[default]
    ImageVolume,
    /// Copy the binary via an init container and emptyDir volume.
    /// Works on all Kubernetes versions.
    InitContainer,
}

impl std::fmt::Display for SupervisorSideloadMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImageVolume => f.write_str("image-volume"),
            Self::InitContainer => f.write_str("init-container"),
        }
    }
}

impl FromStr for SupervisorSideloadMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "image-volume" => Ok(Self::ImageVolume),
            "init-container" => Ok(Self::InitContainer),
            other => Err(format!(
                "unknown supervisor sideload method '{other}'; expected 'image-volume' or 'init-container'"
            )),
        }
    }
}

/// How the supervisor is arranged inside Kubernetes sandbox pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorTopology {
    /// Run networking and process supervision in the agent container.
    #[default]
    Combined,
    /// Run network supervision in a privileged sidecar and process supervision
    /// as a low-capability wrapper in the agent container.
    Sidecar,
}

impl std::fmt::Display for SupervisorTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Combined => f.write_str("combined"),
            Self::Sidecar => f.write_str("sidecar"),
        }
    }
}

impl FromStr for SupervisorTopology {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "combined" => Ok(Self::Combined),
            "sidecar" => Ok(Self::Sidecar),
            other => Err(format!("unknown topology '{other}'")),
        }
    }
}

/// How workspaces map to Kubernetes namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceMode {
    /// All sandboxes render into a single statically-configured namespace.
    /// Resource names use `{workspace}--{name}` for collision avoidance.
    #[default]
    Shared,
    /// The driver creates and deletes K8s namespaces on demand using the
    /// convention `openshell-{gateway_id}-{workspace_name}`.
    Managed,
    /// Sandboxes render into pre-existing K8s namespaces. The driver has no
    /// namespace create/delete permissions. Platform teams manage namespaces
    /// via their existing tooling.
    Operator,
}

impl std::fmt::Display for WorkspaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared => f.write_str("shared"),
            Self::Managed => f.write_str("managed"),
            Self::Operator => f.write_str("operator"),
        }
    }
}

impl FromStr for WorkspaceMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "shared" => Ok(Self::Shared),
            "managed" => Ok(Self::Managed),
            "operator" => Ok(Self::Operator),
            other => Err(format!(
                "unknown workspace mode '{other}'; expected 'shared', 'managed', or 'operator'"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesSidecarConfig {
    /// UID used by relaxed long-running network sidecars in `sidecar`
    /// topology. The network init container installs nftables rules that
    /// exempt this UID, so it must not match the sandbox workload UID.
    /// Strict process/binary-aware sidecars run as UID 0 so Kubernetes grants
    /// the requested `/proc` inspection capabilities into the effective set.
    pub proxy_uid: u32,
    /// Require process/binary-aware network policy enforcement in sidecar
    /// topology. When disabled, the network sidecar runs as `proxy_uid`,
    /// drops the extra `/proc` inspection permissions, and evaluates
    /// endpoint/L7 policy without matching `policy.binaries`.
    pub process_binary_aware_network_policy: bool,
}

impl Default for KubernetesSidecarConfig {
    fn default() -> Self {
        Self {
            proxy_uid: DEFAULT_PROXY_UID,
            process_binary_aware_network_policy: true,
        }
    }
}

impl KubernetesSidecarConfig {
    pub fn validate_proxy_uid(&self) -> Result<(), String> {
        if !(openshell_policy::MIN_SANDBOX_PROXY_UID..=openshell_policy::MAX_SANDBOX_UID)
            .contains(&self.proxy_uid)
        {
            return Err(format!(
                "sidecar.proxy_uid must be in range [{}, {}]",
                openshell_policy::MIN_SANDBOX_PROXY_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        Ok(())
    }
}

/// Kubernetes `AppArmor` profile requested for the sandbox agent container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArmorProfile {
    RuntimeDefault,
    Unconfined,
    Localhost(String),
}

impl AppArmorProfile {
    #[must_use]
    pub fn to_k8s_type(&self) -> &'static str {
        match self {
            Self::RuntimeDefault => "RuntimeDefault",
            Self::Unconfined => "Unconfined",
            Self::Localhost(_) => "Localhost",
        }
    }

    #[must_use]
    pub fn localhost_profile(&self) -> Option<&str> {
        match self {
            Self::Localhost(profile) => Some(profile),
            Self::RuntimeDefault | Self::Unconfined => None,
        }
    }
}

impl std::fmt::Display for AppArmorProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeDefault => f.write_str("RuntimeDefault"),
            Self::Unconfined => f.write_str("Unconfined"),
            Self::Localhost(profile) => write!(f, "Localhost/{profile}"),
        }
    }
}

impl FromStr for AppArmorProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "RuntimeDefault" => Ok(Self::RuntimeDefault),
            "Unconfined" => Ok(Self::Unconfined),
            other => match other.strip_prefix("Localhost/") {
                Some("") => Err(
                    "invalid AppArmor profile 'Localhost/'; expected non-empty profile name"
                        .to_string(),
                ),
                Some(profile) => Ok(Self::Localhost(profile.to_string())),
                None => Err(format!(
                    "unknown AppArmor profile '{other}'; expected 'RuntimeDefault', 'Unconfined', or 'Localhost/<profile-name>'"
                )),
            },
        }
    }
}

impl Serialize for AppArmorProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AppArmorProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

fn deserialize_optional_app_armor_profile<'de, D>(
    deserializer: D,
) -> Result<Option<AppArmorProfile>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref() {
        None | Some("") => Ok(None),
        Some(value) => AppArmorProfile::from_str(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn deserialize_provider_spiffe_workload_api_socket_path<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_provider_spiffe_workload_api_socket_path_value(&value)
        .map_err(serde::de::Error::custom)?;
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesComputeConfig {
    /// How workspaces map to Kubernetes namespaces. `"shared"` (default)
    /// renders all sandboxes into `namespace`; `"managed"` creates per-workspace
    /// namespaces on demand; `"operator"` uses pre-provisioned namespaces.
    pub workspace_mode: WorkspaceMode,
    /// Stable gateway identity used in managed-mode namespace naming
    /// (`openshell-{gateway_id}-{workspace}`). Propagated from
    /// `gateway_jwt.gateway_id`.
    pub gateway_id: String,
    pub namespace: String,
    /// K8s label selector for operator-mode namespace discovery (e.g.,
    /// `"openshell.ai/workspace=true"`). The driver watches namespaces matching
    /// this label and builds the allowlist dynamically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_namespace_label: Option<String>,
    /// Path to a JSON file containing an array of namespace names allowed in
    /// operator mode. Hot-reloaded on change. Delivered via `ConfigMap` volume mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_namespace_file: Option<String>,
    /// Kubernetes `ServiceAccount` assigned to sandbox pods and accepted by
    /// the gateway's `TokenReview` bootstrap authenticator.
    pub service_account_name: String,
    pub default_image: String,
    pub image_pull_policy: String,
    /// Kubernetes `imagePullSecrets` names attached to sandbox pods.
    pub image_pull_secrets: Vec<String>,
    /// Managed-mode SSH ingress isolation. When enabled, the driver creates a
    /// `NetworkPolicy` in each managed workspace namespace that permits TCP 2222
    /// only from gateway pods matching this peer.
    pub managed_ssh_ingress: ManagedSshIngressConfig,
    /// Image that provides the `openshell-sandbox` supervisor binary.
    /// Mounted directly as an image volume, or copied via an init container,
    /// depending on `supervisor_sideload_method`.
    pub supervisor_image: String,
    /// Kubernetes `imagePullPolicy` for the supervisor image.
    /// Empty string delegates to the Kubernetes default.
    pub supervisor_image_pull_policy: String,
    /// How the supervisor binary is delivered into sandbox pods.
    pub supervisor_sideload_method: SupervisorSideloadMethod,
    /// How the supervisor is arranged for Kubernetes sandbox pods.
    pub topology: SupervisorTopology,
    /// Sidecar-only settings used when `topology = "sidecar"`.
    pub sidecar: KubernetesSidecarConfig,
    /// Corporate HTTP forward proxy used by the network supervisor for
    /// policy-approved TLS CONNECT egress.
    pub https_proxy: Option<String>,
    /// Comma-separated destinations that bypass the corporate proxy while
    /// continuing through `OpenShell` policy evaluation.
    pub no_proxy: Option<String>,
    /// Name of the Kubernetes Secret holding the `user:pass` proxy credential.
    /// The Secret is mounted only in the network-supervising container. The
    /// driver validates this reference at startup; the supervisor validates
    /// the Secret content when kubelet mounts it before accepting egress.
    pub proxy_auth_secret_name: Option<String>,
    /// Key in `proxy_auth_secret_name` containing the `user:pass` credential.
    pub proxy_auth_secret_key: Option<String>,
    /// Explicit acknowledgement that Basic authentication is cleartext over
    /// the connection to an `http://` forward proxy.
    pub proxy_auth_allow_insecure: Option<bool>,
    /// Send hostnames rather than validated IPs in CONNECT requests. This is a
    /// last-resort compatibility mode for hostname-filtering proxy ACLs.
    pub proxy_connect_by_hostname: Option<bool>,
    pub grpc_endpoint: String,
    pub ssh_socket_path: String,
    pub client_tls_secret_name: String,
    pub host_gateway_ip: String,
    pub enable_user_namespaces: bool,
    /// Kubernetes `AppArmor` profile requested for the sandbox agent container.
    /// Empty/None omits the `appArmorProfile` field from sandbox pod specs.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_app_armor_profile"
    )]
    pub app_armor_profile: Option<AppArmorProfile>,
    pub workspace_default_storage_size: String,
    /// Kubernetes `StorageClass` name for the default workspace PVC.
    /// Empty string (default) = omit `storageClassName`, using the cluster's
    /// default `StorageClass`. Set this on clusters with no default
    /// `StorageClass`, otherwise the workspace PVC stays `Pending` and the
    /// sandbox never starts.
    pub workspace_storage_class: String,
    /// Default Kubernetes `runtimeClassName` for sandbox pods.
    /// Applied when a `CreateSandbox` request does not specify one.
    /// Empty string (default) = omit the field, using the cluster default.
    pub default_runtime_class_name: String,
    /// Lifetime (seconds) of the projected `ServiceAccount` token kubelet
    /// writes into each sandbox pod. Used only for the one-shot
    /// `IssueSandboxToken` bootstrap exchange — the gateway-minted JWT
    /// that follows has its own TTL set via `gateway_jwt.ttl_secs`.
    ///
    /// Kubelet enforces a minimum of 600 seconds; the supervisor uses
    /// this token within a few seconds of pod start, so any value at
    /// the floor is sufficient. Default 3600.
    pub sa_token_ttl_secs: i64,
    /// SPIFFE Workload API socket path mounted into sandbox pods for dynamic
    /// provider token grants. Empty disables provider token-grant SPIFFE
    /// material.
    #[serde(
        default,
        deserialize_with = "deserialize_provider_spiffe_workload_api_socket_path"
    )]
    pub provider_spiffe_workload_api_socket_path: String,
    /// UID used for privilege-drop operations and workspace init container
    /// ownership. The supervisor container always runs as UID 0 (root) to
    /// create network namespaces and configure Landlock/seccomp; the
    /// `sandbox_uid` is injected as the `SANDBOX_UID` environment variable so
    /// the supervisor knows which UID to drop to for child processes.
    /// When empty, the driver auto-detects from `OpenShift` SCC annotations on
    /// the target namespace; if those are also absent, falls back to `1000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_uid: Option<u32>,
    /// GID used alongside `sandbox_uid` for PVC init container operations.
    /// When empty and `sandbox_uid` is set, defaults to the resolved UID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_gid: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagedSshIngressConfig {
    pub enabled: bool,
    pub gateway_namespace: String,
    pub gateway_pod_selector: BTreeMap<String, String>,
}

/// Lower bound enforced by kubelet for projected SA tokens.
pub const MIN_SA_TOKEN_TTL_SECS: i64 = 600;

/// Cap at 24h — operators who want longer-lived bootstrap tokens are
/// almost certainly misconfigured (the token is consumed seconds after
/// pod start).
pub const MAX_SA_TOKEN_TTL_SECS: i64 = 86_400;

/// Default sandbox UID used when neither config nor `OpenShift` SCC annotations
/// provide a resolved value.
pub(crate) const DEFAULT_SANDBOX_UID: u32 = 1000;

/// The annotation key for the `OpenShift` `ServiceAccount` UID range.
/// Format: `<start>/<size>` (e.g. `1000000000/10000`).
pub const ANNOTATION_SCC_UID_RANGE: &str = "openshift.io/sa.scc.uid-range";

/// The annotation key for the `OpenShift` `ServiceAccount` supplemental groups.
/// Format: `<start>/<size>` (e.g. `1000000000/10000`).
pub const ANNOTATION_SCC_SUPPLEMENTAL_GROUPS: &str = "openshift.io/sa.scc.supplemental-groups";

impl Default for KubernetesComputeConfig {
    fn default() -> Self {
        Self {
            workspace_mode: WorkspaceMode::default(),
            gateway_id: DEFAULT_GATEWAY_ID.to_string(),
            namespace: DEFAULT_K8S_NAMESPACE.to_string(),
            operator_namespace_label: None,
            operator_namespace_file: None,
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME.to_string(),
            default_image: openshell_core::image::default_sandbox_image(),
            // Default empty so the gateway omits `imagePullPolicy` from pod
            // specs and Kubernetes applies its own default (Always for `latest`,
            // IfNotPresent otherwise). `DEFAULT_IMAGE_PULL_POLICY` ("missing")
            // is Podman vocabulary and is not a valid Kubernetes value.
            image_pull_policy: String::new(),
            image_pull_secrets: Vec::new(),
            managed_ssh_ingress: ManagedSshIngressConfig::default(),
            supervisor_image: config::default_supervisor_image(),
            supervisor_image_pull_policy: String::new(),
            supervisor_sideload_method: SupervisorSideloadMethod::default(),
            topology: SupervisorTopology::default(),
            sidecar: KubernetesSidecarConfig::default(),
            https_proxy: None,
            no_proxy: None,
            proxy_auth_secret_name: None,
            proxy_auth_secret_key: None,
            proxy_auth_allow_insecure: None,
            proxy_connect_by_hostname: None,
            grpc_endpoint: String::new(),
            ssh_socket_path: openshell_core::container_paths::SSH_SOCKET_PATH.to_string(),
            client_tls_secret_name: String::new(),
            host_gateway_ip: String::new(),
            enable_user_namespaces: false,
            app_armor_profile: None,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE.to_string(),
            workspace_storage_class: String::new(),
            default_runtime_class_name: String::new(),
            sa_token_ttl_secs: 3600,
            provider_spiffe_workload_api_socket_path: String::new(),
            sandbox_uid: None,
            sandbox_gid: None,
        }
    }
}

impl KubernetesComputeConfig {
    /// Clamp `sa_token_ttl_secs` into the `[MIN_SA_TOKEN_TTL_SECS,
    /// MAX_SA_TOKEN_TTL_SECS]` range used by the projected-volume spec.
    /// Invalid (≤0) values fall back to the default 3600.
    #[must_use]
    pub fn effective_sa_token_ttl_secs(&self) -> i64 {
        if self.sa_token_ttl_secs <= 0 {
            3600
        } else {
            self.sa_token_ttl_secs
                .clamp(MIN_SA_TOKEN_TTL_SECS, MAX_SA_TOKEN_TTL_SECS)
        }
    }

    #[must_use]
    pub fn provider_spiffe_enabled(&self) -> bool {
        !self
            .provider_spiffe_workload_api_socket_path
            .trim()
            .is_empty()
    }

    pub fn validate_provider_spiffe_workload_api_socket_path(&self) -> Result<(), String> {
        validate_provider_spiffe_workload_api_socket_path_value(
            &self.provider_spiffe_workload_api_socket_path,
        )
    }

    pub fn validate_proxy_uid(&self) -> Result<(), String> {
        self.sidecar.validate_proxy_uid()
    }

    /// Validate the operator-owned corporate upstream proxy configuration.
    pub fn validate_upstream_proxy_config(&self) -> Result<(), String> {
        use openshell_core::driver_utils::{UpstreamProxyUrlError, parse_upstream_proxy_url};

        if let Some(url) = &self.https_proxy {
            parse_upstream_proxy_url(url).map_err(|err| match err {
                UpstreamProxyUrlError::Empty => "https_proxy must not be empty when set".to_string(),
                UpstreamProxyUrlError::InlineCredentials => "https_proxy must not embed credentials in the URL; supply them through proxy_auth_secret_name and proxy_auth_secret_key".to_string(),
                err => format!("https_proxy {err}"),
            })?;
        }

        if let Some(list) = self.no_proxy.as_deref() {
            if list.trim().is_empty() {
                return Err("no_proxy must not be empty when set; omit it instead".to_string());
            }
            if self.https_proxy.is_none() {
                return Err("no_proxy is set but no https_proxy is configured".to_string());
            }
        }

        let secret_name = self.proxy_auth_secret_name.as_deref();
        let secret_key = self.proxy_auth_secret_key.as_deref();
        match (secret_name, secret_key) {
            (None, None) => {
                if self.proxy_auth_allow_insecure == Some(true) {
                    return Err("proxy_auth_allow_insecure is set but no proxy credential Secret is configured".to_string());
                }
            }
            (Some(name), Some(key)) => {
                if name.trim().is_empty() || key.trim().is_empty() {
                    return Err(
                        "proxy credential Secret name and key must not be empty".to_string()
                    );
                }
                if !is_dns1123_subdomain(name) {
                    return Err(
                        "proxy_auth_secret_name must be a valid Kubernetes DNS-1123 subdomain"
                            .to_string(),
                    );
                }
                if !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
                {
                    return Err(
                        "proxy_auth_secret_key must contain only letters, digits, '.', '-', or '_'"
                            .to_string(),
                    );
                }
                // Kubernetes rejects Secret keys longer than 253 bytes and the
                // reserved `.`/`..` names. Reject them here so an invalid
                // deployment setting fails at gateway startup instead of
                // surfacing as repeated Pod-provisioning failures.
                if key.len() > 253 {
                    return Err(
                        "proxy_auth_secret_key must be at most 253 bytes to satisfy Kubernetes Secret key limits"
                            .to_string(),
                    );
                }
                if key == "." || key == ".." {
                    return Err("proxy_auth_secret_key must not be '.' or '..'".to_string());
                }
                if self.https_proxy.is_none() {
                    return Err(
                        "proxy credential Secret is set but no https_proxy is configured"
                            .to_string(),
                    );
                }
                if self.proxy_auth_allow_insecure != Some(true) {
                    return Err("proxy credentials use cleartext Basic auth over the connection to the http:// proxy; set proxy_auth_allow_insecure = true to accept that exposure, or remove the credential Secret".to_string());
                }
                if self.topology == SupervisorTopology::Combined {
                    return Err(
                        "proxy credential Secrets require topology = \"sidecar\"; combined topology shares the credential mount with the workload and fsGroup can make it readable by the sandbox user"
                            .to_string(),
                    );
                }
            }
            _ => {
                return Err(
                    "proxy_auth_secret_name and proxy_auth_secret_key must be set together"
                        .to_string(),
                );
            }
        }

        if self.proxy_connect_by_hostname.is_some() && self.https_proxy.is_none() {
            return Err(
                "proxy_connect_by_hostname is set but no https_proxy is configured".to_string(),
            );
        }
        Ok(())
    }

    /// Resolve the sandbox UID/GID pair.
    ///
    /// Resolution order:
    /// 1. Configured `sandbox_uid` / `sandbox_gid` (explicit override)
    /// 2. `OpenShift` SCC namespace annotations (`sa.scc.uid-range`,
    ///    `sa.scc.supplemental-groups`) — passed in as the optional
    ///    `namespace_annotations` map
    /// 3. Fallback defaults: UID=`1000`, GID=UID
    pub fn resolve_sandbox_uid(
        &self,
        namespace_annotations: Option<&BTreeMap<String, String>>,
    ) -> u32 {
        if let Some(uid) = self.sandbox_uid {
            return uid;
        }
        // Try OpenShift SCC annotation.
        if let Some(anns) = namespace_annotations
            && let Some(range) = anns.get(ANNOTATION_SCC_UID_RANGE)
            && let Some(uid) = Self::from_open_shift_uid_range(range)
        {
            return uid;
        }
        DEFAULT_SANDBOX_UID
    }

    pub fn resolve_sandbox_gid(
        &self,
        resolved_uid: u32,
        _namespace_annotations: Option<&BTreeMap<String, String>>,
    ) -> u32 {
        self.sandbox_gid
            .or(self.sandbox_uid)
            .unwrap_or(resolved_uid)
    }

    /// Parse `OpenShift` SCC `sa.scc.uid-range` annotation.
    ///
    /// Format: `<start>/<size>` (e.g. `1000000000/10000`).
    pub fn from_open_shift_uid_range(annotation: &str) -> Option<u32> {
        let (start, _) = annotation.split_once('/')?;
        start.trim().parse::<u32>().ok().filter(|&uid| {
            (openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID).contains(&uid)
        })
    }

    /// Parse `OpenShift` SCC `sa.scc.supplemental-groups` annotation.
    pub fn from_open_shift_supplemental_groups(annotation: &str) -> Option<u32> {
        let (start, _) = annotation.split_once('/')?;
        start.trim().parse::<u32>().ok().filter(|&gid| {
            (openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID).contains(&gid)
        })
    }

    /// Validate that configured `sandbox_uid` and `sandbox_gid` fall within
    /// the policy-enforced UID/GID range. Called during driver initialization
    /// before any pod parameters are rendered.
    pub fn validate_sandbox_identity_config(&self) -> Result<(), String> {
        let range = openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID;
        if let Some(uid) = self.sandbox_uid
            && !range.contains(&uid)
        {
            return Err(format!(
                "sandbox_uid {uid} is outside the allowed range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        if let Some(gid) = self.sandbox_gid
            && !range.contains(&gid)
        {
            return Err(format!(
                "sandbox_gid {gid} is outside the allowed range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        Ok(())
    }

    /// Resolve the K8s namespace for a workspace.
    ///
    /// - **Shared:** returns the static `namespace` config field.
    /// - **Managed:** computes `openshell-{gateway_id}-{workspace_name}`.
    /// - **Operator:** looks up `workspace` in the dynamic allowlist. Fails
    ///   closed if the workspace is not found.
    pub fn namespace_for_workspace(
        &self,
        workspace: &str,
        operator_allowlist: Option<&OperatorNamespaceAllowlist>,
    ) -> Result<String, String> {
        match self.workspace_mode {
            WorkspaceMode::Shared => Ok(self.namespace.clone()),
            WorkspaceMode::Managed => Ok(managed_namespace(&self.gateway_id, workspace)),
            WorkspaceMode::Operator => {
                let allowlist =
                    operator_allowlist.ok_or("operator mode requires a namespace allowlist")?;
                let namespaces = allowlist.read();
                if namespaces.contains(workspace) {
                    Ok(workspace.to_string())
                } else {
                    Err(format!(
                        "workspace '{workspace}' is not in the operator namespace allowlist"
                    ))
                }
            }
        }
    }

    /// Whether the driver operates across multiple namespaces.
    #[must_use]
    pub fn is_multi_namespace(&self) -> bool {
        !matches!(self.workspace_mode, WorkspaceMode::Shared)
    }

    /// Compute the K8s resource name for a sandbox.
    ///
    /// - **Shared:** `{workspace}--{name}` (namespace doesn't provide isolation).
    /// - **Managed/Operator:** bare sandbox name (namespace provides isolation).
    #[must_use]
    pub fn kube_resource_name(&self, workspace: &str, name: &str) -> String {
        match self.workspace_mode {
            WorkspaceMode::Shared => format!("{workspace}--{name}"),
            WorkspaceMode::Managed | WorkspaceMode::Operator => name.to_string(),
        }
    }

    /// Validate workspace-mode-specific configuration at startup.
    pub fn validate_workspace_mode(&self) -> Result<(), String> {
        match self.workspace_mode {
            WorkspaceMode::Shared => Ok(()),
            WorkspaceMode::Managed => {
                if self.gateway_id.is_empty() {
                    return Err("managed workspace mode requires a non-empty gateway_id".into());
                }
                if !is_dns_1123_label(&self.gateway_id) {
                    return Err(format!(
                        "gateway_id '{}' is not a valid DNS-1123 label",
                        self.gateway_id
                    ));
                }
                // Workspace names can be up to 19 chars (MAX_ROUTABLE_NAME_LEN
                // in the server crate). The managed namespace prefix +
                // workspace must fit within 63 chars.
                let prefix = managed_namespace_prefix(&self.gateway_id);
                if prefix.len() + 19 > 63 {
                    return Err(format!(
                        "gateway_id '{}' is too long for managed mode; \
                         the namespace prefix '{}' ({} chars) plus the \
                         maximum workspace name (19 chars) exceeds the \
                         63-char K8s namespace limit",
                        self.gateway_id,
                        prefix,
                        prefix.len()
                    ));
                }
                if self.managed_ssh_ingress.enabled {
                    if self.managed_ssh_ingress.gateway_namespace.is_empty() {
                        return Err(
                            "managed SSH ingress isolation requires gateway_namespace".into()
                        );
                    }
                    if self.managed_ssh_ingress.gateway_pod_selector.is_empty() {
                        return Err(
                            "managed SSH ingress isolation requires gateway_pod_selector".into(),
                        );
                    }
                }
                Ok(())
            }
            WorkspaceMode::Operator => {
                if self.operator_namespace_label.is_none() && self.operator_namespace_file.is_none()
                {
                    return Err("operator workspace mode requires exactly one of \
                         operator_namespace_label or operator_namespace_file"
                        .into());
                }
                if self.operator_namespace_label.is_some() && self.operator_namespace_file.is_some()
                {
                    return Err("operator workspace mode requires exactly one of \
                         operator_namespace_label or operator_namespace_file, not both"
                        .into());
                }
                if let Some(ref label) = self.operator_namespace_label
                    && label.is_empty()
                {
                    return Err("operator_namespace_label must not be empty when set".into());
                }
                if let Some(ref file) = self.operator_namespace_file
                    && file.is_empty()
                {
                    return Err("operator_namespace_file must not be empty when set".into());
                }
                Ok(())
            }
        }
    }
}

/// Compute the managed-mode namespace name for a workspace.
#[must_use]
pub fn managed_namespace(gateway_id: &str, workspace: &str) -> String {
    format!("openshell-{gateway_id}-{workspace}")
}

/// The managed-mode namespace prefix used for SA token validation.
#[must_use]
pub fn managed_namespace_prefix(gateway_id: &str) -> String {
    format!("openshell-{gateway_id}-")
}

/// Check whether a string is a valid DNS-1123 label (lowercase alphanumeric
/// and hyphens, 1-63 chars, must start and end with alphanumeric).
#[must_use]
pub fn is_dns_1123_label(s: &str) -> bool {
    let len = s.len();
    if len == 0 || len > 63 {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[len - 1].is_ascii_lowercase() && !bytes[len - 1].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate that a workspace name produces a valid K8s namespace name in
/// managed mode (combined length <= 63, DNS-1123 compliant).
pub fn validate_managed_namespace_name(gateway_id: &str, workspace: &str) -> Result<(), String> {
    let ns = managed_namespace(gateway_id, workspace);
    if !is_dns_1123_label(&ns) {
        return Err(format!(
            "managed namespace '{ns}' (from workspace '{workspace}') is not a valid DNS-1123 label"
        ));
    }
    Ok(())
}

/// Thread-safe dynamic allowlist of valid operator-mode namespaces.
///
/// Backed by an `Arc<RwLock<BTreeSet<String>>>` that is updated by background
/// tasks (label selector watcher, drop-in file watcher) and read by the SA
/// authenticator and namespace resolver.
#[derive(Debug, Clone)]
pub struct OperatorNamespaceAllowlist {
    inner: Arc<RwLock<BTreeSet<String>>>,
}

impl OperatorNamespaceAllowlist {
    fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<String>> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, BTreeSet<String>> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    #[must_use]
    pub fn from_set(set: BTreeSet<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(set)),
        }
    }

    /// Replace the entire allowlist (used by background watchers on refresh).
    pub fn replace(&self, new_set: BTreeSet<String>) {
        let mut guard = self.write_guard();
        *guard = new_set;
    }

    /// Merge additional namespaces into the allowlist.
    pub fn merge(&self, additional: &BTreeSet<String>) {
        let mut guard = self.write_guard();
        guard.extend(additional.iter().cloned());
    }

    /// Read the current allowlist snapshot.
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<String>> {
        self.read_guard()
    }

    /// Check whether a namespace is in the allowlist.
    #[must_use]
    pub fn contains(&self, namespace: &str) -> bool {
        self.read_guard().contains(namespace)
    }

    /// Insert a namespace into the allowlist. Returns `true` if it was new.
    pub fn insert(&self, name: String) -> bool {
        self.write_guard().insert(name)
    }

    /// Remove a namespace from the allowlist. Returns `true` if it was present.
    pub fn remove(&self, name: &str) -> bool {
        self.write_guard().remove(name)
    }

    /// Return a clone of the inner `Arc` for sharing with background tasks.
    #[must_use]
    pub fn shared(&self) -> Arc<RwLock<BTreeSet<String>>> {
        Arc::clone(&self.inner)
    }
}

impl Default for OperatorNamespaceAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

fn is_dns1123_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn validate_provider_spiffe_workload_api_socket_path_value(
    socket_path: &str,
) -> Result<(), String> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed != socket_path {
        return Err(
            "provider_spiffe_workload_api_socket_path must not contain leading or trailing whitespace"
                .to_string(),
        );
    }
    let path = Path::new(socket_path);
    if !path.is_absolute() {
        return Err(
            "provider_spiffe_workload_api_socket_path must be an absolute UNIX socket path"
                .to_string(),
        );
    }
    let parent = path.parent().ok_or_else(|| {
        "provider_spiffe_workload_api_socket_path must include a parent directory".to_string()
    })?;
    if parent == Path::new("/") {
        return Err(
            "provider_spiffe_workload_api_socket_path must live below a dedicated directory"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as HashMap;

    #[test]
    fn default_workspace_storage_size_is_2gi() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.workspace_default_storage_size,
            DEFAULT_WORKSPACE_STORAGE_SIZE
        );
    }

    #[test]
    fn default_workspace_storage_class_is_empty() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.workspace_storage_class.is_empty());
    }

    #[test]
    fn default_topology_is_combined() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(cfg.topology, SupervisorTopology::Combined);
        assert_eq!(cfg.topology.to_string(), "combined");
    }

    #[test]
    fn default_proxy_uid_is_dedicated_non_root_uid() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(cfg.sidecar.proxy_uid, DEFAULT_PROXY_UID);
    }

    #[test]
    fn default_sidecar_requires_process_binary_aware_network_policy() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.sidecar.process_binary_aware_network_policy);
    }

    #[test]
    fn serde_override_topology_sidecar() {
        let json = serde_json::json!({
            "topology": "sidecar"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.topology, SupervisorTopology::Sidecar);
    }

    #[test]
    fn serde_override_topology_combined() {
        let json = serde_json::json!({
            "topology": "combined"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.topology, SupervisorTopology::Combined);
    }

    #[test]
    fn serde_rejects_sidecar_binary_identity_field() {
        let json = serde_json::json!({
            "sidecar": {
                "binary_identity": "shared-pid"
            }
        });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn serde_override_sidecar_process_binary_aware_network_policy_nested() {
        let json = serde_json::json!({
            "sidecar": {
                "process_binary_aware_network_policy": false
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert!(!cfg.sidecar.process_binary_aware_network_policy);
    }

    #[test]
    fn serde_override_sidecar_proxy_uid_nested() {
        let json = serde_json::json!({
            "sidecar": {
                "proxy_uid": 2000
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.sidecar.proxy_uid, 2000);
        cfg.validate_proxy_uid().unwrap();
    }

    #[test]
    fn validate_proxy_uid_rejects_privileged_uid() {
        let cfg = KubernetesComputeConfig {
            sidecar: KubernetesSidecarConfig {
                proxy_uid: 999,
                ..KubernetesSidecarConfig::default()
            },
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_proxy_uid().unwrap_err();
        assert!(err.contains("proxy_uid"));
    }

    #[test]
    fn serde_rejects_invalid_topology() {
        let json = serde_json::json!({
            "topology": "unsupported"
        });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_removed_topology_alias_field() {
        let mut json = serde_json::Map::new();
        json.insert(
            ["supervisor", "topology"].join("_"),
            serde_json::json!("sidecar"),
        );
        let err =
            serde_json::from_value::<KubernetesComputeConfig>(serde_json::Value::Object(json))
                .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn serde_rejects_removed_flat_sidecar_fields() {
        for json in [
            serde_json::json!({ "sidecar_binary_identity": "shared-pid" }),
            serde_json::json!({ "proxy_uid": 2000 }),
        ] {
            let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
            assert!(err.to_string().contains("unknown field"));
        }
    }

    #[test]
    fn serde_rejects_removed_process_enforcement_field() {
        let json = serde_json::json!({
            "process_enforcement": "network-only"
        });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn default_service_account_name_is_default() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.service_account_name,
            DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
        );
    }

    #[test]
    fn serde_override_workspace_storage_size() {
        let json = serde_json::json!({
            "workspace_default_storage_size": "10Gi"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.workspace_default_storage_size, "10Gi");
    }

    #[test]
    fn serde_override_workspace_storage_class() {
        let json = serde_json::json!({
            "workspace_storage_class": "fast-ssd"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.workspace_storage_class, "fast-ssd");
    }

    #[test]
    fn serde_override_service_account_name() {
        let json = serde_json::json!({
            "service_account_name": "openshell-sandbox"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.service_account_name, "openshell-sandbox");
    }

    #[test]
    fn serde_override_default_runtime_class_name() {
        let json = serde_json::json!({
            "default_runtime_class_name": "nvidia"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.default_runtime_class_name, "nvidia");
    }

    #[test]
    fn default_runtime_class_name_is_empty() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.default_runtime_class_name.is_empty());
    }

    #[test]
    fn default_app_armor_profile_is_none() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.app_armor_profile.is_none());
    }

    #[test]
    fn serde_override_app_armor_profile_unconfined() {
        let json = serde_json::json!({
            "app_armor_profile": "Unconfined"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.app_armor_profile, Some(AppArmorProfile::Unconfined));
    }

    #[test]
    fn serde_override_app_armor_profile_runtime_default() {
        let json = serde_json::json!({
            "app_armor_profile": "RuntimeDefault"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.app_armor_profile, Some(AppArmorProfile::RuntimeDefault));
    }

    #[test]
    fn serde_override_app_armor_profile_localhost() {
        let json = serde_json::json!({
            "app_armor_profile": "Localhost/openshell-supervisor"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            cfg.app_armor_profile,
            Some(AppArmorProfile::Localhost(
                "openshell-supervisor".to_string()
            ))
        );
    }

    #[test]
    fn serde_empty_app_armor_profile_disables_field() {
        let json = serde_json::json!({
            "app_armor_profile": ""
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.app_armor_profile, None);
    }

    #[test]
    fn serde_accepts_absolute_provider_spiffe_socket_path() {
        let json = serde_json::json!({
            "provider_spiffe_workload_api_socket_path": "/spiffe-workload-api/spire-agent.sock"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        cfg.validate_provider_spiffe_workload_api_socket_path()
            .unwrap();
    }

    #[test]
    fn serde_rejects_invalid_provider_spiffe_socket_path() {
        for socket_path in [
            "spiffe-workload-api/spire-agent.sock",
            "/spire-agent.sock",
            " /spiffe-workload-api/spire-agent.sock",
        ] {
            let json = serde_json::json!({
                "provider_spiffe_workload_api_socket_path": socket_path
            });
            let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
            assert!(
                err.to_string()
                    .contains("provider_spiffe_workload_api_socket_path"),
                "unexpected error for {socket_path}: {err}"
            );
        }
    }

    #[test]
    fn serde_rejects_invalid_app_armor_profile() {
        let json = serde_json::json!({
            "app_armor_profile": "runtime/default"
        });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown AppArmor profile"));
    }

    #[test]
    fn serde_override_image_pull_secrets() {
        let json = serde_json::json!({
            "image_pull_secrets": ["regcred", "backup-regcred"]
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.image_pull_secrets, ["regcred", "backup-regcred"]);
    }

    #[test]
    fn default_sandbox_uid_and_gid_are_none() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(cfg.sandbox_uid, None);
        assert_eq!(cfg.sandbox_gid, None);
    }

    #[test]
    fn serde_override_sandbox_uid() {
        let json = serde_json::json!({
            "sandbox_uid": 1500
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.sandbox_uid, Some(1500));
    }

    #[test]
    fn serde_override_sandbox_gid() {
        let json = serde_json::json!({
            "sandbox_gid": 2000
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.sandbox_gid, Some(2000));
    }

    #[test]
    fn parse_openshift_uid_range() {
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("1000000000/10000"),
            Some(1_000_000_000)
        );
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("1000/50000"),
            Some(1000)
        );
    }

    #[test]
    fn parse_openshift_uid_range_accepts_non_root_system_uid() {
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("999/50000"),
            Some(999)
        );
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("1/50000"),
            Some(1)
        );
    }

    #[test]
    fn parse_openshift_uid_range_rejects_root() {
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("0/50000"),
            None
        );
    }

    #[test]
    fn parse_openshift_uid_range_rejects_above_max() {
        // u32::MAX is the invalid identity sentinel.
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("4294967295/10000"),
            None
        );
    }

    #[test]
    fn validate_sandbox_identity_config_accepts_valid_range() {
        let cfg = KubernetesComputeConfig {
            sandbox_uid: Some(500),
            sandbox_gid: Some(30),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_sandbox_identity_config().is_ok());
    }

    #[test]
    fn validate_sandbox_identity_config_rejects_uid_zero() {
        let cfg = KubernetesComputeConfig {
            sandbox_uid: Some(0),
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_sandbox_identity_config().unwrap_err();
        assert!(err.contains("sandbox_uid"));
    }

    #[test]
    fn validate_sandbox_identity_config_rejects_gid_above_max() {
        let cfg = KubernetesComputeConfig {
            sandbox_gid: Some(openshell_policy::MAX_SANDBOX_UID + 1),
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_sandbox_identity_config().unwrap_err();
        assert!(err.contains("sandbox_gid"));
    }

    #[test]
    fn validate_sandbox_identity_config_accepts_none_fields() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.validate_sandbox_identity_config().is_ok());
    }

    #[test]
    fn parse_openshift_supplemental_groups() {
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_supplemental_groups("1000/50000"),
            Some(1000)
        );
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_supplemental_groups("30/50000"),
            Some(30)
        );
    }

    #[test]
    fn resolve_sandbox_uid_prefers_config() {
        let cfg = KubernetesComputeConfig {
            sandbox_uid: Some(5000),
            ..KubernetesComputeConfig::default()
        };
        // Config value should win even when annotations are present.
        let mut anns: HashMap<String, String> = HashMap::new();
        anns.insert(
            ANNOTATION_SCC_UID_RANGE.to_string(),
            "1000000000/10000".to_string(),
        );
        assert_eq!(cfg.resolve_sandbox_uid(Some(&anns)), 5000);
    }

    #[test]
    fn resolve_sandbox_uid_falls_back_to_openshift_annotation() {
        let cfg = KubernetesComputeConfig::default();
        let mut anns: HashMap<String, String> = HashMap::new();
        anns.insert(
            ANNOTATION_SCC_UID_RANGE.to_string(),
            "1000000000/10000".to_string(),
        );
        assert_eq!(cfg.resolve_sandbox_uid(Some(&anns)), 1_000_000_000);
    }

    #[test]
    fn resolve_sandbox_uid_falls_back_to_default() {
        let cfg = KubernetesComputeConfig::default();
        // No config, no annotations.
        assert_eq!(cfg.resolve_sandbox_uid(None), DEFAULT_SANDBOX_UID);
        // Empty annotations map.
        let anns: HashMap<String, String> = HashMap::new();
        assert_eq!(cfg.resolve_sandbox_uid(Some(&anns)), DEFAULT_SANDBOX_UID);
    }

    #[test]
    fn resolve_sandbox_gid_prefers_config() {
        let cfg = KubernetesComputeConfig {
            sandbox_uid: Some(5000),
            sandbox_gid: Some(6000),
            ..KubernetesComputeConfig::default()
        };
        assert_eq!(
            cfg.resolve_sandbox_gid(cfg.resolve_sandbox_uid(None), None),
            6000
        );
    }

    #[test]
    fn resolve_sandbox_gid_falls_back_to_uid() {
        let cfg = KubernetesComputeConfig {
            sandbox_uid: Some(5000),
            ..KubernetesComputeConfig::default()
        };
        // sandbox_gid is None, should fall back to sandbox_uid.
        assert_eq!(
            cfg.resolve_sandbox_gid(cfg.resolve_sandbox_uid(None), None),
            5000
        );
    }

    #[test]
    fn resolve_sandbox_gid_falls_back_to_resolved_uid() {
        let cfg = KubernetesComputeConfig::default();
        // Both are None, should use the resolved UID.
        let uid = cfg.resolve_sandbox_uid(None);
        assert_eq!(cfg.resolve_sandbox_gid(uid, None), uid);
    }

    #[test]
    fn upstream_proxy_config_accepts_http_proxy_without_credentials() {
        let cfg = KubernetesComputeConfig {
            https_proxy: Some("http://proxy.corp.example:8080".to_string()),
            no_proxy: Some(".svc.cluster.local,10.96.0.0/12".to_string()),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_upstream_proxy_config().is_ok());
    }

    #[test]
    fn upstream_proxy_config_accepts_secret_credentials_with_acknowledgement() {
        let cfg = KubernetesComputeConfig {
            topology: SupervisorTopology::Sidecar,
            https_proxy: Some("http://proxy.corp.example:8080".to_string()),
            proxy_auth_secret_name: Some("corporate-proxy-auth".to_string()),
            proxy_auth_secret_key: Some("credentials".to_string()),
            proxy_auth_allow_insecure: Some(true),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_upstream_proxy_config().is_ok());
    }

    #[test]
    fn toml_deserializes_sidecar_upstream_proxy_settings() {
        let cfg: KubernetesComputeConfig = toml::from_str(
            r#"
                topology = "sidecar"
                https_proxy = "http://proxy.corp.example:8080"
                no_proxy = ".svc.cluster.local,10.96.0.0/12"
                proxy_auth_secret_name = "corporate-proxy-auth"
                proxy_auth_secret_key = "credentials"
                proxy_auth_allow_insecure = true
                proxy_connect_by_hostname = true
            "#,
        )
        .unwrap();
        assert!(cfg.validate_upstream_proxy_config().is_ok());
        assert_eq!(
            cfg.https_proxy.as_deref(),
            Some("http://proxy.corp.example:8080")
        );
        assert_eq!(
            cfg.proxy_auth_secret_name.as_deref(),
            Some("corporate-proxy-auth")
        );
    }

    #[test]
    fn upstream_proxy_config_rejects_incoherent_auxiliary_settings() {
        for cfg in [
            KubernetesComputeConfig {
                no_proxy: Some(".svc".to_string()),
                ..KubernetesComputeConfig::default()
            },
            KubernetesComputeConfig {
                https_proxy: Some("http://proxy.corp.example:8080".to_string()),
                proxy_auth_secret_name: Some("corporate-proxy-auth".to_string()),
                ..KubernetesComputeConfig::default()
            },
            KubernetesComputeConfig {
                https_proxy: Some("http://proxy.corp.example:8080".to_string()),
                proxy_auth_secret_name: Some("corporate-proxy-auth".to_string()),
                proxy_auth_secret_key: Some("credentials".to_string()),
                ..KubernetesComputeConfig::default()
            },
            KubernetesComputeConfig {
                proxy_connect_by_hostname: Some(true),
                ..KubernetesComputeConfig::default()
            },
        ] {
            assert!(cfg.validate_upstream_proxy_config().is_err());
        }
    }

    // -- WorkspaceMode tests --

    #[test]
    fn default_workspace_mode_is_shared() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(cfg.workspace_mode, WorkspaceMode::Shared);
    }

    #[test]
    fn serde_override_workspace_mode_managed() {
        let json = serde_json::json!({ "workspace_mode": "managed" });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.workspace_mode, WorkspaceMode::Managed);
    }

    #[test]
    fn serde_override_workspace_mode_operator() {
        let json = serde_json::json!({ "workspace_mode": "operator" });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.workspace_mode, WorkspaceMode::Operator);
    }

    #[test]
    fn serde_rejects_invalid_workspace_mode() {
        let json = serde_json::json!({ "workspace_mode": "invalid" });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn workspace_mode_display_roundtrips() {
        for mode in [
            WorkspaceMode::Shared,
            WorkspaceMode::Managed,
            WorkspaceMode::Operator,
        ] {
            assert_eq!(mode.to_string().parse::<WorkspaceMode>().unwrap(), mode);
        }
    }

    #[test]
    fn upstream_proxy_config_rejects_unsupported_proxy_scheme() {
        let cfg = KubernetesComputeConfig {
            https_proxy: Some("https://proxy.corp.example:8443".to_string()),
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_upstream_proxy_config().unwrap_err();
        assert!(err.contains("https_proxy"), "{err}");
    }

    #[test]
    fn upstream_proxy_config_rejects_invalid_secret_name() {
        let cfg = KubernetesComputeConfig {
            https_proxy: Some("http://proxy.corp.example:8080".to_string()),
            proxy_auth_secret_name: Some("Not_A_Secret".to_string()),
            proxy_auth_secret_key: Some("credentials".to_string()),
            proxy_auth_allow_insecure: Some(true),
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_upstream_proxy_config().unwrap_err();
        assert!(err.contains("proxy_auth_secret_name"), "{err}");
    }

    #[test]
    fn upstream_proxy_config_rejects_invalid_secret_key() {
        // A key that Kubernetes cannot create must fail at gateway startup
        // instead of surfacing as repeated Pod-provisioning failures.
        for key in [
            "a".repeat(254), // exceeds the 253-byte Secret key limit
            ".".to_string(),
            "..".to_string(),
            "bad key".to_string(), // whitespace is outside the allowed charset
        ] {
            let cfg = KubernetesComputeConfig {
                topology: SupervisorTopology::Sidecar,
                https_proxy: Some("http://proxy.corp.example:8080".to_string()),
                proxy_auth_secret_name: Some("corporate-proxy-auth".to_string()),
                proxy_auth_secret_key: Some(key.clone()),
                proxy_auth_allow_insecure: Some(true),
                ..KubernetesComputeConfig::default()
            };
            let err = cfg.validate_upstream_proxy_config().unwrap_err();
            assert!(
                err.contains("proxy_auth_secret_key"),
                "key {key:?} should be rejected with a key-specific error: {err}"
            );
        }
    }

    #[test]
    fn upstream_proxy_config_accepts_max_length_secret_key() {
        let cfg = KubernetesComputeConfig {
            topology: SupervisorTopology::Sidecar,
            https_proxy: Some("http://proxy.corp.example:8080".to_string()),
            proxy_auth_secret_name: Some("corporate-proxy-auth".to_string()),
            proxy_auth_secret_key: Some("a".repeat(253)),
            proxy_auth_allow_insecure: Some(true),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_upstream_proxy_config().is_ok());
    }

    #[test]
    fn upstream_proxy_config_rejects_credentials_in_combined_topology() {
        let cfg = KubernetesComputeConfig {
            topology: SupervisorTopology::Combined,
            https_proxy: Some("http://proxy.corp.example:8080".to_string()),
            proxy_auth_secret_name: Some("corporate-proxy-auth".to_string()),
            proxy_auth_secret_key: Some("credentials".to_string()),
            proxy_auth_allow_insecure: Some(true),
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_upstream_proxy_config().unwrap_err();
        assert!(err.contains("topology = \"sidecar\""), "{err}");
    }

    #[test]
    fn upstream_proxy_config_allows_explicit_false_acknowledgement_without_credentials() {
        let cfg = KubernetesComputeConfig {
            https_proxy: Some("http://proxy.corp.example:8080".to_string()),
            proxy_auth_allow_insecure: Some(false),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_upstream_proxy_config().is_ok());
    }

    #[test]
    fn namespace_for_workspace_shared() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Shared,
            namespace: "sandbox-ns".to_string(),
            ..KubernetesComputeConfig::default()
        };
        assert_eq!(
            cfg.namespace_for_workspace("team-a", None).unwrap(),
            "sandbox-ns"
        );
        assert_eq!(
            cfg.namespace_for_workspace("team-b", None).unwrap(),
            "sandbox-ns"
        );
    }

    #[test]
    fn namespace_for_workspace_managed() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: "gw1".to_string(),
            ..KubernetesComputeConfig::default()
        };
        assert_eq!(
            cfg.namespace_for_workspace("team-a", None).unwrap(),
            "openshell-gw1-team-a"
        );
    }

    #[test]
    fn namespace_for_workspace_operator() {
        let allowlist = OperatorNamespaceAllowlist::from_set(BTreeSet::from(["prod".to_string()]));
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            operator_namespace_label: Some("openshell.ai/workspace=true".to_string()),
            ..KubernetesComputeConfig::default()
        };
        assert_eq!(
            cfg.namespace_for_workspace("prod", Some(&allowlist))
                .unwrap(),
            "prod"
        );
        assert!(
            cfg.namespace_for_workspace("unknown", Some(&allowlist))
                .is_err()
        );
    }

    #[test]
    fn namespace_for_workspace_operator_requires_allowlist() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            operator_namespace_label: Some("openshell.ai/workspace=true".to_string()),
            ..KubernetesComputeConfig::default()
        };

        let err = cfg.namespace_for_workspace("prod", None).unwrap_err();
        assert_eq!(err, "operator mode requires a namespace allowlist");
    }

    #[test]
    fn kube_resource_name_shared_prefixes_workspace() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(cfg.kube_resource_name("ws", "box1"), "ws--box1");
    }

    #[test]
    fn kube_resource_name_managed_uses_bare_name() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            ..KubernetesComputeConfig::default()
        };
        assert_eq!(cfg.kube_resource_name("ws", "box1"), "box1");
    }

    #[test]
    fn kube_resource_name_operator_uses_bare_name() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            operator_namespace_label: Some("x=y".to_string()),
            ..KubernetesComputeConfig::default()
        };
        assert_eq!(cfg.kube_resource_name("ws", "box1"), "box1");
    }

    #[test]
    fn is_multi_namespace() {
        assert!(!KubernetesComputeConfig::default().is_multi_namespace());
        assert!(
            KubernetesComputeConfig {
                workspace_mode: WorkspaceMode::Managed,
                ..KubernetesComputeConfig::default()
            }
            .is_multi_namespace()
        );
        assert!(
            KubernetesComputeConfig {
                workspace_mode: WorkspaceMode::Operator,
                operator_namespace_label: Some("x=y".to_string()),
                ..KubernetesComputeConfig::default()
            }
            .is_multi_namespace()
        );
    }

    #[test]
    fn validate_workspace_mode_shared_always_ok() {
        let cfg = KubernetesComputeConfig::default();
        cfg.validate_workspace_mode().unwrap();
    }

    #[test]
    fn validate_workspace_mode_managed_requires_gateway_id() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: String::new(),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_workspace_mode().is_err());
    }

    #[test]
    fn validate_workspace_mode_managed_rejects_invalid_gateway_id() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: "INVALID".to_string(),
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_workspace_mode().is_err());
    }

    #[test]
    fn validate_workspace_mode_managed_rejects_long_gateway_id() {
        // prefix = "openshell-{id}-" = 11 + id.len()
        // 11 + 34 + 19 = 64 > 63 → rejected
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: "a".repeat(34),
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_workspace_mode().unwrap_err();
        assert!(err.contains("too long for managed mode"), "{err}");
    }

    #[test]
    fn validate_workspace_mode_managed_accepts_max_gateway_id() {
        // 11 + 33 + 19 = 63 → accepted
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: "a".repeat(33),
            ..KubernetesComputeConfig::default()
        };
        cfg.validate_workspace_mode().unwrap();
    }

    #[test]
    fn validate_workspace_mode_managed_requires_complete_ssh_ingress_peer() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            managed_ssh_ingress: ManagedSshIngressConfig {
                enabled: true,
                gateway_namespace: "gateway".to_string(),
                gateway_pod_selector: BTreeMap::new(),
            },
            ..KubernetesComputeConfig::default()
        };
        let err = cfg.validate_workspace_mode().unwrap_err();
        assert!(err.contains("gateway_pod_selector"), "{err}");
    }

    #[test]
    fn validate_workspace_mode_managed_accepts_complete_ssh_ingress_peer() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            managed_ssh_ingress: ManagedSshIngressConfig {
                enabled: true,
                gateway_namespace: "gateway".to_string(),
                gateway_pod_selector: BTreeMap::from([(
                    "app.kubernetes.io/name".to_string(),
                    "openshell".to_string(),
                )]),
            },
            ..KubernetesComputeConfig::default()
        };
        cfg.validate_workspace_mode().unwrap();
    }

    #[test]
    fn validate_workspace_mode_operator_requires_discovery() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            ..KubernetesComputeConfig::default()
        };
        assert!(cfg.validate_workspace_mode().is_err());
    }

    #[test]
    fn validate_workspace_mode_operator_accepts_label_only() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            operator_namespace_label: Some("openshell.ai/workspace=true".to_string()),
            ..KubernetesComputeConfig::default()
        };
        cfg.validate_workspace_mode().unwrap();
    }

    #[test]
    fn validate_workspace_mode_operator_accepts_file_only() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            operator_namespace_file: Some("/etc/openshell/namespaces.json".to_string()),
            ..KubernetesComputeConfig::default()
        };
        cfg.validate_workspace_mode().unwrap();
    }

    #[test]
    fn validate_workspace_mode_operator_rejects_label_and_file() {
        let cfg = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Operator,
            operator_namespace_label: Some("openshell.ai/workspace=true".to_string()),
            operator_namespace_file: Some("/etc/openshell/namespaces.json".to_string()),
            ..KubernetesComputeConfig::default()
        };

        let err = cfg.validate_workspace_mode().unwrap_err();
        assert!(err.contains("not both"), "{err}");
    }

    #[test]
    fn dns_1123_label_validation() {
        assert!(is_dns_1123_label("openshell"));
        assert!(is_dns_1123_label("my-gateway-1"));
        assert!(is_dns_1123_label("a"));
        assert!(!is_dns_1123_label(""));
        assert!(!is_dns_1123_label("UPPER"));
        assert!(!is_dns_1123_label("-starts-with-dash"));
        assert!(!is_dns_1123_label("ends-with-dash-"));
        assert!(!is_dns_1123_label("has_underscore"));
        assert!(!is_dns_1123_label(&"a".repeat(64)));
    }

    #[test]
    fn managed_namespace_naming() {
        assert_eq!(
            managed_namespace("openshell", "default"),
            "openshell-openshell-default"
        );
        assert_eq!(managed_namespace("gw1", "team-a"), "openshell-gw1-team-a");
    }

    #[test]
    fn validate_managed_namespace_name_accepts_valid() {
        validate_managed_namespace_name("gw1", "team-a").unwrap();
    }

    #[test]
    fn validate_managed_namespace_name_rejects_invalid_workspace_characters() {
        let err = validate_managed_namespace_name("gw1", "INVALID").unwrap_err();
        assert!(err.contains("not a valid DNS-1123 label"));
    }

    #[test]
    fn validate_managed_namespace_name_rejects_too_long() {
        let long_workspace = "a".repeat(50);
        assert!(validate_managed_namespace_name("openshell", &long_workspace).is_err());
    }

    #[test]
    fn operator_allowlist_operations() {
        let al = OperatorNamespaceAllowlist::new();
        assert!(!al.contains("ns1"));

        al.replace(BTreeSet::from(["ns1".to_string(), "ns2".to_string()]));
        assert!(al.contains("ns1"));
        assert!(al.contains("ns2"));
        assert!(!al.contains("ns3"));

        al.merge(&BTreeSet::from(["ns3".to_string()]));
        assert!(al.contains("ns3"));

        al.replace(BTreeSet::new());
        assert!(!al.contains("ns1"));
    }

    #[test]
    fn operator_allowlist_recovers_from_poisoned_lock() {
        let al = OperatorNamespaceAllowlist::from_set(BTreeSet::from(["ns1".to_string()]));
        let shared = al.shared();
        let _ = std::thread::spawn(move || {
            let _guard = shared.write().unwrap();
            panic!("poison allowlist lock");
        })
        .join();

        assert!(al.contains("ns1"));
        assert!(al.insert("ns2".to_string()));
        assert!(al.read().contains("ns2"));
        assert!(al.remove("ns1"));
    }
}
