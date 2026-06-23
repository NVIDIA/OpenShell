// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::DEFAULT_SUPERVISOR_IMAGE;
use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;
use std::str::FromStr;

/// Default Kubernetes namespace for sandbox resources.
pub const DEFAULT_K8S_NAMESPACE: &str = "openshell";

/// Default Kubernetes `ServiceAccount` assigned to sandbox pods.
pub const DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME: &str = "default";

/// Default storage size for the workspace PVC.
pub const DEFAULT_WORKSPACE_STORAGE_SIZE: &str = "2Gi";

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
}

impl std::fmt::Display for SupervisorTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Combined => f.write_str("combined"),
        }
    }
}

impl FromStr for SupervisorTopology {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "combined" => Ok(Self::Combined),
            other => Err(format!("unknown supervisor topology '{other}'")),
        }
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
    pub namespace: String,
    /// Kubernetes `ServiceAccount` assigned to sandbox pods and accepted by
    /// the gateway's `TokenReview` bootstrap authenticator.
    pub service_account_name: String,
    pub default_image: String,
    pub image_pull_policy: String,
    /// Kubernetes `imagePullSecrets` names attached to sandbox pods.
    pub image_pull_secrets: Vec<String>,
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
    pub supervisor_topology: SupervisorTopology,
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
            namespace: DEFAULT_K8S_NAMESPACE.to_string(),
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME.to_string(),
            default_image: openshell_core::image::default_sandbox_image(),
            // Default empty so the gateway omits `imagePullPolicy` from pod
            // specs and Kubernetes applies its own default (Always for `latest`,
            // IfNotPresent otherwise). `DEFAULT_IMAGE_PULL_POLICY` ("missing")
            // is Podman vocabulary and is not a valid Kubernetes value.
            image_pull_policy: String::new(),
            image_pull_secrets: Vec::new(),
            supervisor_image: DEFAULT_SUPERVISOR_IMAGE.to_string(),
            supervisor_image_pull_policy: String::new(),
            supervisor_sideload_method: SupervisorSideloadMethod::default(),
            supervisor_topology: SupervisorTopology::default(),
            grpc_endpoint: String::new(),
            ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            client_tls_secret_name: String::new(),
            host_gateway_ip: String::new(),
            enable_user_namespaces: false,
            app_armor_profile: None,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE.to_string(),
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
        namespace_annotations: Option<&std::collections::BTreeMap<String, String>>,
    ) -> u32 {
        if let Some(uid) = self.sandbox_uid {
            return uid;
        }
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
        _namespace_annotations: Option<&std::collections::BTreeMap<String, String>>,
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
    fn default_service_account_name_is_default() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.service_account_name,
            DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
        );
    }

    #[test]
    fn default_supervisor_topology_is_combined() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(cfg.supervisor_topology, SupervisorTopology::Combined);
        assert_eq!(cfg.supervisor_topology.to_string(), "combined");
    }

    #[test]
    fn serde_override_supervisor_topology_combined() {
        let json = serde_json::json!({
            "supervisor_topology": "combined"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.supervisor_topology, SupervisorTopology::Combined);
    }

    #[test]
    fn serde_rejects_invalid_supervisor_topology() {
        let json = serde_json::json!({
            "supervisor_topology": "unsupported"
        });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
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
    fn parse_openshift_uid_range_rejects_below_min() {
        // 999 is below MIN_SANDBOX_UID (1000) — should be rejected.
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("999/50000"),
            None
        );
    }

    #[test]
    fn parse_openshift_uid_range_rejects_above_max() {
        // u32::MAX is well above MAX_SANDBOX_UID — should be rejected.
        assert_eq!(
            KubernetesComputeConfig::from_open_shift_uid_range("4294967295/10000"),
            None
        );
    }

    #[test]
    fn validate_sandbox_identity_config_accepts_valid_range() {
        let cfg = KubernetesComputeConfig {
            sandbox_uid: Some(1000),
            sandbox_gid: Some(1000),
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
}
