// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

const DEFAULT_CNI_VERSION: &str = "1.0.0";
const SUPPORTED_CNI_VERSIONS: &[&str] = &["0.3.0", "0.3.1", "0.4.0", "1.0.0"];
const DEFAULT_KUBECONFIG_PATH: &str = "/etc/cni/net.d/openshell-cni-kubeconfig";
const OPENSHELL_CNI_ENABLED_ANNOTATION: &str = "openshell.ai/cni";
const OPENSHELL_CNI_PROXY_UID_ANNOTATION: &str = "openshell.ai/proxy-uid";
const OPENSHELL_CNI_NETWORK_ENFORCEMENT_MODE_ANNOTATION: &str =
    "openshell.ai/network-enforcement-mode";
const CNI_SIDECAR_NETWORK_ENFORCEMENT_MODE: &str = "cni-sidecar";
/// Node label set by the CNI installer once the chained plugin is in place and
/// cleared when it is not, so the gateway can gate sandbox scheduling on
/// per-node egress-enforcement readiness. Must stay in sync with the identical
/// constant in `openshell-driver-kubernetes` (used for the sandbox pod
/// nodeAffinity) and with the CNI `DaemonSet`'s node-patch RBAC.
const NODE_READY_LABEL: &str = "openshell.ai/cni-ready";
#[allow(dead_code)]
const OPENSHELL_TABLE: &str = "openshell_sidecar_bypass";
#[allow(dead_code)]
const OPENSHELL_IPTABLES_CHAIN: &str = "OPENSHELL_OUTPUT";
#[cfg(target_os = "linux")]
const NFT_SEARCH_PATHS: &[&str] = &[
    "/usr/sbin/nft",
    "/sbin/nft",
    "/usr/bin/nft",
    "/bin/nft",
    "/opt/cni/bin/nft",
    "/bin/aux/nft",
];
#[cfg(target_os = "linux")]
const IPTABLES_SEARCH_PATHS: &[&str] = &[
    "/usr/sbin/iptables",
    "/sbin/iptables",
    "/usr/bin/iptables",
    "/bin/iptables",
    "/opt/cni/bin/iptables",
    "/bin/aux/iptables",
];
#[cfg(target_os = "linux")]
const IP6TABLES_SEARCH_PATHS: &[&str] = &[
    "/usr/sbin/ip6tables",
    "/sbin/ip6tables",
    "/usr/bin/ip6tables",
    "/bin/ip6tables",
    "/opt/cni/bin/ip6tables",
    "/bin/aux/ip6tables",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CniConfig {
    cni_version: Option<String>,
    #[serde(default)]
    prev_result: Option<Value>,
    #[serde(default)]
    openshell: OpenShellConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenShellConfig {
    kubeconfig: Option<String>,
    log_file: Option<String>,
    #[serde(default)]
    sandbox_namespaces: Vec<String>,
}

#[derive(Debug, Clone)]
struct CniEnv {
    command: String,
    netns: Option<PathBuf>,
    args: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodRef {
    namespace: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct PodResponse {
    metadata: PodMetadata,
}

#[derive(Debug, Deserialize)]
struct PodMetadata {
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct DaemonSetResponse {
    metadata: ObjectMeta,
}

#[derive(Debug, Default, Deserialize)]
struct ObjectMeta {
    #[serde(rename = "deletionTimestamp")]
    deletion_timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KubeConfig {
    #[serde(rename = "current-context")]
    current_context: String,
    clusters: Vec<NamedCluster>,
    contexts: Vec<NamedContext>,
    users: Vec<NamedUser>,
}

#[derive(Debug, Deserialize)]
struct NamedCluster {
    name: String,
    cluster: ClusterConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ClusterConfig {
    server: String,
    certificate_authority_data: Option<String>,
    certificate_authority: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NamedContext {
    name: String,
    context: ContextConfig,
}

#[derive(Debug, Deserialize)]
struct ContextConfig {
    cluster: String,
    user: String,
}

#[derive(Debug, Deserialize)]
struct NamedUser {
    name: String,
    user: UserConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UserConfig {
    token: Option<String>,
    token_file: Option<String>,
}

struct Runtime;

trait PodReader {
    fn pod_annotations(&self, kubeconfig: &Path, pod: &PodRef) -> Result<BTreeMap<String, String>>;
}

trait RuleInstaller {
    fn install(&self, netns: &Path, proxy_uid: u32) -> Result<InstallReport>;
    fn cleanup(&self, netns: &Path) -> Result<()>;
}

/// Returns true when `/proc/net/if_inet6` contents report at least one
/// non-loopback IPv6 address. Link-local (`fe80::/10`) counts because it can
/// still reach on-link peers and node services; only loopback (`::1`) is
/// excluded. Empty contents (IPv6 disabled in the kernel) return false.
fn if_inet6_has_non_loopback_ipv6(contents: &str) -> bool {
    contents.lines().any(|line| {
        // Format: <32-hex-addr> <ifidx> <prefixlen> <scope> <flags> <devname>
        line.split_whitespace()
            .next()
            .is_some_and(|addr| addr != "00000000000000000000000000000001")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstallReport {
    backend: &'static str,
}

/// CNI spec reserves error codes >= 100 for plugin-specific failures.
const CNI_PLUGIN_ERROR_CODE: u32 = 100;

/// Parses the `node-ready` subcommand flags into the desired readiness state.
/// `--set` marks the node ready; `--clear` fences it.
fn parse_node_ready_args(args: &[String]) -> Result<bool> {
    let mut ready = None;
    for arg in args {
        match arg.as_str() {
            "--set" => ready = Some(true),
            "--clear" => ready = Some(false),
            other => return Err(miette::miette!("unknown node-ready argument '{other}'")),
        }
    }
    ready.ok_or_else(|| miette::miette!("node-ready requires --set or --clear"))
}

/// Entry point for `openshell-cni node-ready`, the CNI installer's readiness gate.
///
/// Invoked by the installer `DaemonSet` to gate sandbox scheduling on per-node
/// enforcement readiness. `--set` labels the node ready once the chained plugin
/// is installed; `--clear` removes the label on shutdown or repair failure so
/// new sandbox pods will not schedule on a node where egress enforcement is
/// absent. Reads the target node from `NODE_NAME` and authenticates with the
/// pod's in-cluster service account.
pub fn node_ready(args: &[String]) -> Result<()> {
    let ready = parse_node_ready_args(args)?;
    let node = std::env::var("NODE_NAME")
        .map_err(|_| miette::miette!("NODE_NAME env var is required for node-ready"))?;
    let client = KubeApiClient::from_in_cluster()?;
    let value = if ready { Some("true") } else { None };
    client.patch_node_label(&node, NODE_READY_LABEL, value)
}

/// Entry point for `openshell-cni daemonset-active`.
///
/// Used by the installer `preStop` hook to distinguish an ordinary pod
/// restart/rolling update from a real teardown (helm uninstall / `DaemonSet`
/// delete).
///
/// Returns `Ok(())` (exit 0) whenever enforcement should be **preserved** — the
/// owning `DaemonSet` still exists and is not being deleted, OR the state cannot
/// be determined (missing env, API error). Enforcement lives in the host CNI
/// config and survives pod restarts, so preserving is the fail-safe default.
/// Returns `Err` (non-zero) only when the `DaemonSet` is positively confirmed
/// gone or terminating, signalling the caller that cleanup is appropriate.
pub fn daemonset_active() -> Result<()> {
    let (Ok(name), Ok(namespace)) = (std::env::var("DS_NAME"), std::env::var("DS_NAMESPACE"))
    else {
        // Cannot identify the owning DaemonSet; preserve enforcement.
        return Ok(());
    };
    let Ok(client) = KubeApiClient::from_in_cluster() else {
        return Ok(());
    };
    match client.daemonset_terminating(&namespace, &name) {
        Ok(true) => Err(miette::miette!(
            "owning DaemonSet {namespace}/{name} is gone or terminating"
        )),
        // Active, or an API error we cannot interpret: preserve enforcement.
        Ok(false) | Err(_) => Ok(()),
    }
}

pub fn run() -> Result<()> {
    let env = CniEnv::from_process();
    let mut input = String::new();
    let result = (|| -> Result<Option<Value>> {
        std::io::stdin()
            .read_to_string(&mut input)
            .into_diagnostic()
            .wrap_err("failed to read CNI config from stdin")?;
        let runtime = Runtime;
        handle_command(&input, &env, &runtime, &runtime)
    })();

    match result {
        Ok(output) => {
            if let Some(output) = output {
                println!("{}", serde_json::to_string(&output).into_diagnostic()?);
            }
            Ok(())
        }
        Err(error) => {
            log_cni_error(&input, &env, &error);
            // Per the CNI spec a failing plugin must print a structured error object
            // on stdout and exit non-zero; the runtime parses this to surface the
            // failure instead of treating stderr text as an opaque crash.
            emit_cni_error(&input, &error);
            Err(error)
        }
    }
}

/// Builds the CNI-spec error object (`cniVersion`, `code`, `msg`, `details`). The
/// version echoes the request when parseable so the runtime accepts the reply.
fn cni_error_payload(input: &str, error: &miette::Report) -> Value {
    let cni_version = serde_json::from_str::<CniConfig>(input)
        .ok()
        .and_then(|config| config.cni_version)
        .unwrap_or_else(|| DEFAULT_CNI_VERSION.to_string());
    serde_json::json!({
        "cniVersion": cni_version,
        "code": CNI_PLUGIN_ERROR_CODE,
        "msg": "OpenShell CNI plugin error",
        "details": one_line_error(error),
    })
}

fn emit_cni_error(input: &str, error: &miette::Report) {
    if let Ok(serialized) = serde_json::to_string(&cni_error_payload(input, error)) {
        println!("{serialized}");
    }
}

fn log_cni_error(input: &str, env: &CniEnv, error: &miette::Report) {
    let Ok(config) = serde_json::from_str::<CniConfig>(input) else {
        return;
    };
    log_cni_info(&config, env, &format!("error={}", one_line_error(error)));
}

fn log_cni_info(config: &CniConfig, env: &CniEnv, message: &str) {
    let Some(log_file) = config.openshell.log_file.as_deref() else {
        return;
    };
    if log_file.is_empty() {
        return;
    }

    let pod = env.pod_ref().map_or_else(
        || "-".to_string(),
        |pod| format!("{}/{}", pod.namespace, pod.name),
    );
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
    else {
        return;
    };
    let _ = writeln!(file, "command={} pod={} {}", env.command, pod, message);
}

fn one_line_error(error: &miette::Report) -> String {
    format!("{error:?}")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn handle_command(
    input: &str,
    env: &CniEnv,
    pod_reader: &impl PodReader,
    installer: &impl RuleInstaller,
) -> Result<Option<Value>> {
    match env.command.as_str() {
        "VERSION" => Ok(Some(version_response())),
        "DEL" => {
            if let Some(netns) = env.netns.as_deref() {
                let _ = installer.cleanup(netns);
            }
            Ok(None)
        }
        "ADD" => {
            let config: CniConfig = serde_json::from_str(input).into_diagnostic()?;
            if let Some(workload) = workload_from_config(&config, env, pod_reader)? {
                let netns = env.netns.as_deref().ok_or_else(|| {
                    miette::miette!("CNI_NETNS is required for OpenShell CNI ADD")
                })?;
                let report = installer.install(netns, workload.proxy_uid)?;
                log_cni_info(
                    &config,
                    env,
                    &format!(
                        "status=installed backend={} proxy_uid={}",
                        report.backend, workload.proxy_uid
                    ),
                );
            }
            Ok(Some(pass_through_result(&config)))
        }
        "CHECK" => {
            let config: CniConfig = serde_json::from_str(input).into_diagnostic()?;
            if let Some(workload) = workload_from_config(&config, env, pod_reader)? {
                let netns = env.netns.as_deref().ok_or_else(|| {
                    miette::miette!("CNI_NETNS is required for OpenShell CNI CHECK")
                })?;
                let report = installer.install(netns, workload.proxy_uid)?;
                log_cni_info(
                    &config,
                    env,
                    &format!(
                        "status=installed backend={} proxy_uid={}",
                        report.backend, workload.proxy_uid
                    ),
                );
            }
            Ok(None)
        }
        other => Err(miette::miette!("unsupported CNI_COMMAND '{other}'")),
    }
}

#[derive(Debug, Clone, Copy)]
struct WorkloadConfig {
    proxy_uid: u32,
}

fn workload_from_config(
    config: &CniConfig,
    env: &CniEnv,
    pod_reader: &impl PodReader,
) -> Result<Option<WorkloadConfig>> {
    let Some(pod) = env.pod_ref() else {
        return Ok(None);
    };
    if !config.openshell.sandbox_namespaces.is_empty()
        && !config
            .openshell
            .sandbox_namespaces
            .iter()
            .any(|namespace| namespace == &pod.namespace)
    {
        return Ok(None);
    }
    let kubeconfig = config
        .openshell
        .kubeconfig
        .as_deref()
        .unwrap_or(DEFAULT_KUBECONFIG_PATH);
    let annotations = pod_reader.pod_annotations(Path::new(kubeconfig), &pod)?;
    if annotations
        .get(OPENSHELL_CNI_ENABLED_ANNOTATION)
        .map(String::as_str)
        != Some("enabled")
    {
        return Ok(None);
    }
    if annotations
        .get(OPENSHELL_CNI_NETWORK_ENFORCEMENT_MODE_ANNOTATION)
        .map(String::as_str)
        != Some(CNI_SIDECAR_NETWORK_ENFORCEMENT_MODE)
    {
        return Ok(None);
    }
    let proxy_uid = annotations
        .get(OPENSHELL_CNI_PROXY_UID_ANNOTATION)
        .ok_or_else(|| miette::miette!("OpenShell CNI pod is missing proxy UID annotation"))?
        .parse::<u32>()
        .into_diagnostic()
        .wrap_err("invalid OpenShell CNI proxy UID annotation")?;
    Ok(Some(WorkloadConfig { proxy_uid }))
}

fn pass_through_result(config: &CniConfig) -> Value {
    config.prev_result.clone().unwrap_or_else(|| {
        serde_json::json!({
            "cniVersion": config.cni_version.as_deref().unwrap_or(DEFAULT_CNI_VERSION)
        })
    })
}

fn version_response() -> Value {
    serde_json::json!({
        "cniVersion": DEFAULT_CNI_VERSION,
        "supportedVersions": SUPPORTED_CNI_VERSIONS
    })
}

impl CniEnv {
    fn from_process() -> Self {
        Self {
            command: std::env::var("CNI_COMMAND").unwrap_or_else(|_| "VERSION".to_string()),
            netns: std::env::var_os("CNI_NETNS").map(PathBuf::from),
            args: std::env::var("CNI_ARGS").ok(),
        }
    }

    fn pod_ref(&self) -> Option<PodRef> {
        let args = self.args.as_deref()?;
        let values = parse_cni_args(args);
        let namespace = values.get("K8S_POD_NAMESPACE")?.to_string();
        let name = values.get("K8S_POD_NAME")?.to_string();
        Some(PodRef { namespace, name })
    }
}

fn parse_cni_args(args: &str) -> BTreeMap<&str, &str> {
    args.split(';')
        .filter_map(|part| part.split_once('='))
        .collect()
}

impl PodReader for Runtime {
    fn pod_annotations(&self, kubeconfig: &Path, pod: &PodRef) -> Result<BTreeMap<String, String>> {
        let client = KubeApiClient::from_kubeconfig(kubeconfig)?;
        client.pod_annotations(pod)
    }
}

struct KubeApiClient {
    server: String,
    token: String,
    client: reqwest::blocking::Client,
}

impl KubeApiClient {
    fn from_kubeconfig(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read kubeconfig {}", path.display()))?;
        let kubeconfig: KubeConfig = serde_yml::from_str(&contents)
            .into_diagnostic()
            .wrap_err("invalid kubeconfig")?;
        let context = kubeconfig
            .contexts
            .iter()
            .find(|context| context.name == kubeconfig.current_context)
            .ok_or_else(|| miette::miette!("current kubeconfig context not found"))?;
        let cluster = kubeconfig
            .clusters
            .iter()
            .find(|cluster| cluster.name == context.context.cluster)
            .ok_or_else(|| miette::miette!("current kubeconfig cluster not found"))?;
        let user = kubeconfig
            .users
            .iter()
            .find(|user| user.name == context.context.user)
            .ok_or_else(|| miette::miette!("current kubeconfig user not found"))?;
        let token = match (&user.user.token, &user.user.token_file) {
            (Some(token), _) => token.clone(),
            (None, Some(token_file)) => std::fs::read_to_string(token_file)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read kubeconfig token file {token_file}"))?
                .trim()
                .to_string(),
            (None, None) => {
                return Err(miette::miette!(
                    "kubeconfig user must contain token or token-file"
                ));
            }
        };
        let mut builder = reqwest::blocking::Client::builder();
        if let Some(ca) = cluster_certificate_authority(path, &cluster.cluster)? {
            builder = builder.add_root_certificate(ca);
        }
        let client = builder.build().into_diagnostic()?;
        Ok(Self {
            server: cluster.cluster.server.trim_end_matches('/').to_string(),
            token,
            client,
        })
    }

    /// Builds a client from the pod's mounted in-cluster service account,
    /// independent of the plugin kubeconfig (whose token-file path is a host
    /// path that does not resolve inside the installer container).
    fn from_in_cluster() -> Result<Self> {
        const TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        const CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            miette::miette!("KUBERNETES_SERVICE_HOST is required for in-cluster access")
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").map_err(|_| {
            miette::miette!("KUBERNETES_SERVICE_PORT is required for in-cluster access")
        })?;
        let token = std::fs::read_to_string(TOKEN_PATH)
            .into_diagnostic()
            .wrap_err("failed to read in-cluster service account token")?
            .trim()
            .to_string();
        let ca_pem = std::fs::read(CA_PATH)
            .into_diagnostic()
            .wrap_err("failed to read in-cluster CA certificate")?;
        let ca = reqwest::Certificate::from_pem(&ca_pem).into_diagnostic()?;
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(ca)
            .build()
            .into_diagnostic()?;
        Ok(Self {
            server: format!("https://{host}:{port}"),
            token,
            client,
        })
    }

    /// Sets (`value = Some`) or removes (`value = None`) a single node label via
    /// a JSON merge patch. A null value in a merge patch deletes the key.
    fn patch_node_label(&self, node: &str, key: &str, value: Option<&str>) -> Result<()> {
        let url = format!("{}/api/v1/nodes/{}", self.server, node);
        let label_value = value.map_or(Value::Null, |v| Value::String(v.to_string()));
        let body = serde_json::json!({ "metadata": { "labels": { key: label_value } } });
        let response = self
            .client
            .patch(url)
            .bearer_auth(&self.token)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/merge-patch+json",
            )
            .body(serde_json::to_vec(&body).into_diagnostic()?)
            .send()
            .into_diagnostic()
            .wrap_err("failed to patch node label")?;
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while patching node {}",
                response.status(),
                node
            ));
        }
        Ok(())
    }

    /// Returns true when the named `DaemonSet` is gone (404) or has a
    /// `deletionTimestamp` set (being deleted). A non-404 HTTP error is
    /// propagated so the caller can treat it as indeterminate.
    fn daemonset_terminating(&self, namespace: &str, name: &str) -> Result<bool> {
        let url = format!(
            "{}/apis/apps/v1/namespaces/{}/daemonsets/{}",
            self.server, namespace, name
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .into_diagnostic()
            .wrap_err("failed to query Kubernetes API for DaemonSet state")?;
        if response.status().as_u16() == 404 {
            return Ok(true);
        }
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while reading DaemonSet {}/{}",
                response.status(),
                namespace,
                name
            ));
        }
        let ds = response.json::<DaemonSetResponse>().into_diagnostic()?;
        Ok(ds.metadata.deletion_timestamp.is_some())
    }

    fn pod_annotations(&self, pod: &PodRef) -> Result<BTreeMap<String, String>> {
        let url = format!(
            "{}/api/v1/namespaces/{}/pods/{}",
            self.server, pod.namespace, pod.name
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .into_diagnostic()
            .wrap_err("failed to query Kubernetes API for pod annotations")?;
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while reading pod {}/{}",
                response.status(),
                pod.namespace,
                pod.name
            ));
        }
        let pod = response.json::<PodResponse>().into_diagnostic()?;
        Ok(pod.metadata.annotations)
    }
}

fn cluster_certificate_authority(
    kubeconfig_path: &Path,
    cluster: &ClusterConfig,
) -> Result<Option<reqwest::Certificate>> {
    if let Some(data) = cluster.certificate_authority_data.as_deref() {
        let pem = base64::engine::general_purpose::STANDARD
            .decode(data)
            .into_diagnostic()
            .wrap_err("invalid kubeconfig certificate-authority-data")?;
        return Ok(Some(
            reqwest::Certificate::from_pem(&pem).into_diagnostic()?,
        ));
    }
    if let Some(path) = cluster.certificate_authority.as_deref() {
        let ca_path = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            kubeconfig_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
        };
        let pem = std::fs::read(ca_path).into_diagnostic()?;
        return Ok(Some(
            reqwest::Certificate::from_pem(&pem).into_diagnostic()?,
        ));
    }
    Ok(None)
}

impl RuleInstaller for Runtime {
    fn install(&self, netns: &Path, proxy_uid: u32) -> Result<InstallReport> {
        install_rules(netns, proxy_uid)
    }

    fn cleanup(&self, netns: &Path) -> Result<()> {
        cleanup_rules(netns)
    }
}

#[allow(dead_code)]
fn generate_sidecar_bypass_ruleset(proxy_uid: u32, log_prefix: Option<&str>) -> String {
    let log_tcp = log_prefix
        .map(|p| {
            format!(
                "\n        tcp flags syn limit rate 5/second burst 10 packets log prefix \"{p}\" flags skuid"
            )
        })
        .unwrap_or_default();
    let log_udp = log_prefix
        .map(|p| {
            format!(
                "\n        meta l4proto udp limit rate 5/second burst 10 packets log prefix \"{p}\" flags skuid"
            )
        })
        .unwrap_or_default();

    format!(
        r#"table inet {OPENSHELL_TABLE} {{
    chain output {{
        type filter hook output priority 0; policy accept;

        oifname "lo" accept
        ct state established,related accept
        meta skuid {proxy_uid} accept{log_tcp}
        meta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable{log_udp}
        meta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable
    }}
}}
"#
    )
}

#[cfg(target_os = "linux")]
fn install_rules(netns: &Path, proxy_uid: u32) -> Result<InstallReport> {
    // The preferred nft backend programs both families in one inet ruleset, so
    // its IPv6 reject rules are harmless no-ops on IPv4-only pods and it needs no
    // IPv6 probe. Only the iptables fallback must decide whether ip6tables is
    // required, and it does so by inspecting the pod netns (fail-closed).
    let nft_error = if let Some(nft) = find_nft() {
        match install_nft_rules(netns, proxy_uid, &nft) {
            Ok(()) => {
                return Ok(InstallReport { backend: "nft" });
            }
            Err(error) => Some(one_line_error(&error)),
        }
    } else {
        None
    };

    if let Some(iptables) = find_iptables() {
        let enforce_ipv6 = netns_requires_ipv6_enforcement(netns);
        install_iptables_rules(netns, proxy_uid, &iptables, enforce_ipv6)
            .wrap_err("iptables fallback failed")?;
        return Ok(InstallReport {
            backend: "iptables",
        });
    }

    if let Some(nft_error) = nft_error {
        return Err(miette::miette!(
            "nft rule installation failed and iptables was not found on node: {nft_error}"
        ));
    }

    Err(miette::miette!(
        "neither nft nor iptables was found on node; OpenShell CNI requires a pod-network firewall backend"
    ))
}

#[cfg(target_os = "linux")]
fn install_nft_rules(netns: &Path, proxy_uid: u32, nft: &str) -> Result<()> {
    let _ = run_nft_args_in_netns(netns, &nft, &["delete", "table", "inet", OPENSHELL_TABLE]);
    let ruleset = generate_sidecar_bypass_ruleset(proxy_uid, Some("openshell:cni-sidecar:"));
    run_nft_ruleset_in_netns(netns, &nft, &ruleset)
}

#[cfg(not(target_os = "linux"))]
fn install_rules(netns: &Path, proxy_uid: u32) -> Result<InstallReport> {
    let _ = (netns, proxy_uid);
    Err(miette::miette!(
        "OpenShell CNI rule installation is supported only on Linux nodes"
    ))
}

/// Decides whether the iptables fallback must enforce IPv6, by probing the pod
/// netns for any non-loopback IPv6 address. Fails closed: any error (setns/exec
/// failure, or the probe reporting IPv6 present) returns true, so a pod with
/// IPv6 is never left unenforced just because detection was inconclusive. Only a
/// clean "no IPv6" result (probe exit 0) returns false, keeping IPv4-only nodes
/// working without ip6tables.
#[cfg(target_os = "linux")]
fn netns_requires_ipv6_enforcement(netns: &Path) -> bool {
    // Re-exec this binary inside the target netns; its exit status encodes the
    // result (exit 0 = no IPv6 → Ok, non-zero = IPv6/undetermined → Err).
    run_command_in_netns(netns, "/proc/self/exe", &[NETNS_IPV6_PROBE_ARG]).is_err()
}

/// Argument that runs the in-netns IPv6 probe (see `netns_probe_ipv6`).
#[cfg(target_os = "linux")]
const NETNS_IPV6_PROBE_ARG: &str = "__netns-probe-ipv6";

/// In-netns IPv6 probe entry point, re-exec'd inside the pod netns.
///
/// Reports via exit status whether IPv6 enforcement is needed: success (exit 0)
/// means no non-loopback IPv6 is present; a non-success exit means IPv6 is
/// present or could not be determined, so the caller fails closed. A missing
/// `/proc/net/if_inet6` means IPv6 is disabled in the kernel (no enforcement
/// needed); any other read error is treated as indeterminate.
pub fn netns_probe_ipv6() -> Result<()> {
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(contents) => {
            if if_inet6_has_non_loopback_ipv6(&contents) {
                Err(miette::miette!("pod netns has non-loopback IPv6"))
            } else {
                Ok(())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .into_diagnostic()
            .wrap_err("failed to read /proc/net/if_inet6 for IPv6 probe"),
    }
}

#[cfg(target_os = "linux")]
fn cleanup_rules(netns: &Path) -> Result<()> {
    if let Some(nft) = find_nft() {
        let _ = cleanup_nft_rules(netns, &nft);
    }
    if let Some(iptables) = find_iptables() {
        cleanup_iptables_rules(netns, &iptables);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_nft_rules(netns: &Path, nft: &str) -> Result<()> {
    run_nft_args_in_netns(netns, nft, &["delete", "table", "inet", OPENSHELL_TABLE])
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn cleanup_rules(netns: &Path) -> Result<()> {
    let _ = netns;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_nft_ruleset_in_netns(netns: &Path, nft: &str, ruleset: &str) -> Result<()> {
    use std::io::Write;

    let mut tmp = tempfile::Builder::new()
        .prefix("openshell-cni-")
        .suffix(".nft")
        .tempfile()
        .into_diagnostic()?;
    tmp.write_all(ruleset.as_bytes()).into_diagnostic()?;
    let ruleset_path = tmp.path().to_string_lossy().to_string();
    run_nft_args_in_netns(netns, nft, &["-f", &ruleset_path])
}

#[cfg(target_os = "linux")]
fn run_nft_args_in_netns(netns: &Path, nft: &str, args: &[&str]) -> Result<()> {
    run_command_in_netns(netns, nft, args)
}

#[cfg(target_os = "linux")]
fn run_command_in_netns(netns: &Path, program: &str, args: &[&str]) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let netns = std::fs::File::open(netns).into_diagnostic()?;
    let fd = netns.as_raw_fd();
    let output = {
        let mut command = Command::new(program);
        command.args(args);
        // SAFETY: pre_exec runs in the child after fork and before exec. setns
        // only affects that child process before it executes the firewall tool.
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(move || {
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.output().into_diagnostic()?
    };

    if output.status.success() {
        return Ok(());
    }
    Err(miette::miette!(
        "{} failed in CNI network namespace: {}",
        program,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(target_os = "linux")]
fn find_nft() -> Option<String> {
    find_existing_binary(NFT_SEARCH_PATHS)
}

#[cfg(target_os = "linux")]
fn find_iptables() -> Option<IptablesBackend> {
    find_existing_binary(IPTABLES_SEARCH_PATHS).map(|ipv4| IptablesBackend {
        ipv4,
        ipv6: find_existing_binary(IP6TABLES_SEARCH_PATHS),
    })
}

#[cfg(target_os = "linux")]
fn find_existing_binary(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}

#[cfg(target_os = "linux")]
struct IptablesBackend {
    ipv4: String,
    ipv6: Option<String>,
}

#[cfg(target_os = "linux")]
fn install_iptables_rules(
    netns: &Path,
    proxy_uid: u32,
    backend: &IptablesBackend,
    enforce_ipv6: bool,
) -> Result<()> {
    cleanup_iptables_family(netns, &backend.ipv4);
    install_iptables_family(netns, &backend.ipv4, proxy_uid, "icmp-port-unreachable")?;

    if enforce_ipv6 {
        // The pod has a routable IPv6 address, so unenforced IPv6 would be a
        // policy bypass. Fail closed if ip6tables is missing rather than leaving
        // IPv4-only enforcement in place. IPv4-only pods skip this entirely so
        // nodes without ip6tables still work.
        let ipv6 = backend.ipv6.as_deref().ok_or_else(|| {
            miette::miette!(
                "pod has IPv6 connectivity but ip6tables was not found on node; OpenShell CNI requires it to enforce IPv6 egress in the iptables fallback (install ip6tables or nft)"
            )
        })?;
        cleanup_iptables_family(netns, ipv6);
        install_iptables_family(netns, ipv6, proxy_uid, "icmp6-port-unreachable")?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_iptables_rules(netns: &Path, backend: &IptablesBackend) {
    cleanup_iptables_family(netns, &backend.ipv4);
    if let Some(ipv6) = backend.ipv6.as_deref() {
        cleanup_iptables_family(netns, ipv6);
    }
}

#[cfg(target_os = "linux")]
fn cleanup_iptables_family(netns: &Path, iptables: &str) {
    for _ in 0..16 {
        if run_command_in_netns(
            netns,
            iptables,
            &[
                "-w",
                "-t",
                "filter",
                "-D",
                "OUTPUT",
                "-j",
                OPENSHELL_IPTABLES_CHAIN,
            ],
        )
        .is_err()
        {
            break;
        }
    }
    let _ = run_command_in_netns(
        netns,
        iptables,
        &["-w", "-t", "filter", "-F", OPENSHELL_IPTABLES_CHAIN],
    );
    let _ = run_command_in_netns(
        netns,
        iptables,
        &["-w", "-t", "filter", "-X", OPENSHELL_IPTABLES_CHAIN],
    );
}

#[cfg(target_os = "linux")]
fn install_iptables_family(
    netns: &Path,
    iptables: &str,
    proxy_uid: u32,
    reject_with: &str,
) -> Result<()> {
    for args in generate_iptables_install_commands(proxy_uid, reject_with) {
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_command_in_netns(netns, iptables, &args)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn generate_iptables_install_commands(proxy_uid: u32, reject_with: &str) -> Vec<Vec<String>> {
    let uid = proxy_uid.to_string();
    [
        vec!["-w", "-t", "filter", "-N", OPENSHELL_IPTABLES_CHAIN],
        vec![
            "-w",
            "-t",
            "filter",
            "-A",
            OPENSHELL_IPTABLES_CHAIN,
            "-o",
            "lo",
            "-j",
            "RETURN",
        ],
        vec![
            "-w",
            "-t",
            "filter",
            "-A",
            OPENSHELL_IPTABLES_CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "RETURN",
        ],
        vec![
            "-w",
            "-t",
            "filter",
            "-A",
            OPENSHELL_IPTABLES_CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            &uid,
            "-j",
            "RETURN",
        ],
        vec![
            "-w",
            "-t",
            "filter",
            "-A",
            OPENSHELL_IPTABLES_CHAIN,
            "-p",
            "tcp",
            "-j",
            "REJECT",
            "--reject-with",
            reject_with,
        ],
        vec![
            "-w",
            "-t",
            "filter",
            "-A",
            OPENSHELL_IPTABLES_CHAIN,
            "-p",
            "udp",
            "-j",
            "REJECT",
            "--reject-with",
            reject_with,
        ],
        vec![
            "-w",
            "-t",
            "filter",
            "-I",
            "OUTPUT",
            "1",
            "-j",
            OPENSHELL_IPTABLES_CHAIN,
        ],
    ]
    .into_iter()
    .map(|args| args.into_iter().map(str::to_string).collect())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPods {
        annotations: BTreeMap<String, String>,
    }

    impl PodReader for TestPods {
        fn pod_annotations(
            &self,
            _kubeconfig: &Path,
            _pod: &PodRef,
        ) -> Result<BTreeMap<String, String>> {
            Ok(self.annotations.clone())
        }
    }

    #[derive(Default)]
    struct TestInstaller {
        installed: std::sync::Mutex<Vec<u32>>,
        cleaned: std::sync::Mutex<u32>,
    }

    impl RuleInstaller for TestInstaller {
        fn install(&self, _netns: &Path, proxy_uid: u32) -> Result<InstallReport> {
            self.installed.lock().unwrap().push(proxy_uid);
            Ok(InstallReport { backend: "test" })
        }

        fn cleanup(&self, _netns: &Path) -> Result<()> {
            *self.cleaned.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn cni_input() -> String {
        serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "openshell",
            "type": "openshell-cni",
            "prevResult": {
                "cniVersion": "1.0.0",
                "interfaces": []
            },
            "openshell": {
                "kubeconfig": "/tmp/openshell-kubeconfig",
                "sandboxNamespaces": ["openshell"]
            }
        })
        .to_string()
    }

    fn cni_input_with_log_file(log_file: &Path) -> String {
        serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "openshell",
            "type": "openshell-cni",
            "openshell": {
                "kubeconfig": "/tmp/openshell-kubeconfig",
                "sandboxNamespaces": ["openshell"],
                "logFile": log_file.to_string_lossy()
            }
        })
        .to_string()
    }

    fn env(command: &str) -> CniEnv {
        CniEnv {
            command: command.to_string(),
            netns: Some(PathBuf::from("/proc/1/ns/net")),
            args: Some("K8S_POD_NAMESPACE=openshell;K8S_POD_NAME=sandbox-1".to_string()),
        }
    }

    fn openshell_annotations() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                OPENSHELL_CNI_ENABLED_ANNOTATION.to_string(),
                "enabled".to_string(),
            ),
            (
                OPENSHELL_CNI_NETWORK_ENFORCEMENT_MODE_ANNOTATION.to_string(),
                CNI_SIDECAR_NETWORK_ENFORCEMENT_MODE.to_string(),
            ),
            (
                OPENSHELL_CNI_PROXY_UID_ANNOTATION.to_string(),
                "1337".to_string(),
            ),
        ])
    }

    #[test]
    fn parses_kubernetes_cni_args() {
        let pod = env("ADD").pod_ref().unwrap();
        assert_eq!(pod.namespace, "openshell");
        assert_eq!(pod.name, "sandbox-1");
    }

    #[test]
    fn version_returns_supported_versions() {
        let pods = TestPods {
            annotations: BTreeMap::new(),
        };
        let installer = TestInstaller::default();
        let output = handle_command("", &env("VERSION"), &pods, &installer)
            .unwrap()
            .unwrap();
        assert_eq!(output["cniVersion"], DEFAULT_CNI_VERSION);
        assert!(
            output["supportedVersions"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("0.3.1"))
        );
        assert!(
            output["supportedVersions"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("1.0.0"))
        );
    }

    #[test]
    fn add_installs_for_annotated_openshell_pod() {
        let pods = TestPods {
            annotations: openshell_annotations(),
        };
        let installer = TestInstaller::default();
        let output = handle_command(&cni_input(), &env("ADD"), &pods, &installer)
            .unwrap()
            .unwrap();
        assert_eq!(output["interfaces"], serde_json::json!([]));
        assert_eq!(*installer.installed.lock().unwrap(), vec![1337]);
    }

    #[test]
    fn add_passes_through_non_openshell_pod() {
        let pods = TestPods {
            annotations: BTreeMap::new(),
        };
        let installer = TestInstaller::default();
        let output = handle_command(&cni_input(), &env("ADD"), &pods, &installer)
            .unwrap()
            .unwrap();
        assert_eq!(output["interfaces"], serde_json::json!([]));
        assert!(installer.installed.lock().unwrap().is_empty());
    }

    #[test]
    fn add_passes_through_unconfigured_namespace_without_api_lookup() {
        struct FailingPods;

        impl PodReader for FailingPods {
            fn pod_annotations(
                &self,
                _kubeconfig: &Path,
                _pod: &PodRef,
            ) -> Result<BTreeMap<String, String>> {
                Err(miette::miette!("unexpected API lookup"))
            }
        }

        let installer = TestInstaller::default();
        let mut env = env("ADD");
        env.args = Some("K8S_POD_NAMESPACE=kube-system;K8S_POD_NAME=coredns".to_string());
        let output = handle_command(&cni_input(), &env, &FailingPods, &installer)
            .unwrap()
            .unwrap();
        assert_eq!(output["interfaces"], serde_json::json!([]));
        assert!(installer.installed.lock().unwrap().is_empty());
    }

    #[test]
    fn del_cleans_when_netns_available() {
        let pods = TestPods {
            annotations: openshell_annotations(),
        };
        let installer = TestInstaller::default();
        handle_command("", &env("DEL"), &pods, &installer).unwrap();
        assert_eq!(*installer.cleaned.lock().unwrap(), 1);
    }

    #[test]
    fn sidecar_ruleset_allows_proxy_uid_before_rejects() {
        let ruleset = generate_sidecar_bypass_ruleset(1337, Some("openshell:cni-sidecar:"));
        let uid_pos = ruleset.find("meta skuid 1337 accept").unwrap();
        let reject_pos = ruleset
            .find("meta nfproto ipv4 meta l4proto tcp reject")
            .unwrap();
        assert!(uid_pos < reject_pos);
        assert!(ruleset.contains("oifname \"lo\" accept"));
        assert_eq!(
            ruleset
                .matches("log prefix \"openshell:cni-sidecar:\"")
                .count(),
            2
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn iptables_fallback_commands_allow_proxy_uid_before_rejects() {
        let commands = generate_iptables_install_commands(1337, "icmp-port-unreachable");
        let rendered = commands
            .iter()
            .map(|command| command.join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        let uid_pos = rendered.find("--uid-owner 1337 -j RETURN").unwrap();
        let reject_pos = rendered.find("-p tcp -j REJECT").unwrap();
        assert!(uid_pos < reject_pos);
        assert!(rendered.contains("-A OPENSHELL_OUTPUT -o lo -j RETURN"));
        assert!(rendered.contains("-I OUTPUT 1 -j OPENSHELL_OUTPUT"));
        assert!(rendered.contains("--reject-with icmp-port-unreachable"));
    }

    #[test]
    fn cni_errors_append_to_configured_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_file = dir.path().join("openshell-cni.log");
        let error = miette::miette!(
            "neither nft nor iptables was found on node; OpenShell CNI requires a pod-network firewall backend"
        );

        log_cni_error(&cni_input_with_log_file(&log_file), &env("ADD"), &error);

        let log = std::fs::read_to_string(log_file).unwrap();
        assert!(log.contains("command=ADD"));
        assert!(log.contains("pod=openshell/sandbox-1"));
        assert!(log.contains("neither nft nor iptables was found"));
    }

    #[test]
    fn add_success_appends_to_configured_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_file = dir.path().join("openshell-cni.log");
        let pods = TestPods {
            annotations: openshell_annotations(),
        };
        let installer = TestInstaller::default();

        handle_command(
            &cni_input_with_log_file(&log_file),
            &env("ADD"),
            &pods,
            &installer,
        )
        .unwrap();

        let log = std::fs::read_to_string(log_file).unwrap();
        assert!(log.contains("command=ADD"));
        assert!(log.contains("pod=openshell/sandbox-1"));
        assert!(log.contains("status=installed"));
        assert!(log.contains("backend=test"));
        assert!(log.contains("proxy_uid=1337"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nft_search_path_includes_k3s_aux_path() {
        assert!(NFT_SEARCH_PATHS.contains(&"/bin/aux/nft"));
    }

    #[test]
    fn cni_error_payload_is_spec_compliant() {
        let error = miette::miette!("boom failure");
        let payload = cni_error_payload(&cni_input(), &error);
        assert_eq!(payload["cniVersion"], "1.0.0");
        assert_eq!(payload["code"], serde_json::json!(CNI_PLUGIN_ERROR_CODE));
        assert_eq!(payload["msg"], "OpenShell CNI plugin error");
        assert!(
            payload["details"]
                .as_str()
                .unwrap()
                .contains("boom failure")
        );
    }

    #[test]
    fn cni_error_payload_defaults_cni_version_on_unparseable_input() {
        let error = miette::miette!("boom");
        let payload = cni_error_payload("not valid json", &error);
        assert_eq!(payload["cniVersion"], DEFAULT_CNI_VERSION);
    }

    #[test]
    fn if_inet6_detects_global_and_ula() {
        // Global address on eth0.
        let contents = "fd0010244000000000000000000000005 03 40 00 80 eth0\n";
        assert!(if_inet6_has_non_loopback_ipv6(contents));
    }

    #[test]
    fn if_inet6_counts_link_local() {
        // Link-local fe80::/10 can still reach on-link peers and node services.
        let contents = "fe800000000000000042acfffe110002 02 40 20 80 eth0\n";
        assert!(if_inet6_has_non_loopback_ipv6(contents));
    }

    #[test]
    fn if_inet6_ignores_loopback_only() {
        // Only ::1 on lo → no enforcement needed.
        let contents = "00000000000000000000000000000001 01 80 10 80 lo\n";
        assert!(!if_inet6_has_non_loopback_ipv6(contents));
    }

    #[test]
    fn if_inet6_empty_means_no_ipv6() {
        assert!(!if_inet6_has_non_loopback_ipv6(""));
    }

    #[test]
    fn parse_node_ready_args_set_and_clear() {
        assert!(parse_node_ready_args(&["--set".to_string()]).unwrap());
        assert!(!parse_node_ready_args(&["--clear".to_string()]).unwrap());
    }

    #[test]
    fn parse_node_ready_args_requires_a_flag() {
        assert!(parse_node_ready_args(&[]).is_err());
    }

    #[test]
    fn parse_node_ready_args_rejects_unknown_flag() {
        assert!(parse_node_ready_args(&["--bogus".to_string()]).is_err());
    }
}
