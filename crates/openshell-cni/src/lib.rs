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
/// Annotation the gateway stamps on each cni-sidecar pod naming the CNI contract
/// version it requires. The node plugin is a cluster singleton that may be an
/// older build than some gateways (mixed-version clusters), so it fails closed
/// rather than mis-enforcing a pod whose contract it does not implement. Must
/// stay in sync with the identical constant in `openshell-driver-kubernetes`.
const OPENSHELL_CNI_CONTRACT_VERSION_ANNOTATION: &str = "openshell.ai/cni-contract-version";
/// CNI contract version this plugin implements. Bump only on a breaking change to
/// the pod-annotation contract or the installed ruleset shape. The plugin accepts
/// any pod requiring a version <= this and refuses (fail closed) any requiring a
/// higher version. Absent annotation = a pre-versioning gateway, treated as
/// compatible.
const CNI_CONTRACT_VERSION: u32 = 1;
/// Node label set by the CNI installer once the chained plugin is in place and
/// cleared when it is not, so the gateway can gate sandbox scheduling on
/// per-node egress-enforcement readiness. Must stay in sync with the identical
/// constant in `openshell-driver-kubernetes` (used for the sandbox pod
/// nodeAffinity) and with the CNI `DaemonSet`'s node-patch RBAC.
const NODE_READY_LABEL: &str = "openshell.ai/cni-ready";
/// Node taint applied at boot (via an operator-provided `MachineConfig` / node
/// config) so a rebooted node repels workloads until egress enforcement is
/// re-established — the persistent `cni-ready` label cannot reflect a reboot that
/// wipes tmpfs-backed enforcement, so a boot-time taint narrows that window
/// (a small residual reboot race remains — see the `MachineConfig` example). The
/// installer only REMOVES this taint (once enforcement is ready); it never adds
/// it, so a transient unready never over-repels a running node. Must stay in sync
/// with the taint key used by the `MachineConfig` and the `DaemonSet` toleration.
const NODE_NOT_READY_TAINT_KEY: &str = "openshell.ai/cni-not-ready";
const NODE_NOT_READY_TAINT_EFFECT: &str = "NoSchedule";
/// Namespace label a gateway release stamps on its sandbox namespace so the CNI
/// singleton discovers and enforces it automatically — no manual allowlist edit
/// per release. The installer aggregates every namespace containing a marker
/// `ConfigMap` with this label into the plugin's `sandboxNamespaces`. The marker is
/// a Helm-owned resource, so uninstalling a release (or changing its sandbox
/// namespace) removes the marker and de-registers the namespace automatically.
const CNI_REGISTRATION_LABEL: &str = "openshell.ai/cni-registration";
/// Node annotation the installer sets to the sorted CSV of the namespaces it
/// currently enforces on that node, so the gateway can wait for cluster-wide
/// acknowledgement of its namespace before it serves sandboxes.
const NODE_COVERAGE_ANNOTATION: &str = "openshell.ai/cni-sandbox-namespaces";
/// Label selector identifying OpenShell-managed sandbox pods (set by the gateway
/// driver). Used to keep a namespace enforced while its sandboxes are still
/// running even after its registration marker is removed (drain-gated prune).
const SANDBOX_POD_LABEL_SELECTOR: &str = "openshell.ai/managed-by=openshell";
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
    /// Read-only validation that the bypass-prevention rules are present AND
    /// structurally complete for `proxy_uid` (the OUTPUT hook, the proxy-UID
    /// exemption, and TCP/UDP rejection across both address families). Must NOT
    /// modify live rules (CNI CHECK runs on a running pod; a destructive reinstall
    /// that fails would leave it unenforced).
    fn verify(&self, netns: &Path, proxy_uid: u32) -> Result<()>;
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
    if ready {
        // Set the label first (still fenced by the boot taint if present), then
        // remove the boot taint so scheduling opens only once both agree.
        client.patch_node_label(&node, NODE_READY_LABEL, Some("true"))?;
        client.remove_node_taint(&node, NODE_NOT_READY_TAINT_KEY, NODE_NOT_READY_TAINT_EFFECT)
    } else {
        // Clear the label to fence new sandbox pods. Do NOT add the taint here:
        // the taint is boot-managed (it would over-repel all workloads on a
        // transient unready); the label gate is sandbox-specific.
        client.patch_node_label(&node, NODE_READY_LABEL, None)
    }
}

/// Entry point for `openshell-cni list-sandbox-namespaces`.
///
/// Run by the installer reconcile to compute the enforcement allowlist. Prints,
/// one per line, the union of:
///   * namespaces containing a Helm-owned registration marker `ConfigMap`
///     (`openshell.ai/cni-registration=true`) — active registrations; and
///   * namespaces that still contain an OpenShell-managed sandbox pod
///     (`openshell.ai/managed-by=openshell`).
///
/// The second set makes the allowlist **monotonic while in use**: removing a
/// release's marker does not immediately drop enforcement for a namespace whose
/// sandboxes are still running (which would fail-open their recreated pods). The
/// namespace is pruned only once it is drained — no marker and no sandbox pods.
pub fn list_sandbox_namespaces() -> Result<()> {
    let client = KubeApiClient::from_in_cluster()?;
    let mut namespaces = client.list_registration_namespaces(CNI_REGISTRATION_LABEL)?;
    namespaces.extend(client.list_sandbox_pod_namespaces(SANDBOX_POD_LABEL_SELECTOR)?);
    namespaces.sort();
    namespaces.dedup();
    for ns in namespaces {
        println!("{ns}");
    }
    Ok(())
}

/// Entry point for `openshell-cni set-node-coverage <csv>`.
///
/// Run by the installer reconcile to publish, on its own node, the sorted CSV of
/// namespaces it currently enforces, so gateways can wait for cluster-wide
/// acknowledgement of their namespace before serving sandboxes.
pub fn set_node_coverage(args: &[String]) -> Result<()> {
    let csv = args.first().map_or("", String::as_str);
    let node = std::env::var("NODE_NAME")
        .map_err(|_| miette::miette!("NODE_NAME env var is required for set-node-coverage"))?;
    let client = KubeApiClient::from_in_cluster()?;
    client.patch_node_annotation(&node, NODE_COVERAGE_ANNOTATION, csv)
}

/// Entry point for `openshell-cni wait-coverage <namespace>`, run as a gateway
/// init container so the gateway does not serve sandboxes until every
/// enforcement-ready node acknowledges the namespace.
///
/// Blocks until at least one node carries the `cni-ready` label and every such
/// node's coverage annotation includes the namespace. Times out (non-zero exit,
/// failing the init container fail-closed) after a bounded wait.
pub fn wait_coverage(args: &[String]) -> Result<()> {
    let namespace = args
        .first()
        .ok_or_else(|| miette::miette!("wait-coverage requires a namespace argument"))?;
    let client = KubeApiClient::from_in_cluster()?;
    // ~5 minutes of 5s polls; fail closed if enforcement never converges.
    for _ in 0..60 {
        match client.namespace_covered_on_all_ready_nodes(
            namespace,
            NODE_READY_LABEL,
            NODE_COVERAGE_ANNOTATION,
        ) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => eprintln!("wait-coverage: transient error: {error:?}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    Err(miette::miette!(
        "namespace {namespace} not enforced on all cni-ready nodes within timeout"
    ))
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
                // CHECK is read-only: verify the rules are present and structurally
                // complete without touching them, so a check never leaves a running
                // pod momentarily unenforced.
                installer.verify(netns, workload.proxy_uid)?;
                let report = InstallReport {
                    backend: "verified",
                };
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
    // sandbox_namespaces is the allowlist of namespaces whose pods we inspect.
    // A pod outside it is passed through immediately WITHOUT a Kubernetes API
    // lookup — a blast-radius guard so control-plane/RBAC problems cannot block
    // unrelated workloads' pod creation. Within the allowlist, enforcement is
    // gated by the per-pod OpenShell annotations below (set only by a gateway on
    // its own sandbox pods). The singleton installer populates this from
    // cni.sandboxNamespaces (default: the release's sandbox namespace). An empty
    // list means "any namespace" and is intentionally avoided by the chart.
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
    // Fail closed on version skew: if this (possibly older) singleton plugin does
    // not implement the contract the pod's gateway requires, refuse rather than
    // install rules that may not match the gateway's expectations. An absent
    // annotation is a pre-versioning gateway and is treated as compatible.
    if let Some(required) = annotations.get(OPENSHELL_CNI_CONTRACT_VERSION_ANNOTATION) {
        let required: u32 = required
            .parse()
            .into_diagnostic()
            .wrap_err("invalid OpenShell CNI contract version annotation")?;
        if required > CNI_CONTRACT_VERSION {
            return Err(miette::miette!(
                "pod requires OpenShell CNI contract version {required} but this node plugin implements {CNI_CONTRACT_VERSION}; upgrade the openshell-cni installer (mixed-version cluster)"
            ));
        }
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

/// Blocking HTTP client builder with bounded connect and request deadlines. The
/// CNI plugin runs synchronously on the CNI ADD path and in the installer's
/// reconcile/coverage loops; without deadlines an API stall would wedge pod
/// creation, invalidate the coverage wait's time bound, and stall reconciliation.
fn kube_client_builder() -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
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
        let mut builder = kube_client_builder();
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
        let client = kube_client_builder()
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

    /// Sets a single node annotation to `value` via a JSON merge patch.
    fn patch_node_annotation(&self, node: &str, key: &str, value: &str) -> Result<()> {
        let url = format!("{}/api/v1/nodes/{}", self.server, node);
        let body = serde_json::json!({ "metadata": { "annotations": { key: Value::String(value.to_string()) } } });
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
            .wrap_err("failed to patch node annotation")?;
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while annotating node {}",
                response.status(),
                node
            ));
        }
        Ok(())
    }

    /// Returns the namespaces of all registration marker `ConfigMaps` (those
    /// carrying `key=true`) across the cluster.
    fn list_registration_namespaces(&self, key: &str) -> Result<Vec<String>> {
        let selector = format!("{key}=true");
        let url = format!("{}/api/v1/configmaps", self.server);
        let response = self
            .client
            .get(url)
            .query(&[("labelSelector", selector.as_str())])
            .bearer_auth(&self.token)
            .send()
            .into_diagnostic()
            .wrap_err("failed to list registration ConfigMaps")?;
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while listing ConfigMaps",
                response.status()
            ));
        }
        let list = response.json::<Value>().into_diagnostic()?;
        let mut namespaces: Vec<String> = list["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["metadata"]["namespace"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        namespaces.sort();
        namespaces.dedup();
        Ok(namespaces)
    }

    /// Returns the distinct namespaces of all pods matching `selector`
    /// cluster-wide (used to keep enforcement for namespaces with live sandboxes).
    fn list_sandbox_pod_namespaces(&self, selector: &str) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/pods", self.server);
        let response = self
            .client
            .get(url)
            .query(&[("labelSelector", selector)])
            .bearer_auth(&self.token)
            .send()
            .into_diagnostic()
            .wrap_err("failed to list sandbox pods")?;
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while listing sandbox pods",
                response.status()
            ));
        }
        let list = response.json::<Value>().into_diagnostic()?;
        let mut namespaces: Vec<String> = list["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["metadata"]["namespace"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        namespaces.sort();
        namespaces.dedup();
        Ok(namespaces)
    }

    /// Returns true when at least one node carries `ready_label` and every such
    /// node's `coverage_annotation` (a comma-separated list) contains `namespace`.
    fn namespace_covered_on_all_ready_nodes(
        &self,
        namespace: &str,
        ready_label: &str,
        coverage_annotation: &str,
    ) -> Result<bool> {
        let url = format!("{}/api/v1/nodes", self.server);
        let response = self
            .client
            .get(url)
            .query(&[("labelSelector", ready_label)])
            .bearer_auth(&self.token)
            .send()
            .into_diagnostic()
            .wrap_err("failed to list cni-ready nodes")?;
        if !response.status().is_success() {
            return Err(miette::miette!(
                "Kubernetes API returned {} while listing nodes",
                response.status()
            ));
        }
        let list = response.json::<Value>().into_diagnostic()?;
        let Some(nodes) = list["items"].as_array() else {
            return Ok(false);
        };
        if nodes.is_empty() {
            return Ok(false);
        }
        Ok(nodes.iter().all(|node| {
            node["metadata"]["annotations"][coverage_annotation]
                .as_str()
                .unwrap_or_default()
                .split(',')
                .any(|ns| ns == namespace)
        }))
    }

    /// Removes the given taint (key + effect) from the node if present, using a
    /// JSON Patch whose `test` on `metadata.resourceVersion` provides optimistic
    /// concurrency so a concurrent taint change by another controller is not
    /// clobbered (retried on conflict). A no-op when the taint is absent.
    fn remove_node_taint(&self, node: &str, key: &str, effect: &str) -> Result<()> {
        let url = format!("{}/api/v1/nodes/{}", self.server, node);
        for _attempt in 0..5 {
            let obj = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .into_diagnostic()
                .wrap_err("failed to read node for taint removal")?;
            if !obj.status().is_success() {
                return Err(miette::miette!(
                    "Kubernetes API returned {} while reading node {}",
                    obj.status(),
                    node
                ));
            }
            let node_obj = obj.json::<Value>().into_diagnostic()?;
            let resource_version = node_obj["metadata"]["resourceVersion"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let taints = node_obj["spec"]["taints"].as_array();
            let filtered: Vec<Value> = taints
                .map(|list| {
                    list.iter()
                        .filter(|t| {
                            !(t["key"].as_str() == Some(key)
                                && t["effect"].as_str() == Some(effect))
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            // Nothing to remove.
            if taints.is_none_or(|list| list.len() == filtered.len()) {
                return Ok(());
            }
            let patch = serde_json::json!([
                { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
                { "op": "replace", "path": "/spec/taints", "value": filtered },
            ]);
            let response = self
                .client
                .patch(&url)
                .bearer_auth(&self.token)
                .header(reqwest::header::CONTENT_TYPE, "application/json-patch+json")
                .body(serde_json::to_vec(&patch).into_diagnostic()?)
                .send()
                .into_diagnostic()
                .wrap_err("failed to patch node taints")?;
            let status = response.status().as_u16();
            // 409 (resourceVersion conflict) or 422 (test op failed) → retry.
            if status == 409 || status == 422 {
                continue;
            }
            if !response.status().is_success() {
                return Err(miette::miette!(
                    "Kubernetes API returned {} while removing taint from node {}",
                    response.status(),
                    node
                ));
            }
            return Ok(());
        }
        Err(miette::miette!(
            "failed to remove taint from node {node} after retries (conflict)"
        ))
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

    fn verify(&self, netns: &Path, proxy_uid: u32) -> Result<()> {
        verify_rules(netns, proxy_uid)
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
    // Atomic replace: ensure-exists, delete, recreate in a SINGLE `nft -f`
    // transaction. nft applies the whole file atomically, so a failure never
    // leaves the pod with the table deleted-but-not-recreated (unenforced). The
    // leading `table {}` makes the subsequent `delete table` safe on first apply.
    let body = generate_sidecar_bypass_ruleset(proxy_uid, Some("openshell:cni-sidecar:"));
    let ruleset =
        format!("table inet {OPENSHELL_TABLE} {{}}\ndelete table inet {OPENSHELL_TABLE}\n{body}");
    run_nft_ruleset_in_netns(netns, &nft, &ruleset)
}

/// Read-only check that the bypass-prevention rules are present AND structurally
/// complete in the netns. Never modifies live rules. Prefers nft (one inet table
/// covers both families), falls back to iptables. Merely finding the table/chain
/// is not enough: an empty or partially damaged ruleset would pass while allowing
/// bypass, so the dump is validated for the OUTPUT hook, the proxy-UID exemption,
/// and TCP/UDP rejection on both address families.
#[cfg(target_os = "linux")]
fn verify_rules(netns: &Path, proxy_uid: u32) -> Result<()> {
    if let Some(nft) = find_nft() {
        if let Ok(dump) =
            run_command_capture_in_netns(netns, &nft, &["list", "table", "inet", OPENSHELL_TABLE])
        {
            return verify_nft_ruleset(&dump, proxy_uid);
        }
    }
    if let Some(iptables) = find_iptables() {
        return verify_iptables_rules(netns, &iptables, proxy_uid);
    }
    Err(miette::miette!(
        "OpenShell CNI bypass-prevention rules are not present in the pod network namespace"
    ))
}

/// Validates a `nft list table inet openshell_sidecar_bypass` dump has the full
/// egress fence. nft programs both families in one inet table, so one dump covers
/// IPv4 and IPv6.
// Non-Linux builds compile this pure validator for unit tests but have no runtime
// caller (verify_rules is Linux-only).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn verify_nft_ruleset(dump: &str, proxy_uid: u32) -> Result<()> {
    let required: [(&str, String); 6] = [
        ("output hook", "hook output".to_string()),
        ("proxy-UID exemption", format!("skuid {proxy_uid}")),
        ("IPv4 family rule", "nfproto ipv4".to_string()),
        ("IPv6 family rule", "nfproto ipv6".to_string()),
        ("TCP rejection", "tcp reject".to_string()),
        ("UDP rejection", "udp reject".to_string()),
    ];
    for (what, needle) in &required {
        if !dump.contains(needle) {
            return Err(miette::miette!(
                "OpenShell CNI nft ruleset is incomplete: missing {what} (expected `{needle}`)"
            ));
        }
    }
    Ok(())
}

/// Validates the iptables fallback for both families it programmed. IPv4 is always
/// required; IPv6 is required only when the pod has routable IPv6 (mirrors
/// install), so an IPv4-only pod is not failed for absent ip6tables rules.
#[cfg(target_os = "linux")]
fn verify_iptables_rules(netns: &Path, backend: &IptablesBackend, proxy_uid: u32) -> Result<()> {
    verify_iptables_family(netns, &backend.ipv4, proxy_uid, "IPv4")?;
    if netns_requires_ipv6_enforcement(netns) {
        let ipv6 = backend.ipv6.as_deref().ok_or_else(|| {
            miette::miette!(
                "pod has IPv6 connectivity but ip6tables enforcement is absent; OpenShell CNI egress is bypassable over IPv6"
            )
        })?;
        verify_iptables_family(netns, ipv6, proxy_uid, "IPv6")?;
    }
    Ok(())
}

/// Confirms the OUTPUT chain jumps to OPENSHELL_OUTPUT and that chain contains the
/// proxy-UID exemption plus TCP and UDP rejection, for one iptables family.
#[cfg(target_os = "linux")]
fn verify_iptables_family(
    netns: &Path,
    iptables: &str,
    proxy_uid: u32,
    family: &str,
) -> Result<()> {
    if run_command_in_netns(
        netns,
        iptables,
        &[
            "-w",
            "-t",
            "filter",
            "-C",
            "OUTPUT",
            "-j",
            OPENSHELL_IPTABLES_CHAIN,
        ],
    )
    .is_err()
    {
        return Err(miette::miette!(
            "OpenShell CNI {family} enforcement is incomplete: OUTPUT does not jump to {OPENSHELL_IPTABLES_CHAIN}"
        ));
    }
    let spec = run_command_capture_in_netns(
        netns,
        iptables,
        &["-w", "-t", "filter", "-S", OPENSHELL_IPTABLES_CHAIN],
    )
    .map_err(|_| {
        miette::miette!(
            "OpenShell CNI {family} enforcement is incomplete: {OPENSHELL_IPTABLES_CHAIN} chain is absent"
        )
    })?;
    verify_iptables_chain_spec(&spec, proxy_uid, family)
}

/// Validates an `iptables -S OPENSHELL_OUTPUT` chain spec for one family.
// Non-Linux builds compile this pure validator for unit tests but have no runtime
// caller (verify_iptables_family is Linux-only).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn verify_iptables_chain_spec(spec: &str, proxy_uid: u32, family: &str) -> Result<()> {
    let required: [(&str, String); 3] = [
        ("proxy-UID exemption", format!("--uid-owner {proxy_uid}")),
        ("TCP rejection", "-p tcp -j REJECT".to_string()),
        ("UDP rejection", "-p udp -j REJECT".to_string()),
    ];
    for (what, needle) in &required {
        if !spec.contains(needle) {
            return Err(miette::miette!(
                "OpenShell CNI {family} enforcement is incomplete: missing {what} (expected `{needle}`)"
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_rules(netns: &Path, proxy_uid: u32) -> Result<()> {
    let _ = (netns, proxy_uid);
    Err(miette::miette!(
        "OpenShell CNI rule verification is supported only on Linux nodes"
    ))
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
    run_command_capture_in_netns(netns, program, args).map(|_| ())
}

/// Like `run_command_in_netns` but returns the command's stdout on success. Used
/// by the read-only CHECK path to inspect the live ruleset structure.
#[cfg(target_os = "linux")]
fn run_command_capture_in_netns(netns: &Path, program: &str, args: &[&str]) -> Result<String> {
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
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
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
        verified: std::sync::Mutex<u32>,
        cleaned: std::sync::Mutex<u32>,
    }

    impl RuleInstaller for TestInstaller {
        fn install(&self, _netns: &Path, proxy_uid: u32) -> Result<InstallReport> {
            self.installed.lock().unwrap().push(proxy_uid);
            Ok(InstallReport { backend: "test" })
        }

        fn verify(&self, _netns: &Path, _proxy_uid: u32) -> Result<()> {
            *self.verified.lock().unwrap() += 1;
            Ok(())
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
    fn add_accepts_supported_and_absent_contract_version() {
        // Absent annotation (pre-versioning gateway) is compatible.
        let installer = TestInstaller::default();
        handle_command(
            &cni_input(),
            &env("ADD"),
            &TestPods {
                annotations: openshell_annotations(),
            },
            &installer,
        )
        .unwrap();
        assert_eq!(*installer.installed.lock().unwrap(), vec![1337]);

        // Version equal to what the plugin implements is accepted.
        let mut annotations = openshell_annotations();
        annotations.insert(
            OPENSHELL_CNI_CONTRACT_VERSION_ANNOTATION.to_string(),
            CNI_CONTRACT_VERSION.to_string(),
        );
        let installer = TestInstaller::default();
        handle_command(
            &cni_input(),
            &env("ADD"),
            &TestPods { annotations },
            &installer,
        )
        .unwrap();
        assert_eq!(*installer.installed.lock().unwrap(), vec![1337]);
    }

    #[test]
    fn add_fails_closed_on_higher_contract_version() {
        // A newer gateway requires a contract this (older) plugin does not
        // implement: refuse rather than install rules that may not match.
        let mut annotations = openshell_annotations();
        annotations.insert(
            OPENSHELL_CNI_CONTRACT_VERSION_ANNOTATION.to_string(),
            (CNI_CONTRACT_VERSION + 1).to_string(),
        );
        let installer = TestInstaller::default();
        let err = handle_command(
            &cni_input(),
            &env("ADD"),
            &TestPods { annotations },
            &installer,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("contract version"), "unexpected error: {err}");
        // Fail closed: nothing installed.
        assert!(installer.installed.lock().unwrap().is_empty());
    }

    #[test]
    fn check_verifies_without_reinstalling() {
        let pods = TestPods {
            annotations: openshell_annotations(),
        };
        let installer = TestInstaller::default();
        handle_command(&cni_input(), &env("CHECK"), &pods, &installer).unwrap();
        // CHECK must be read-only: verify, never install (a destructive reinstall
        // that failed would leave the running pod unenforced).
        assert_eq!(*installer.verified.lock().unwrap(), 1);
        assert!(installer.installed.lock().unwrap().is_empty());
    }

    // A representative `nft list table inet openshell_sidecar_bypass` dump for the
    // complete ruleset (nft renders priority 0 as `priority filter`).
    fn nft_dump(proxy_uid: u32) -> String {
        format!(
            "table inet openshell_sidecar_bypass {{\n\
             \tchain output {{\n\
             \t\ttype filter hook output priority filter; policy accept;\n\
             \t\toifname \"lo\" accept\n\
             \t\tct state established,related accept\n\
             \t\tmeta skuid {proxy_uid} accept\n\
             \t\tmeta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable\n\
             \t\tmeta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable\n\
             \t\tmeta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable\n\
             \t\tmeta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable\n\
             \t}}\n\
             }}\n"
        )
    }

    #[test]
    fn verify_nft_ruleset_accepts_complete_dump() {
        assert!(verify_nft_ruleset(&nft_dump(0), 0).is_ok());
        assert!(verify_nft_ruleset(&nft_dump(1337), 1337).is_ok());
    }

    #[test]
    fn verify_nft_ruleset_rejects_empty_chain() {
        // Table/chain exist but the fence rules are gone — must NOT pass.
        let empty = "table inet openshell_sidecar_bypass {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n}\n";
        let err = verify_nft_ruleset(empty, 0).unwrap_err().to_string();
        assert!(err.contains("incomplete"), "unexpected error: {err}");
    }

    #[test]
    fn verify_nft_ruleset_rejects_wrong_uid_and_missing_family() {
        // Exemption for a different UID than the sidecar proxy runs as.
        assert!(verify_nft_ruleset(&nft_dump(0), 1337).is_err());
        // Drop the IPv6 reject rules: IPv6 egress would be unenforced.
        let ipv4_only: String = nft_dump(0)
            .lines()
            .filter(|line| !line.contains("nfproto ipv6"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = verify_nft_ruleset(&ipv4_only, 0).unwrap_err().to_string();
        assert!(err.contains("IPv6"), "unexpected error: {err}");
    }

    #[test]
    fn verify_iptables_chain_spec_accepts_complete_and_rejects_partial() {
        let complete = "-N OPENSHELL_OUTPUT\n\
             -A OPENSHELL_OUTPUT -o lo -j RETURN\n\
             -A OPENSHELL_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n\
             -A OPENSHELL_OUTPUT -m owner --uid-owner 0 -j RETURN\n\
             -A OPENSHELL_OUTPUT -p tcp -j REJECT --reject-with icmp-port-unreachable\n\
             -A OPENSHELL_OUTPUT -p udp -j REJECT --reject-with icmp-port-unreachable\n";
        assert!(verify_iptables_chain_spec(complete, 0, "IPv4").is_ok());
        // Wrong UID.
        assert!(verify_iptables_chain_spec(complete, 1337, "IPv4").is_err());
        // Missing UDP rejection.
        let no_udp: String = complete
            .lines()
            .filter(|line| !line.contains("-p udp"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = verify_iptables_chain_spec(&no_udp, 0, "IPv4")
            .unwrap_err()
            .to_string();
        assert!(err.contains("UDP"), "unexpected error: {err}");
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
