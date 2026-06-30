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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstallReport {
    backend: &'static str,
}

pub fn run() -> Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .into_diagnostic()?;
    let env = CniEnv::from_process();
    let runtime = Runtime;
    let output = match handle_command(&input, &env, &runtime, &runtime) {
        Ok(output) => output,
        Err(error) => {
            log_cni_error(&input, &env, &error);
            return Err(error);
        }
    };
    if let Some(output) = output {
        println!("{}", serde_json::to_string(&output).into_diagnostic()?);
    }
    Ok(())
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
        install_iptables_rules(netns, proxy_uid, &iptables).wrap_err("iptables fallback failed")?;
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
fn install_iptables_rules(netns: &Path, proxy_uid: u32, backend: &IptablesBackend) -> Result<()> {
    cleanup_iptables_family(netns, &backend.ipv4);
    install_iptables_family(netns, &backend.ipv4, proxy_uid, "icmp-port-unreachable")?;

    if let Some(ipv6) = backend.ipv6.as_deref() {
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
}
