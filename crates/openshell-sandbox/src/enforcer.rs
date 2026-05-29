// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Node/host enforcer entrypoint and workload registration client.
//!
//! The node enforcer runs as a privileged host-PID DaemonSet. Workload
//! supervisors register after loading policy and before spawning the agent
//! process. The enforcer locates the pod network namespace by pod IP and
//! installs coarse nftables rules in that namespace:
//!
//! - loopback traffic is allowed so sandbox processes can reach the local proxy
//! - UID 0 traffic is allowed so the supervisor-owned proxy can reach upstreams
//! - non-root TCP/UDP egress is rejected, forcing sandbox-user traffic through
//!   the proxy where OPA and L7 policy are evaluated

use miette::{IntoDiagnostic, Result};
use openshell_core::sandbox_env::NetworkEnforcementMode;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};
use url::Url;

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:17671";
#[cfg(target_os = "linux")]
const ENFORCER_TABLE: &str = "openshell_external_enforcer";
#[cfg(target_os = "linux")]
const NFT_SEARCH_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];
#[cfg(target_os = "linux")]
const PROC_ROOT: &str = "/proc";

#[derive(Debug, Clone)]
pub struct EnforcerRuntimeConfig {
    pub listen_addr: SocketAddr,
    pub network_enforcement_mode: NetworkEnforcementMode,
}

#[derive(Debug, Clone)]
pub struct WorkloadRegistration {
    pub endpoint: String,
    pub sandbox_id: String,
    pub sandbox_name: Option<String>,
    pub pod_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistrationPayload {
    sandbox_id: String,
    sandbox_name: Option<String>,
    pod_ip: Option<String>,
    protocol: Option<String>,
}

pub async fn run(config: EnforcerRuntimeConfig) -> Result<i32> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .into_diagnostic()?;
    warn!(
        listen_addr = %config.listen_addr,
        network_enforcement_mode = %config.network_enforcement_mode,
        "OpenShell node enforcer started; workload registrations install coarse pod-netns egress rules"
    );
    info!(
        listen_addr = %config.listen_addr,
        "Node enforcer is watching for workload supervisor registrations"
    );

    loop {
        let (stream, peer) = listener.accept().await.into_diagnostic()?;
        let mode = config.network_enforcement_mode;
        tokio::spawn(async move {
            if let Err(error) = handle_registration(stream, peer, mode).await {
                debug!(error = %error, peer = %peer, "Failed to handle enforcer request");
            }
        });
    }
}

async fn handle_registration(
    mut stream: TcpStream,
    peer: SocketAddr,
    mode: NetworkEnforcementMode,
) -> Result<()> {
    let request_bytes = read_http_request(&mut stream).await?;
    let request = String::from_utf8_lossy(&request_bytes);
    let request_line = request.lines().next().unwrap_or_default();
    let payload = request
        .split_once("\r\n\r\n")
        .and_then(|(_, body)| serde_json::from_str::<RegistrationPayload>(body).ok());

    if let Some(payload) = payload {
        info!(
            peer = %peer,
            request = request_line,
            sandbox_id = %payload.sandbox_id,
            sandbox_name = payload.sandbox_name.as_deref().unwrap_or_default(),
            pod_ip = payload.pod_ip.as_deref().unwrap_or_default(),
            protocol = payload.protocol.as_deref().unwrap_or_default(),
            "Observed sandbox workload registration"
        );
        info!(
            sandbox_id = %payload.sandbox_id,
            pod_ip = payload.pod_ip.as_deref().unwrap_or_default(),
            network_enforcement_mode = %mode,
            action = "install-coarse-egress-enforcement",
            "Reconciling sandbox network enforcement"
        );

        if matches!(mode, NetworkEnforcementMode::ExternalEnforcer) {
            let target_ip = target_pod_ip(&payload, peer);
            if let Some(pod_ip) = target_ip {
                let sandbox_id = payload.sandbox_id.clone();
                install_external_enforcement_blocking(sandbox_id, pod_ip).await?;
            } else {
                warn!(
                    peer = %peer,
                    sandbox_id = %payload.sandbox_id,
                    pod_ip = payload.pod_ip.as_deref().unwrap_or_default(),
                    "Skipping host-side enforcement because no non-loopback pod IP is available"
                );
            }
        }
    } else {
        warn!(
            peer = %peer,
            request = request_line,
            "Accepted workload supervisor registration without parseable payload"
        );
    }

    let response = concat!(
        "HTTP/1.1 202 Accepted\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n",
        "\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .await
        .into_diagnostic()?;
    Ok(())
}

async fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; 8192];
    let mut len = 0_usize;
    let mut header_end = None;

    while len < buf.len() {
        let read = stream.read(&mut buf[len..]).await.into_diagnostic()?;
        if read == 0 {
            break;
        }
        len += read;
        if let Some(pos) = find_header_end(&buf[..len]) {
            header_end = Some(pos);
            break;
        }
    }

    let Some(header_end) = header_end else {
        buf.truncate(len);
        return Ok(buf);
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| line.split_once(':'))
        .and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let request_len = header_end + 4 + content_length;

    if request_len > buf.len() {
        buf.resize(request_len, 0);
    }
    while len < request_len {
        let read = stream
            .read(&mut buf[len..request_len])
            .await
            .into_diagnostic()?;
        if read == 0 {
            break;
        }
        len += read;
    }

    buf.truncate(len);
    Ok(buf)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn target_pod_ip(payload: &RegistrationPayload, peer: SocketAddr) -> Option<IpAddr> {
    payload
        .pod_ip
        .as_deref()
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .or_else(|| (!peer.ip().is_loopback()).then_some(peer.ip()))
        .filter(|ip| !ip.is_loopback())
}

#[cfg(target_os = "linux")]
async fn install_external_enforcement_blocking(sandbox_id: String, pod_ip: IpAddr) -> Result<()> {
    tokio::task::spawn_blocking(move || install_external_enforcement(&sandbox_id, pod_ip))
        .await
        .map_err(|error| miette::miette!("enforcer task panicked: {error}"))?
}

#[cfg(not(target_os = "linux"))]
async fn install_external_enforcement_blocking(sandbox_id: String, pod_ip: IpAddr) -> Result<()> {
    let _ = sandbox_id;
    Err(miette::miette!(
        "external node enforcement is only supported on Linux nodes (pod_ip={pod_ip})"
    ))
}

#[cfg(target_os = "linux")]
fn install_external_enforcement(sandbox_id: &str, pod_ip: IpAddr) -> Result<()> {
    info!(
        sandbox_id,
        pod_ip = %pod_ip,
        "Installing sandbox network egress enforcement for pod {pod_ip}"
    );
    let netns_path = find_pod_netns_path(pod_ip)?;
    let nft_path = find_nft().ok_or_else(|| {
        miette::miette!(
            "nft binary not found; node enforcer image must include nftables for external enforcement"
        )
    })?;

    delete_enforcer_table(&netns_path, &nft_path);
    let ruleset = generate_external_enforcer_ruleset(&external_log_prefix(sandbox_id));
    run_nft_ruleset_in_netns(&netns_path, &nft_path, &ruleset)?;

    info!(
        sandbox_id,
        pod_ip = %pod_ip,
        netns = %netns_path.display(),
        "Sandbox network egress enforcement installed for pod {pod_ip} in {}",
        netns_path.display()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn find_pod_netns_path(pod_ip: IpAddr) -> Result<PathBuf> {
    let mut last_error = None;
    for _ in 0..20 {
        match find_pod_netns_path_once(pod_ip) {
            Ok(path) => return Ok(path),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(last_error.unwrap_or_else(|| {
        miette::miette!("failed to find pod network namespace for pod IP {pod_ip}")
    }))
}

#[cfg(target_os = "linux")]
fn find_pod_netns_path_once(pod_ip: IpAddr) -> Result<PathBuf> {
    let proc = Path::new(PROC_ROOT);
    let entries = std::fs::read_dir(proc).into_diagnostic()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str() else {
            continue;
        };
        if !pid.as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }

        let netns_path = proc.join(pid).join("ns/net");
        if !netns_path.exists() {
            continue;
        }

        if proc_netns_has_local_ip(&proc.join(pid), pod_ip) {
            return Ok(netns_path);
        }
    }

    Err(miette::miette!(
        "failed to find pod network namespace for pod IP {pod_ip}"
    ))
}

#[cfg(target_os = "linux")]
fn proc_netns_has_local_ip(proc_pid_path: &Path, pod_ip: IpAddr) -> bool {
    match pod_ip {
        IpAddr::V4(ip) => {
            let fib_trie_path = proc_pid_path.join("net/fib_trie");
            let Ok(fib_trie) = std::fs::read_to_string(&fib_trie_path) else {
                return false;
            };
            fib_trie_contains_local_address(&fib_trie, &ip.to_string())
        }
        IpAddr::V6(ip) => {
            let if_inet6_path = proc_pid_path.join("net/if_inet6");
            let Ok(if_inet6) = std::fs::read_to_string(&if_inet6_path) else {
                return false;
            };
            let compact = ip
                .segments()
                .iter()
                .map(|segment| format!("{segment:04x}"))
                .collect::<String>();
            if_inet6
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .any(|address| address.eq_ignore_ascii_case(&compact))
        }
    }
}

#[cfg(target_os = "linux")]
fn fib_trie_contains_local_address(fib_trie: &str, pod_ip: &str) -> bool {
    let mut matched_leaf = false;

    for line in fib_trie.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(marker), Some(address)) = (parts.next(), parts.next())
            && marker.ends_with("--")
        {
            matched_leaf = address == pod_ip;
            continue;
        }

        if matched_leaf && line.split_whitespace().eq(["/32", "host", "LOCAL"]) {
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn delete_enforcer_table(netns_path: &Path, nft_path: &str) {
    if let Err(error) = run_nft_args_in_netns(
        netns_path,
        nft_path,
        &["delete", "table", "inet", ENFORCER_TABLE],
    ) {
        debug!(
            error = %error,
            netns = %netns_path.display(),
            "No prior external enforcer nftables table to delete"
        );
    }
}

#[cfg(target_os = "linux")]
fn run_nft_ruleset_in_netns(netns_path: &Path, nft_path: &str, ruleset: &str) -> Result<()> {
    let mut file = tempfile::Builder::new()
        .prefix("openshell-external-enforcer-")
        .suffix(".nft")
        .tempfile()
        .into_diagnostic()?;
    std::io::Write::write_all(&mut file, ruleset.as_bytes()).into_diagnostic()?;
    let path = file.path().to_string_lossy().to_string();
    run_nft_args_in_netns(netns_path, nft_path, &["-f", &path])
}

#[cfg(target_os = "linux")]
fn run_nft_args_in_netns(netns_path: &Path, nft_path: &str, args: &[&str]) -> Result<()> {
    let netns = std::fs::File::open(netns_path).into_diagnostic()?;
    let fd = netns.as_raw_fd();
    let output = {
        let mut command = Command::new(nft_path);
        command.args(args);
        // SAFETY: pre_exec runs in the child after fork and before exec. setns
        // is async-signal-safe and only affects the child process.
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(move || {
                let result = libc::setns(fd, libc::CLONE_NEWNET);
                if result != 0 {
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(miette::miette!(
        "nft command failed in pod netns: {}",
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
fn generate_external_enforcer_ruleset(log_prefix: &str) -> String {
    format!(
        r#"table inet {ENFORCER_TABLE} {{
    chain output {{
        type filter hook output priority 0; policy accept;

        oifname "lo" accept
        ct state established,related accept
        meta skuid 0 accept
        tcp flags syn limit rate 5/second burst 10 packets log prefix "{log_prefix}" flags skuid
        meta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable
        meta l4proto udp limit rate 5/second burst 10 packets log prefix "{log_prefix}" flags skuid
        meta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable
    }}
}}
"#
    )
}

#[cfg(target_os = "linux")]
fn external_log_prefix(sandbox_id: &str) -> String {
    let short_id: String = sandbox_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(16)
        .collect();
    format!("openshell:external:{short_id}:")
}

#[cfg(target_os = "linux")]
fn find_nft() -> Option<String> {
    NFT_SEARCH_PATHS
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}

pub async fn register_workload(registration: WorkloadRegistration) -> Result<()> {
    let url = Url::parse(registration.endpoint.trim()).into_diagnostic()?;
    if url.scheme() != "http" {
        return Err(miette::miette!(
            "external enforcer endpoint must use http:// for the prototype registration protocol"
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| miette::miette!("external enforcer endpoint is missing a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| miette::miette!("external enforcer endpoint is missing a port"))?;
    let addr = format!("{host}:{port}");
    let path = if url.path().is_empty() || url.path() == "/" {
        format!("/v1/sandboxes/{}/register", registration.sandbox_id)
    } else {
        url.path().to_string()
    };

    let mut stream = TcpStream::connect(&addr).await.into_diagnostic()?;
    let body = serde_json::json!({
        "sandbox_id": registration.sandbox_id,
        "sandbox_name": registration.sandbox_name,
        "pod_ip": registration.pod_ip,
        "protocol": "openshell-node-enforcer-prototype-v1"
    })
    .to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .into_diagnostic()?;

    let mut response = [0_u8; 128];
    let read = stream.read(&mut response).await.into_diagnostic()?;
    let status = String::from_utf8_lossy(&response[..read]);
    if status.starts_with("HTTP/1.1 202") || status.starts_with("HTTP/1.1 200") {
        info!(endpoint = %registration.endpoint, "External enforcer registration acknowledged");
        return Ok(());
    }

    Err(miette::miette!(
        "external enforcer registration failed: {}",
        status.lines().next().unwrap_or("empty response")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_workload_accepts_enforcer_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_registration(stream, peer, NetworkEnforcementMode::ExternalEnforcer)
                .await
                .unwrap();
        });

        register_workload(WorkloadRegistration {
            endpoint: format!("http://{addr}"),
            sandbox_id: "sb-123".to_string(),
            sandbox_name: Some("demo".to_string()),
            pod_ip: None,
        })
        .await
        .unwrap();

        server.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_ruleset_allows_root_and_rejects_non_root_tcp_udp() {
        let ruleset = generate_external_enforcer_ruleset("openshell:external:test:");

        assert!(ruleset.contains("table inet openshell_external_enforcer"));
        assert!(ruleset.contains("oifname \"lo\" accept"));
        assert!(ruleset.contains("meta skuid 0 accept"));
        assert!(ruleset.contains("meta nfproto ipv4 meta l4proto tcp reject"));
        assert!(ruleset.contains("meta nfproto ipv4 meta l4proto udp reject"));
        assert!(
            ruleset.find("meta skuid 0 accept").unwrap()
                < ruleset
                    .find("meta nfproto ipv4 meta l4proto tcp reject")
                    .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fib_trie_match_requires_local_address() {
        let host_route = r#"
           +-- 10.40.0.0/14 2 0 2
              |-- 10.40.1.33
                 /32 host UNICAST
        "#;
        let pod_local = r#"
           +-- 0.0.0.0/0 3 0 5
              |-- 10.40.1.33
                 /32 host LOCAL
        "#;

        assert!(!fib_trie_contains_local_address(host_route, "10.40.1.33"));
        assert!(fib_trie_contains_local_address(pod_local, "10.40.1.33"));
    }

    #[test]
    fn target_pod_ip_prefers_payload_and_ignores_loopback() {
        let payload = RegistrationPayload {
            sandbox_id: "sb".to_string(),
            sandbox_name: None,
            pod_ip: Some("10.40.1.28".to_string()),
            protocol: None,
        };
        let peer = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(
            target_pod_ip(&payload, peer),
            Some("10.40.1.28".parse().unwrap())
        );

        let payload = RegistrationPayload {
            sandbox_id: "sb".to_string(),
            sandbox_name: None,
            pod_ip: None,
            protocol: None,
        };
        assert_eq!(target_pod_ip(&payload, peer), None);
    }
}
