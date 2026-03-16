// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bypass detection monitor — reads kernel log messages from `/dev/kmsg` to
//! detect and report direct connection attempts that bypass the HTTP CONNECT
//! proxy.
//!
//! When the sandbox network namespace has iptables LOG rules installed (see
//! `NetworkNamespace::install_bypass_rules`), the kernel writes a log line for
//! each dropped packet. This module reads those messages, parses the iptables
//! LOG format, and emits structured tracing events + denial aggregator entries.
//!
//! ## Graceful degradation
//!
//! If `/dev/kmsg` cannot be opened (e.g., restricted container environment),
//! the monitor logs a one-time warning and returns. The iptables REJECT rules
//! still provide fast-fail UX — the monitor only adds diagnostic visibility.

use crate::denial_aggregator::DenialEvent;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// A parsed iptables LOG entry from `/dev/kmsg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassEvent {
    /// Destination IP address.
    pub dst_addr: String,
    /// Destination port.
    pub dst_port: u16,
    /// Source port (used for process identity resolution).
    pub src_port: u16,
    /// Protocol (TCP or UDP).
    pub proto: String,
    /// UID of the process that initiated the connection.
    pub uid: Option<u32>,
}

/// Parse an iptables LOG line from `/dev/kmsg`.
///
/// Expected format (from the kernel LOG target):
/// ```text
/// ...,;openshell:bypass:<ns-id>:IN= OUT=veth-s-... SRC=10.200.0.2 DST=93.184.216.34
///  LEN=60 ... PROTO=TCP SPT=48012 DPT=443 ... UID=1000
/// ```
///
/// Returns `None` if the line doesn't match the expected prefix or is malformed.
pub fn parse_kmsg_line(line: &str, namespace_prefix: &str) -> Option<BypassEvent> {
    // Check that this line contains our namespace prefix.
    let prefix_pos = line.find(namespace_prefix)?;
    let relevant = &line[prefix_pos + namespace_prefix.len()..];

    let dst_addr = extract_field(relevant, "DST=")?;
    let dst_port = extract_field(relevant, "DPT=")?.parse::<u16>().ok()?;
    let src_port = extract_field(relevant, "SPT=")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let proto = extract_field(relevant, "PROTO=")
        .unwrap_or_else(|| "unknown".to_string())
        .to_lowercase();
    let uid = extract_field(relevant, "UID=").and_then(|s| s.parse::<u32>().ok());

    Some(BypassEvent {
        dst_addr,
        dst_port,
        src_port,
        proto,
        uid,
    })
}

/// Extract a single space-delimited field value from an iptables LOG line.
///
/// Given `"DST="` and a string like `"...DST=93.184.216.34 LEN=60..."`,
/// returns `Some("93.184.216.34")`.
fn extract_field(s: &str, key: &str) -> Option<String> {
    let start = s.find(key)? + key.len();
    let rest = &s[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let value = &rest[..end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Generate a protocol-appropriate hint for the bypass event.
fn hint_for_event(event: &BypassEvent) -> &'static str {
    if event.proto == "udp" && event.dst_port == 53 {
        "DNS queries should route through the sandbox proxy; check resolver configuration"
    } else if event.proto == "udp" {
        "UDP traffic must route through the sandbox proxy"
    } else {
        "ensure process honors HTTP_PROXY/HTTPS_PROXY; for Node.js set NODE_USE_ENV_PROXY=1"
    }
}

/// Spawn the bypass monitor as a background tokio task.
///
/// Uses `dmesg --follow` to tail the kernel ring buffer for iptables LOG
/// entries matching the given namespace. Falls back gracefully if `dmesg`
/// is not available.
///
/// We use `dmesg` rather than reading `/dev/kmsg` directly because the
/// container runtime's device cgroup policy blocks direct `/dev/kmsg` access
/// even with `CAP_SYSLOG`. The `dmesg` command reads via the `syslog(2)`
/// syscall which is permitted with `CAP_SYSLOG`.
///
/// Returns a `JoinHandle` if the monitor was started, or `None` if `dmesg`
/// is not available.
pub fn spawn(
    namespace_name: String,
    entrypoint_pid: Arc<AtomicU32>,
    denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
) -> Option<tokio::task::JoinHandle<()>> {
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    // Verify dmesg is available before spawning the monitor.
    let dmesg_check = Command::new("dmesg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !dmesg_check.is_ok_and(|s| s.success()) {
        warn!(
            "dmesg not available; bypass detection monitor will not run. \
             Bypass REJECT rules still provide fast-fail behavior."
        );
        return None;
    }

    let namespace_prefix = format!("openshell:bypass:{namespace_name}:");
    debug!(
        namespace = %namespace_name,
        "Starting bypass detection monitor via dmesg --follow"
    );

    let handle = tokio::task::spawn_blocking(move || {
        // Start dmesg in follow mode to tail new kernel messages.
        let mut child = match Command::new("dmesg")
            .args(["--follow", "--notime"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to start dmesg --follow; bypass monitor will not run");
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                warn!("dmesg --follow produced no stdout; bypass monitor will not run");
                return;
            }
        };

        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    debug!(error = %e, "Error reading dmesg line, continuing");
                    continue;
                }
            };

            let Some(event) = parse_kmsg_line(&line, &namespace_prefix) else {
                continue;
            };

            // Attempt process identity resolution (best-effort, TCP only).
            let pid = entrypoint_pid.load(Ordering::Acquire);
            let (binary, binary_pid, ancestors) =
                if event.proto == "tcp" && event.src_port > 0 && pid > 0 {
                    resolve_process_identity(pid, event.src_port)
                } else {
                    ("-".to_string(), "-".to_string(), "-".to_string())
                };

            let hint = hint_for_event(&event);

            warn!(
                dst_addr = %event.dst_addr,
                dst_port = event.dst_port,
                proto = %event.proto,
                binary = %binary,
                binary_pid = %binary_pid,
                ancestors = %ancestors,
                action = "reject",
                reason = "direct connection bypassed HTTP CONNECT proxy",
                hint = hint,
                "BYPASS_DETECT",
            );

            // Send to denial aggregator if available.
            if let Some(ref tx) = denial_tx {
                let ancestors_vec: Vec<String> = if ancestors == "-" {
                    vec![]
                } else {
                    ancestors.split(" -> ").map(String::from).collect()
                };

                let _ = tx.send(DenialEvent {
                    host: event.dst_addr.clone(),
                    port: event.dst_port,
                    binary: binary.clone(),
                    ancestors: ancestors_vec,
                    deny_reason: "direct connection bypassed HTTP CONNECT proxy".to_string(),
                    denial_stage: "bypass".to_string(),
                    l7_method: None,
                    l7_path: None,
                });
            }
        }

        // Clean up the dmesg child process.
        let _ = child.kill();
        let _ = child.wait();
        debug!("Bypass monitor: dmesg reader exited");
    });

    Some(handle)
}

/// Resolve process identity from a TCP source port.
///
/// Returns `(binary_path, pid, ancestors)` as display strings.
/// Falls back to `("-", "-", "-")` on any failure (race condition, etc.).
fn resolve_process_identity(entrypoint_pid: u32, src_port: u16) -> (String, String, String) {
    #[cfg(target_os = "linux")]
    {
        use crate::procfs;

        match procfs::resolve_tcp_peer_identity(entrypoint_pid, src_port) {
            Ok((binary_path, pid)) => {
                let ancestors = procfs::collect_ancestor_binaries(pid, entrypoint_pid);
                let ancestors_str = if ancestors.is_empty() {
                    "-".to_string()
                } else {
                    ancestors
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                };
                (
                    binary_path.display().to_string(),
                    pid.to_string(),
                    ancestors_str,
                )
            }
            Err(_) => ("-".to_string(), "-".to_string(), "-".to_string()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (entrypoint_pid, src_port);
        ("-".to_string(), "-".to_string(), "-".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kmsg_line_tcp_bypass() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=10.200.0.2 DST=93.184.216.34 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 \
                    DF PROTO=TCP SPT=48012 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0 UID=1000";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "93.184.216.34");
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.src_port, 48012);
        assert_eq!(event.proto, "tcp");
        assert_eq!(event.uid, Some(1000));
    }

    #[test]
    fn parse_kmsg_line_udp_dns_bypass() {
        let line = "6,5678,9012,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=10.200.0.2 DST=8.8.8.8 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=0 \
                    DF PROTO=UDP SPT=53421 DPT=53 LEN=32 UID=1000";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "8.8.8.8");
        assert_eq!(event.dst_port, 53);
        assert_eq!(event.src_port, 53421);
        assert_eq!(event.proto, "udp");
        assert_eq!(event.uid, Some(1000));
    }

    #[test]
    fn parse_kmsg_line_no_uid() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=10.200.0.2 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=12345 DPT=6379";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "10.0.0.5");
        assert_eq!(event.dst_port, 6379);
        assert_eq!(event.proto, "tcp");
        assert_eq!(event.uid, None);
    }

    #[test]
    fn parse_kmsg_line_wrong_namespace_returns_none() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-other:IN= OUT=veth \
                    SRC=10.200.0.2 DST=1.2.3.4 PROTO=TCP SPT=1111 DPT=80";

        let result = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:");
        assert!(result.is_none());
    }

    #[test]
    fn parse_kmsg_line_unrelated_message_returns_none() {
        let line = "6,1234,5678,-;audit: type=1400 audit(1234567890.123:1): something else";
        let result = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:");
        assert!(result.is_none());
    }

    #[test]
    fn parse_kmsg_line_missing_dst_returns_none() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth \
                    SRC=10.200.0.2 PROTO=TCP SPT=1111 DPT=80";
        // Missing DST= field
        let result = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:");
        assert!(result.is_none());
    }

    #[test]
    fn parse_kmsg_line_ipv6_address() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=fd00::2 DST=2001:4860:4860::8888 LEN=60 PROTO=TCP SPT=55555 DPT=443 UID=1000";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "2001:4860:4860::8888");
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.proto, "tcp");
    }

    #[test]
    fn hint_for_tcp_event() {
        let event = BypassEvent {
            dst_addr: "1.2.3.4".to_string(),
            dst_port: 443,
            src_port: 12345,
            proto: "tcp".to_string(),
            uid: None,
        };
        assert!(hint_for_event(&event).contains("HTTP_PROXY"));
    }

    #[test]
    fn hint_for_dns_bypass() {
        let event = BypassEvent {
            dst_addr: "8.8.8.8".to_string(),
            dst_port: 53,
            src_port: 12345,
            proto: "udp".to_string(),
            uid: None,
        };
        assert!(hint_for_event(&event).contains("DNS"));
    }

    #[test]
    fn hint_for_non_dns_udp() {
        let event = BypassEvent {
            dst_addr: "1.2.3.4".to_string(),
            dst_port: 5060,
            src_port: 12345,
            proto: "udp".to_string(),
            uid: None,
        };
        assert!(hint_for_event(&event).contains("UDP"));
    }

    #[test]
    fn extract_field_basic() {
        let s = "DST=1.2.3.4 LEN=60";
        assert_eq!(extract_field(s, "DST="), Some("1.2.3.4".to_string()));
        assert_eq!(extract_field(s, "LEN="), Some("60".to_string()));
    }

    #[test]
    fn extract_field_missing() {
        let s = "DST=1.2.3.4 LEN=60";
        assert_eq!(extract_field(s, "PROTO="), None);
    }

    #[test]
    fn extract_field_at_end_of_string() {
        let s = "DST=1.2.3.4";
        assert_eq!(extract_field(s, "DST="), Some("1.2.3.4".to_string()));
    }
}
