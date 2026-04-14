// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace isolation for sandboxed processes.
//!
//! Creates an isolated network namespace with a veth pair connecting
//! the sandbox to the host. This ensures the sandboxed process can only
//! communicate through the proxy running on the host side of the veth.

use miette::{IntoDiagnostic, Result};
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::process::Command;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Default subnet for sandbox networking.
const SUBNET_PREFIX: &str = "10.200.0";
const HOST_IP_SUFFIX: u8 = 1;
const SANDBOX_IP_SUFFIX: u8 = 2;

/// Handle to a network namespace with veth pair.
///
/// The namespace and veth interfaces are automatically cleaned up on drop.
#[derive(Debug)]
pub struct NetworkNamespace {
    /// Namespace name (e.g., "sandbox-{uuid}")
    name: String,
    /// Host-side veth interface name
    veth_host: String,
    /// Sandbox-side veth interface name (inside namespace, used only during setup)
    _veth_sandbox: String,
    /// Host-side IP address (proxy binds here)
    host_ip: IpAddr,
    /// Sandbox-side IP address
    sandbox_ip: IpAddr,
    /// File descriptor for the namespace (for setns)
    ns_fd: Option<RawFd>,
}

impl NetworkNamespace {
    /// Create a new isolated network namespace with veth pair.
    ///
    /// Sets up:
    /// - A new network namespace named `sandbox-{uuid}`
    /// - A veth pair connecting host and sandbox
    /// - IP addresses on both ends (10.200.0.1/24 and 10.200.0.2/24)
    /// - Default route in sandbox pointing to host
    ///
    /// # Errors
    ///
    /// Returns an error if namespace creation or network setup fails.
    pub fn create() -> Result<Self> {
        let id = Uuid::new_v4();
        let short_id = &id.to_string()[..8];
        let name = format!("sandbox-{short_id}");
        let veth_host = format!("veth-h-{short_id}");
        let veth_sandbox = format!("veth-s-{short_id}");

        let host_ip: IpAddr = format!("{SUBNET_PREFIX}.{HOST_IP_SUFFIX}").parse().unwrap();
        let sandbox_ip: IpAddr = format!("{SUBNET_PREFIX}.{SANDBOX_IP_SUFFIX}")
            .parse()
            .unwrap();

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "creating")
                .message(format!(
                    "Creating network namespace [ns:{name} host_veth:{veth_host} sandbox_veth:{veth_sandbox}]"
                ))
                .build()
        );

        // Create the namespace
        run_ip(&["netns", "add", &name])?;

        // Create veth pair
        if let Err(e) = run_ip(&[
            "link",
            "add",
            &veth_host,
            "type",
            "veth",
            "peer",
            "name",
            &veth_sandbox,
        ]) {
            // Cleanup namespace on failure
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        // Move sandbox veth into namespace
        if let Err(e) = run_ip(&["link", "set", &veth_sandbox, "netns", &name]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        // Configure host side
        let host_cidr = format!("{host_ip}/24");
        if let Err(e) = run_ip(&["addr", "add", &host_cidr, "dev", &veth_host]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        if let Err(e) = run_ip(&["link", "set", &veth_host, "up"]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        // Configure sandbox side (inside namespace)
        let sandbox_cidr = format!("{sandbox_ip}/24");
        if let Err(e) = run_ip_netns(&name, &["addr", "add", &sandbox_cidr, "dev", &veth_sandbox]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        if let Err(e) = run_ip_netns(&name, &["link", "set", &veth_sandbox, "up"]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        // Bring up loopback in namespace
        if let Err(e) = run_ip_netns(&name, &["link", "set", "lo", "up"]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        // Add default route via host
        let host_ip_str = host_ip.to_string();
        if let Err(e) = run_ip_netns(&name, &["route", "add", "default", "via", &host_ip_str]) {
            let _ = run_ip(&["link", "delete", &veth_host]);
            let _ = run_ip(&["netns", "delete", &name]);
            return Err(e);
        }

        // Open the namespace file descriptor for later use with setns
        let ns_path = format!("/var/run/netns/{name}");
        let ns_fd = match nix::fcntl::open(
            ns_path.as_str(),
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => Some(fd),
            Err(e) => {
                warn!(error = %e, "Failed to open namespace fd, will use nsenter fallback");
                None
            }
        };

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "created")
                .message(format!(
                    "Network namespace created [ns:{name} host_ip:{host_ip} sandbox_ip:{sandbox_ip}]"
                ))
                .build()
        );

        Ok(Self {
            name,
            veth_host,
            _veth_sandbox: veth_sandbox,
            host_ip,
            sandbox_ip,
            ns_fd,
        })
    }

    /// Get the host-side IP address (proxy should bind to this).
    #[must_use]
    pub const fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    /// Get the sandbox-side IP address.
    #[must_use]
    pub const fn sandbox_ip(&self) -> IpAddr {
        self.sandbox_ip
    }

    /// Get the namespace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Enter this network namespace.
    ///
    /// Must be called from the child process after fork, before exec.
    /// Uses `setns()` to switch the calling process into the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if setns fails.
    ///
    /// # Safety
    ///
    /// This function should only be called in a `pre_exec` context after fork.
    pub fn enter(&self) -> Result<()> {
        if let Some(fd) = self.ns_fd {
            debug!(namespace = %self.name, "Entering network namespace via setns");
            // SAFETY: setns is safe to call after fork, before exec
            let result = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
            if result != 0 {
                return Err(miette::miette!(
                    "setns failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        } else {
            Err(miette::miette!(
                "No namespace file descriptor available for setns"
            ))
        }
    }

    /// Get the namespace file descriptor for use with clone/unshare.
    #[must_use]
    pub const fn ns_fd(&self) -> Option<RawFd> {
        self.ns_fd
    }

    /// Install iptables rules for bypass detection inside the namespace.
    ///
    /// Sets up OUTPUT chain rules that:
    /// 1. ACCEPT traffic destined for the proxy (host_ip:proxy_port)
    /// 2. ACCEPT loopback traffic
    /// 3. ACCEPT established/related connections (response packets)
    /// 4. LOG + REJECT all other TCP/UDP traffic (bypass attempts)
    ///
    /// This provides two benefits:
    /// - **Fast-fail UX**: applications get immediate ECONNREFUSED instead of
    ///   a 30-second timeout when they bypass the proxy
    /// - **Diagnostics**: iptables LOG entries are picked up by the bypass
    ///   monitor to emit structured tracing events
    ///
    /// Degrades gracefully if `iptables` is not available — the namespace
    /// still provides isolation via routing, just without fast-fail and
    /// diagnostic logging.
    pub fn install_bypass_rules(&self, proxy_port: u16) -> Result<()> {
        // Check if iptables is available before attempting to install rules.
        let iptables_path = match find_iptables() {
            Some(path) => path,
            None => {
                openshell_ocsf::ocsf_emit!(openshell_ocsf::ConfigStateChangeBuilder::new(
                    crate::ocsf_ctx()
                )
                .severity(openshell_ocsf::SeverityId::Medium)
                .status(openshell_ocsf::StatusId::Failure)
                .state(openshell_ocsf::StateId::Disabled, "degraded")
                .message(format!(
                    "iptables not found; bypass detection rules will not be installed [ns:{}]",
                    self.name
                ))
                .build());
                return Ok(());
            }
        };

        let host_ip_str = self.host_ip.to_string();
        let proxy_port_str = proxy_port.to_string();
        let log_prefix = format!("openshell:bypass:{}:", &self.name);

        // "Installing bypass detection rules" is a transient step — skip OCSF.
        // The completion event below covers the outcome.

        // Install IPv4 rules
        if let Err(e) = self.install_bypass_rules_for(
            &iptables_path,
            &host_ip_str,
            &proxy_port_str,
            &log_prefix,
        ) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "failed")
                    .message(format!(
                        "Failed to install IPv4 bypass detection rules [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );
            return Err(e);
        }

        // Install IPv6 rules — best-effort.
        // Skip the proxy ACCEPT rule for IPv6 since the proxy address is IPv4.
        if let Some(ip6_path) = find_ip6tables(&iptables_path) {
            if let Err(e) = self.install_bypass_rules_for_v6(&ip6_path, &log_prefix) {
                openshell_ocsf::ocsf_emit!(openshell_ocsf::ConfigStateChangeBuilder::new(
                    crate::ocsf_ctx()
                )
                .severity(openshell_ocsf::SeverityId::Low)
                .status(openshell_ocsf::StatusId::Failure)
                .state(openshell_ocsf::StateId::Other, "degraded")
                .message(format!(
                    "Failed to install IPv6 bypass detection rules (non-fatal) [ns:{}]: {e}",
                    self.name
                ))
                .build());
            }
        }

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "installed")
                .message(format!(
                    "Bypass detection rules installed [ns:{}]",
                    self.name
                ))
                .build()
        );

        Ok(())
    }

    /// Install bypass detection rules for a specific iptables variant (iptables or ip6tables).
    fn install_bypass_rules_for(
        &self,
        iptables_cmd: &str,
        host_ip: &str,
        proxy_port: &str,
        log_prefix: &str,
    ) -> Result<()> {
        // Rule 1: ACCEPT traffic to the proxy
        run_iptables_netns(
            &self.name,
            iptables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-d",
                &format!("{host_ip}/32"),
                "-p",
                "tcp",
                "--dport",
                proxy_port,
                "-j",
                "ACCEPT",
            ],
        )?;

        // Rule 2: ACCEPT loopback traffic
        run_iptables_netns(
            &self.name,
            iptables_cmd,
            &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        )?;

        // Rule 3: ACCEPT established/related connections (response packets)
        run_iptables_netns(
            &self.name,
            iptables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )?;

        // Rule 4: LOG TCP SYN bypass attempts (rate-limited)
        // LOG rule failure is non-fatal — the REJECT rule still provides fast-fail.
        if let Err(e) = run_iptables_netns(
            &self.name,
            iptables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--syn",
                "-m",
                "limit",
                "--limit",
                "5/sec",
                "--limit-burst",
                "10",
                "-j",
                "LOG",
                "--log-prefix",
                log_prefix,
                "--log-uid",
            ],
        ) {
            openshell_ocsf::ocsf_emit!(openshell_ocsf::ConfigStateChangeBuilder::new(
                crate::ocsf_ctx()
            )
            .severity(openshell_ocsf::SeverityId::Low)
            .status(openshell_ocsf::StatusId::Failure)
            .state(openshell_ocsf::StateId::Other, "degraded")
            .message(format!(
                "Failed to install LOG rule for TCP (xt_LOG module may not be loaded) [ns:{}]: {e}",
                self.name
            ))
            .build());
        }

        // Rule 5: REJECT TCP bypass attempts (fast-fail)
        run_iptables_netns(
            &self.name,
            iptables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-port-unreachable",
            ],
        )?;

        // Rule 6: LOG UDP bypass attempts (rate-limited, covers DNS bypass)
        if let Err(e) = run_iptables_netns(
            &self.name,
            iptables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "-m",
                "limit",
                "--limit",
                "5/sec",
                "--limit-burst",
                "10",
                "-j",
                "LOG",
                "--log-prefix",
                log_prefix,
                "--log-uid",
            ],
        ) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Other, "degraded")
                    .message(format!(
                        "Failed to install LOG rule for UDP [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );
        }

        // Rule 7: REJECT UDP bypass attempts (covers DNS bypass)
        run_iptables_netns(
            &self.name,
            iptables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-port-unreachable",
            ],
        )?;

        Ok(())
    }

    /// Install IPv6 bypass detection rules.
    ///
    /// Similar to `install_bypass_rules_for` but omits the proxy ACCEPT rule
    /// (the proxy listens on an IPv4 address) and uses IPv6-appropriate
    /// REJECT types.
    fn install_bypass_rules_for_v6(&self, ip6tables_cmd: &str, log_prefix: &str) -> Result<()> {
        // ACCEPT loopback traffic
        run_iptables_netns(
            &self.name,
            ip6tables_cmd,
            &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        )?;

        // ACCEPT established/related connections
        run_iptables_netns(
            &self.name,
            ip6tables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )?;

        // LOG TCP SYN bypass attempts (rate-limited)
        if let Err(e) = run_iptables_netns(
            &self.name,
            ip6tables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--syn",
                "-m",
                "limit",
                "--limit",
                "5/sec",
                "--limit-burst",
                "10",
                "-j",
                "LOG",
                "--log-prefix",
                log_prefix,
                "--log-uid",
            ],
        ) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Other, "degraded")
                    .message(format!(
                        "Failed to install IPv6 LOG rule for TCP [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );
        }

        // REJECT TCP bypass attempts
        run_iptables_netns(
            &self.name,
            ip6tables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp6-port-unreachable",
            ],
        )?;

        // LOG UDP bypass attempts (rate-limited)
        if let Err(e) = run_iptables_netns(
            &self.name,
            ip6tables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "-m",
                "limit",
                "--limit",
                "5/sec",
                "--limit-burst",
                "10",
                "-j",
                "LOG",
                "--log-prefix",
                log_prefix,
                "--log-uid",
            ],
        ) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Other, "degraded")
                    .message(format!(
                        "Failed to install IPv6 LOG rule for UDP [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );
        }

        // REJECT UDP bypass attempts
        run_iptables_netns(
            &self.name,
            ip6tables_cmd,
            &[
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp6-port-unreachable",
            ],
        )?;

        Ok(())
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        debug!(namespace = %self.name, "Cleaning up network namespace");

        // Close the fd if we have one
        if let Some(fd) = self.ns_fd.take() {
            let _ = nix::unistd::close(fd);
        }

        // Delete the host-side veth (this also removes the peer)
        if let Err(e) = run_ip(&["link", "delete", &self.veth_host]) {
            warn!(
                error = %e,
                veth = %self.veth_host,
                "Failed to delete veth interface"
            );
        }

        // Delete the namespace
        if let Err(e) = run_ip(&["netns", "delete", &self.name]) {
            warn!(
                error = %e,
                namespace = %self.name,
                "Failed to delete network namespace"
            );
        }

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Disabled, "cleaned_up")
                .message(format!("Network namespace cleaned up [ns:{}]", self.name))
                .build()
        );
    }
}

/// Run an `ip` command on the host.
fn run_ip(args: &[&str]) -> Result<()> {
    debug!(command = %format!("ip {}", args.join(" ")), "Running ip command");

    let output = Command::new("ip").args(args).output().into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

/// Run an `ip` command inside a network namespace via `nsenter --net=`.
///
/// We use `nsenter` instead of `ip netns exec` because `ip netns exec`
/// remounts `/sys` to reflect the target namespace's sysfs entries. That
/// sysfs remount requires real `CAP_SYS_ADMIN` in the host user namespace,
/// which is unavailable in rootless container runtimes (e.g. rootless
/// Podman). `nsenter --net=` enters only the network namespace without
/// changing the mount namespace, avoiding the sysfs remount entirely.
/// The supervisor's operations (addr add, link set, route add) are all
/// netlink-based and do not need sysfs access.
fn run_ip_netns(netns: &str, args: &[&str]) -> Result<()> {
    let ns_path = format!("/var/run/netns/{netns}");
    let net_flag = format!("--net={ns_path}");

    let mut full_args = vec![net_flag.as_str(), "--", "ip"];
    full_args.extend(args);

    debug!(command = %format!("nsenter {}", full_args.join(" ")), "Running ip in namespace via nsenter");

    let output = Command::new("nsenter")
        .args(&full_args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "nsenter --net={} ip {} failed: {}",
            ns_path,
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

/// Run an iptables command inside a network namespace via `nsenter --net=`.
///
/// Uses `nsenter` instead of `ip netns exec` to avoid the sysfs remount
/// that fails in rootless container runtimes. See `run_ip_netns` for details.
fn run_iptables_netns(netns: &str, iptables_cmd: &str, args: &[&str]) -> Result<()> {
    let ns_path = format!("/var/run/netns/{netns}");
    let net_flag = format!("--net={ns_path}");

    let mut full_args = vec![net_flag.as_str(), "--", iptables_cmd];
    full_args.extend(args);

    debug!(
        command = %format!("nsenter {}", full_args.join(" ")),
        "Running iptables in namespace via nsenter"
    );

    let output = Command::new("nsenter")
        .args(&full_args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "nsenter --net={} {} failed: {}",
            ns_path,
            iptables_cmd,
            stderr.trim()
        ));
    }

    Ok(())
}

/// Well-known paths where iptables may be installed.
/// The sandbox container PATH often excludes `/usr/sbin`, so we probe
/// explicit paths rather than relying on `which`.
const IPTABLES_SEARCH_PATHS: &[&str] =
    &["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"];

/// Returns true if xt extension modules (e.g. xt_comment) cannot be used
/// via the given iptables binary.
///
/// Some kernels have nf_tables but lack the nft_compat bridge that allows
/// xt extension modules to be used through the nf_tables path (e.g. Jetson
/// Linux 5.15-tegra). This probe detects that condition by attempting to
/// insert a rule using the xt_comment extension. If it fails, xt extensions
/// are unavailable and the caller should fall back to iptables-legacy.
fn xt_extensions_unavailable(iptables_path: &str) -> bool {
    // Create a temporary probe chain. If this fails (e.g. no CAP_NET_ADMIN),
    // we can't determine availability — assume extensions are available.
    let created = Command::new(iptables_path)
        .args(["-t", "filter", "-N", "_xt_probe"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !created {
        return false;
    }

    // Attempt to insert a rule using xt_comment. Failure means nft_compat
    // cannot bridge xt extension modules on this kernel.
    let probe_ok = Command::new(iptables_path)
        .args([
            "-t",
            "filter",
            "-A",
            "_xt_probe",
            "-m",
            "comment",
            "--comment",
            "probe",
            "-j",
            "ACCEPT",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Clean up — best-effort, ignore failures.
    let _ = Command::new(iptables_path)
        .args([
            "-t",
            "filter",
            "-D",
            "_xt_probe",
            "-m",
            "comment",
            "--comment",
            "probe",
            "-j",
            "ACCEPT",
        ])
        .output();
    let _ = Command::new(iptables_path)
        .args(["-t", "filter", "-X", "_xt_probe"])
        .output();

    !probe_ok
}

/// Find the iptables binary path, checking well-known locations.
///
/// If xt extension modules are unavailable via the standard binary and
/// `iptables-legacy` is available alongside it, the legacy binary is returned
/// instead. This ensures bypass-detection rules can be installed on kernels
/// where `nft_compat` is unavailable (e.g. Jetson Linux 5.15-tegra).
fn find_iptables() -> Option<String> {
    let standard_path = IPTABLES_SEARCH_PATHS
        .iter()
        .find(|path| std::path::Path::new(path).exists())
        .copied()?;

    if xt_extensions_unavailable(standard_path) {
        let legacy_path = standard_path.replace("iptables", "iptables-legacy");
        if std::path::Path::new(&legacy_path).exists() {
            debug!(
                legacy = legacy_path,
                "xt extensions unavailable; using iptables-legacy"
            );
            return Some(legacy_path);
        }
    }

    Some(standard_path.to_string())
}

/// Find the ip6tables binary path, deriving it from the iptables location.
fn find_ip6tables(iptables_path: &str) -> Option<String> {
    let ip6_path = iptables_path.replace("iptables", "ip6tables");
    if std::path::Path::new(&ip6_path).exists() {
        Some(ip6_path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require root and network namespace support
    // Run with: sudo cargo test -- --ignored

    #[test]
    #[ignore = "requires root privileges"]
    fn test_create_and_drop_namespace() {
        let ns = NetworkNamespace::create().expect("Failed to create namespace");
        let name = ns.name().to_string();

        // Verify namespace exists
        let ns_path = format!("/var/run/netns/{name}");
        assert!(
            std::path::Path::new(&ns_path).exists(),
            "Namespace file should exist"
        );

        // Verify IPs are set correctly
        assert_eq!(
            ns.host_ip().to_string(),
            format!("{SUBNET_PREFIX}.{HOST_IP_SUFFIX}")
        );
        assert_eq!(
            ns.sandbox_ip().to_string(),
            format!("{SUBNET_PREFIX}.{SANDBOX_IP_SUFFIX}")
        );

        // Drop should clean up
        drop(ns);

        // Verify namespace is gone
        assert!(
            !std::path::Path::new(&ns_path).exists(),
            "Namespace should be cleaned up"
        );
    }
}
