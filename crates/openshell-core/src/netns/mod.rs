// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace isolation for sandboxed processes.
//!
//! Creates an isolated network namespace with a veth pair connecting
//! the sandbox to the host. This ensures the sandboxed process can only
//! communicate through the proxy running on the host side of the veth.

mod nft_ruleset;

use miette::{IntoDiagnostic, Result};
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::process::Command;
use tracing::{debug, warn};
use uuid::Uuid;

/// Default subnet for sandbox networking.
const SUBNET_PREFIX: &str = "10.200.0";
const HOST_IP_SUFFIX: u8 = 1;
const SANDBOX_IP_SUFFIX: u8 = 2;
const IP_SEARCH_PATHS: &[&str] = &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];
const NSENTER_SEARCH_PATHS: &[&str] = &[
    "/usr/bin/nsenter",
    "/bin/nsenter",
    "/usr/sbin/nsenter",
    "/sbin/nsenter",
];

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
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
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
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
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
            // libc/syscall FFI requires unsafe
            #[allow(unsafe_code)]
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

    /// Install nftables rules for bypass detection inside the namespace.
    ///
    /// Sets up OUTPUT chain rules that:
    /// 1. ACCEPT traffic destined for the proxy (`host_ip:proxy_port`)
    /// 2. ACCEPT loopback traffic
    /// 3. ACCEPT established/related connections (response packets)
    /// 4. LOG + REJECT all other TCP/UDP traffic (bypass attempts)
    ///
    /// This provides two benefits:
    /// - **Fast-fail UX**: applications get immediate ECONNREFUSED instead of
    ///   a 30-second timeout when they bypass the proxy
    /// - **Diagnostics**: nftables LOG entries are picked up by the bypass
    ///   monitor to emit structured tracing events
    ///
    /// Degrades gracefully if `nft` is not available — the namespace
    /// still provides isolation via routing, just without fast-fail and
    /// diagnostic logging.
    pub fn install_bypass_rules(&self, proxy_port: u16) -> Result<()> {
        let Some(nft_path) = find_nft() else {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "degraded")
                    .message(format!(
                        "nft not found; bypass detection rules will not be installed [ns:{}]",
                        self.name
                    ))
                    .build()
            );
            return Ok(());
        };

        let host_ip_str = self.host_ip.to_string();
        let log_prefix = format!("openshell:bypass:{}:", &self.name);

        // The kernel's nf_log_syslog module suppresses log output from
        // non-init network namespaces by default. Enable it so the bypass
        // monitor can see log entries from the sandbox namespace.
        enable_nf_log_all_netns();

        // Try combined ruleset with log rules first. Log rules must appear
        // before reject rules in the chain so packets are logged before being
        // rejected. If the kernel lacks nft_log support, fall back to the
        // reject-only ruleset.
        let ruleset_with_log =
            nft_ruleset::generate_bypass_ruleset(&host_ip_str, proxy_port, Some(&log_prefix));

        if let Err(e) = run_nft_netns(&self.name, &nft_path, &ruleset_with_log) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Other, "degraded")
                    .message(format!(
                        "Failed to install bypass log rules (non-fatal), falling back to reject-only [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );

            let ruleset_no_log =
                nft_ruleset::generate_bypass_ruleset(&host_ip_str, proxy_port, None);

            if let Err(e) = run_nft_netns(&self.name, &nft_path, &ruleset_no_log) {
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(openshell_ocsf::SeverityId::Medium)
                        .status(openshell_ocsf::StatusId::Failure)
                        .state(openshell_ocsf::StateId::Disabled, "failed")
                        .message(format!(
                            "Failed to install bypass detection rules [ns:{}]: {e}",
                            self.name
                        ))
                        .build()
                );
                return Err(e);
            }
        }

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
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
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
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
    let ip_path = find_trusted_binary("ip", IP_SEARCH_PATHS)?;

    debug!(command = %format!("{ip_path} {}", args.join(" ")), "Running ip command");

    let output = Command::new(ip_path)
        .args(args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{ip_path} {} failed: {}",
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
    let ip_path = find_trusted_binary("ip", IP_SEARCH_PATHS)?;
    let nsenter_path = find_trusted_binary("nsenter", NSENTER_SEARCH_PATHS)?;
    let ns_path = format!("/var/run/netns/{netns}");
    let net_flag = format!("--net={ns_path}");

    let mut full_args = vec![net_flag.as_str(), "--", ip_path];
    full_args.extend(args);

    debug!(
        command = %format!("{nsenter_path} {}", full_args.join(" ")),
        "Running ip in namespace via nsenter"
    );

    let output = Command::new(nsenter_path)
        .args(&full_args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{nsenter_path} --net={} {ip_path} {} failed: {}",
            ns_path,
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

/// Load an nftables ruleset inside a network namespace via `nsenter --net=`.
///
/// Writes the ruleset to a temp file and loads it with `nft -f <path>`.
/// A temp file is used instead of piping to stdin (`nft -f -`) because
/// `nft` resolves `-` to `/dev/stdin`, which may not exist in minimal
/// VM guest environments (e.g. virtiofs rootfs without /proc mounted
/// at nft invocation time).
fn run_nft_netns(netns: &str, nft_cmd: &str, ruleset: &str) -> Result<()> {
    use std::io::Write;
    let mut tmp = tempfile::Builder::new()
        .prefix("openshell-nft-")
        .suffix(".conf")
        .tempfile()
        .into_diagnostic()?;
    tmp.write_all(ruleset.as_bytes()).into_diagnostic()?;
    let ruleset_path = tmp.path().to_string_lossy().to_string();

    let nsenter_path = find_trusted_binary("nsenter", NSENTER_SEARCH_PATHS)?;
    let ns_path = format!("/var/run/netns/{netns}");
    let net_flag = format!("--net={ns_path}");

    debug!(
        command = %format!("{nsenter_path} {net_flag} -- {nft_cmd} -f {ruleset_path}"),
        "Loading nftables ruleset in namespace"
    );

    let output = Command::new(nsenter_path)
        .args([net_flag.as_str(), "--", nft_cmd, "-f", &ruleset_path])
        .output()
        .into_diagnostic()?;

    drop(tmp);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "nft ruleset load failed in netns {netns}: {}",
            stderr.trim()
        ));
    }

    Ok(())
}

const NF_LOG_ALL_NETNS_PATH: &str = "/proc/sys/net/netfilter/nf_log_all_netns";

/// Enable nftables logging from non-init network namespaces.
///
/// The kernel's `nf_log_syslog` module silently suppresses log output from
/// non-init network namespaces unless `net.netfilter.nf_log_all_netns` is
/// set to 1. Since sandbox bypass rules live in a per-sandbox network
/// namespace, the bypass monitor can't see log entries without this.
fn enable_nf_log_all_netns() {
    use std::path::Path;
    if !Path::new(NF_LOG_ALL_NETNS_PATH).exists() {
        debug!("nf_log_all_netns sysctl not available (may already be set by init)");
        return;
    }
    match std::fs::write(NF_LOG_ALL_NETNS_PATH, "1") {
        Ok(()) => {
            debug!("Enabled nf_log_all_netns for non-init namespace logging");
        }
        Err(e) => {
            debug!(
                error = %e,
                "Could not enable nf_log_all_netns; bypass log rules may not produce output"
            );
        }
    }
}

/// Well-known paths where nft may be installed.
const NFT_SEARCH_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];

fn find_trusted_binary<'a>(name: &str, paths: &'a [&str]) -> Result<&'a str> {
    paths
        .iter()
        .copied()
        .find(|path| {
            let path = Path::new(path);
            path.is_absolute() && path.is_file()
        })
        .ok_or_else(|| {
            miette::miette!(
                "trusted {name} helper not found; checked {}",
                paths.join(", ")
            )
        })
}

/// Find the nft binary path, checking well-known locations.
fn find_nft() -> Option<String> {
    find_trusted_binary("nft", NFT_SEARCH_PATHS)
        .ok()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // These tests require root and network namespace support
    // Run with: sudo cargo test -- --ignored

    #[test]
    fn find_trusted_binary_uses_absolute_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let helper = tempdir.path().join("ip");
        fs::write(&helper, b"test helper").unwrap();
        let helper = helper.to_str().unwrap();

        assert_eq!(
            find_trusted_binary("ip", &["relative-ip", "/missing/ip", helper]).unwrap(),
            helper
        );
    }

    #[test]
    fn find_trusted_binary_rejects_missing_helpers() {
        let err =
            find_trusted_binary("nsenter", &["relative-nsenter", "/missing/nsenter"]).unwrap_err();

        assert!(err.to_string().contains("trusted nsenter helper not found"));
    }

    #[test]
    fn nft_search_paths_are_absolute() {
        for path in NFT_SEARCH_PATHS {
            assert!(
                path.starts_with('/'),
                "NFT_SEARCH_PATHS entry must be absolute: {path}"
            );
        }
    }

    #[test]
    #[ignore = "requires root privileges"]
    fn test_create_and_drop_namespace() {
        let ns = NetworkNamespace::create().expect("Failed to create namespace");
        let name = ns.name().to_string();

        // Verify namespace exists
        let ns_path = format!("/var/run/netns/{name}");
        assert!(Path::new(&ns_path).exists(), "Namespace file should exist");

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
            !Path::new(&ns_path).exists(),
            "Namespace should be cleaned up"
        );
    }
}
