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
use std::os::fd::AsRawFd as _;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, warn};
use uuid::Uuid;

/// Default subnet for sandbox networking.
const SUBNET_PREFIX: &str = "10.200.0";
const HOST_IP_SUFFIX: u8 = 1;
const SANDBOX_IP_SUFFIX: u8 = 2;
const IP_SEARCH_PATHS: &[&str] = &["usr/sbin/ip", "sbin/ip", "usr/bin/ip", "bin/ip"];

#[derive(Clone, Debug)]
struct TrustedHelper {
    executable: PathBuf,
    loader: Option<PathBuf>,
    library_path: String,
    xtables_path: PathBuf,
}

impl TrustedHelper {
    fn command(&self) -> Command {
        self.loader.as_ref().map_or_else(
            || Command::new(&self.executable),
            |loader| {
                let mut command = Command::new(loader);
                command
                    .env_clear()
                    .env("XTABLES_LIBDIR", &self.xtables_path)
                    .arg("--library-path")
                    .arg(&self.library_path)
                    .arg(&self.executable);
                command
            },
        )
    }

    fn tokio_command(&self) -> tokio::process::Command {
        self.loader.as_ref().map_or_else(
            || tokio::process::Command::new(&self.executable),
            |loader| {
                let mut command = tokio::process::Command::new(loader);
                command
                    .env_clear()
                    .env("XTABLES_LIBDIR", &self.xtables_path)
                    .arg("--library-path")
                    .arg(&self.library_path)
                    .arg(&self.executable);
                command
            },
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum HelperSource {
    LegacyWorkloadImage,
    TrustedSupervisorRuntime,
}

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
    #[allow(dead_code)]
    veth_sandbox: String,
    /// Host-side IP address (proxy binds here)
    host_ip: IpAddr,
    /// Sandbox-side IP address
    sandbox_ip: IpAddr,
    /// File descriptor for the namespace (for setns)
    ns_fd: Option<RawFd>,
    helper_source: HelperSource,
}

/// Cloneable coordinates for checking a live ceiling without retaining the
/// namespace fd or delaying namespace cleanup.
#[derive(Clone, Debug)]
pub struct EgressCeilingVerifier {
    namespace: String,
    host_ip: IpAddr,
    helper_source: HelperSource,
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
        Self::create_with_helper_source(HelperSource::LegacyWorkloadImage)
    }

    fn create_conformant() -> Result<Self> {
        Self::create_with_helper_source(HelperSource::TrustedSupervisorRuntime)
    }

    fn create_with_helper_source(helper_source: HelperSource) -> Result<Self> {
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
        run_ip(helper_source, &["netns", "add", &name])?;

        // Create veth pair
        if let Err(e) = run_ip(
            helper_source,
            &[
                "link",
                "add",
                &veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &veth_sandbox,
            ],
        ) {
            // Cleanup namespace on failure
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        // Move sandbox veth into namespace
        if let Err(e) = run_ip(
            helper_source,
            &["link", "set", &veth_sandbox, "netns", &name],
        ) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        // Configure host side
        let host_cidr = format!("{host_ip}/24");
        if let Err(e) = run_ip(
            helper_source,
            &["addr", "add", &host_cidr, "dev", &veth_host],
        ) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        if let Err(e) = run_ip(helper_source, &["link", "set", &veth_host, "up"]) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        // Configure sandbox side (inside namespace)
        let sandbox_cidr = format!("{sandbox_ip}/24");
        if let Err(e) = run_ip_netns(
            helper_source,
            &name,
            &["addr", "add", &sandbox_cidr, "dev", &veth_sandbox],
        ) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        if let Err(e) = run_ip_netns(helper_source, &name, &["link", "set", &veth_sandbox, "up"]) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        // Bring up loopback in namespace
        if let Err(e) = run_ip_netns(helper_source, &name, &["link", "set", "lo", "up"]) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
            return Err(e);
        }

        // Add default route via host
        let host_ip_str = host_ip.to_string();
        if let Err(e) = run_ip_netns(
            helper_source,
            &name,
            &["route", "add", "default", "via", &host_ip_str],
        ) {
            let _ = run_ip(helper_source, &["link", "delete", &veth_host]);
            let _ = run_ip(helper_source, &["netns", "delete", &name]);
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
                warn!(error = %e, "Failed to retain network namespace fd");
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
            veth_sandbox,
            host_ip,
            sandbox_ip,
            ns_fd,
            helper_source,
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

    /// Duplicate the namespace descriptor for a retained runtime handle.
    pub fn try_clone_ns_fd(&self) -> Result<Option<OwnedFd>> {
        self.ns_fd
            .map(|fd| {
                // SAFETY: `NetworkNamespace` owns `fd` for at least this call.
                #[allow(unsafe_code)]
                let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                borrowed.try_clone_to_owned().into_diagnostic()
            })
            .transpose()
    }

    /// Install the legacy best-effort nftables bypass-detection rules.
    pub fn install_bypass_rules(&self, proxy_port: u16) -> Result<()> {
        let Some(nft_path) = find_nft(self.helper_source) else {
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
        let host_ip = self.host_ip.to_string();
        let log_prefix = format!("openshell:bypass:{}:", &self.name);
        enable_nf_log_all_netns();
        let commands =
            nft_ruleset::generate_bypass_commands(&host_ip, proxy_port, Some(&log_prefix));
        if let Err(error) = run_nft_commands_netns(&self.name, &nft_path, &commands) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "failed")
                    .message(format!(
                        "Failed to install bypass detection rules [ns:{}]: {error}",
                        self.name
                    ))
                    .build()
            );
            return Err(error);
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

    /// Install the RFC 0012 default-deny egress ceiling inside the namespace.
    ///
    /// Sets up OUTPUT chain rules that:
    /// 1. ACCEPT traffic destined for the proxy (`host_ip:proxy_port`)
    /// 2. ACCEPT loopback traffic
    /// 3. LOG + REJECT TCP/UDP bypass attempts and DROP every other packet
    ///
    /// This provides two benefits:
    /// - **Fast-fail UX**: applications get immediate ECONNREFUSED instead of
    ///   a 30-second timeout when they bypass the proxy
    /// - **Diagnostics**: nftables LOG entries are picked up by the bypass
    ///   monitor to emit structured tracing events
    ///
    /// Missing nftables support is fatal: without the default-deny ceiling the
    /// backend cannot confirm that all workload egress reaches mediation.
    pub fn install_egress_ceiling(&self, proxy_port: u16) -> Result<()> {
        let Some(nft_path) = find_nft(self.helper_source) else {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::High)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "unavailable")
                    .message(format!(
                        "nft not found; refusing to establish the egress ceiling [ns:{}]",
                        self.name
                    ))
                    .build()
            );
            return Err(miette::miette!(
                "nft not found; cannot establish default-deny egress ceiling"
            ));
        };

        let host_ip_str = self.host_ip.to_string();
        let log_prefix = format!("openshell:bypass:{}:", &self.name);

        // The kernel's nf_log_syslog module suppresses log output from
        // non-init network namespaces by default. Enable it so the bypass
        // monitor can see log entries from the sandbox namespace.
        enable_nf_log_all_netns();

        let commands = nft_ruleset::generate_egress_ceiling_commands(
            &host_ip_str,
            proxy_port,
            Some(&log_prefix),
        );

        if let Err(e) = run_nft_commands_netns(&self.name, &nft_path, &commands) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::High)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "failed")
                    .message(format!(
                        "Failed to establish egress ceiling [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );
            return Err(e);
        }

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "installed")
                .message(format!(
                    "Default-deny egress ceiling established [ns:{}]",
                    self.name
                ))
                .build()
        );

        Ok(())
    }

    /// Verify the live default-deny egress ceiling installed for this boundary.
    ///
    /// This reads the ruleset back from the kernel rather than treating a
    /// successful installation attempt as proof that standing enforcement is
    /// still present.
    pub fn verify_egress_ceiling(&self, proxy_port: u16) -> Result<()> {
        self.egress_ceiling_verifier().verify(proxy_port)
    }

    #[must_use]
    pub fn egress_ceiling_verifier(&self) -> EgressCeilingVerifier {
        EgressCeilingVerifier {
            namespace: self.name.clone(),
            host_ip: self.host_ip,
            helper_source: self.helper_source,
        }
    }

    /// Bind a TCP listener inside this network namespace on a dedicated thread.
    ///
    /// Spawns a short-lived OS thread that enters the namespace via `setns`,
    /// binds a `std::net::TcpListener`, then exits. The listener fd is handed
    /// back as a non-blocking `tokio::net::TcpListener`. Using a dedicated
    /// thread (not `spawn_blocking`) avoids contaminating the tokio thread
    /// pool's namespace state.
    ///
    /// Returns `Err` if the namespace has no fd, `setns` fails, or bind fails.
    pub async fn bind_tcp_in_netns(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        let ns_fd = self
            .ns_fd
            .ok_or_else(|| std::io::Error::other("no namespace fd available for bind"))?;
        let addr = addr.to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<std::net::TcpListener> {
                // SAFETY: setns is safe to call; this is a dedicated thread
                // that exits after binding. The thread's namespace state does
                // not contaminate any thread pool.
                #[allow(unsafe_code)]
                let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                std::net::TcpListener::bind(&addr)
            })();
            let _ = tx.send(result);
        });

        let std_listener = rx
            .await
            .map_err(|_| std::io::Error::other("netns bind thread panicked"))??;
        std_listener.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(std_listener)
    }
}

impl EgressCeilingVerifier {
    fn nft_helper(&self) -> Result<TrustedHelper> {
        find_nft(self.helper_source)
            .ok_or_else(|| miette::miette!("nft not found; cannot verify egress ceiling"))
    }

    fn verify(&self, proxy_port: u16) -> Result<()> {
        let nft = self.nft_helper()?;
        let output = trusted_command_in_netns(&nft, &self.namespace)?
            .args(["-j", "list", "chain", "inet", "openshell_bypass", "output"])
            .output()
            .into_diagnostic()?;
        self.validate_output(proxy_port, &output)
    }

    /// Run a verifier helper with a hard deadline. Dropping the timed-out
    /// future kills the child, so a stuck `nft` cannot retain the
    /// namespace or suspend enforcement-loss detection indefinitely.
    pub async fn verify_bounded(
        &self,
        proxy_port: u16,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let nft = self.nft_helper()?;
        let mut command = trusted_tokio_command_in_netns(&nft, &self.namespace)?;
        command.kill_on_drop(true).args([
            "-j",
            "list",
            "chain",
            "inet",
            "openshell_bypass",
            "output",
        ]);
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| miette::miette!("egress ceiling verification timed out"))?
            .into_diagnostic()?;
        self.validate_output(proxy_port, &output)
    }

    fn validate_output(&self, proxy_port: u16, output: &std::process::Output) -> Result<()> {
        if !output.status.success() {
            return Err(miette::miette!(
                "could not read back egress ceiling in netns {}: {}",
                self.namespace,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        verify_egress_ceiling_json(&output.stdout, &self.host_ip.to_string(), proxy_port)
    }
}

fn verify_egress_ceiling_json(json: &[u8], host_ip: &str, proxy_port: u16) -> Result<()> {
    let document: serde_json::Value = serde_json::from_slice(json).into_diagnostic()?;
    let objects = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| miette::miette!("nft response has no nftables object list"))?;

    let chain_is_default_deny = objects.iter().any(|object| {
        let Some(chain) = object.get("chain") else {
            return false;
        };
        chain.get("family").and_then(serde_json::Value::as_str) == Some("inet")
            && chain.get("table").and_then(serde_json::Value::as_str) == Some("openshell_bypass")
            && chain.get("name").and_then(serde_json::Value::as_str) == Some("output")
            && chain.get("type").and_then(serde_json::Value::as_str) == Some("filter")
            && chain.get("hook").and_then(serde_json::Value::as_str) == Some("output")
            && chain.get("prio").and_then(serde_json::Value::as_i64) == Some(0)
            && chain.get("policy").and_then(serde_json::Value::as_str) == Some("drop")
    });
    if !chain_is_default_deny {
        return Err(miette::miette!(
            "egress ceiling output chain is absent or not policy drop"
        ));
    }

    let output_rules: Vec<&serde_json::Value> = objects
        .iter()
        .filter_map(|object| object.get("rule"))
        .collect();
    for rule in &output_rules {
        let expressions = rule
            .get("expr")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| miette::miette!("egress ceiling rule has no expression list"))?;
        for expression in expressions {
            let keys = expression
                .as_object()
                .ok_or_else(|| miette::miette!("egress ceiling contains a malformed expression"))?;
            if keys.len() != 1
                || !keys.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "match" | "counter" | "limit" | "log" | "reject" | "drop" | "accept"
                    )
                })
            {
                return Err(miette::miette!(
                    "egress ceiling contains an unsupported or redirecting expression"
                ));
            }
        }
    }
    let accept_rules: Vec<&serde_json::Value> = output_rules
        .into_iter()
        .filter(|rule| {
            rule.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                && rule.get("table").and_then(serde_json::Value::as_str) == Some("openshell_bypass")
                && rule.get("chain").and_then(serde_json::Value::as_str) == Some("output")
        })
        .filter(|rule| {
            rule.get("expr")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|expressions| {
                    expressions
                        .iter()
                        .any(|expression| expression == &serde_json::json!({"accept": null}))
                })
        })
        .collect();
    let proxy_expressions = serde_json::json!([
        {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":host_ip}},
        {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":proxy_port}},
        {"accept":null}
    ]);
    let loopback_expressions = serde_json::json!([
        {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},
        {"accept":null}
    ]);
    let mut proxy_allowed = false;
    let mut loopback_allowed = false;
    for rule in accept_rules {
        let expressions = rule.get("expr").expect("accept rule has expressions");
        if expressions == &proxy_expressions {
            proxy_allowed = true;
        } else if expressions == &loopback_expressions {
            loopback_allowed = true;
        } else {
            return Err(miette::miette!(
                "egress ceiling contains an unexpected accept rule: {expressions}"
            ));
        }
    }
    if !proxy_allowed || !loopback_allowed {
        return Err(miette::miette!(
            "egress ceiling is missing the proxy or loopback accept rule"
        ));
    }
    Ok(())
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        debug!(namespace = %self.name, "Cleaning up network namespace");

        // Close the fd if we have one
        if let Some(fd) = self.ns_fd.take() {
            let _ = nix::unistd::close(fd);
        }

        // Delete the host-side veth (this also removes the peer)
        let mut cleanup_failed = false;
        if let Err(e) = run_ip(self.helper_source, &["link", "delete", &self.veth_host]) {
            cleanup_failed = true;
            warn!(
                error = %e,
                veth = %self.veth_host,
                "Failed to delete veth interface"
            );
        }

        // Delete the namespace
        if let Err(e) = run_ip(self.helper_source, &["netns", "delete", &self.name]) {
            cleanup_failed = true;
            warn!(
                error = %e,
                namespace = %self.name,
                "Failed to delete network namespace"
            );
        }

        let event = openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(if cleanup_failed {
                openshell_ocsf::SeverityId::High
            } else {
                openshell_ocsf::SeverityId::Informational
            })
            .status(if cleanup_failed {
                openshell_ocsf::StatusId::Failure
            } else {
                openshell_ocsf::StatusId::Success
            })
            .state(
                openshell_ocsf::StateId::Disabled,
                if cleanup_failed {
                    "cleanup_failed"
                } else {
                    "cleaned_up"
                },
            )
            .message(if cleanup_failed {
                format!("Network namespace cleanup incomplete [ns:{}]", self.name)
            } else {
                format!("Network namespace cleaned up [ns:{}]", self.name)
            })
            .build();
        openshell_ocsf::ocsf_emit!(event);
    }
}

/// Create the workload's network namespace and install bypass detection
/// rules. Returns `None` when the policy is not in proxy mode.
///
/// The namespace is shared infrastructure: the proxy binds to its host-side
/// veth IP and reads /dev/kmsg from inside it for bypass detection, while
/// the workload child and SSH sessions enter it via `setns()`.
///
/// # Errors
///
/// Returns an error if proxy mode is requested but the namespace cannot be
/// created (e.g., missing `CAP_NET_ADMIN` / `CAP_SYS_ADMIN` or `iproute2`).
/// Legacy bypass-rule installation remains best-effort for compatibility.
pub fn create_netns_for_proxy(
    policy: &openshell_core::policy::SandboxPolicy,
) -> Result<Option<NetworkNamespace>> {
    create_netns(policy, false)
}

/// Create a proxy namespace whose nftables policy is a mandatory RFC 0012
/// default-deny ceiling. Unlike the legacy helper, any installation failure
/// aborts boundary establishment.
pub fn create_conformant_netns_for_proxy(
    policy: &openshell_core::policy::SandboxPolicy,
) -> Result<Option<NetworkNamespace>> {
    create_netns(policy, true)
}

fn create_netns(
    policy: &openshell_core::policy::SandboxPolicy,
    require_egress_ceiling: bool,
) -> Result<Option<NetworkNamespace>> {
    use openshell_core::policy::NetworkMode;
    use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};

    if !matches!(policy.network.mode, NetworkMode::Proxy) {
        return Ok(None);
    }
    let namespace = if require_egress_ceiling {
        NetworkNamespace::create_conformant()
    } else {
        NetworkNamespace::create()
    };
    match namespace {
        Ok(ns) => {
            let proxy_port = policy
                .network
                .proxy
                .as_ref()
                .and_then(|p| p.http_addr)
                .map_or(3128, |addr| addr.port());
            if require_egress_ceiling {
                ns.install_egress_ceiling(proxy_port).map_err(|error| {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .state(StateId::Disabled, "failed")
                            .message(format!("Failed to establish egress ceiling: {error}"))
                            .build()
                    );
                    error
                })?;
            } else if let Err(error) = ns.install_bypass_rules(proxy_port) {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Disabled, "degraded")
                        .message(format!(
                            "Failed to install bypass detection rules (non-fatal): {error}"
                        ))
                        .build()
                );
            }
            Ok(Some(ns))
        }
        Err(e) => Err(miette::miette!(
            "Network namespace creation failed and proxy mode requires isolation. \
             Ensure CAP_NET_ADMIN and CAP_SYS_ADMIN are available and iproute2 is installed. \
             Error: {e}"
        )),
    }
}

/// Install pod-network bypass enforcement for Kubernetes sidecar topology.
///
/// This runs in the current network namespace, not in a per-workload netns.
/// The rules allow loopback and the sidecar proxy UID, then reject direct
/// TCP/UDP egress from other UIDs so traffic must use the sidecar's local
/// proxy.
///
/// # Errors
///
/// Returns an error when `nft` is unavailable or the ruleset cannot be loaded.
pub fn install_sidecar_bypass_rules(proxy_uid: u32) -> Result<()> {
    match install_sidecar_nft_bypass_rules(proxy_uid) {
        Ok(()) => Ok(()),
        Err(nft_error) => {
            warn!(
                error = %nft_error,
                "Failed to install nftables sidecar rules; trying iptables-legacy fallback"
            );
            install_sidecar_iptables_legacy_bypass_rules(proxy_uid).map_err(|iptables_error| {
                miette::miette!(
                    "sidecar nft ruleset load failed: {nft_error}; sidecar iptables-legacy fallback failed: {iptables_error}"
                )
            })
        }
    }
}

fn install_sidecar_nft_bypass_rules(proxy_uid: u32) -> Result<()> {
    let nft_cmd = find_nft(HelperSource::TrustedSupervisorRuntime).ok_or_else(|| {
        miette::miette!(
            "trusted nft helper not found; sidecar network enforcement requires nftables"
        )
    })?;
    let log_prefix = Some("openshell:sidecar-bypass:");
    let commands = nft_ruleset::generate_sidecar_bypass_commands(proxy_uid, log_prefix);
    run_nft_commands_current_namespace(&nft_cmd, &commands)
}

const SIDECAR_IPTABLES_CHAIN: &str = "OPENSHELL_SIDECAR_BYPASS";
const PROC_NET_IF_INET6_PATH: &str = "/proc/net/if_inet6";

fn install_sidecar_iptables_legacy_bypass_rules(proxy_uid: u32) -> Result<()> {
    let ipv4_filter_tool = find_iptables_legacy(HelperSource::TrustedSupervisorRuntime).ok_or_else(|| {
        miette::miette!(
            "trusted iptables-legacy helper not found; sidecar network enforcement fallback unavailable"
        )
    })?;

    let ipv6_fence_tool = if current_namespace_has_non_loopback_ipv6()? {
        Some(find_ip6tables_legacy(HelperSource::TrustedSupervisorRuntime).ok_or_else(|| {
            miette::miette!(
                "trusted ip6tables-legacy helper not found; sidecar network enforcement fallback cannot fence IPv6"
            )
        })?)
    } else {
        warn!(
            "Skipping IPv6 sidecar iptables-legacy fallback because the current namespace has no non-loopback IPv6 interface"
        );
        None
    };

    cleanup_sidecar_iptables_legacy_rule_families(&ipv4_filter_tool, ipv6_fence_tool.as_ref());

    if let Err(e) = install_sidecar_iptables_legacy_family_rules(
        &ipv4_filter_tool,
        proxy_uid,
        "icmp-port-unreachable",
    ) {
        cleanup_sidecar_iptables_legacy_rule_families(&ipv4_filter_tool, ipv6_fence_tool.as_ref());
        return Err(e);
    }

    if let Some(ipv6_fence_tool) = ipv6_fence_tool
        && let Err(e) = install_sidecar_iptables_legacy_family_rules(
            &ipv6_fence_tool,
            proxy_uid,
            "icmp6-port-unreachable",
        )
    {
        cleanup_sidecar_iptables_legacy_rule_families(&ipv4_filter_tool, Some(&ipv6_fence_tool));
        return Err(e);
    }

    Ok(())
}

fn current_namespace_has_non_loopback_ipv6() -> Result<bool> {
    match std::fs::read_to_string(PROC_NET_IF_INET6_PATH) {
        Ok(content) => Ok(has_non_loopback_ipv6_interface(&content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(miette::miette!(
            "failed to inspect {PROC_NET_IF_INET6_PATH} before installing sidecar IPv6 fence: {e}"
        )),
    }
}

fn has_non_loopback_ipv6_interface(content: &str) -> bool {
    content.lines().any(|line| {
        line.split_whitespace()
            .nth(5)
            .is_some_and(|iface| iface != "lo")
    })
}

fn install_sidecar_iptables_legacy_family_rules(
    cmd: &TrustedHelper,
    proxy_uid: u32,
    udp_reject_with: &str,
) -> Result<()> {
    let proxy_uid_arg = proxy_uid.to_string();
    let commands: Vec<Vec<&str>> = vec![
        vec!["-N", SIDECAR_IPTABLES_CHAIN],
        vec!["-A", SIDECAR_IPTABLES_CHAIN, "-o", "lo", "-j", "ACCEPT"],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            &proxy_uid_arg,
            "-j",
            "ACCEPT",
        ],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-p",
            "tcp",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-p",
            "udp",
            "-j",
            "REJECT",
            "--reject-with",
            udp_reject_with,
        ],
        vec!["-A", "OUTPUT", "-j", SIDECAR_IPTABLES_CHAIN],
    ];

    for args in commands {
        if let Err(e) = run_iptables_legacy_current_namespace(cmd, &args) {
            cleanup_sidecar_iptables_legacy_rules(cmd);
            return Err(e);
        }
    }

    Ok(())
}

fn cleanup_sidecar_iptables_legacy_rules(iptables_cmd: &TrustedHelper) {
    while run_iptables_legacy_current_namespace(
        iptables_cmd,
        &["-D", "OUTPUT", "-j", SIDECAR_IPTABLES_CHAIN],
    )
    .is_ok()
    {}
    let _ = run_iptables_legacy_current_namespace(iptables_cmd, &["-F", SIDECAR_IPTABLES_CHAIN]);
    let _ = run_iptables_legacy_current_namespace(iptables_cmd, &["-X", SIDECAR_IPTABLES_CHAIN]);
}

fn cleanup_sidecar_iptables_legacy_rule_families(
    ipv4_cmd: &TrustedHelper,
    ipv6_cmd: Option<&TrustedHelper>,
) {
    cleanup_sidecar_iptables_legacy_rules(ipv4_cmd);
    if let Some(ipv6_cmd) = ipv6_cmd {
        cleanup_sidecar_iptables_legacy_rules(ipv6_cmd);
    }
}

#[allow(unsafe_code)]
fn trusted_command_in_netns(helper: &TrustedHelper, netns: &str) -> Result<Command> {
    use std::os::unix::process::CommandExt as _;

    let namespace = std::fs::File::open(format!("/var/run/netns/{netns}")).into_diagnostic()?;
    let mut command = helper.command();
    // SAFETY: `setns` is async-signal-safe and the captured file remains open
    // in the child until this pre-exec hook completes.
    unsafe {
        command.pre_exec(move || {
            if libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(command)
}

#[allow(unsafe_code)]
fn trusted_tokio_command_in_netns(
    helper: &TrustedHelper,
    netns: &str,
) -> Result<tokio::process::Command> {
    let namespace = std::fs::File::open(format!("/var/run/netns/{netns}")).into_diagnostic()?;
    let mut command = helper.tokio_command();
    // SAFETY: `setns` is async-signal-safe and the captured file remains open
    // in the child until this pre-exec hook completes.
    unsafe {
        command.pre_exec(move || {
            if libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(command)
}

/// Run an `ip` command on the host.
fn run_ip(source: HelperSource, args: &[&str]) -> Result<()> {
    let ip = find_binary(source, "ip", IP_SEARCH_PATHS)?;

    debug!(command = %format!("{} {}", ip.executable.display(), args.join(" ")), "Running ip command");

    let output = ip.command().args(args).output().into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{} {} failed: {}",
            ip.executable.display(),
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

fn run_iptables_legacy_current_namespace(
    iptables_cmd: &TrustedHelper,
    args: &[&str],
) -> Result<()> {
    debug!(
        command = %format!("{} {}", iptables_cmd.executable.display(), args.join(" ")),
        "Running iptables-legacy sidecar command"
    );

    let output = iptables_cmd
        .command()
        .args(args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{} {} failed: {}",
            iptables_cmd.executable.display(),
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

/// Run a sequence of nft commands in the current network namespace.
///
/// Each command is executed as a separate `nft` invocation to avoid atomic
/// batch rollback (where one unsupported expression like `ct state` or `log`
/// causes the entire transaction, including table creation, to fail).
///
/// Commands marked as non-required are allowed to fail with a warning.
/// Required commands that fail abort the sequence immediately.
fn run_nft_commands_current_namespace(
    nft_cmd: &TrustedHelper,
    commands: &[nft_ruleset::NftCommand],
) -> Result<()> {
    for cmd in commands {
        let args_str = cmd.args.join(" ");
        debug!(command = %format!("{} {args_str}", nft_cmd.executable.display()), "Running nft command");

        let output = nft_cmd
            .command()
            .args(&cmd.args)
            .output()
            .into_diagnostic()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if cmd.required {
                return Err(miette::miette!(
                    "{} {args_str} failed: {}",
                    nft_cmd.executable.display(),
                    stderr.trim()
                ));
            }
            warn!(
                command = %args_str,
                error = %stderr.trim(),
                "non-required nft command failed (continuing)"
            );
        }
    }
    Ok(())
}

/// Run an `ip` command inside a network namespace.
///
/// The child enters only the network namespace before exec. This avoids both
/// `ip netns exec`'s sysfs remount and a separate `nsenter` helper.
fn run_ip_netns(source: HelperSource, netns: &str, args: &[&str]) -> Result<()> {
    let ip = find_binary(source, "ip", IP_SEARCH_PATHS)?;

    debug!(
        command = %format!("{} {}", ip.executable.display(), args.join(" ")),
        "Running ip in namespace"
    );

    let output = trusted_command_in_netns(&ip, netns)?
        .args(args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{} {} failed in netns {netns}: {}",
            ip.executable.display(),
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

/// Run a sequence of nft commands inside a network namespace.
///
/// Each command is executed as a separate invocation to avoid atomic batch
/// rollback. See [`run_nft_commands_current_namespace`] for rationale.
fn run_nft_commands_netns(
    netns: &str,
    nft_cmd: &TrustedHelper,
    commands: &[nft_ruleset::NftCommand],
) -> Result<()> {
    for cmd in commands {
        let args_str = cmd.args.join(" ");
        debug!(
            command = %format!("{} {args_str}", nft_cmd.executable.display()),
            "Running nft command in namespace"
        );

        let arg_refs: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let output = trusted_command_in_netns(nft_cmd, netns)?
            .args(&arg_refs)
            .output()
            .into_diagnostic()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if cmd.required {
                return Err(miette::miette!(
                    "nft {args_str} failed in netns {netns}: {}",
                    stderr.trim()
                ));
            }
            warn!(
                command = %args_str,
                error = %stderr.trim(),
                netns = %netns,
                "non-required nft command failed in namespace (continuing)"
            );
        }
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

/// Paths within the driver-controlled supervisor runtime.
const NFT_SEARCH_PATHS: &[&str] = &["usr/sbin/nft", "sbin/nft", "usr/bin/nft"];
const IPTABLES_LEGACY_SEARCH_PATHS: &[&str] = &[
    "usr/sbin/iptables-legacy",
    "sbin/iptables-legacy",
    "usr/bin/iptables-legacy",
];
const IP6TABLES_LEGACY_SEARCH_PATHS: &[&str] = &[
    "usr/sbin/ip6tables-legacy",
    "sbin/ip6tables-legacy",
    "usr/bin/ip6tables-legacy",
];

fn trusted_runtime_root() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(root) = std::env::var_os("OPENSHELL_TEST_TRUSTED_RUNTIME_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let executable = std::env::current_exe().into_diagnostic()?;
    let parent = executable
        .parent()
        .ok_or_else(|| miette::miette!("supervisor executable has no parent directory"))?;
    Ok(parent.join("openshell-runtime"))
}

fn find_binary(source: HelperSource, name: &str, paths: &[&str]) -> Result<TrustedHelper> {
    match source {
        HelperSource::LegacyWorkloadImage => find_legacy_binary(name, paths),
        HelperSource::TrustedSupervisorRuntime => find_trusted_binary(name, paths),
    }
}

fn find_legacy_binary(name: &str, paths: &[&str]) -> Result<TrustedHelper> {
    use std::os::unix::fs::MetadataExt as _;

    let trusted_uid = nix::unistd::geteuid().as_raw();
    let executable = paths
        .iter()
        .map(|path| Path::new("/").join(path))
        .find_map(|path| {
            let resolved = path.canonicalize().ok()?;
            let metadata = resolved.metadata().ok()?;
            (metadata.is_file()
                && metadata.uid() == trusted_uid
                && metadata.mode() & 0o111 != 0
                && metadata.mode() & 0o022 == 0)
                .then_some(resolved)
        })
        .ok_or_else(|| {
            miette::miette!(
                "{name} helper not found in legacy workload image; checked {}",
                paths.join(", ")
            )
        })?;
    Ok(TrustedHelper {
        executable,
        loader: None,
        library_path: String::new(),
        xtables_path: PathBuf::new(),
    })
}

fn find_trusted_binary(name: &str, paths: &[&str]) -> Result<TrustedHelper> {
    find_trusted_binary_in(&trusted_runtime_root()?, name, paths)
}

fn find_trusted_binary_in(root: &Path, name: &str, paths: &[&str]) -> Result<TrustedHelper> {
    use std::os::unix::fs::MetadataExt;

    let trusted_uid = nix::unistd::geteuid().as_raw();
    let resolved_root = root.canonicalize().map_err(|error| {
        miette::miette!(
            "trusted supervisor helper runtime {} is unavailable: {error}",
            root.display()
        )
    })?;
    // Kubernetes and Podman preserve root ownership from the supervisor image.
    // Docker may materialize the same image-owned runtime in a gateway-user
    // cache before bind-mounting it read-only. In that case the immutable
    // mount, not its namespace-visible UID, establishes provenance.
    let runtime_is_read_only = nix::sys::statvfs::statvfs(&resolved_root)
        .is_ok_and(|stat| stat.flags().contains(nix::sys::statvfs::FsFlags::ST_RDONLY));
    let executable = paths
        .iter()
        .map(|path| resolved_root.join(path))
        .find_map(|path| {
            let resolved = path.canonicalize().ok()?;
            if !resolved.starts_with(&resolved_root) {
                return None;
            }
            let Ok(metadata) = resolved.metadata() else {
                return None;
            };
            (metadata.is_file()
                && (metadata.uid() == trusted_uid || runtime_is_read_only)
                && metadata.mode() & 0o111 != 0
                && metadata.mode() & 0o022 == 0)
                .then_some(resolved)
        })
        .ok_or_else(|| {
            miette::miette!(
                "trusted {name} helper not found below {}; checked {}",
                resolved_root.display(),
                paths.join(", ")
            )
        })?;
    let loader = runtime_library_directories(&resolved_root)
        .into_iter()
        .filter_map(|directory| std::fs::read_dir(directory).ok())
        .flatten()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|path| is_runtime_loader(path))
        .ok_or_else(|| {
            miette::miette!(
                "trusted dynamic loader not found below {}",
                resolved_root.display()
            )
        })?
        .canonicalize()
        .into_diagnostic()?;
    if !loader.starts_with(&resolved_root) {
        return Err(miette::miette!("trusted runtime loader escapes its root"));
    }
    let loader_metadata = loader.metadata().into_diagnostic()?;
    if !loader_metadata.is_file()
        || (loader_metadata.uid() != trusted_uid && !runtime_is_read_only)
        || loader_metadata.mode() & 0o111 == 0
        || loader_metadata.mode() & 0o022 != 0
    {
        return Err(miette::miette!(
            "trusted runtime loader has unsafe ownership or mode"
        ));
    }
    let library_path = runtime_library_directories(&resolved_root)
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let xtables_path = runtime_library_directories(&resolved_root)
        .into_iter()
        .map(|directory| directory.join("xtables"))
        .find(|path| path.is_dir())
        .unwrap_or_else(|| resolved_root.join("usr/lib/xtables"));
    Ok(TrustedHelper {
        executable,
        loader: Some(loader),
        library_path,
        xtables_path,
    })
}

fn runtime_library_directories(root: &Path) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    for base in ["lib", "lib64", "usr/lib", "usr/lib64"] {
        let base = root.join(base);
        if !base.is_dir() {
            continue;
        }
        directories.push(base.clone());
        if let Ok(entries) = std::fs::read_dir(base) {
            directories.extend(
                entries
                    .filter_map(std::result::Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.is_dir()),
            );
        }
    }
    directories
}

fn is_runtime_loader(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            (name.starts_with("ld-musl-") && name.ends_with(".so.1"))
                || name == "ld-linux-x86-64.so.2"
                || name == "ld-linux-aarch64.so.1"
        })
}

/// Find the nft binary path, checking well-known locations.
fn find_nft(source: HelperSource) -> Option<TrustedHelper> {
    find_binary(source, "nft", NFT_SEARCH_PATHS).ok()
}

fn find_iptables_legacy(source: HelperSource) -> Option<TrustedHelper> {
    find_binary(source, "iptables-legacy", IPTABLES_LEGACY_SEARCH_PATHS).ok()
}

fn find_ip6tables_legacy(source: HelperSource) -> Option<TrustedHelper> {
    find_binary(source, "ip6tables-legacy", IP6TABLES_LEGACY_SEARCH_PATHS).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    // These tests require root and network namespace support
    // Run with: sudo cargo test -- --ignored

    #[test]
    fn find_trusted_binary_uses_only_the_supplied_runtime() {
        let tempdir = tempfile::tempdir().unwrap();
        let helper = tempdir.path().join("usr/sbin/ip");
        fs::create_dir_all(helper.parent().unwrap()).unwrap();
        fs::write(&helper, b"test helper").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let lib = tempdir.path().join("lib");
        fs::create_dir(&lib).unwrap();
        let loader = lib.join("ld-musl-test.so.1");
        fs::write(&loader, b"test loader").unwrap();
        fs::set_permissions(loader, fs::Permissions::from_mode(0o755)).unwrap();

        let resolved = find_trusted_binary_in(tempdir.path(), "ip", &["usr/sbin/ip"]).unwrap();
        assert_eq!(resolved.executable, helper);
    }

    #[test]
    fn find_trusted_binary_rejects_missing_helpers() {
        let tempdir = tempfile::tempdir().unwrap();
        let err = find_trusted_binary_in(tempdir.path(), "ip", &["usr/sbin/ip"]).unwrap_err();

        assert!(err.to_string().contains("trusted ip helper not found"));
    }

    #[test]
    fn trusted_runtime_rejects_helper_symlink_into_workload_root() {
        use std::os::unix::fs::symlink;

        let runtime = tempfile::tempdir().unwrap();
        let workload = tempfile::tempdir().unwrap();
        let malicious = workload.path().join("ip");
        fs::write(&malicious, b"malicious workload helper").unwrap();
        fs::set_permissions(&malicious, fs::Permissions::from_mode(0o755)).unwrap();
        let helper = runtime.path().join("usr/sbin/ip");
        fs::create_dir_all(helper.parent().unwrap()).unwrap();
        symlink(&malicious, &helper).unwrap();

        let error = find_trusted_binary_in(runtime.path(), "ip", &["usr/sbin/ip"])
            .expect_err("helper escaping the trusted runtime must be rejected");
        assert!(error.to_string().contains("trusted ip helper not found"));
    }

    #[test]
    fn nft_search_paths_are_runtime_relative() {
        for path in NFT_SEARCH_PATHS {
            assert!(
                !path.starts_with('/'),
                "NFT_SEARCH_PATHS entry must be runtime-relative: {path}"
            );
        }
    }

    #[test]
    fn iptables_legacy_search_paths_are_runtime_relative() {
        for path in IPTABLES_LEGACY_SEARCH_PATHS {
            assert!(
                !path.starts_with('/'),
                "IPTABLES_LEGACY_SEARCH_PATHS entry must be runtime-relative: {path}"
            );
        }
    }

    #[test]
    fn ip6tables_legacy_search_paths_are_runtime_relative() {
        for path in IP6TABLES_LEGACY_SEARCH_PATHS {
            assert!(
                !path.starts_with('/'),
                "IP6TABLES_LEGACY_SEARCH_PATHS entry must be runtime-relative: {path}"
            );
        }
    }

    #[test]
    fn non_loopback_ipv6_detector_ignores_empty_input() {
        assert!(!has_non_loopback_ipv6_interface(""));
        assert!(!has_non_loopback_ipv6_interface("\n\n"));
    }

    #[test]
    fn non_loopback_ipv6_detector_ignores_loopback() {
        let content = "00000000000000000000000000000001 01 80 10 80 lo\n";

        assert!(!has_non_loopback_ipv6_interface(content));
    }

    #[test]
    fn non_loopback_ipv6_detector_detects_pod_interface() {
        let content = "\
00000000000000000000000000000001 01 80 10 80 lo
fe800000000000000000000000000001 02 40 20 80 eth0
";

        assert!(has_non_loopback_ipv6_interface(content));
    }

    #[test]
    fn egress_ceiling_verification_accepts_required_live_rules() {
        let ruleset = br#"{
          "nftables": [
            {"chain":{"family":"inet","table":"openshell_bypass","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
            {"rule":{"family":"inet","table":"openshell_bypass","chain":"output","expr":[
              {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.200.0.1"}},
              {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":3128}},
              {"accept":null}
            ]}},
            {"rule":{"family":"inet","table":"openshell_bypass","chain":"output","expr":[
              {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},
              {"accept":null}
            ]}}
          ]
        }"#;

        verify_egress_ceiling_json(ruleset, "10.200.0.1", 3128).unwrap();
    }

    #[test]
    fn egress_ceiling_verification_rejects_fail_open_chain() {
        let ruleset = br#"{
          "nftables": [
            {"chain":{"family":"inet","table":"openshell_bypass","name":"output","hook":"output","policy":"accept"}},
            {"rule":{"family":"inet","table":"openshell_bypass","chain":"output","expr":[{"match":{"right":"10.200.0.1"}},{"match":{"right":3128}},{"accept":null}]}},
            {"rule":{"family":"inet","table":"openshell_bypass","chain":"output","expr":[{"match":{"right":"lo"}},{"accept":null}]}}
          ]
        }"#;

        assert!(verify_egress_ceiling_json(ruleset, "10.200.0.1", 3128).is_err());
    }

    #[test]
    fn egress_ceiling_verification_rejects_missing_required_allow() {
        let ruleset = br#"{
          "nftables": [
            {"chain":{"family":"inet","table":"openshell_bypass","name":"output","hook":"output","policy":"drop"}},
            {"rule":{"family":"inet","table":"openshell_bypass","chain":"output","expr":[{"match":{"right":"lo"}},{"accept":null}]}}
          ]
        }"#;

        assert!(verify_egress_ceiling_json(ruleset, "10.200.0.1", 3128).is_err());
    }

    fn ruleset_with_accept_expressions(expressions: &str) -> Vec<u8> {
        format!(
            r#"{{"nftables":[
              {{"chain":{{"family":"inet","table":"openshell_bypass","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}}}},
              {{"rule":{{"family":"inet","table":"openshell_bypass","chain":"output","expr":[
                {{"match":{{"op":"==","left":{{"payload":{{"protocol":"ip","field":"daddr"}}}},"right":"10.200.0.1"}}}},
                {{"match":{{"op":"==","left":{{"payload":{{"protocol":"tcp","field":"dport"}}}},"right":3128}}}},{{"accept":null}}]}}}},
              {{"rule":{{"family":"inet","table":"openshell_bypass","chain":"output","expr":[
                {{"match":{{"op":"==","left":{{"meta":{{"key":"oifname"}}}},"right":"lo"}}}},{{"accept":null}}]}}}},
              {{"rule":{{"family":"inet","table":"openshell_bypass","chain":"output","expr":{expressions}}}}}
            ]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn egress_ceiling_verification_rejects_unconditional_accept() {
        let ruleset = ruleset_with_accept_expressions(r#"[{"accept":null}]"#);
        assert!(verify_egress_ceiling_json(&ruleset, "10.200.0.1", 3128).is_err());
    }

    #[test]
    fn egress_ceiling_verification_rejects_unrelated_matching_metadata() {
        let ruleset = ruleset_with_accept_expressions(
            r#"[{"comment":{"address":"10.200.0.1","port":3128}},{"accept":null}]"#,
        );
        assert!(verify_egress_ceiling_json(&ruleset, "10.200.0.1", 3128).is_err());
    }

    #[test]
    fn egress_ceiling_verification_rejects_wrong_protocol_or_operator() {
        for expressions in [
            r#"[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":3128}},{"accept":null}]"#,
            r#"[{"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.200.0.1"}},{"accept":null}]"#,
        ] {
            let ruleset = ruleset_with_accept_expressions(expressions);
            assert!(verify_egress_ceiling_json(&ruleset, "10.200.0.1", 3128).is_err());
        }
    }

    #[test]
    fn egress_ceiling_verification_rejects_extra_destination_allow() {
        let ruleset = ruleset_with_accept_expressions(
            r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"203.0.113.1"}},{"accept":null}]"#,
        );
        assert!(verify_egress_ceiling_json(&ruleset, "10.200.0.1", 3128).is_err());
    }

    #[test]
    fn egress_ceiling_verification_rejects_jump_to_unverified_chain() {
        let ruleset = ruleset_with_accept_expressions(r#"[{"jump":{"target":"unverified"}}]"#);
        assert!(verify_egress_ceiling_json(&ruleset, "10.200.0.1", 3128).is_err());
    }

    #[test]
    fn egress_ceiling_verification_ignores_accept_in_another_chain() {
        let mut document: serde_json::Value =
            serde_json::from_slice(&ruleset_with_accept_expressions(r#"[{"accept":null}]"#))
                .unwrap();
        document["nftables"][3]["rule"]["chain"] = serde_json::json!("other");
        let ruleset = serde_json::to_vec(&document).unwrap();
        verify_egress_ceiling_json(&ruleset, "10.200.0.1", 3128).unwrap();
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

    #[test]
    #[ignore = "requires root privileges"]
    fn installed_egress_ceiling_round_trips_through_kernel() {
        let ns = NetworkNamespace::create_conformant().expect("create conformant namespace");
        ns.install_egress_ceiling(3128).expect("install ceiling");
        ns.verify_egress_ceiling(3128).expect("verify ceiling");
    }

    #[test]
    #[ignore = "requires root privileges"]
    fn installed_egress_ceiling_allows_only_proxy_tcp() {
        use std::time::Duration;

        #[allow(unsafe_code)]
        fn enter_namespace(ns_fd: RawFd) {
            // SAFETY: the owning NetworkNamespace remains alive until every
            // test thread has joined, so the descriptor stays valid.
            let result = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
            assert_eq!(result, 0, "enter workload network namespace");
        }

        let ns = NetworkNamespace::create_conformant().expect("create conformant namespace");
        let ns_fd = ns.ns_fd().expect("network namespace fd");
        let host_ip = ns.host_ip();

        let alternate_host_ip: std::net::Ipv4Addr = "10.200.0.3".parse().unwrap();
        run_ip(
            ns.helper_source,
            &["addr", "add", "10.200.0.3/24", "dev", &ns.veth_host],
        )
        .expect("add alternate routed IPv4 destination");
        let host_ipv6: std::net::Ipv6Addr = "fd00:200::1".parse().unwrap();
        run_ip(
            ns.helper_source,
            &[
                "-6",
                "addr",
                "add",
                "fd00:200::1/64",
                "dev",
                &ns.veth_host,
                "nodad",
            ],
        )
        .expect("add host IPv6 destination");
        run_ip_netns(
            ns.helper_source,
            ns.name(),
            &[
                "-6",
                "addr",
                "add",
                "fd00:200::2/64",
                "dev",
                &ns.veth_sandbox,
                "nodad",
            ],
        )
        .expect("add workload IPv6 source");

        // Positive controls prove each route/protocol works before the ceiling
        // is installed, so later denial cannot pass because of broken setup.
        let ipv4_control =
            std::net::TcpListener::bind((alternate_host_ip, 0)).expect("bind IPv4 control");
        let ipv4_control_address = ipv4_control.local_addr().unwrap();
        assert!(
            std::thread::spawn(move || {
                enter_namespace(ns_fd);
                std::net::TcpStream::connect_timeout(&ipv4_control_address, Duration::from_secs(1))
            })
            .join()
            .expect("IPv4 control thread")
            .is_ok(),
            "alternate IPv4 route must work before enforcement"
        );

        let ipv6_control = std::net::TcpListener::bind((host_ipv6, 0)).expect("bind IPv6 control");
        let ipv6_control_address = ipv6_control.local_addr().unwrap();
        assert!(
            std::thread::spawn(move || {
                enter_namespace(ns_fd);
                std::net::TcpStream::connect_timeout(&ipv6_control_address, Duration::from_secs(1))
            })
            .join()
            .expect("IPv6 control thread")
            .is_ok(),
            "IPv6 route must work before enforcement"
        );

        let udp_control =
            std::net::UdpSocket::bind((host_ip, 0)).expect("bind UDP positive control");
        udp_control
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let udp_control_address = udp_control.local_addr().unwrap();
        std::thread::spawn(move || {
            enter_namespace(ns_fd);
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind control UDP");
            socket.send_to(b"control", udp_control_address)
        })
        .join()
        .expect("UDP control thread")
        .expect("send UDP positive control");
        let mut control = [0_u8; 7];
        udp_control
            .recv_from(&mut control)
            .expect("UDP route must work before enforcement");
        assert_eq!(&control, b"control");

        let proxy = std::net::TcpListener::bind((host_ip, 0)).expect("bind proxy listener");
        let proxy_address = proxy.local_addr().expect("proxy address");
        ns.install_egress_ceiling(proxy_address.port())
            .expect("install ceiling");

        let allowed = std::thread::spawn(move || {
            enter_namespace(ns_fd);
            std::net::TcpStream::connect_timeout(&proxy_address, Duration::from_secs(1))
        });
        proxy
            .set_nonblocking(true)
            .expect("set proxy listener nonblocking");
        assert!(allowed.join().expect("allowed-connect thread").is_ok());

        let direct = std::net::TcpListener::bind((host_ip, 0)).expect("bind direct listener");
        let direct_address = direct.local_addr().expect("direct address");
        let denied = std::thread::spawn(move || {
            enter_namespace(ns_fd);
            std::net::TcpStream::connect_timeout(&direct_address, Duration::from_millis(300))
        });
        assert!(
            denied.join().expect("denied-connect thread").is_err(),
            "direct TCP must not bypass mediation"
        );

        let alternate = std::net::TcpListener::bind((alternate_host_ip, proxy_address.port()))
            .expect("bind alternate routed listener");
        let alternate_address = alternate.local_addr().unwrap();
        let denied = std::thread::spawn(move || {
            enter_namespace(ns_fd);
            std::net::TcpStream::connect_timeout(&alternate_address, Duration::from_millis(300))
        });
        assert!(
            denied.join().expect("alternate-connect thread").is_err(),
            "the proxy port at another routed IPv4 destination must be denied"
        );

        let ipv6 = std::net::TcpListener::bind((host_ipv6, proxy_address.port()))
            .expect("bind IPv6 observer");
        let ipv6_address = ipv6.local_addr().unwrap();
        let denied = std::thread::spawn(move || {
            enter_namespace(ns_fd);
            std::net::TcpStream::connect_timeout(&ipv6_address, Duration::from_millis(300))
        });
        assert!(
            denied.join().expect("IPv6-connect thread").is_err(),
            "direct IPv6 TCP must not bypass mediation"
        );

        let udp = std::net::UdpSocket::bind((host_ip, proxy_address.port()))
            .expect("bind UDP observer at proxy destination");
        udp.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set UDP timeout");
        let udp_address = udp.local_addr().expect("UDP address");
        let udp_send = std::thread::spawn(move || {
            enter_namespace(ns_fd);
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind workload UDP");
            socket.send_to(b"bypass", udp_address)
        })
        .join()
        .expect("UDP thread");
        let mut byte = [0_u8; 1];
        assert!(
            udp_send.is_err() || udp.recv_from(&mut byte).is_err(),
            "direct UDP must not bypass mediation"
        );
    }
}
