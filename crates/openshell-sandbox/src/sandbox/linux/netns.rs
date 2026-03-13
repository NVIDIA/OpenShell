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

        info!(
            namespace = %name,
            host_veth = %veth_host,
            sandbox_veth = %veth_sandbox,
            "Creating network namespace"
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

        info!(
            namespace = %name,
            host_ip = %host_ip,
            sandbox_ip = %sandbox_ip,
            "Network namespace created"
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

        info!(namespace = %self.name, "Network namespace cleaned up");
    }
}

/// Run an `ip` command.
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

/// Run an `ip netns exec` command inside a namespace.
fn run_ip_netns(netns: &str, args: &[&str]) -> Result<()> {
    let mut full_args = vec!["netns", "exec", netns, "ip"];
    full_args.extend(args);

    debug!(command = %format!("ip {}", full_args.join(" ")), "Running ip netns exec command");

    let output = Command::new("ip")
        .args(&full_args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "ip netns exec {} ip {} failed: {}",
            netns,
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
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
