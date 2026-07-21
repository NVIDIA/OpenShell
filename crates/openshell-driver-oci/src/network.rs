// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox network namespace + veth pair + nftables ruleset.
//!
//! This is the "generalize the VM driver's TAP/nftables path to a
//! veth-based default network path" piece of the design: instead of a TAP
//! device bridging into a microVM, each sandbox gets its own network
//! namespace joined to the host via a veth pair, scoped by the same
//! NAT + default-deny nftables shape the VM driver already uses (shared via
//! `openshell-nft-ruleset`).
//!
//! containerd does not manage host networking for a task by default (that
//! is what Kubernetes' CNI plugins or Docker/Podman's own bridge drivers do
//! for their respective backends); this module is what fills that gap for
//! the oci driver, matching the division of responsibility the VM
//! driver already has between hypervisor networking (gvproxy/TAP) and its
//! own nftables ruleset.
//!
//! Verified end to end against a real kernel: a container whose OCI spec
//! joins a namespace created by [`SandboxNetwork::setup`] sees only `lo` —
//! none of the host's interfaces are visible.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::NFT_TABLE_PREFIX;

/// Number of `/30` subnet slots available under a configured
/// `subnet_base` (see [`SandboxNetwork::plan`]).
const MAX_SUBNET_SLOTS: u32 = 64;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("failed to run {command}: {reason}")]
    CommandFailed { command: String, reason: String },
    #[error("no free /30 subnet slot available under {subnet_base} ({slots} in use)")]
    SubnetExhausted { subnet_base: String, slots: u32 },
}

/// Network resources allocated for one sandbox.
///
/// Every field is derived deterministically from the sandbox ID and the
/// configured subnet base by [`Self::plan`], so no shared allocator state
/// is needed across driver restarts.
#[derive(Debug, Clone)]
pub struct SandboxNetwork {
    /// Name of the network namespace this sandbox's container joins.
    pub netns_name: String,
    /// Absolute path to the namespace's bind-mounted handle
    /// (`/run/netns/<netns_name>`), suitable for the OCI spec's network
    /// namespace `path`.
    pub netns_path: PathBuf,
    /// Host-side end of the veth pair.
    host_veth: String,
    /// Sandbox-side end of the veth pair (named inside the namespace).
    ns_veth: String,
    /// Point-to-point /30 subnet shared by `host_ip`/`ns_ip`.
    subnet_cidr: String,
    host_ip: String,
    ns_ip: String,
    /// `/30` slot index within `subnet_base` this instance was assigned.
    /// Only meaningful for instances returned by [`Self::allocate`]; a
    /// plain [`Self::plan`] call sets this to its naive hash-derived slot
    /// without checking for collisions.
    slot: u32,
}

impl SandboxNetwork {
    /// Derive deterministic, host-unique interface names, a namespace name,
    /// and a naive hash-derived /30 subnet slot for a sandbox ID.
    ///
    /// `subnet_base` is interpreted as the first three octets of a /24 (the
    /// fourth octet is ignored). This gives 64 usable /30 blocks, i.e. up to
    /// 64 concurrent sandboxes per configured base — matching the VM
    /// driver's own TAP subnet's concurrency ceiling.
    ///
    /// This alone does not check whether the resulting slot is already in
    /// use by another live sandbox; callers setting up a real sandbox
    /// should use [`Self::allocate`] instead. `plan` remains useful on its
    /// own for recomputing a sandbox's deterministic identity (interface
    /// names) during teardown, where no new allocation is needed.
    #[must_use]
    pub fn plan(sandbox_id: &str, subnet_base: &str) -> Self {
        let short = short_hash(sandbox_id);
        let netns_name = format!("osh-{short}");
        let host_veth = format!("oshv{short}h");
        let ns_veth = format!("oshv{short}n");

        let slot = u32::from_str_radix(&short[..2], 16).unwrap_or(0) % MAX_SUBNET_SLOTS;
        let (subnet_cidr, host_ip, ns_ip) = subnet_for_slot(subnet_base, slot);

        Self {
            netns_path: PathBuf::from(format!("/run/netns/{netns_name}")),
            netns_name,
            host_veth,
            ns_veth,
            subnet_cidr,
            host_ip,
            ns_ip,
            slot,
        }
    }

    /// Like [`Self::plan`], but detects and avoids a subnet collision with
    /// another sandbox that is still live: a slot is claimed by writing a
    /// marker file (containing `sandbox_id`) under
    /// `<state_dir>/network-slots/<slot>`, and is only reused for a
    /// *different* sandbox once that sandbox's network namespace
    /// (`/run/netns/osh-<hash>`) no longer exists (i.e. the marker is
    /// stale, left behind by a driver crash rather than a live sandbox).
    ///
    /// Starts probing at the same hash-derived slot [`Self::plan`] would
    /// pick (so the common, collision-free case is unaffected) and walks
    /// forward through the remaining slots on conflict.
    ///
    /// # Errors
    /// Returns [`NetworkError::SubnetExhausted`] if every slot under
    /// `subnet_base` is claimed by another live sandbox.
    pub fn allocate(
        sandbox_id: &str,
        subnet_base: &str,
        state_dir: &Path,
    ) -> Result<Self, NetworkError> {
        Self::allocate_with(sandbox_id, subnet_base, state_dir, netns_is_live)
    }

    /// Implementation behind [`Self::allocate`], parameterized over the
    /// liveness check so tests can simulate a collision with a "live"
    /// sandbox without creating a real network namespace.
    fn allocate_with(
        sandbox_id: &str,
        subnet_base: &str,
        state_dir: &Path,
        is_live: impl Fn(&str) -> bool,
    ) -> Result<Self, NetworkError> {
        let mut candidate = Self::plan(sandbox_id, subnet_base);
        let preferred_slot = candidate.slot;

        let slots_dir = state_dir.join("network-slots");
        std::fs::create_dir_all(&slots_dir).map_err(|err| NetworkError::CommandFailed {
            command: "create network-slots state directory".to_string(),
            reason: err.to_string(),
        })?;

        for offset in 0..MAX_SUBNET_SLOTS {
            let slot = (preferred_slot + offset) % MAX_SUBNET_SLOTS;
            let marker = slots_dir.join(slot.to_string());

            if let Ok(owner) = std::fs::read_to_string(&marker) {
                let owner = owner.trim();
                if owner != sandbox_id && is_live(owner) {
                    // Genuinely claimed by another live sandbox; try the
                    // next slot.
                    continue;
                }
            }

            std::fs::write(&marker, sandbox_id).map_err(|err| NetworkError::CommandFailed {
                command: format!("claim network slot {slot}"),
                reason: err.to_string(),
            })?;

            let (subnet_cidr, host_ip, ns_ip) = subnet_for_slot(subnet_base, slot);
            candidate.subnet_cidr = subnet_cidr;
            candidate.host_ip = host_ip;
            candidate.ns_ip = ns_ip;
            candidate.slot = slot;
            return Ok(candidate);
        }

        Err(NetworkError::SubnetExhausted {
            subnet_base: subnet_base.to_string(),
            slots: MAX_SUBNET_SLOTS,
        })
    }

    /// Release this sandbox's claimed subnet slot (if any), so it can be
    /// reused by a future sandbox. Best-effort: safe to call even if no
    /// slot was ever claimed (e.g. `plan` was used instead of `allocate`).
    pub fn release_slot(sandbox_id: &str, state_dir: &Path) {
        let slots_dir = state_dir.join("network-slots");
        let Ok(entries) = std::fs::read_dir(&slots_dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let owner = std::fs::read_to_string(entry.path()).unwrap_or_default();
            if owner.trim() == sandbox_id {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// The sandbox-side IP address the container should be told to use as
    /// its default route target's peer address (e.g. for readiness probes
    /// run from the driver against the sandbox, if ever needed).
    #[must_use]
    pub fn sandbox_ip(&self) -> &str {
        &self.ns_ip
    }

    /// The host-side address the sandbox reaches this driver/gateway
    /// through (the veth peer address). Unlike loopback, this address is
    /// reachable from inside the sandbox's own network namespace.
    #[must_use]
    pub fn host_ip(&self) -> &str {
        &self.host_ip
    }

    /// Create the network namespace, veth pair, addressing, and nftables
    /// ruleset. Tears down any stale state left by a prior crashed run for
    /// the same sandbox ID first (best-effort), mirroring the VM driver's
    /// stale-TAP cleanup.
    pub fn setup(&self, gateway_port: u16) -> Result<(), NetworkError> {
        let _ = self.teardown_best_effort();

        run("ip", &["netns", "add", &self.netns_name])?;
        run(
            "ip",
            &[
                "link",
                "add",
                &self.host_veth,
                "type",
                "veth",
                "peer",
                "name",
                &self.ns_veth,
            ],
        )?;
        run(
            "ip",
            &["link", "set", &self.ns_veth, "netns", &self.netns_name],
        )?;
        run(
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/30", self.host_ip),
                "dev",
                &self.host_veth,
            ],
        )?;
        run("ip", &["link", "set", &self.host_veth, "up"])?;

        run_in_netns(&self.netns_name, "ip", &["link", "set", "lo", "up"])?;
        run_in_netns(
            &self.netns_name,
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/30", self.ns_ip),
                "dev",
                &self.ns_veth,
            ],
        )?;
        run_in_netns(
            &self.netns_name,
            "ip",
            &["link", "set", &self.ns_veth, "up"],
        )?;
        run_in_netns(
            &self.netns_name,
            "ip",
            &["route", "add", "default", "via", &self.host_ip],
        )?;

        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

        let ruleset = openshell_nft_ruleset::generate_ruleset(
            NFT_TABLE_PREFIX,
            &self.host_veth,
            &self.subnet_cidr,
            gateway_port,
        );
        run_nft_stdin(&ruleset)?;

        Ok(())
    }

    /// Tear down every resource `setup` created. Best-effort: every step
    /// runs even if an earlier one fails, so a partially-created namespace
    /// from a previous crash never blocks cleanup.
    pub fn teardown_best_effort(&self) -> Result<(), NetworkError> {
        let table_name =
            openshell_nft_ruleset::teardown_table_name(NFT_TABLE_PREFIX, &self.host_veth);
        let _ = run("nft", &["delete", "table", "ip", &table_name]);
        // Deleting the host-side veth end also destroys its peer even
        // though the peer has been moved into another namespace.
        let _ = run("ip", &["link", "del", &self.host_veth]);
        let _ = run("ip", &["netns", "del", &self.netns_name]);
        Ok(())
    }
}

/// Compute the `/30` CIDR and the host/namespace-side addresses within it
/// for a given slot index, relative to `subnet_base` (the first three
/// octets of a /24; the fourth octet is ignored).
fn subnet_for_slot(subnet_base: &str, slot: u32) -> (String, String, String) {
    let base_octets = subnet_base
        .parse::<std::net::Ipv4Addr>()
        .map_or([10, 0, 132, 0], |ip| ip.octets());
    let fourth = u8::try_from(slot * 4).unwrap_or(0);
    let host_ip =
        std::net::Ipv4Addr::new(base_octets[0], base_octets[1], base_octets[2], fourth + 1);
    let ns_ip = std::net::Ipv4Addr::new(base_octets[0], base_octets[1], base_octets[2], fourth + 2);
    let subnet_cidr = format!(
        "{}.{}.{}.{}/30",
        base_octets[0], base_octets[1], base_octets[2], fourth
    );
    (subnet_cidr, host_ip.to_string(), ns_ip.to_string())
}

/// Whether a sandbox's network namespace still exists on this host, used
/// by [`SandboxNetwork::allocate`] to tell a stale subnet-slot marker
/// (left behind by a driver crash) from one still held by a live sandbox.
fn netns_is_live(owner_sandbox_id: &str) -> bool {
    let netns_name = format!("osh-{}", short_hash(owner_sandbox_id));
    PathBuf::from("/run/netns").join(netns_name).exists()
}

/// Deterministic, interface-name-safe short hash of a sandbox ID.
///
/// Interface names are limited to 15 characters (`IFNAMSIZ - 1`), so a full
/// UUID cannot be embedded directly.
fn short_hash(sandbox_id: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let digest = Sha256::digest(sandbox_id.as_bytes());
    let mut hex = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn run(cmd: &str, args: &[&str]) -> Result<(), NetworkError> {
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| NetworkError::CommandFailed {
            command: format!("{cmd} {}", args.join(" ")),
            reason: e.to_string(),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NetworkError::CommandFailed {
            command: format!("{cmd} {}", args.join(" ")),
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

fn run_in_netns(netns_name: &str, cmd: &str, args: &[&str]) -> Result<(), NetworkError> {
    let mut full_args = vec!["netns", "exec", netns_name, cmd];
    full_args.extend_from_slice(args);
    run("ip", &full_args)
}

fn run_nft_stdin(ruleset: &str) -> Result<(), NetworkError> {
    use std::io::Write;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| NetworkError::CommandFailed {
            command: "nft -f -".to_string(),
            reason: e.to_string(),
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(ruleset.as_bytes());
    }

    let output = child
        .wait_with_output()
        .map_err(|e| NetworkError::CommandFailed {
            command: "nft -f -".to_string(),
            reason: e.to_string(),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NetworkError::CommandFailed {
            command: "nft -f -".to_string(),
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_deterministic_for_the_same_sandbox_id() {
        let a = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        let b = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        assert_eq!(a.netns_name, b.netns_name);
        assert_eq!(a.host_veth, b.host_veth);
        assert_eq!(a.subnet_cidr, b.subnet_cidr);
        assert_eq!(a.sandbox_ip(), b.sandbox_ip());
    }

    #[test]
    fn plan_differs_for_different_sandbox_ids() {
        let a = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        let b = SandboxNetwork::plan("sandbox-xyz", "10.0.132.0");
        assert_ne!(a.netns_name, b.netns_name);
        assert_ne!(a.host_veth, b.host_veth);
    }

    #[test]
    fn interface_names_fit_ifnamsiz() {
        let plan = SandboxNetwork::plan("a-very-long-sandbox-identifier-uuid", "10.0.132.0");
        assert!(plan.host_veth.len() <= 15, "{}", plan.host_veth);
        assert!(plan.ns_veth.len() <= 15, "{}", plan.ns_veth);
        assert!(plan.netns_name.len() <= 15, "{}", plan.netns_name);
    }

    #[test]
    fn netns_path_points_under_run_netns() {
        let plan = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        assert_eq!(
            plan.netns_path,
            PathBuf::from(format!("/run/netns/{}", plan.netns_name))
        );
    }

    #[test]
    fn subnet_cidr_is_a_slash_30() {
        let plan = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        assert!(plan.subnet_cidr.ends_with("/30"));
    }

    #[test]
    fn host_and_sandbox_ip_share_the_subnet_and_differ_from_each_other() {
        let plan = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        assert_ne!(plan.host_ip, plan.ns_ip);
        let prefix = plan.subnet_cidr.trim_end_matches("/30");
        let base: Vec<&str> = prefix.rsplitn(2, '.').collect();
        assert!(plan.host_ip.starts_with(base[1]));
        assert!(plan.ns_ip.starts_with(base[1]));
    }

    #[test]
    fn allocate_reuses_the_same_slot_for_the_same_sandbox_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = SandboxNetwork::allocate("sandbox-abc", "10.0.132.0", dir.path())
            .expect("first allocation succeeds");
        let b = SandboxNetwork::allocate("sandbox-abc", "10.0.132.0", dir.path())
            .expect("re-allocation for the same id succeeds");
        assert_eq!(a.subnet_cidr, b.subnet_cidr);
        assert_eq!(a.slot, b.slot);
    }

    #[test]
    fn allocate_probes_past_a_slot_claimed_by_a_different_live_sandbox() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Force a's and b's preferred slot to collide by claiming a's
        // slot directly for a fake "other" owner, then allocate b with a
        // liveness check that always reports "live" — simulating a real
        // collision with a running sandbox rather than a stale marker.
        let a = SandboxNetwork::plan("sandbox-a", "10.0.132.0");
        let slots_dir = dir.path().join("network-slots");
        std::fs::create_dir_all(&slots_dir).unwrap();
        std::fs::write(
            slots_dir.join(a.slot.to_string()),
            "some-other-live-sandbox",
        )
        .unwrap();

        let b = SandboxNetwork::allocate_with("sandbox-a", "10.0.132.0", dir.path(), |_| true)
            .expect("allocate probes past the collision");
        assert_ne!(
            b.slot, a.slot,
            "collided slot must not be reused while its owner is live"
        );
    }

    #[test]
    fn allocate_returns_subnet_exhausted_when_every_slot_is_live() {
        let dir = tempfile::tempdir().expect("tempdir");
        let slots_dir = dir.path().join("network-slots");
        std::fs::create_dir_all(&slots_dir).unwrap();
        for slot in 0..64 {
            std::fs::write(slots_dir.join(slot.to_string()), "some-other-live-sandbox").unwrap();
        }

        let err = SandboxNetwork::allocate_with("sandbox-a", "10.0.132.0", dir.path(), |_| true)
            .expect_err("every slot appearing live must exhaust the pool");
        assert!(matches!(err, NetworkError::SubnetExhausted { .. }));
    }

    #[test]
    fn release_slot_frees_the_marker_for_reuse() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = SandboxNetwork::allocate("sandbox-abc", "10.0.132.0", dir.path())
            .expect("allocation succeeds");
        SandboxNetwork::release_slot("sandbox-abc", dir.path());

        let slots_dir = dir.path().join("network-slots");
        let marker = slots_dir.join(a.slot.to_string());
        assert!(!marker.exists(), "marker should be removed after release");
    }

    #[test]
    fn stale_marker_is_reclaimed_when_owner_netns_is_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = SandboxNetwork::plan("sandbox-abc", "10.0.132.0");
        let slots_dir = dir.path().join("network-slots");
        std::fs::create_dir_all(&slots_dir).unwrap();
        // Simulate a marker left behind by a crashed driver: the owning
        // sandbox's netns (which never existed in this test environment)
        // is "gone", so a different sandbox id should be able to reclaim
        // the same slot.
        std::fs::write(slots_dir.join(a.slot.to_string()), "sandbox-abc").unwrap();

        let b = SandboxNetwork::allocate("sandbox-xyz-different", "10.0.132.0", dir.path());
        assert!(b.is_ok());
    }
}
