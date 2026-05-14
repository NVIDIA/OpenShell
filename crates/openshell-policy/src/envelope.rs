// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-task envelope policy and composition with the baseline `SandboxPolicy`.
//!
//! An [`EnvelopePolicy`] is a per-task constraint surface authored by the
//! gateway/orchestrator on top of the operator-controlled baseline
//! [`SandboxPolicy`]. The resulting [`EffectiveEnvelope`] is the
//! most-restrictive intersection of the two: an envelope can only ever
//! *narrow* what the baseline allows, never broaden it.
//!
//! See `rfc/0004-aegis-governance` §"Policy composition" and §"Wire shape".
//
// TODO(aegis-proto): once the `EnvelopePolicy` proto message lands (tracked by
// the proto-aegis task), re-export the prost-generated type from here instead
// of carrying a duplicate definition.

use std::collections::BTreeSet;

use openshell_core::proto::SandboxPolicy;
use serde::{Deserialize, Serialize};

/// Per-task envelope policy.
///
/// Field shape mirrors the planned `EnvelopePolicy` proto message. All fields
/// are optional in spirit: empty vectors mean "no constraint contributed by
/// the envelope on this axis" only for `denied_paths`; for the path allow
/// lists an empty vector means "envelope grants nothing on this axis", which
/// is the most-restrictive floor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopePolicy {
    /// Paths the task may read and write.
    pub readwrite_paths: Vec<String>,
    /// Paths the task may read.
    pub readonly_paths: Vec<String>,
    /// Paths the task must not access. Unioned with the baseline's deny list.
    pub denied_paths: Vec<String>,
    /// Whether the task may use the network at all.
    pub network_enabled: bool,
    /// Whether the task may reach loopback / link-local destinations.
    pub allow_local_network: bool,
    /// Maximum task wall-clock time in milliseconds. `0` means "unlimited".
    pub timeout_ms: u32,
    /// Named sandbox profile (capability bundle) requested by the task. Empty
    /// string means "no profile pinned by the envelope".
    pub sandbox_profile: String,
}

/// The result of composing an [`EnvelopePolicy`] against a [`SandboxPolicy`].
///
/// Returned by [`compose`]. This is a separate type from [`EnvelopePolicy`] so
/// that composition is type-safe: an effective envelope cannot accidentally be
/// fed back into composition as if it were a fresh per-task envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEnvelope {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub network_enabled: bool,
    pub allow_local_network: bool,
    pub timeout_ms: u32,
    pub sandbox_profile: String,
}

/// Compose a baseline [`SandboxPolicy`] with a per-task [`EnvelopePolicy`],
/// producing the most-restrictive intersection.
///
/// Composition rules (see RFC 0004 §"Policy composition"):
///
/// * `readwrite_paths` = `envelope.readwrite_paths` ∩
///   `baseline.filesystem.read_write`
/// * `readonly_paths` = (`envelope.readonly_paths` ∪
///   `envelope.readwrite_paths`) ∩ `baseline.filesystem.read_only`
/// * `denied_paths` = `envelope.denied_paths` ∪ baseline deny list
/// * `network_enabled` = `envelope.network_enabled` ∧ `baseline_allows_network`
/// * `allow_local_network` = `envelope.allow_local_network` ∧
///   `baseline_allows_local_network`
/// * `timeout_ms` = `min(envelope.timeout_ms, baseline.max_timeout_ms)` where
///   `0` is treated as "unlimited"; the result is `0` only when both inputs
///   are `0`.
/// * `sandbox_profile`: the envelope must request the same profile the
///   baseline pins, or the empty string. Otherwise the envelope is rejected
///   by clearing the field — callers should treat an empty profile in the
///   effective envelope as "no capability bundle granted".
///
/// Outputs are deterministic: path vectors are sorted and deduplicated.
#[must_use]
pub fn compose(baseline: &SandboxPolicy, envelope: &EnvelopePolicy) -> EffectiveEnvelope {
    // Baseline filesystem allow lists. The proto `SandboxPolicy` carries
    // these inside the optional `filesystem` submessage with field names
    // `read_write` / `read_only`. They are the closest equivalents to the
    // RFC's `allowed_writable_paths` / `allowed_readable_paths`.
    let baseline_rw: BTreeSet<&str> = baseline
        .filesystem
        .as_ref()
        .map(|fs| fs.read_write.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let baseline_ro: BTreeSet<&str> = baseline
        .filesystem
        .as_ref()
        .map(|fs| fs.read_only.iter().map(String::as_str).collect())
        .unwrap_or_default();

    // TODO(aegis-baseline): the current `SandboxPolicy` proto has no explicit
    // `denied_paths` field. Treat the baseline contribution to the deny list
    // as empty until the proto grows one (tracked in RFC 0004).
    let baseline_denied: BTreeSet<&str> = BTreeSet::new();

    // Intersect envelope read-write against baseline read-write.
    let env_rw: BTreeSet<&str> = envelope.readwrite_paths.iter().map(String::as_str).collect();
    let readwrite_paths = sorted_intersection(&env_rw, &baseline_rw);

    // Read-only effective set: union envelope ro + envelope rw, intersect
    // with baseline ro. Anything the envelope wants writable must also be at
    // least readable on the baseline — but we surface that requirement via
    // the read-only allow list, not by hoisting writable entries into it.
    let mut env_ro_union: BTreeSet<&str> =
        envelope.readonly_paths.iter().map(String::as_str).collect();
    env_ro_union.extend(envelope.readwrite_paths.iter().map(String::as_str));
    let readonly_paths = sorted_intersection(&env_ro_union, &baseline_ro);

    // Denied paths are a union — anything either side denies stays denied.
    let mut denied_set: BTreeSet<&str> =
        envelope.denied_paths.iter().map(String::as_str).collect();
    denied_set.extend(baseline_denied.iter().copied());
    let denied_paths: Vec<String> = denied_set.into_iter().map(str::to_owned).collect();

    // TODO(aegis-baseline): the current `SandboxPolicy` proto has no explicit
    // `allows_network` flag. Approximate it as "baseline grants network iff
    // it ships at least one network policy rule"; an empty `network_policies`
    // map is interpreted as "no network allowed" (matches
    // `restrictive_default_policy()`).
    let baseline_allows_network = !baseline.network_policies.is_empty();
    let network_enabled = envelope.network_enabled && baseline_allows_network;

    // TODO(aegis-baseline): the current `SandboxPolicy` proto has no explicit
    // `allows_local_network` flag. Default the baseline contribution to
    // `true` (most-permissive on this axis) so the envelope's value wins
    // until the baseline can actually constrain it.
    let baseline_allows_local_network = true;
    let allow_local_network = envelope.allow_local_network && baseline_allows_local_network;

    // TODO(aegis-baseline): the current `SandboxPolicy` proto has no explicit
    // `max_timeout_ms`. Default the baseline contribution to `0` (unlimited);
    // the envelope's timeout will dominate until the proto grows one.
    let baseline_max_timeout_ms: u32 = 0;
    let timeout_ms = min_timeout(envelope.timeout_ms, baseline_max_timeout_ms);

    // TODO(aegis-baseline): the current `SandboxPolicy` proto has no explicit
    // `sandbox_profile` pin. Default the baseline contribution to `""` (no
    // pin) so any envelope-requested profile passes through. When the proto
    // gains a pinned profile, `sandbox_profile` becomes: empty if the
    // envelope's request differs from the pin and is non-empty; otherwise
    // the envelope's value.
    let baseline_sandbox_profile: &str = "";
    let sandbox_profile = compose_profile(&envelope.sandbox_profile, baseline_sandbox_profile);

    EffectiveEnvelope {
        readwrite_paths,
        readonly_paths,
        denied_paths,
        network_enabled,
        allow_local_network,
        timeout_ms,
        sandbox_profile,
    }
}

fn sorted_intersection(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> Vec<String> {
    a.intersection(b).map(|s| (*s).to_owned()).collect()
}

fn min_timeout(envelope_ms: u32, baseline_ms: u32) -> u32 {
    match (envelope_ms, baseline_ms) {
        (0, 0) => 0,
        (0, b) => b,
        (e, 0) => e,
        (e, b) => e.min(b),
    }
}

fn compose_profile(envelope_profile: &str, baseline_profile: &str) -> String {
    if baseline_profile.is_empty() {
        envelope_profile.to_owned()
    } else if envelope_profile.is_empty() || envelope_profile == baseline_profile {
        baseline_profile.to_owned()
    } else {
        // Envelope asks for a different profile than the baseline pins —
        // reject by yielding "no profile granted".
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openshell_core::proto::{
        FilesystemPolicy, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
    };

    use super::*;

    fn baseline_with_fs(read_only: Vec<&str>, read_write: Vec<&str>) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                read_only: read_only.into_iter().map(str::to_owned).collect(),
                read_write: read_write.into_iter().map(str::to_owned).collect(),
            }),
            landlock: None,
            process: None,
            network_policies: HashMap::new(),
        }
    }

    fn baseline_with_network() -> SandboxPolicy {
        let mut policy = baseline_with_fs(vec!["/usr"], vec!["/tmp"]);
        policy.network_policies.insert(
            "allow_all".to_owned(),
            NetworkPolicyRule {
                name: "allow_all".to_owned(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".to_owned(),
                    port: 443,
                    ..NetworkEndpoint::default()
                }],
                binaries: vec![],
            },
        );
        policy
    }

    #[test]
    fn empty_envelope_against_permissive_baseline_is_fully_restrictive() {
        let baseline = baseline_with_fs(
            vec!["/usr", "/etc", "/var/log"],
            vec!["/tmp", "/sandbox"],
        );
        let envelope = EnvelopePolicy::default();

        let effective = compose(&baseline, &envelope);

        assert!(effective.readwrite_paths.is_empty());
        assert!(effective.readonly_paths.is_empty());
        assert!(effective.denied_paths.is_empty());
        assert!(!effective.network_enabled);
        assert!(!effective.allow_local_network);
        assert_eq!(effective.timeout_ms, 0);
        assert!(effective.sandbox_profile.is_empty());
    }

    #[test]
    fn envelope_writable_path_not_in_baseline_is_excluded() {
        let baseline = baseline_with_fs(vec!["/usr"], vec!["/tmp"]);
        let envelope = EnvelopePolicy {
            readwrite_paths: vec!["/tmp".to_owned(), "/forbidden".to_owned()],
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);

        assert_eq!(effective.readwrite_paths, vec!["/tmp".to_owned()]);
        assert!(!effective.readwrite_paths.contains(&"/forbidden".to_owned()));
    }

    #[test]
    fn denied_paths_are_unioned_with_baseline() {
        // Baseline currently contributes no deny entries (see compose() TODO),
        // so the union is exactly the envelope's deny list — but the result
        // must still be sorted + deduped.
        let baseline = baseline_with_fs(vec![], vec![]);
        let envelope = EnvelopePolicy {
            denied_paths: vec![
                "/secrets".to_owned(),
                "/etc/shadow".to_owned(),
                "/secrets".to_owned(),
            ],
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);

        assert_eq!(
            effective.denied_paths,
            vec!["/etc/shadow".to_owned(), "/secrets".to_owned()],
        );
    }

    #[test]
    fn envelope_wants_network_but_baseline_blocks_it() {
        let baseline = baseline_with_fs(vec![], vec![]); // no network_policies
        let envelope = EnvelopePolicy {
            network_enabled: true,
            allow_local_network: true,
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);

        assert!(!effective.network_enabled);
        // allow_local_network currently passes through (see TODO in compose()).
        assert!(effective.allow_local_network);
    }

    #[test]
    fn envelope_and_baseline_both_allow_network() {
        let baseline = baseline_with_network();
        let envelope = EnvelopePolicy {
            network_enabled: true,
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);

        assert!(effective.network_enabled);
    }

    #[test]
    fn timeout_min_selection_when_both_nonzero() {
        assert_eq!(min_timeout(5_000, 10_000), 5_000);
        assert_eq!(min_timeout(10_000, 5_000), 5_000);
    }

    #[test]
    fn timeout_zero_is_unlimited() {
        assert_eq!(min_timeout(0, 0), 0);
        assert_eq!(min_timeout(0, 7_500), 7_500);
        assert_eq!(min_timeout(7_500, 0), 7_500);
    }

    #[test]
    fn readonly_includes_envelope_writable_when_baseline_allows_reading_it() {
        let baseline = baseline_with_fs(vec!["/usr", "/tmp"], vec!["/tmp"]);
        let envelope = EnvelopePolicy {
            readwrite_paths: vec!["/tmp".to_owned()],
            readonly_paths: vec!["/usr".to_owned()],
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);

        assert_eq!(effective.readwrite_paths, vec!["/tmp".to_owned()]);
        assert_eq!(
            effective.readonly_paths,
            vec!["/tmp".to_owned(), "/usr".to_owned()],
        );
    }

    #[test]
    fn outputs_are_sorted_and_deduplicated() {
        let baseline = baseline_with_fs(
            vec!["/a", "/b", "/c"],
            vec!["/x", "/y", "/z"],
        );
        let envelope = EnvelopePolicy {
            readwrite_paths: vec!["/z".to_owned(), "/x".to_owned(), "/x".to_owned()],
            readonly_paths: vec!["/c".to_owned(), "/a".to_owned()],
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);

        assert_eq!(effective.readwrite_paths, vec!["/x".to_owned(), "/z".to_owned()]);
        // readonly = (envelope.readonly ∪ envelope.readwrite) ∩ baseline.read_only
        // baseline.read_only is {/a,/b,/c}, so the intersection is {/a,/c}.
        assert_eq!(effective.readonly_paths, vec!["/a".to_owned(), "/c".to_owned()]);
    }

    #[test]
    fn compose_is_deterministic() {
        let baseline = baseline_with_fs(vec!["/a", "/b"], vec!["/x", "/y"]);
        let envelope = EnvelopePolicy {
            readwrite_paths: vec!["/y".to_owned(), "/x".to_owned()],
            readonly_paths: vec!["/b".to_owned(), "/a".to_owned()],
            denied_paths: vec!["/two".to_owned(), "/one".to_owned()],
            ..EnvelopePolicy::default()
        };

        let first = compose(&baseline, &envelope);
        let second = compose(&baseline, &envelope);
        assert_eq!(first, second);
    }

    #[test]
    fn sandbox_profile_passes_through_when_baseline_unpinned() {
        let baseline = baseline_with_fs(vec![], vec![]);
        let envelope = EnvelopePolicy {
            sandbox_profile: "minimal".to_owned(),
            ..EnvelopePolicy::default()
        };

        let effective = compose(&baseline, &envelope);
        assert_eq!(effective.sandbox_profile, "minimal");
    }

    #[test]
    fn compose_profile_helper() {
        // Baseline unpinned -> envelope wins.
        assert_eq!(compose_profile("minimal", ""), "minimal");
        assert_eq!(compose_profile("", ""), "");
        // Baseline pinned, envelope empty -> baseline wins.
        assert_eq!(compose_profile("", "strict"), "strict");
        // Baseline pinned, envelope agrees -> baseline.
        assert_eq!(compose_profile("strict", "strict"), "strict");
        // Baseline pinned, envelope disagrees -> rejected.
        assert_eq!(compose_profile("loose", "strict"), "");
    }
}
