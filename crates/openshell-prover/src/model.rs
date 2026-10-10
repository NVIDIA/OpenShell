// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Z3 constraint model encoding network policy reachability and binary
//! capabilities.

use std::collections::{HashMap, HashSet};

use z3::ast::Bool;
use z3::{Context, SatResult, Solver};

use crate::credentials::CredentialSet;
use crate::policy::{Endpoint, NetworkPolicyRule, PolicyModel, WRITE_METHODS};
use crate::registry::BinaryRegistry;

/// Unique identifier for a network endpoint in the model.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EndpointId {
    pub policy_name: String,
    pub host: String,
    pub port: u16,
}

impl EndpointId {
    /// Stable string key used for Z3 variable naming.
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.policy_name, self.host, self.port)
    }
}

/// Z3-backed reachability model for an `OpenShell` sandbox policy.
pub struct ReachabilityModel {
    pub policy: PolicyModel,
    pub credentials: CredentialSet,
    pub binary_registry: BinaryRegistry,

    // Indexed facts
    pub endpoints: Vec<EndpointId>,
    pub binary_paths: Vec<String>,

    // Z3 solver
    solver: Solver,

    // Boolean variable maps
    policy_allows: HashMap<String, Bool>,
    l7_enforced: HashMap<String, Bool>,
    l7_allows_write: HashMap<String, Bool>,
    binary_bypasses_l7: HashMap<String, Bool>,
    binary_can_exfil: HashMap<String, Bool>,
    binary_can_construct_http: HashMap<String, Bool>,
}

impl ReachabilityModel {
    /// Build a new reachability model from the given inputs.
    pub fn new(
        policy: PolicyModel,
        credentials: CredentialSet,
        binary_registry: BinaryRegistry,
    ) -> Self {
        let solver = Solver::new();
        let mut model = Self {
            policy,
            credentials,
            binary_registry,
            endpoints: Vec::new(),
            binary_paths: Vec::new(),
            solver,
            policy_allows: HashMap::new(),
            l7_enforced: HashMap::new(),
            l7_allows_write: HashMap::new(),
            binary_bypasses_l7: HashMap::new(),
            binary_can_exfil: HashMap::new(),
            binary_can_construct_http: HashMap::new(),
        };
        model.build();
        model
    }

    fn build(&mut self) {
        self.index_endpoints();
        self.index_binaries();
        self.encode_policy_allows();
        self.encode_l7_enforcement();
        self.encode_binary_capabilities();
    }

    /// Declare a Bool constant named `name` and pin it to `value`.
    fn fixed_bool(&self, name: String, value: bool) -> Bool {
        let var = Bool::new_const(name);
        if value {
            self.solver.assert(&var);
        } else {
            self.solver.assert(&!var.clone());
        }
        var
    }

    fn index_endpoints(&mut self) {
        self.endpoints = endpoint_ports(&self.policy)
            .map(|(eid, _, _)| eid)
            .collect();
    }

    fn index_binaries(&mut self) {
        let mut seen = HashSet::new();
        for rule in self.policy.network_policies.values() {
            for b in &rule.binaries {
                if seen.insert(b.path.clone()) {
                    self.binary_paths.push(b.path.clone());
                }
            }
        }
    }

    fn encode_policy_allows(&mut self) {
        for (eid, _, rule) in endpoint_ports(&self.policy) {
            for b in &rule.binaries {
                let key = format!("{}:{}", b.path, eid.key());
                let var = self.fixed_bool(format!("policy_allows_{key}"), true);
                self.policy_allows.insert(key, var);
            }
        }
    }

    fn encode_l7_enforcement(&mut self) {
        let write_set: HashSet<&str> = WRITE_METHODS.iter().copied().collect();
        for (eid, ep, _) in endpoint_ports(&self.policy) {
            let ek = eid.key();

            let enforced = ep.is_l7_enforced();
            let l7_var = self.fixed_bool(format!("l7_enforced_{ek}"), enforced);
            self.l7_enforced.insert(ek.clone(), l7_var);

            // L4-only endpoints (and empty method sets) let every method pass.
            let allowed = ep.allowed_methods();
            let allows_write = !enforced
                || allowed.is_empty()
                || allowed.iter().any(|m| write_set.contains(m.as_str()));
            let l7_write_var = self.fixed_bool(format!("l7_allows_write_{ek}"), allows_write);
            self.l7_allows_write.insert(ek, l7_write_var);
        }
    }

    fn encode_binary_capabilities(&mut self) {
        for bpath in &self.binary_paths.clone() {
            let cap = self.binary_registry.get_or_unknown(bpath);

            let bypass_var =
                self.fixed_bool(format!("binary_bypasses_l7_{bpath}"), cap.bypasses_l7());
            self.binary_bypasses_l7.insert(bpath.clone(), bypass_var);

            let exfil_var =
                self.fixed_bool(format!("binary_can_exfil_{bpath}"), cap.can_exfiltrate);
            self.binary_can_exfil.insert(bpath.clone(), exfil_var);

            let http_var = self.fixed_bool(
                format!("binary_can_construct_http_{bpath}"),
                cap.can_construct_http,
            );
            self.binary_can_construct_http
                .insert(bpath.clone(), http_var);
        }
    }

    // --- Query helpers ---

    fn false_val() -> Bool {
        Bool::from_bool(false)
    }

    /// Look up a model variable, treating a missing entry as `false`.
    fn lookup(vars: &HashMap<String, Bool>, key: &str) -> Bool {
        vars.get(key).cloned().unwrap_or_else(Self::false_val)
    }

    /// Build a Z3 expression for whether data can be exfiltrated via this path.
    pub fn can_exfil_via_endpoint(&self, bpath: &str, eid: &EndpointId) -> Bool {
        let ek = eid.key();
        let access_key = format!("{bpath}:{ek}");

        let has_access = match self.policy_allows.get(&access_key) {
            Some(v) => v.clone(),
            None => return Self::false_val(),
        };

        let exfil = Self::lookup(&self.binary_can_exfil, bpath);
        let bypass = Self::lookup(&self.binary_bypasses_l7, bpath);
        let l7_enforced = Self::lookup(&self.l7_enforced, &ek);
        let l7_write = Self::lookup(&self.l7_allows_write, &ek);
        let http = Self::lookup(&self.binary_can_construct_http, bpath);

        Bool::and(&[
            has_access,
            exfil,
            Bool::or(&[
                Bool::and(&[!l7_enforced, http.clone()]),
                Bool::and(&[l7_write, http]),
                bypass,
            ]),
        ])
    }

    /// Check satisfiability of an expression against the base constraints.
    pub fn check_sat(&self, expr: &Bool) -> SatResult {
        self.solver.push();
        self.solver.assert(expr);
        let result = self.solver.check();
        self.solver.pop(1);
        result
    }
}

/// Every `(endpoint id, endpoint, owning rule)` in the policy, one per
/// effective port.
fn endpoint_ports(
    policy: &PolicyModel,
) -> impl Iterator<Item = (EndpointId, &Endpoint, &NetworkPolicyRule)> {
    policy
        .network_policies
        .iter()
        .flat_map(|(policy_name, rule)| {
            rule.endpoints.iter().flat_map(move |ep| {
                ep.effective_ports().into_iter().map(move |port| {
                    let eid = EndpointId {
                        policy_name: policy_name.clone(),
                        host: ep.host.clone(),
                        port,
                    };
                    (eid, ep, rule)
                })
            })
        })
}

/// Build a reachability model from the given inputs.
pub fn build_model(
    policy: PolicyModel,
    credentials: CredentialSet,
    binary_registry: BinaryRegistry,
) -> ReachabilityModel {
    // Ensure the thread-local Z3 context is initialized
    let _ctx = Context::thread_local();
    ReachabilityModel::new(policy, credentials, binary_registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy_str;
    use crate::registry::load_embedded_binary_registry;

    const CURL: &str = "/usr/bin/curl";
    const SSH: &str = "/usr/bin/ssh";

    fn can_exfil(model: &ReachabilityModel, binary: &str, host: &str) -> bool {
        let eid = model
            .endpoints
            .iter()
            .find(|e| e.host == host)
            .expect("endpoint");
        model.check_sat(&model.can_exfil_via_endpoint(binary, eid)) == SatResult::Sat
    }

    #[test]
    fn exfil_reach_follows_policy_l7_and_binary_capabilities() {
        let policy = parse_policy_str(
            r"
version: 1
network_policies:
  l4:
    name: l4
    endpoints:
      - host: l4.example.com
        port: 443
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/ssh
  read_only:
    name: read-only
    endpoints:
      - host: ro.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/ssh
  read_write:
    name: read-write
    endpoints:
      - host: rw.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
    binaries:
      - path: /usr/bin/curl
  ssh_only:
    name: ssh-only
    endpoints:
      - host: ssh.example.com
        port: 22
    binaries:
      - path: /usr/bin/ssh
",
        )
        .expect("parse policy");
        let registry = load_embedded_binary_registry().expect("load registry");
        let model = build_model(policy, CredentialSet::default(), registry);

        for (binary, host, expected) in [
            // L4 endpoint: curl builds HTTP, ssh bypasses L7.
            (CURL, "l4.example.com", true),
            (SSH, "l4.example.com", true),
            // L7 read-only blocks curl writes; ssh still bypasses L7.
            (CURL, "ro.example.com", false),
            (SSH, "ro.example.com", true),
            // L7 read-write lets curl write.
            (CURL, "rw.example.com", true),
            // curl has no policy access to this endpoint.
            (CURL, "ssh.example.com", false),
        ] {
            assert_eq!(
                can_exfil(&model, binary, host),
                expected,
                "{binary} -> {host}"
            );
        }
    }
}
