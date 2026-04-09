// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Z3 constraint model encoding policy, credentials, and binary capabilities.

use std::collections::{HashMap, HashSet};

use z3::ast::Bool;
use z3::{Context, SatResult, Solver};

use crate::credentials::CredentialSet;
use crate::policy::{PolicyModel, WRITE_METHODS};
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

/// Z3-backed reachability model for an OpenShell sandbox policy.
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
    binary_can_write: HashMap<String, Bool>,
    binary_can_exfil: HashMap<String, Bool>,
    binary_can_construct_http: HashMap<String, Bool>,
    credential_has_write: HashMap<String, Bool>,
    #[allow(dead_code)]
    credential_has_destructive: HashMap<String, Bool>,
    #[allow(dead_code)]
    filesystem_readable: HashMap<String, Bool>,
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
            binary_can_write: HashMap::new(),
            binary_can_exfil: HashMap::new(),
            binary_can_construct_http: HashMap::new(),
            credential_has_write: HashMap::new(),
            credential_has_destructive: HashMap::new(),
            filesystem_readable: HashMap::new(),
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
        self.encode_credentials();
        self.encode_filesystem();
    }

    fn index_endpoints(&mut self) {
        for (policy_name, rule) in &self.policy.network_policies {
            for ep in &rule.endpoints {
                for port in ep.effective_ports() {
                    self.endpoints.push(EndpointId {
                        policy_name: policy_name.clone(),
                        host: ep.host.clone(),
                        port,
                    });
                }
            }
        }
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
        for (policy_name, rule) in &self.policy.network_policies {
            for ep in &rule.endpoints {
                for port in ep.effective_ports() {
                    let eid = EndpointId {
                        policy_name: policy_name.clone(),
                        host: ep.host.clone(),
                        port,
                    };
                    for b in &rule.binaries {
                        let key = format!("{}:{}", b.path, eid.key());
                        let var = Bool::new_const(format!("policy_allows_{key}"));
                        self.solver.assert(&var);
                        self.policy_allows.insert(key, var);
                    }
                }
            }
        }
    }

    fn encode_l7_enforcement(&mut self) {
        for (policy_name, rule) in &self.policy.network_policies {
            for ep in &rule.endpoints {
                for port in ep.effective_ports() {
                    let eid = EndpointId {
                        policy_name: policy_name.clone(),
                        host: ep.host.clone(),
                        port,
                    };
                    let ek = eid.key();

                    // L7 enforced?
                    let l7_var = Bool::new_const(format!("l7_enforced_{ek}"));
                    if ep.is_l7_enforced() {
                        self.solver.assert(&l7_var);
                    } else {
                        self.solver.assert(&!l7_var.clone());
                    }
                    self.l7_enforced.insert(ek.clone(), l7_var);

                    // L7 allows write?
                    let allowed = ep.allowed_methods();
                    let write_set: HashSet<&str> = WRITE_METHODS.iter().copied().collect();
                    let has_write = if allowed.is_empty() {
                        true // L4-only: all methods pass
                    } else {
                        allowed.iter().any(|m| write_set.contains(m.as_str()))
                    };

                    let l7w_var = Bool::new_const(format!("l7_allows_write_{ek}"));
                    if ep.is_l7_enforced() {
                        if has_write {
                            self.solver.assert(&l7w_var);
                        } else {
                            self.solver.assert(&!l7w_var.clone());
                        }
                    } else {
                        // L4-only: all methods pass through
                        self.solver.assert(&l7w_var);
                    }
                    self.l7_allows_write.insert(ek, l7w_var);
                }
            }
        }
    }

    fn encode_binary_capabilities(&mut self) {
        for bpath in &self.binary_paths.clone() {
            let cap = self.binary_registry.get_or_unknown(bpath);

            let bypass_var = Bool::new_const(format!("binary_bypasses_l7_{bpath}"));
            if cap.bypasses_l7() {
                self.solver.assert(&bypass_var);
            } else {
                self.solver.assert(&!bypass_var.clone());
            }
            self.binary_bypasses_l7.insert(bpath.clone(), bypass_var);

            let write_var = Bool::new_const(format!("binary_can_write_{bpath}"));
            if cap.can_write() {
                self.solver.assert(&write_var);
            } else {
                self.solver.assert(&!write_var.clone());
            }
            self.binary_can_write.insert(bpath.clone(), write_var);

            let exfil_var = Bool::new_const(format!("binary_can_exfil_{bpath}"));
            if cap.can_exfiltrate {
                self.solver.assert(&exfil_var);
            } else {
                self.solver.assert(&!exfil_var.clone());
            }
            self.binary_can_exfil.insert(bpath.clone(), exfil_var);

            let http_var = Bool::new_const(format!("binary_can_construct_http_{bpath}"));
            if cap.can_construct_http {
                self.solver.assert(&http_var);
            } else {
                self.solver.assert(&!http_var.clone());
            }
            self.binary_can_construct_http
                .insert(bpath.clone(), http_var);
        }
    }

    fn encode_credentials(&mut self) {
        let hosts: HashSet<String> = self.endpoints.iter().map(|e| e.host.clone()).collect();

        for host in &hosts {
            let creds = self.credentials.credentials_for_host(host);
            let api = self.credentials.api_for_host(host);

            let mut has_write = false;
            let mut has_destructive = false;

            for cred in &creds {
                if let Some(api) = api {
                    if !api.write_actions_for_scopes(&cred.scopes).is_empty() {
                        has_write = true;
                    }
                    if !api.destructive_actions_for_scopes(&cred.scopes).is_empty() {
                        has_destructive = true;
                    }
                } else if !cred.scopes.is_empty() {
                    has_write = true;
                }
            }

            let cw_var = Bool::new_const(format!("credential_has_write_{host}"));
            if has_write {
                self.solver.assert(&cw_var);
            } else {
                self.solver.assert(&!cw_var.clone());
            }
            self.credential_has_write.insert(host.clone(), cw_var);

            let cd_var = Bool::new_const(format!("credential_has_destructive_{host}"));
            if has_destructive {
                self.solver.assert(&cd_var);
            } else {
                self.solver.assert(&!cd_var.clone());
            }
            self.credential_has_destructive.insert(host.clone(), cd_var);
        }
    }

    fn encode_filesystem(&mut self) {
        for path in self.policy.filesystem_policy.readable_paths() {
            let var = Bool::new_const(format!("fs_readable_{path}"));
            self.solver.assert(&var);
            self.filesystem_readable.insert(path, var);
        }
    }

    // --- Query helpers ---

    fn false_val() -> Bool {
        Bool::from_bool(false)
    }

    /// Build a Z3 expression for whether a binary can write to an endpoint.
    pub fn can_write_to_endpoint(&self, bpath: &str, eid: &EndpointId) -> Bool {
        let ek = eid.key();
        let access_key = format!("{bpath}:{ek}");

        let has_access = match self.policy_allows.get(&access_key) {
            Some(v) => v.clone(),
            None => return Self::false_val(),
        };

        let bypass = self
            .binary_bypasses_l7
            .get(bpath)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let l7_enforced = self
            .l7_enforced
            .get(&ek)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let l7_write = self
            .l7_allows_write
            .get(&ek)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let binary_write = self
            .binary_can_write
            .get(bpath)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let cred_write = self
            .credential_has_write
            .get(&eid.host)
            .cloned()
            .unwrap_or_else(Self::false_val);

        Bool::and(&[
            has_access,
            binary_write,
            Bool::or(&[!l7_enforced, l7_write, bypass]),
            cred_write,
        ])
    }

    /// Build a Z3 expression for whether data can be exfiltrated via this path.
    pub fn can_exfil_via_endpoint(&self, bpath: &str, eid: &EndpointId) -> Bool {
        let ek = eid.key();
        let access_key = format!("{bpath}:{ek}");

        let has_access = match self.policy_allows.get(&access_key) {
            Some(v) => v.clone(),
            None => return Self::false_val(),
        };

        let exfil = self
            .binary_can_exfil
            .get(bpath)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let bypass = self
            .binary_bypasses_l7
            .get(bpath)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let l7_enforced = self
            .l7_enforced
            .get(&ek)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let l7_write = self
            .l7_allows_write
            .get(&ek)
            .cloned()
            .unwrap_or_else(Self::false_val);
        let http = self
            .binary_can_construct_http
            .get(bpath)
            .cloned()
            .unwrap_or_else(Self::false_val);

        Bool::and(&[
            has_access,
            exfil,
            Bool::or(&[
                Bool::and(&[!l7_enforced.clone(), http.clone()]),
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
