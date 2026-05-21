// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Z3 constraint model encoding policy, credentials, and binary capabilities.

use std::collections::{HashMap, HashSet};

use z3::ast::Bool;
use z3::{Context, SatResult, Solver};

use crate::credentials::CredentialSet;
use crate::policy::{PolicyModel, WRITE_METHODS};

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

    // Indexed facts
    pub endpoints: Vec<EndpointId>,

    // Z3 solver
    solver: Solver,

    // Boolean variable maps
    l7_enforced: HashMap<String, Bool>,
    l7_allows_write: HashMap<String, Bool>,
    credential_has_write: HashMap<String, Bool>,
    #[allow(dead_code)]
    credential_has_destructive: HashMap<String, Bool>,
    #[allow(dead_code)]
    filesystem_readable: HashMap<String, Bool>,
}

impl ReachabilityModel {
    /// Build a new reachability model from the given inputs.
    pub fn new(policy: PolicyModel, credentials: CredentialSet) -> Self {
        let solver = Solver::new();
        let mut model = Self {
            policy,
            credentials,
            endpoints: Vec::new(),
            solver,
            l7_enforced: HashMap::new(),
            l7_allows_write: HashMap::new(),
            credential_has_write: HashMap::new(),
            credential_has_destructive: HashMap::new(),
            filesystem_readable: HashMap::new(),
        };
        model.build();
        model
    }

    fn build(&mut self) {
        self.index_endpoints();
        self.encode_l7_enforcement();
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

                    let l7_write_var = Bool::new_const(format!("l7_allows_write_{ek}"));
                    if ep.is_l7_enforced() {
                        if has_write {
                            self.solver.assert(&l7_write_var);
                        } else {
                            self.solver.assert(&!l7_write_var.clone());
                        }
                    } else {
                        // L4-only: all methods pass through
                        self.solver.assert(&l7_write_var);
                    }
                    self.l7_allows_write.insert(ek, l7_write_var);
                }
            }
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

            let destructive_var = Bool::new_const(format!("credential_has_destructive_{host}"));
            if has_destructive {
                self.solver.assert(&destructive_var);
            } else {
                self.solver.assert(&!destructive_var.clone());
            }
            self.credential_has_destructive
                .insert(host.clone(), destructive_var);
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

    /// Build a Z3 expression for whether an endpoint allows write operations.
    pub fn endpoint_allows_write(&self, eid: &EndpointId) -> Bool {
        let ek = eid.key();

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
        let cred_write = self
            .credential_has_write
            .get(&eid.host)
            .cloned()
            .unwrap_or_else(Self::false_val);

        Bool::and(&[Bool::or(&[!l7_enforced, l7_write]), cred_write])
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
pub fn build_model(policy: PolicyModel, credentials: CredentialSet) -> ReachabilityModel {
    // Ensure the thread-local Z3 context is initialized
    let _ctx = Context::thread_local();
    ReachabilityModel::new(policy, credentials)
}
