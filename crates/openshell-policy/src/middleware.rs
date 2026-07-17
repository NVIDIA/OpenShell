// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML schema and protobuf conversion for supervisor middleware policies.

use std::collections::{BTreeMap, HashMap};

use openshell_core::middleware::{MAX_MIDDLEWARE_CONFIGS, MAX_MIDDLEWARE_SELECTOR_PATTERNS};
use openshell_core::proto::{
    MiddlewareEndpointSelector, NetworkEndpoint, NetworkMiddlewareConfig, NetworkPolicyRule,
    SandboxPolicy,
};
use openshell_core::proto_struct::{
    ProtoStructError, json_object_to_struct, struct_to_json_object,
};
use serde::{Deserialize, Serialize};

use super::PolicyViolation;

pub use openshell_core::host_pattern::host_matches as middleware_host_matches;
use openshell_core::host_pattern::{HostPattern, HostSelector};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMiddlewareConfigDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    middleware: String,
    #[serde(default, skip_serializing_if = "is_default")]
    order: i32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    config: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    on_error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoints: Option<MiddlewareEndpointSelectorDef>,
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiddlewareEndpointSelectorDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<String>,
}

/// Middleware-relevant projection of the runtime policy JSON accepted by the
/// supervisor's local-file mode. Unrelated network and L7 fields are ignored;
/// middleware entries retain their strict canonical schema.
#[derive(Debug, Default, Deserialize)]
struct MiddlewareValidationPolicyDef {
    #[serde(default)]
    network_middlewares: BTreeMap<String, NetworkMiddlewareConfigDef>,
    #[serde(default)]
    network_policies: BTreeMap<String, MiddlewareValidationNetworkPolicyDef>,
}

#[derive(Debug, Default, Deserialize)]
struct MiddlewareValidationNetworkPolicyDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoints: Vec<MiddlewareValidationEndpointDef>,
}

#[derive(Debug, Default, Deserialize)]
struct MiddlewareValidationEndpointDef {
    #[serde(default)]
    host: String,
    #[serde(default)]
    tls: String,
}

pub fn into_proto(
    definitions: BTreeMap<String, NetworkMiddlewareConfigDef>,
) -> Result<HashMap<String, NetworkMiddlewareConfig>, ProtoStructError> {
    definitions
        .into_iter()
        .map(|(key, definition)| {
            Ok((
                key.clone(),
                NetworkMiddlewareConfig {
                    name: if definition.name.is_empty() {
                        key
                    } else {
                        definition.name
                    },
                    middleware: definition.middleware,
                    order: definition.order,
                    config: Some(json_object_to_struct(
                        definition.config.into_iter().collect(),
                    )?),
                    on_error: definition.on_error,
                    endpoints: definition
                        .endpoints
                        .map(|selector| MiddlewareEndpointSelector {
                            include: selector.include,
                            exclude: selector.exclude,
                        }),
                },
            ))
        })
        .collect()
}

pub fn from_proto(
    middlewares: &HashMap<String, NetworkMiddlewareConfig>,
) -> BTreeMap<String, NetworkMiddlewareConfigDef> {
    middlewares
        .iter()
        .map(|(name, middleware)| {
            (
                name.clone(),
                NetworkMiddlewareConfigDef {
                    name: middleware.name.clone(),
                    middleware: middleware.middleware.clone(),
                    order: middleware.order,
                    config: middleware
                        .config
                        .as_ref()
                        .map(struct_to_json_object)
                        .unwrap_or_default()
                        .into_iter()
                        .collect(),
                    on_error: middleware.on_error.clone(),
                    endpoints: middleware.endpoints.as_ref().map(|selector| {
                        MiddlewareEndpointSelectorDef {
                            include: selector.include.clone(),
                            exclude: selector.exclude.clone(),
                        }
                    }),
                },
            )
        })
        .collect()
}

/// Validate middleware configuration from the supervisor's runtime policy
/// JSON through the same typed validator used for protobuf policies.
pub fn validate_json(data: &serde_json::Value) -> Result<Vec<PolicyViolation>, String> {
    validate_json_with_config(data, |_implementation, _config| Ok(()))
}

/// Validate middleware policy structure and delegate implementation-owned
/// configuration to the supplied registry or catalog.
pub fn validate_json_with_config<F>(
    data: &serde_json::Value,
    validate_config: F,
) -> Result<Vec<PolicyViolation>, String>
where
    F: Fn(&str, &prost_types::Struct) -> Result<(), String>,
{
    let definition: MiddlewareValidationPolicyDef = serde_json::from_value(data.clone())
        .map_err(|error| format!("failed to parse network middleware policy: {error}"))?;
    let network_middlewares = into_proto(definition.network_middlewares)
        .map_err(|error| format!("failed to convert network middleware config: {error}"))?;
    let network_policies = definition
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let rule = NetworkPolicyRule {
                name: rule.name,
                endpoints: rule
                    .endpoints
                    .into_iter()
                    .map(|endpoint| NetworkEndpoint {
                        host: endpoint.host,
                        tls: endpoint.tls,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            (key, rule)
        })
        .collect();
    let policy = SandboxPolicy {
        network_middlewares,
        network_policies,
        ..Default::default()
    };
    let mut violations = validate(&policy);
    if policy.network_middlewares.len() <= MAX_MIDDLEWARE_CONFIGS {
        for (name, middleware) in &policy.network_middlewares {
            let config = middleware.config.clone().unwrap_or_default();
            if let Err(reason) = validate_config(&middleware.middleware, &config) {
                violations.push(PolicyViolation::InvalidMiddlewareConfig {
                    name: name.clone(),
                    reason,
                });
            }
        }
    }
    Ok(violations)
}

pub fn validate(policy: &SandboxPolicy) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    let mut orders = BTreeMap::new();
    if policy.network_middlewares.len() > MAX_MIDDLEWARE_CONFIGS {
        violations.push(PolicyViolation::TooManyMiddlewareConfigs {
            count: policy.network_middlewares.len(),
        });
    }

    let mut middlewares: Vec<_> = policy.network_middlewares.iter().collect();
    middlewares.sort_by_key(|(name, _)| name.as_str());
    for (name, middleware) in middlewares {
        if name.is_empty() {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: name.clone(),
                reason: "name must not be empty".to_string(),
            });
        }

        if let Some(first_name) = orders.insert(middleware.order, name.clone()) {
            violations.push(PolicyViolation::DuplicateMiddlewareOrder {
                order: middleware.order,
                first_name,
                second_name: name.clone(),
            });
        }

        if middleware.middleware.is_empty() {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: name.clone(),
                reason: "middleware must not be empty".to_string(),
            });
        }

        if !matches!(
            middleware.on_error.as_str(),
            "" | "fail_closed" | "fail_open"
        ) {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: name.clone(),
                reason: format!("invalid on_error '{}'", middleware.on_error),
            });
        }

        let Some(selector) = &middleware.endpoints else {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: name.clone(),
                reason: "endpoint selector is required".to_string(),
            });
            continue;
        };
        if selector.include.is_empty() {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: name.clone(),
                reason: "endpoint selector must include at least one host pattern".to_string(),
            });
        }
        let selector_patterns = selector
            .include
            .len()
            .saturating_add(selector.exclude.len());
        if selector_patterns > MAX_MIDDLEWARE_SELECTOR_PATTERNS {
            violations.push(PolicyViolation::TooManyMiddlewareSelectorPatterns {
                name: name.clone(),
                count: selector_patterns,
            });
            continue;
        }
        let mut selector_valid = !selector.include.is_empty();
        for pattern in selector.include.iter().chain(&selector.exclude) {
            if let Err(reason) = HostPattern::new(pattern) {
                selector_valid = false;
                violations.push(PolicyViolation::InvalidMiddlewareConfig {
                    name: name.clone(),
                    reason: format!("endpoint selector pattern '{pattern}' is invalid: {reason}"),
                });
            }
        }
        let compiled_selector = if selector_valid {
            HostSelector::new(&selector.include, &selector.exclude).ok()
        } else {
            None
        };

        let requires_inspection = matches!(middleware.on_error.as_str(), "" | "fail_closed");
        for (key, rule) in &policy.network_policies {
            let policy_name = if rule.name.is_empty() {
                key
            } else {
                &rule.name
            };
            for endpoint in &rule.endpoints {
                let overlaps_tls_skip = requires_inspection
                    && endpoint.tls == "skip"
                    && compiled_selector.as_ref().is_some_and(|selector| {
                        HostPattern::new(&endpoint.host)
                            .is_ok_and(|endpoint| selector.may_match_pattern(&endpoint))
                    });
                if overlaps_tls_skip {
                    violations.push(PolicyViolation::MiddlewareTlsSkipConflict {
                        middleware_name: name.clone(),
                        policy_name: policy_name.clone(),
                        host: endpoint.host.clone(),
                    });
                }
            }
        }
    }

    violations
}
