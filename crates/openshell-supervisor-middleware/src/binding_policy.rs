// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use miette::{Result, miette};
use openshell_core::proto::{
    MiddlewareBinding, SupervisorMiddlewareBinding as Binding,
    SupervisorMiddlewareBindingPolicy as Policy, SupervisorMiddlewareService,
};

/// A validated operator policy. The gateway sends the same policy to the
/// supervisor, which authorizes its own Describe rather than trusting the
/// service to advertise the same bindings to both callers.
pub enum BindingPolicy {
    Dynamic,
    Allowlist(BTreeSet<Binding>),
    Exact(BTreeSet<Binding>),
}

impl TryFrom<&SupervisorMiddlewareService> for BindingPolicy {
    type Error = miette::Report;

    fn try_from(service: &SupervisorMiddlewareService) -> Result<Self> {
        let name = &service.name;
        let policy = Policy::try_from(service.binding_policy)
            .map_err(|_| miette!("middleware '{name}' has unknown binding_policy"))?;
        let mut bindings = BTreeSet::new();
        for &value in &service.bindings {
            let binding = Binding::try_from(value)
                .ok()
                .filter(|binding| *binding != Binding::Unspecified)
                .ok_or_else(|| miette!("middleware '{name}' has invalid binding {value}"))?;
            if !bindings.insert(binding) {
                return Err(miette!("middleware '{name}' repeats binding {binding:?}"));
            }
        }
        match policy {
            // Gateways that predate binding policies omit both fields.
            Policy::Unspecified | Policy::Dynamic if bindings.is_empty() => Ok(Self::Dynamic),
            Policy::Unspecified | Policy::Dynamic => Err(miette!(
                "middleware '{name}' with bindings must set binding_policy to allowlist or exact"
            )),
            Policy::Allowlist | Policy::Exact if bindings.is_empty() => Err(miette!(
                "middleware '{name}' with {policy:?} binding_policy must configure bindings"
            )),
            Policy::Allowlist => Ok(Self::Allowlist(bindings)),
            Policy::Exact => Ok(Self::Exact(bindings)),
        }
    }
}

impl BindingPolicy {
    pub fn authorize(
        &self,
        source: &str,
        advertised: &mut BTreeMap<Binding, MiddlewareBinding>,
    ) -> Result<()> {
        let (Self::Allowlist(required) | Self::Exact(required)) = self else {
            tracing::warn!(
                "{source} uses dynamic binding discovery; the service controls its bindings"
            );
            return Ok(());
        };
        for binding in required {
            if !advertised.contains_key(binding) {
                return Err(miette!(
                    "{source} does not advertise required binding {binding:?}"
                ));
            }
        }
        if let Self::Exact(_) = self
            && let Some(extra) = advertised
                .keys()
                .find(|binding| !required.contains(binding))
        {
            return Err(miette!(
                "{source} advertises binding {extra:?} outside its exact policy"
            ));
        }
        advertised.retain(|binding, _| {
            let authorized = required.contains(binding);
            if !authorized {
                tracing::info!("{source} binding {binding:?} is not in the allowlist, ignoring");
            }
            authorized
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_binding_policies_are_not_treated_as_dynamic() {
        let request = Binding::HttpRequestPreCredentials as i32;
        for (policy, bindings) in [
            (1234, vec![]),
            (Policy::Unspecified as i32, vec![request]),
            (Policy::Dynamic as i32, vec![request]),
            (Policy::Allowlist as i32, vec![]),
            (Policy::Exact as i32, vec![]),
            (Policy::Exact as i32, vec![0]),
            (Policy::Allowlist as i32, vec![1234]),
            (Policy::Allowlist as i32, vec![request, request]),
        ] {
            let service = SupervisorMiddlewareService {
                binding_policy: policy,
                bindings,
                ..Default::default()
            };
            assert!(BindingPolicy::try_from(&service).is_err(), "{service:?}");
        }
    }

    #[test]
    fn exact_requires_the_same_set_not_just_a_subset() {
        let request = Binding::HttpRequestPreCredentials;
        let response = Binding::HttpResponsePreReturn;
        let policy = BindingPolicy::Exact(BTreeSet::from([request]));
        let matching = BTreeMap::from([(request, MiddlewareBinding::default())]);
        policy.authorize("service", &mut matching.clone()).unwrap();

        let mut extra = matching;
        extra.insert(response, MiddlewareBinding::default());
        let error = policy.authorize("service", &mut extra).unwrap_err();
        assert!(
            error.to_string().contains("outside its exact policy"),
            "{error}"
        );
    }
}
