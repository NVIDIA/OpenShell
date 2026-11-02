// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Admission of resource guarantees, separate from operator host-resource policy.

use crate::proto::compute::v1::{DriverSandbox, ResourceCapabilities};
use crate::proto::sandbox::v1::{
    ResourceEnforcement, ResourceEnforcementKind as Kind, ResourceEnforcementScope as Scope,
    SampledResourceBudget,
};

/// Canonical positive protobuf duration, in nanoseconds without narrowing.
pub fn positive_duration_nanos(value: &prost_types::Duration) -> Result<u128, &'static str> {
    if !(0..=315_576_000_000).contains(&value.seconds) || !(0..1_000_000_000).contains(&value.nanos)
    {
        return Err("resource duration must be positive and canonical");
    }
    let nanos = u128::from(value.seconds.unsigned_abs()) * 1_000_000_000
        + u128::from(value.nanos.unsigned_abs());
    if nanos == 0 {
        return Err("resource duration must be positive");
    }
    Ok(nanos)
}

pub fn validate_sampled_budget(budget: &SampledResourceBudget) -> Result<(), &'static str> {
    if budget.cpu_time.is_none() && budget.resident_bytes.is_none() {
        return Err("sampled resource budget must select CPU time or resident bytes");
    }
    if let Some(cpu) = &budget.cpu_time {
        positive_duration_nanos(cpu)?;
    }
    if budget.resident_bytes == Some(0) {
        return Err("sampled resident bytes must be positive");
    }
    Ok(())
}

fn require_enforcement(
    enforcement: Option<&ResourceEnforcement>,
    kind: Kind,
) -> Result<(), &'static str> {
    let Some(enforcement) = enforcement else {
        return Err("requested resource guarantee is unreported by the compute driver");
    };
    if Kind::try_from(enforcement.kind).ok() != Some(kind)
        || !matches!(
            Scope::try_from(enforcement.scope),
            Ok(Scope::Container | Scope::SandboxAccount | Scope::VirtualMachine)
        )
    {
        return Err("requested resource guarantee is unsupported at sandbox scope");
    }
    Ok(())
}

/// Validate both independent CPU/memory axes before any provisioning.
///
/// Legacy drivers retain their existing hard-limit behavior, but cannot accept the new
/// sampled request by silently ignoring an unknown protobuf field.
pub fn validate_request(
    sandbox: &DriverSandbox,
    capabilities: Option<&ResourceCapabilities>,
    negotiated: bool,
) -> Result<(), &'static str> {
    let spec = sandbox.spec.as_ref();
    let resources = spec
        .and_then(|s| s.template.as_ref())
        .and_then(|t| t.resources.as_ref());
    if negotiated && let Some(resources) = resources {
        let cpu = capabilities.and_then(|c| c.cpu.as_ref());
        let memory = capabilities.and_then(|c| c.memory.as_ref());
        if !resources.cpu_limit.is_empty() {
            if !cpu.is_some_and(|c| c.limit_supported) {
                return Err("compute driver does not support a hard CPU-rate limit");
            }
            require_enforcement(
                cpu.and_then(|c| c.limit_enforcement.as_ref()),
                Kind::KernelLimit,
            )?;
        }
        if !resources.memory_limit.is_empty() {
            if !memory.is_some_and(|c| c.limit_supported) {
                return Err("compute driver does not support a hard memory limit");
            }
            require_enforcement(
                memory.and_then(|c| c.limit_enforcement.as_ref()),
                Kind::KernelLimit,
            )?;
        }
        if !resources.cpu_request.is_empty() {
            require_enforcement(
                cpu.and_then(|c| c.request_enforcement.as_ref()),
                Kind::SchedulerRequest,
            )?;
        }
        if !resources.memory_request.is_empty() {
            require_enforcement(
                memory.and_then(|c| c.request_enforcement.as_ref()),
                Kind::SchedulerRequest,
            )?;
        }
    }
    if let Some(budget) = spec
        .and_then(|s| s.resource_requirements.as_ref())
        .and_then(|r| r.sampled_budget.as_ref())
    {
        validate_sampled_budget(budget)?;
        if !negotiated {
            return Err("sampled budgets require openshell.compute.resource-contract");
        }
        let Some(cap) = capabilities.and_then(|c| c.sampled_budget.as_ref()) else {
            return Err("compute driver does not support sampled resource budgets");
        };
        if !cap.terminate_on_excess
            || Scope::try_from(cap.scope).ok() != Some(Scope::SandboxAccount)
        {
            return Err("sampled budgets require terminating account-wide observation");
        }
        positive_duration_nanos(
            cap.sampling_interval
                .as_ref()
                .ok_or("sampling interval is unreported")?,
        )?;
        if let Some(cpu) = &budget.cpu_time {
            if !cap.cpu_time_supported {
                return Err("sampled CPU-time budget is unsupported");
            }
            let resolution = positive_duration_nanos(
                cap.cpu_time_resolution
                    .as_ref()
                    .ok_or("CPU-time resolution is unreported")?,
            )?;
            if positive_duration_nanos(cpu)? % resolution != 0 {
                return Err(
                    "sampled CPU-time budget cannot be represented at the driver resolution",
                );
            }
        }
        if budget.resident_bytes.is_some() && !cap.resident_bytes_supported {
            return Err("sampled resident-memory budget is unsupported");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::compute::v1::{
        CpuResourceCapabilities, DriverResourceRequirements, DriverSandboxSpec,
        DriverSandboxTemplate, MemoryResourceCapabilities, ResourceRequirements,
    };
    use crate::proto::sandbox::v1::SampledResourceBudgetCapabilities;

    #[test]
    fn resource_guarantees_validate_both_axes_and_never_infer_support() {
        let mut sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    resources: Some(DriverResourceRequirements::default()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        for (cpu, memory) in [("1", ""), ("", "512Mi")] {
            let resources = sandbox
                .spec
                .as_mut()
                .unwrap()
                .template
                .as_mut()
                .unwrap()
                .resources
                .as_mut()
                .unwrap();
            resources.cpu_limit = cpu.into();
            resources.memory_limit = memory.into();
            for (kind, scope, accepted) in [
                (Kind::KernelLimit as i32, Scope::Container as i32, true),
                (Kind::KernelLimit as i32, Scope::Process as i32, false),
                (
                    Kind::SchedulerRequest as i32,
                    Scope::Container as i32,
                    false,
                ),
                (99, Scope::Container as i32, false),
                (Kind::KernelLimit as i32, 99, false),
            ] {
                let enforcement = Some(ResourceEnforcement { kind, scope });
                let capabilities = ResourceCapabilities {
                    cpu: Some(CpuResourceCapabilities {
                        limit_supported: true,
                        limit_enforcement: enforcement,
                        ..Default::default()
                    }),
                    memory: Some(MemoryResourceCapabilities {
                        limit_supported: true,
                        limit_enforcement: enforcement,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                assert_eq!(
                    validate_request(&sandbox, Some(&capabilities), true).is_ok(),
                    accepted
                );
            }
            assert!(validate_request(&sandbox, None, true).is_err());
            assert!(validate_request(&sandbox, None, false).is_ok());
        }
        sandbox.spec.as_mut().unwrap().template = None;
        let capabilities = ResourceCapabilities {
            sampled_budget: Some(SampledResourceBudgetCapabilities {
                cpu_time_supported: true,
                resident_bytes_supported: true,
                scope: Scope::SandboxAccount as i32,
                sampling_interval: Some(prost_types::Duration {
                    seconds: 0,
                    nanos: 100_000_000,
                }),
                cpu_time_resolution: Some(prost_types::Duration {
                    seconds: 0,
                    nanos: 1_000_000,
                }),
                terminate_on_excess: true,
                per_process_cpu_limit: true,
            }),
            ..Default::default()
        };
        for (seconds, nanos, resident, accepted) in [
            (0, 1_000_000, None, true),
            (1, 0, Some(4096), true),
            (0, 1, None, false),
            (0, 0, None, false),
            (-1, 0, None, false),
            (1, -1, None, false),
            (1, 1_000_000_000, None, false),
            (315_576_000_001, 0, None, false),
            (1, 0, Some(0), false),
        ] {
            sandbox.spec.as_mut().unwrap().resource_requirements = Some(ResourceRequirements {
                sampled_budget: Some(SampledResourceBudget {
                    cpu_time: Some(prost_types::Duration { seconds, nanos }),
                    resident_bytes: resident,
                }),
                ..Default::default()
            });
            assert_eq!(
                validate_request(&sandbox, Some(&capabilities), true).is_ok(),
                accepted
            );
            assert!(validate_request(&sandbox, Some(&capabilities), false).is_err());
        }
    }
}
