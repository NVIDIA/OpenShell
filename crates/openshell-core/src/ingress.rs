// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared validation of compute-admitted ingress; the backend enforces targets.

use crate::proto::{IngressScope, SandboxIngressAdmission};
use std::collections::BTreeSet;

/// Validate a negotiated descriptor without treating unknown evidence as legacy.
pub fn validate(admission: &SandboxIngressAdmission) -> Result<IngressScope, &'static str> {
    let scope =
        IngressScope::try_from(admission.scope).map_err(|_| "unknown compute ingress scope")?;
    if scope == IngressScope::Unspecified {
        return Err(
            "compute ingress admission is unavailable; recreate the sandbox with an ingress-aware driver",
        );
    }
    if (admission.all_ports && !admission.ports.is_empty())
        || (scope == IngressScope::Unsupported
            && (admission.all_ports || !admission.ports.is_empty()))
        || admission.ports.len() > 65535
    {
        return Err("invalid compute ingress envelope");
    }
    let mut seen = BTreeSet::new();
    for port in &admission.ports {
        if !(1..=65535).contains(port) || !seen.insert(port) {
            return Err("compute ingress ports must be unique and between 1 and 65535");
        }
    }
    Ok(scope)
}

/// Authorize before listeners, service persistence, or any pooled upstream use.
/// Legacy absence is permitted only when the gateway has not negotiated ingress.
pub fn admit_port(
    admission: Option<&SandboxIngressAdmission>,
    port: u32,
    required: bool,
) -> Result<IngressScope, &'static str> {
    if !(1..=65535).contains(&port) {
        return Err("target port must be between 1 and 65535");
    }
    let Some(admission) = admission else {
        return if required {
            Err("compute ingress admission is missing; recreate the sandbox")
        } else {
            Ok(IngressScope::Unspecified)
        };
    };
    let scope = validate(admission)?;
    if scope == IngressScope::Unsupported {
        return Err("the compute driver does not support sandbox ingress");
    }
    if !admission.all_ports && !admission.ports.contains(&port) {
        return Err(
            "target port was not admitted by the compute driver; recreate the sandbox with that service port",
        );
    }
    Ok(scope)
}
