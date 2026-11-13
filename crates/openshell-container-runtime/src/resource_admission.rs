// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned external resource admission. GPU attachments are temporarily
//! exempt; this policy must not be interpreted as permission to attach host paths.

/// Reserved driver-owned runtime metadata; caller labels must never override it.
pub const CONFIG_USED_LABEL: &str = "openshell.ai/caller-driver-config-used";

pub const IDENTITIES_LABEL: &str = "openshell.ai/resource-admission-identities";

pub fn check_config_provenance(allowed: bool, recorded: Option<&str>) -> Result<(), tonic::Status> {
    match recorded {
        Some("false") => Ok(()),
        Some("true") if allowed => Ok(()),
        _ => Err(tonic::Status::failed_precondition(
            "sandbox uses forbidden driver config or lacks admission provenance; recreate it",
        )),
    }
}
