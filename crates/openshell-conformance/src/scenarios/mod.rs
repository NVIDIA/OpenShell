// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registered, portable conformance scenarios.

mod file_transfer;
mod policy_behavior;
mod provider_auto_create;
mod sandbox_lifecycle;
mod sandbox_templates;
mod settings_management;
mod smoke;
mod workspace_lifecycle;

pub use file_transfer::{
    FILE_TRANSFER_CREATE_UPLOAD_SCENARIO, FILE_TRANSFER_GIT_FILTERING_SCENARIO,
    FILE_TRANSFER_PATH_SAFETY_SCENARIO, FILE_TRANSFER_ROUND_TRIP_SCENARIO, FILE_TRANSFER_SCENARIO,
};
pub use policy_behavior::{
    MECHANISTIC_PROPOSAL_SCENARIO, NEW_HOSTNAME_PROPOSAL_SCENARIO, POLICY_LOCAL_SCENARIO,
};
pub use provider_auto_create::PROVIDER_AUTO_CREATE_SCENARIO;
pub use sandbox_lifecycle::SANDBOX_LIFECYCLE_SCENARIO;
pub use sandbox_templates::{
    SANDBOX_TEMPLATE_DUPLICATE_NAME_SCENARIO, SANDBOX_TEMPLATE_GET_AFTER_DELETE_SCENARIO,
    SANDBOX_TEMPLATE_LIFECYCLE_SCENARIO, SANDBOX_TEMPLATE_MISSING_TEMPLATE_SCENARIO,
    SANDBOX_TEMPLATES_SCENARIO,
};
pub use settings_management::SETTINGS_MANAGEMENT_SCENARIO;
pub use smoke::SMOKE_SCENARIO;
pub use workspace_lifecycle::{WORKSPACE_LIFECYCLE_SCENARIO, WORKSPACE_TERMINATING_SCENARIO};
