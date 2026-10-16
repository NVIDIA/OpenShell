// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

#[path = "support/provider_refresh_handles.rs"]
mod support;

const PROVIDER_NAME: &str = "e2e-oauth-refresh-handle";
const PROFILE_ID: &str = "e2e-oauth-refresh-handle";

#[tokio::test]
async fn long_running_process_survives_rotations_and_reconfigure_revokes() -> Result<(), String> {
    support::exercise_refresh_handles(None).await
}
