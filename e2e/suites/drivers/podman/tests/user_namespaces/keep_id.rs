// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::gateway::{Profile, with_profile};
use super::helpers::assert_workspace_and_uid_map;

#[tokio::test]
async fn mapping_matches_podman_and_preserves_workspace_access() {
    with_profile(Profile::KeepId, async |gateway, runner| {
        assert_workspace_and_uid_map(gateway, runner).await
    })
    .await
    .expect("keep_id Podman user namespace preserves workspace access");
}
