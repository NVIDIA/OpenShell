// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::lima::LimaProvider;
use crate::machine::{Machine, MachineProvider, MachineRequest, PersistentDisk, Provider};

impl MachineProvider for Provider {
    fn persistent_disk_mount_point(&self, disk: &PersistentDisk) -> String {
        match self {
            Self::Lima => LimaProvider.persistent_disk_mount_point(disk),
        }
    }

    fn acquire(
        &self,
        request: MachineRequest,
        setup_script: &str,
    ) -> Result<Box<dyn Machine>, String> {
        match self {
            Self::Lima => LimaProvider.acquire(request, setup_script),
        }
    }
}
