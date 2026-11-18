// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-to-supervisor SSH exec request for the Windows MXC runtime.

use std::collections::HashMap;

/// A leading ASCII record separator distinguishes the frame from native shell text.
pub const ARGV_PREFIX: &str = "\x1eopenshell-exec-argv-v1\n";

/// The argv, environment, and working directory from an MXC `ExecSandbox` RPC.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshExecArgv {
    pub command: Vec<String>,
    pub environment: HashMap<String, String>,
    pub workdir: String,
}
