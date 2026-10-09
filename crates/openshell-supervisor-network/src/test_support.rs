// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

/// Give rooted synthetic executable paths a drive on Windows. Preserve empty,
/// relative, and already native paths so invalid-identity tests remain useful.
pub fn executable_path(path: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    if path.starts_with('/') {
        return PathBuf::from(format!("C:{path}"));
    }
    PathBuf::from(path)
}

/// Match policy binary paths to the synthetic identities without changing HTTP
/// rule paths or other policy fields.
pub fn policy_with_native_executable_paths(data: &str) -> String {
    let mut policy: serde_yml::Value = serde_yml::from_str(data).expect("parse test policy");
    if let Some(policies) = policy["network_policies"].as_mapping_mut() {
        for (_, policy) in policies {
            if let Some(binaries) = policy["binaries"].as_sequence_mut() {
                for binary in binaries {
                    if let Some(path) = binary["path"].as_str() {
                        binary["path"] = serde_yml::Value::String(
                            executable_path(path).to_str().unwrap().to_string(),
                        );
                    }
                }
            }
        }
    }
    serde_yml::to_string(&policy).expect("serialize test policy")
}
