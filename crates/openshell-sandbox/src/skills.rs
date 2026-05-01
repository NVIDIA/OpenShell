// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Static agent guidance files exposed inside the sandbox.

use miette::{IntoDiagnostic, Result};
use std::path::{Path, PathBuf};

const SKILLS_RELATIVE_DIR: &str = "etc/openshell/skills";
const POLICY_ADVISOR_FILE: &str = "policy_advisor.md";
const POLICY_ADVISOR_CONTENT: &str = include_str!("skills/policy_advisor.md");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSkills {
    pub policy_advisor: PathBuf,
}

pub fn install_static_skills() -> Result<InstalledSkills> {
    install_static_skills_at(Path::new("/"))
}

fn install_static_skills_at(root: &Path) -> Result<InstalledSkills> {
    let skills_dir = root.join(SKILLS_RELATIVE_DIR);
    std::fs::create_dir_all(&skills_dir).into_diagnostic()?;

    let policy_advisor = skills_dir.join(POLICY_ADVISOR_FILE);
    std::fs::write(&policy_advisor, POLICY_ADVISOR_CONTENT).into_diagnostic()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&policy_advisor, std::fs::Permissions::from_mode(0o444))
            .into_diagnostic()?;
    }

    Ok(InstalledSkills { policy_advisor })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_static_skills_at_writes_policy_advisor() {
        let dir = tempfile::tempdir().unwrap();

        let installed = install_static_skills_at(dir.path()).unwrap();

        let expected = dir
            .path()
            .join("etc")
            .join("openshell")
            .join("skills")
            .join("policy_advisor.md");
        assert_eq!(installed.policy_advisor, expected);

        let content = std::fs::read_to_string(expected).unwrap();
        assert!(content.contains("# OpenShell Policy Advisor"));
        assert!(content.contains("policy.local"));
        assert!(content.contains("PolicyMergeOperation"));
    }
}
