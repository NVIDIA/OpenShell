// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Static agent guidance files exposed inside the sandbox.

use miette::{IntoDiagnostic, Result};
use std::path::{Path, PathBuf};

const SKILLS_RELATIVE_DIR: &str = "etc/openshell/skills";
const POLICY_ADVISOR_FILE: &str = "policy_advisor.md";
const POLICY_ADVISOR_SKILL_DIR: &str = "policy-advisor";
const POLICY_ADVISOR_SKILL_FILE: &str = "SKILL.md";
const POLICY_ADVISOR_CONTENT: &str = include_str!("skills/policy_advisor.md");
const POLICY_ADVISOR_SKILL_CONTENT: &str = include_str!("skills/policy-advisor/SKILL.md");
const AGENTS_FILE: &str = "AGENTS.md";
const AGENTS_CONTENT: &str = r"# OpenShell Sandbox Guidance

When you see `policy_denied`, do not treat it as final if the user task still needs that request. Read `/etc/openshell/skills/policy_advisor.md` and use `http://policy.local` to submit the narrowest policy proposal, then wait for approval before retrying.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSkills {
    pub policy_advisor: PathBuf,
    pub policy_advisor_skill: PathBuf,
    pub agents: Option<PathBuf>,
}

pub fn install_static_skills() -> Result<InstalledSkills> {
    install_static_skills_at(Path::new("/"))
}

fn install_static_skills_at(root: &Path) -> Result<InstalledSkills> {
    let skills_dir = root.join(SKILLS_RELATIVE_DIR);
    std::fs::create_dir_all(&skills_dir).into_diagnostic()?;

    let policy_advisor = skills_dir.join(POLICY_ADVISOR_FILE);
    write_readonly(&policy_advisor, POLICY_ADVISOR_CONTENT)?;

    let policy_advisor_skill_dir = skills_dir.join(POLICY_ADVISOR_SKILL_DIR);
    std::fs::create_dir_all(&policy_advisor_skill_dir).into_diagnostic()?;
    let policy_advisor_skill = policy_advisor_skill_dir.join(POLICY_ADVISOR_SKILL_FILE);
    write_readonly(&policy_advisor_skill, POLICY_ADVISOR_SKILL_CONTENT)?;

    let agents = install_optional_agents_pointer(root);

    Ok(InstalledSkills {
        policy_advisor,
        policy_advisor_skill,
        agents,
    })
}

fn write_readonly(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).into_diagnostic()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).into_diagnostic()?;
    }
    Ok(())
}

fn install_optional_agents_pointer(root: &Path) -> Option<PathBuf> {
    let agents_path = root.join(AGENTS_FILE);
    match std::fs::symlink_metadata(&agents_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            write_readonly(&agents_path, AGENTS_CONTENT).ok()?;
            Some(agents_path)
        }
        Ok(_) | Err(_) => None,
    }
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

        let content = std::fs::read_to_string(&expected).unwrap();
        assert!(content.contains("# OpenShell Policy Advisor"));
        assert!(content.contains("policy.local"));
        assert!(content.contains("addRule"));
        // The wait-loop teaching is load-bearing for the agent feedback
        // UX; lock the workflow language in so future skill edits cannot
        // drop it silently. Each substring targets a directive, not the
        // field name (which could appear in the API doc block alone).
        assert!(content.contains("/v1/proposals/{chunk_id}/wait"));
        assert!(content.contains("read `rejection_reason`"));
        // policy_reloaded distinguishes "safe to retry" from "approval
        // landed but supervisor hasn't reloaded yet"; without both
        // branches taught the agent retries blind on approve+not-yet
        // and re-runs into policy_denied.
        assert!(content.contains("`policy_reloaded: true`"));
        assert!(content.contains("`policy_reloaded: false`"));

        let skill_file = dir
            .path()
            .join("etc")
            .join("openshell")
            .join("skills")
            .join("policy-advisor")
            .join("SKILL.md");
        assert_eq!(installed.policy_advisor_skill, skill_file);
        let skill_content = std::fs::read_to_string(&skill_file).unwrap();
        assert!(skill_content.contains("policy_denied"));
        assert!(skill_content.contains("policy.local"));
        assert!(skill_content.contains("/etc/openshell/skills/policy_advisor.md"));

        let agents = installed.agents.expect("AGENTS.md should be installed");
        assert_eq!(agents, dir.path().join("AGENTS.md"));
        let agents_content = std::fs::read_to_string(agents).unwrap();
        assert!(agents_content.contains("policy_denied"));
        assert!(agents_content.contains("policy.local"));
    }

    #[test]
    fn install_static_skills_at_does_not_overwrite_existing_agents_file() {
        let dir = tempfile::tempdir().unwrap();
        let agents = dir.path().join("AGENTS.md");
        std::fs::write(&agents, "keep me").unwrap();

        let installed = install_static_skills_at(dir.path()).unwrap();

        assert_eq!(installed.agents, None);
        assert_eq!(std::fs::read_to_string(agents).unwrap(), "keep me");
    }

    #[cfg(unix)]
    #[test]
    fn install_static_skills_at_treats_broken_agents_symlink_as_existing() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let agents = dir.path().join("AGENTS.md");
        symlink(dir.path().join("missing-target"), &agents).unwrap();

        let installed = install_static_skills_at(dir.path()).unwrap();

        assert_eq!(installed.agents, None);
        assert!(
            std::fs::symlink_metadata(agents)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
