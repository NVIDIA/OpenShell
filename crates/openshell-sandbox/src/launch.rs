// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-local requirements retained for initial launch and later execs.

/// Runtime-derived inputs kept separate from the authored sandbox policy.
#[derive(Debug, Clone, Default)]
pub struct WorkloadLaunchContext {
    #[cfg(target_os = "linux")]
    pub(crate) cdi_requirements: Option<CdiDerivedRequirements>,
}

#[cfg(target_os = "linux")]
impl WorkloadLaunchContext {
    /// Check that the runtime applied the CDI `additionalGids`. Older
    /// runtimes ignore them, so missing groups are reported rather than
    /// fatal: devices that do not depend on them stay usable.
    pub(crate) fn validate_running_groups(&self) -> miette::Result<()> {
        use miette::IntoDiagnostic as _;
        let Some(requirements) = &self.cdi_requirements else {
            return Ok(());
        };
        if requirements.additional_gids.is_empty() {
            return Ok(());
        }
        if requirements.additional_gids.contains(&0) {
            return Err(miette::miette!(
                "CDI additionalGids must not contain root GID 0"
            ));
        }
        let actual = nix::unistd::getgroups().into_diagnostic()?;
        let actual = actual.iter().map(|gid| gid.as_raw()).collect::<Vec<_>>();
        let primary = nix::unistd::getegid().as_raw();
        if !required_cdi_groups_present(&requirements.additional_gids, primary, &actual) {
            let missing = missing_cdi_groups(&requirements.additional_gids, primary, &actual);
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Other, "degraded")
                    .message(format!(
                        "CDI groups not applied by workload runtime [missing:{missing:?} \
                         required:{:?}]; GPU devices restricted to these groups may be \
                         inaccessible",
                        requirements.additional_gids
                    ))
                    .build()
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn required_cdi_groups_present(required: &[u32], primary: u32, actual: &[u32]) -> bool {
    if required.contains(&0) {
        return false;
    }
    let mut available = actual.to_vec();
    available.push(primary);
    available.sort_unstable();
    supplementary_groups_match(&available, required, true)
}

#[cfg(target_os = "linux")]
pub(crate) fn missing_cdi_groups(required: &[u32], primary: u32, actual: &[u32]) -> Vec<u32> {
    required
        .iter()
        .copied()
        .filter(|gid| *gid == 0 || (*gid != primary && !actual.contains(gid)))
        .collect()
}

/// Match the sorted runtime groups against required identity groups. Runtime
/// GPU groups may extend, but never replace, the image-derived identity.
#[cfg(target_os = "linux")]
pub(crate) fn supplementary_groups_match(
    actual: &[u32],
    expected: &[u32],
    allow_extra: bool,
) -> bool {
    if allow_extra {
        expected.iter().all(|gid| actual.binary_search(gid).is_ok())
    } else {
        actual == expected
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CdiDerivedRequirements {
    pub device_node_paths: Vec<String>,
    /// Exact Unix socket destinations. Never expanded into filesystem grants.
    pub socket_paths: Vec<String>,
    /// Derived read-only policy paths. Shared-library mounts contribute their
    /// parent directory; other read-only mounts contribute their exact path.
    pub read_only_paths: Vec<String>,
    pub read_write_mount_paths: Vec<String>,
    /// Known writable IPC directories, such as the NVIDIA MPS pipe directory.
    /// Granted read-write on the exact directory and revalidated at each launch.
    pub ipc_directory_paths: Vec<String>,
    pub additional_gids: Vec<u32>,
    /// Original ordinary mount destinations, separate from sockets and library parents.
    /// Access is confirmed in the workload namespace before enrichment.
    pub mounts: Vec<CdiMountRequirement>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CdiMountRequirement {
    pub path: String,
    pub read_only: bool,
}
