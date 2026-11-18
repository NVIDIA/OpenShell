// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway RPCs that change state for a user or operator, each recorded as
//! one API Activity event per call.

use openshell_ocsf::ActivityId;

const CREATE: ActivityId = ActivityId::Open;
const UPDATE: ActivityId = ActivityId::Reset;
const DELETE: ActivityId = ActivityId::Fail;
const OTHER: ActivityId = ActivityId::Other;

macro_rules! openshell {
    ($method:literal) => {
        concat!("/openshell.v1.OpenShell/", $method)
    };
}

const CATALOG: &[(&str, ActivityId)] = &[
    (openshell!("CreateSandbox"), CREATE),
    (openshell!("DeleteSandbox"), DELETE),
    (openshell!("StopSandbox"), UPDATE),
    (openshell!("StartSandbox"), UPDATE),
    (openshell!("SuspendSandbox"), UPDATE),
    (openshell!("ResumeSandbox"), UPDATE),
    ("/openshell.v1.SandboxUpdates/UpdateSandbox", UPDATE),
    (openshell!("BeginRootfsTarStaging"), CREATE),
    (openshell!("CreateSandboxTemplate"), CREATE),
    (openshell!("DeleteSandboxTemplate"), DELETE),
    (openshell!("AttachSandboxProvider"), CREATE),
    (openshell!("DetachSandboxProvider"), DELETE),
    (openshell!("ExecSandbox"), OTHER),
    (openshell!("ExecSandboxInteractive"), OTHER),
    (openshell!("ForwardTcp"), OTHER),
    (openshell!("CreateSshSession"), CREATE),
    (openshell!("RevokeSshSession"), DELETE),
    (openshell!("ExposeService"), CREATE),
    (openshell!("DeleteService"), DELETE),
    (openshell!("CreateProvider"), CREATE),
    (openshell!("UpdateProvider"), UPDATE),
    (openshell!("DeleteProvider"), DELETE),
    (openshell!("ImportProviderProfiles"), CREATE),
    (openshell!("UpdateProviderProfiles"), UPDATE),
    (openshell!("DeleteProviderProfile"), DELETE),
    (openshell!("ConfigureProviderRefresh"), UPDATE),
    (openshell!("DeleteProviderRefresh"), DELETE),
    (openshell!("InlineProviderRefreshSecrets"), UPDATE),
    (openshell!("RotateProviderCredential"), UPDATE),
    (openshell!("CreateSecret"), CREATE),
    (openshell!("UpdateSecret"), UPDATE),
    (openshell!("DeleteSecret"), DELETE),
    (openshell!("UpdateConfig"), UPDATE),
    (openshell!("ApproveDraftChunk"), UPDATE),
    (openshell!("ApproveAllDraftChunks"), UPDATE),
    (openshell!("RejectDraftChunk"), UPDATE),
    (openshell!("EditDraftChunk"), UPDATE),
    (openshell!("UndoDraftChunk"), UPDATE),
    (openshell!("ClearDraftChunks"), DELETE),
    (openshell!("CreateWorkspace"), CREATE),
    (openshell!("DeleteWorkspace"), DELETE),
    (openshell!("AddWorkspaceMember"), CREATE),
    (openshell!("RemoveWorkspaceMember"), DELETE),
];

/// The activity of the gRPC method at `path`, if it is audited.
pub fn lookup(path: &str) -> Option<ActivityId> {
    CATALOG
        .iter()
        .find(|(entry_path, _)| *entry_path == path)
        .map(|&(_, activity)| activity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::descriptor_authz;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_lists_exactly_the_write_scoped_rpcs() {
        let write_scoped: BTreeSet<&str> = descriptor_authz::all_paths()
            .filter(|path| {
                descriptor_authz::lookup(path)
                    .and_then(|entry| entry.scope.as_deref())
                    .is_some_and(|scope| scope.ends_with(":write"))
            })
            .collect();
        let cataloged: BTreeSet<&str> = CATALOG.iter().map(|(path, ..)| *path).collect();

        let missing: Vec<_> = write_scoped.difference(&cataloged).collect();
        let stale: Vec<_> = cataloged.difference(&write_scoped).collect();
        assert!(
            missing.is_empty(),
            "write-scoped RPCs missing from the audit catalog: {missing:?}"
        );
        assert!(
            stale.is_empty(),
            "audit catalog names RPCs that are not write-scoped: {stale:?}"
        );
        assert_eq!(
            cataloged.len(),
            CATALOG.len(),
            "audit catalog lists an RPC twice"
        );
    }
}
