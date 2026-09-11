// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"

func namedWorkspaceScope(workspace string) *dm.WorkspaceSelector {
	return &dm.WorkspaceSelector{
		Selection: &dm.WorkspaceSelector_Workspace{Workspace: workspace},
	}
}

func allWorkspacesScope() *dm.WorkspaceSelector {
	return &dm.WorkspaceSelector{
		Selection: &dm.WorkspaceSelector_AllWorkspaces{AllWorkspaces: &dm.AllWorkspaces{}},
	}
}

func sandboxReferenceByName(workspace, name string) *dm.SandboxReference {
	return &dm.SandboxReference{
		Identifier:     &dm.SandboxReference_Name{Name: name},
		WorkspaceScope: namedWorkspaceScope(workspace),
	}
}

func sandboxReferenceByID(id string) *dm.SandboxReference {
	return &dm.SandboxReference{
		Identifier: &dm.SandboxReference_Id{Id: id},
	}
}
