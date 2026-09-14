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
