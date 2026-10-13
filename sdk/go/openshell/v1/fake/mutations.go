// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func deletionResult(existed bool, sandboxID string, opts []v1.DeleteOptions) (*types.DeletionResult, error) {
	if existed {
		return &types.DeletionResult{Outcome: types.DeletionCompleted, SandboxID: sandboxID}, nil
	}
	if len(opts) > 0 && opts[0].AllowMissing {
		return &types.DeletionResult{Outcome: types.DeletionAlreadyAbsent}, nil
	}
	return nil, &types.StatusError{Code: types.ErrorNotFound, Message: "target not found"}
}
