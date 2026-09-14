// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

// DeletionOutcome distinguishes completion from asynchronous acceptance.
type DeletionOutcome = types.DeletionOutcome

// Known deletion outcomes. Unrecognized values do not establish completion.
const (
	DeletionUnspecified   = types.DeletionUnspecified
	DeletionCompleted     = types.DeletionCompleted
	DeletionAccepted      = types.DeletionAccepted
	DeletionAlreadyAbsent = types.DeletionAlreadyAbsent
)

// DeletionResult describes the original target, not a same-name replacement.
type DeletionResult = types.DeletionResult

// DeleteOptions configures the missing-target contract.
type DeleteOptions = types.DeleteOptions

func allowMissing(opts []DeleteOptions) bool {
	return len(opts) > 0 && opts[0].AllowMissing
}
