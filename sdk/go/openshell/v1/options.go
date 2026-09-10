// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"math"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// CreateOptions configures resource creation.
type CreateOptions = types.CreateOptions

// ListOptions configures resource listing with pagination and filtering.
type ListOptions = types.ListOptions

// WatchOptions configures watch behavior.
type WatchOptions = types.WatchOptions

// WaitOptions configures wait behavior. Use context for timeout control.
type WaitOptions = types.WaitOptions

// ExecOptions configures command execution.
type ExecOptions = types.ExecOptions

func listPageSize(opts []ListOptions) (int32, error) {
	if len(opts) == 0 {
		return 0, nil
	}
	if opts[0].PageSize < 0 {
		return 0, &StatusError{Code: ErrorInvalidArgument, Message: "page size must not be negative"}
	}
	if opts[0].PageSize > math.MaxInt32 {
		return math.MaxInt32, nil
	}
	return int32(opts[0].PageSize), nil
}
