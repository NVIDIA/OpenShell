// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// CreateOptions configures resource creation.
type CreateOptions = types.CreateOptions

// GetOptions configures resource retrieval.
type GetOptions = types.GetOptions

// ListOptions configures resource listing with pagination and filtering.
type ListOptions = types.ListOptions

// DeleteOptions configures resource deletion.
type DeleteOptions = types.DeleteOptions

// UpdateOptions configures resource updates.
type UpdateOptions = types.UpdateOptions

// WatchOptions configures watch behavior.
type WatchOptions = types.WatchOptions

// WaitOptions configures wait behavior. Use context for timeout control.
type WaitOptions = types.WaitOptions

// ExecOptions configures command execution.
type ExecOptions = types.ExecOptions
