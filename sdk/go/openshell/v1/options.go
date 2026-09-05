// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// CreateOption configures a Create call.
type CreateOption = types.CreateOption

// WithLabels sets labels on the created resource.
var WithLabels = types.WithLabels

// WithAnnotations sets annotations on the created resource.
var WithAnnotations = types.WithAnnotations

// ListOptions configures resource listing with pagination and filtering.
type ListOptions = types.ListOptions

// WatchOptions configures watch behavior.
type WatchOptions = types.WatchOptions

// WaitOptions configures wait behavior. Use context for timeout control.
type WaitOptions = types.WaitOptions

// ExecOptions configures command execution.
type ExecOptions = types.ExecOptions
