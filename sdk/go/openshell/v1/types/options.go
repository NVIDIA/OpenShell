// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// CreateOptions configures resource creation.
type CreateOptions struct{}

// GetOptions configures resource retrieval.
type GetOptions struct{}

// ListOptions configures resource listing with pagination and filtering.
type ListOptions struct {
	Limit         int
	Offset        int
	LabelSelector string
	AllWorkspaces bool
}

// DeleteOptions configures resource deletion.
type DeleteOptions struct{}

// UpdateOptions configures resource updates.
type UpdateOptions struct{}

// WatchOptions configures watch behavior.
type WatchOptions struct {
	// TimeoutSeconds is reserved for future use. Use context for timeout control.
	TimeoutSeconds int64
	// LabelSelector is reserved for future use.
	LabelSelector string
	// StopOnTerminal causes the watch to close automatically when the sandbox
	// reaches a terminal phase (Ready or Error).
	StopOnTerminal bool
}

// WaitOptions configures wait behavior. Use context for timeout control.
type WaitOptions struct {
	PollInterval time.Duration
}

// ExecOptions configures command execution.
type ExecOptions struct {
	Env     map[string]string
	WorkDir string
}
