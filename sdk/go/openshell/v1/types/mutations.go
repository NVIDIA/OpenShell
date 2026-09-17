// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// DeletionOutcome distinguishes completion from asynchronous acceptance.
// Unknown numeric values are preserved and must not be treated as completion.
type DeletionOutcome int32

// Known deletion outcomes. Only Completed and AlreadyAbsent establish completion.
const (
	DeletionUnspecified DeletionOutcome = iota
	DeletionCompleted
	DeletionAccepted
	DeletionAlreadyAbsent
)

// DeletionResult describes the original target, not a same-name replacement.
type DeletionResult struct {
	Outcome DeletionOutcome
	// SandboxID is empty for non-sandbox deletions and missing targets.
	SandboxID string
}

// DeleteOptions configures the missing-target contract.
type DeleteOptions struct {
	AllowMissing bool
}
