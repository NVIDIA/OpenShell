// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// FrozenPolicyState distinguishes a requested freeze from an accepted snapshot.
type FrozenPolicyState struct {
	Requested bool
	Policy    *FrozenSandboxPolicy
}

// FrozenSandboxPolicy is the immutable accepted policy and its original source.
// Provider authorization metadata remains available through the generated API.
type FrozenSandboxPolicy struct {
	Policy              *SandboxPolicy
	Version             uint32
	PolicyHash          string
	FrozenAt            time.Time
	PolicySource        PolicySource
	GlobalPolicyVersion uint32
}

// FrozenGlobalConfigUpdate reports a global update and its frozen exceptions.
type FrozenGlobalConfigUpdate struct {
	Update          *ConfigUpdateResult
	FrozenSandboxes []string
}
