// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrozenPolicyStateCopiesSnapshot(t *testing.T) {
	wire := &pb.FrozenSandboxPolicyState{Requested: true, Policy: &pb.FrozenSandboxPolicy{
		Policy:  &sbv1.SandboxPolicy{Version: 1, Filesystem: &sbv1.FilesystemPolicy{ReadOnly: []string{"/etc"}}},
		Version: 3, PolicyHash: "accepted-hash",
	}}
	got := FrozenPolicyStateFromProto(wire)
	require.NotNil(t, got.Policy)
	wire.Policy.Policy.Filesystem.ReadOnly[0] = "/changed"
	assert.Equal(t, []string{"/etc"}, got.Policy.Policy.Filesystem.ReadOnly)
}

func TestConverterCoversFrozenPolicyMessages(t *testing.T) {
	assertAllFieldsCovered(t, (&pb.FrozenSandboxPolicyState{}).ProtoReflect().Descriptor(), fieldSet{"requested": true, "policy": true}, nil)
	// Provider identities, profiles and refresh epochs are gateway-owned authorization.
	// They are inspectable through the generated API, not the curated snapshot.
	assertAllFieldsCovered(t, (&pb.FrozenSandboxPolicy{}).ProtoReflect().Descriptor(), fieldSet{
		"policy": true, "version": true, "policy_hash": true, "frozen_time": true,
		"policy_source": true, "global_policy_version": true,
	}, fieldSet{"providers": true})
	assertAllFieldsCovered(t, (&pb.FrozenSandboxResponse{}).ProtoReflect().Descriptor(), fieldSet{"sandbox": true, "frozen_policy": true, "service_urls": true}, nil)
	assertAllFieldsCovered(t, (&pb.UpdateFrozenGlobalConfigResponse{}).ProtoReflect().Descriptor(), fieldSet{"update": true, "frozen_sandboxes": true}, nil)
}
