// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// --- T018: fakeSSHClient stub tests ---

func TestFakeSSH_CreateSession_ReturnsUnimplemented(t *testing.T) {
	c := newFakeSSHClient(func() bool { return false })
	_, err := c.CreateSession(context.Background(), "default", "sandbox-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeSSH_RevokeSession_ReturnsUnimplemented(t *testing.T) {
	c := newFakeSSHClient(func() bool { return false })
	_, err := c.RevokeSession(context.Background(), "default", "tok-abc")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeSSH_CreateSession_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeSSHClient(func() bool { return true })
	_, err := c.CreateSession(context.Background(), "default", "sandbox-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeSSH_RevokeSession_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeSSHClient(func() bool { return true })
	_, err := c.RevokeSession(context.Background(), "default", "tok-abc")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

// --- T014: Fake Tunnel tests ---

func TestFakeSSH_Tunnel_ReturnsUnimplemented(t *testing.T) {
	c := newFakeSSHClient(func() bool { return false })
	_, err := c.Tunnel(context.Background(), "default", "my-sandbox", 22)
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeSSH_Tunnel_WithTunnelOption(t *testing.T) {
	c := newFakeSSHClient(func() bool { return false })
	_, err := c.Tunnel(context.Background(), "default", "my-sandbox", 22, v1.WithTunnelServiceID("audit-svc"))
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeSSH_Tunnel_InvalidPort(t *testing.T) {
	c := newFakeSSHClient(func() bool { return false })

	_, err := c.Tunnel(context.Background(), "default", "my-sandbox", 0)
	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))

	_, err = c.Tunnel(context.Background(), "default", "my-sandbox", 65536)
	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeSSH_Tunnel_EmptySandboxName(t *testing.T) {
	c := newFakeSSHClient(func() bool { return false })
	_, err := c.Tunnel(context.Background(), "default", "", 22)
	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeSSH_Tunnel_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeSSHClient(func() bool { return true })
	_, err := c.Tunnel(context.Background(), "default", "my-sandbox", 22)
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
