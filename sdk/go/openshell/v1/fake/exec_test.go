// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// --- T021: Exec stub tests ---

func TestExec_Run_Unimplemented(t *testing.T) {
	ec := newFakeExecClient(func() bool { return false })
	ctx := context.Background()

	_, err := ec.Run(ctx, "default", "sandbox-1", []string{"echo", "hello"})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestExec_Stream_Unimplemented(t *testing.T) {
	ec := newFakeExecClient(func() bool { return false })
	ctx := context.Background()

	_, err := ec.Stream(ctx, "default", "sandbox-1", []string{"tail", "-f", "/var/log/app.log"})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestExec_Interactive_Unimplemented(t *testing.T) {
	ec := newFakeExecClient(func() bool { return false })
	ctx := context.Background()

	_, err := ec.Interactive(ctx, "default", "sandbox-1", []string{"/bin/bash"}, 80, 24)
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestExec_Run_ClosedClient(t *testing.T) {
	ec := newFakeExecClient(func() bool { return true })
	ctx := context.Background()

	_, err := ec.Run(ctx, "default", "sandbox-1", []string{"echo"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestExec_Stream_ClosedClient(t *testing.T) {
	ec := newFakeExecClient(func() bool { return true })
	ctx := context.Background()

	_, err := ec.Stream(ctx, "default", "sandbox-1", []string{"tail"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestExec_Interactive_ClosedClient(t *testing.T) {
	ec := newFakeExecClient(func() bool { return true })
	ctx := context.Background()

	_, err := ec.Interactive(ctx, "default", "sandbox-1", []string{"/bin/bash"}, 80, 24)
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
