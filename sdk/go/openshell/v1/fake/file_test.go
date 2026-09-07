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

// --- T022: File stub tests ---

func TestFile_Upload_Unimplemented(t *testing.T) {
	fc := newFakeFileClient(func() bool { return false })
	ctx := context.Background()

	err := fc.Upload(ctx, "default", "test-sandbox", "/local/file.txt", "/remote/file.txt")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFile_Download_Unimplemented(t *testing.T) {
	fc := newFakeFileClient(func() bool { return false })
	ctx := context.Background()

	err := fc.Download(ctx, "default", "test-sandbox", "/remote/file.txt", "/local/file.txt")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFile_Upload_ClosedClient(t *testing.T) {
	fc := newFakeFileClient(func() bool { return true })
	ctx := context.Background()

	err := fc.Upload(ctx, "default", "test-sandbox", "/local/file.txt", "/remote/file.txt")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFile_Download_ClosedClient(t *testing.T) {
	fc := newFakeFileClient(func() bool { return true })
	ctx := context.Background()

	err := fc.Download(ctx, "default", "test-sandbox", "/remote/file.txt", "/local/file.txt")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
