// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package v1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func gatewayAddress(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("OPENSHELL_GATEWAY_ADDRESS")
	if addr == "" {
		t.Skip("OPENSHELL_GATEWAY_ADDRESS not set")
	}
	return addr
}

func TestIntegration_HealthCheck(t *testing.T) {
	addr := gatewayAddress(t)

	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	_, err = client.Health().Check(context.Background())
	require.NoError(t, err)
}

func TestIntegration_SandboxExecSmoke(t *testing.T) {
	addr := gatewayAddress(t)
	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	image := os.Getenv("OPENSHELL_GO_SDK_TEST_IMAGE")
	if image == "" {
		image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
	}
	name := fmt.Sprintf("go-smoke-%09d", time.Now().UnixNano()%1_000_000_000)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_, err = client.Sandboxes().Create(ctx, "default", name, &SandboxSpec{
		Template: &SandboxTemplate{Image: image},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		require.NoError(t, client.Sandboxes().Delete(cleanupCtx, "default", name))
	})

	_, err = client.Sandboxes().WaitReady(ctx, "default", name)
	require.NoError(t, err)
	result, err := client.Exec().Run(ctx, "default", name,
		[]string{"sh", "-c", "printf openshell-go-sdk-smoke"}, ExecOptions{})
	require.NoError(t, err)
	require.Equal(t, 0, result.ExitCode)
	require.Equal(t, "openshell-go-sdk-smoke", string(result.Stdout))
	require.Empty(t, result.Stderr)
}

func TestIntegration_FileTransfer(t *testing.T) {
	addr := gatewayAddress(t)

	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	defer client.Close()

	err = client.Files().Upload(context.Background(), "default", "unused", "missing", "/tmp/missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrTransportNotAvailable))
}
