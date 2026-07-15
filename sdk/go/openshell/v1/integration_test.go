// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package v1

import (
	"context"
	"os"
	"testing"

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
	defer client.Close()

	t.Skip("TODO: Health().Check() is a stub until PR B lands")

	_, err = client.Health().Check(context.Background())
	require.NoError(t, err)
}

func TestIntegration_ProviderLifecycle(t *testing.T) {
	addr := gatewayAddress(t)

	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	defer client.Close()

	t.Skip("TODO: implement provider create/get/list/delete integration test")
}

func TestIntegration_SandboxLifecycle(t *testing.T) {
	addr := gatewayAddress(t)

	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	defer client.Close()

	t.Skip("TODO: implement sandbox create/wait-ready/delete integration test")
}

func TestIntegration_ExecRun(t *testing.T) {
	addr := gatewayAddress(t)

	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	defer client.Close()

	t.Skip("TODO: implement exec run integration test")
}

func TestIntegration_FileTransfer(t *testing.T) {
	addr := gatewayAddress(t)

	client, err := NewClient(Config{Address: addr})
	require.NoError(t, err)
	defer client.Close()

	t.Skip("TODO: implement file upload/download integration test")
}
