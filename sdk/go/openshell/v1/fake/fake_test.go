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

// --- T025: FakeClient Close tests ---

func TestFakeClient_Close(t *testing.T) {
	fc := NewClient()

	err := fc.Close()
	require.NoError(t, err)
}

func TestFakeClient_Close_Idempotent(t *testing.T) {
	fc := NewClient()

	err := fc.Close()
	require.NoError(t, err)

	err = fc.Close()
	require.NoError(t, err)
}

func TestFakeClient_Sandboxes_AfterClose(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	_ = fc.Close()

	_, err := fc.Sandboxes().Create(ctx, "default", "test", &types.SandboxSpec{}, nil)
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeClient_Providers_AfterClose(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	_ = fc.Close()

	_, err := fc.Providers().Create(ctx, "default", &types.Provider{Name: "test"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeClient_Health_AfterClose(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	_ = fc.Close()

	_, err := fc.Health().Check(ctx)
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeClient_Exec_AfterClose(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	_ = fc.Close()

	_, err := fc.Exec().Run(ctx, "default", "sandbox", []string{"echo"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeClient_Files_AfterClose(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	_ = fc.Close()

	err := fc.Files().Upload(ctx, "default", "sandbox", "/local", "/remote")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeClient_Watch_StoppedOnClose(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	w, err := fc.Sandboxes().Watch(ctx, "default", "")
	require.NoError(t, err)

	_ = fc.Close()

	// Channel should be closed after FakeClient.Close
	_, ok := <-w.ResultChan()
	assert.False(t, ok, "watcher channel should be closed after FakeClient.Close")
}

func TestFakeClient_WithHealthResult(t *testing.T) {
	custom := &types.HealthResult{Healthy: false, Version: "broken"}
	fc := NewClient(WithHealthResult(custom))
	ctx := context.Background()

	result, err := fc.Health().Check(ctx)
	require.NoError(t, err)
	assert.False(t, result.Healthy)
	assert.Equal(t, "broken", result.Version)
}

func TestFakeClient_SubClients(t *testing.T) {
	fc := NewClient()

	assert.NotNil(t, fc.Sandboxes())
	assert.NotNil(t, fc.Providers())
	assert.NotNil(t, fc.Exec())
	assert.NotNil(t, fc.Files())
	assert.NotNil(t, fc.Health())
}

// --- T013: Pre-seed tests ---

func TestFakeClient_AddSandbox(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	sb := &types.Sandbox{
		Name: "pre-seeded",
		Spec: types.SandboxSpec{LogLevel: "debug"},
		Status: types.SandboxStatus{
			Phase: types.SandboxReady,
		},
	}

	fc.AddSandbox("default", sb)

	got, err := fc.Sandboxes().Get(ctx, "default", "pre-seeded")
	require.NoError(t, err)
	assert.Equal(t, "pre-seeded", got.Name)
	assert.Equal(t, "debug", got.Spec.LogLevel)
	assert.Equal(t, types.SandboxReady, got.Status.Phase)
}

func TestFakeClient_AddSandbox_InList(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	fc.AddSandbox("default", &types.Sandbox{Name: "sb-1"})
	fc.AddSandbox("default", &types.Sandbox{Name: "sb-2"})

	list, err := fc.Sandboxes().List(ctx, "default")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestFakeClient_AddSandbox_NoWatchEvents(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	w, err := fc.Sandboxes().Watch(ctx, "default", "")
	require.NoError(t, err)
	defer w.Stop()

	fc.AddSandbox("default", &types.Sandbox{Name: "pre-seeded"})

	// No event should be received — AddSandbox bypasses the broadcaster
	select {
	case ev := <-w.ResultChan():
		t.Fatalf("unexpected event: %v", ev)
	default:
		// Good — no event received
	}
}

func TestFakeClient_AddSandbox_DeepCopy(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	sb := &types.Sandbox{
		Name:   "pre-seeded",
		Labels: map[string]string{"env": "test"},
	}
	fc.AddSandbox("default", sb)

	// Mutate the input
	sb.Labels["env"] = "mutated"

	got, err := fc.Sandboxes().Get(ctx, "default", "pre-seeded")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Labels["env"])
}

func TestFakeClient_AddProvider(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	p := &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-4"}},
	}

	fc.AddProvider("default", p)

	got, err := fc.Providers().Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "openai", got.Name)
	assert.Equal(t, "gpt-4", got.Spec.Config["model"])
}

func TestFakeClient_AddProvider_DeepCopy(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()

	p := &types.Provider{
		Name: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-4"}},
	}
	fc.AddProvider("default", p)

	// Mutate input
	p.Spec.Config["model"] = "mutated"

	got, err := fc.Providers().Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", got.Spec.Config["model"])
}
