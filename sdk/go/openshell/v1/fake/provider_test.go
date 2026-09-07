// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// helper to build a minimal fake provider client for testing.
func newTestProviderClient() *fakeProviderClient {
	store := newobjectStore(providerName, copyProvider)
	return newFakeProviderClient(store, func() bool { return false })
}

// --- T015: Provider CRUD tests ---

func TestProvider_Create(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	p := &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{
			Credentials: map[string]string{"api_key": "sk-test"},
			Config:      map[string]string{"model": "gpt-4"},
		},
	}

	result, err := pc.Create(ctx, "default", p)
	require.NoError(t, err)
	assert.Equal(t, "openai", result.Name)
	assert.Equal(t, "openai", result.Type)
	assert.Equal(t, "sk-test", result.Spec.Credentials["api_key"])
	assert.NotZero(t, result.CreatedAt)
	assert.Equal(t, uint64(1), result.ResourceVersion)
}

func TestProvider_Create_AlreadyExists(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	p := &types.Provider{Name: "openai", Type: "openai"}
	_, err := pc.Create(ctx, "default", p)
	require.NoError(t, err)

	_, err = pc.Create(ctx, "default", p)
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err))
}

func TestProvider_Get(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, _ = pc.Create(ctx, "default", &types.Provider{Name: "openai", Type: "openai"})

	got, err := pc.Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "openai", got.Name)
}

func TestProvider_Get_NotFound(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, err := pc.Get(ctx, "default", "nonexistent")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestProvider_List_Empty(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	list, err := pc.List(ctx, "default")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestProvider_List(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, _ = pc.Create(ctx, "default", &types.Provider{Name: "openai", Type: "openai"})
	_, _ = pc.Create(ctx, "default", &types.Provider{Name: "anthropic", Type: "anthropic"})

	list, err := pc.List(ctx, "default")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestProvider_Update(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, _ = pc.Create(ctx, "default", &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-3.5"}},
	})

	updated, err := pc.Update(ctx, "default", &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-4"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", updated.Spec.Config["model"])
	assert.Equal(t, uint64(2), updated.ResourceVersion)
}

func TestProvider_Update_NotFound(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, err := pc.Update(ctx, "default", &types.Provider{Name: "nonexistent"})
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestProvider_Delete(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, _ = pc.Create(ctx, "default", &types.Provider{Name: "openai"})

	err := pc.Delete(ctx, "default", "openai")
	require.NoError(t, err)

	_, err = pc.Get(ctx, "default", "openai")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestProvider_Delete_Idempotent(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	err := pc.Delete(ctx, "default", "nonexistent")
	require.NoError(t, err)
}

func TestProvider_Ensure_CreatesIfMissing(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	p := &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-4"}},
	}

	result, err := pc.Ensure(ctx, "default", p)
	require.NoError(t, err)
	assert.Equal(t, "openai", result.Name)
	assert.Equal(t, "gpt-4", result.Spec.Config["model"])

	// Verify it was stored
	got, err := pc.Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", got.Spec.Config["model"])
}

func TestProvider_Ensure_UpdatesIfExists(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, _ = pc.Create(ctx, "default", &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-3.5"}},
	})

	result, err := pc.Ensure(ctx, "default", &types.Provider{
		Name: "openai",
		Type: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-4"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", result.Spec.Config["model"])
}

func TestProvider_DeepCopy_OnCreate(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	spec := types.ProviderSpec{
		Credentials:         map[string]string{"key": "secret"},
		Config:              map[string]string{"model": "gpt-4"},
		CredentialExpiresAt: map[string]time.Time{"key": time.Now()},
	}
	p := &types.Provider{
		Name:   "openai",
		Labels: map[string]string{"env": "test"},
		Spec:   spec,
	}

	result, err := pc.Create(ctx, "default", p)
	require.NoError(t, err)

	// Mutate inputs
	p.Labels["env"] = "mutated"
	p.Spec.Credentials["key"] = "mutated"
	p.Spec.Config["model"] = "mutated"

	got, err := pc.Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Labels["env"])
	assert.Equal(t, "secret", got.Spec.Credentials["key"])
	assert.Equal(t, "gpt-4", got.Spec.Config["model"])

	// Mutate returned object
	result.Labels["env"] = "mutated-return"
	got2, err := pc.Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "test", got2.Labels["env"])
}

func TestProvider_DeepCopy_OnGet(t *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	_, _ = pc.Create(ctx, "default", &types.Provider{
		Name: "openai",
		Spec: types.ProviderSpec{Config: map[string]string{"model": "gpt-4"}},
	})

	got, err := pc.Get(ctx, "default", "openai")
	require.NoError(t, err)

	got.Spec.Config["model"] = "mutated"

	got2, err := pc.Get(ctx, "default", "openai")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", got2.Spec.Config["model"])
}

// --- T020: Concurrent provider access tests ---

func TestProvider_ConcurrentCreateGetListDeleteEnsure(_ *testing.T) {
	pc := newTestProviderClient()
	ctx := context.Background()

	const goroutines = 10
	const opsPerGoroutine = 20

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				name := fmt.Sprintf("prov-%d-%d", id, j)
				p := &types.Provider{Name: name, Type: "test"}
				_, _ = pc.Create(ctx, "default", p)
				_, _ = pc.Get(ctx, "default", name)
				_, _ = pc.List(ctx, "default")
				_, _ = pc.Update(ctx, "default", &types.Provider{Name: name, Type: "updated"})
				_, _ = pc.Ensure(ctx, "default", &types.Provider{Name: name, Type: "ensured"})
				_ = pc.Delete(ctx, "default", name)
			}
		}(i)
	}
	wg.Wait()
}
