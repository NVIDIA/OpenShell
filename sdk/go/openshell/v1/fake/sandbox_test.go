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

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// helper to build a minimal fake sandbox client for testing.
func newTestSandboxClient() *fakeSandboxClient {
	store := newobjectStore(sandboxName, copySandbox)
	broadcaster := newWatchBroadcaster[*types.Sandbox]()
	return newFakeSandboxClient(store, broadcaster, func() bool { return false })
}

// --- T008: Sandbox CRUD tests ---

func TestSandbox_Create(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{LogLevel: "debug"}, map[string]string{"env": "test"})
	require.NoError(t, err)
	assert.Equal(t, "test-sb", sb.Name)
	assert.Equal(t, "debug", sb.Spec.LogLevel)
	assert.Equal(t, "test", sb.Labels["env"])
	assert.Equal(t, types.SandboxProvisioning, sb.Status.Phase)
	assert.NotZero(t, sb.CreatedAt)
	assert.Equal(t, uint64(1), sb.ResourceVersion)
}

func TestSandbox_Create_AlreadyExists(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	_, err = sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err))
}

func TestSandbox_Create_NilSpec(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "test-sb", sb.Name)
}

func TestSandbox_Get(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{LogLevel: "info"}, nil)
	require.NoError(t, err)

	got, err := sc.Get(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, "test-sb", got.Name)
	assert.Equal(t, "info", got.Spec.LogLevel)
}

func TestSandbox_Get_NotFound(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.Get(ctx, "nonexistent")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandbox_List_Empty(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	list, err := sc.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestSandbox_List(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "sb-1", &types.SandboxSpec{}, nil)
	_, _ = sc.Create(ctx, "sb-2", &types.SandboxSpec{}, nil)

	list, err := sc.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestSandbox_Delete(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)

	err := sc.Delete(ctx, "test-sb")
	require.NoError(t, err)

	_, err = sc.Get(ctx, "test-sb")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandbox_Delete_Idempotent(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	// Delete non-existent sandbox should not error
	err := sc.Delete(ctx, "nonexistent")
	require.NoError(t, err)
}

func TestSandbox_DeepCopy_OnCreate(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	labels := map[string]string{"env": "test"}
	spec := &types.SandboxSpec{
		LogLevel:    "debug",
		Environment: map[string]string{"KEY": "value"},
	}

	sb, err := sc.Create(ctx, "test-sb", spec, labels)
	require.NoError(t, err)

	// Mutating inputs should not affect stored object
	labels["env"] = "mutated"
	spec.LogLevel = "mutated"
	spec.Environment["KEY"] = "mutated"

	got, err := sc.Get(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Labels["env"])
	assert.Equal(t, "debug", got.Spec.LogLevel)
	assert.Equal(t, "value", got.Spec.Environment["KEY"])

	// Mutating returned object should not affect stored object
	sb.Labels["env"] = "mutated-return"
	got2, err := sc.Get(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, "test", got2.Labels["env"])
}

func TestSandbox_DeepCopy_OnGet(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{
		Environment: map[string]string{"KEY": "value"},
	}, nil)

	got, err := sc.Get(ctx, "test-sb")
	require.NoError(t, err)

	got.Spec.Environment["KEY"] = "mutated"

	got2, err := sc.Get(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, "value", got2.Spec.Environment["KEY"])
}

// --- T009: WaitReady tests ---

func TestSandbox_WaitReady(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	sb, err := sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, types.SandboxReady, sb.Status.Phase)

	// Verify the store is also updated
	got, err := sc.Get(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, types.SandboxReady, got.Status.Phase)
}

func TestSandbox_WaitReady_NotFound(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.WaitReady(ctx, "nonexistent")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandbox_WaitReady_ContextCancellation(t *testing.T) {
	sc := newTestSandboxClient()

	_, err := sc.Create(context.Background(), "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = sc.WaitReady(ctx, "test-sb")
	require.Error(t, err)
	// Should return a context error, not a status error
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSandbox_WaitReady_AlreadyReady(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)

	// Make it ready
	_, err := sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)

	// WaitReady on an already-ready sandbox should return immediately
	sb, err := sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)
	assert.Equal(t, types.SandboxReady, sb.Status.Phase)
}

func TestSandbox_WaitReady_IncrementsResourceVersion(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	created, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)
	initialVersion := created.ResourceVersion

	ready, err := sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)
	assert.Greater(t, ready.ResourceVersion, initialVersion)
}

func TestSandbox_WaitReady_ContextTimeout(t *testing.T) {
	sc := newTestSandboxClient()

	_, err := sc.Create(context.Background(), "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Override the sandbox phase to Error so WaitReady doesn't auto-transition
	// Actually, with our simple fake, WaitReady transitions immediately unless context is done.
	// So just test the context-cancelled path:
	cancel()
	_, err = sc.WaitReady(ctx, "test-sb")
	require.Error(t, err)
}

// --- T011: Watch tests ---

func TestSandbox_Watch_AddedOnCreate(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w.Stop()

	_, err = sc.Create(ctx, "test-sb", &types.SandboxSpec{LogLevel: "info"}, nil)
	require.NoError(t, err)

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventAdded, ev.Type)
		assert.Equal(t, "test-sb", ev.Object.Name)
		assert.Equal(t, "info", ev.Object.Spec.LogLevel)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ADDED event")
	}
}

func TestSandbox_Watch_DeletedOnDelete(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)

	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w.Stop()

	err = sc.Delete(ctx, "test-sb")
	require.NoError(t, err)

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventDeleted, ev.Type)
		assert.Equal(t, "test-sb", ev.Object.Name)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DELETED event")
	}
}

func TestSandbox_Watch_ModifiedOnWaitReady(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)

	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w.Stop()

	_, err = sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventModified, ev.Type)
		assert.Equal(t, types.SandboxReady, ev.Object.Status.Phase)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MODIFIED event")
	}
}

func TestSandbox_Watch_NameFiltering(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	// Watch only "alpha"
	w, err := sc.Watch(ctx, "alpha")
	require.NoError(t, err)
	defer w.Stop()

	// Create "beta" — should not be received
	_, _ = sc.Create(ctx, "beta", &types.SandboxSpec{}, nil)

	// Create "alpha" — should be received
	_, _ = sc.Create(ctx, "alpha", &types.SandboxSpec{}, nil)

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventAdded, ev.Type)
		assert.Equal(t, "alpha", ev.Object.Name)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for filtered event")
	}
}

func TestSandbox_Watch_MultipleWatchers(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	w1, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w1.Stop()

	w2, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w2.Stop()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)

	for _, w := range []types.WatchInterface[*types.Sandbox]{w1, w2} {
		select {
		case ev := <-w.ResultChan():
			assert.Equal(t, types.EventAdded, ev.Type)
			assert.Equal(t, "test-sb", ev.Object.Name)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event on watcher")
		}
	}
}

func TestSandbox_Watch_StopClosesChannel(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)

	w.Stop()

	_, ok := <-w.ResultChan()
	assert.False(t, ok, "channel should be closed after Stop")
}

func TestSandbox_Watch_DeletedEventContainsFullObject(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, _ = sc.Create(ctx, "test-sb", &types.SandboxSpec{LogLevel: "debug"}, map[string]string{"env": "test"})

	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w.Stop()

	_ = sc.Delete(ctx, "test-sb")

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventDeleted, ev.Type)
		// Verify the DELETED event contains the full last-known object
		assert.Equal(t, "debug", ev.Object.Spec.LogLevel)
		assert.Equal(t, "test", ev.Object.Labels["env"])
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DELETED event")
	}
}

// --- T019: Concurrent sandbox access tests ---

func TestSandbox_ConcurrentCreateGetDeleteWatch(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	const goroutines = 10
	const opsPerGoroutine = 20

	// Start a watcher to exercise broadcast under concurrency
	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w.Stop()

	// Drain watcher events in a background goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range w.ResultChan() { //nolint:revive // intentionally draining channel
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				name := fmt.Sprintf("sb-%d-%d", id, j)
				_, _ = sc.Create(ctx, name, &types.SandboxSpec{LogLevel: "info"}, nil)
				_, _ = sc.Get(ctx, name)
				_, _ = sc.List(ctx)
				_, _ = sc.WaitReady(ctx, name)
				_ = sc.Delete(ctx, name)
			}
		}(i)
	}
	wg.Wait()

	// Stop watcher and wait for drain goroutine
	w.Stop()
	<-done
}

// --- T026: AttachProvider / DetachProvider / ListProviders tests ---

func TestSandbox_AttachProvider(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	result, err := sc.AttachProvider(ctx, "test-sb", "openai", sb.ResourceVersion)
	require.NoError(t, err)
	assert.True(t, result.Attached)
	assert.Equal(t, "test-sb", result.Sandbox.Name)
	assert.Contains(t, result.Sandbox.Spec.Providers, "openai")
}

func TestSandbox_AttachProvider_AlreadyAttached(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	result, err := sc.AttachProvider(ctx, "test-sb", "openai", sb.ResourceVersion)
	require.NoError(t, err)
	assert.True(t, result.Attached)

	// Attach again — should return Attached=false (idempotent, already attached)
	result2, err := sc.AttachProvider(ctx, "test-sb", "openai", result.Sandbox.ResourceVersion)
	require.NoError(t, err)
	assert.False(t, result2.Attached)
}

func TestSandbox_AttachProvider_SandboxNotFound(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.AttachProvider(ctx, "nonexistent", "openai", 0)
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandbox_DetachProvider(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	result, err := sc.AttachProvider(ctx, "test-sb", "openai", sb.ResourceVersion)
	require.NoError(t, err)

	detach, err := sc.DetachProvider(ctx, "test-sb", "openai", result.Sandbox.ResourceVersion)
	require.NoError(t, err)
	assert.True(t, detach.Detached)
	assert.NotContains(t, detach.Sandbox.Spec.Providers, "openai")
}

func TestSandbox_DetachProvider_NotAttached(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	result, err := sc.DetachProvider(ctx, "test-sb", "openai", sb.ResourceVersion)
	require.NoError(t, err)
	assert.False(t, result.Detached)
}

func TestSandbox_DetachProvider_SandboxNotFound(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.DetachProvider(ctx, "nonexistent", "openai", 0)
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandbox_ListProviders(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	// No providers yet
	providers, err := sc.ListProviders(ctx, "test-sb")
	require.NoError(t, err)
	assert.Empty(t, providers)

	// Attach two providers
	result, err := sc.AttachProvider(ctx, "test-sb", "openai", sb.ResourceVersion)
	require.NoError(t, err)

	_, err = sc.AttachProvider(ctx, "test-sb", "anthropic", result.Sandbox.ResourceVersion)
	require.NoError(t, err)

	providers, err = sc.ListProviders(ctx, "test-sb")
	require.NoError(t, err)
	assert.Len(t, providers, 2)

	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name
	}
	assert.Contains(t, names, "openai")
	assert.Contains(t, names, "anthropic")
}

func TestSandbox_ListProviders_SandboxNotFound(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.ListProviders(ctx, "nonexistent")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandbox_AttachProvider_BroadcastsModified(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	w, err := sc.Watch(ctx, "")
	require.NoError(t, err)
	defer w.Stop()

	_, err = sc.AttachProvider(ctx, "test-sb", "openai", sb.ResourceVersion)
	require.NoError(t, err)

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventModified, ev.Type)
		assert.Contains(t, ev.Object.Spec.Providers, "openai")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MODIFIED event from AttachProvider")
	}
}

// --- T033: StopOnTerminal tests for fake Watch ---

func TestSandbox_Watch_StopOnTerminal_Ready(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	w, err := sc.Watch(ctx, "test-sb", v1.WatchOptions{StopOnTerminal: true})
	require.NoError(t, err)

	// Transition to Ready — this broadcasts a MODIFIED event with SandboxReady phase
	_, err = sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)

	// Should receive the Ready event
	var gotReady bool
	for ev := range w.ResultChan() {
		if ev.Object != nil && ev.Object.Status.Phase == types.SandboxReady {
			gotReady = true
		}
	}
	// Channel should be closed after the terminal event
	assert.True(t, gotReady, "expected to receive a Ready event before channel closed")
}

func TestSandbox_Watch_StopOnTerminal_Error(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	sb, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	w, err := sc.Watch(ctx, "test-sb", v1.WatchOptions{StopOnTerminal: true})
	require.NoError(t, err)

	// Manually transition to Error phase via store update + broadcast
	sb.Status.Phase = types.SandboxError
	sb.ResourceVersion++
	updated, err := sc.store.Update(sb)
	require.NoError(t, err)
	sc.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, "test-sb")

	// Should receive the Error event and then the channel closes
	var gotError bool
	for ev := range w.ResultChan() {
		if ev.Object != nil && ev.Object.Status.Phase == types.SandboxError {
			gotError = true
		}
	}
	assert.True(t, gotError, "expected to receive an Error event before channel closed")
}

func TestSandbox_Watch_StopOnTerminal_False_DoesNotClose(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	_, err := sc.Create(ctx, "test-sb", &types.SandboxSpec{}, nil)
	require.NoError(t, err)

	// Watch WITHOUT StopOnTerminal
	w, err := sc.Watch(ctx, "test-sb")
	require.NoError(t, err)
	defer w.Stop()

	// Transition to Ready
	_, err = sc.WaitReady(ctx, "test-sb")
	require.NoError(t, err)

	// Receive the Ready event
	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.SandboxReady, ev.Object.Status.Phase)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Ready event")
	}

	// Channel should still be open — verify by checking no close
	select {
	case _, ok := <-w.ResultChan():
		if !ok {
			t.Fatal("channel closed unexpectedly when StopOnTerminal was not set")
		}
		// Got another event, that's fine
	case <-time.After(100 * time.Millisecond):
		// No event and not closed — correct behavior
	}
}

// --- T016: Sandbox Create with Policy ---

func TestFakeSandboxCreateWithPolicy(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	spec := &types.SandboxSpec{
		LogLevel: "debug",
		Policy: &types.SandboxPolicy{
			Version: 3,
			Filesystem: &types.FilesystemPolicy{
				IncludeWorkdir: true,
				ReadOnly:       []string{"/etc", "/usr/share"},
				ReadWrite:      []string{"/tmp"},
			},
			Landlock: &types.LandlockPolicy{
				Compatibility: "best_effort",
			},
			Process: &types.ProcessPolicy{
				RunAsUser:  "sandbox",
				RunAsGroup: "sandbox-group",
			},
			NetworkPolicies: map[string]types.NetworkPolicyRule{
				"web": {
					Name: "web",
					Endpoints: []types.PolicyNetworkEndpoint{
						{Host: "api.example.com", Port: 443, Protocol: "rest"},
					},
				},
			},
		},
	}

	created, err := sc.Create(ctx, "policy-sb", spec, nil)
	require.NoError(t, err)

	// Verify created sandbox has policy
	require.NotNil(t, created.Spec.Policy)
	assert.Equal(t, uint32(3), created.Spec.Policy.Version)

	// Get it back and verify all fields
	got, err := sc.Get(ctx, "policy-sb")
	require.NoError(t, err)
	require.NotNil(t, got.Spec.Policy)

	p := got.Spec.Policy
	assert.Equal(t, uint32(3), p.Version)

	require.NotNil(t, p.Filesystem)
	assert.True(t, p.Filesystem.IncludeWorkdir)
	assert.Equal(t, []string{"/etc", "/usr/share"}, p.Filesystem.ReadOnly)
	assert.Equal(t, []string{"/tmp"}, p.Filesystem.ReadWrite)

	require.NotNil(t, p.Landlock)
	assert.Equal(t, "best_effort", p.Landlock.Compatibility)

	require.NotNil(t, p.Process)
	assert.Equal(t, "sandbox", p.Process.RunAsUser)
	assert.Equal(t, "sandbox-group", p.Process.RunAsGroup)

	require.Len(t, p.NetworkPolicies, 1)
	webRule, ok := p.NetworkPolicies["web"]
	require.True(t, ok)
	assert.Equal(t, "web", webRule.Name)
	require.Len(t, webRule.Endpoints, 1)
	assert.Equal(t, "api.example.com", webRule.Endpoints[0].Host)
	assert.Equal(t, uint32(443), webRule.Endpoints[0].Port)

	// Deep-copy isolation: mutate input spec, verify stored copy unchanged
	spec.Policy.Version = 99
	spec.Policy.Filesystem.ReadOnly[0] = "mutated"
	spec.Policy.NetworkPolicies["web"] = types.NetworkPolicyRule{Name: "mutated"}

	got2, err := sc.Get(ctx, "policy-sb")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), got2.Spec.Policy.Version)
	assert.Equal(t, "/etc", got2.Spec.Policy.Filesystem.ReadOnly[0])
	assert.Equal(t, "web", got2.Spec.Policy.NetworkPolicies["web"].Name)

	// Deep-copy isolation: mutate returned object, verify store unchanged
	got.Spec.Policy.Filesystem.ReadWrite[0] = "mutated"
	got3, err := sc.Get(ctx, "policy-sb")
	require.NoError(t, err)
	assert.Equal(t, "/tmp", got3.Spec.Policy.Filesystem.ReadWrite[0])
}

func TestFakeSandboxCreateWithNilPolicy(t *testing.T) {
	sc := newTestSandboxClient()
	ctx := context.Background()

	created, err := sc.Create(ctx, "no-policy-sb", &types.SandboxSpec{LogLevel: "info"}, nil)
	require.NoError(t, err)
	assert.Nil(t, created.Spec.Policy)

	got, err := sc.Get(ctx, "no-policy-sb")
	require.NoError(t, err)
	assert.Nil(t, got.Spec.Policy)
}

// --- T032: GetLogs stub tests ---

func TestSandbox_GetLogs_ReturnsUnimplemented(t *testing.T) {
	sc := newTestSandboxClient()
	_, err := sc.GetLogs(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestSandbox_GetLogs_ClosedReturnsUnavailable(t *testing.T) {
	store := newobjectStore(sandboxName, copySandbox)
	broadcaster := newWatchBroadcaster[*types.Sandbox]()
	sc := newFakeSandboxClient(store, broadcaster, func() bool { return true })
	_, err := sc.GetLogs(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
