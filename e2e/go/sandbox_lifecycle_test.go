// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

func TestSandboxCRUDAndExec(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	name := uniqueName("sb-crud")
	sb, err := client.Sandboxes().Create(ctx, "default", name, &v1.SandboxSpec{
		Policy: defaultPolicy(),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		require.NoError(t, client.Sandboxes().Delete(cleanupCtx, "default", name))
	})
	require.NotEmpty(t, sb.ID)
	require.Equal(t, name, sb.Name)

	ready, err := client.Sandboxes().WaitReady(ctx, "default", name)
	require.NoError(t, err)
	requireReadySandbox(t, ready, sb.ID)

	fetched, err := client.Sandboxes().Get(ctx, "default", name)
	require.NoError(t, err)
	require.Equal(t, sb.ID, fetched.ID)

	sandboxes, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{PageSize: 100})
	require.NoError(t, err)
	require.True(t, containsID(sandboxes, sb.ID))

	result, err := client.Exec().Run(ctx, "default", name, []string{"sh", "-c", "printf sandbox-ok"}, v1.ExecOptions{})
	require.NoError(t, err)
	require.Equal(t, 0, result.ExitCode)
	require.Equal(t, "sandbox-ok", string(result.Stdout))

	// Exec launches share the same sandbox filesystem across calls.
	writeResult, err := client.Exec().Run(ctx, "default", name,
		[]string{"sh", "-c", "echo persisted > /sandbox/exec-persistence.txt"}, v1.ExecOptions{})
	require.NoError(t, err)
	require.Equal(t, 0, writeResult.ExitCode)

	readResult, err := client.Exec().Run(ctx, "default", name,
		[]string{"cat", "/sandbox/exec-persistence.txt"}, v1.ExecOptions{})
	require.NoError(t, err)
	require.Equal(t, 0, readResult.ExitCode)
	require.Equal(t, "persisted\n", string(readResult.Stdout))
}

func TestSandboxListScopedAndAllWorkspaces(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	otherWorkspace := uniqueName("list-ws")
	_, err := client.Workspaces().Create(ctx, otherWorkspace, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		// Sandbox deletion (registered after this cleanup, so it runs first
		// under LIFO ordering) only asynchronously clears the store row via a
		// background watcher. Workspace deletion is blocked while any
		// sandbox still references it, so wait for the workspace to drain
		// before attempting the delete.
		waitForWorkspaceSandboxesGone(cleanupCtx, client, otherWorkspace)
		_ = client.Workspaces().Delete(cleanupCtx, otherWorkspace)
	})

	defaultName := uniqueName("ls-def")
	defaultSandbox, err := client.Sandboxes().Create(ctx, "default", defaultName, &v1.SandboxSpec{}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = client.Sandboxes().Delete(cleanupCtx, "default", defaultName)
	})

	otherName := uniqueName("ls-oth")
	otherSandbox, err := client.Sandboxes().Create(ctx, otherWorkspace, otherName, &v1.SandboxSpec{}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = client.Sandboxes().Delete(cleanupCtx, otherWorkspace, otherName)
	})

	defaultList, err := client.Sandboxes().ListAll(ctx, "default")
	require.NoError(t, err)
	require.True(t, containsID(defaultList, defaultSandbox.ID))
	require.False(t, containsID(defaultList, otherSandbox.ID))

	otherList, err := client.Sandboxes().ListAll(ctx, otherWorkspace)
	require.NoError(t, err)
	require.True(t, containsID(otherList, otherSandbox.ID))
	require.False(t, containsID(otherList, defaultSandbox.ID))

	allList, err := client.Sandboxes().ListAll(ctx, "", v1.ListOptions{AllWorkspaces: true})
	require.NoError(t, err)
	require.True(t, containsID(allList, defaultSandbox.ID))
	require.True(t, containsID(allList, otherSandbox.ID))
}

func TestSandboxLabelsAndSelectors(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := uniqueName("lbl")
	jobA := fmt.Sprintf("%s-a", suffix)
	jobB := fmt.Sprintf("%s-b", suffix)
	groupSelector := fmt.Sprintf("aiq-test=%s", suffix)
	primarySelector := fmt.Sprintf("aiq-test=%s,role=primary", suffix)

	refA, err := client.Sandboxes().Create(ctx, "default", jobA, &v1.SandboxSpec{},
		map[string]string{"aiq-test": suffix, "role": "primary"})
	require.NoError(t, err)
	deletedA := false
	t.Cleanup(func() {
		if deletedA {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = client.Sandboxes().Delete(cleanupCtx, "default", jobA)
	})

	_, err = client.Sandboxes().Create(ctx, "default", jobB, &v1.SandboxSpec{},
		map[string]string{"aiq-test": suffix, "role": "secondary"})
	require.NoError(t, err)
	deletedB := false
	t.Cleanup(func() {
		if deletedB {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = client.Sandboxes().Delete(cleanupCtx, "default", jobB)
	})

	require.Equal(t, "primary", refA.Labels["role"])

	fetchedA, err := client.Sandboxes().Get(ctx, "default", jobA)
	require.NoError(t, err)
	require.Equal(t, "primary", fetchedA.Labels["role"])

	fetchedB, err := client.Sandboxes().Get(ctx, "default", jobB)
	require.NoError(t, err)
	require.Equal(t, "secondary", fetchedB.Labels["role"])

	primaryOnly, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{LabelSelector: primarySelector})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{jobA}, names(primaryOnly))

	both, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{LabelSelector: groupSelector})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{jobA, jobB}, names(both))

	require.NoError(t, client.Sandboxes().Delete(ctx, "default", jobA))
	deletedA = true

	remaining := pollUntilNamesMatch(t, ctx, func() []string {
		list, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{LabelSelector: groupSelector})
		require.NoError(t, err)
		return names(list)
	}, []string{jobB})
	require.ElementsMatch(t, []string{jobB}, remaining)

	require.NoError(t, client.Sandboxes().Delete(ctx, "default", jobB))
	deletedB = true

	empty := pollUntilNamesMatch(t, ctx, func() []string {
		list, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{LabelSelector: groupSelector})
		require.NoError(t, err)
		return names(list)
	}, []string{})
	require.Empty(t, empty)
}

// pollUntilNamesMatch waits for fetch to report exactly the expected set of
// sandbox names. Sandbox deletion removes the gateway's list-visible record
// asynchronously (via a background watcher draining the compute driver's
// deletion event), so a List call issued immediately after Delete can still
// return the just-deleted sandbox for a short window.
func pollUntilNamesMatch(t *testing.T, ctx context.Context, fetch func() []string, expected []string) []string {
	t.Helper()
	deadline := time.Now().Add(35 * time.Second)
	for {
		values := fetch()
		if elementsMatch(values, expected) {
			return values
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for sandbox list %v, last observed %v", expected, values)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done while polling: %v", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func elementsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		counts[v]--
	}
	for _, c := range counts {
		if c != 0 {
			return false
		}
	}
	return true
}

// waitForWorkspaceSandboxesGone polls until a workspace has no sandboxes
// left, up to a 20s deadline. It is best-effort: cleanup proceeds regardless
// of whether the deadline is reached, since the subsequent workspace delete
// is itself best-effort in callers of this helper.
func waitForWorkspaceSandboxesGone(ctx context.Context, client *v1.Client, workspace string) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		list, err := client.Sandboxes().ListAll(ctx, workspace)
		if err == nil && len(list) == 0 {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func containsID(sandboxes []*v1.Sandbox, id string) bool {
	for _, sb := range sandboxes {
		if sb.ID == id {
			return true
		}
	}
	return false
}

func names(sandboxes []*v1.Sandbox) []string {
	result := make([]string, 0, len(sandboxes))
	for _, sb := range sandboxes {
		result = append(result, sb.Name)
	}
	return result
}
