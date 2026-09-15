// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Provider credentials are fetched at runtime by the sandbox supervisor.
// Sandboxed child processes must see placeholder values (never raw secrets),
// and only when a provider is actually attached to the sandbox.
package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

func isPlaceholderForEnvKey(value, key string) bool {
	const prefix = "openshell:resolve:env:"
	if value == prefix+key {
		return true
	}
	token, ok := strings.CutPrefix(value, prefix)
	if !ok {
		return false
	}
	return strings.HasPrefix(token, "v") && strings.HasSuffix(token, "_"+key)
}

// requireProviderResponse checks the stable public fields returned by provider
// APIs. Credentials are write-only and intentionally omitted from Go SDK
// provider responses.
func requireProviderResponse(t *testing.T, provider *v1.Provider, workspace, name, providerType string) {
	t.Helper()
	require.NotNil(t, provider)
	require.NotEmpty(t, provider.ID)
	require.Equal(t, workspace, provider.Workspace)
	require.Equal(t, name, provider.Name)
	require.Equal(t, providerType, provider.Type)
	require.NotZero(t, provider.ResourceVersion)
	require.Empty(t, provider.Spec.Credentials)
}

func requireReadySandbox(t *testing.T, sandbox *v1.Sandbox, id string) {
	t.Helper()
	require.NotNil(t, sandbox)
	require.Equal(t, id, sandbox.ID)
	require.Equal(t, v1.SandboxReady, sandbox.Status.Phase)
}

func readEnvVar(ctx context.Context, client *v1.Client, workspace, sandboxName, key string) (string, error) {
	result, err := client.Exec().Run(ctx, workspace, sandboxName,
		[]string{"sh", "-c", fmt.Sprintf(`printf "%%s" "${%s:-NOT_SET}"`, key)}, v1.ExecOptions{})
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("exec exited %d: %s", result.ExitCode, string(result.Stderr))
	}
	return string(result.Stdout), nil
}

func deleteProviderIgnoreNotFound(ctx context.Context, t *testing.T, client *v1.Client, workspace, name string) {
	t.Helper()
	err := client.Providers().Delete(ctx, workspace, name)
	if err != nil && !v1.IsNotFound(err) {
		require.NoError(t, err)
	}
}

// detachProviderBestEffort clears a provider from a sandbox's spec before the
// sandbox is deleted. Sandbox deletion removes the gateway's Sandbox record
// asynchronously (via a background watcher), so a provider-delete cleanup
// racing right behind a sandbox-delete cleanup can still see the sandbox as
// attached and fail with a conflict unless the attachment is cleared
// synchronously first.
func detachProviderBestEffort(ctx context.Context, client *v1.Client, workspace, sandboxName, providerName string) {
	if current, err := client.Sandboxes().Get(ctx, workspace, sandboxName); err == nil {
		_, _ = client.Sandboxes().DetachProvider(ctx, workspace, sandboxName, providerName, current.ResourceVersion)
	}
}

// attachProviderRetry attaches a provider to a sandbox, retrying with a
// freshly fetched resource version whenever the gateway reports a
// concurrent-modification conflict (e.g. a status update racing the
// optimistic-concurrency check between Get and AttachProvider).
func attachProviderRetry(ctx context.Context, t *testing.T, client *v1.Client, workspace, sandboxName, providerName string) *v1.AttachProviderResult {
	t.Helper()
	for {
		current, err := client.Sandboxes().Get(ctx, workspace, sandboxName)
		require.NoError(t, err)
		result, err := client.Sandboxes().AttachProvider(ctx, workspace, sandboxName, providerName, current.ResourceVersion)
		if err == nil {
			return result
		}
		if !v1.IsConflict(err) {
			require.NoError(t, err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done while retrying attach provider: %v", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// detachProviderRetry mirrors attachProviderRetry for detach.
func detachProviderRetry(ctx context.Context, t *testing.T, client *v1.Client, workspace, sandboxName, providerName string) *v1.DetachProviderResult {
	t.Helper()
	for {
		current, err := client.Sandboxes().Get(ctx, workspace, sandboxName)
		require.NoError(t, err)
		result, err := client.Sandboxes().DetachProvider(ctx, workspace, sandboxName, providerName, current.ResourceVersion)
		if err == nil {
			return result
		}
		if !v1.IsConflict(err) {
			require.NoError(t, err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done while retrying detach provider: %v", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestProviderCredentialsAvailableAsEnvVar(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	providerName := uniqueName("prov-env")
	const secret = "sk-e2e-test-key-12345"
	provider, err := client.Providers().Create(ctx, "default", &v1.Provider{
		Name: providerName,
		Type: "claude",
		Spec: v1.ProviderSpec{Credentials: map[string]string{"ANTHROPIC_API_KEY": secret}},
	})
	require.NoError(t, err)
	requireProviderResponse(t, provider, "default", providerName, "claude-code")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deleteProviderIgnoreNotFound(cleanupCtx, t, client, "default", providerName)
	})

	sandboxName := uniqueName("sb-penv")
	sandbox, err := client.Sandboxes().Create(ctx, "default", sandboxName, &v1.SandboxSpec{
		Policy:    defaultPolicy(),
		Providers: []string{providerName},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		detachProviderBestEffort(cleanupCtx, client, "default", sandboxName, providerName)
		require.NoError(t, client.Sandboxes().Delete(cleanupCtx, "default", sandboxName))
	})

	ready, err := client.Sandboxes().WaitReady(ctx, "default", sandboxName)
	require.NoError(t, err)
	requireReadySandbox(t, ready, sandbox.ID)

	value, err := readEnvVar(ctx, client, "default", sandboxName, "ANTHROPIC_API_KEY")
	require.NoError(t, err)
	require.True(t, isPlaceholderForEnvKey(value, "ANTHROPIC_API_KEY"), "expected a placeholder, got %q", value)
	require.NotEqual(t, secret, value)
}

func TestProfilelessProviderCreationIsRejected(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	providerName := uniqueName("prov-generic")
	_, err := client.Providers().Create(ctx, "default", &v1.Provider{
		Name: providerName,
		Type: "generic",
		Spec: v1.ProviderSpec{Credentials: map[string]string{
			"CUSTOM_SERVICE_TOKEN": "token-generic-123",
			"CUSTOM_SERVICE_URL":   "https://internal.example.test/api",
		}},
	})
	require.Error(t, err)
	require.True(t, v1.IsInvalidArgument(err), "expected InvalidArgument, got: %v", err)
	require.ErrorContains(t, err, "provider profile 'generic' was not found")
}

func TestAttachDetachProviderUpdatesCredentials(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	providerName := uniqueName("prov-attach")
	provider, err := client.Providers().Create(ctx, "default", &v1.Provider{
		Name: providerName,
		Type: "nvidia",
		Spec: v1.ProviderSpec{Credentials: map[string]string{"NVIDIA_API_KEY": "nvapi-e2e-test-key"}},
	})
	require.NoError(t, err)
	requireProviderResponse(t, provider, "default", providerName, "nvidia")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deleteProviderIgnoreNotFound(cleanupCtx, t, client, "default", providerName)
	})

	sandboxName := uniqueName("sb-patt")
	sandbox, err := client.Sandboxes().Create(ctx, "default", sandboxName, &v1.SandboxSpec{Policy: defaultPolicy()}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		detachProviderBestEffort(cleanupCtx, client, "default", sandboxName, providerName)
		require.NoError(t, client.Sandboxes().Delete(cleanupCtx, "default", sandboxName))
	})

	ready, err := client.Sandboxes().WaitReady(ctx, "default", sandboxName)
	require.NoError(t, err)
	requireReadySandbox(t, ready, sandbox.ID)

	value, err := readEnvVar(ctx, client, "default", sandboxName, "NVIDIA_API_KEY")
	require.NoError(t, err)
	require.Equal(t, "NOT_SET", value)

	attachResult := attachProviderRetry(ctx, t, client, "default", sandboxName, providerName)
	require.True(t, attachResult.Attached)

	value = pollUntil(t, ctx, func() string {
		v, err := readEnvVar(ctx, client, "default", sandboxName, "NVIDIA_API_KEY")
		require.NoError(t, err)
		return v
	}, func(v string) bool { return v != "NOT_SET" })
	require.True(t, isPlaceholderForEnvKey(value, "NVIDIA_API_KEY"), "expected a placeholder, got %q", value)

	detachResult := detachProviderRetry(ctx, t, client, "default", sandboxName, providerName)
	require.True(t, detachResult.Detached)

	value = pollUntil(t, ctx, func() string {
		v, err := readEnvVar(ctx, client, "default", sandboxName, "NVIDIA_API_KEY")
		require.NoError(t, err)
		return v
	}, func(v string) bool { return v == "NOT_SET" })
	require.Equal(t, "NOT_SET", value)
}

func TestProviderCRUDResponseContract(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	providerName := uniqueName("prov-crud")
	const secret = "sk-e2e-provider-crud-12345"
	created, err := client.Providers().Create(ctx, "default", &v1.Provider{
		Name:   providerName,
		Type:   "claude",
		Labels: map[string]string{"e2e": "provider-response-contract"},
		Spec: v1.ProviderSpec{
			Credentials: map[string]string{"ANTHROPIC_API_KEY": secret},
		},
	})
	require.NoError(t, err)
	requireProviderResponse(t, created, "default", providerName, "claude-code")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deleteProviderIgnoreNotFound(cleanupCtx, t, client, "default", providerName)
	})
	require.Equal(t, "provider-response-contract", created.Labels["e2e"])

	fetched, err := client.Providers().Get(ctx, "default", providerName)
	require.NoError(t, err)
	requireProviderResponse(t, fetched, "default", providerName, "claude-code")
	require.Equal(t, created.ID, fetched.ID)

	updatedInput := *fetched
	// Get omits write-only credentials, so leave them unchanged in this update.
	updatedInput.Spec.Credentials = nil
	updatedInput.Spec.Config = map[string]string{"e2e-response-contract": "updated"}
	updated, err := client.Providers().Update(ctx, "default", &updatedInput)
	require.NoError(t, err)
	requireProviderResponse(t, updated, "default", providerName, "claude-code")
	require.Equal(t, "updated", updated.Spec.Config["e2e-response-contract"])
	require.Greater(t, updated.ResourceVersion, fetched.ResourceVersion)

	providers, err := client.Providers().ListAll(ctx, "default")
	require.NoError(t, err)
	for _, listed := range providers {
		if listed.Name == providerName {
			requireProviderResponse(t, listed, "default", providerName, "claude-code")
			require.Equal(t, updated.ID, listed.ID)
			require.Equal(t, "updated", listed.Spec.Config["e2e-response-contract"])
			return
		}
	}
	t.Fatalf("expected provider %q in List response", providerName)
}

// pollUntil calls fetch until predicate is satisfied or ctx carries a
// deadline of 35 seconds, whichever comes first. It fails the test on timeout.
func pollUntil(t *testing.T, ctx context.Context, fetch func() string, predicate func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(35 * time.Second)
	for {
		value := fetch()
		if predicate(value) {
			return value
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for expected value, last observed %q", value)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done while polling: %v", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
