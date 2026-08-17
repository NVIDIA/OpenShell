// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e contains end-to-end tests for the Go SDK, run against a real
// OpenShell gateway with `mise run e2e:go` (Podman) or
// `mise run e2e:go:docker` (Docker).
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

var (
	sharedClient *v1.Client
	gatewayName  string
)

func TestMain(m *testing.M) {
	gatewayName = os.Getenv("OPENSHELL_GATEWAY")
	if gatewayName == "" {
		// No gateway configured; requireClient skips every test individually.
		os.Exit(m.Run())
	}

	cfg, err := gateway.LoadConfig(gatewayName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: failed to load gateway config: %v\n", err)
		os.Exit(1)
	}

	var opts []gateway.ClientOption
	if opt := mtlsClientOption(cfg.Dir); opt != nil {
		opts = append(opts, opt)
	}

	client, err := gateway.NewClient(gatewayName, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: failed to build gateway client: %v\n", err)
		os.Exit(1)
	}
	sharedClient = client

	if err := waitForPersistenceReady(sharedClient); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: %v\n", err)
		_ = sharedClient.Close()
		os.Exit(1)
	}

	code := m.Run()
	_ = sharedClient.Close()
	os.Exit(code)
}

// mtlsClientOption inspects <dir>/mtls for an on-disk certificate bundle
// written by e2e_register_mtls_gateway (see e2e/support/gateway-common.sh)
// and returns a ClientOption applying it. Returns nil when no bundle is
// present (e.g. plaintext or OIDC e2e lanes), so callers should skip it.
func mtlsClientOption(dir string) gateway.ClientOption {
	mtlsDir := filepath.Join(dir, "mtls")
	caPath := filepath.Join(mtlsDir, "ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		return nil
	}

	cfg := &types.TLSConfig{CAFile: caPath}

	certPath := filepath.Join(mtlsDir, "tls.crt")
	keyPath := filepath.Join(mtlsDir, "tls.key")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			cfg.CertFile = certPath
			cfg.KeyFile = keyPath
		}
	}

	return gateway.WithTLS(cfg)
}

// requireClient returns the shared gateway client, skipping the calling test
// when OPENSHELL_GATEWAY was not set at process startup.
func requireClient(t *testing.T) *v1.Client {
	t.Helper()
	if gatewayName == "" {
		t.Skip("OPENSHELL_GATEWAY not set")
	}
	return sharedClient
}

// waitForPersistenceReady polls the gateway until its persistence layer is
// initialized, tolerating the transient errors observed right after the
// gateway process starts (transport not yet listening, sqlite migrations
// not yet applied).
func waitForPersistenceReady(client *v1.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var lastErr error
	for range 60 {
		_, err := client.Sandboxes().ListAll(ctx, "default", v1.ListOptions{PageSize: 1})
		if err == nil {
			return nil
		}
		lastErr = err
		if v1.IsUnavailable(err) {
			time.Sleep(2 * time.Second)
			continue
		}
		if strings.Contains(err.Error(), "no such table: objects") {
			time.Sleep(1 * time.Second)
			continue
		}
		return fmt.Errorf("unexpected error waiting for persistence: %w", err)
	}
	return fmt.Errorf("openshell-server persistence is not initialized after 60 attempts: %w", lastErr)
}

// uniqueName returns a process-unique resource name so parallel tests never
// collide on the same sandbox/workspace/provider name.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%09d", prefix, time.Now().UnixNano()%1_000_000_000)
}

func requireSandboxResponse(t *testing.T, sandbox *v1.Sandbox, workspace, name string) {
	t.Helper()
	require.NotNil(t, sandbox)
	require.NotEmpty(t, sandbox.ID)
	require.Equal(t, workspace, sandbox.Workspace)
	require.Equal(t, name, sandbox.Name)
	require.False(t, sandbox.CreatedAt.IsZero())
	require.NotZero(t, sandbox.ResourceVersion)
}

func requireReadySandbox(t *testing.T, sandbox *v1.Sandbox, id string) {
	t.Helper()
	require.NotNil(t, sandbox)
	require.Equal(t, id, sandbox.ID)
	require.Equal(t, v1.SandboxReady, sandbox.Status.Phase)
}

func readEnvVar(ctx context.Context, client *v1.Client, workspace, sandboxName, key string) (string, error) {
	result, err := client.Exec().Run(ctx, workspace, sandboxName,
		[]string{"sh", "-c", `if value=$(printenv "$1"); then printf "%s" "$value"; else printf NOT_SET; fi`, "--", key},
		v1.ExecOptions{})
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("exec exited %d: %s", result.ExitCode, string(result.Stderr))
	}
	if len(result.Stderr) != 0 {
		return "", fmt.Errorf("exec wrote unexpected stderr: %s", string(result.Stderr))
	}
	return string(result.Stdout), nil
}

func isPlaceholderForEnvKey(value, key string) bool {
	const prefix = "openshell:resolve:env:"
	suffix, ok := strings.CutPrefix(value, prefix)
	if !ok {
		return false
	}
	if suffix == key {
		return true
	}

	discriminator, placeholderKey, ok := strings.Cut(suffix, "_")
	if !ok || placeholderKey != key || len(discriminator) < 2 {
		return false
	}

	switch discriminator[0] {
	case 'v':
		for _, char := range discriminator[1:] {
			if char < '0' || char > '9' {
				return false
			}
		}
		return true
	case 's':
		if len(discriminator) != 65 {
			return false
		}
		for _, char := range discriminator[1:] {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func TestIsPlaceholderForEnvKey(t *testing.T) {
	stableHandle := strings.Repeat("a1", 32)
	tests := []struct {
		name  string
		value string
		key   string
		want  bool
	}{
		{name: "plain", value: "openshell:resolve:env:API_KEY", key: "API_KEY", want: true},
		{name: "revisioned", value: "openshell:resolve:env:v12_API_KEY", key: "API_KEY", want: true},
		{name: "stable handle", value: "openshell:resolve:env:s" + stableHandle + "_API_KEY", key: "API_KEY", want: true},
		{name: "overlapping key suffix", value: "openshell:resolve:env:v12_LONG_API_KEY", key: "API_KEY", want: false},
		{name: "revision requires digits", value: "openshell:resolve:env:vnext_API_KEY", key: "API_KEY", want: false},
		{name: "stable handle requires lowercase hex", value: "openshell:resolve:env:s" + strings.ToUpper(stableHandle) + "_API_KEY", key: "API_KEY", want: false},
		{name: "stable handle requires 64 characters", value: "openshell:resolve:env:sabc_API_KEY", key: "API_KEY", want: false},
		{name: "wrong key", value: "openshell:resolve:env:v12_OTHER_KEY", key: "API_KEY", want: false},
		{name: "raw secret", value: "secret", key: "API_KEY", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, isPlaceholderForEnvKey(test.value, test.key))
		})
	}
}

// pollUntil calls fetch until the predicate is satisfied, the local polling
// timeout expires, or ctx is done, whichever happens first.
func pollUntil[T any](t *testing.T, ctx context.Context, fetch func() T, predicate func(T) bool) T {
	t.Helper()
	deadline := time.NewTimer(35 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		value := fetch()
		if predicate(value) {
			return value
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done while polling; last observed %v: %v", value, ctx.Err())
		case <-deadline.C:
			t.Fatalf("timed out waiting for expected value, last observed %v", value)
		case <-ticker.C:
		}
	}
}

// defaultPolicy returns a baseline sandbox policy sufficient for exec-based tests.
func defaultPolicy() *v1.SandboxPolicy {
	return &v1.SandboxPolicy{
		Version: 1,
		Filesystem: &v1.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       []string{"/usr", "/lib", "/etc", "/app", "/dev/urandom"},
			ReadWrite:      []string{"/sandbox", "/tmp"},
		},
		Landlock: &v1.LandlockPolicy{Compatibility: "best_effort"},
		Process:  &v1.ProcessPolicy{RunAsUser: "sandbox", RunAsGroup: "sandbox"},
	}
}
