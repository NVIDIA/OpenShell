// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e contains end-to-end tests for the Go SDK, run against a real
// OpenShell gateway (see e2e/with-docker-gateway.sh and `mise run e2e:go`).
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	ctx := context.Background()
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
