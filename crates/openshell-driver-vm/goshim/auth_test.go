// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestRegistryCredsAnonymousWithoutToken(t *testing.T) {
	t.Setenv(envRegistryToken, "")
	t.Setenv(envRegistryUsername, "")

	username, secret, err := registryCreds("docker.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "" || secret != "" {
		t.Fatalf("expected anonymous creds, got username=%q secret=%q", username, secret)
	}
}

func TestRegistryCredsUsesExplicitUsername(t *testing.T) {
	t.Setenv(envRegistryToken, "tok")
	t.Setenv(envRegistryUsername, "alice")

	username, secret, err := registryCreds("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "alice" || secret != "tok" {
		t.Fatalf("got username=%q secret=%q", username, secret)
	}
}

func TestRegistryCredsDefaultsGHCRUsername(t *testing.T) {
	t.Setenv(envRegistryToken, "tok")
	t.Setenv(envRegistryUsername, "")

	username, secret, err := registryCreds("ghcr.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "__token__" || secret != "tok" {
		t.Fatalf("got username=%q secret=%q", username, secret)
	}
}

func TestRegistryCredsRequiresUsernameForNonGHCR(t *testing.T) {
	t.Setenv(envRegistryToken, "tok")
	t.Setenv(envRegistryUsername, "")

	_, _, err := registryCreds("example.com")
	if err == nil {
		t.Fatal("expected error when username is missing for a non-GHCR registry")
	}
}
