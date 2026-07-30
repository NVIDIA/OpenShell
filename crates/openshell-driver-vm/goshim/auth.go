// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/core/remotes/docker"
)

// Environment variables consulted for registry auth. These mirror the
// variables historically read by the Rust oci-client based pull path so
// operator configuration does not need to change.
const (
	envRegistryUsername = "OPENSHELL_REGISTRY_USERNAME"
	envRegistryToken    = "OPENSHELL_REGISTRY_TOKEN"
)

// newResolver builds a docker.Resolver configured with credentials from the
// environment, matching the historical (anonymous by default, optional
// username/token, GHCR "__token__" convenience default) auth behavior.
func newResolver() docker.ResolverOptions {
	authorizer := docker.NewDockerAuthorizer(docker.WithAuthCreds(registryCreds))
	return docker.ResolverOptions{
		Hosts: docker.ConfigureDefaultRegistries(docker.WithAuthorizer(authorizer)),
	}
}

func registryCreds(host string) (string, string, error) {
	token := strings.TrimSpace(os.Getenv(envRegistryToken))
	if token == "" {
		return "", "", nil
	}

	username := strings.TrimSpace(os.Getenv(envRegistryUsername))
	if username != "" {
		return username, token, nil
	}
	if isGHCRHost(host) {
		return "__token__", token, nil
	}
	return "", "", fmt.Errorf(
		"%s is required when %s is set for non-GHCR registries",
		envRegistryUsername, envRegistryToken,
	)
}

func isGHCRHost(host string) bool {
	return strings.EqualFold(host, "ghcr.io")
}
