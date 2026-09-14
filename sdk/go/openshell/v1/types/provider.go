// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// Provider represents an AI provider registration.
type Provider struct {
	ID                string
	Name              string
	Type              string
	CreatedAt         time.Time
	Labels            map[string]string
	Annotations       map[string]string
	ResourceVersion   uint64
	Workspace         string
	DeletionTimestamp *time.Time
	Spec              ProviderSpec
}

// ProviderSpec holds provider-specific configuration and credentials.
type ProviderSpec struct {
	Credentials         map[string]string
	Config              map[string]string
	CredentialExpiresAt map[string]time.Time
	ProfileWorkspace    string
	CredentialHandles   map[string]CredentialHandle
}

// CredentialHandle is an opaque handle for a provider credential stored by
// gateway credential storage. Handles are created by OpenShell and are not
// accepted as user-authored input.
type CredentialHandle struct {
	Driver   string
	Handle   string
	Metadata map[string]string
}
