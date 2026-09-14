// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Provider represents an AI provider registration.
type Provider = types.Provider

// ProviderSpec holds provider-specific configuration and credentials.
type ProviderSpec = types.ProviderSpec

// ProviderInterface defines CRUD and Ensure operations on providers,
// plus sub-client accessors for profiles and credential refresh.
type ProviderInterface interface {
	Create(ctx context.Context, workspace string, provider *Provider) (*Provider, error)
	Get(ctx context.Context, workspace, name string) (*Provider, error)
	List(ctx context.Context, workspace string, opts ...ListOptions) ([]*Provider, error)
	Update(ctx context.Context, workspace string, provider *Provider) (*Provider, error)
	Delete(ctx context.Context, workspace, name string) error
	Ensure(ctx context.Context, workspace string, provider *Provider) (*Provider, error)
	Profiles() ProfileInterface
	Refresh() RefreshInterface
}
