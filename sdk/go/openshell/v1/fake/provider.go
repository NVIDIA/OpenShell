// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// providerName extracts the name from a Provider pointer for use as the
// objectStore key function.
func providerName(p *types.Provider) string {
	return p.Name
}

// copyProvider returns a deep copy of a Provider pointer. All maps are
// duplicated to prevent aliasing.
func copyProvider(p *types.Provider) *types.Provider {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Labels = copyStringMap(p.Labels)
	cp.Spec = copyProviderSpec(p.Spec)
	return &cp
}

func copyProviderSpec(s types.ProviderSpec) types.ProviderSpec {
	s.Credentials = copyStringMap(s.Credentials)
	s.Config = copyStringMap(s.Config)
	s.CredentialExpiresAt = copyTimeMap(s.CredentialExpiresAt)
	return s
}

// copyTimeMap returns a shallow copy of a string-to-time.Time map.
func copyTimeMap(m map[string]time.Time) map[string]time.Time {
	if m == nil {
		return nil
	}
	cp := make(map[string]time.Time, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// fakeProviderClient implements v1.ProviderInterface backed by an in-memory
// objectStore.
type fakeProviderClient struct {
	store      *objectStore[*types.Provider]
	closedFunc func() bool
	profiles   *fakeProfileClient
	refresh    *fakeRefreshClient
}

// newFakeProviderClient creates a new fakeProviderClient.
func newFakeProviderClient(
	store *objectStore[*types.Provider],
	closedFunc func() bool,
) *fakeProviderClient {
	return &fakeProviderClient{
		store:      store,
		closedFunc: closedFunc,
		profiles:   newFakeProfileClient(closedFunc),
		refresh:    newFakeRefreshClient(closedFunc),
	}
}

// Profiles returns a sub-client for provider profile operations.
func (c *fakeProviderClient) Profiles() v1.ProfileInterface {
	return c.profiles
}

// Refresh returns a sub-client for credential refresh operations.
func (c *fakeProviderClient) Refresh() v1.RefreshInterface {
	return c.refresh
}

// Create adds a new provider. CreatedAt and ResourceVersion are set
// automatically.
func (c *fakeProviderClient) Create(_ context.Context, provider *types.Provider) (*types.Provider, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if provider == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "provider must not be nil"}
	}

	p := copyProvider(provider)
	p.CreatedAt = time.Now()
	p.ResourceVersion = 1

	return c.store.Create(p)
}

// Get retrieves a provider by name.
func (c *fakeProviderClient) Get(_ context.Context, name string) (*types.Provider, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return c.store.Get(name)
}

// List returns all providers. ListOptions are accepted for interface
// compatibility but filtering is not implemented.
func (c *fakeProviderClient) List(_ context.Context, _ ...v1.ListOptions) ([]*types.Provider, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return c.store.List(), nil
}

// Update replaces an existing provider's data. ResourceVersion is
// incremented automatically.
func (c *fakeProviderClient) Update(_ context.Context, provider *types.Provider) (*types.Provider, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if provider == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "provider must not be nil"}
	}

	// Fetch existing to preserve CreatedAt and increment ResourceVersion
	existing, err := c.store.Get(provider.Name)
	if err != nil {
		return nil, err
	}

	p := copyProvider(provider)
	p.CreatedAt = existing.CreatedAt
	p.ResourceVersion = existing.ResourceVersion + 1

	return c.store.Update(p)
}

// Delete removes a provider by name. The operation is idempotent.
func (c *fakeProviderClient) Delete(_ context.Context, name string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	c.store.Delete(name)
	return nil
}

// Ensure creates a provider if it does not exist, or updates it if it does.
func (c *fakeProviderClient) Ensure(ctx context.Context, provider *types.Provider) (*types.Provider, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if provider == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "provider must not be nil"}
	}

	_, err := c.store.Get(provider.Name)
	if err != nil {
		// Not found — create
		if types.IsNotFound(err) {
			return c.Create(ctx, provider)
		}
		return nil, err
	}
	// Exists — update
	return c.Update(ctx, provider)
}
