// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type providerClient struct {
	client   pb.OpenShellClient
	profiles *profileClient
	refresh  *refreshClient
}

func newProviderClient(conn grpc.ClientConnInterface) *providerClient {
	return &providerClient{
		client:   pb.NewOpenShellClient(conn),
		profiles: newProfileClient(conn),
		refresh:  newRefreshClient(conn),
	}
}

func (p *providerClient) Profiles() ProfileInterface {
	return p.profiles
}

func (p *providerClient) Refresh() RefreshInterface {
	return p.refresh
}

func (p *providerClient) Create(ctx context.Context, workspace string, provider *Provider) (*Provider, error) {
	resp, err := p.client.CreateProvider(ctx, &pb.CreateProviderRequest{
		Provider:  converter.ProviderToProto(provider),
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ProviderFromProto(resp.GetProvider()), nil
}

func (p *providerClient) Get(ctx context.Context, workspace, name string) (*Provider, error) {
	resp, err := p.client.GetProvider(ctx, &pb.GetProviderRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ProviderFromProto(resp.GetProvider()), nil
}

func (p *providerClient) List(ctx context.Context, workspace string, opts ...ListOptions) ([]*Provider, error) {
	req := &pb.ListProvidersRequest{
		Workspace: workspace,
	}
	if len(opts) > 0 {
		if opts[0].Limit < 0 {
			return nil, &StatusError{Code: ErrorInvalidArgument, Message: "limit must not be negative"}
		}
		if opts[0].Offset < 0 {
			return nil, &StatusError{Code: ErrorInvalidArgument, Message: "offset must not be negative"}
		}
		req.Limit = uint32(opts[0].Limit)
		req.Offset = uint32(opts[0].Offset)
		req.AllWorkspaces = opts[0].AllWorkspaces
	}

	resp, err := p.client.ListProviders(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	providers := make([]*Provider, 0, len(resp.GetProviders()))
	for _, proto := range resp.GetProviders() {
		providers = append(providers, converter.ProviderFromProto(proto))
	}
	return providers, nil
}

func (p *providerClient) Update(ctx context.Context, workspace string, provider *Provider) (*Provider, error) {
	proto := converter.ProviderToProto(provider)
	req := &pb.UpdateProviderRequest{
		Provider:  proto,
		Workspace: workspace,
	}
	if proto != nil {
		req.CredentialExpiresAtMs = proto.CredentialExpiresAtMs
	}

	resp, err := p.client.UpdateProvider(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ProviderFromProto(resp.GetProvider()), nil
}

func (p *providerClient) Delete(ctx context.Context, workspace, name string) error {
	_, err := p.client.DeleteProvider(ctx, &pb.DeleteProviderRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (p *providerClient) Ensure(ctx context.Context, workspace string, provider *Provider) (*Provider, error) {
	if provider == nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "provider must not be nil"}
	}
	existing, err := p.Get(ctx, workspace, provider.Name)
	if err != nil {
		if !IsNotFound(err) {
			return nil, err
		}
		return p.Create(ctx, workspace, provider)
	}

	updated := *provider
	updated.ID = existing.ID
	updated.ResourceVersion = existing.ResourceVersion
	return p.Update(ctx, workspace, &updated)
}
