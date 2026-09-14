// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type profileClient struct {
	client pb.OpenShellClient
}

func newProfileClient(conn grpc.ClientConnInterface) *profileClient {
	return &profileClient{client: pb.NewOpenShellClient(conn)}
}

func (p *profileClient) List(workspace string, opts ...ListOptions) (*Pager[*ProviderProfile], error) {
	pageSize, err := listPageSize(opts)
	if err != nil {
		return nil, err
	}
	var pageToken string
	if len(opts) > 0 {
		pageToken = opts[0].PageToken
	}
	return newPager(pageToken, func(ctx context.Context, pageToken string) (*Page[*ProviderProfile], error) {
		req := &pb.ListProviderProfilesRequest{Workspace: workspace, PageSize: pageSize, PageToken: pageToken}
		resp, err := p.client.ListProviderProfiles(ctx, req)
		if err != nil {
			return nil, converter.FromGRPCError(err)
		}
		profiles := make([]*ProviderProfile, 0, len(resp.GetProfiles()))
		for _, profile := range resp.GetProfiles() {
			profiles = append(profiles, converter.ProviderProfileFromProto(profile))
		}
		return &Page[*ProviderProfile]{Items: profiles, NextPageToken: resp.GetNextPageToken()}, nil
	}), nil
}

func (p *profileClient) ListAll(ctx context.Context, workspace string, opts ...ListOptions) ([]*ProviderProfile, error) {
	pager, err := p.List(workspace, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}

func (p *profileClient) Get(ctx context.Context, workspace, id string) (*ProviderProfile, error) {
	resp, err := p.client.GetProviderProfile(ctx, &pb.GetProviderProfileRequest{
		Id:        id,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ProviderProfileFromProto(resp.GetProfile()), nil
}

func (p *profileClient) Import(ctx context.Context, workspace string, items []ProfileImportItem) (*ImportResult, error) {
	pbItems := make([]*pb.ProviderProfileImportItem, len(items))
	for i := range items {
		pbItems[i] = converter.ProfileImportItemToProto(&items[i])
	}

	resp, err := p.client.ImportProviderProfiles(ctx, &pb.ImportProviderProfilesRequest{
		Profiles:  pbItems,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	result := &ImportResult{
		Imported: resp.GetImported(),
	}

	for _, d := range resp.GetDiagnostics() {
		if diag := converter.ProfileDiagnosticFromProto(d); diag != nil {
			result.Diagnostics = append(result.Diagnostics, *diag)
		}
	}

	for _, pp := range resp.GetProfiles() {
		if profile := converter.ProviderProfileFromProto(pp); profile != nil {
			result.Profiles = append(result.Profiles, *profile)
		}
	}

	return result, nil
}

func (p *profileClient) Update(ctx context.Context, workspace, id string, expectedResourceVersion uint64, item ProfileImportItem) (*UpdateResult, error) {
	resp, err := p.client.UpdateProviderProfiles(ctx, &pb.UpdateProviderProfilesRequest{
		Id:                      id,
		Profile:                 converter.ProfileImportItemToProto(&item),
		ExpectedResourceVersion: expectedResourceVersion,
		Workspace:               workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	result := &UpdateResult{
		Updated: resp.GetUpdated(),
		Profile: converter.ProviderProfileFromProto(resp.GetProfile()),
	}

	for _, d := range resp.GetDiagnostics() {
		if diag := converter.ProfileDiagnosticFromProto(d); diag != nil {
			result.Diagnostics = append(result.Diagnostics, *diag)
		}
	}

	return result, nil
}

func (p *profileClient) Lint(ctx context.Context, workspace string, items []ProfileImportItem) (*LintResult, error) {
	pbItems := make([]*pb.ProviderProfileImportItem, len(items))
	for i := range items {
		pbItems[i] = converter.ProfileImportItemToProto(&items[i])
	}

	resp, err := p.client.LintProviderProfiles(ctx, &pb.LintProviderProfilesRequest{
		Profiles:  pbItems,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	result := &LintResult{
		Valid: resp.GetValid(),
	}

	for _, d := range resp.GetDiagnostics() {
		if diag := converter.ProfileDiagnosticFromProto(d); diag != nil {
			result.Diagnostics = append(result.Diagnostics, *diag)
		}
	}

	return result, nil
}

func (p *profileClient) Delete(ctx context.Context, workspace, id string) (bool, error) {
	resp, err := p.client.DeleteProviderProfile(ctx, &pb.DeleteProviderProfileRequest{
		Id:        id,
		Workspace: workspace,
	})
	if err != nil {
		return false, converter.FromGRPCError(err)
	}
	return resp.GetDeleted(), nil
}
