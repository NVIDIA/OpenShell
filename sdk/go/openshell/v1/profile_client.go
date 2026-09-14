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

func (p *profileClient) List(ctx context.Context, workspace string, opts ...ListOptions) ([]*ProviderProfile, error) {
	req := &pb.ListProviderProfilesRequest{
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
	}

	resp, err := p.client.ListProviderProfiles(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	profiles := make([]*ProviderProfile, 0, len(resp.GetProfiles()))
	for _, pp := range resp.GetProfiles() {
		profiles = append(profiles, converter.ProviderProfileFromProto(pp))
	}
	return profiles, nil
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
