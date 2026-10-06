// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	pb "github.com/NVIDIA/Ryno/sdk/go/proto/rynov1"
	"github.com/NVIDIA/Ryno/sdk/go/ryno/v1/internal/converter"
	"google.golang.org/grpc"
)

type refreshClient struct {
	client pb.RynoClient
}

func newRefreshClient(conn grpc.ClientConnInterface) *refreshClient {
	return &refreshClient{client: pb.NewRynoClient(conn)}
}

func (r *refreshClient) GetStatus(ctx context.Context, workspace, provider, credentialKey string) ([]*RefreshStatus, error) {
	resp, err := r.client.GetProviderRefreshStatus(ctx, &pb.GetProviderRefreshStatusRequest{
		Provider:       provider,
		CredentialKey:  credentialKey,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	statuses := make([]*RefreshStatus, 0, len(resp.GetCredentials()))
	for _, s := range resp.GetCredentials() {
		statuses = append(statuses, converter.RefreshStatusFromProto(s))
	}
	return statuses, nil
}

func (r *refreshClient) Configure(ctx context.Context, workspace string, config *RefreshConfig) (*RefreshStatus, error) {
	req := converter.RefreshConfigToProto(config)
	req.WorkspaceScope = namedWorkspaceScope(workspace)
	resp, err := r.client.ConfigureProviderRefresh(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.RefreshStatusFromProto(resp.GetStatus()), nil
}

func (r *refreshClient) Rotate(ctx context.Context, workspace, provider, credentialKey string) (*RefreshStatus, error) {
	resp, err := r.client.RotateProviderCredential(ctx, &pb.RotateProviderCredentialRequest{
		Provider:       provider,
		CredentialKey:  credentialKey,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.RefreshStatusFromProto(resp.GetStatus()), nil
}

func (r *refreshClient) Delete(ctx context.Context, workspace, provider, credentialKey string, opts ...DeleteOptions) (*DeletionResult, error) {
	resp, err := r.client.DeleteProviderRefresh(ctx, &pb.DeleteProviderRefreshRequest{
		AllowMissing:   allowMissing(opts),
		Provider:       provider,
		CredentialKey:  credentialKey,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return &DeletionResult{Outcome: DeletionOutcome(resp.GetOutcome())}, nil
}
