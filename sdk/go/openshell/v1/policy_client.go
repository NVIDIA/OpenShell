// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type policyClient struct {
	client pb.OpenShellClient
}

func newPolicyClient(conn grpc.ClientConnInterface) *policyClient {
	return &policyClient{client: pb.NewOpenShellClient(conn)}
}

func (p *policyClient) GetDraft(ctx context.Context, workspace, sandboxName string, opts ...GetDraftOption) (*DraftPolicy, error) {
	cfg := types.ApplyGetDraftOptions(opts)
	resp, err := p.client.GetDraftPolicy(ctx, &pb.GetDraftPolicyRequest{
		Name:         sandboxName,
		StatusFilter: cfg.StatusFilter(),
		Workspace:    workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.DraftPolicyFromProto(resp), nil
}

func (p *policyClient) ApproveDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reviewToken string) (*ApproveResult, error) {
	resp, err := p.client.ApproveDraftChunk(ctx, &pb.ApproveDraftChunkRequest{
		Name:        sandboxName,
		ChunkId:     chunkID,
		Workspace:   workspace,
		ReviewToken: reviewToken,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ApproveResultFromProto(resp), nil
}

func (p *policyClient) RejectDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reason string) error {
	_, err := p.client.RejectDraftChunk(ctx, &pb.RejectDraftChunkRequest{
		Name:      sandboxName,
		ChunkId:   chunkID,
		Reason:    reason,
		Workspace: workspace,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (p *policyClient) ApproveAllDraftChunks(ctx context.Context, workspace, sandboxName string, opts ...ApproveAllOption) (*ApproveAllResult, error) {
	cfg := types.ApplyApproveAllOptions(opts)
	approvals := make([]*pb.DraftChunkApproval, 0, len(cfg.Approvals()))
	for _, approval := range cfg.Approvals() {
		approvals = append(approvals, &pb.DraftChunkApproval{
			ChunkId:     approval.ChunkID,
			ReviewToken: approval.ReviewToken,
		})
	}
	resp, err := p.client.ApproveAllDraftChunks(ctx, &pb.ApproveAllDraftChunksRequest{
		Name:                   sandboxName,
		IncludeSecurityFlagged: cfg.IncludeSecurityFlagged(),
		Workspace:              workspace,
		Approvals:              approvals,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ApproveAllResultFromProto(resp), nil
}

func (p *policyClient) ClearDraftChunks(ctx context.Context, workspace, sandboxName string) (*ClearResult, error) {
	resp, err := p.client.ClearDraftChunks(ctx, &pb.ClearDraftChunksRequest{
		Name:      sandboxName,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ClearResultFromProto(resp), nil
}

func (p *policyClient) GetDraftHistory(ctx context.Context, workspace, sandboxName string) ([]DraftHistoryEntry, error) {
	resp, err := p.client.GetDraftHistory(ctx, &pb.GetDraftHistoryRequest{
		Name:      sandboxName,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	entries := resp.GetEntries()
	if len(entries) == 0 {
		return nil, nil
	}
	result := make([]DraftHistoryEntry, 0, len(entries))
	for _, e := range entries {
		if converted := converter.DraftHistoryEntryFromProto(e); converted != nil {
			result = append(result, *converted)
		}
	}
	return result, nil
}

func (p *policyClient) GetStatus(ctx context.Context, workspace, sandboxName string, opts ...GetStatusOption) (*PolicyStatusResult, error) {
	cfg := types.ApplyGetStatusOptions(opts)
	resp, err := p.client.GetSandboxPolicyStatus(ctx, &pb.GetSandboxPolicyStatusRequest{
		Name:      sandboxName,
		Version:   cfg.Version(),
		Workspace: workspace,
		Global:    cfg.Global(),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.PolicyStatusResultFromProto(resp), nil
}

func (p *policyClient) List(ctx context.Context, workspace string, opts ...ListPolicyOption) ([]SandboxPolicyRevision, error) {
	cfg := types.ApplyListPolicyOptions(opts)
	resp, err := p.client.ListSandboxPolicies(ctx, &pb.ListSandboxPoliciesRequest{
		Workspace: workspace,
		Limit:     cfg.Limit(),
		Offset:    cfg.Offset(),
		Global:    cfg.Global(),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	revisions := resp.GetRevisions()
	if len(revisions) == 0 {
		return nil, nil
	}
	result := make([]SandboxPolicyRevision, 0, len(revisions))
	for _, r := range revisions {
		if converted := converter.SandboxPolicyRevisionFromProto(r); converted != nil {
			result = append(result, *converted)
		}
	}
	return result, nil
}

func (p *policyClient) EditDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string, proposedRule *NetworkPolicyRule) error {
	_, err := p.client.EditDraftChunk(ctx, &pb.EditDraftChunkRequest{
		Name:         sandboxName,
		ChunkId:      chunkID,
		ProposedRule: converter.NetworkPolicyRuleToProto(proposedRule),
		Workspace:    workspace,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (p *policyClient) UndoDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string) (*UndoResult, error) {
	resp, err := p.client.UndoDraftChunk(ctx, &pb.UndoDraftChunkRequest{
		Name:      sandboxName,
		ChunkId:   chunkID,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.UndoResultFromProto(resp), nil
}
