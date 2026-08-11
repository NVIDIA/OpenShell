// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type workspaceClient struct {
	client pb.OpenShellClient
}

func newWorkspaceClient(conn grpc.ClientConnInterface) *workspaceClient {
	return &workspaceClient{client: pb.NewOpenShellClient(conn)}
}

func (w *workspaceClient) Create(ctx context.Context, name string, labels map[string]string) (*Workspace, error) {
	if name == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}

	resp, err := w.client.CreateWorkspace(ctx, &pb.CreateWorkspaceRequest{
		Name:   name,
		Labels: labels,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.WorkspaceFromProto(resp.GetWorkspace()), nil
}

func (w *workspaceClient) Get(ctx context.Context, name string) (*Workspace, error) {
	if name == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}

	resp, err := w.client.GetWorkspace(ctx, &pb.GetWorkspaceRequest{
		Name: name,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.WorkspaceFromProto(resp.GetWorkspace()), nil
}

func (w *workspaceClient) List(ctx context.Context, opts ...ListOptions) ([]*Workspace, error) {
	req := &pb.ListWorkspacesRequest{}
	if len(opts) > 0 {
		if opts[0].Limit < 0 {
			return nil, &StatusError{Code: ErrorInvalidArgument, Message: "limit must not be negative"}
		}
		if opts[0].Offset < 0 {
			return nil, &StatusError{Code: ErrorInvalidArgument, Message: "offset must not be negative"}
		}
		req.Limit = uint32(opts[0].Limit)
		req.Offset = uint32(opts[0].Offset)
		req.LabelSelector = opts[0].LabelSelector
	}

	resp, err := w.client.ListWorkspaces(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	workspaces := make([]*Workspace, 0, len(resp.GetWorkspaces()))
	for _, proto := range resp.GetWorkspaces() {
		workspaces = append(workspaces, converter.WorkspaceFromProto(proto))
	}
	return workspaces, nil
}

func (w *workspaceClient) Delete(ctx context.Context, name string) error {
	if name == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}

	_, err := w.client.DeleteWorkspace(ctx, &pb.DeleteWorkspaceRequest{
		Name: name,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (w *workspaceClient) AddMember(ctx context.Context, workspace, principalSubject string, role WorkspaceRole) (*WorkspaceMember, error) {
	if workspace == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}
	if principalSubject == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "principal subject must not be empty"}
	}

	protoRole := converter.WorkspaceRoleToProto(role)
	if protoRole == pb.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "role must be Admin or User"}
	}

	resp, err := w.client.AddWorkspaceMember(ctx, &pb.AddWorkspaceMemberRequest{
		Workspace:        workspace,
		PrincipalSubject: principalSubject,
		Role:             protoRole,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.WorkspaceMemberFromProto(resp.GetMember()), nil
}

func (w *workspaceClient) RemoveMember(ctx context.Context, workspace, principalSubject string) error {
	if workspace == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}
	if principalSubject == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "principal subject must not be empty"}
	}

	_, err := w.client.RemoveWorkspaceMember(ctx, &pb.RemoveWorkspaceMemberRequest{
		Workspace:        workspace,
		PrincipalSubject: principalSubject,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (w *workspaceClient) ListMembers(ctx context.Context, workspace string, opts ...ListOptions) ([]*WorkspaceMember, error) {
	if workspace == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}

	req := &pb.ListWorkspaceMembersRequest{
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

	resp, err := w.client.ListWorkspaceMembers(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	members := make([]*WorkspaceMember, 0, len(resp.GetMembers()))
	for _, proto := range resp.GetMembers() {
		members = append(members, converter.WorkspaceMemberFromProto(proto))
	}
	return members, nil
}
