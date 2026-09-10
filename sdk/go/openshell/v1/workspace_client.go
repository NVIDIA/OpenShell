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
	pageSize, err := listPageSize(opts)
	if err != nil {
		return nil, err
	}
	req := &pb.ListWorkspacesRequest{PageSize: pageSize}
	if len(opts) > 0 {
		req.LabelSelector = opts[0].LabelSelector
	}

	var workspaces []*Workspace
	for {
		resp, err := w.client.ListWorkspaces(ctx, req)
		if err != nil {
			return nil, converter.FromGRPCError(err)
		}
		for _, proto := range resp.GetWorkspaces() {
			workspaces = append(workspaces, converter.WorkspaceFromProto(proto))
		}
		if resp.GetNextPageToken() == "" {
			return workspaces, nil
		}
		req.PageToken = resp.GetNextPageToken()
	}
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

	pageSize, err := listPageSize(opts)
	if err != nil {
		return nil, err
	}
	req := &pb.ListWorkspaceMembersRequest{
		Workspace: workspace,
		PageSize:  pageSize,
	}
	var members []*WorkspaceMember
	for {
		resp, err := w.client.ListWorkspaceMembers(ctx, req)
		if err != nil {
			return nil, converter.FromGRPCError(err)
		}
		for _, proto := range resp.GetMembers() {
			members = append(members, converter.WorkspaceMemberFromProto(proto))
		}
		if resp.GetNextPageToken() == "" {
			return members, nil
		}
		req.PageToken = resp.GetNextPageToken()
	}
}
