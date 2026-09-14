// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type sandboxTemplateClient struct {
	client pb.OpenShellClient
}

var _ SandboxTemplateInterface = (*sandboxTemplateClient)(nil)

func newSandboxTemplateClient(conn grpc.ClientConnInterface) *sandboxTemplateClient {
	return &sandboxTemplateClient{client: pb.NewOpenShellClient(conn)}
}

func (s *sandboxTemplateClient) Create(ctx context.Context, workspace string, template *SandboxWorkloadTemplate) (*SandboxWorkloadTemplate, error) {
	if template == nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "template must not be nil"}
	}
	protoTemplate, err := converter.SandboxWorkloadTemplateToProtoChecked(template)
	if err != nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: err.Error()}
	}
	resp, err := s.client.CreateSandboxTemplate(ctx, &pb.CreateSandboxTemplateRequest{
		Template:       protoTemplate,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxWorkloadTemplateFromProto(resp.GetTemplate()), nil
}

func (s *sandboxTemplateClient) Get(ctx context.Context, workspace, name string) (*SandboxWorkloadTemplate, error) {
	resp, err := s.client.GetSandboxTemplate(ctx, &pb.GetSandboxTemplateRequest{
		Name:           name,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxWorkloadTemplateFromProto(resp.GetTemplate()), nil
}

func (s *sandboxTemplateClient) List(workspace string, opts ...ListOptions) (*Pager[*SandboxWorkloadTemplate], error) {
	pageSize, err := listPageSize(opts)
	if err != nil {
		return nil, err
	}
	var pageToken, labelSelector string
	var allWorkspaces bool
	if len(opts) > 0 {
		pageToken = opts[0].PageToken
		labelSelector = opts[0].LabelSelector
		allWorkspaces = opts[0].AllWorkspaces
	}
	workspaceScope := namedWorkspaceScope(workspace)
	if allWorkspaces {
		workspaceScope = allWorkspacesScope()
	}
	return newPager(pageToken, func(ctx context.Context, pageToken string) (*Page[*SandboxWorkloadTemplate], error) {
		req := &pb.ListSandboxTemplatesRequest{
			WorkspaceScope: workspaceScope, PageSize: pageSize, PageToken: pageToken,
			LabelSelector: labelSelector,
		}
		resp, err := s.client.ListSandboxTemplates(ctx, req)
		if err != nil {
			return nil, converter.FromGRPCError(err)
		}
		templates := make([]*SandboxWorkloadTemplate, 0, len(resp.GetTemplates()))
		for _, protoTemplate := range resp.GetTemplates() {
			templates = append(templates, converter.SandboxWorkloadTemplateFromProto(protoTemplate))
		}
		return &Page[*SandboxWorkloadTemplate]{Items: templates, NextPageToken: resp.GetNextPageToken()}, nil
	}), nil
}

func (s *sandboxTemplateClient) ListAll(ctx context.Context, workspace string, opts ...ListOptions) ([]*SandboxWorkloadTemplate, error) {
	pager, err := s.List(workspace, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}

func (s *sandboxTemplateClient) Delete(ctx context.Context, workspace, name string) (bool, error) {
	resp, err := s.client.DeleteSandboxTemplate(ctx, &pb.DeleteSandboxTemplateRequest{
		Name:           name,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return false, converter.FromGRPCError(err)
	}
	return resp.GetDeleted(), nil
}
