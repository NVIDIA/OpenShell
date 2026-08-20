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
		Template:  protoTemplate,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxWorkloadTemplateFromProto(resp.GetTemplate()), nil
}

func (s *sandboxTemplateClient) Get(ctx context.Context, workspace, name string) (*SandboxWorkloadTemplate, error) {
	resp, err := s.client.GetSandboxTemplate(ctx, &pb.GetSandboxTemplateRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxWorkloadTemplateFromProto(resp.GetTemplate()), nil
}

func (s *sandboxTemplateClient) List(ctx context.Context, workspace string, opts ...ListOptions) ([]*SandboxWorkloadTemplate, error) {
	req := &pb.ListSandboxTemplatesRequest{
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
		req.LabelSelector = opts[0].LabelSelector
		req.AllWorkspaces = opts[0].AllWorkspaces
		if req.AllWorkspaces {
			req.Workspace = ""
		}
	}

	resp, err := s.client.ListSandboxTemplates(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	templates := make([]*SandboxWorkloadTemplate, 0, len(resp.GetTemplates()))
	for _, protoTemplate := range resp.GetTemplates() {
		templates = append(templates, converter.SandboxWorkloadTemplateFromProto(protoTemplate))
	}
	return templates, nil
}

func (s *sandboxTemplateClient) Delete(ctx context.Context, workspace, name string) (bool, error) {
	resp, err := s.client.DeleteSandboxTemplate(ctx, &pb.DeleteSandboxTemplateRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return false, converter.FromGRPCError(err)
	}
	return resp.GetDeleted(), nil
}
