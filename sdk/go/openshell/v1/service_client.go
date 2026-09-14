// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type serviceClient struct {
	client pb.OpenShellClient
}

func newServiceClient(conn grpc.ClientConnInterface) *serviceClient {
	return &serviceClient{client: pb.NewOpenShellClient(conn)}
}

func (s *serviceClient) Expose(ctx context.Context, workspace, sandboxName, serviceName string, targetPort uint32, domain bool) (*ServiceEndpoint, error) {
	resp, err := s.client.ExposeService(ctx, &pb.ExposeServiceRequest{
		Sandbox:        sandboxName,
		Service:        serviceName,
		TargetPort:     targetPort,
		Domain:         domain,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ServiceEndpointFromProto(resp), nil
}

func (s *serviceClient) Get(ctx context.Context, workspace, sandboxName, serviceName string) (*ServiceEndpoint, error) {
	resp, err := s.client.GetService(ctx, &pb.GetServiceRequest{
		Sandbox:        sandboxName,
		Service:        serviceName,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ServiceEndpointFromProto(resp), nil
}

func (s *serviceClient) List(workspace, sandboxName string, opts ...ListOptions) (*Pager[*ServiceEndpoint], error) {
	pageSize, err := listPageSize(opts)
	if err != nil {
		return nil, err
	}
	var pageToken string
	var allWorkspaces bool
	if len(opts) > 0 {
		pageToken = opts[0].PageToken
		allWorkspaces = opts[0].AllWorkspaces
	}
	workspaceScope := namedWorkspaceScope(workspace)
	if allWorkspaces {
		workspaceScope = allWorkspacesScope()
	}
	return newPager(pageToken, func(ctx context.Context, pageToken string) (*Page[*ServiceEndpoint], error) {
		req := &pb.ListServicesRequest{
			Sandbox: sandboxName, WorkspaceScope: workspaceScope, PageSize: pageSize,
			PageToken: pageToken,
		}
		resp, err := s.client.ListServices(ctx, req)
		if err != nil {
			return nil, converter.FromGRPCError(err)
		}
		endpoints := make([]*ServiceEndpoint, 0, len(resp.GetServices()))
		for _, svc := range resp.GetServices() {
			endpoints = append(endpoints, converter.ServiceEndpointFromProto(svc))
		}
		return &Page[*ServiceEndpoint]{Items: endpoints, NextPageToken: resp.GetNextPageToken()}, nil
	}), nil
}

func (s *serviceClient) ListAll(ctx context.Context, workspace, sandboxName string, opts ...ListOptions) ([]*ServiceEndpoint, error) {
	pager, err := s.List(workspace, sandboxName, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}

func (s *serviceClient) Delete(ctx context.Context, workspace, sandboxName, serviceName string) error {
	_, err := s.client.DeleteService(ctx, &pb.DeleteServiceRequest{
		Sandbox:        sandboxName,
		Service:        serviceName,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}
