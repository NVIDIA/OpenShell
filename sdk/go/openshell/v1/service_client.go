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

func (s *serviceClient) List(ctx context.Context, workspace, sandboxName string, opts ...ListOptions) ([]*ServiceEndpoint, error) {
	req := &pb.ListServicesRequest{
		Sandbox:        sandboxName,
		WorkspaceScope: namedWorkspaceScope(workspace),
	}
	return s.list(ctx, req, opts...)
}

func (s *serviceClient) ListAll(ctx context.Context, opts ...ListOptions) ([]*ServiceEndpoint, error) {
	return s.list(ctx, &pb.ListServicesRequest{WorkspaceScope: allWorkspacesScope()}, opts...)
}

func (s *serviceClient) list(ctx context.Context, req *pb.ListServicesRequest, opts ...ListOptions) ([]*ServiceEndpoint, error) {
	pageSize, err := listPageSize(opts)
	if err != nil {
		return nil, err
	}
	req.PageSize = pageSize

	var endpoints []*ServiceEndpoint
	for {
		resp, err := s.client.ListServices(ctx, req)
		if err != nil {
			return nil, converter.FromGRPCError(err)
		}
		for _, svc := range resp.GetServices() {
			endpoints = append(endpoints, converter.ServiceEndpointFromProto(svc))
		}
		if resp.GetNextPageToken() == "" {
			return endpoints, nil
		}
		req.PageToken = resp.GetNextPageToken()
	}
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
