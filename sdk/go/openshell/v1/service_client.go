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

func (s *serviceClient) Expose(ctx context.Context, sandboxName, serviceName string, targetPort uint32, domain bool) (*ServiceEndpoint, error) {
	resp, err := s.client.ExposeService(ctx, &pb.ExposeServiceRequest{
		Sandbox:    sandboxName,
		Service:    serviceName,
		TargetPort: targetPort,
		Domain:     domain,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ServiceEndpointFromProto(resp), nil
}

func (s *serviceClient) Get(ctx context.Context, sandboxName, serviceName string) (*ServiceEndpoint, error) {
	resp, err := s.client.GetService(ctx, &pb.GetServiceRequest{
		Sandbox: sandboxName,
		Service: serviceName,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ServiceEndpointFromProto(resp), nil
}

func (s *serviceClient) List(ctx context.Context, sandboxName string, opts ...ListOptions) ([]*ServiceEndpoint, error) {
	req := &pb.ListServicesRequest{
		Sandbox: sandboxName,
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

	resp, err := s.client.ListServices(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	endpoints := make([]*ServiceEndpoint, 0, len(resp.GetServices()))
	for _, svc := range resp.GetServices() {
		endpoints = append(endpoints, converter.ServiceEndpointFromProto(svc))
	}
	return endpoints, nil
}

func (s *serviceClient) Delete(ctx context.Context, sandboxName, serviceName string) error {
	_, err := s.client.DeleteService(ctx, &pb.DeleteServiceRequest{
		Sandbox: sandboxName,
		Service: serviceName,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}
