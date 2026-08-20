// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type healthClient struct {
	client pb.OpenShellClient
}

func newHealthClient(conn grpc.ClientConnInterface) *healthClient {
	return &healthClient{client: pb.NewOpenShellClient(conn)}
}

func (h *healthClient) Check(ctx context.Context) (*HealthResult, error) {
	resp, err := h.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	return &HealthResult{
		Healthy: resp.GetStatus() == pb.ServiceStatus_SERVICE_STATUS_HEALTHY,
		Version: resp.GetVersion(),
	}, nil
}

func (h *healthClient) GetGatewayInfo(ctx context.Context) (*GatewayInfo, error) {
	resp, err := h.client.GetGatewayInfo(ctx, &pb.GetGatewayInfoRequest{})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.GatewayInfoFromProto(resp), nil
}

func (h *healthClient) GetCurrentUser(ctx context.Context) (*CurrentUser, error) {
	resp, err := h.client.GetCurrentUser(ctx, &pb.GetCurrentUserRequest{})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.CurrentUserFromProto(resp), nil
}
