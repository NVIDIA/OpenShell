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
