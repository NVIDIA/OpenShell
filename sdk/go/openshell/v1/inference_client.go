// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/inferencev1"
	"google.golang.org/grpc"
)

type inferenceClient struct {
	client pb.InferenceClient
}

func newInferenceClient(conn grpc.ClientConnInterface) *inferenceClient {
	return &inferenceClient{client: pb.NewInferenceClient(conn)}
}

func (c *inferenceClient) SetRoute(ctx context.Context, workspace string, config *InferenceRouteConfig) (*InferenceRoute, error) {
	if workspace == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "workspace must not be empty"}
	}
	if config == nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "config must not be nil"}
	}
	if config.ProviderName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "provider name must not be empty"}
	}
	if config.ModelID == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "model ID must not be empty"}
	}

	req := converter.InferenceRouteConfigToProto(workspace, config)
	resp, err := c.client.SetInferenceRoute(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.InferenceRouteFromSetResponse(resp), nil
}

func (c *inferenceClient) GetRoute(ctx context.Context, workspace, routeName string) (*InferenceRoute, error) {
	if workspace == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "workspace must not be empty"}
	}

	resp, err := c.client.GetInferenceRoute(ctx, &pb.GetInferenceRouteRequest{
		Workspace: workspace,
		RouteName: routeName,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.InferenceRouteFromGetResponse(resp), nil
}

func (c *inferenceClient) DeleteRoute(ctx context.Context, workspace, routeName string) error {
	if workspace == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "workspace must not be empty"}
	}

	_, err := c.client.DeleteInferenceRoute(ctx, &pb.DeleteInferenceRouteRequest{
		Workspace: workspace,
		RouteName: routeName,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}
