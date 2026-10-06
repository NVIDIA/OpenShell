// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	pb "github.com/NVIDIA/Ryno/sdk/go/proto/rynov1"
	sbv1 "github.com/NVIDIA/Ryno/sdk/go/proto/sandboxv1"
	"github.com/NVIDIA/Ryno/sdk/go/ryno/v1/internal/converter"
	"google.golang.org/grpc"
)

type configClient struct {
	client    pb.RynoClient
	sandboxes SandboxInterface
}

func newConfigClient(conn grpc.ClientConnInterface, sandboxes SandboxInterface) *configClient {
	return &configClient{client: pb.NewRynoClient(conn), sandboxes: sandboxes}
}

func (c *configClient) GetSandbox(ctx context.Context, workspace, sandboxName string) (*SandboxConfig, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if _, err := c.sandboxes.Get(ctx, workspace, sandboxName); err != nil {
		return nil, err
	}
	resp, err := c.client.GetSandboxConfig(ctx, &sbv1.GetSandboxConfigRequest{
		Name:           sandboxName,
		WorkspaceScope: namedWorkspaceScope(workspace),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxConfigFromProto(resp), nil
}

func (c *configClient) GetGateway(ctx context.Context) (*GatewayConfig, error) {
	resp, err := c.client.GetGatewayConfig(ctx, &sbv1.GetGatewayConfigRequest{})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.GatewayConfigFromProto(resp), nil
}

func (c *configClient) Update(ctx context.Context, workspace string, update *ConfigUpdate) (*ConfigUpdateResult, error) {
	if update == nil {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: "update must not be nil",
		}
	}
	req, convErr := converter.ConfigUpdateToProto(update)
	if convErr != nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: convErr.Error()}
	}
	if !req.GetGlobal() {
		req.WorkspaceScope = namedWorkspaceScope(workspace)
	}
	resp, err := c.client.UpdateConfig(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ConfigUpdateResultFromProto(resp), nil
}
