// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"google.golang.org/grpc"
)

type configClient struct {
	client    pb.OpenShellClient
	sandboxes SandboxInterface
}

func newConfigClient(conn grpc.ClientConnInterface, sandboxes SandboxInterface) *configClient {
	return &configClient{client: pb.NewOpenShellClient(conn), sandboxes: sandboxes}
}

func (c *configClient) GetSandbox(ctx context.Context, workspace, sandboxName string) (*SandboxConfig, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	sb, err := c.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.GetSandboxConfig(ctx, &sbv1.GetSandboxConfigRequest{
		SandboxId: sb.ID,
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
	req.Workspace = workspace
	resp, err := c.client.UpdateConfig(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ConfigUpdateResultFromProto(resp), nil
}
