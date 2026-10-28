// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type cedarCompatibilityClient struct {
	pb.OpenShellClient
	supported bool
	checks    int
	mutations int
}

func (c *cedarCompatibilityClient) Health(context.Context, *pb.HealthRequest, ...grpc.CallOption) (*pb.HealthResponse, error) {
	c.checks++
	return &pb.HealthResponse{SupportsCedarPolicy: c.supported}, nil
}
func (c *cedarCompatibilityClient) CreateSandbox(context.Context, *pb.CreateSandboxRequest, ...grpc.CallOption) (*pb.SandboxResponse, error) {
	c.mutations++
	return &pb.SandboxResponse{}, nil
}
func (c *cedarCompatibilityClient) UpdateConfig(context.Context, *pb.UpdateConfigRequest, ...grpc.CallOption) (*pb.UpdateConfigResponse, error) {
	c.mutations++
	return &pb.UpdateConfigResponse{}, nil
}
func TestCedarChecksBeforeMutations(t *testing.T) {
	for _, supported := range []bool{false, true} {
		wire := &cedarCompatibilityClient{supported: supported}
		sandboxes := &sandboxClient{client: wire}
		config := &configClient{client: wire}
		policy := &SandboxPolicy{CedarPolicySource: `permit(principal, action, resource);`}
		calls := []func() error{
			func() error {
				_, err := sandboxes.Create(context.Background(), "default", "cedar", &SandboxSpec{Policy: policy}, nil)
				return err
			},
			func() error {
				_, err := sandboxes.CreateFromTemplate(context.Background(), "default", "cedar", "python", &SandboxSpec{Policy: policy}, nil)
				return err
			},
			func() error {
				_, err := config.Update(context.Background(), "default", &ConfigUpdate{Policy: policy})
				return err
			},
		}
		for _, call := range calls {
			if supported {
				require.NoError(t, call())
			} else {
				require.ErrorContains(t, call(), "Cedar policy support")
			}
		}
		require.Equal(t, len(calls), wire.checks)
		if supported {
			require.Equal(t, len(calls), wire.mutations)
		} else {
			require.Zero(t, wire.mutations)
		}
		require.NoError(t, requireCedarPolicySupport(context.Background(), wire, &sbv1.SandboxPolicy{}))
		require.Equal(t, len(calls), wire.checks, "YAML must not require capability negotiation")
	}
}
