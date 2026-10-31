// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// FrozenPolicyState distinguishes a requested freeze from an accepted snapshot.
type FrozenPolicyState = types.FrozenPolicyState

// FrozenSandboxPolicy is the immutable accepted policy and its original source.
type FrozenSandboxPolicy = types.FrozenSandboxPolicy

// FrozenGlobalConfigUpdate reports a global update and its frozen exceptions.
type FrozenGlobalConfigUpdate = types.FrozenGlobalConfigUpdate

// FrozenPoliciesInterface is an optional service, separate from existing SDK interfaces.
type FrozenPoliciesInterface interface {
	Create(ctx context.Context, workspace, name string, spec *SandboxSpec, opts ...CreateOption) (*Sandbox, error)
	CreateFromTemplate(ctx context.Context, workspace, name, templateName string, spec *SandboxSpec, opts ...CreateOption) (*Sandbox, error)
	Get(ctx context.Context, workspace, name string) (*FrozenPolicyState, error)
	UpdateGlobalConfig(ctx context.Context, update *ConfigUpdate) (*FrozenGlobalConfigUpdate, error)
}

// FrozenPolicies returns the optional frozen-policy service over this client's connection.
// This accessor is intentionally separate from ClientInterface so existing clients and fakes remain compatible.
func (c *Client) FrozenPolicies() FrozenPoliciesInterface {
	return &frozenPoliciesClient{client: pb.NewFrozenSandboxPoliciesClient(c.conn)}
}

type frozenPoliciesClient struct {
	client pb.FrozenSandboxPoliciesClient
}

func (c *frozenPoliciesClient) Create(ctx context.Context, workspace, name string, spec *SandboxSpec, opts ...CreateOption) (*Sandbox, error) {
	return c.create(ctx, workspace, name, "", spec, opts...)
}

func (c *frozenPoliciesClient) CreateFromTemplate(ctx context.Context, workspace, name, templateName string, spec *SandboxSpec, opts ...CreateOption) (*Sandbox, error) {
	if templateName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "template name is required"}
	}
	if err := validateTemplateCreateSpec(spec); err != nil {
		return nil, err
	}
	return c.create(ctx, workspace, name, templateName, spec, opts...)
}

func (c *frozenPoliciesClient) create(ctx context.Context, workspace, name, templateName string, spec *SandboxSpec, opts ...CreateOption) (*Sandbox, error) {
	protoSpec, err := converter.SandboxSpecToProtoChecked(spec)
	if err != nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: err.Error()}
	}
	cfg := types.ApplyCreateOptions(opts)
	resp, err := c.client.CreateSandbox(ctx, &pb.CreateFrozenSandboxRequest{
		WorkspaceScope:   namedWorkspaceScope(workspace),
		Name:             name,
		Spec:             protoSpec,
		WorkloadTemplate: templateName,
		Labels:           converter.CopyStringMap(cfg.Labels()),
		Annotations:      converter.CopyStringMap(cfg.Annotations()),
		ServiceExposures: serviceExposuresToProto(cfg.ServiceExposures()),
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	sandbox := converter.SandboxFromProto(resp.GetSandbox())
	if sandbox == nil {
		return nil, &StatusError{Code: ErrorInternal, Message: "sandbox missing from gateway response"}
	}
	if !resp.GetFrozenPolicy().GetRequested() {
		return nil, &StatusError{Code: ErrorUnimplemented, Message: fmt.Sprintf(
			"gateway did not acknowledge frozen creation for sandbox %q (ID %q, workspace %q); remove the sandbox before retrying",
			sandbox.Name, sandbox.ID, workspace,
		)}
	}
	sandbox.ServiceURLs = converter.CopyStringMap(resp.GetServiceUrls())
	return sandbox, nil
}

func (c *frozenPoliciesClient) Get(ctx context.Context, workspace, name string) (*FrozenPolicyState, error) {
	if name == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	resp, err := c.client.GetPolicy(ctx, &pb.GetFrozenSandboxPolicyRequest{
		WorkspaceScope: namedWorkspaceScope(workspace), Name: name,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.FrozenPolicyStateFromProto(resp), nil
}

func (c *frozenPoliciesClient) UpdateGlobalConfig(ctx context.Context, update *ConfigUpdate) (*FrozenGlobalConfigUpdate, error) {
	if update == nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "update must not be nil"}
	}
	if update.Name != "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "global updates must not specify a sandbox name"}
	}
	globalUpdate := *update
	globalUpdate.Global = true
	req, err := converter.ConfigUpdateToProto(&globalUpdate)
	if err != nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: err.Error()}
	}
	resp, err := c.client.UpdateGlobalConfig(ctx, &pb.UpdateFrozenGlobalConfigRequest{
		Policy: req.Policy, SettingKey: req.SettingKey, SettingValue: req.SettingValue,
		DeleteSetting: req.DeleteSetting, Global: true, MergeOperations: req.MergeOperations,
		ExpectedResourceVersion: req.ExpectedResourceVersion, Annotations: req.Annotations,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	if resp.GetUpdate() == nil {
		return nil, &StatusError{Code: ErrorInternal, Message: "global update result missing from gateway response"}
	}
	return &FrozenGlobalConfigUpdate{
		Update:          converter.ConfigUpdateResultFromProto(resp.GetUpdate()),
		FrozenSandboxes: converter.CopyStringSlice(resp.GetFrozenSandboxes()),
	}, nil
}
