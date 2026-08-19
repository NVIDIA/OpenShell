// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func sandboxTemplateName(template *types.SandboxTemplate) string {
	return template.Name
}

func copySandboxTemplatePtr(template *types.SandboxTemplate) *types.SandboxTemplate {
	if template == nil {
		return nil
	}
	copied := copySandboxTemplate(*template)
	return &copied
}

type fakeSandboxTemplateClient struct {
	store      *objectStore[*types.SandboxTemplate]
	closedFunc func() bool
}

func newFakeSandboxTemplateClient(
	store *objectStore[*types.SandboxTemplate],
	closedFunc func() bool,
) *fakeSandboxTemplateClient {
	return &fakeSandboxTemplateClient{
		store:      store,
		closedFunc: closedFunc,
	}
}

func (c *fakeSandboxTemplateClient) Create(_ context.Context, workspace string, template *types.SandboxTemplate) (*types.SandboxTemplate, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if template == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "template must not be nil"}
	}

	t := copySandboxTemplatePtr(template)
	t.Workspace = workspace
	t.CreatedAt = time.Now()
	t.ResourceVersion = 1

	return c.store.Create(workspace, t)
}

func (c *fakeSandboxTemplateClient) Get(_ context.Context, workspace, name string) (*types.SandboxTemplate, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return c.store.Get(workspace, name)
}

func (c *fakeSandboxTemplateClient) List(_ context.Context, workspace string, opts ...v1.ListOptions) ([]*types.SandboxTemplate, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if len(opts) > 0 && opts[0].AllWorkspaces {
		return c.store.ListAll(), nil
	}
	return c.store.List(workspace), nil
}

func (c *fakeSandboxTemplateClient) Delete(_ context.Context, workspace, name string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	c.store.Delete(workspace, name)
	return nil
}
