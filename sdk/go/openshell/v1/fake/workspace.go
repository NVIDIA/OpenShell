// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func workspaceName(ws *types.Workspace) string {
	return ws.Name
}

func copyWorkspace(ws *types.Workspace) *types.Workspace {
	if ws == nil {
		return nil
	}
	cp := *ws
	cp.Labels = copyStringMap(ws.Labels)
	cp.Annotations = copyStringMap(ws.Annotations)
	if ws.DeletionTimestamp != nil {
		t := *ws.DeletionTimestamp
		cp.DeletionTimestamp = &t
	}
	return &cp
}

func memberName(m *types.WorkspaceMember) string {
	return m.PrincipalSubject
}

func copyMember(m *types.WorkspaceMember) *types.WorkspaceMember {
	if m == nil {
		return nil
	}
	cp := *m
	cp.Labels = copyStringMap(m.Labels)
	cp.Annotations = copyStringMap(m.Annotations)
	return &cp
}

type fakeWorkspaceClient struct {
	workspaceStore *objectStore[*types.Workspace]
	memberStore    *objectStore[*types.WorkspaceMember]
	closedFunc     func() bool
}

func newFakeWorkspaceClient(
	workspaceStore *objectStore[*types.Workspace],
	memberStore *objectStore[*types.WorkspaceMember],
	closedFunc func() bool,
) *fakeWorkspaceClient {
	return &fakeWorkspaceClient{
		workspaceStore: workspaceStore,
		memberStore:    memberStore,
		closedFunc:     closedFunc,
	}
}

func (c *fakeWorkspaceClient) Create(_ context.Context, name string, labels map[string]string) (*types.Workspace, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if name == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}

	ws := &types.Workspace{
		Name:            name,
		CreatedAt:       time.Now(),
		Labels:          copyStringMap(labels),
		ResourceVersion: 1,
		Phase:           types.WorkspaceActive,
	}

	return c.workspaceStore.Create("", ws)
}

func (c *fakeWorkspaceClient) Get(_ context.Context, name string) (*types.Workspace, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if name == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}
	return c.workspaceStore.Get("", name)
}

// List returns all workspaces. ListOptions are accepted for interface compatibility but filtering is not implemented.
func (c *fakeWorkspaceClient) List(_ context.Context, _ ...v1.ListOptions) ([]*types.Workspace, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return c.workspaceStore.ListAll(), nil
}

// Delete removes a workspace. Unlike the sandbox fake (which treats delete as
// idempotent), workspace delete returns NotFound for non-existent workspaces to
// match the gateway's workspace deletion behavior.
func (c *fakeWorkspaceClient) Delete(_ context.Context, name string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if name == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}

	_, existed := c.workspaceStore.DeleteAndGet("", name)
	if !existed {
		return &types.StatusError{Code: types.ErrorNotFound, Message: name + " not found"}
	}
	c.memberStore.DeleteWorkspace(name)
	return nil
}

func (c *fakeWorkspaceClient) AddMember(_ context.Context, workspace, principalSubject string, role types.WorkspaceRole) (*types.WorkspaceMember, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if workspace == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}
	if principalSubject == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "principal subject must not be empty"}
	}
	if role != types.WorkspaceRoleAdmin && role != types.WorkspaceRoleUser {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "role must be Admin or User"}
	}

	member := &types.WorkspaceMember{
		Name:             principalSubject,
		CreatedAt:        time.Now(),
		ResourceVersion:  1,
		PrincipalSubject: principalSubject,
		Role:             role,
	}

	return c.memberStore.Create(workspace, member)
}

func (c *fakeWorkspaceClient) RemoveMember(_ context.Context, workspace, principalSubject string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if workspace == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}
	if principalSubject == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "principal subject must not be empty"}
	}

	_, existed := c.memberStore.DeleteAndGet(workspace, principalSubject)
	if !existed {
		return &types.StatusError{Code: types.ErrorNotFound, Message: principalSubject + " not found"}
	}
	return nil
}

// ListMembers returns all members for the workspace. ListOptions are accepted for interface compatibility but filtering is not implemented.
func (c *fakeWorkspaceClient) ListMembers(_ context.Context, workspace string, _ ...v1.ListOptions) ([]*types.WorkspaceMember, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if workspace == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace name must not be empty"}
	}
	return c.memberStore.List(workspace), nil
}
