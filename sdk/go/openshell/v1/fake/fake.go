// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"sync"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Client implements v1.ClientInterface with in-memory stores. It is
// designed for testing consumers of the OpenShell SDK without requiring a
// real gRPC connection. Create one with NewClient.
type Client struct {
	sandboxStore       *objectStore[*types.Sandbox]
	providerStore      *objectStore[*types.Provider]
	workspaceStore     *objectStore[*types.Workspace]
	memberStore        *objectStore[*types.WorkspaceMember]
	sandboxBroadcaster *watchBroadcaster[*types.Sandbox]

	sandboxes  v1.SandboxInterface
	providers  v1.ProviderInterface
	services   v1.ServiceInterface
	exec       v1.ExecInterface
	files      v1.FileInterface
	health     v1.HealthInterface
	ssh        v1.SSHInterface
	tcp        v1.TCPInterface
	cfg        v1.ConfigInterface
	policy     v1.PolicyInterface
	workspaces v1.WorkspaceInterface
	inference  v1.InferenceInterface

	closeOnce sync.Once
	closed    bool
	mu        sync.RWMutex // guards closed flag
}

// ClientOption configures a Client during construction.
type ClientOption func(*Client)

// WithHealthResult returns an option that configures the health sub-client
// to return the given result instead of the default healthy response.
func WithHealthResult(r *types.HealthResult) ClientOption {
	return func(fc *Client) {
		fc.health.(*fakeHealthClient).result = r
	}
}

// WithGatewayInfo returns an option that configures the health sub-client
// to return the given gateway info instead of the default response.
func WithGatewayInfo(info *types.GatewayInfo) ClientOption {
	return func(fc *Client) {
		fc.health.(*fakeHealthClient).gatewayInfo = copyGatewayInfo(info)
	}
}

// WithCurrentUser returns an option that configures the health sub-client
// to return the given current user instead of the default response.
func WithCurrentUser(user *types.CurrentUser) ClientOption {
	return func(fc *Client) {
		fc.health.(*fakeHealthClient).currentUser = copyCurrentUser(user)
	}
}

// NewClient creates a new Client with all sub-clients wired up.
// Options (e.g., WithHealthResult) are applied after the default setup.
func NewClient(opts ...ClientOption) *Client {
	fc := &Client{
		sandboxStore:       newobjectStore(sandboxName, copySandbox),
		providerStore:      newobjectStore(providerName, copyProvider),
		workspaceStore:     newobjectStore(workspaceName, copyWorkspace),
		memberStore:        newobjectStore(memberName, copyMember),
		sandboxBroadcaster: newWatchBroadcaster[*types.Sandbox](),
	}

	fc.sandboxes = newFakeSandboxClient(fc.sandboxStore, fc.sandboxBroadcaster, fc.isClosed)
	fc.providers = newFakeProviderClient(fc.providerStore, fc.isClosed)
	fc.services = newFakeServiceClient(fc.isClosed)
	fc.exec = newFakeExecClient(fc.isClosed)
	fc.files = newFakeFileClient(fc.isClosed)
	fc.health = newFakeHealthClient(nil, fc.isClosed)
	fc.ssh = newFakeSSHClient(fc.isClosed)
	fc.tcp = newFakeTCPClient(fc.isClosed)
	fc.cfg = newFakeConfigClient(fc.isClosed)
	fc.policy = newFakePolicyClient(fc.isClosed)
	fc.workspaces = newFakeWorkspaceClient(fc.workspaceStore, fc.memberStore, fc.isClosed)
	fc.inference = newFakeInferenceClient(fc.isClosed)

	for _, opt := range opts {
		opt(fc)
	}

	return fc
}

// isClosed returns true if the client has been closed. This is passed to
// all sub-clients as the closedFunc parameter.
func (fc *Client) isClosed() bool {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.closed
}

// Sandboxes returns the sandbox sub-client.
func (fc *Client) Sandboxes() v1.SandboxInterface { return fc.sandboxes }

// Providers returns the provider sub-client.
func (fc *Client) Providers() v1.ProviderInterface { return fc.providers }

// Services returns the service sub-client.
func (fc *Client) Services() v1.ServiceInterface { return fc.services }

// Exec returns the exec sub-client.
func (fc *Client) Exec() v1.ExecInterface { return fc.exec }

// Files returns the file sub-client.
func (fc *Client) Files() v1.FileInterface { return fc.files }

// Health returns the health sub-client.
func (fc *Client) Health() v1.HealthInterface { return fc.health }

// SSH returns the SSH session sub-client.
func (fc *Client) SSH() v1.SSHInterface { return fc.ssh }

// TCP returns the TCP port forwarding sub-client.
func (fc *Client) TCP() v1.TCPInterface { return fc.tcp }

// Config returns the configuration sub-client.
func (fc *Client) Config() v1.ConfigInterface { return fc.cfg }

// Policy returns the policy management sub-client.
func (fc *Client) Policy() v1.PolicyInterface { return fc.policy }

// Workspaces returns the workspace management sub-client.
func (fc *Client) Workspaces() v1.WorkspaceInterface { return fc.workspaces }

// Inference returns the inference route management sub-client.
func (fc *Client) Inference() v1.InferenceInterface { return fc.inference }

// Close marks the client as closed, stops all active watchers, and causes
// subsequent sub-client calls to return Unavailable. Safe to call multiple
// times.
func (fc *Client) Close() error {
	fc.closeOnce.Do(func() {
		fc.mu.Lock()
		fc.closed = true
		fc.mu.Unlock()

		fc.sandboxBroadcaster.StopAll()
	})
	return nil
}

// AddSandbox inserts a sandbox directly into the store without triggering
// watch events. This is intended for pre-seeding test fixtures before the
// test begins. The sandbox is deep-copied on insert.
func (fc *Client) AddSandbox(workspace string, sb *types.Sandbox) {
	if sb == nil {
		return
	}
	fc.sandboxStore.Insert(workspace, sb)
}

// AddProvider inserts a provider directly into the store without triggering
// any side effects. This is intended for pre-seeding test fixtures before
// the test begins. The provider is deep-copied on insert.
func (fc *Client) AddProvider(workspace string, p *types.Provider) {
	if p == nil {
		return
	}
	fc.providerStore.Insert(workspace, p)
}

// AddWorkspace inserts a workspace directly into the store without triggering
// any side effects. This is intended for pre-seeding test fixtures before
// the test begins. The workspace is deep-copied on insert.
func (fc *Client) AddWorkspace(ws *types.Workspace) {
	if ws == nil {
		return
	}
	fc.workspaceStore.Insert("", ws)
}

// AddMember inserts a workspace member directly into the store without
// triggering any side effects. This is intended for pre-seeding test fixtures
// before the test begins. The member is deep-copied on insert.
func (fc *Client) AddMember(workspace string, m *types.WorkspaceMember) {
	if m == nil {
		return
	}
	fc.memberStore.Insert(workspace, m)
}

// AddGlobalRevision adds a gateway-global policy revision for test seeding.
// Global revisions are returned by Policy().List() and Policy().GetStatus()
// when the global option is enabled.
func (fc *Client) AddGlobalRevision(rev types.SandboxPolicyRevision) {
	fc.policy.(*fakePolicyClient).AddGlobalRevision(rev)
}

// AddRevision adds a sandbox-scoped policy revision for test seeding.
// Sandbox revisions are returned by Policy().List() and Policy().GetStatus()
// when the global option is not set.
func (fc *Client) AddRevision(workspace, name string, rev types.SandboxPolicyRevision) {
	fc.policy.(*fakePolicyClient).AddRevision(workspace, name, rev)
}

// Compile-time interface check.
var _ v1.ClientInterface = (*Client)(nil)
