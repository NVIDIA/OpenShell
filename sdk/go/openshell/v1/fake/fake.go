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
	sandboxBroadcaster *watchBroadcaster[*types.Sandbox]

	sandboxes v1.SandboxInterface
	providers v1.ProviderInterface
	services  v1.ServiceInterface
	exec      v1.ExecInterface
	files     v1.FileInterface
	health    v1.HealthInterface
	ssh       v1.SSHInterface
	tcp       v1.TCPInterface
	cfg       v1.ConfigInterface
	policy    v1.PolicyInterface

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
		fc.health = newFakeHealthClient(r, fc.isClosed)
	}
}

// NewClient creates a new Client with all sub-clients wired up.
// Options (e.g., WithHealthResult) are applied after the default setup.
func NewClient(opts ...ClientOption) *Client {
	fc := &Client{
		sandboxStore:       newobjectStore(sandboxName, copySandbox),
		providerStore:      newobjectStore(providerName, copyProvider),
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
func (fc *Client) AddSandbox(sb *types.Sandbox) {
	fc.sandboxStore.Insert(sb)
}

// AddProvider inserts a provider directly into the store without triggering
// any side effects. This is intended for pre-seeding test fixtures before
// the test begins. The provider is deep-copied on insert.
func (fc *Client) AddProvider(p *types.Provider) {
	fc.providerStore.Insert(p)
}

// Compile-time interface check.
var _ v1.ClientInterface = (*Client)(nil)
