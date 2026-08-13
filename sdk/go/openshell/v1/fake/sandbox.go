// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// sandboxName extracts the name from a Sandbox pointer for use as the
// objectStore key function.
func sandboxName(sb *types.Sandbox) string {
	return sb.Name
}

// copySandbox returns a deep copy of a Sandbox pointer. All maps, slices,
// and nested pointer fields are duplicated to prevent aliasing.
func copySandbox(sb *types.Sandbox) *types.Sandbox {
	if sb == nil {
		return nil
	}
	cp := *sb
	cp.Labels = copyStringMap(sb.Labels)
	cp.Annotations = copyStringMap(sb.Annotations)
	if sb.DeletionTimestamp != nil {
		t := *sb.DeletionTimestamp
		cp.DeletionTimestamp = &t
	}
	cp.Spec = copySandboxSpec(sb.Spec)
	cp.Status = copySandboxStatus(sb.Status)
	return &cp
}

func copySandboxSpec(s types.SandboxSpec) types.SandboxSpec {
	s.Environment = copyStringMap(s.Environment)
	s.Providers = copyStringSlice(s.Providers)
	if s.Template != nil {
		t := copySandboxTemplate(*s.Template)
		s.Template = &t
	}
	if s.GPUCount != nil {
		v := *s.GPUCount
		s.GPUCount = &v
	}
	s.Policy = copySandboxPolicy(s.Policy)
	return s
}

// copySandboxPolicy returns a deep copy of a SandboxPolicy pointer.
// All sub-policies, slices, and map entries are duplicated.
func copySandboxPolicy(p *types.SandboxPolicy) *types.SandboxPolicy {
	if p == nil {
		return nil
	}
	cp := *p
	if p.Filesystem != nil {
		fs := *p.Filesystem
		fs.ReadOnly = copyStringSlice(p.Filesystem.ReadOnly)
		fs.ReadWrite = copyStringSlice(p.Filesystem.ReadWrite)
		cp.Filesystem = &fs
	}
	if p.Landlock != nil {
		ll := *p.Landlock
		cp.Landlock = &ll
	}
	if p.Process != nil {
		pr := *p.Process
		cp.Process = &pr
	}
	if p.NetworkPolicies != nil {
		np := make(map[string]types.NetworkPolicyRule, len(p.NetworkPolicies))
		for k, rule := range p.NetworkPolicies {
			r := rule
			if rule.Endpoints != nil {
				eps := make([]types.PolicyNetworkEndpoint, len(rule.Endpoints))
				for i, ep := range rule.Endpoints {
					eps[i] = copyPolicyNetworkEndpoint(ep)
				}
				r.Endpoints = eps
			}
			if rule.Binaries != nil {
				bins := make([]types.PolicyNetworkBinary, len(rule.Binaries))
				copy(bins, rule.Binaries)
				r.Binaries = bins
			}
			np[k] = r
		}
		cp.NetworkPolicies = np
	}
	if p.NetworkMiddlewares != nil {
		nm := make(map[string]types.NetworkMiddlewareConfig, len(p.NetworkMiddlewares))
		for k, mw := range p.NetworkMiddlewares {
			mw.Config = copyAnyMap(mw.Config)
			if mw.Endpoints != nil {
				ep := *mw.Endpoints
				ep.Include = copyStringSlice(mw.Endpoints.Include)
				ep.Exclude = copyStringSlice(mw.Endpoints.Exclude)
				mw.Endpoints = &ep
			}
			nm[k] = mw
		}
		cp.NetworkMiddlewares = nm
	}
	return &cp
}

func copyPolicyNetworkEndpoint(ep types.PolicyNetworkEndpoint) types.PolicyNetworkEndpoint {
	if ep.Ports != nil {
		ports := make([]uint32, len(ep.Ports))
		copy(ports, ep.Ports)
		ep.Ports = ports
	}
	if ep.Rules != nil {
		rules := make([]types.L7Rule, len(ep.Rules))
		for i, r := range ep.Rules {
			rules[i] = r
			if r.Allow != nil {
				a := *r.Allow
				a.Query = copyL7QueryMap(r.Allow.Query)
				a.Fields = copyStringSlice(r.Allow.Fields)
				a.Params = copyL7QueryMap(r.Allow.Params)
				rules[i].Allow = &a
			}
		}
		ep.Rules = rules
	}
	ep.AllowedIPs = copyStringSlice(ep.AllowedIPs)
	if ep.DenyRules != nil {
		drs := make([]types.L7DenyRule, len(ep.DenyRules))
		for i, dr := range ep.DenyRules {
			dr.Query = copyL7QueryMap(dr.Query)
			dr.Fields = copyStringSlice(dr.Fields)
			dr.Params = copyL7QueryMap(dr.Params)
			drs[i] = dr
		}
		ep.DenyRules = drs
	}
	if ep.GraphqlPersistedQueries != nil {
		gq := make(map[string]types.GraphqlOperation, len(ep.GraphqlPersistedQueries))
		for k, v := range ep.GraphqlPersistedQueries {
			v.Fields = copyStringSlice(v.Fields)
			gq[k] = v
		}
		ep.GraphqlPersistedQueries = gq
	}
	if ep.CredentialBinding != nil {
		cb := *ep.CredentialBinding
		ep.CredentialBinding = &cb
	}
	if ep.Mcp != nil {
		mcp := *ep.Mcp
		mcp.StrictToolNames = copyBoolPtr(ep.Mcp.StrictToolNames)
		mcp.AllowAllKnownMcpMethods = copyBoolPtr(ep.Mcp.AllowAllKnownMcpMethods)
		ep.Mcp = &mcp
	}
	return ep
}

func copyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyL7QueryMap(m map[string]types.L7QueryMatcher) map[string]types.L7QueryMatcher {
	if m == nil {
		return nil
	}
	cp := make(map[string]types.L7QueryMatcher, len(m))
	for k, v := range m {
		v.Any = copyStringSlice(v.Any)
		cp[k] = v
	}
	return cp
}

func copySandboxTemplate(t types.SandboxTemplate) types.SandboxTemplate {
	t.Labels = copyStringMap(t.Labels)
	t.Annotations = copyStringMap(t.Annotations)
	t.Environment = copyStringMap(t.Environment)
	if t.UserNamespaces != nil {
		v := *t.UserNamespaces
		t.UserNamespaces = &v
	}
	t.Resources = copyAnyMap(t.Resources)
	t.DriverConfig = copyAnyMap(t.DriverConfig)
	return t
}

func copyAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = copyAnyValue(v)
	}
	return cp
}

func copyAnyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return copyAnyMap(val)
	case []any:
		s := make([]any, len(val))
		for i, elem := range val {
			s[i] = copyAnyValue(elem)
		}
		return s
	default:
		return v
	}
}

func copySandboxStatus(s types.SandboxStatus) types.SandboxStatus {
	if s.Conditions != nil {
		conds := make([]types.SandboxCondition, len(s.Conditions))
		copy(conds, s.Conditions)
		s.Conditions = conds
	}
	return s
}

// copyStringMap returns a shallow copy of a string-to-string map.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// copyStringSlice returns a copy of a string slice.
func copyStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}

// fakeSandboxClient implements v1.SandboxInterface backed by an in-memory
// objectStore and watchBroadcaster.
type fakeSandboxClient struct {
	store       *objectStore[*types.Sandbox]
	broadcaster *watchBroadcaster[*types.Sandbox]
	closedFunc  func() bool
}

// newFakeSandboxClient creates a new fakeSandboxClient.
func newFakeSandboxClient(
	store *objectStore[*types.Sandbox],
	broadcaster *watchBroadcaster[*types.Sandbox],
	closedFunc func() bool,
) *fakeSandboxClient {
	return &fakeSandboxClient{
		store:       store,
		broadcaster: broadcaster,
		closedFunc:  closedFunc,
	}
}

// Create creates a new sandbox with Provisioning phase.
func (c *fakeSandboxClient) Create(_ context.Context, workspace, name string, spec *types.SandboxSpec, labels map[string]string, opts ...types.CreateOptions) (*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	if spec == nil {
		spec = &types.SandboxSpec{}
	}

	var annotations map[string]string
	if len(opts) > 0 {
		annotations = copyStringMap(opts[0].Annotations)
	}

	sb := &types.Sandbox{
		Name:            name,
		Workspace:       workspace,
		CreatedAt:       time.Now(),
		Labels:          copyStringMap(labels),
		Annotations:     annotations,
		ResourceVersion: 1,
		Spec:            copySandboxSpec(*spec),
		Status: types.SandboxStatus{
			SandboxName: name,
			Phase:       types.SandboxProvisioning,
		},
	}

	result, err := c.store.Create(workspace, sb)
	if err != nil {
		return nil, err
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventAdded,
		Object: copySandbox(result),
	}, name)

	return result, nil
}

// Get retrieves a sandbox by name.
func (c *fakeSandboxClient) Get(_ context.Context, workspace, name string) (*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return c.store.Get(workspace, name)
}

// List returns all sandboxes. ListOptions are accepted for interface
// compatibility but filtering is not implemented.
func (c *fakeSandboxClient) List(_ context.Context, workspace string, opts ...v1.ListOptions) ([]*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if len(opts) > 0 && opts[0].AllWorkspaces {
		return c.store.ListAll(), nil
	}
	return c.store.List(workspace), nil
}

// Stop transitions a sandbox to the Stopped phase.
func (c *fakeSandboxClient) Stop(_ context.Context, workspace, name string) (*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	sb, err := c.store.Get(workspace, name)
	if err != nil {
		return nil, err
	}

	sb.Status.Phase = types.SandboxStopped
	sb.ResourceVersion++

	updated, err := c.store.Update(workspace, sb)
	if err != nil {
		return nil, err
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, name)

	return updated, nil
}

// Start transitions a stopped sandbox back to the Ready phase.
func (c *fakeSandboxClient) Start(_ context.Context, workspace, name string) (*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	sb, err := c.store.Get(workspace, name)
	if err != nil {
		return nil, err
	}

	sb.Status.Phase = types.SandboxReady
	sb.ResourceVersion++

	updated, err := c.store.Update(workspace, sb)
	if err != nil {
		return nil, err
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, name)

	return updated, nil
}

// WaitStopped polls until a sandbox reaches the Stopped phase.
func (c *fakeSandboxClient) WaitStopped(ctx context.Context, workspace, name string, _ ...v1.WaitOptions) (*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	select {
	case <-ctx.Done():
		err := ctx.Err()
		switch err {
		case context.DeadlineExceeded:
			return nil, &types.StatusError{Code: types.ErrorDeadlineExceeded, Message: err.Error(), Cause: err}
		case context.Canceled:
			return nil, &types.StatusError{Code: types.ErrorCancelled, Message: err.Error(), Cause: err}
		default:
			return nil, &types.StatusError{Code: types.ErrorInternal, Message: err.Error(), Cause: err}
		}
	default:
	}

	sb, err := c.store.Get(workspace, name)
	if err != nil {
		return nil, err
	}

	if sb.Status.Phase == types.SandboxStopped {
		return sb, nil
	}

	sb.Status.Phase = types.SandboxStopped
	sb.ResourceVersion++

	updated, err := c.store.Update(workspace, sb)
	if err != nil {
		return nil, err
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, name)

	return updated, nil
}

// Delete removes a sandbox by name. The operation is idempotent.
func (c *fakeSandboxClient) Delete(_ context.Context, workspace, name string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	deleted, existed := c.store.DeleteAndGet(workspace, name)
	if !existed {
		// Not found — idempotent delete
		return nil
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventDeleted,
		Object: deleted,
	}, name)

	return nil
}

// WaitReady transitions a sandbox to the Ready phase. In the fake
// implementation this happens synchronously — context cancellation is
// checked first to support timeout testing.
func (c *fakeSandboxClient) WaitReady(ctx context.Context, workspace, name string, _ ...v1.WaitOptions) (*types.Sandbox, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	select {
	case <-ctx.Done():
		err := ctx.Err()
		switch err {
		case context.DeadlineExceeded:
			return nil, &types.StatusError{Code: types.ErrorDeadlineExceeded, Message: err.Error(), Cause: err}
		case context.Canceled:
			return nil, &types.StatusError{Code: types.ErrorCancelled, Message: err.Error(), Cause: err}
		default:
			return nil, &types.StatusError{Code: types.ErrorInternal, Message: err.Error(), Cause: err}
		}
	default:
	}

	sb, err := c.store.Get(workspace, name)
	if err != nil {
		return nil, err
	}

	// If already ready, return immediately
	if sb.Status.Phase == types.SandboxReady {
		return sb, nil
	}

	sb.Status.Phase = types.SandboxReady
	sb.ResourceVersion++

	updated, err := c.store.Update(workspace, sb)
	if err != nil {
		return nil, fmt.Errorf("updating sandbox phase: %w", err)
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, name)

	return updated, nil
}

// Watch registers a watcher for sandbox events. If name is non-empty, only
// events for that sandbox are delivered. When StopOnTerminal is set, the
// watcher auto-closes after delivering a terminal phase event (SandboxReady
// or SandboxError).
func (c *fakeSandboxClient) Watch(ctx context.Context, _, name string, opts ...v1.WatchOptions) (types.WatchInterface[*types.Sandbox], error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	inner := c.broadcaster.Watch(name)
	if done := ctx.Done(); done != nil {
		go func() {
			<-done
			inner.Stop()
		}()
	}

	var stopOnTerminal bool
	if len(opts) > 0 {
		stopOnTerminal = opts[0].StopOnTerminal
	}

	if !stopOnTerminal {
		return inner, nil
	}

	// Wrap with a filtering watcher that auto-stops after terminal events.
	out := make(chan types.Event[*types.Sandbox], watchChannelBuffer)
	tw := &terminalWatcher{
		ch:     out,
		inner:  inner,
		stopCh: make(chan struct{}),
	}
	go func() {
		defer close(out)
		for ev := range inner.ResultChan() {
			select {
			case out <- ev:
			case <-ctx.Done():
				inner.Stop()
				return
			case <-tw.stopCh:
				return
			}
			if ev.Object != nil &&
				(ev.Object.Status.Phase == types.SandboxReady || ev.Object.Status.Phase == types.SandboxError) {
				inner.Stop()
				return
			}
		}
	}()
	return tw, nil
}

// terminalWatcher wraps an inner watcher and exposes its own output channel.
type terminalWatcher struct {
	ch     chan types.Event[*types.Sandbox]
	inner  types.WatchInterface[*types.Sandbox]
	once   sync.Once
	stopCh chan struct{}
}

func (w *terminalWatcher) ResultChan() <-chan types.Event[*types.Sandbox] {
	return w.ch
}

func (w *terminalWatcher) Stop() {
	w.once.Do(func() {
		close(w.stopCh)
		w.inner.Stop()
	})
}

// AttachProvider adds a provider name to the sandbox's Spec.Providers list.
// If the provider is already attached, Attached is false (idempotent).
// The sandbox's ResourceVersion is incremented and a MODIFIED event is
// broadcast.
func (c *fakeSandboxClient) AttachProvider(_ context.Context, workspace, sandboxName, providerName string, _ uint64) (*types.AttachProviderResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	sb, err := c.store.Get(workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	// Check if already attached
	for _, p := range sb.Spec.Providers {
		if p == providerName {
			return &types.AttachProviderResult{
				Sandbox:  sb,
				Attached: false,
			}, nil
		}
	}

	sb.Spec.Providers = append(sb.Spec.Providers, providerName)
	sb.ResourceVersion++

	updated, err := c.store.Update(workspace, sb)
	if err != nil {
		return nil, err
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, sandboxName)

	return &types.AttachProviderResult{
		Sandbox:  updated,
		Attached: true,
	}, nil
}

// DetachProvider removes a provider name from the sandbox's Spec.Providers
// list. If the provider is not attached, Detached is false (idempotent).
// The sandbox's ResourceVersion is incremented and a MODIFIED event is
// broadcast when a provider is actually removed.
func (c *fakeSandboxClient) DetachProvider(_ context.Context, workspace, sandboxName, providerName string, _ uint64) (*types.DetachProviderResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	sb, err := c.store.Get(workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	// Find and remove the provider
	found := false
	providers := make([]string, 0, len(sb.Spec.Providers))
	for _, p := range sb.Spec.Providers {
		if p == providerName {
			found = true
			continue
		}
		providers = append(providers, p)
	}

	if !found {
		return &types.DetachProviderResult{
			Sandbox:  sb,
			Detached: false,
		}, nil
	}

	sb.Spec.Providers = providers
	sb.ResourceVersion++

	updated, err := c.store.Update(workspace, sb)
	if err != nil {
		return nil, err
	}

	c.broadcaster.Broadcast(types.Event[*types.Sandbox]{
		Type:   types.EventModified,
		Object: copySandbox(updated),
	}, sandboxName)

	return &types.DetachProviderResult{
		Sandbox:  updated,
		Detached: true,
	}, nil
}

// GetLogs returns Unimplemented — fake log retrieval is not yet supported.
func (c *fakeSandboxClient) GetLogs(_ context.Context, _, _ string, _ ...v1.LogOption) (*types.LogResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetLogs not implemented in fake client"}
}

// ListProviders returns stub Provider objects for each provider name
// attached to the sandbox. The returned providers contain only the Name
// field, since the fake client does not maintain a full provider registry
// per sandbox.
func (c *fakeSandboxClient) ListProviders(_ context.Context, workspace, sandboxName string) ([]*types.Provider, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	sb, err := c.store.Get(workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	result := make([]*types.Provider, len(sb.Spec.Providers))
	for i, name := range sb.Spec.Providers {
		result[i] = &types.Provider{Name: name}
	}
	return result, nil
}
