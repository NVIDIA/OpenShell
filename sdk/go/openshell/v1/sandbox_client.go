// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

const defaultPollInterval = 500 * time.Millisecond

type sandboxClient struct {
	client pb.OpenShellClient
}

func newSandboxClient(conn grpc.ClientConnInterface) *sandboxClient {
	return &sandboxClient{client: pb.NewOpenShellClient(conn)}
}

func (s *sandboxClient) Create(ctx context.Context, workspace, name string, spec *SandboxSpec, labels map[string]string) (*Sandbox, error) {
	pbSpec, err := converter.SandboxSpecToProto(spec)
	if err != nil {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: err.Error()}
	}
	resp, err := s.client.CreateSandbox(ctx, &pb.CreateSandboxRequest{
		Name:      name,
		Spec:      pbSpec,
		Labels:    labels,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxFromProto(resp.GetSandbox()), nil
}

func (s *sandboxClient) Get(ctx context.Context, workspace, name string) (*Sandbox, error) {
	resp, err := s.client.GetSandbox(ctx, &pb.GetSandboxRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxFromProto(resp.GetSandbox()), nil
}

func (s *sandboxClient) List(ctx context.Context, workspace string, opts ...ListOptions) ([]*Sandbox, error) {
	req := &pb.ListSandboxesRequest{
		Workspace: workspace,
	}
	if len(opts) > 0 {
		if opts[0].Limit > 0 {
			req.Limit = uint32(opts[0].Limit)
		}
		if opts[0].Offset > 0 {
			req.Offset = uint32(opts[0].Offset)
		}
		req.LabelSelector = opts[0].LabelSelector
		req.AllWorkspaces = opts[0].AllWorkspaces
	}

	resp, err := s.client.ListSandboxes(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	sandboxes := make([]*Sandbox, 0, len(resp.GetSandboxes()))
	for _, proto := range resp.GetSandboxes() {
		sandboxes = append(sandboxes, converter.SandboxFromProto(proto))
	}
	return sandboxes, nil
}

func (s *sandboxClient) Delete(ctx context.Context, workspace, name string) error {
	_, err := s.client.DeleteSandbox(ctx, &pb.DeleteSandboxRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (s *sandboxClient) Stop(ctx context.Context, workspace, name string) (*Sandbox, error) {
	resp, err := s.client.StopSandbox(ctx, &pb.StopSandboxRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxFromProto(resp.GetSandbox()), nil
}

func (s *sandboxClient) Start(ctx context.Context, workspace, name string) (*Sandbox, error) {
	resp, err := s.client.StartSandbox(ctx, &pb.StartSandboxRequest{
		Name:      name,
		Workspace: workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SandboxFromProto(resp.GetSandbox()), nil
}

func (s *sandboxClient) AttachProvider(ctx context.Context, workspace, sandboxName, providerName string, expectedResourceVersion uint64) (*AttachProviderResult, error) {
	resp, err := s.client.AttachSandboxProvider(ctx, &pb.AttachSandboxProviderRequest{
		SandboxName:             sandboxName,
		ProviderName:            providerName,
		ExpectedResourceVersion: expectedResourceVersion,
		Workspace:               workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return &AttachProviderResult{
		Sandbox:  converter.SandboxFromProto(resp.GetSandbox()),
		Attached: resp.GetAttached(),
	}, nil
}

func (s *sandboxClient) DetachProvider(ctx context.Context, workspace, sandboxName, providerName string, expectedResourceVersion uint64) (*DetachProviderResult, error) {
	resp, err := s.client.DetachSandboxProvider(ctx, &pb.DetachSandboxProviderRequest{
		SandboxName:             sandboxName,
		ProviderName:            providerName,
		ExpectedResourceVersion: expectedResourceVersion,
		Workspace:               workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return &DetachProviderResult{
		Sandbox:  converter.SandboxFromProto(resp.GetSandbox()),
		Detached: resp.GetDetached(),
	}, nil
}

func (s *sandboxClient) ListProviders(ctx context.Context, workspace, sandboxName string) ([]*Provider, error) {
	resp, err := s.client.ListSandboxProviders(ctx, &pb.ListSandboxProvidersRequest{
		SandboxName: sandboxName,
		Workspace:   workspace,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	providers := make([]*Provider, 0, len(resp.GetProviders()))
	for _, proto := range resp.GetProviders() {
		providers = append(providers, converter.ProviderFromProto(proto))
	}
	return providers, nil
}

func (s *sandboxClient) WaitReady(ctx context.Context, workspace, name string, opts ...WaitOptions) (*Sandbox, error) {
	return s.waitForPhase(ctx, workspace, name, SandboxReady, opts...)
}

func (s *sandboxClient) WaitStopped(ctx context.Context, workspace, name string, opts ...WaitOptions) (*Sandbox, error) {
	return s.waitForPhase(ctx, workspace, name, SandboxStopped, opts...)
}

func (s *sandboxClient) waitForPhase(ctx context.Context, workspace, name string, target SandboxPhase, opts ...WaitOptions) (*Sandbox, error) {
	interval := defaultPollInterval
	if len(opts) > 0 && opts[0].PollInterval > 0 {
		interval = opts[0].PollInterval
	}

	sb, err := s.Get(ctx, workspace, name)
	if err != nil {
		return nil, err
	}

	if sb.Status.Phase == target {
		return sb, nil
	}
	if sb.Status.Phase == SandboxError {
		return nil, &StatusError{Code: ErrorInternal, Message: fmt.Sprintf("sandbox %q is in error state", name)}
	}
	if sb.Status.Phase == SandboxDeleting {
		return nil, &StatusError{Code: ErrorInternal, Message: fmt.Sprintf("sandbox %q is being deleted", name)}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, contextError(ctx.Err())
		case <-ticker.C:
			sb, err = s.Get(ctx, workspace, name)
			if err != nil {
				return nil, err
			}
			if sb.Status.Phase == target {
				return sb, nil
			}
			if sb.Status.Phase == SandboxError {
				return nil, &StatusError{Code: ErrorInternal, Message: fmt.Sprintf("sandbox %q is in error state", name)}
			}
			if sb.Status.Phase == SandboxDeleting {
				return nil, &StatusError{Code: ErrorInternal, Message: fmt.Sprintf("sandbox %q is being deleted", name)}
			}
		}
	}
}

func (s *sandboxClient) Watch(ctx context.Context, workspace, name string, opts ...WatchOptions) (WatchInterface[*Sandbox], error) {
	if name == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}

	var watchOpts WatchOptions
	if len(opts) > 0 {
		watchOpts = opts[0]
	}

	// Resolve sandbox name to ID — the proto RPC takes Id, not name.
	sb, err := s.Get(ctx, workspace, name)
	if err != nil {
		return nil, err
	}

	streamCtx, streamCancel := context.WithCancel(ctx)
	stream, err := s.client.WatchSandbox(streamCtx, &pb.WatchSandboxRequest{
		Id:             sb.ID,
		FollowStatus:   true,
		StopOnTerminal: watchOpts.StopOnTerminal,
	})
	if err != nil {
		streamCancel()
		return nil, converter.FromGRPCError(err)
	}

	first, err := stream.Recv()
	if err != nil {
		streamCancel()
		return nil, converter.FromGRPCError(err)
	}

	ch := make(chan Event[*Sandbox], 64)
	w := newWatcher(ch, streamCancel)

	go func() {
		defer close(ch)
		defer streamCancel()
		ev := first
		isFirst := true
		for {
			if sbPayload, ok := ev.Payload.(*pb.SandboxStreamEvent_Sandbox); ok && sbPayload.Sandbox != nil {
				sandbox := converter.SandboxFromProto(sbPayload.Sandbox)
				eventType := EventModified
				if isFirst {
					eventType = EventAdded
					isFirst = false
				} else if sandbox.Status.Phase == SandboxDeleting {
					eventType = EventDeleted
				}
				select {
				case ch <- Event[*Sandbox]{Type: eventType, Object: sandbox}:
				case <-w.done:
					return
				}
				// StopOnTerminal: close watcher after delivering a terminal phase event
				if watchOpts.StopOnTerminal && (sandbox.Status.Phase == SandboxReady || sandbox.Status.Phase == SandboxError) {
					w.Stop()
					return
				}
			}
			var recvErr error
			ev, recvErr = stream.Recv()
			if recvErr != nil {
				if recvErr != io.EOF {
					select {
					case ch <- Event[*Sandbox]{Type: EventError, Err: converter.FromGRPCError(recvErr)}:
					case <-w.done:
					}
				}
				return
			}
		}
	}()

	return w, nil
}

func (s *sandboxClient) GetLogs(ctx context.Context, workspace, sandboxName string, opts ...LogOption) (*LogResult, error) {
	// Resolve sandbox name to ID — the proto RPC takes SandboxId, not name.
	sb, err := s.Get(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	cfg := types.ApplyLogOptions(opts)
	req := &pb.GetSandboxLogsRequest{
		SandboxId: sb.ID,
		Lines:     cfg.Lines(),
		Sources:   cfg.Sources(),
		MinLevel:  cfg.MinLevel(),
		Workspace: workspace,
	}
	if !cfg.Since().IsZero() {
		req.SinceMs = converter.MillisFromTime(cfg.Since())
	}

	resp, err := s.client.GetSandboxLogs(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.LogResultFromProto(resp), nil
}
