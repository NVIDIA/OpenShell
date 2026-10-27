// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

// ServiceRouteSnapshot is a complete replacement view of workspace installations.
type ServiceRouteSnapshot = types.ServiceRouteSnapshot

// DiscoveredServiceRoute identifies an installed service and its current supervisor.
type DiscoveredServiceRoute = types.DiscoveredServiceRoute

// ServiceRouteEndpoint is the trusted supervisor TLS endpoint.
type ServiceRouteEndpoint = types.ServiceRouteEndpoint

// ServiceRouteScope selects a nonempty workspace set or all active workspaces.
type ServiceRouteScope = types.ServiceRouteScope

// ServiceRouteWatch delivers full replacements. Call Recv from one goroutine;
// Close is safe concurrently. EOF is normal bounded stream completion: reconnect
// and relist. Errors are not empty replacements. Expire cached routes independently.
type ServiceRouteWatch interface {
	Recv() (*ServiceRouteSnapshot, error)
	Close()
}

// ServiceDiscoveryInterface is a narrow interface for external discovery consumers.
// Selection never grants authority: the gateway must authorize every requested workspace.
type ServiceDiscoveryInterface interface {
	Snapshot(ctx context.Context, workspace string) (*ServiceRouteSnapshot, error)
	Watch(ctx context.Context, workspace string) (ServiceRouteWatch, error)
	SnapshotFor(ctx context.Context, scope ServiceRouteScope) (*ServiceRouteSnapshot, error)
	WatchFor(ctx context.Context, scope ServiceRouteScope) (ServiceRouteWatch, error)
}

type serviceDiscoveryClient struct{ client pb.OpenShellClient }

func newServiceDiscoveryClient(conn grpc.ClientConnInterface) *serviceDiscoveryClient {
	return &serviceDiscoveryClient{client: pb.NewOpenShellClient(conn)}
}

func discoveryScope(scope ServiceRouteScope) (ServiceRouteScope, error) {
	invalid := func() (ServiceRouteScope, error) {
		return ServiceRouteScope{}, &StatusError{Code: ErrorInvalidArgument, Message: "choose up to 64 distinct workspaces or all workspaces"}
	}
	if scope.AllWorkspaces == (len(scope.Workspaces) > 0) || len(scope.Workspaces) > 64 {
		return invalid()
	}
	scope.Workspaces = slices.Clone(scope.Workspaces)
	slices.Sort(scope.Workspaces)
	for i, name := range scope.Workspaces {
		if name == "" || len(name) > 19 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") || (i > 0 && name == scope.Workspaces[i-1]) {
			return invalid()
		}
		for _, c := range name {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return invalid()
			}
		}
	}
	return scope, nil
}

func (s *serviceDiscoveryClient) Snapshot(ctx context.Context, workspace string) (*ServiceRouteSnapshot, error) {
	return s.SnapshotFor(ctx, ServiceRouteScope{Workspaces: []string{workspace}})
}
func (s *serviceDiscoveryClient) Watch(ctx context.Context, workspace string) (ServiceRouteWatch, error) {
	return s.WatchFor(ctx, ServiceRouteScope{Workspaces: []string{workspace}})
}

// SnapshotFor returns one complete replacement view for the selected discovery scope.
func (s *serviceDiscoveryClient) SnapshotFor(ctx context.Context, requested ServiceRouteScope) (*ServiceRouteSnapshot, error) {
	scope, err := discoveryScope(requested)
	if err != nil {
		return nil, err
	}
	request := &pb.GetServiceRouteSnapshotRequest{}
	if scope.AllWorkspaces {
		request.WorkspaceScope = allWorkspacesScope()
	} else if len(scope.Workspaces) == 1 {
		request.WorkspaceScope = namedWorkspaceScope(scope.Workspaces[0])
	} else {
		request.Workspaces = scope.Workspaces
	}
	response, err := s.client.GetServiceRouteSnapshot(ctx, request)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.ServiceRouteSnapshotForScopeFromProto(response.GetSnapshot(), scope)
}

// WatchFor watches complete replacements, leaving reconnect policy to the caller.
func (s *serviceDiscoveryClient) WatchFor(ctx context.Context, requested ServiceRouteScope) (ServiceRouteWatch, error) {
	scope, err := discoveryScope(requested)
	if err != nil {
		return nil, err
	}
	request := &pb.WatchServiceRoutesRequest{}
	if scope.AllWorkspaces {
		request.WorkspaceScope = allWorkspacesScope()
	} else if len(scope.Workspaces) == 1 {
		request.WorkspaceScope = namedWorkspaceScope(scope.Workspaces[0])
	} else {
		request.Workspaces = scope.Workspaces
	}
	ctx, cancel := context.WithCancel(ctx)
	stream, err := s.client.WatchServiceRoutes(ctx, request)
	if err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}
	return &serviceRouteWatch{stream: stream, cancel: cancel, scope: scope}, nil
}

type serviceRouteWatch struct {
	stream grpc.ServerStreamingClient[pb.WatchServiceRoutesResponse]
	cancel context.CancelFunc
	scope  ServiceRouteScope
	once   sync.Once
}

func (w *serviceRouteWatch) Close() { w.once.Do(w.cancel) }

func (w *serviceRouteWatch) Recv() (*ServiceRouteSnapshot, error) {
	response, err := w.stream.Recv()
	if err != nil {
		w.Close()
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, converter.FromGRPCError(err)
	}
	result, err := converter.ServiceRouteSnapshotForScopeFromProto(response.GetSnapshot(), w.scope)
	if err != nil {
		w.Close()
	}
	return result, err
}
