// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// ServiceRouteSnapshotFromProto validates and copies a full discovery view.
func ServiceRouteSnapshotFromProto(snapshot *pb.ServiceRouteSnapshot, workspace string) (*types.ServiceRouteSnapshot, error) {
	return ServiceRouteSnapshotForScopeFromProto(snapshot, types.ServiceRouteScope{Workspaces: []string{workspace}})
}

// ServiceRouteSnapshotForScopeFromProto validates route containment and copies the complete view.
func ServiceRouteSnapshotForScopeFromProto(snapshot *pb.ServiceRouteSnapshot, scope types.ServiceRouteScope) (*types.ServiceRouteSnapshot, error) {
	allowed := make(map[string]bool, len(scope.Workspaces))
	for _, workspace := range scope.Workspaces {
		allowed[workspace] = true
	}
	invalid := func() (*types.ServiceRouteSnapshot, error) {
		return nil, &types.StatusError{Code: types.ErrorInternal, Message: "invalid service discovery snapshot"}
	}
	if snapshot == nil || snapshot.GetRevision() == "" || len(snapshot.GetRoutes()) > 4096 {
		return invalid()
	}
	result := &types.ServiceRouteSnapshot{Revision: snapshot.GetRevision(), Routes: make([]types.DiscoveredServiceRoute, 0, len(snapshot.GetRoutes()))}
	hostnames := make(map[string]bool, len(snapshot.GetRoutes()))
	for _, route := range snapshot.GetRoutes() {
		if route == nil || (route.GetWorkspace() == "" || (!scope.AllWorkspaces && !allowed[route.GetWorkspace()])) || route.GetHostname() == "" || route.GetInstallationVersion() == "" || route.GetEndpoint() == nil || route.GetEndpoint().GetHost() == "" || route.GetEndpoint().GetPort() == 0 || route.GetEndpoint().GetPort() > 65535 || route.GetExpiresAt() == nil || route.GetExpiresAt().CheckValid() != nil || hostnames[route.GetHostname()] {
			return invalid()
		}
		hostnames[route.GetHostname()] = true
		result.Routes = append(result.Routes, types.DiscoveredServiceRoute{
			Workspace: route.GetWorkspace(), Sandbox: route.GetSandbox(), Name: route.GetName(), Hostname: route.GetHostname(),
			Endpoint:            types.ServiceRouteEndpoint{Host: route.GetEndpoint().GetHost(), Port: route.GetEndpoint().GetPort()},
			InstallationVersion: route.GetInstallationVersion(), DeclarationRevision: route.GetDeclarationRevision(), ExpiresAt: route.GetExpiresAt().AsTime(),
		})
	}
	return result, nil
}
